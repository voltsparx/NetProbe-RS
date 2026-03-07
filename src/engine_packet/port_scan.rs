// Packet-blast runner for raw SYN scanning with async-engine-compatible output shape.

use std::collections::HashMap;
use std::io;
use std::net::{IpAddr, Ipv4Addr, UdpSocket};
use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::engine_intel::device_profile::{classify_mac, DeviceClass, DeviceProfile};
use crate::engine_intel::strategy::ScanStrategy;
use crate::engine_packet::afxdp_backend::open_afxdp_backends;
use crate::engine_packet::arp as packet_arp;
use crate::engine_packet::datalink_backend::open_layer2_backends;
use crate::engine_packet::intelligence_pipeline::{
    run_multi_stage_tcp_probe_pipeline, MultiStageProbePolicy, MultiStageProbeReport,
};
use crate::engine_packet::socket_backend::{RawSocketRx, RawSocketTx};
use crate::engine_packet::syn_scanner::{
    RawPortState, RawSynScanner, RawSynScannerConfig, RawTxBackend,
};
use crate::engines::async_engine::AsyncPacketEngine;
use crate::engines::bio_response_governor;
use crate::engines::fusion_engine::{FusionEngine, PacketFusionInput, PacketFusionPlan};
use crate::engines::phantom_preflight;
use crate::error::{NProbeError, NProbeResult};
use crate::fingerprint_db::FingerprintDatabase;
use crate::models::{HostResult, PortFinding, PortState, ScanRequest};
use crate::service_db::ServiceRegistry;

#[derive(Debug)]
struct BackendRunResult {
    findings: Vec<crate::engine_packet::syn_scanner::RawSynResult>,
    backend_mode: String,
}

#[derive(Debug, Clone, Copy, Default)]
struct AdaptiveFusionFeedback {
    packet_drop_ratio: f64,
    timeout_pressure: f64,
    response_ratio: f64,
    queue_pressure: f64,
    retry_pressure: f64,
}

pub async fn run(
    request: &ScanRequest,
    target: IpAddr,
    ports: Vec<u16>,
    services: Arc<ServiceRegistry>,
    fingerprint_db: Arc<FingerprintDatabase>,
    strategy: &ScanStrategy,
) -> NProbeResult<(HostResult, usize)> {
    if ports.is_empty() {
        return Err(NProbeError::Parse(
            "packet-blast mode received empty port list".to_string(),
        ));
    }

    let target_v4 = match target {
        IpAddr::V4(value) => value,
        IpAddr::V6(_) => {
            return Err(NProbeError::Safety(
                "packet-blast raw SYN mode currently supports IPv4 targets only".to_string(),
            ));
        }
    };

    if !request.effective_privileged_probes() {
        return Err(NProbeError::Safety(
            "packet-blast raw SYN mode requires privileged probes/root".to_string(),
        ));
    }

    let source_ip = discover_source_ipv4(target_v4).map_err(|err| {
        NProbeError::Io(std::io::Error::new(
            err.kind(),
            format!("could not determine source IPv4 route for raw scanner: {err}"),
        ))
    })?;

    let mut warnings = Vec::<String>::new();
    let mut safety_actions = Vec::<String>::new();
    let mut observed_mac = None::<String>;
    let mut device_class = None::<String>;
    let mut device_vendor = None::<String>;
    let base_rate_pps = request.rate_limit_pps.unwrap_or(strategy.rate_limit_pps) as u64;
    let mut rate_pps = base_rate_pps;
    let runtime = request.runtime_settings();
    let mut raw_worker_cap = runtime.concurrency.max(1);
    let mut chunk_delay = runtime.delay;
    let mut stage2_service_detection = request.service_detection;
    let mut fingerprint_payload_budget = if stage2_service_detection { 4 } else { 0 };
    let burst_size = request.burst_size.unwrap_or(strategy.burst_size);
    let seed = request.scan_seed.unwrap_or(0x4e50_5253_5241_5753_u64);
    let source_port = source_port_from_seed(seed);
    let scan_timeout = request
        .timeout_ms
        .map(Duration::from_millis)
        .unwrap_or(strategy.recommended_timeout)
        .clamp(Duration::from_millis(150), Duration::from_secs(10));

    let mut device_profile = None::<DeviceProfile>;
    if packet_arp::is_lan_ipv4(target_v4) {
        match packet_arp::resolve_neighbor_mac(target_v4, Duration::from_millis(120)) {
            Ok(Some(mac)) => {
                let profile = classify_mac(&mac);
                observed_mac = Some(mac.clone());
                device_class = Some(profile.class.to_string());
                device_vendor = profile.vendor.map(str::to_string);
                if let Some(max_pps) = profile.max_pps {
                    rate_pps = rate_pps.min(max_pps as u64);
                }
                warnings.push(format!(
                    "device-profile active: mac={} {}",
                    mac,
                    profile.describe()
                ));
                safety_actions.push(format!("device-profile:{}", profile.class));
                if rate_pps < base_rate_pps {
                    warnings.push(format!(
                        "device-profile throttle applied: rate reduced from {}pps to {}pps",
                        base_rate_pps, rate_pps
                    ));
                    safety_actions.push(format!("rate-capped:{}->{}pps", base_rate_pps, rate_pps));
                }
                device_profile = Some(profile);
            }
            Ok(None) => {
                warnings.push(
                    "device-profile skipped: no neighbor MAC resolved for LAN target".to_string(),
                );
            }
            Err(err) => {
                warnings.push(format!("device-profile skipped: arp lookup failed: {err}"));
            }
        }
    }

    if !matches!(
        device_profile.map(|profile| profile.class),
        Some(DeviceClass::Enterprise)
    ) && rate_pps > 500
    {
        warnings.push(format!(
            "defensive guard applied conservative raw rate cap: {}pps -> 500pps",
            rate_pps
        ));
        safety_actions.push(format!("rate-capped:{}->500pps", rate_pps));
        rate_pps = 500;
    }

    let bio_response = bio_response_governor::decide(
        request.profile,
        request.strict_safety,
        device_profile.map(|profile| profile.class),
        rate_pps.min(u32::MAX as u64) as u32,
        raw_worker_cap,
        chunk_delay,
    );
    if (bio_response.rate_cap_pps as u64) < rate_pps {
        warnings.push(format!(
            "bio-response governor applied raw rate cap: {}pps -> {}pps",
            rate_pps, bio_response.rate_cap_pps
        ));
        safety_actions.push(format!(
            "bio-response:rate-capped:{}->{}pps",
            rate_pps, bio_response.rate_cap_pps
        ));
        rate_pps = bio_response.rate_cap_pps as u64;
    }
    if bio_response.concurrency_cap < raw_worker_cap {
        let previous = raw_worker_cap;
        raw_worker_cap = bio_response.concurrency_cap;
        warnings.push(format!(
            "bio-response governor applied raw worker cap: {} -> {}",
            previous, raw_worker_cap
        ));
        safety_actions.push(format!(
            "bio-response:concurrency-capped:{}->{}",
            previous, raw_worker_cap
        ));
    }
    if bio_response.delay_floor > chunk_delay {
        let previous = chunk_delay;
        chunk_delay = bio_response.delay_floor;
        warnings.push(format!(
            "bio-response governor raised raw chunk delay floor: {}ms -> {}ms",
            previous.as_millis(),
            chunk_delay.as_millis()
        ));
        safety_actions.push(format!(
            "bio-response:delay-raised:{}ms->{}ms",
            previous.as_millis(),
            chunk_delay.as_millis()
        ));
    }
    if stage2_service_detection && !bio_response.service_detection_allowed {
        stage2_service_detection = false;
        fingerprint_payload_budget = 0;
        warnings.push(
            "bio-response governor withheld deeper packet-path service detection until the host proved resilient enough for safe follow-up"
                .to_string(),
        );
        safety_actions.push("bio-response:passive-stage1".to_string());
    }
    safety_actions.push(format!("bio-response:stage={}", bio_response.stage));
    warnings.push(format!(
        "bio-response governor stage={} policy active for the packet path",
        bio_response.stage
    ));
    warnings.extend(bio_response.notes);

    let safety_blacklist = device_profile
        .map(|profile| profile.safety_blacklist.to_vec())
        .unwrap_or_default();
    let blocked_ports = ports
        .iter()
        .copied()
        .filter(|port| safety_blacklist.contains(port))
        .collect::<Vec<_>>();
    if !blocked_ports.is_empty() {
        warnings.push(format!(
            "device-profile safety blacklist applied: skipping ports {:?}",
            blocked_ports
        ));
        safety_actions.push(format!("ports-skipped:{blocked_ports:?}"));
    }

    let scan_targets = ports
        .iter()
        .copied()
        .filter(|port| !safety_blacklist.contains(port))
        .map(|port| (target_v4, port))
        .collect::<Vec<_>>();
    let preflight_ports = scan_targets
        .iter()
        .map(|(_, port)| *port)
        .collect::<Vec<_>>();
    let preflight = phantom_preflight::run(phantom_preflight::PhantomPreflightInput {
        target,
        ports: &preflight_ports,
        requested_timeout: scan_timeout,
        requested_rate_pps: rate_pps.min(u32::MAX as u64) as u32,
        requested_concurrency: raw_worker_cap,
        requested_delay: chunk_delay,
        service_detection_requested: stage2_service_detection,
        strict_safety: request.strict_safety,
        profile: request.profile,
        device_class: device_profile.map(|profile| profile.class),
    })
    .await;
    let phantom_device_check = Some(preflight.summary());
    warnings.push(format!(
        "phantom preflight stage={} responsive={}/{} timeout={} avg-latency={}ms",
        preflight.stage,
        preflight.responsive_ports,
        preflight.sampled_ports.len(),
        preflight.timeout_ports,
        preflight
            .avg_latency_ms
            .map(|latency| latency.to_string())
            .unwrap_or_else(|| "n/a".to_string())
    ));
    safety_actions.push(format!("phantom-preflight:stage={}", preflight.stage));
    if (preflight.rate_cap_pps as u64) < rate_pps {
        warnings.push(format!(
            "phantom preflight tightened raw rate cap: {}pps -> {}pps",
            rate_pps, preflight.rate_cap_pps
        ));
        safety_actions.push(format!(
            "phantom-preflight:rate-capped:{}->{}pps",
            rate_pps, preflight.rate_cap_pps
        ));
        rate_pps = preflight.rate_cap_pps as u64;
    }
    if preflight.concurrency_cap < raw_worker_cap {
        let previous = raw_worker_cap;
        raw_worker_cap = preflight.concurrency_cap;
        warnings.push(format!(
            "phantom preflight tightened raw worker cap: {} -> {}",
            previous, raw_worker_cap
        ));
        safety_actions.push(format!(
            "phantom-preflight:concurrency-capped:{}->{}",
            previous, raw_worker_cap
        ));
    }
    if preflight.delay_floor > chunk_delay {
        let previous = chunk_delay;
        chunk_delay = preflight.delay_floor;
        warnings.push(format!(
            "phantom preflight raised raw chunk delay floor: {}ms -> {}ms",
            previous.as_millis(),
            chunk_delay.as_millis()
        ));
        safety_actions.push(format!(
            "phantom-preflight:delay-raised:{}ms->{}ms",
            previous.as_millis(),
            chunk_delay.as_millis()
        ));
    }
    if stage2_service_detection && !preflight.service_detection_allowed {
        stage2_service_detection = false;
        warnings.push(
            "phantom preflight withheld packet-path service detection because the device-check stage did not justify deeper active follow-up"
                .to_string(),
        );
        safety_actions.push("phantom-preflight:passive-follow-up".to_string());
    }
    let requested_payload_budget = fingerprint_payload_budget;
    fingerprint_payload_budget = if stage2_service_detection {
        requested_payload_budget.min(preflight.fingerprint_payload_budget)
    } else {
        0
    };
    if fingerprint_payload_budget < requested_payload_budget {
        warnings.push(format!(
            "phantom preflight reduced packet-path payload budget: {} -> {}",
            requested_payload_budget, fingerprint_payload_budget
        ));
        safety_actions.push(format!(
            "phantom-preflight:payload-budget:{}->{}",
            requested_payload_budget, fingerprint_payload_budget
        ));
    }
    warnings.extend(preflight.notes);

    let mut fusion_engine = FusionEngine::default();
    let mut feedback = AdaptiveFusionFeedback::default();
    let mut findings = Vec::<crate::engine_packet::syn_scanner::RawSynResult>::new();
    let mut chunk_notes = Vec::<String>::new();
    let mut backend_mode = None::<String>;
    let mut last_fusion_plan = None::<PacketFusionPlan>;
    let mut scanned = 0usize;
    let mut responsive = 0usize;
    let mut chunk_count = 0usize;
    let mut rate_sum_pps = 0u64;

    while scanned < scan_targets.len() {
        let remaining = scan_targets.len().saturating_sub(scanned);
        let fusion_plan = fusion_engine.plan(PacketFusionInput {
            requested_rate_pps: rate_pps.max(1),
            burst_size,
            target_count: remaining,
            packet_drop_ratio: feedback.packet_drop_ratio,
            timeout_pressure: feedback.timeout_pressure,
            response_ratio: feedback.response_ratio,
            queue_pressure: feedback.queue_pressure,
            retry_pressure: feedback.retry_pressure,
        });
        last_fusion_plan = Some(fusion_plan);

        let tx_workers = fusion_plan.tx_workers.min(raw_worker_cap).max(1);
        let window_size = fusion_plan
            .window_size
            .min(remaining)
            .min(
                tx_workers
                    .saturating_mul(fusion_plan.tx_batch_size)
                    .saturating_mul(4),
            )
            .max(1);
        let chunk_targets = scan_targets[scanned..scanned + window_size].to_vec();
        let config = RawSynScannerConfig {
            source_ip,
            source_port,
            rate_pps: fusion_plan.effective_rate_pps,
            burst_size,
            tx_workers,
            tx_batch_size: fusion_plan.tx_batch_size,
            rx_grace: scan_timeout,
            scan_seed: seed,
        };

        let chunk_started = Instant::now();
        let backend_result = AsyncPacketEngine::run_blocking("packet-blast", move || {
            let scanner = RawSynScanner::new(config);
            run_with_preferred_backend(scanner, source_ip, target_v4, &chunk_targets)
        })
        .await
        .map_err(NProbeError::Io)?;
        let chunk_elapsed = chunk_started.elapsed();

        if backend_mode.is_none() {
            backend_mode = Some(backend_result.backend_mode.clone());
        }

        let chunk_responsive = backend_result.findings.len().min(window_size);
        findings.extend(backend_result.findings);
        feedback = derive_feedback(
            window_size,
            chunk_responsive,
            chunk_elapsed,
            fusion_plan.effective_rate_pps,
            scan_timeout,
            tx_workers,
            fusion_plan.tx_batch_size,
        );

        scanned = scanned.saturating_add(window_size);
        responsive = responsive.saturating_add(chunk_responsive);
        chunk_count = chunk_count.saturating_add(1);
        rate_sum_pps = rate_sum_pps.saturating_add(fusion_plan.effective_rate_pps);

        if chunk_notes.len() < 5 || scanned >= scan_targets.len() {
            chunk_notes.push(format!(
                "fusion-stage {}: situation={} rate={}pps workers={} batch={} window={} multiplier={:.3} response={:.2}% drop={:.2}% timeout-pressure={:.2}%",
                chunk_count,
                fusion_plan.situation,
                fusion_plan.effective_rate_pps,
                tx_workers,
                fusion_plan.tx_batch_size,
                window_size,
                fusion_plan.rate_multiplier,
                feedback.response_ratio * 100.0,
                feedback.packet_drop_ratio * 100.0,
                feedback.timeout_pressure * 100.0
            ));
        }

        if scanned < scan_targets.len() && !chunk_delay.is_zero() {
            tokio::time::sleep(chunk_delay).await;
        }
    }

    let mut final_findings = build_default_findings(&ports, &services);
    let mut index_by_port = HashMap::<u16, usize>::with_capacity(final_findings.len());
    for (idx, finding) in final_findings.iter().enumerate() {
        index_by_port.insert(finding.port, idx);
    }

    for port in &blocked_ports {
        if let Some(idx) = index_by_port.get(port).copied() {
            let entry = &mut final_findings[idx];
            entry.state = PortState::Filtered;
            entry.reason = "skipped by device-profile safety blacklist".to_string();
            entry.matched_by = Some("device-profile-safety".to_string());
            entry.confidence = Some(1.0);
            entry.educational_note = Some(
                "safety policy suppressed active probing on this port for the detected device class"
                    .to_string(),
            );
        }
    }

    for finding in findings {
        if let Some(idx) = index_by_port.get(&finding.port).copied() {
            let entry = &mut final_findings[idx];
            match finding.state {
                RawPortState::Open => {
                    entry.state = PortState::Open;
                    entry.reason = format!(
                        "syn-ack received (raw-syn ttl={} flags=0x{:02x})",
                        finding.ttl, finding.flags
                    );
                }
                RawPortState::Closed => {
                    entry.state = PortState::Closed;
                    entry.reason = format!(
                        "rst received (raw-syn ttl={} flags=0x{:02x})",
                        finding.ttl, finding.flags
                    );
                }
                RawPortState::Unknown => {
                    entry.state = PortState::Filtered;
                    entry.reason = format!(
                        "unexpected tcp flags in raw response (ttl={} flags=0x{:02x})",
                        finding.ttl, finding.flags
                    );
                }
            }
        }
    }

    // Stage 2/3: async intelligence pipeline for open TCP ports only.
    let mut stage2_report = MultiStageProbeReport::default();
    if stage2_service_detection
        && matches!(
            device_profile.map(|profile| profile.allows_active_fingerprinting()),
            Some(true)
        )
    {
        let stage2_concurrency = match device_profile.map(|profile| profile.class) {
            Some(DeviceClass::FragileEmbedded) => raw_worker_cap.min(4),
            Some(DeviceClass::PrinterSensitive) => raw_worker_cap.min(8),
            _ => raw_worker_cap,
        };
        stage2_report = run_multi_stage_tcp_probe_pipeline(
            target,
            &mut final_findings,
            Arc::clone(&fingerprint_db),
            scan_timeout,
            MultiStageProbePolicy {
                max_concurrency: stage2_concurrency,
                fragile_mode: matches!(
                    device_profile.map(|profile| profile.class),
                    Some(DeviceClass::FragileEmbedded) | Some(DeviceClass::PrinterSensitive)
                ),
                safety_blacklist: safety_blacklist.clone(),
                payload_budget: fingerprint_payload_budget.max(1),
            },
        )
        .await;
        if matches!(
            device_profile.map(|profile| profile.class),
            Some(DeviceClass::FragileEmbedded) | Some(DeviceClass::PrinterSensitive)
        ) {
            safety_actions.push(format!(
                "fragile-mode:stage2-concurrency={}",
                stage2_concurrency
            ));
        }
    } else if request.service_detection && !stage2_service_detection {
        stage2_report.notes.push(
            "stage2-intelligence skipped: Phantom device check kept the packet path in passive follow-up mode"
                .to_string(),
        );
        safety_actions.push("phantom-preflight:passive-follow-up".to_string());
    } else if request.service_detection {
        stage2_report.notes.push(
            "stage2-intelligence skipped: defensive guard requires an enterprise-resilient device profile before deeper active fingerprinting"
                .to_string(),
        );
        safety_actions.push("defensive-probing:passive-stage1".to_string());
    } else {
        stage2_report
            .notes
            .push("stage2-intelligence skipped: service detection disabled".to_string());
    }

    let avg_rate_pps = if chunk_count == 0 {
        0
    } else {
        rate_sum_pps / chunk_count as u64
    };
    let responsive_ratio = if scanned == 0 {
        0.0
    } else {
        responsive as f64 / scanned as f64
    };
    warnings.push(backend_mode.unwrap_or_else(|| "packet-blast backend: unavailable".to_string()));
    warnings.push(format!(
        "fusion-engine adaptive: chunks={} avg-rate={}pps responsive={}/{} ({:.2}%) final-drop={:.2}% final-timeout-pressure={:.2}% crafters={}",
        chunk_count,
        avg_rate_pps,
        responsive,
        scanned,
        responsive_ratio * 100.0,
        feedback.packet_drop_ratio * 100.0,
        feedback.timeout_pressure * 100.0,
        last_fusion_plan
            .map(|plan| plan.active_crafters)
            .unwrap_or_default()
    ));
    warnings.push(format!(
        "multi-stage pipeline: stage2-tasks={} service-identifications={}",
        stage2_report.tasks_spawned, stage2_report.services_identified
    ));
    warnings.extend(stage2_report.notes.into_iter().take(3));
    warnings.extend(chunk_notes);

    let host = HostResult {
        target: request.target.clone(),
        ip: target.to_string(),
        reverse_dns: None,
        observed_mac,
        device_class,
        device_vendor,
        phantom_device_check,
        safety_actions,
        warnings,
        ports: final_findings,
        risk_score: 0,
        insights: Vec::new(),
        defensive_advice: Vec::new(),
        learning_notes: Vec::new(),
        lua_findings: Vec::new(),
    };

    Ok((
        host,
        ports.len().saturating_add(stage2_report.tasks_spawned),
    ))
}

fn run_with_preferred_backend(
    scanner: RawSynScanner,
    source_ip: Ipv4Addr,
    target_ip: Ipv4Addr,
    scan_targets: &[(Ipv4Addr, u16)],
) -> io::Result<BackendRunResult> {
    let worker_count = scanner.effective_tx_workers(scan_targets.len());

    let afxdp_err = match open_afxdp_backends(source_ip, target_ip) {
        Ok((tx, rx)) => {
            let mut first_tx = Some(tx);
            let findings = scanner.run_with_tx_factory(
                move |worker_id| {
                    if worker_id == 0 {
                        let primary = first_tx.take().ok_or_else(|| {
                            io::Error::other("primary af_xdp tx backend already consumed")
                        })?;
                        return Ok(Box::new(primary) as Box<dyn RawTxBackend>);
                    }

                    let (extra_tx, _extra_rx) = open_afxdp_backends(source_ip, target_ip)?;
                    Ok(Box::new(extra_tx) as Box<dyn RawTxBackend>)
                },
                rx,
                scan_targets,
            )?;
            return Ok(BackendRunResult {
                findings,
                backend_mode: format!(
                    "packet-blast backend: AF_XDP zero-copy path (tx-workers={})",
                    worker_count
                ),
            });
        }
        Err(err) => err,
    };

    match open_layer2_backends(source_ip, target_ip) {
        Ok((tx, rx)) => {
            let mut first_tx = Some(tx);
            let findings = scanner.run_with_tx_factory(
                move |worker_id| {
                    if worker_id == 0 {
                        let primary = first_tx.take().ok_or_else(|| {
                            io::Error::other("primary layer-2 tx backend already consumed")
                        })?;
                        return Ok(Box::new(primary) as Box<dyn RawTxBackend>);
                    }

                    let (extra_tx, _extra_rx) = open_layer2_backends(source_ip, target_ip)?;
                    Ok(Box::new(extra_tx) as Box<dyn RawTxBackend>)
                },
                rx,
                scan_targets,
            )?;
            Ok(BackendRunResult {
                findings,
                backend_mode: format!(
                    "packet-blast backend: direct L2 crafted frames (kernel TCP stack bypass, tx-workers={}; af_xdp unavailable: {})",
                    worker_count, afxdp_err
                ),
            })
        }
        Err(l2_err) => {
            let rx = RawSocketRx::new(source_ip)?;
            let findings = scanner.run_with_tx_factory(
                move |_| Ok(Box::new(RawSocketTx::new(source_ip)?) as Box<dyn RawTxBackend>),
                rx,
                scan_targets,
            )?;
            Ok(BackendRunResult {
                findings,
                backend_mode: format!(
                    "packet-blast backend fallback: raw sockets (af_xdp unavailable: {}; L2 unavailable: {}; tx-workers={})",
                    afxdp_err, l2_err, worker_count
                ),
            })
        }
    }
}

fn build_default_findings(ports: &[u16], services: &ServiceRegistry) -> Vec<PortFinding> {
    let mut findings = Vec::with_capacity(ports.len());
    for port in ports {
        let initial_service = services.lookup(*port, "tcp").map(ToOwned::to_owned);
        findings.push(PortFinding {
            port: *port,
            protocol: "tcp".to_string(),
            state: PortState::Filtered,
            service: initial_service.clone(),
            service_identity: None,
            banner: None,
            reason: "no response (raw-syn)".to_string(),
            matched_by: initial_service
                .as_ref()
                .map(|_| "nmap-services-port-map".to_string()),
            confidence: initial_service.as_ref().map(|_| 0.44),
            vulnerability_hints: Vec::new(),
            educational_note: None,
            latency_ms: None,
            explanation: None,
        });
    }
    findings
}

fn discover_source_ipv4(target: Ipv4Addr) -> std::io::Result<Ipv4Addr> {
    let socket = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0))?;
    socket.connect((target, 33434))?;
    let local = socket.local_addr()?;
    match local.ip() {
        IpAddr::V4(v4) => Ok(v4),
        IpAddr::V6(_) => Err(std::io::Error::other("resolved local address is not IPv4")),
    }
}

fn source_port_from_seed(seed: u64) -> u16 {
    let span = 65_535u32 - 40_000u32;
    let mapped = ((seed as u32) % span) + 40_000u32;
    mapped as u16
}

fn derive_feedback(
    attempted: usize,
    responsive: usize,
    elapsed: Duration,
    effective_rate_pps: u64,
    rx_grace: Duration,
    tx_workers: usize,
    tx_batch_size: usize,
) -> AdaptiveFusionFeedback {
    let attempts = attempted.max(1) as f64;
    let response_ratio = (responsive as f64 / attempts).clamp(0.0, 1.0);
    let packet_drop_ratio = (1.0 - response_ratio).clamp(0.0, 1.0);

    // Include configured RX grace in baseline expectation to avoid false timeout pressure.
    let expected_dispatch_secs = attempts / effective_rate_pps.max(1) as f64;
    let expected_total_secs = expected_dispatch_secs + (rx_grace.as_secs_f64() * 0.70);
    let observed_secs = elapsed.as_secs_f64();
    let timeout_pressure = if expected_total_secs <= 0.0 {
        0.0
    } else {
        ((observed_secs - expected_total_secs) / expected_total_secs).clamp(0.0, 1.0)
    };

    let density = (tx_workers.saturating_mul(tx_batch_size) as f64 / attempts).clamp(0.0, 1.0);
    let queue_pressure = (packet_drop_ratio * 0.60 + density * 0.40).clamp(0.0, 1.0);
    let retry_pressure = (timeout_pressure * 0.65 + packet_drop_ratio * 0.35).clamp(0.0, 1.0);

    AdaptiveFusionFeedback {
        packet_drop_ratio,
        timeout_pressure,
        response_ratio,
        queue_pressure,
        retry_pressure,
    }
}

#[cfg(test)]
mod tests {
    use super::derive_feedback;
    use std::time::Duration;

    #[test]
    fn derive_feedback_flags_drop_and_timeout_pressure() {
        let feedback = derive_feedback(
            512,
            64,
            Duration::from_secs(2),
            100_000,
            Duration::from_millis(500),
            4,
            64,
        );
        assert!(feedback.packet_drop_ratio > 0.80);
        assert!(feedback.timeout_pressure >= 0.0);
        assert!(feedback.retry_pressure > 0.0);
    }

    #[test]
    fn derive_feedback_for_healthy_chunk_stays_low_pressure() {
        let feedback = derive_feedback(
            512,
            460,
            Duration::from_millis(650),
            80_000,
            Duration::from_millis(600),
            2,
            32,
        );
        assert!(feedback.packet_drop_ratio < 0.20);
        assert!(feedback.response_ratio > 0.75);
    }
}

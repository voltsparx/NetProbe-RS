// Flow sketch: host target -> async scan engine -> host findings.

use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use crate::engine_async::scanner::{self, AsyncScanConfig};
use crate::engine_intel::device_profile::{classify_mac, DeviceClass};
use crate::engine_intel::strategy::ScanStrategy;
use crate::engine_packet::arp as packet_arp;
use crate::engines::{bio_response_governor, phantom_preflight};
use crate::error::NProbeResult;
use crate::fingerprint_db::FingerprintDatabase;
use crate::models::{HostResult, PortFinding, PortState, ScanRequest};
use crate::service_db::ServiceRegistry;

pub async fn run(
    request: &ScanRequest,
    target: IpAddr,
    ports: Vec<u16>,
    services: Arc<ServiceRegistry>,
    fingerprint_db: Arc<FingerprintDatabase>,
    strategy: &ScanStrategy,
) -> NProbeResult<(HostResult, usize)> {
    let mut runtime = request.runtime_settings();
    let mut warnings = Vec::new();
    let mut safety_actions = Vec::new();
    let mut observed_mac = None;
    let mut device_class = None;
    let mut device_vendor = None;
    let mut blocked_findings = Vec::new();
    let mut scan_ports = ports;
    let mut service_detection = request.service_detection;
    let mut fingerprint_payload_budget = if service_detection { 4 } else { 0 };
    let base_rate_pps = request.rate_limit_pps.unwrap_or(strategy.rate_limit_pps);
    let mut rate_limit_pps = base_rate_pps;
    let mut profile_class = None::<DeviceClass>;

    if let Some(chapter) = request.profile.tbns_chapter() {
        warnings.push(format!(
            "tbns {} active: chapter={} low-impact safety bus enforced for this host",
            request.profile.as_str(),
            chapter
        ));
        safety_actions.push(format!(
            "tbns:{}:chapter={}",
            request.profile.as_str(),
            chapter
        ));
    }

    if let IpAddr::V4(target_v4) = target {
        if packet_arp::is_lan_ipv4(target_v4) {
            match tokio::task::spawn_blocking(move || {
                packet_arp::resolve_neighbor_mac(target_v4, Duration::from_millis(120))
            })
            .await
            {
                Ok(Ok(Some(mac))) => {
                    let profile = classify_mac(&mac);
                    observed_mac = Some(mac.clone());
                    device_class = Some(profile.class.to_string());
                    device_vendor = profile.vendor.map(str::to_string);
                    profile_class = Some(profile.class);
                    warnings.push(format!(
                        "device-profile active: mac={} {}",
                        mac,
                        profile.describe()
                    ));
                    safety_actions.push(format!("device-profile:{}", profile.class));

                    if let Some(max_pps) = profile.max_pps {
                        if rate_limit_pps > max_pps {
                            rate_limit_pps = max_pps;
                            warnings.push(format!(
                                "device-profile throttle applied: rate reduced from {}pps to {}pps",
                                base_rate_pps, rate_limit_pps
                            ));
                            safety_actions.push(format!(
                                "rate-capped:{}->{}pps",
                                base_rate_pps, rate_limit_pps
                            ));
                        }
                    }

                    if let Some(cap) = profile.async_concurrency_cap() {
                        if runtime.concurrency > cap {
                            let previous = runtime.concurrency;
                            runtime.concurrency = cap;
                            warnings.push(format!(
                                "device-profile concurrency cap applied: reduced from {} to {}",
                                previous, runtime.concurrency
                            ));
                            safety_actions.push(format!(
                                "concurrency-capped:{}->{}",
                                previous, runtime.concurrency
                            ));
                        }
                    }

                    if !profile.allows_active_fingerprinting() && service_detection {
                        service_detection = false;
                        warnings.push(
                            "defensive guard kept service detection passive because the target has not demonstrated enterprise-grade resilience"
                                .to_string(),
                        );
                        safety_actions.push("defensive-probing:passive-stage1".to_string());
                    }

                    if !profile.safety_blacklist.is_empty() {
                        let blocked_ports = scan_ports
                            .iter()
                            .copied()
                            .filter(|port| profile.safety_blacklist.contains(port))
                            .collect::<Vec<_>>();
                        if !blocked_ports.is_empty() {
                            scan_ports.retain(|port| !profile.safety_blacklist.contains(port));
                            warnings.push(format!(
                                "device-profile safety blacklist applied: skipping ports {:?}",
                                blocked_ports
                            ));
                            safety_actions.push(format!("ports-skipped:{blocked_ports:?}"));
                            blocked_findings = build_blocked_port_findings(
                                &blocked_ports,
                                services.as_ref(),
                                request.include_udp,
                            );
                        }
                    }
                }
                Ok(Ok(None)) => warnings.push(
                    "device-profile skipped: no neighbor MAC resolved for LAN target".to_string(),
                ),
                Ok(Err(err)) => {
                    warnings.push(format!("device-profile skipped: arp lookup failed: {err}"));
                }
                Err(err) => warnings.push(format!(
                    "device-profile skipped: background lookup failed: {err}"
                )),
            }
        }
    }

    if request.strict_safety && !matches!(profile_class, Some(DeviceClass::Enterprise)) {
        if runtime.concurrency > 8 {
            let previous = runtime.concurrency;
            runtime.concurrency = 8;
            warnings.push(format!(
                "strict-safety unknown-device cap applied: reduced concurrency from {} to {}",
                previous, runtime.concurrency
            ));
            safety_actions.push(format!(
                "concurrency-capped:{}->{}",
                previous, runtime.concurrency
            ));
        }
        if rate_limit_pps > 250 {
            warnings.push(format!(
                "strict-safety unknown-device cap applied: rate reduced from {}pps to 250pps",
                rate_limit_pps
            ));
            safety_actions.push(format!("rate-capped:{}->250pps", rate_limit_pps));
            rate_limit_pps = 250;
        }
        if service_detection {
            service_detection = false;
            warnings.push(
                "strict-safety active: deeper probes suppressed until the host is explicitly classified as resilient"
                    .to_string(),
            );
            safety_actions.push("strict-safety:passive-only".to_string());
        }
    }

    let bio_response = bio_response_governor::decide(
        request.profile,
        request.strict_safety,
        profile_class,
        rate_limit_pps,
        runtime.concurrency,
        runtime.delay,
    );
    if bio_response.rate_cap_pps < rate_limit_pps {
        warnings.push(format!(
            "bio-response governor applied rate cap: {}pps -> {}pps",
            rate_limit_pps, bio_response.rate_cap_pps
        ));
        safety_actions.push(format!(
            "bio-response:rate-capped:{}->{}pps",
            rate_limit_pps, bio_response.rate_cap_pps
        ));
        rate_limit_pps = bio_response.rate_cap_pps;
    }
    if bio_response.concurrency_cap < runtime.concurrency {
        let previous = runtime.concurrency;
        runtime.concurrency = bio_response.concurrency_cap;
        warnings.push(format!(
            "bio-response governor applied concurrency cap: {} -> {}",
            previous, runtime.concurrency
        ));
        safety_actions.push(format!(
            "bio-response:concurrency-capped:{}->{}",
            previous, runtime.concurrency
        ));
    }
    if bio_response.delay_floor > runtime.delay {
        let previous = runtime.delay;
        runtime.delay = bio_response.delay_floor;
        warnings.push(format!(
            "bio-response governor raised dispatch delay floor: {}ms -> {}ms",
            previous.as_millis(),
            runtime.delay.as_millis()
        ));
        safety_actions.push(format!(
            "bio-response:delay-raised:{}ms->{}ms",
            previous.as_millis(),
            runtime.delay.as_millis()
        ));
    }
    if service_detection && !bio_response.service_detection_allowed {
        service_detection = false;
        warnings.push(
            "bio-response governor withheld deeper service detection until the host proved resilient enough for safe follow-up"
                .to_string(),
        );
        safety_actions.push("bio-response:passive-stage1".to_string());
    }
    warnings.push(format!(
        "bio-response governor stage={} policy active for this host",
        bio_response.stage
    ));
    safety_actions.push(format!("bio-response:stage={}", bio_response.stage));
    for note in bio_response.notes {
        warnings.push(note);
    }

    let preflight = phantom_preflight::run(phantom_preflight::PhantomPreflightInput {
        target,
        ports: &scan_ports,
        requested_timeout: runtime.timeout,
        requested_rate_pps: rate_limit_pps,
        requested_concurrency: runtime.concurrency,
        requested_delay: runtime.delay,
        service_detection_requested: service_detection,
        strict_safety: request.strict_safety,
        profile: request.profile,
        device_class: profile_class,
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
    if preflight.rate_cap_pps < rate_limit_pps {
        warnings.push(format!(
            "phantom preflight tightened rate cap: {}pps -> {}pps",
            rate_limit_pps, preflight.rate_cap_pps
        ));
        safety_actions.push(format!(
            "phantom-preflight:rate-capped:{}->{}pps",
            rate_limit_pps, preflight.rate_cap_pps
        ));
        rate_limit_pps = preflight.rate_cap_pps;
    }
    if preflight.concurrency_cap < runtime.concurrency {
        let previous = runtime.concurrency;
        runtime.concurrency = preflight.concurrency_cap;
        warnings.push(format!(
            "phantom preflight tightened concurrency: {} -> {}",
            previous, runtime.concurrency
        ));
        safety_actions.push(format!(
            "phantom-preflight:concurrency-capped:{}->{}",
            previous, runtime.concurrency
        ));
    }
    if preflight.delay_floor > runtime.delay {
        let previous = runtime.delay;
        runtime.delay = preflight.delay_floor;
        warnings.push(format!(
            "phantom preflight raised dispatch delay floor: {}ms -> {}ms",
            previous.as_millis(),
            runtime.delay.as_millis()
        ));
        safety_actions.push(format!(
            "phantom-preflight:delay-raised:{}ms->{}ms",
            previous.as_millis(),
            runtime.delay.as_millis()
        ));
    }
    if service_detection && !preflight.service_detection_allowed {
        service_detection = false;
        warnings.push(
            "phantom preflight withheld active service detection because the target did not demonstrate a stable enough response profile"
                .to_string(),
        );
        safety_actions.push("phantom-preflight:passive-follow-up".to_string());
    }
    let requested_payload_budget = fingerprint_payload_budget;
    fingerprint_payload_budget = if service_detection {
        requested_payload_budget.min(preflight.fingerprint_payload_budget)
    } else {
        0
    };
    if fingerprint_payload_budget < requested_payload_budget {
        warnings.push(format!(
            "phantom preflight reduced active payload budget: {} -> {}",
            requested_payload_budget, fingerprint_payload_budget
        ));
        safety_actions.push(format!(
            "phantom-preflight:payload-budget:{}->{}",
            requested_payload_budget, fingerprint_payload_budget
        ));
    }
    for note in preflight.notes {
        warnings.push(note);
    }

    let config = AsyncScanConfig {
        target,
        ports: scan_ports,
        include_udp: request.include_udp,
        timeout: runtime.timeout,
        concurrency: runtime.concurrency,
        dispatch_delay: runtime.delay,
        service_detection,
        aggressive_root: request.aggressive_root,
        privileged_probes: request.effective_privileged_probes(),
        fingerprint_db,
        rate_limit_pps,
        burst_size: request.burst_size.unwrap_or(strategy.burst_size),
        max_retries: request.max_retries.unwrap_or(strategy.max_retries),
        scan_seed: request.scan_seed,
        fingerprint_payload_budget,
    };

    let (mut findings, task_count) = scanner::scan_ports(config, services).await;
    findings.extend(blocked_findings);
    findings.sort_by(|left, right| {
        left.port
            .cmp(&right.port)
            .then_with(|| left.protocol.cmp(&right.protocol))
    });

    let host = HostResult {
        target: request.target.clone(),
        ip: target.to_string(),
        reverse_dns: None,
        observed_mac,
        device_class,
        device_vendor,
        operating_system: None,
        phantom_device_check,
        safety_actions,
        warnings,
        ports: findings,
        risk_score: 0,
        insights: Vec::new(),
        defensive_advice: Vec::new(),
        learning_notes: Vec::new(),
        lua_findings: Vec::new(),
    };

    Ok((host, task_count))
}

fn build_blocked_port_findings(
    blocked_ports: &[u16],
    services: &ServiceRegistry,
    include_udp: bool,
) -> Vec<PortFinding> {
    let mut findings = Vec::new();
    for port in blocked_ports {
        findings.push(blocked_finding(*port, "tcp", services.lookup(*port, "tcp")));
        if include_udp {
            findings.push(blocked_finding(*port, "udp", services.lookup(*port, "udp")));
        }
    }
    findings
}

fn blocked_finding(port: u16, protocol: &str, service: Option<&str>) -> PortFinding {
    PortFinding {
        port,
        protocol: protocol.to_string(),
        state: PortState::Filtered,
        service: service.map(str::to_string),
        service_identity: None,
        banner: None,
        reason: "skipped by device-profile safety blacklist".to_string(),
        matched_by: Some("device-profile-safety".to_string()),
        confidence: Some(1.0),
        vulnerability_hints: Vec::new(),
        educational_note: Some(
            "nprobe-rs skipped this probe because the detected device class has a safety rule for this port."
                .to_string(),
        ),
        latency_ms: None,
        explanation: None,
    }
}

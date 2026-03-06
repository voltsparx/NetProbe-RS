// Flow sketch: host target -> async scan engine -> host findings.

use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use crate::engine_async::scanner::{self, AsyncScanConfig};
use crate::engine_intel::device_profile::classify_mac;
use crate::engine_intel::strategy::ScanStrategy;
use crate::engine_packet::arp as packet_arp;
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
    let base_rate_pps = request.rate_limit_pps.unwrap_or(strategy.rate_limit_pps);
    let mut rate_limit_pps = base_rate_pps;

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

                    if profile.is_fragile() && service_detection {
                        service_detection = false;
                        warnings.push(
                            "fragile-mode active: banner/service detection downgraded to passive probes"
                                .to_string(),
                        );
                        safety_actions.push("fragile-mode:passive-probes".to_string());
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
        banner: None,
        reason: "skipped by device-profile safety blacklist".to_string(),
        matched_by: Some("device-profile-safety".to_string()),
        confidence: Some(1.0),
        educational_note: Some(
            "nprobe-rs skipped this probe because the detected device class has a safety rule for this port."
                .to_string(),
        ),
        latency_ms: None,
        explanation: None,
    }
}

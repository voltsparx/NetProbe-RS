// Packet-blast runner for raw SYN scanning with async-engine-compatible output shape.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, UdpSocket};
use std::sync::Arc;
use std::time::Duration;

use crate::engine_intel::strategy::ScanStrategy;
use crate::engine_packet::socket_backend::{RawSocketRx, RawSocketTx};
use crate::engine_packet::syn_scanner::{RawPortState, RawSynScanner, RawSynScannerConfig};
use crate::error::{NProbeError, NProbeResult};
use crate::models::{HostResult, PortFinding, PortState, ScanRequest};
use crate::service_db::ServiceRegistry;

pub async fn run(
    request: &ScanRequest,
    target: IpAddr,
    ports: Vec<u16>,
    services: Arc<ServiceRegistry>,
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

    let rate_pps = request.rate_limit_pps.unwrap_or(strategy.rate_limit_pps) as u64;
    let burst_size = request.burst_size.unwrap_or(strategy.burst_size);
    let seed = request.scan_seed.unwrap_or(0x4e50_5253_5241_5753_u64);
    let source_port = source_port_from_seed(seed);
    let scan_timeout = request
        .timeout_ms
        .map(Duration::from_millis)
        .unwrap_or(strategy.recommended_timeout)
        .clamp(Duration::from_millis(150), Duration::from_secs(10));

    let scan_targets = ports
        .iter()
        .copied()
        .map(|port| (target_v4, port))
        .collect::<Vec<_>>();
    let config = RawSynScannerConfig {
        source_ip,
        source_port,
        rate_pps,
        burst_size,
        rx_grace: scan_timeout,
        scan_seed: seed,
    };

    let findings = tokio::task::spawn_blocking(move || {
        let tx = RawSocketTx::new(source_ip)?;
        let rx = RawSocketRx::new(source_ip)?;
        let scanner = RawSynScanner::new(config);
        scanner.run_with_backends(tx, rx, &scan_targets)
    })
    .await
    .map_err(NProbeError::Join)?
    .map_err(NProbeError::Io)?;

    let mut final_findings = build_default_findings(&ports, &services);
    let mut index_by_port = HashMap::<u16, usize>::with_capacity(final_findings.len());
    for (idx, finding) in final_findings.iter().enumerate() {
        index_by_port.insert(finding.port, idx);
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

    let host = HostResult {
        target: request.target.clone(),
        ip: target.to_string(),
        reverse_dns: None,
        warnings: Vec::new(),
        ports: final_findings,
        risk_score: 0,
        insights: Vec::new(),
        defensive_advice: Vec::new(),
        learning_notes: Vec::new(),
        lua_findings: Vec::new(),
    };

    Ok((host, ports.len()))
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
            banner: None,
            reason: "no response (raw-syn)".to_string(),
            matched_by: initial_service
                .as_ref()
                .map(|_| "nmap-services-port-map".to_string()),
            confidence: initial_service.as_ref().map(|_| 0.44),
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

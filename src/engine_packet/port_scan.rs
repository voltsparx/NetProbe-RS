// Packet-blast runner for raw SYN scanning with async-engine-compatible output shape.

use std::collections::HashMap;
use std::io;
use std::net::{IpAddr, Ipv4Addr, UdpSocket};
use std::sync::Arc;
use std::time::Duration;

use crate::engine_intel::strategy::ScanStrategy;
use crate::engine_packet::datalink_backend::open_layer2_backends;
use crate::engine_packet::socket_backend::{RawSocketRx, RawSocketTx};
use crate::engine_packet::syn_scanner::{
    RawPortState, RawSynScanner, RawSynScannerConfig, RawTxBackend,
};
use crate::engines::async_engine::AsyncPacketEngine;
use crate::engines::fusion_engine::{FusionEngine, PacketFusionInput};
use crate::error::{NProbeError, NProbeResult};
use crate::models::{HostResult, PortFinding, PortState, ScanRequest};
use crate::service_db::ServiceRegistry;

#[derive(Debug)]
struct BackendRunResult {
    findings: Vec<crate::engine_packet::syn_scanner::RawSynResult>,
    backend_mode: String,
}

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
    let mut fusion_engine = FusionEngine::default();
    let fusion_plan = fusion_engine.plan(PacketFusionInput {
        requested_rate_pps: rate_pps.max(1),
        burst_size,
        target_count: scan_targets.len(),
        packet_drop_ratio: 0.0,
        timeout_pressure: 0.0,
    });

    let config = RawSynScannerConfig {
        source_ip,
        source_port,
        rate_pps: fusion_plan.effective_rate_pps,
        burst_size,
        tx_workers: fusion_plan.tx_workers,
        tx_batch_size: fusion_plan.tx_batch_size,
        rx_grace: scan_timeout,
        scan_seed: seed,
    };

    let backend_result = AsyncPacketEngine::run_blocking("packet-blast", move || {
        let scanner = RawSynScanner::new(config);
        run_with_preferred_backend(scanner, source_ip, target_v4, &scan_targets)
    })
    .await
    .map_err(NProbeError::Io)?;
    let findings = backend_result.findings;

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
        warnings: vec![
            backend_result.backend_mode,
            format!(
                "fusion-engine: effective-rate={}pps tx-workers={} batch={} crafters={}",
                fusion_plan.effective_rate_pps,
                fusion_plan.tx_workers,
                fusion_plan.tx_batch_size,
                fusion_plan.active_crafters
            ),
        ],
        ports: final_findings,
        risk_score: 0,
        insights: Vec::new(),
        defensive_advice: Vec::new(),
        learning_notes: Vec::new(),
        lua_findings: Vec::new(),
    };

    Ok((host, ports.len()))
}

fn run_with_preferred_backend(
    scanner: RawSynScanner,
    source_ip: Ipv4Addr,
    target_ip: Ipv4Addr,
    scan_targets: &[(Ipv4Addr, u16)],
) -> io::Result<BackendRunResult> {
    match open_layer2_backends(source_ip, target_ip) {
        Ok((tx, rx)) => {
            let worker_count = scanner.effective_tx_workers(scan_targets.len());
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
                    "packet-blast backend: direct L2 crafted frames (kernel TCP stack bypass, tx-workers={})",
                    worker_count
                ),
            })
        }
        Err(l2_err) => {
            let worker_count = scanner.effective_tx_workers(scan_targets.len());
            let rx = RawSocketRx::new(source_ip)?;
            let findings = scanner.run_with_tx_factory(
                move |_| Ok(Box::new(RawSocketTx::new(source_ip)?) as Box<dyn RawTxBackend>),
                rx,
                scan_targets,
            )?;
            Ok(BackendRunResult {
                findings,
                backend_mode: format!(
                    "packet-blast backend fallback: raw sockets (L2 unavailable: {}, tx-workers={})",
                    l2_err, worker_count
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

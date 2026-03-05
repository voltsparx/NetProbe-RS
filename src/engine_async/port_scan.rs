// Flow sketch: host target -> async scan engine -> host findings.

use std::net::IpAddr;
use std::sync::Arc;

use crate::engine_async::scanner::{self, AsyncScanConfig};
use crate::engine_intel::strategy::ScanStrategy;
use crate::error::NProbeResult;
use crate::fingerprint_db::FingerprintDatabase;
use crate::models::{HostResult, ScanRequest};
use crate::service_db::ServiceRegistry;

pub async fn run(
    request: &ScanRequest,
    target: IpAddr,
    ports: Vec<u16>,
    services: Arc<ServiceRegistry>,
    fingerprint_db: Arc<FingerprintDatabase>,
    strategy: &ScanStrategy,
) -> NProbeResult<(HostResult, usize)> {
    let runtime = request.runtime_settings();
    let config = AsyncScanConfig {
        target,
        ports,
        include_udp: request.include_udp,
        timeout: runtime.timeout,
        concurrency: runtime.concurrency,
        dispatch_delay: runtime.delay,
        service_detection: request.service_detection,
        aggressive_root: request.aggressive_root,
        privileged_probes: request.effective_privileged_probes(),
        fingerprint_db,
        rate_limit_pps: strategy.rate_limit_pps,
        burst_size: strategy.burst_size,
        max_retries: strategy.max_retries,
    };

    let (findings, task_count) = scanner::scan_ports(config, services).await;
    let host = HostResult {
        target: request.target.clone(),
        ip: target.to_string(),
        reverse_dns: None,
        warnings: Vec::new(),
        ports: findings,
        risk_score: 0,
        insights: Vec::new(),
        defensive_advice: Vec::new(),
        learning_notes: Vec::new(),
        lua_findings: Vec::new(),
    };

    Ok((host, task_count))
}

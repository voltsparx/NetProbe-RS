// Flow sketch: host target -> task pipeline -> enriched host result
// Pseudo-block:
//   read input -> process safely -> return deterministic output

use std::net::IpAddr;
use std::sync::Arc;

use crate::engines::async_engine::{self, AsyncScanConfig};
use crate::error::NetProbeResult;
use crate::fingerprint_db::FingerprintDatabase;
use crate::models::{HostResult, ScanRequest};
use crate::service_db::ServiceRegistry;

pub async fn run(
    request: &ScanRequest,
    target: IpAddr,
    ports: Vec<u16>,
    services: Arc<ServiceRegistry>,
    fingerprint_db: Arc<FingerprintDatabase>,
) -> NetProbeResult<(HostResult, usize)> {
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
    };

    let (findings, task_count) = async_engine::scan_ports(config, services).await;
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


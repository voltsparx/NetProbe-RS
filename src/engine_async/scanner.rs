// Flow sketch: scan request -> probe engine -> raw findings
// Pseudo-block:
//   read input -> process safely -> return deterministic output
// async probes sprint; timeouts keep them from running marathons.

use std::sync::Arc;
use std::time::{Duration, Instant};
use std::{
    collections::VecDeque,
    io,
    net::{IpAddr, SocketAddr},
};

use futures::stream::{FuturesUnordered, StreamExt};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpSocket, TcpStream, UdpSocket};
use tokio::time::timeout;

use crate::fingerprint_db::{FingerprintDatabase, ProbeProtocol};
use crate::models::{PortFinding, PortState, ServiceIdentity};
use crate::service_db::ServiceRegistry;

#[derive(Debug, Clone)]
pub struct AsyncScanConfig {
    pub target: IpAddr,
    pub ports: Vec<u16>,
    pub include_udp: bool,
    pub timeout: Duration,
    pub concurrency: usize,
    pub dispatch_delay: Duration,
    pub service_detection: bool,
    pub aggressive_root: bool,
    pub privileged_probes: bool,
    pub fingerprint_db: Arc<FingerprintDatabase>,
    pub rate_limit_pps: u32,
    pub burst_size: usize,
    pub max_retries: u8,
    pub scan_seed: Option<u64>,
    pub fingerprint_payload_budget: usize,
}

#[derive(Debug, Clone)]
struct ProbeSharedContext {
    target: IpAddr,
    timeout_value: Duration,
    aggressive_root: bool,
    privileged_probes: bool,
    max_retries: u8,
    fingerprint_payload_budget: usize,
    services: Arc<ServiceRegistry>,
    fingerprint_db: Arc<FingerprintDatabase>,
}

#[derive(Debug, Clone)]
struct TcpProbeRequest {
    port: u16,
    service_detection: bool,
    shared: ProbeSharedContext,
}

#[derive(Debug, Clone)]
struct UdpProbeRequest {
    port: u16,
    shared: ProbeSharedContext,
}

#[derive(Debug, Clone)]
struct DetectionEvidence {
    banner: Option<String>,
    service: Option<String>,
    service_identity: Option<ServiceIdentity>,
    matched_by: Option<String>,
    confidence: Option<f32>,
}

#[derive(Debug, Clone, Copy)]
enum ProbeFeedback {
    Success(Duration),
    Timeout,
    Error,
}

#[derive(Debug, Clone)]
struct AdaptiveProbeController {
    base_timeout: Duration,
    min_timeout: Duration,
    max_timeout: Duration,
    srtt_ms: f64,
    rttvar_ms: f64,
    samples: u64,
    success_count: u64,
    timeout_count: u64,
    error_count: u64,
    max_window: usize,
}

#[derive(Debug, Clone)]
struct RateGovernor {
    configured_rate_pps: u32,
    effective_rate_pps: f64,
    min_rate_pps: f64,
    max_rate_pps: f64,
    success_credit: u8,
    burst_size: usize,
    tokens: f64,
    last_refill: Instant,
}

impl AdaptiveProbeController {
    fn new(base_timeout: Duration, max_window: usize) -> Self {
        let base_ms = duration_to_ms(base_timeout).clamp(120, 3500);
        let min_timeout = Duration::from_millis((base_ms / 4).clamp(80, 900));
        let max_timeout = Duration::from_millis((base_ms * 4).clamp(500, 10_000));
        Self {
            base_timeout: Duration::from_millis(base_ms),
            min_timeout,
            max_timeout,
            srtt_ms: base_ms as f64,
            rttvar_ms: (base_ms as f64) / 2.0,
            samples: 0,
            success_count: 0,
            timeout_count: 0,
            error_count: 0,
            max_window: max_window.max(1),
        }
    }

    fn current_timeout(&self) -> Duration {
        if self.samples == 0 {
            return self.base_timeout;
        }

        let rto_ms = (self.srtt_ms + (4.0 * self.rttvar_ms)).round() as u64;
        Duration::from_millis(rto_ms).clamp(self.min_timeout, self.max_timeout)
    }

    fn current_window(&self) -> usize {
        if self.max_window <= 4 {
            return self.max_window;
        }

        let total = self.success_count + self.timeout_count + self.error_count;
        if total < 16 {
            return self.max_window.min(64);
        }

        let timeout_ratio = self.timeout_count as f64 / total as f64;
        let error_ratio = self.error_count as f64 / total as f64;
        let factor = if timeout_ratio > 0.45 || error_ratio > 0.30 {
            0.20
        } else if timeout_ratio > 0.30 || error_ratio > 0.20 {
            0.35
        } else if timeout_ratio > 0.18 {
            0.55
        } else if timeout_ratio > 0.10 {
            0.75
        } else {
            1.0
        };

        let floor = (self.max_window / 8).max(4);
        ((self.max_window as f64 * factor).round() as usize).clamp(floor, self.max_window)
    }

    fn dispatch_delay(&self, base_delay: Duration) -> Duration {
        let total = self.success_count + self.timeout_count + self.error_count;
        if total == 0 {
            return base_delay;
        }

        let timeout_ratio = self.timeout_count as f64 / total as f64;
        let pressure_delay = if timeout_ratio > 0.45 {
            Duration::from_millis(7)
        } else if timeout_ratio > 0.30 {
            Duration::from_millis(4)
        } else if timeout_ratio > 0.18 {
            Duration::from_millis(2)
        } else {
            Duration::ZERO
        };

        base_delay.max(pressure_delay)
    }

    fn observe(&mut self, feedback: ProbeFeedback) {
        match feedback {
            ProbeFeedback::Success(rtt) => {
                let rtt_ms = duration_to_ms(rtt).max(1) as f64;
                if self.samples == 0 {
                    self.srtt_ms = rtt_ms;
                    self.rttvar_ms = rtt_ms / 2.0;
                } else {
                    // Jacobson/Karels-style smoothing for adaptive probe timeout.
                    let err = (self.srtt_ms - rtt_ms).abs();
                    self.rttvar_ms = (0.75 * self.rttvar_ms) + (0.25 * err);
                    self.srtt_ms = (0.875 * self.srtt_ms) + (0.125 * rtt_ms);
                }
                self.samples += 1;
                self.success_count += 1;
            }
            ProbeFeedback::Timeout => {
                self.timeout_count += 1;
                self.rttvar_ms =
                    (self.rttvar_ms * 1.20).min(duration_to_ms(self.max_timeout) as f64);
            }
            ProbeFeedback::Error => {
                self.error_count += 1;
                self.rttvar_ms =
                    (self.rttvar_ms * 1.08).min(duration_to_ms(self.max_timeout) as f64);
            }
        }
    }
}

impl RateGovernor {
    fn new(rate_pps: u32, burst_size: usize) -> Self {
        let burst = burst_size.max(1);
        let max_rate_pps = rate_pps as f64;
        let min_rate_pps = if rate_pps == 0 {
            0.0
        } else {
            (max_rate_pps * 0.10).max(64.0)
        };
        Self {
            configured_rate_pps: rate_pps,
            effective_rate_pps: max_rate_pps,
            min_rate_pps,
            max_rate_pps,
            success_credit: 0,
            burst_size: burst,
            tokens: burst as f64,
            last_refill: Instant::now(),
        }
    }

    async fn wait_for_slot(&mut self) {
        if self.configured_rate_pps == 0 {
            return;
        }

        loop {
            self.refill();
            if self.tokens >= 1.0 {
                self.tokens -= 1.0;
                return;
            }

            let missing = (1.0 - self.tokens).max(0.01);
            let wait_secs = missing / self.effective_rate_pps.max(1.0);
            let wait = Duration::from_secs_f64(wait_secs)
                .clamp(Duration::from_millis(1), Duration::from_millis(50));
            tokio::time::sleep(wait).await;
        }
    }

    fn refill(&mut self) {
        if self.configured_rate_pps == 0 {
            return;
        }

        let now = Instant::now();
        let elapsed = now.saturating_duration_since(self.last_refill);
        self.last_refill = now;
        if elapsed.is_zero() {
            return;
        }

        let added = elapsed.as_secs_f64() * self.effective_rate_pps.max(1.0);
        self.tokens = (self.tokens + added).min(self.effective_burst_cap());
    }

    fn observe(&mut self, feedback: ProbeFeedback) {
        if self.configured_rate_pps == 0 {
            return;
        }

        match feedback {
            ProbeFeedback::Success(_) => {
                self.success_credit = self.success_credit.saturating_add(1);
                if self.success_credit >= 10 {
                    let add_step = (self.max_rate_pps * 0.04).max(16.0);
                    self.effective_rate_pps =
                        (self.effective_rate_pps + add_step).min(self.max_rate_pps);
                    self.success_credit = 0;
                }
            }
            ProbeFeedback::Timeout => {
                self.success_credit = 0;
                let downshift = if self.effective_rate_pps > self.max_rate_pps * 0.55 {
                    0.78
                } else {
                    0.88
                };
                self.effective_rate_pps = (self.effective_rate_pps * downshift)
                    .clamp(self.min_rate_pps, self.max_rate_pps);
            }
            ProbeFeedback::Error => {
                self.success_credit = 0;
                self.effective_rate_pps =
                    (self.effective_rate_pps * 0.92).clamp(self.min_rate_pps, self.max_rate_pps);
            }
        }

        self.tokens = self.tokens.min(self.effective_burst_cap());
    }

    fn effective_burst_cap(&self) -> f64 {
        if self.configured_rate_pps == 0 {
            return self.burst_size as f64;
        }

        let ratio = if self.max_rate_pps > 0.0 {
            (self.effective_rate_pps / self.max_rate_pps).clamp(0.10, 1.0)
        } else {
            1.0
        };
        let scaled = (self.burst_size as f64 * ratio).ceil();
        scaled.clamp(4.0, self.burst_size as f64)
    }
}

pub async fn scan_ports(
    config: AsyncScanConfig,
    services: Arc<ServiceRegistry>,
) -> (Vec<PortFinding>, usize) {
    let mut findings = Vec::new();
    let mut task_count = 0usize;

    let tcp = scan_tcp(&config, services.clone()).await;
    task_count += tcp.len();
    findings.extend(tcp);

    if config.include_udp {
        let udp = scan_udp(&config, services).await;
        task_count += udp.len();
        findings.extend(udp);
    }

    findings.sort_by(|a, b| {
        a.port
            .cmp(&b.port)
            .then_with(|| a.protocol.cmp(&b.protocol))
    });
    (findings, task_count)
}

async fn scan_tcp(config: &AsyncScanConfig, services: Arc<ServiceRegistry>) -> Vec<PortFinding> {
    let mut queue = VecDeque::from(shuffled_ports(
        &config.ports,
        protocol_seed(config.target, 0x5450_435f_5343_414e, config.scan_seed),
    ));
    let mut in_flight = FuturesUnordered::new();
    let mut findings = Vec::with_capacity(config.ports.len());
    let mut control = AdaptiveProbeController::new(config.timeout, config.concurrency);
    let mut governor = RateGovernor::new(config.rate_limit_pps, config.burst_size);

    while !queue.is_empty() || !in_flight.is_empty() {
        let max_window = control.current_window().max(1);
        let timeout_value = control.current_timeout();
        let dispatch_delay = control.dispatch_delay(config.dispatch_delay);

        while in_flight.len() < max_window {
            let Some(port) = queue.pop_front() else {
                break;
            };
            governor.wait_for_slot().await;

            let request = TcpProbeRequest {
                port,
                service_detection: config.service_detection,
                shared: ProbeSharedContext {
                    target: config.target,
                    timeout_value,
                    aggressive_root: config.aggressive_root,
                    privileged_probes: config.privileged_probes,
                    max_retries: config.max_retries,
                    fingerprint_payload_budget: config.fingerprint_payload_budget,
                    services: services.clone(),
                    fingerprint_db: config.fingerprint_db.clone(),
                },
            };

            in_flight.push(scan_one_tcp(request));

            if !dispatch_delay.is_zero() {
                tokio::time::sleep(dispatch_delay).await;
            }
        }

        if let Some(finding) = in_flight.next().await {
            let feedback = classify_feedback(&finding);
            control.observe(feedback);
            governor.observe(feedback);
            findings.push(finding);
        }
    }

    findings
}

async fn scan_udp(config: &AsyncScanConfig, services: Arc<ServiceRegistry>) -> Vec<PortFinding> {
    let mut queue = VecDeque::from(shuffled_ports(
        &config.ports,
        protocol_seed(config.target, 0x5544_505f_5343_414e, config.scan_seed),
    ));
    let mut in_flight = FuturesUnordered::new();
    let mut findings = Vec::with_capacity(config.ports.len());
    let mut control = AdaptiveProbeController::new(config.timeout, config.concurrency);
    let mut governor = RateGovernor::new(config.rate_limit_pps, config.burst_size);

    while !queue.is_empty() || !in_flight.is_empty() {
        let max_window = control.current_window().max(1);
        let timeout_value = control.current_timeout();
        let dispatch_delay = control.dispatch_delay(config.dispatch_delay);

        while in_flight.len() < max_window {
            let Some(port) = queue.pop_front() else {
                break;
            };
            governor.wait_for_slot().await;

            let request = UdpProbeRequest {
                port,
                shared: ProbeSharedContext {
                    target: config.target,
                    timeout_value,
                    aggressive_root: config.aggressive_root,
                    privileged_probes: config.privileged_probes,
                    max_retries: config.max_retries,
                    fingerprint_payload_budget: config.fingerprint_payload_budget,
                    services: services.clone(),
                    fingerprint_db: config.fingerprint_db.clone(),
                },
            };

            in_flight.push(scan_one_udp(request));

            if !dispatch_delay.is_zero() {
                tokio::time::sleep(dispatch_delay).await;
            }
        }

        if let Some(finding) = in_flight.next().await {
            let feedback = classify_feedback(&finding);
            control.observe(feedback);
            governor.observe(feedback);
            findings.push(finding);
        }
    }

    findings
}

fn classify_feedback(finding: &PortFinding) -> ProbeFeedback {
    let reason_lower = finding.reason.to_ascii_lowercase();
    let timeout_like = reason_lower.contains("timed out")
        || reason_lower.contains("timeout")
        || reason_lower.contains("no response")
        || reason_lower.contains("no udp reply");

    if let Some(latency) = finding.latency_ms {
        let duration = Duration::from_millis(latency.min(u64::MAX as u128) as u64);
        if matches!(finding.state, PortState::Open | PortState::Closed) {
            return ProbeFeedback::Success(duration);
        }
        if !timeout_like {
            return ProbeFeedback::Error;
        }
    }

    if timeout_like
        || matches!(
            finding.state,
            PortState::Filtered | PortState::OpenOrFiltered
        )
    {
        ProbeFeedback::Timeout
    } else {
        ProbeFeedback::Error
    }
}

fn duration_to_ms(duration: Duration) -> u64 {
    duration.as_millis().min(u64::MAX as u128) as u64
}

fn shuffled_ports(ports: &[u16], seed: u64) -> Vec<u16> {
    let mut out = ports.to_vec();
    if out.len() < 2 {
        return out;
    }

    let mut state = if seed == 0 {
        0x9e37_79b9_7f4a_7c15
    } else {
        seed
    };

    for idx in (1..out.len()).rev() {
        state = xorshift64(state);
        let swap_idx = (state as usize) % (idx + 1);
        out.swap(idx, swap_idx);
    }
    out
}

fn xorshift64(mut value: u64) -> u64 {
    value ^= value << 13;
    value ^= value >> 7;
    value ^= value << 17;
    value
}

fn protocol_seed(target: IpAddr, marker: u64, custom_seed: Option<u64>) -> u64 {
    const FNV_OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
    const FNV_PRIME: u64 = 0x0000_0100_0000_01b3;

    let mut seed = FNV_OFFSET ^ marker;
    match target {
        IpAddr::V4(addr) => {
            for byte in addr.octets() {
                seed ^= byte as u64;
                seed = seed.wrapping_mul(FNV_PRIME);
            }
        }
        IpAddr::V6(addr) => {
            for byte in addr.octets() {
                seed ^= byte as u64;
                seed = seed.wrapping_mul(FNV_PRIME);
            }
        }
    }
    seed ^ custom_seed.unwrap_or(0)
}

async fn scan_one_tcp(request: TcpProbeRequest) -> PortFinding {
    let TcpProbeRequest {
        port,
        service_detection,
        shared,
    } = request;
    let ProbeSharedContext {
        target,
        timeout_value,
        aggressive_root,
        privileged_probes,
        max_retries,
        fingerprint_payload_budget,
        services,
        fingerprint_db,
    } = shared;

    let initial_service = services.lookup(port, "tcp").map(ToOwned::to_owned);
    let mut finding = PortFinding {
        port,
        protocol: "tcp".to_string(),
        state: PortState::Filtered,
        service: initial_service.clone(),
        service_identity: None,
        banner: None,
        reason: "no response".to_string(),
        matched_by: initial_service
            .as_ref()
            .map(|_| "nmap-services-port-map".to_string()),
        confidence: initial_service.as_ref().map(|_| 0.46),
        vulnerability_hints: Vec::new(),
        educational_note: None,
        latency_ms: None,
        explanation: None,
    };

    let start = Instant::now();
    let mut open_stream = None;
    match timeout(timeout_value, connect_tcp(target, port, privileged_probes)).await {
        Ok(Ok(stream)) => {
            finding.state = PortState::Open;
            finding.reason = if privileged_probes {
                "tcp handshake completed (privileged source probe)".to_string()
            } else {
                "tcp handshake completed".to_string()
            };
            finding.latency_ms = Some(start.elapsed().as_millis());
            open_stream = Some(stream);
        }
        Ok(Err(err)) => match err.kind() {
            io::ErrorKind::ConnectionRefused => {
                finding.state = PortState::Closed;
                finding.reason = "connection refused (likely RST)".to_string();
                finding.latency_ms = Some(start.elapsed().as_millis());
            }
            io::ErrorKind::TimedOut => {
                finding.state = PortState::Filtered;
                finding.reason = "timeout waiting for connect".to_string();
            }
            _ => {
                finding.state = PortState::Filtered;
                finding.reason = format!("connect error: {}", err);
            }
        },
        Err(_) => {
            finding.state = PortState::Filtered;
            finding.reason = "probe timed out".to_string();
        }
    }

    let adaptive_retry_budget = max_retries as usize + usize::from(aggressive_root);
    for retry_index in 0..adaptive_retry_budget {
        if !matches!(finding.state, PortState::Filtered) {
            break;
        }

        let retry_timeout = timeout_value
            .max(Duration::from_millis(450))
            .saturating_add(Duration::from_millis(200 + (retry_index as u64 * 120)));
        match timeout(retry_timeout, connect_tcp(target, port, privileged_probes)).await {
            Ok(Ok(stream)) => {
                finding.state = PortState::Open;
                finding.reason = if retry_index == 0 && aggressive_root {
                    "tcp handshake completed on aggressive retry".to_string()
                } else {
                    format!(
                        "tcp handshake completed on adaptive retry {}",
                        retry_index + 1
                    )
                };
                finding.latency_ms = Some(start.elapsed().as_millis());
                open_stream = Some(stream);
                break;
            }
            Ok(Err(err)) if err.kind() == io::ErrorKind::ConnectionRefused => {
                finding.state = PortState::Closed;
                finding.reason = if retry_index == 0 && aggressive_root {
                    "connection refused on aggressive retry".to_string()
                } else {
                    format!("connection refused on adaptive retry {}", retry_index + 1)
                };
                finding.latency_ms = Some(start.elapsed().as_millis());
                break;
            }
            Ok(Err(err)) => {
                finding.reason = format!(
                    "{}; retry {} connect error: {}",
                    finding.reason,
                    retry_index + 1,
                    err
                );
            }
            Err(_) => {
                finding.reason = format!("{}; retry {} timed out", finding.reason, retry_index + 1);
            }
        }
    }

    if service_detection {
        if let Some(mut stream) = open_stream {
            let evidence = attempt_banner_and_fingerprint(
                &mut stream,
                port,
                timeout_value,
                fingerprint_db,
                ProbeProtocol::Tcp,
                fingerprint_payload_budget,
            )
            .await;
            if evidence.banner.is_some() {
                finding.banner = evidence.banner;
            }
            if evidence.service.is_some() {
                finding.service = evidence.service;
            }
            if evidence.service_identity.is_some() {
                finding.service_identity = evidence.service_identity;
            }
            if evidence.matched_by.is_some() {
                finding.matched_by = evidence.matched_by;
            }
            if evidence.confidence.is_some() {
                finding.confidence = evidence.confidence;
            }
        }
    }

    finding
}

async fn scan_one_udp(request: UdpProbeRequest) -> PortFinding {
    let UdpProbeRequest { port, shared } = request;
    let ProbeSharedContext {
        target,
        timeout_value,
        aggressive_root,
        privileged_probes,
        max_retries,
        fingerprint_payload_budget,
        services,
        fingerprint_db,
    } = shared;

    let initial_service = services.lookup(port, "udp").map(ToOwned::to_owned);
    let mut finding = PortFinding {
        port,
        protocol: "udp".to_string(),
        state: PortState::OpenOrFiltered,
        service: initial_service.clone(),
        service_identity: None,
        banner: None,
        reason: "no ICMP unreachable seen".to_string(),
        matched_by: initial_service
            .as_ref()
            .map(|_| "nmap-services-port-map".to_string()),
        confidence: initial_service.as_ref().map(|_| 0.43),
        vulnerability_hints: Vec::new(),
        educational_note: None,
        latency_ms: None,
        explanation: None,
    };

    let socket = match bind_udp_probe_socket(target, port, privileged_probes).await {
        Ok(sock) => sock,
        Err(err) => {
            finding.state = PortState::Filtered;
            finding.reason = format!("udp bind error: {}", err);
            return finding;
        }
    };

    if let Err(err) = socket.connect((target, port)).await {
        finding.state = PortState::Filtered;
        finding.reason = format!("udp connect error: {}", err);
        return finding;
    }

    let start = Instant::now();
    let mut payloads =
        fingerprint_db.payloads_for(ProbeProtocol::Udp, port, fingerprint_payload_budget.max(1));
    if payloads.is_empty() {
        payloads.push(vec![0x00]);
    }

    match udp_probe_once(
        &socket,
        &payloads[0],
        timeout_value,
        Duration::from_millis(350),
    )
    .await
    {
        UdpProbeOutcome::Response(buffer) => {
            finding.state = PortState::Open;
            finding.reason = "udp response payload received".to_string();
            finding.latency_ms = Some(start.elapsed().as_millis());
            finding.banner = Some(sanitize_banner(&buffer));

            if let Some(matched) = fingerprint_db.match_banner(ProbeProtocol::Udp, port, &buffer) {
                finding.service = Some(matched.service);
                finding.service_identity = Some(matched.identity);
                finding.matched_by = Some(if matched.soft {
                    format!("fingerprint-soft:{}", matched.source)
                } else {
                    format!("fingerprint-hard:{}", matched.source)
                });
                finding.confidence = Some(matched.confidence);
            } else if let Some(heuristic) = infer_service_from_banner(&buffer) {
                finding.service = Some(heuristic);
                finding.matched_by = Some("banner-heuristic".to_string());
                finding.confidence = Some(0.56);
            }
        }
        UdpProbeOutcome::Closed => {
            finding.state = PortState::Closed;
            finding.reason = "icmp port unreachable / connection refused".to_string();
            finding.latency_ms = Some(start.elapsed().as_millis());
        }
        UdpProbeOutcome::NoReply => {
            finding.state = PortState::OpenOrFiltered;
            finding.reason = "no udp reply (open|filtered)".to_string();
            finding.latency_ms = Some(start.elapsed().as_millis());
        }
        UdpProbeOutcome::Error(err) => {
            finding.state = PortState::Filtered;
            finding.reason = err;
            finding.latency_ms = Some(start.elapsed().as_millis());
        }
    }

    let adaptive_retry_budget = max_retries as usize + usize::from(aggressive_root);
    for retry_index in 0..adaptive_retry_budget {
        if !matches!(
            finding.state,
            PortState::OpenOrFiltered | PortState::Filtered
        ) {
            break;
        }

        let retry_payload = payloads
            .get((retry_index + 1).min(payloads.len().saturating_sub(1)))
            .cloned()
            .unwrap_or_else(|| payloads[0].clone());
        match udp_probe_once(
            &socket,
            &retry_payload,
            timeout_value
                .max(Duration::from_millis(450))
                .saturating_add(Duration::from_millis(200 + (retry_index as u64 * 140))),
            Duration::from_millis(650 + (retry_index as u64 * 120)),
        )
        .await
        {
            UdpProbeOutcome::Response(buffer) => {
                finding.state = PortState::Open;
                finding.reason = if retry_index == 0 && aggressive_root {
                    "udp response payload received on aggressive retry".to_string()
                } else {
                    format!(
                        "udp response payload received on adaptive retry {}",
                        retry_index + 1
                    )
                };
                finding.latency_ms = Some(start.elapsed().as_millis());
                finding.banner = Some(sanitize_banner(&buffer));
                if let Some(matched) =
                    fingerprint_db.match_banner(ProbeProtocol::Udp, port, &buffer)
                {
                    finding.service = Some(matched.service);
                    finding.service_identity = Some(matched.identity);
                    finding.matched_by = Some(if matched.soft {
                        format!("fingerprint-soft:{}", matched.source)
                    } else {
                        format!("fingerprint-hard:{}", matched.source)
                    });
                    finding.confidence = Some(matched.confidence);
                } else if let Some(heuristic) = infer_service_from_banner(&buffer) {
                    finding.service = Some(heuristic);
                    finding.matched_by = Some("banner-heuristic".to_string());
                    finding.confidence = Some(0.56);
                }
                break;
            }
            UdpProbeOutcome::Closed => {
                finding.state = PortState::Closed;
                finding.reason = if retry_index == 0 && aggressive_root {
                    "icmp port unreachable on aggressive retry".to_string()
                } else {
                    format!(
                        "icmp port unreachable on adaptive retry {}",
                        retry_index + 1
                    )
                };
                finding.latency_ms = Some(start.elapsed().as_millis());
                break;
            }
            UdpProbeOutcome::NoReply => {
                finding.reason =
                    format!("{}; retry {} got no reply", finding.reason, retry_index + 1);
            }
            UdpProbeOutcome::Error(err) => {
                finding.reason = format!(
                    "{}; retry {} error: {}",
                    finding.reason,
                    retry_index + 1,
                    err
                );
            }
        }
    }

    finding
}

const PRIVILEGED_SOURCE_PORTS: [u16; 8] = [20, 53, 67, 68, 80, 123, 161, 443];

enum UdpProbeOutcome {
    Response(Vec<u8>),
    Closed,
    NoReply,
    Error(String),
}

async fn connect_tcp(target: IpAddr, port: u16, privileged_probes: bool) -> io::Result<TcpStream> {
    if !privileged_probes {
        return TcpStream::connect((target, port)).await;
    }

    let remote = SocketAddr::new(target, port);
    let mut last_err = None;
    for source_port in privileged_source_ports(port) {
        let socket = match target {
            IpAddr::V4(_) => TcpSocket::new_v4(),
            IpAddr::V6(_) => TcpSocket::new_v6(),
        }?;

        match socket.bind(wildcard_bind_addr(target, source_port)) {
            Ok(_) => match socket.connect(remote).await {
                Ok(stream) => return Ok(stream),
                Err(err) => last_err = Some(err),
            },
            Err(err) if err.kind() == io::ErrorKind::PermissionDenied => return Err(err),
            Err(err) => last_err = Some(err),
        }
    }

    TcpStream::connect(remote)
        .await
        .map_err(|err| last_err.unwrap_or(err))
}

async fn bind_udp_probe_socket(
    target: IpAddr,
    port: u16,
    privileged_probes: bool,
) -> io::Result<UdpSocket> {
    if !privileged_probes {
        return UdpSocket::bind(wildcard_bind_addr(target, 0)).await;
    }

    let mut last_err = None;
    for source_port in privileged_source_ports(port) {
        match UdpSocket::bind(wildcard_bind_addr(target, source_port)).await {
            Ok(socket) => return Ok(socket),
            Err(err) if err.kind() == io::ErrorKind::PermissionDenied => return Err(err),
            Err(err) => last_err = Some(err),
        }
    }

    UdpSocket::bind(wildcard_bind_addr(target, 0))
        .await
        .map_err(|err| last_err.unwrap_or(err))
}

async fn udp_probe_once(
    socket: &UdpSocket,
    payload: &[u8],
    send_timeout: Duration,
    receive_timeout: Duration,
) -> UdpProbeOutcome {
    match timeout(send_timeout, socket.send(payload)).await {
        Ok(Ok(_)) => {
            let mut buffer = [0u8; 512];
            match timeout(receive_timeout, socket.recv(&mut buffer)).await {
                Ok(Ok(bytes)) if bytes > 0 => UdpProbeOutcome::Response(buffer[..bytes].to_vec()),
                Ok(Ok(_)) => UdpProbeOutcome::NoReply,
                Ok(Err(err)) if err.kind() == io::ErrorKind::ConnectionRefused => {
                    UdpProbeOutcome::Closed
                }
                Ok(Err(err)) => UdpProbeOutcome::Error(format!("udp recv error: {}", err)),
                Err(_) => UdpProbeOutcome::NoReply,
            }
        }
        Ok(Err(err)) if err.kind() == io::ErrorKind::ConnectionRefused => UdpProbeOutcome::Closed,
        Ok(Err(err)) => UdpProbeOutcome::Error(format!("udp send error: {}", err)),
        Err(_) => UdpProbeOutcome::NoReply,
    }
}

fn wildcard_bind_addr(target: IpAddr, port: u16) -> SocketAddr {
    match target {
        IpAddr::V4(_) => SocketAddr::from(([0, 0, 0, 0], port)),
        IpAddr::V6(_) => SocketAddr::from(([0, 0, 0, 0, 0, 0, 0, 0], port)),
    }
}

fn privileged_source_ports(seed_port: u16) -> Vec<u16> {
    let len = PRIVILEGED_SOURCE_PORTS.len();
    if len == 0 {
        return Vec::new();
    }
    let offset = seed_port as usize % len;
    (0..len)
        .map(|idx| PRIVILEGED_SOURCE_PORTS[(offset + idx) % len])
        .collect()
}

async fn attempt_banner_and_fingerprint(
    stream: &mut TcpStream,
    port: u16,
    timeout_value: Duration,
    fingerprint_db: Arc<FingerprintDatabase>,
    protocol: ProbeProtocol,
    fingerprint_payload_budget: usize,
) -> DetectionEvidence {
    let mut best_banner = None;

    if let Some(raw) = read_response(stream, Duration::from_millis(220)).await {
        let banner_text = sanitize_banner(&raw);
        best_banner = Some(banner_text);
        if let Some(matched) = fingerprint_db.match_banner(protocol, port, &raw) {
            return DetectionEvidence {
                banner: best_banner,
                service: Some(matched.service),
                service_identity: Some(matched.identity),
                matched_by: Some(if matched.soft {
                    format!("fingerprint-soft:{}", matched.source)
                } else {
                    format!("fingerprint-hard:{}", matched.source)
                }),
                confidence: Some(matched.confidence),
            };
        }
    }

    if fingerprint_payload_budget == 0 {
        return DetectionEvidence {
            banner: best_banner,
            service: None,
            service_identity: None,
            matched_by: None,
            confidence: None,
        };
    }

    let mut payloads = fingerprint_db.payloads_for(protocol, port, fingerprint_payload_budget);
    if payloads.is_empty() {
        payloads.push(default_probe_payload(port));
    }

    for payload in payloads {
        if !payload.is_empty()
            && timeout(timeout_value, stream.write_all(&payload))
                .await
                .is_err()
        {
            continue;
        }

        if let Some(raw) = read_response(stream, Duration::from_millis(420)).await {
            let banner_text = sanitize_banner(&raw);
            if best_banner.is_none() {
                best_banner = Some(banner_text.clone());
            }

            if let Some(matched) = fingerprint_db.match_banner(protocol, port, &raw) {
                return DetectionEvidence {
                    banner: Some(banner_text),
                    service: Some(matched.service),
                    service_identity: Some(matched.identity),
                    matched_by: Some(if matched.soft {
                        format!("fingerprint-soft:{}", matched.source)
                    } else {
                        format!("fingerprint-hard:{}", matched.source)
                    }),
                    confidence: Some(matched.confidence),
                };
            }

            if let Some(heuristic) = infer_service_from_sanitized_banner(&banner_text) {
                return DetectionEvidence {
                    banner: Some(banner_text),
                    service: Some(heuristic),
                    service_identity: None,
                    matched_by: Some("banner-heuristic".to_string()),
                    confidence: Some(0.57),
                };
            }
        }
    }

    DetectionEvidence {
        banner: best_banner,
        service: None,
        service_identity: None,
        matched_by: None,
        confidence: None,
    }
}

async fn read_response(stream: &mut TcpStream, wait: Duration) -> Option<Vec<u8>> {
    let mut buf = [0u8; 1024];
    match timeout(wait, stream.read(&mut buf)).await {
        Ok(Ok(bytes)) if bytes > 0 => Some(buf[..bytes].to_vec()),
        _ => None,
    }
}

fn default_probe_payload(port: u16) -> Vec<u8> {
    match port {
        80 | 8000 | 8080 | 8888 => b"HEAD / HTTP/1.0\r\nHost: target\r\n\r\n".to_vec(),
        21 => b"HELP\r\n".to_vec(),
        25 | 587 => b"EHLO nprobe.local\r\n".to_vec(),
        110 => b"CAPA\r\n".to_vec(),
        143 => b"A1 CAPABILITY\r\n".to_vec(),
        6379 => b"PING\r\n".to_vec(),
        _ => b"\r\n".to_vec(),
    }
}

fn infer_service_from_sanitized_banner(banner: &str) -> Option<String> {
    let banner = banner.to_ascii_lowercase();
    if banner.contains("ssh-") {
        return Some("ssh".to_string());
    }
    if banner.contains("smtp") || banner.contains("esmtp") {
        return Some("smtp".to_string());
    }
    if banner.contains("http/1.") || banner.contains("server:") {
        return Some("http".to_string());
    }
    if banner.contains("imap") {
        return Some("imap".to_string());
    }
    if banner.contains("pop3") {
        return Some("pop3".to_string());
    }
    if banner.contains("ftp") {
        return Some("ftp".to_string());
    }
    if banner.contains("redis") || banner.starts_with("+pong") {
        return Some("redis".to_string());
    }
    None
}

fn infer_service_from_banner(raw: &[u8]) -> Option<String> {
    let banner = sanitize_banner(raw);
    infer_service_from_sanitized_banner(&banner)
}

fn sanitize_banner(raw: &[u8]) -> String {
    let mut out = String::with_capacity(raw.len().min(220));
    let mut last_was_space = false;
    for byte in raw.iter().copied().take(220) {
        if byte.is_ascii_graphic() || byte == b' ' {
            let ch = char::from(byte);
            if ch == ' ' {
                if !last_was_space {
                    out.push(' ');
                    last_was_space = true;
                }
            } else {
                out.push(ch);
                last_was_space = false;
            }
        } else if (byte == b'\r' || byte == b'\n' || byte == b'\t') && !last_was_space {
            out.push(' ');
            last_was_space = true;
        }
    }
    out.trim().to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shuffled_ports_is_deterministic_for_seed() {
        let source = vec![22, 80, 443, 8080, 3306, 5432];
        let first = shuffled_ports(&source, 0x1234_5678_9abc_def0);
        let second = shuffled_ports(&source, 0x1234_5678_9abc_def0);
        assert_eq!(first, second);
        assert_ne!(first, source);
    }

    #[test]
    fn adaptive_timeout_moves_toward_observed_rtt() {
        let mut control = AdaptiveProbeController::new(Duration::from_millis(1200), 256);
        let before = control.current_timeout();
        for _ in 0..16 {
            control.observe(ProbeFeedback::Success(Duration::from_millis(80)));
        }
        let after = control.current_timeout();
        assert!(after < before);
        assert!(after <= Duration::from_millis(600));
    }

    #[test]
    fn adaptive_window_drops_under_timeout_pressure() {
        let mut control = AdaptiveProbeController::new(Duration::from_millis(700), 512);
        for _ in 0..48 {
            control.observe(ProbeFeedback::Timeout);
        }
        let window = control.current_window();
        assert!(window < 512);
        assert!(window >= 4);
    }

    #[test]
    fn governor_backs_off_under_timeouts() {
        let mut governor = RateGovernor::new(8_000, 128);
        let baseline = governor.effective_rate_pps;
        for _ in 0..6 {
            governor.observe(ProbeFeedback::Timeout);
        }
        assert!(governor.effective_rate_pps < baseline);
        assert!(governor.effective_rate_pps >= governor.min_rate_pps);
    }

    #[test]
    fn governor_recovers_after_stable_success() {
        let mut governor = RateGovernor::new(6_000, 96);
        for _ in 0..5 {
            governor.observe(ProbeFeedback::Timeout);
        }
        let slowed = governor.effective_rate_pps;
        for _ in 0..40 {
            governor.observe(ProbeFeedback::Success(Duration::from_millis(50)));
        }
        assert!(governor.effective_rate_pps > slowed);
        assert!(governor.effective_rate_pps <= governor.max_rate_pps);
    }
}

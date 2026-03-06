// Multi-stage TCP probe pipeline:
// 1) generic probe for fast narrowing
// 2) targeted probes from parsed nmap-service-probes payloads
// 3) regex/heuristic matching to set service identity

use std::collections::VecDeque;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use futures::stream::{FuturesUnordered, StreamExt};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

use crate::fingerprint_db::{FingerprintDatabase, ProbeProtocol};
use crate::models::{PortFinding, PortState};

#[derive(Debug, Clone, Default)]
pub struct MultiStageProbeReport {
    pub tasks_spawned: usize,
    pub services_identified: usize,
    pub notes: Vec<String>,
}

#[derive(Debug, Clone, Default)]
pub struct MultiStageProbePolicy {
    pub max_concurrency: usize,
    pub fragile_mode: bool,
    pub safety_blacklist: Vec<u16>,
}

#[derive(Debug, Clone)]
struct PortProbeUpdate {
    index: usize,
    banner: Option<String>,
    service: Option<String>,
    matched_by: Option<String>,
    confidence: Option<f32>,
    stage: &'static str,
}

pub async fn run_multi_stage_tcp_probe_pipeline(
    target: IpAddr,
    findings: &mut [PortFinding],
    fingerprint_db: Arc<FingerprintDatabase>,
    timeout_budget: Duration,
    policy: MultiStageProbePolicy,
) -> MultiStageProbeReport {
    let mut report = MultiStageProbeReport::default();
    let mut candidates = VecDeque::new();
    let mut blacklisted_ports = Vec::new();

    for (index, finding) in findings.iter().enumerate() {
        if finding.protocol != "tcp" || !matches!(finding.state, PortState::Open) {
            continue;
        }
        if policy.safety_blacklist.contains(&finding.port) {
            blacklisted_ports.push(finding.port);
            continue;
        }
        candidates.push_back((index, finding.port));
    }

    if !blacklisted_ports.is_empty() {
        blacklisted_ports.sort_unstable();
        blacklisted_ports.dedup();
        report.notes.push(format!(
            "stage2-intelligence safety skip: blocked ports {:?}",
            blacklisted_ports
        ));
    }
    if policy.fragile_mode {
        report.notes.push(
            "stage2-intelligence fragile-mode active: concurrency capped for low-power target"
                .to_string(),
        );
    }

    if candidates.is_empty() {
        report
            .notes
            .push("stage2-intelligence skipped: no eligible open tcp ports".to_string());
        return report;
    }

    let concurrency_cap = if policy.fragile_mode { 8 } else { 128 };
    let concurrency = policy
        .max_concurrency
        .clamp(1, concurrency_cap)
        .min(candidates.len().max(1));
    let mut in_flight = FuturesUnordered::new();

    while !candidates.is_empty() || !in_flight.is_empty() {
        while in_flight.len() < concurrency {
            let Some((index, port)) = candidates.pop_front() else {
                break;
            };
            let db = Arc::clone(&fingerprint_db);
            in_flight.push(tokio::spawn(async move {
                probe_open_tcp_port(index, target, port, db, timeout_budget).await
            }));
            report.tasks_spawned += 1;
        }

        if let Some(joined) = in_flight.next().await {
            let Ok(Some(update)) = joined else {
                continue;
            };
            if let Some(finding) = findings.get_mut(update.index) {
                if update.banner.is_some() {
                    finding.banner = update.banner;
                }
                if update.service.is_some() {
                    report.services_identified += 1;
                    finding.service = update.service;
                }
                if update.matched_by.is_some() {
                    finding.matched_by = update.matched_by;
                }
                if update.confidence.is_some() {
                    finding.confidence = update.confidence;
                }
                finding.reason = format!("{}; stage2={}", finding.reason, update.stage);
            }
        }
    }

    report.notes.push(format!(
        "stage2-intelligence completed: spawned={} identified={}",
        report.tasks_spawned, report.services_identified
    ));
    report
}

async fn probe_open_tcp_port(
    index: usize,
    target: IpAddr,
    port: u16,
    fingerprint_db: Arc<FingerprintDatabase>,
    timeout_budget: Duration,
) -> Option<PortProbeUpdate> {
    let generic = generic_probe_payload(port);
    let mut best_banner = None::<String>;
    if let Some(raw) = tcp_probe_roundtrip(target, port, &generic, timeout_budget).await {
        let banner = sanitize_banner(&raw);
        if !banner.is_empty() {
            best_banner = Some(banner.clone());
        }
        if let Some(matched) = fingerprint_db.match_banner(ProbeProtocol::Tcp, port, &raw) {
            return Some(PortProbeUpdate {
                index,
                banner: best_banner,
                service: Some(matched.service),
                matched_by: Some(if matched.soft {
                    format!("fingerprint-soft:{}", matched.source)
                } else {
                    format!("fingerprint-hard:{}", matched.source)
                }),
                confidence: Some(matched.confidence),
                stage: "generic-match",
            });
        }
        if let Some(heuristic) = infer_service_from_banner(&raw) {
            return Some(PortProbeUpdate {
                index,
                banner: best_banner,
                service: Some(heuristic),
                matched_by: Some("banner-heuristic".to_string()),
                confidence: Some(0.57),
                stage: "generic-heuristic",
            });
        }
    }

    let mut payloads = fingerprint_db.payloads_for(ProbeProtocol::Tcp, port, 4);
    if payloads.is_empty() {
        payloads.push(b"\r\n".to_vec());
    }
    for payload in payloads {
        if payload == generic {
            continue;
        }
        if let Some(raw) = tcp_probe_roundtrip(target, port, &payload, timeout_budget).await {
            let banner = sanitize_banner(&raw);
            if best_banner.is_none() && !banner.is_empty() {
                best_banner = Some(banner);
            }

            if let Some(matched) = fingerprint_db.match_banner(ProbeProtocol::Tcp, port, &raw) {
                return Some(PortProbeUpdate {
                    index,
                    banner: best_banner,
                    service: Some(matched.service),
                    matched_by: Some(if matched.soft {
                        format!("fingerprint-soft:{}", matched.source)
                    } else {
                        format!("fingerprint-hard:{}", matched.source)
                    }),
                    confidence: Some(matched.confidence),
                    stage: "targeted-match",
                });
            }

            if let Some(heuristic) = infer_service_from_banner(&raw) {
                return Some(PortProbeUpdate {
                    index,
                    banner: best_banner,
                    service: Some(heuristic),
                    matched_by: Some("banner-heuristic".to_string()),
                    confidence: Some(0.57),
                    stage: "targeted-heuristic",
                });
            }
        }
    }

    best_banner.map(|banner| PortProbeUpdate {
        index,
        banner: Some(banner),
        service: None,
        matched_by: None,
        confidence: None,
        stage: "banner-only",
    })
}

async fn tcp_probe_roundtrip(
    target: IpAddr,
    port: u16,
    payload: &[u8],
    timeout_budget: Duration,
) -> Option<Vec<u8>> {
    let connect_timeout = timeout_budget.clamp(Duration::from_millis(120), Duration::from_secs(5));
    let mut stream = timeout(connect_timeout, TcpStream::connect((target, port)))
        .await
        .ok()?
        .ok()?;

    if !payload.is_empty() {
        timeout(connect_timeout, stream.write_all(payload))
            .await
            .ok()?
            .ok()?;
    }

    let mut buf = [0u8; 2048];
    let read_timeout = timeout_budget
        .max(Duration::from_millis(220))
        .min(Duration::from_millis(850));
    let read = timeout(read_timeout, stream.read(&mut buf))
        .await
        .ok()?
        .ok()?;
    if read == 0 {
        return None;
    }
    Some(buf[..read].to_vec())
}

fn generic_probe_payload(port: u16) -> Vec<u8> {
    match port {
        80 | 8080 | 8000 | 8888 | 3000 | 5000 | 7001 | 8008 => {
            b"GET / HTTP/1.0\r\nHost: target\r\n\r\n".to_vec()
        }
        21 => b"HELP\r\n".to_vec(),
        25 | 587 => b"EHLO nprobe.local\r\n".to_vec(),
        110 => b"CAPA\r\n".to_vec(),
        143 => b"A1 CAPABILITY\r\n".to_vec(),
        _ => b"\r\n".to_vec(),
    }
}

fn infer_service_from_banner(raw: &[u8]) -> Option<String> {
    let banner = sanitize_banner(raw).to_ascii_lowercase();
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

fn sanitize_banner(raw: &[u8]) -> String {
    let mut out = String::with_capacity(raw.len());
    for byte in raw.iter().copied().take(220) {
        if byte.is_ascii_graphic() || byte == b' ' {
            out.push(char::from(byte));
        } else if byte == b'\r' || byte == b'\n' || byte == b'\t' {
            out.push(' ');
        }
    }
    out.split_whitespace().collect::<Vec<_>>().join(" ")
}

#[cfg(test)]
mod tests {
    use super::{run_multi_stage_tcp_probe_pipeline, MultiStageProbePolicy, MultiStageProbeReport};
    use crate::fingerprint_db::FingerprintDatabase;
    use crate::models::{PortFinding, PortState};
    use std::net::{IpAddr, Ipv4Addr};
    use std::sync::Arc;
    use std::time::Duration;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    #[tokio::test]
    async fn stage2_generic_probe_identifies_http_banner() {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("listener");
        let port = listener.local_addr().expect("addr").port();
        tokio::spawn(async move {
            if let Ok((mut socket, _)) = listener.accept().await {
                let mut buf = [0u8; 256];
                let _ = socket.read(&mut buf).await;
                let _ = socket
                    .write_all(b"HTTP/1.1 200 OK\r\nServer: test\r\n\r\n")
                    .await;
            }
        });

        let mut findings = vec![PortFinding {
            port,
            protocol: "tcp".to_string(),
            state: PortState::Open,
            service: None,
            banner: None,
            reason: "syn-ack received".to_string(),
            matched_by: None,
            confidence: None,
            educational_note: None,
            latency_ms: None,
            explanation: None,
        }];
        let report = run_multi_stage_tcp_probe_pipeline(
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            &mut findings,
            Arc::new(FingerprintDatabase::empty()),
            Duration::from_millis(650),
            MultiStageProbePolicy {
                max_concurrency: 8,
                fragile_mode: false,
                safety_blacklist: Vec::new(),
            },
        )
        .await;

        assert_eq!(report.tasks_spawned, 1);
        assert_eq!(findings[0].service.as_deref(), Some("http"));
        assert!(findings[0]
            .matched_by
            .as_deref()
            .unwrap_or("")
            .contains("heuristic"));
    }

    #[test]
    fn empty_open_port_set_short_circuits() {
        let mut findings = vec![PortFinding {
            port: 443,
            protocol: "tcp".to_string(),
            state: PortState::Closed,
            service: None,
            banner: None,
            reason: "closed".to_string(),
            matched_by: None,
            confidence: None,
            educational_note: None,
            latency_ms: None,
            explanation: None,
        }];

        let runtime = tokio::runtime::Runtime::new().expect("runtime");
        let report: MultiStageProbeReport = runtime.block_on(run_multi_stage_tcp_probe_pipeline(
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            &mut findings,
            Arc::new(FingerprintDatabase::empty()),
            Duration::from_millis(400),
            MultiStageProbePolicy {
                max_concurrency: 4,
                fragile_mode: false,
                safety_blacklist: Vec::new(),
            },
        ));
        assert_eq!(report.tasks_spawned, 0);
        assert_eq!(report.services_identified, 0);
    }
}

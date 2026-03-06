// Fetcher pipeline: lightweight post-scan enrichment inspired by plugin chains.

use std::net::IpAddr;
use std::process::Command;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio::time::timeout;

use crate::engine_packet::arp as packet_arp;
use crate::models::{HostResult, PortFinding, PortState, ScanRequest};

#[derive(Debug, Clone, Default)]
pub struct FetcherReport {
    pub warnings: Vec<String>,
    pub insights: Vec<String>,
    pub learning_notes: Vec<String>,
    pub parallel_tasks: usize,
}

impl FetcherReport {
    fn merge(&mut self, mut other: FetcherReport) {
        self.warnings.append(&mut other.warnings);
        self.insights.append(&mut other.insights);
        self.learning_notes.append(&mut other.learning_notes);
        self.parallel_tasks += other.parallel_tasks;
    }
}

#[derive(Debug, Clone, Copy)]
struct IcmpObservation {
    ttl: Option<u8>,
    rtt_ms: Option<f32>,
}

pub async fn run(request: &ScanRequest, host: &HostResult) -> FetcherReport {
    let Ok(ip) = host.ip.parse::<IpAddr>() else {
        return FetcherReport::default();
    };

    let timeout_budget = request
        .timeout_ms
        .map(Duration::from_millis)
        .unwrap_or_else(|| Duration::from_millis(request.profile.defaults().timeout_ms))
        .clamp(Duration::from_millis(180), Duration::from_secs(3));

    let mut report = FetcherReport::default();
    report.parallel_tasks += 1;

    let web_task = web_detect_fetcher(ip, &host.ports, timeout_budget);
    let snmp_task = snmp_fetcher(ip, &host.ports, timeout_budget);
    let icmp_task = icmp_probe_fetcher(ip, timeout_budget);

    let (web_report, snmp_report, icmp_obs) = tokio::join!(web_task, snmp_task, icmp_task);
    report.merge(web_report);
    report.merge(snmp_report);

    if let Some(icmp) = icmp_obs {
        if let Some(rtt_ms) = icmp.rtt_ms {
            report
                .insights
                .push(format!("icmp reachability confirmed ({rtt_ms:.1} ms)"));
        }
        if let Some(ttl) = icmp.ttl {
            report.learning_notes.push(format!(
                "icmp ttl hint observed: {} ({})",
                ttl,
                os_hint_from_ttl(ttl)
            ));
        }
    }

    if request.arp_discovery && packet_arp::parse_ipv4_cidr(&request.target).is_none() {
        if let IpAddr::V4(target_v4) = ip {
            if packet_arp::is_lan_ipv4(target_v4) {
                report.parallel_tasks += 1;
                match tokio::task::spawn_blocking(move || {
                    packet_arp::resolve_neighbor_mac(target_v4, Duration::from_millis(150))
                })
                .await
                {
                    Ok(Ok(Some(mac))) => {
                        report
                            .insights
                            .push(format!("arp neighbor: {} is at {}", target_v4, mac));
                    }
                    Ok(Err(err)) if request.verbose => report.warnings.push(format!(
                        "arp fetcher could not read neighbor for {}: {}",
                        target_v4, err
                    )),
                    Err(_) if request.verbose => report
                        .warnings
                        .push(format!("arp fetcher worker failed for {}", target_v4)),
                    _ => {}
                }
            }
        }
    }

    report.warnings.sort_unstable();
    report.warnings.dedup();
    report.insights.sort_unstable();
    report.insights.dedup();
    report.learning_notes.sort_unstable();
    report.learning_notes.dedup();
    report
}

async fn web_detect_fetcher(
    ip: IpAddr,
    ports: &[PortFinding],
    timeout_budget: Duration,
) -> FetcherReport {
    let mut report = FetcherReport::default();
    let candidates = ports
        .iter()
        .filter(|port| {
            port.protocol == "tcp"
                && matches!(port.state, PortState::Open)
                && matches!(port.port, 80 | 8080 | 8000 | 3000 | 5000 | 8888)
        })
        .map(|port| port.port)
        .take(4)
        .collect::<Vec<_>>();
    if candidates.is_empty() {
        return report;
    }

    report.parallel_tasks += candidates.len();
    for port in candidates {
        if let Some(title) = probe_http_title(ip, port, timeout_budget).await {
            report
                .insights
                .push(format!("web fetcher: {}:{} title='{}'", ip, port, title));
        }
    }
    report
}

async fn probe_http_title(ip: IpAddr, port: u16, timeout_budget: Duration) -> Option<String> {
    let stream = timeout(timeout_budget, TcpStream::connect((ip, port)))
        .await
        .ok()?
        .ok()?;
    let mut stream = stream;
    let host = ip.to_string();
    let request = format!(
        "GET / HTTP/1.0\r\nHost: {host}\r\nUser-Agent: nprobe-rs-fetcher\r\nConnection: close\r\n\r\n"
    );
    timeout(timeout_budget, stream.write_all(request.as_bytes()))
        .await
        .ok()?
        .ok()?;

    let mut buf = vec![0u8; 4096];
    let read = timeout(timeout_budget, stream.read(&mut buf))
        .await
        .ok()?
        .ok()?;
    if read == 0 {
        return None;
    }
    parse_html_title(&String::from_utf8_lossy(&buf[..read]))
}

fn parse_html_title(body: &str) -> Option<String> {
    let lower = body.to_ascii_lowercase();
    let start = lower.find("<title>")?;
    let end = lower[start + 7..].find("</title>")?;
    let raw = &body[start + 7..start + 7 + end];
    let title = raw.split_whitespace().collect::<Vec<_>>().join(" ");
    if title.is_empty() {
        None
    } else {
        Some(title.chars().take(120).collect())
    }
}

async fn snmp_fetcher(
    ip: IpAddr,
    ports: &[PortFinding],
    timeout_budget: Duration,
) -> FetcherReport {
    let mut report = FetcherReport::default();
    let has_snmp_port = ports.iter().any(|port| {
        port.port == 161
            && port.protocol == "udp"
            && matches!(port.state, PortState::Open | PortState::OpenOrFiltered)
    });
    if !has_snmp_port {
        return report;
    }

    report.parallel_tasks += 1;
    match probe_snmp_sysdescr(ip, timeout_budget).await {
        Some(response) => {
            let trimmed = response.trim();
            if trimmed.is_empty() {
                report
                    .insights
                    .push(format!("snmp fetcher: {} responded on udp/161", ip));
            } else {
                report
                    .insights
                    .push(format!("snmp fetcher: {} sysdescr hint '{}'", ip, trimmed));
            }
        }
        None => report.warnings.push(format!(
            "snmp fetcher: udp/161 open but no response from {}",
            ip
        )),
    }
    report
}

async fn probe_snmp_sysdescr(ip: IpAddr, timeout_budget: Duration) -> Option<String> {
    let socket = UdpSocket::bind(match ip {
        IpAddr::V4(_) => "0.0.0.0:0",
        IpAddr::V6(_) => "[::]:0",
    })
    .await
    .ok()?;
    socket.connect((ip, 161)).await.ok()?;

    // SNMPv1 GET sysDescr.0 with community "public".
    const SYS_DESCR_GET: &[u8] = &[
        0x30, 0x26, 0x02, 0x01, 0x00, 0x04, 0x06, b'p', b'u', b'b', b'l', b'i', b'c', 0xa0, 0x19,
        0x02, 0x04, 0x70, 0x71, 0x72, 0x73, 0x02, 0x01, 0x00, 0x02, 0x01, 0x00, 0x30, 0x0b, 0x30,
        0x09, 0x06, 0x05, 0x2b, 0x06, 0x01, 0x02, 0x01, 0x05, 0x00,
    ];
    socket.send(SYS_DESCR_GET).await.ok()?;

    let mut buf = vec![0u8; 2048];
    let size = timeout(timeout_budget, socket.recv(&mut buf))
        .await
        .ok()?
        .ok()?;
    if size == 0 {
        return None;
    }
    let payload = &buf[..size];
    extract_printable_ascii(payload)
}

fn extract_printable_ascii(payload: &[u8]) -> Option<String> {
    let mut best = String::new();
    let mut current = String::new();
    for byte in payload {
        let ch = *byte as char;
        if ch.is_ascii_graphic() || ch == ' ' {
            current.push(ch);
            if current.len() > best.len() {
                best = current.clone();
            }
        } else {
            current.clear();
        }
    }

    let cleaned = best.trim().trim_matches('"').to_string();
    if cleaned.len() >= 5 {
        Some(cleaned.chars().take(120).collect())
    } else {
        None
    }
}

async fn icmp_probe_fetcher(ip: IpAddr, timeout_budget: Duration) -> Option<IcmpObservation> {
    tokio::task::spawn_blocking(move || run_ping_probe(ip, timeout_budget))
        .await
        .ok()
        .flatten()
}

fn run_ping_probe(ip: IpAddr, timeout_budget: Duration) -> Option<IcmpObservation> {
    let timeout_ms = timeout_budget.as_millis().clamp(200, 4000) as u64;
    #[cfg(windows)]
    let output = Command::new("ping")
        .args(["-n", "1", "-w", &timeout_ms.to_string(), &ip.to_string()])
        .output()
        .ok()?;

    #[cfg(not(windows))]
    let output = Command::new("ping")
        .args(["-c", "1", "-W", "1", &ip.to_string()])
        .output()
        .ok()?;

    let text = String::from_utf8_lossy(&output.stdout).to_string();
    Some(IcmpObservation {
        ttl: parse_ttl(&text),
        rtt_ms: parse_rtt_ms(&text),
    })
}

fn parse_ttl(text: &str) -> Option<u8> {
    let lower = text.to_ascii_lowercase();
    for token in lower.split_whitespace() {
        if let Some(value) = token.strip_prefix("ttl=") {
            let digits = value
                .chars()
                .take_while(|ch| ch.is_ascii_digit())
                .collect::<String>();
            if let Ok(parsed) = digits.parse::<u8>() {
                return Some(parsed);
            }
        }
    }
    None
}

fn parse_rtt_ms(text: &str) -> Option<f32> {
    let lower = text.to_ascii_lowercase();
    for token in lower.split_whitespace() {
        if let Some(value) = token
            .strip_prefix("time=")
            .or_else(|| token.strip_prefix("time<"))
        {
            let cleaned = value
                .trim_end_matches("ms")
                .trim_end_matches(',')
                .trim_matches('<');
            if let Ok(parsed) = cleaned.parse::<f32>() {
                return Some(parsed.max(0.1));
            }
        }
    }
    None
}

fn os_hint_from_ttl(ttl: u8) -> &'static str {
    match ttl {
        0..=64 => "low-hop unix/linux-like stack",
        65..=128 => "windows/network stack family",
        _ => "high-default ttl device stack",
    }
}

#[cfg(test)]
mod tests {
    use super::{parse_html_title, parse_rtt_ms, parse_ttl};

    #[test]
    fn parse_html_title_works() {
        let body = "<html><head><title>Example Domain</title></head></html>";
        assert_eq!(parse_html_title(body).as_deref(), Some("Example Domain"));
    }

    #[test]
    fn parse_ping_ttl_and_time() {
        let sample = "64 bytes from 1.1.1.1: icmp_seq=1 ttl=57 time=23.4 ms";
        assert_eq!(parse_ttl(sample), Some(57));
        assert_eq!(parse_rtt_ms(sample), Some(23.4));
    }
}

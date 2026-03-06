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

#[derive(Debug, Clone, Default)]
struct WebDetectOutcome {
    report: FetcherReport,
    detected_ports: Vec<u16>,
}

#[derive(Debug, Clone, Default)]
struct SnmpFetchOutcome {
    report: FetcherReport,
    sysdescr: Option<String>,
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

    // Root nodes in the fetcher DAG.
    let web_task = web_detect_fetcher(ip, &host.ports, timeout_budget);
    let snmp_task = snmp_fetcher(ip, &host.ports, timeout_budget);
    let icmp_task = icmp_probe_fetcher(ip, timeout_budget);
    let arp_task = arp_neighbor_fetcher(request, ip);

    let (web_outcome, snmp_outcome, icmp_obs, arp_report) =
        tokio::join!(web_task, snmp_task, icmp_task, arp_task);
    report.merge(web_outcome.report);
    report.merge(snmp_outcome.report);
    report.merge(arp_report);

    let mut icmp_reachable = false;
    if let Some(icmp) = icmp_obs {
        if let Some(rtt_ms) = icmp.rtt_ms {
            icmp_reachable = true;
            report
                .insights
                .push(format!("icmp reachability confirmed ({rtt_ms:.1} ms)"));
        }
        if let Some(ttl) = icmp.ttl {
            icmp_reachable = true;
            report.learning_notes.push(format!(
                "icmp ttl hint observed: {} ({})",
                ttl,
                os_hint_from_ttl(ttl)
            ));
        }
    }

    // Dependent fetchers run only when prerequisites succeeded.
    if !web_outcome.detected_ports.is_empty() {
        report.merge(web_header_fetcher(ip, &web_outcome.detected_ports, timeout_budget).await);
    }

    if let Some(sysdescr) = snmp_outcome.sysdescr.as_deref() {
        report.merge(snmp_inventory_fetcher(ip, timeout_budget, sysdescr).await);
    }

    report.learning_notes.push(format!(
        "fetcher-dag: icmp={} web={} snmp={} dependents=[web-headers:{}, snmp-inventory:{}]",
        if icmp_reachable { "ok" } else { "none" },
        web_outcome.detected_ports.len(),
        usize::from(snmp_outcome.sysdescr.is_some()),
        if web_outcome.detected_ports.is_empty() {
            "skipped"
        } else {
            "executed"
        },
        if snmp_outcome.sysdescr.is_some() {
            "executed"
        } else {
            "skipped"
        },
    ));

    report.warnings.sort_unstable();
    report.warnings.dedup();
    report.insights.sort_unstable();
    report.insights.dedup();
    report.learning_notes.sort_unstable();
    report.learning_notes.dedup();
    report
}

async fn arp_neighbor_fetcher(request: &ScanRequest, ip: IpAddr) -> FetcherReport {
    let mut report = FetcherReport::default();
    if !request.arp_discovery || packet_arp::parse_ipv4_cidr(&request.target).is_some() {
        return report;
    }

    let IpAddr::V4(target_v4) = ip else {
        return report;
    };
    if !packet_arp::is_lan_ipv4(target_v4) {
        return report;
    }

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

    report
}

async fn web_detect_fetcher(
    ip: IpAddr,
    ports: &[PortFinding],
    timeout_budget: Duration,
) -> WebDetectOutcome {
    let mut outcome = WebDetectOutcome::default();
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
        return outcome;
    }

    outcome.report.parallel_tasks += candidates.len();
    for port in candidates {
        if let Some(title) = probe_http_title(ip, port, timeout_budget).await {
            outcome.detected_ports.push(port);
            outcome
                .report
                .insights
                .push(format!("web fetcher: {}:{} title='{}'", ip, port, title));
        }
    }
    outcome
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

async fn web_header_fetcher(ip: IpAddr, ports: &[u16], timeout_budget: Duration) -> FetcherReport {
    let mut report = FetcherReport::default();
    let ports = ports.iter().copied().take(3).collect::<Vec<_>>();
    if ports.is_empty() {
        return report;
    }

    report.parallel_tasks += ports.len();
    for port in ports {
        if let Some(server) = probe_http_server_header(ip, port, timeout_budget).await {
            report.insights.push(format!(
                "web header fetcher: {}:{} server='{}'",
                ip, port, server
            ));
        }
    }
    report
}

async fn probe_http_server_header(
    ip: IpAddr,
    port: u16,
    timeout_budget: Duration,
) -> Option<String> {
    let stream = timeout(timeout_budget, TcpStream::connect((ip, port)))
        .await
        .ok()?
        .ok()?;
    let mut stream = stream;
    let host = ip.to_string();
    let request = format!(
        "HEAD / HTTP/1.0\r\nHost: {host}\r\nUser-Agent: nprobe-rs-fetcher\r\nConnection: close\r\n\r\n"
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

    parse_http_server_header(&String::from_utf8_lossy(&buf[..read]))
}

fn parse_http_server_header(text: &str) -> Option<String> {
    for line in text.lines() {
        let lower = line.to_ascii_lowercase();
        if !lower.starts_with("server:") {
            continue;
        }
        let raw = line.split_once(':')?.1.trim();
        if raw.is_empty() {
            return None;
        }
        return Some(raw.chars().take(120).collect());
    }
    None
}

async fn snmp_fetcher(
    ip: IpAddr,
    ports: &[PortFinding],
    timeout_budget: Duration,
) -> SnmpFetchOutcome {
    let mut outcome = SnmpFetchOutcome::default();
    let has_snmp_port = ports.iter().any(|port| {
        port.port == 161
            && port.protocol == "udp"
            && matches!(port.state, PortState::Open | PortState::OpenOrFiltered)
    });
    if !has_snmp_port {
        return outcome;
    }

    outcome.report.parallel_tasks += 1;
    match probe_snmp_sysdescr(ip, timeout_budget).await {
        Some(response) => {
            let trimmed = response.trim();
            if trimmed.is_empty() {
                outcome
                    .report
                    .insights
                    .push(format!("snmp fetcher: {} responded on udp/161", ip));
            } else {
                outcome.sysdescr = Some(trimmed.to_string());
                outcome
                    .report
                    .insights
                    .push(format!("snmp fetcher: {} sysdescr hint '{}'", ip, trimmed));
            }
        }
        None => outcome.report.warnings.push(format!(
            "snmp fetcher: udp/161 open but no response from {}",
            ip
        )),
    }
    outcome
}

async fn probe_snmp_sysdescr(ip: IpAddr, timeout_budget: Duration) -> Option<String> {
    const SYS_DESCR_OID: &[u8] = &[0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x01, 0x00];
    probe_snmp_oid(ip, timeout_budget, SYS_DESCR_OID, 0x7071_7273).await
}

async fn snmp_inventory_fetcher(
    ip: IpAddr,
    timeout_budget: Duration,
    base_sysdescr: &str,
) -> FetcherReport {
    const SYS_NAME_OID: &[u8] = &[0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x05, 0x00];
    const SYS_OBJECT_ID_OID: &[u8] = &[0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x02, 0x00];
    const SYS_CONTACT_OID: &[u8] = &[0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x04, 0x00];
    const SYS_LOCATION_OID: &[u8] = &[0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x06, 0x00];
    let inventory_oids = [
        ("sysName", SYS_NAME_OID),
        ("sysObjectID", SYS_OBJECT_ID_OID),
        ("sysContact", SYS_CONTACT_OID),
        ("sysLocation", SYS_LOCATION_OID),
    ];

    let mut report = FetcherReport::default();
    report.parallel_tasks += inventory_oids.len();
    if !base_sysdescr.trim().is_empty() {
        report.learning_notes.push(format!(
            "snmp inventory baseline: sysDescr='{}'",
            base_sysdescr.chars().take(120).collect::<String>()
        ));
    }

    let mut success = 0usize;
    for (idx, (label, oid)) in inventory_oids.iter().enumerate() {
        let request_id = 0x7100_0000u32.wrapping_add(idx as u32);
        if let Some(value) = probe_snmp_oid(ip, timeout_budget, oid, request_id).await {
            success += 1;
            report
                .insights
                .push(format!("snmp inventory: {}='{}'", label, value));
        }
    }

    if success == 0 {
        report.warnings.push(format!(
            "snmp inventory: {} responded to base probe but did not answer standard MIB-2 OIDs",
            ip
        ));
    } else {
        report.learning_notes.push(format!(
            "snmp inventory collected {} MIB-2 attribute(s)",
            success
        ));
    }

    report
}

async fn probe_snmp_oid(
    ip: IpAddr,
    timeout_budget: Duration,
    oid: &[u8],
    request_id: u32,
) -> Option<String> {
    let socket = UdpSocket::bind(match ip {
        IpAddr::V4(_) => "0.0.0.0:0",
        IpAddr::V6(_) => "[::]:0",
    })
    .await
    .ok()?;
    socket.connect((ip, 161)).await.ok()?;
    let request = build_snmp_get_request(request_id, oid)?;
    socket.send(&request).await.ok()?;

    let mut buf = [0u8; 2048];
    let size = timeout(timeout_budget, socket.recv(&mut buf))
        .await
        .ok()?
        .ok()?;
    if size == 0 {
        return None;
    }
    extract_printable_ascii(&buf[..size])
}

fn build_snmp_get_request(request_id: u32, oid: &[u8]) -> Option<Vec<u8>> {
    let oid_tlv = tlv(0x06, oid)?;
    let mut var_bind_value = Vec::with_capacity(oid_tlv.len() + 2);
    var_bind_value.extend_from_slice(&oid_tlv);
    var_bind_value.extend_from_slice(&[0x05, 0x00]); // ASN.1 NULL
    let var_bind = tlv(0x30, &var_bind_value)?;
    let var_bind_list = tlv(0x30, &var_bind)?;

    let request_id_tlv = tlv(0x02, &encode_u32_integer(request_id))?;
    let err_status_tlv = tlv(0x02, &[0x00])?;
    let err_index_tlv = tlv(0x02, &[0x00])?;

    let mut pdu_value = Vec::with_capacity(
        request_id_tlv.len() + err_status_tlv.len() + err_index_tlv.len() + var_bind_list.len(),
    );
    pdu_value.extend_from_slice(&request_id_tlv);
    pdu_value.extend_from_slice(&err_status_tlv);
    pdu_value.extend_from_slice(&err_index_tlv);
    pdu_value.extend_from_slice(&var_bind_list);
    let pdu = tlv(0xa0, &pdu_value)?;

    let version = tlv(0x02, &[0x00])?;
    let community = tlv(0x04, b"public")?;
    let mut message_value = Vec::with_capacity(version.len() + community.len() + pdu.len());
    message_value.extend_from_slice(&version);
    message_value.extend_from_slice(&community);
    message_value.extend_from_slice(&pdu);
    tlv(0x30, &message_value)
}

fn tlv(tag: u8, value: &[u8]) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(value.len() + 4);
    out.push(tag);
    append_ber_length(value.len(), &mut out)?;
    out.extend_from_slice(value);
    Some(out)
}

fn append_ber_length(len: usize, out: &mut Vec<u8>) -> Option<()> {
    if len < 0x80 {
        out.push(len as u8);
        return Some(());
    }
    if len <= 0xff {
        out.push(0x81);
        out.push(len as u8);
        return Some(());
    }
    if len <= 0xffff {
        out.push(0x82);
        out.push(((len >> 8) & 0xff) as u8);
        out.push((len & 0xff) as u8);
        return Some(());
    }
    None
}

fn encode_u32_integer(value: u32) -> Vec<u8> {
    let bytes = value.to_be_bytes();
    let first_non_zero = bytes
        .iter()
        .position(|byte| *byte != 0)
        .unwrap_or(bytes.len().saturating_sub(1));
    let mut encoded = bytes[first_non_zero..].to_vec();
    if encoded.first().is_some_and(|value| value & 0x80 != 0) {
        encoded.insert(0, 0);
    }
    encoded
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
    use super::{
        build_snmp_get_request, parse_html_title, parse_http_server_header, parse_rtt_ms, parse_ttl,
    };

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

    #[test]
    fn parse_server_header_works() {
        let response = "HTTP/1.1 200 OK\r\nServer: nginx/1.25.5\r\nContent-Type: text/html\r\n\r\n";
        assert_eq!(
            parse_http_server_header(response).as_deref(),
            Some("nginx/1.25.5")
        );
    }

    #[test]
    fn snmp_builder_contains_requested_oid() {
        let oid = [0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x05, 0x00];
        let packet = build_snmp_get_request(0x1234_5678, &oid).expect("packet");
        assert_eq!(packet.first().copied(), Some(0x30));
        assert!(packet.windows(oid.len()).any(|window| window == oid));
    }
}

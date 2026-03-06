// Flow sketch: input -> core processing -> output model
// Pseudo-block:
//   read input -> process safely -> return deterministic output

use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::Path;

use regex::bytes::{Regex, RegexBuilder};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProbeProtocol {
    Tcp,
    Udp,
}

impl ProbeProtocol {
    pub fn from_probe_token(raw: &str) -> Option<Self> {
        match raw.to_ascii_lowercase().as_str() {
            "tcp" | "t" => Some(ProbeProtocol::Tcp),
            "udp" | "u" => Some(ProbeProtocol::Udp),
            _ => None,
        }
    }
}

#[derive(Debug, Clone)]
pub struct FingerprintMatch {
    pub service: String,
    pub source: String,
    pub soft: bool,
    pub confidence: f32,
}

#[derive(Debug, Clone)]
pub struct FingerprintStats {
    pub payloads_loaded: usize,
    pub rules_loaded: usize,
    pub rules_compiled: usize,
    pub rules_skipped: usize,
    pub nse_scripts: usize,
    pub nselib_modules: usize,
}

#[derive(Debug, Clone)]
struct FingerprintRule {
    service: String,
    source: String,
    protocol: Option<ProbeProtocol>,
    ports: Vec<u16>,
    soft: bool,
    regex: Regex,
}

impl FingerprintRule {
    fn applies_to(&self, protocol: ProbeProtocol, port: u16) -> bool {
        if let Some(rule_proto) = self.protocol {
            if rule_proto != protocol {
                return false;
            }
        }
        self.ports.is_empty() || self.ports.binary_search(&port).is_ok()
    }
}

#[derive(Debug, Clone)]
pub struct FingerprintDatabase {
    payloads_tcp_by_port: HashMap<u16, Vec<Vec<u8>>>,
    payloads_udp_by_port: HashMap<u16, Vec<Vec<u8>>>,
    payloads_tcp_generic: Vec<Vec<u8>>,
    payloads_udp_generic: Vec<Vec<u8>>,
    hard_rules: Vec<FingerprintRule>,
    soft_rules: Vec<FingerprintRule>,
    stats: FingerprintStats,
}

#[derive(Debug, Clone)]
struct ProbeContext {
    protocol: ProbeProtocol,
    name: String,
    payload: Vec<u8>,
    ports: Vec<u16>,
}

#[derive(Debug, Clone)]
struct RuleRelevanceBudget {
    generic_tcp_rules: usize,
    generic_udp_rules: usize,
    tcp_port_rule_counts: HashMap<u16, usize>,
    udp_port_rule_counts: HashMap<u16, usize>,
    generic_cap: usize,
    per_port_cap: usize,
}

impl RuleRelevanceBudget {
    fn new(generic_cap: usize, per_port_cap: usize) -> Self {
        Self {
            generic_tcp_rules: 0,
            generic_udp_rules: 0,
            tcp_port_rule_counts: HashMap::new(),
            udp_port_rule_counts: HashMap::new(),
            generic_cap,
            per_port_cap,
        }
    }
}

impl FingerprintDatabase {
    pub fn load_for_ports(focus_ports: &[u16], include_udp: bool) -> Self {
        let probes_path = Path::new("temp/nmap/nmap-service-probes");
        let stats = count_nmap_script_assets(Path::new("temp/nmap"));
        let focus = focus_ports.iter().copied().collect::<HashSet<u16>>();
        let mut db = if let Ok(content) = fs::read_to_string(probes_path) {
            Self::from_service_probes(&content, stats.0, stats.1, &focus, include_udp)
        } else {
            Self::fallback(stats.0, stats.1)
        };

        if db.payloads_tcp_generic.is_empty() {
            db.payloads_tcp_generic.push(b"\r\n".to_vec());
        }

        db
    }

    pub fn empty() -> Self {
        Self {
            payloads_tcp_by_port: HashMap::new(),
            payloads_udp_by_port: HashMap::new(),
            payloads_tcp_generic: vec![b"\r\n".to_vec()],
            payloads_udp_generic: vec![vec![0x00]],
            hard_rules: Vec::new(),
            soft_rules: Vec::new(),
            stats: FingerprintStats {
                payloads_loaded: 0,
                rules_loaded: 0,
                rules_compiled: 0,
                rules_skipped: 0,
                nse_scripts: 0,
                nselib_modules: 0,
            },
        }
    }

    pub fn stats(&self) -> &FingerprintStats {
        &self.stats
    }

    pub fn payloads_for(&self, protocol: ProbeProtocol, port: u16, limit: usize) -> Vec<Vec<u8>> {
        let max_items = limit.max(1);
        let mut out = Vec::<Vec<u8>>::new();

        let (port_map, generic) = match protocol {
            ProbeProtocol::Tcp => (&self.payloads_tcp_by_port, &self.payloads_tcp_generic),
            ProbeProtocol::Udp => (&self.payloads_udp_by_port, &self.payloads_udp_generic),
        };

        if let Some(items) = port_map.get(&port) {
            for item in items.iter().take(max_items) {
                push_unique_payload(&mut out, item);
                if out.len() >= max_items {
                    return out;
                }
            }
        }

        for item in generic.iter().take(max_items) {
            push_unique_payload(&mut out, item);
            if out.len() >= max_items {
                break;
            }
        }

        out
    }

    pub fn match_banner(
        &self,
        protocol: ProbeProtocol,
        port: u16,
        banner: &[u8],
    ) -> Option<FingerprintMatch> {
        for rule in &self.hard_rules {
            if rule.applies_to(protocol, port) && rule.regex.is_match(banner) {
                return Some(FingerprintMatch {
                    service: rule.service.clone(),
                    source: rule.source.clone(),
                    soft: false,
                    confidence: 0.93,
                });
            }
        }

        for rule in &self.soft_rules {
            if rule.applies_to(protocol, port) && rule.regex.is_match(banner) {
                return Some(FingerprintMatch {
                    service: rule.service.clone(),
                    source: rule.source.clone(),
                    soft: true,
                    confidence: 0.64,
                });
            }
        }

        None
    }

    fn from_service_probes(
        content: &str,
        nse_scripts: usize,
        nselib_modules: usize,
        focus_ports: &HashSet<u16>,
        include_udp: bool,
    ) -> Self {
        const MAX_GENERIC_RULES_PER_PROTOCOL: usize = 60;
        const MAX_RULES_PER_PORT_PROTOCOL: usize = 120;
        let mut payloads_tcp_by_port = HashMap::<u16, Vec<Vec<u8>>>::new();
        let mut payloads_udp_by_port = HashMap::<u16, Vec<Vec<u8>>>::new();
        let mut payloads_tcp_generic = Vec::<Vec<u8>>::new();
        let mut payloads_udp_generic = Vec::<Vec<u8>>::new();
        let mut hard_rules = Vec::<FingerprintRule>::new();
        let mut soft_rules = Vec::<FingerprintRule>::new();
        let mut rules_loaded = 0usize;
        let mut rules_compiled = 0usize;
        let mut rules_skipped = 0usize;
        let mut payloads_loaded = 0usize;
        let mut current_probe: Option<ProbeContext> = None;
        let mut rule_budget =
            RuleRelevanceBudget::new(MAX_GENERIC_RULES_PER_PROTOCOL, MAX_RULES_PER_PORT_PROTOCOL);

        for line in content.lines() {
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with('#') {
                continue;
            }

            if trimmed.starts_with("Probe ") {
                if let Some(probe) = current_probe.take() {
                    add_probe_payload(
                        probe,
                        &mut payloads_tcp_by_port,
                        &mut payloads_udp_by_port,
                        &mut payloads_tcp_generic,
                        &mut payloads_udp_generic,
                        &mut payloads_loaded,
                    );
                }
                current_probe = parse_probe_line(trimmed);
                continue;
            }

            if let Some(rest) = trimmed.strip_prefix("ports ") {
                if let Some(probe) = current_probe.as_mut() {
                    probe.ports = parse_ports_expr(rest, probe.protocol);
                }
                continue;
            }

            if let Some(rest) = trimmed.strip_prefix("sslports ") {
                if let Some(probe) = current_probe.as_mut() {
                    probe.ports = parse_ports_expr(rest, probe.protocol);
                }
                continue;
            }

            if trimmed.starts_with("match ") || trimmed.starts_with("softmatch ") {
                rules_loaded += 1;
                if let Some(rule) = parse_match_line(trimmed, current_probe.as_ref()) {
                    if !rule_relevant(&rule, focus_ports, include_udp, &mut rule_budget) {
                        continue;
                    }
                    rules_compiled += 1;
                    if rule.soft {
                        soft_rules.push(rule);
                    } else {
                        hard_rules.push(rule);
                    }
                } else {
                    rules_skipped += 1;
                }
            }
        }

        if let Some(probe) = current_probe.take() {
            add_probe_payload(
                probe,
                &mut payloads_tcp_by_port,
                &mut payloads_udp_by_port,
                &mut payloads_tcp_generic,
                &mut payloads_udp_generic,
                &mut payloads_loaded,
            );
        }

        Self {
            payloads_tcp_by_port,
            payloads_udp_by_port,
            payloads_tcp_generic,
            payloads_udp_generic,
            hard_rules,
            soft_rules,
            stats: FingerprintStats {
                payloads_loaded,
                rules_loaded,
                rules_compiled,
                rules_skipped,
                nse_scripts,
                nselib_modules,
            },
        }
    }

    fn fallback(nse_scripts: usize, nselib_modules: usize) -> Self {
        let mut payloads_tcp_by_port = HashMap::new();
        payloads_tcp_by_port.insert(
            80,
            vec![b"HEAD / HTTP/1.0\r\nHost: target\r\n\r\n".to_vec()],
        );
        payloads_tcp_by_port.insert(21, vec![b"HELP\r\n".to_vec()]);
        payloads_tcp_by_port.insert(25, vec![b"EHLO nprobe.local\r\n".to_vec()]);
        payloads_tcp_by_port.insert(110, vec![b"CAPA\r\n".to_vec()]);
        payloads_tcp_by_port.insert(143, vec![b"A1 CAPABILITY\r\n".to_vec()]);
        payloads_tcp_by_port.insert(6379, vec![b"PING\r\n".to_vec()]);
        let mut payloads_udp_by_port = HashMap::new();
        // DNS standard query: A record for root label.
        payloads_udp_by_port.insert(
            53,
            vec![vec![
                0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x01, 0x00, 0x01,
            ]],
        );
        // Minimal SNMPv1 GetRequest for sysDescr.0 using community "public".
        payloads_udp_by_port.insert(
            161,
            vec![vec![
                0x30, 0x26, 0x02, 0x01, 0x00, 0x04, 0x06, b'p', b'u', b'b', b'l', b'i', b'c', 0xa0,
                0x19, 0x02, 0x04, 0x70, 0x71, 0x72, 0x73, 0x02, 0x01, 0x00, 0x02, 0x01, 0x00, 0x30,
                0x0b, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x06, 0x01, 0x02, 0x01, 0x05, 0x00,
            ]],
        );
        // NTP client mode request.
        payloads_udp_by_port.insert(
            123,
            vec![{
                let mut ntp = vec![0u8; 48];
                ntp[0] = 0x1b;
                ntp
            }],
        );
        payloads_udp_by_port.insert(
            1900,
            vec![b"M-SEARCH * HTTP/1.1\r\nHOST:239.255.255.250:1900\r\nMAN:\"ssdp:discover\"\r\nMX:1\r\nST:ssdp:all\r\n\r\n".to_vec()],
        );

        Self {
            payloads_tcp_by_port,
            payloads_udp_by_port,
            payloads_tcp_generic: vec![b"\r\n".to_vec()],
            payloads_udp_generic: vec![vec![0x00]],
            hard_rules: Vec::new(),
            soft_rules: Vec::new(),
            stats: FingerprintStats {
                payloads_loaded: 11,
                rules_loaded: 0,
                rules_compiled: 0,
                rules_skipped: 0,
                nse_scripts,
                nselib_modules,
            },
        }
    }
}

fn rule_relevant(
    rule: &FingerprintRule,
    focus_ports: &HashSet<u16>,
    include_udp: bool,
    budget: &mut RuleRelevanceBudget,
) -> bool {
    if !include_udp && matches!(rule.protocol, Some(ProbeProtocol::Udp)) {
        return false;
    }

    let should_filter = !focus_ports.is_empty();
    if should_filter && !rule.ports.is_empty() {
        let mut matched_ports = rule
            .ports
            .iter()
            .copied()
            .filter(|port| focus_ports.contains(port))
            .collect::<Vec<u16>>();
        if matched_ports.is_empty() {
            return false;
        }
        matched_ports.sort_unstable();
        matched_ports.dedup();

        let counts = match rule.protocol {
            Some(ProbeProtocol::Udp) => &mut budget.udp_port_rule_counts,
            _ => &mut budget.tcp_port_rule_counts,
        };

        for port in matched_ports {
            let counter = counts.entry(port).or_insert(0);
            if *counter < budget.per_port_cap {
                *counter += 1;
                return true;
            }
        }
        return false;
    }

    if should_filter && rule.ports.is_empty() {
        match rule.protocol {
            Some(ProbeProtocol::Tcp) => {
                if budget.generic_tcp_rules >= budget.generic_cap {
                    return false;
                }
                budget.generic_tcp_rules += 1;
                true
            }
            Some(ProbeProtocol::Udp) => {
                if budget.generic_udp_rules >= budget.generic_cap {
                    return false;
                }
                budget.generic_udp_rules += 1;
                true
            }
            None => {
                if budget.generic_tcp_rules >= budget.generic_cap {
                    return false;
                }
                budget.generic_tcp_rules += 1;
                true
            }
        }
    } else {
        true
    }
}

fn parse_probe_line(line: &str) -> Option<ProbeContext> {
    let rest = line.strip_prefix("Probe ")?;
    let mut split = rest.splitn(3, char::is_whitespace);
    let proto_token = split.next()?.trim();
    let name = split.next()?.trim().to_string();
    let payload_spec = split.next()?.trim();
    let protocol = ProbeProtocol::from_probe_token(proto_token)?;
    let (payload_raw, _options) = extract_delimited(payload_spec, 'q')?;
    let payload = decode_payload(payload_raw.as_bytes());

    Some(ProbeContext {
        protocol,
        name,
        payload,
        ports: Vec::new(),
    })
}

fn parse_match_line(line: &str, current_probe: Option<&ProbeContext>) -> Option<FingerprintRule> {
    let (soft, rest) = if let Some(rem) = line.strip_prefix("softmatch ") {
        (true, rem)
    } else if let Some(rem) = line.strip_prefix("match ") {
        (false, rem)
    } else {
        return None;
    };

    let mut parts = rest.splitn(2, char::is_whitespace);
    let service = parts.next()?.trim().to_string();
    let matcher = parts.next()?.trim_start();
    let (pattern, options) = extract_delimited(matcher, 'm')?;
    if pattern.len() > 240 || pattern_is_too_complex(&pattern) {
        return None;
    }

    let mut builder = RegexBuilder::new(&pattern);
    builder.case_insensitive(options.contains('i'));
    builder.dot_matches_new_line(options.contains('s'));
    builder.multi_line(options.contains('m'));
    let regex = builder.build().ok()?;

    let (protocol, ports, source) = if let Some(probe) = current_probe {
        (
            Some(probe.protocol),
            normalized_ports(&probe.ports),
            probe.name.clone(),
        )
    } else {
        (None, Vec::new(), "global".to_string())
    };

    Some(FingerprintRule {
        service,
        source,
        protocol,
        ports,
        soft,
        regex,
    })
}

fn pattern_is_too_complex(pattern: &str) -> bool {
    let wildcards = pattern.matches(".*").count() + pattern.matches(".+").count();
    if wildcards > 12 {
        return true;
    }

    let repeats = pattern.matches('{').count();
    if repeats > 8 {
        return true;
    }

    let alternations = pattern.matches('|').count();
    alternations > 18
}

fn normalized_ports(ports: &[u16]) -> Vec<u16> {
    let mut out = ports.to_vec();
    out.sort_unstable();
    out.dedup();
    out
}

fn add_probe_payload(
    probe: ProbeContext,
    payloads_tcp_by_port: &mut HashMap<u16, Vec<Vec<u8>>>,
    payloads_udp_by_port: &mut HashMap<u16, Vec<Vec<u8>>>,
    payloads_tcp_generic: &mut Vec<Vec<u8>>,
    payloads_udp_generic: &mut Vec<Vec<u8>>,
    payloads_loaded: &mut usize,
) {
    if probe.payload.is_empty() {
        return;
    }

    *payloads_loaded += 1;
    if probe.ports.is_empty() {
        match probe.protocol {
            ProbeProtocol::Tcp => push_unique_payload(payloads_tcp_generic, &probe.payload),
            ProbeProtocol::Udp => push_unique_payload(payloads_udp_generic, &probe.payload),
        }
        return;
    }

    match probe.protocol {
        ProbeProtocol::Tcp => {
            for port in probe.ports.iter().copied() {
                let bucket = payloads_tcp_by_port.entry(port).or_default();
                if bucket.len() < 8 {
                    push_unique_payload(bucket, &probe.payload);
                }
            }
        }
        ProbeProtocol::Udp => {
            for port in probe.ports.iter().copied() {
                let bucket = payloads_udp_by_port.entry(port).or_default();
                if bucket.len() < 6 {
                    push_unique_payload(bucket, &probe.payload);
                }
            }
        }
    }
}

fn push_unique_payload(bucket: &mut Vec<Vec<u8>>, payload: &[u8]) {
    if !bucket.iter().any(|item| item == payload) {
        bucket.push(payload.to_vec());
    }
}

fn extract_delimited(input: &str, leader: char) -> Option<(String, String)> {
    let bytes = input.as_bytes();
    if bytes.len() < 3 || bytes[0] != leader as u8 {
        return None;
    }
    let delim = bytes[1];
    let mut idx = 2usize;
    let mut escaped = false;
    while idx < bytes.len() {
        let b = bytes[idx];
        if escaped {
            escaped = false;
            idx += 1;
            continue;
        }
        if b == b'\\' {
            escaped = true;
            idx += 1;
            continue;
        }
        if b == delim {
            break;
        }
        idx += 1;
    }
    if idx >= bytes.len() {
        return None;
    }

    let body = input[2..idx].to_string();
    let rest = &input[idx + 1..];
    let options: String = rest
        .chars()
        .take_while(|ch| ch.is_ascii_alphabetic())
        .collect();
    Some((body, options))
}

fn decode_payload(raw: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(raw.len());
    let mut idx = 0usize;

    while idx < raw.len() {
        let b = raw[idx];
        if b != b'\\' || idx + 1 >= raw.len() {
            out.push(b);
            idx += 1;
            continue;
        }

        let next = raw[idx + 1];
        match next {
            b'r' => {
                out.push(b'\r');
                idx += 2;
            }
            b'n' => {
                out.push(b'\n');
                idx += 2;
            }
            b't' => {
                out.push(b'\t');
                idx += 2;
            }
            b'0' => {
                out.push(0);
                idx += 2;
            }
            b'\\' => {
                out.push(b'\\');
                idx += 2;
            }
            b'x' => {
                if idx + 3 < raw.len() {
                    let h1 = raw[idx + 2] as char;
                    let h2 = raw[idx + 3] as char;
                    let hex = format!("{h1}{h2}");
                    if let Ok(value) = u8::from_str_radix(&hex, 16) {
                        out.push(value);
                        idx += 4;
                    } else {
                        out.push(next);
                        idx += 2;
                    }
                } else {
                    out.push(next);
                    idx += 2;
                }
            }
            b'1'..=b'7' => {
                let mut oct = vec![next];
                let mut j = idx + 2;
                while j < raw.len() && oct.len() < 3 && matches!(raw[j], b'0'..=b'7') {
                    oct.push(raw[j]);
                    j += 1;
                }
                if let Ok(text) = std::str::from_utf8(&oct) {
                    if let Ok(value) = u8::from_str_radix(text, 8) {
                        out.push(value);
                        idx = j;
                        continue;
                    }
                }
                out.push(next);
                idx += 2;
            }
            _ => {
                out.push(next);
                idx += 2;
            }
        }
    }

    out
}

fn parse_ports_expr(raw: &str, protocol: ProbeProtocol) -> Vec<u16> {
    let mut out = Vec::<u16>::new();
    for token in raw.split(',').map(str::trim).filter(|v| !v.is_empty()) {
        let mut value = token;
        if let Some((prefix, rest)) = token.split_once(':') {
            let wanted = match protocol {
                ProbeProtocol::Tcp => "t",
                ProbeProtocol::Udp => "u",
            };
            if !prefix.eq_ignore_ascii_case(wanted) {
                continue;
            }
            value = rest;
        }

        if let Some((start, end)) = value.split_once('-') {
            if let (Ok(s), Ok(e)) = (start.parse::<u16>(), end.parse::<u16>()) {
                if s <= e {
                    out.extend(s..=e);
                }
            }
            continue;
        }

        if let Ok(port) = value.parse::<u16>() {
            out.push(port);
        }
    }

    out.sort_unstable();
    out.dedup();
    out
}

fn count_nmap_script_assets(root: &Path) -> (usize, usize) {
    let scripts = count_files_with_extension(&root.join("scripts"), "nse");
    let nselib = count_files_with_extension(&root.join("nselib"), "lua");
    (scripts, nselib)
}

fn count_files_with_extension(root: &Path, ext: &str) -> usize {
    let Ok(metadata) = fs::metadata(root) else {
        return 0;
    };
    if !metadata.is_dir() {
        return 0;
    }

    let mut count = 0usize;
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let Ok(entries) = fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if let Ok(meta) = entry.metadata() {
                if meta.is_dir() {
                    stack.push(path);
                    continue;
                }
                if meta.is_file()
                    && path
                        .extension()
                        .and_then(|value| value.to_str())
                        .map(|value| value.eq_ignore_ascii_case(ext))
                        .unwrap_or(false)
                {
                    count += 1;
                }
            }
        }
    }
    count
}

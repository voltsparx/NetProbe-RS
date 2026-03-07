// Flow sketch: input -> core processing -> output model
// Pseudo-block:
//   read input -> process safely -> return deterministic output

use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};

use regex::bytes::{Captures, Regex, RegexBuilder};

use crate::models::ServiceIdentity;

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
    pub identity: ServiceIdentity,
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
    metadata: MatchMetadataTemplate,
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

#[derive(Debug, Clone, Default)]
struct MatchMetadataTemplate {
    product: Option<String>,
    version: Option<String>,
    info: Option<String>,
    hostname: Option<String>,
    operating_system: Option<String>,
    device_type: Option<String>,
    cpes: Vec<String>,
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
        let nmap_root = candidate_nmap_roots()
            .into_iter()
            .find(|root| root.join("nmap-service-probes").exists())
            .unwrap_or_else(|| Path::new("intel-source/nmap").to_path_buf());
        let probes_path = nmap_root.join("nmap-service-probes");
        let stats = count_nmap_script_assets(&nmap_root);
        let focus = focus_ports.iter().copied().collect::<HashSet<u16>>();
        let mut db = if let Ok(content) = fs::read_to_string(&probes_path) {
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
            if rule.applies_to(protocol, port) {
                if let Some(captures) = rule.regex.captures(banner) {
                    return Some(build_fingerprint_match(rule, captures, false));
                }
            }
        }

        for rule in &self.soft_rules {
            if rule.applies_to(protocol, port) {
                if let Some(captures) = rule.regex.captures(banner) {
                    return Some(build_fingerprint_match(rule, captures, true));
                }
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
    let (pattern, options, trailing) = extract_delimited_with_rest(matcher, 'm')?;
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
        metadata: parse_match_metadata_templates(trailing),
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
    let (body, options, _) = extract_delimited_with_rest(input, leader)?;
    Some((body, options))
}

fn extract_template_segment(input: &str) -> Option<(char, String, &str)> {
    let bytes = input.as_bytes();
    let delim = *bytes.first()? as char;
    let mut idx = 1usize;
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
        if b == delim as u8 {
            break;
        }
        idx += 1;
    }
    if idx >= bytes.len() {
        return None;
    }

    let body = input[1..idx].to_string();
    let rest = &input[idx + 1..];
    let option_len = rest
        .chars()
        .take_while(|ch| ch.is_ascii_alphabetic())
        .count();
    Some((delim, body, &rest[option_len..]))
}

fn extract_delimited_with_rest(input: &str, leader: char) -> Option<(String, String, &str)> {
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
    let trailing = &rest[options.len()..];
    Some((body, options, trailing))
}

fn parse_match_metadata_templates(raw: &str) -> MatchMetadataTemplate {
    let mut metadata = MatchMetadataTemplate::default();
    let mut input = raw.trim();

    while !input.is_empty() {
        input = input.trim_start();
        let mode_len = input
            .chars()
            .take_while(|ch| ch.is_ascii_alphabetic())
            .count();
        if mode_len == 0 {
            break;
        }

        let mode = &input[..mode_len];
        let mut cursor = &input[mode_len..];
        if mode.eq_ignore_ascii_case("cpe") && cursor.starts_with(':') {
            cursor = &cursor[1..];
        }
        let Some(delim) = cursor.chars().next() else {
            break;
        };
        if delim.is_ascii_whitespace() {
            break;
        }

        let Some((_template_delim, body, trailing)) = extract_template_segment(cursor) else {
            break;
        };

        let template = if mode.eq_ignore_ascii_case("cpe") {
            format!("cpe:{delim}{body}")
        } else {
            body
        };

        match mode {
            "p" => metadata.product = Some(template),
            "v" => metadata.version = Some(template),
            "i" => metadata.info = Some(template),
            "h" => metadata.hostname = Some(template),
            "o" => metadata.operating_system = Some(template),
            "d" => metadata.device_type = Some(template),
            "cpe" => metadata.cpes.push(template),
            _ => {}
        }

        input = trailing;
    }

    metadata
}

fn build_fingerprint_match(
    rule: &FingerprintRule,
    captures: Captures<'_>,
    soft: bool,
) -> FingerprintMatch {
    FingerprintMatch {
        service: rule.service.clone(),
        source: rule.source.clone(),
        soft,
        confidence: if soft { 0.64 } else { 0.93 },
        identity: ServiceIdentity {
            product: expand_template_opt(rule.metadata.product.as_deref(), &captures),
            version: expand_template_opt(rule.metadata.version.as_deref(), &captures),
            info: expand_template_opt(rule.metadata.info.as_deref(), &captures),
            hostname: expand_template_opt(rule.metadata.hostname.as_deref(), &captures),
            operating_system: expand_template_opt(
                rule.metadata.operating_system.as_deref(),
                &captures,
            ),
            device_type: expand_template_opt(rule.metadata.device_type.as_deref(), &captures),
            cpes: rule
                .metadata
                .cpes
                .iter()
                .filter_map(|template| expand_template_opt(Some(template.as_str()), &captures))
                .collect(),
        },
    }
}

fn expand_template_opt(template: Option<&str>, captures: &Captures<'_>) -> Option<String> {
    let template = template?;
    let expanded = expand_template(template, captures);
    if expanded.is_empty() {
        None
    } else {
        Some(expanded)
    }
}

fn expand_template(template: &str, captures: &Captures<'_>) -> String {
    let bytes = template.as_bytes();
    let mut idx = 0usize;
    let mut out = String::new();

    while idx < bytes.len() {
        match bytes[idx] {
            b'\\' => {
                if idx + 1 < bytes.len() {
                    out.push_str(&decode_template_escape(bytes, &mut idx));
                } else {
                    idx += 1;
                }
            }
            b'$' => {
                if let Some((value, consumed)) = expand_template_token(&template[idx..], captures) {
                    out.push_str(&value);
                    idx += consumed;
                } else {
                    out.push('$');
                    idx += 1;
                }
            }
            other => {
                out.push(char::from(other));
                idx += 1;
            }
        }
    }

    sanitize_template_output(&out)
}

fn decode_template_escape(bytes: &[u8], idx: &mut usize) -> String {
    let start = *idx;
    *idx += 1;
    if *idx >= bytes.len() {
        return String::new();
    }

    let result = match bytes[*idx] {
        b'r' => "\r".to_string(),
        b'n' => "\n".to_string(),
        b't' => "\t".to_string(),
        b'\\' => "\\".to_string(),
        b'/' => "/".to_string(),
        b'x' if *idx + 2 < bytes.len() => {
            let text = std::str::from_utf8(&bytes[*idx + 1..*idx + 3]).unwrap_or("");
            u8::from_str_radix(text, 16)
                .ok()
                .map(|value| String::from_utf8_lossy(&[value]).into_owned())
                .unwrap_or_default()
        }
        other => char::from(other).to_string(),
    };

    *idx = match bytes.get(start + 1) {
        Some(b'x') if start + 3 < bytes.len() => start + 4,
        Some(_) => start + 2,
        None => start + 1,
    };
    result
}

fn expand_template_token(input: &str, captures: &Captures<'_>) -> Option<(String, usize)> {
    let bytes = input.as_bytes();
    if bytes.first().copied()? != b'$' {
        return None;
    }

    if bytes.get(1).copied()?.is_ascii_digit() {
        let digit_len = input[1..]
            .chars()
            .take_while(|ch| ch.is_ascii_digit())
            .count();
        let index = input[1..1 + digit_len].parse::<usize>().ok()?;
        return Some((capture_as_text(captures, index), 1 + digit_len));
    }

    if let Some(token) = input.strip_prefix("$P(") {
        let close = token.find(')')?;
        let index = token[..close].parse::<usize>().ok()?;
        return Some((capture_as_printable(captures, index), close + 4));
    }

    if let Some(token) = input.strip_prefix("$I(") {
        let close = token.find(')')?;
        let args = &token[..close];
        let (index_raw, endian_raw) = args.split_once(',')?;
        let index = index_raw.parse::<usize>().ok()?;
        let endian = endian_raw.trim().trim_matches('"');
        return Some((capture_as_integer(captures, index, endian), close + 4));
    }

    if let Some(token) = input.strip_prefix("$SUBST(") {
        let close = token.find(')')?;
        let args = &token[..close];
        let mut parts = args.splitn(3, ',');
        let index = parts.next()?.trim().parse::<usize>().ok()?;
        let from = parts.next()?.trim().trim_matches('"');
        let to = parts.next()?.trim().trim_matches('"');
        let value = capture_as_printable(captures, index).replace(from, to);
        return Some((value, close + 8));
    }

    None
}

fn capture_as_text(captures: &Captures<'_>, index: usize) -> String {
    captures
        .get(index)
        .map(|item| String::from_utf8_lossy(item.as_bytes()).into_owned())
        .unwrap_or_default()
}

fn capture_as_printable(captures: &Captures<'_>, index: usize) -> String {
    captures
        .get(index)
        .map(|item| sanitize_banner_like(item.as_bytes()))
        .unwrap_or_default()
}

fn capture_as_integer(captures: &Captures<'_>, index: usize, endian: &str) -> String {
    let Some(matched) = captures.get(index) else {
        return String::new();
    };
    let bytes = matched.as_bytes();
    if bytes.is_empty() || bytes.len() > 8 {
        return String::new();
    }

    let value = match endian {
        "<" => bytes.iter().enumerate().fold(0u64, |acc, (shift, byte)| {
            acc | ((*byte as u64) << (shift * 8))
        }),
        _ => bytes
            .iter()
            .fold(0u64, |acc, byte| (acc << 8) | (*byte as u64)),
    };
    value.to_string()
}

fn sanitize_template_output(text: &str) -> String {
    let collapsed = text.split_whitespace().collect::<Vec<_>>().join(" ");
    collapsed
        .trim_matches(|ch: char| ch == ';' || ch == ',' || ch.is_ascii_whitespace())
        .to_string()
}

fn sanitize_banner_like(raw: &[u8]) -> String {
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
        } else if !last_was_space {
            out.push(' ');
            last_was_space = true;
        }
    }
    out.trim().to_string()
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

fn candidate_nmap_roots() -> [PathBuf; 2] {
    [
        Path::new("intel-source/nmap").to_path_buf(),
        Path::new("temp/nmap").to_path_buf(),
    ]
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_match_templates_and_cpe_metadata() {
        let probe = ProbeContext {
            protocol: ProbeProtocol::Tcp,
            name: "GetRequest".to_string(),
            payload: b"GET / HTTP/1.0\r\n\r\n".to_vec(),
            ports: vec![80],
        };
        let rule = parse_match_line(
            "match http m|^HTTP/1\\.1 200 OK\\r\\nServer: nginx/([\\d.]+)| p/nginx/ v/$1/ cpe:/a:nginx:nginx:$1/",
            Some(&probe),
        )
        .expect("rule");

        let captures = rule
            .regex
            .captures(b"HTTP/1.1 200 OK\r\nServer: nginx/1.25.3\r\n\r\n")
            .expect("captures");
        let matched = build_fingerprint_match(&rule, captures, false);

        assert_eq!(matched.service, "http");
        assert_eq!(matched.identity.product.as_deref(), Some("nginx"));
        assert_eq!(matched.identity.version.as_deref(), Some("1.25.3"));
        assert_eq!(
            matched.identity.cpes,
            vec!["cpe:/a:nginx:nginx:1.25.3".to_string()]
        );
    }

    #[test]
    fn expands_subst_and_integer_templates() {
        let regex = RegexBuilder::new("^X(.)_(..)_$").build().expect("regex");
        let captures = regex.captures(b"XA_12_").expect("captures");

        assert_eq!(expand_template("$P(1)", &captures), "A");
        assert_eq!(expand_template("$I(2,\">\")", &captures), "12594");
        assert_eq!(expand_template("v$SUBST(2,\"1\",\"7\")", &captures), "v72");
    }
}

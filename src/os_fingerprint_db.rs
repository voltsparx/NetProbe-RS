use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

use crate::models::{HostOsGuess, HostResult};

#[derive(Debug, Clone, Default)]
pub struct OsFingerprintStats {
    pub fingerprints_loaded: usize,
    pub classes_loaded: usize,
    pub cpes_loaded: usize,
}

#[derive(Debug, Clone)]
pub struct OsFingerprintDatabase {
    classes: Vec<OsClassRecord>,
    stats: OsFingerprintStats,
}

#[derive(Debug, Clone)]
struct OsClassRecord {
    vendor: String,
    family: String,
    generation: String,
    device_type: String,
    name_tokens: Vec<String>,
    tokens: Vec<String>,
    vendor_tokens: Vec<String>,
    family_tokens: Vec<String>,
    generation_tokens: Vec<String>,
    device_type_tokens: Vec<String>,
    cpes: Vec<String>,
    occurrences: usize,
}

#[derive(Debug, Default)]
struct FingerprintBlock {
    name: String,
    classes: Vec<String>,
    cpes: Vec<String>,
}

#[derive(Debug, Default)]
struct HostEvidence {
    os_hints: Vec<Vec<String>>,
    cpe_hints: Vec<CpeKey>,
    vendor_hints: Vec<String>,
    device_type_hints: Vec<String>,
    text_hints: Vec<String>,
    windows_signals: usize,
    unix_signals: usize,
    printer_signals: usize,
    appliance_signals: usize,
    ttl_hint: Option<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct CpeKey {
    part: char,
    vendor: String,
    product: String,
    normalized: String,
}

impl OsFingerprintDatabase {
    pub fn load() -> Self {
        let nmap_root = candidate_nmap_roots()
            .into_iter()
            .find(|root| root.join("nmap-os-db").exists())
            .unwrap_or_else(|| Path::new("intel-source/nmap").to_path_buf());
        let db_path = nmap_root.join("nmap-os-db");
        match fs::read_to_string(db_path) {
            Ok(content) => Self::from_os_db(&content),
            Err(_) => Self::empty(),
        }
    }

    pub fn empty() -> Self {
        Self {
            classes: Vec::new(),
            stats: OsFingerprintStats::default(),
        }
    }

    pub fn stats(&self) -> &OsFingerprintStats {
        &self.stats
    }

    pub fn guess_host(&self, host: &HostResult, ttl_hint: Option<u8>) -> Option<HostOsGuess> {
        if self.classes.is_empty() {
            return None;
        }

        let evidence = HostEvidence::from_host(host, ttl_hint);
        let mut best: Option<(&OsClassRecord, usize, &'static str, usize)> = None;

        for class in &self.classes {
            let (base_score, source, precision) = score_class(class, &evidence);
            if base_score == 0 {
                continue;
            }

            let score = base_score
                + vendor_boost(class, &evidence)
                + device_type_boost(class, &evidence)
                + platform_signal_boost(class, &evidence)
                + ttl_boost(class, &evidence, base_score);

            match best {
                Some((_, best_score, _, best_precision))
                    if score < best_score
                        || (score == best_score && precision < best_precision) => {}
                _ => best = Some((class, score, source, precision)),
            }
        }

        let (class, score, source, precision) = best?;
        if score < 72 {
            return None;
        }

        Some(HostOsGuess {
            label: class.concise_label(precision),
            source: source.to_string(),
            confidence: confidence_from_score(score, source),
            cpes: class.cpes.iter().take(4).cloned().collect(),
        })
    }

    fn from_os_db(content: &str) -> Self {
        let mut stats = OsFingerprintStats::default();
        let mut class_index = BTreeMap::<String, OsClassAggregate>::new();
        let mut current = FingerprintBlock::default();

        for line in content.lines() {
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with('#') {
                continue;
            }

            if let Some(name) = trimmed.strip_prefix("Fingerprint ") {
                if !current.name.is_empty() {
                    flush_block(&current, &mut class_index, &mut stats);
                }
                current = FingerprintBlock {
                    name: name.trim().to_string(),
                    classes: Vec::new(),
                    cpes: Vec::new(),
                };
                continue;
            }

            if let Some(class_line) = trimmed.strip_prefix("Class ") {
                current.classes.push(class_line.trim().to_string());
                continue;
            }

            if let Some(cpe_line) = trimmed.strip_prefix("CPE ") {
                let normalized = normalize_cpe_line(cpe_line);
                if !normalized.is_empty() {
                    current.cpes.push(normalized);
                }
            }
        }

        if !current.name.is_empty() {
            flush_block(&current, &mut class_index, &mut stats);
        }

        let classes = class_index
            .into_values()
            .map(OsClassAggregate::into_record)
            .collect::<Vec<_>>();

        stats.classes_loaded = classes.len();

        Self { classes, stats }
    }
}

#[derive(Debug, Default)]
struct OsClassAggregate {
    vendor: String,
    family: String,
    generation: String,
    device_type: String,
    name_tokens: BTreeSet<String>,
    cpes: BTreeSet<String>,
    occurrences: usize,
}

impl OsClassAggregate {
    fn into_record(self) -> OsClassRecord {
        let joined = format!(
            "{} {} {} {}",
            self.vendor, self.family, self.generation, self.device_type
        );
        let name_tokens = self.name_tokens.into_iter().collect::<Vec<_>>();
        OsClassRecord {
            vendor_tokens: normalized_tokens(&self.vendor),
            family_tokens: normalized_tokens(&self.family),
            generation_tokens: normalized_tokens(&self.generation),
            device_type_tokens: normalized_tokens(&self.device_type),
            name_tokens: name_tokens.clone(),
            tokens: normalized_tokens(&joined)
                .into_iter()
                .chain(
                    self.cpes
                        .iter()
                        .flat_map(|cpe| normalized_tokens(cpe))
                        .collect::<Vec<_>>(),
                )
                .chain(name_tokens.iter().cloned())
                .collect::<BTreeSet<_>>()
                .into_iter()
                .collect(),
            vendor: self.vendor,
            family: self.family,
            generation: self.generation,
            device_type: self.device_type,
            cpes: self.cpes.into_iter().collect(),
            occurrences: self.occurrences,
        }
    }
}

impl OsClassRecord {
    fn concise_label(&self, precision: usize) -> String {
        let mut parts = Vec::<String>::new();

        push_unique_part(&mut parts, &self.vendor);
        if !self.family.eq_ignore_ascii_case(&self.vendor) {
            push_unique_part(&mut parts, &self.family);
        }
        if precision >= 3 {
            push_unique_part(&mut parts, &self.generation);
        }
        if precision >= 2 && !generic_device_type(&self.device_type) {
            push_unique_part(&mut parts, &self.device_type);
        }

        if parts.is_empty() {
            "unknown platform".to_string()
        } else {
            parts.join(" ")
        }
    }
}

impl HostEvidence {
    fn from_host(host: &HostResult, ttl_hint: Option<u8>) -> Self {
        let mut os_hints = BTreeSet::<String>::new();
        let mut cpe_hints = BTreeSet::<String>::new();
        let mut vendor_hints = BTreeSet::<String>::new();
        let mut device_type_hints = BTreeSet::<String>::new();
        let mut text_hints = BTreeSet::<String>::new();

        if let Some(vendor) = host.device_vendor.as_deref() {
            for token in normalized_tokens(vendor) {
                vendor_hints.insert(token);
            }
        }
        if let Some(device_type) = host.device_class.as_deref() {
            for token in normalized_tokens(device_type) {
                device_type_hints.insert(token);
            }
        }
        extend_token_set(
            &mut text_hints,
            host.reverse_dns.as_deref().unwrap_or_default(),
        );

        for port in &host.ports {
            if let Some(service) = port.service.as_deref() {
                extend_token_set(&mut text_hints, service);
            }
            if let Some(banner) = port.banner.as_deref() {
                extend_token_set(&mut text_hints, banner);
            }
            let Some(identity) = port.service_identity.as_ref() else {
                continue;
            };

            if let Some(os) = identity.operating_system.as_deref() {
                let normalized = normalized_tokens(os).join(" ");
                if !normalized.is_empty() {
                    os_hints.insert(normalized);
                }
                extend_token_set(&mut text_hints, os);
            }

            if let Some(device_type) = identity.device_type.as_deref() {
                for token in normalized_tokens(device_type) {
                    device_type_hints.insert(token);
                }
                extend_token_set(&mut text_hints, device_type);
            }

            if let Some(product) = identity.product.as_deref() {
                extend_token_set(&mut text_hints, product);
            }
            if let Some(info) = identity.info.as_deref() {
                extend_token_set(&mut text_hints, info);
            }
            if let Some(hostname) = identity.hostname.as_deref() {
                extend_token_set(&mut text_hints, hostname);
            }

            for cpe in &identity.cpes {
                let normalized = normalize_cpe_line(cpe);
                if !normalized.is_empty() {
                    cpe_hints.insert(normalized);
                }
            }
        }

        Self {
            os_hints: os_hints
                .into_iter()
                .map(|hint| hint.split_whitespace().map(str::to_string).collect())
                .collect(),
            cpe_hints: cpe_hints
                .into_iter()
                .filter_map(|cpe| CpeKey::parse(&cpe))
                .collect(),
            vendor_hints: vendor_hints.into_iter().collect(),
            device_type_hints: device_type_hints.into_iter().collect(),
            windows_signals: signal_count(&text_hints, WINDOWS_SIGNAL_TOKENS),
            unix_signals: signal_count(&text_hints, UNIX_SIGNAL_TOKENS),
            printer_signals: signal_count(&text_hints, PRINTER_SIGNAL_TOKENS),
            appliance_signals: signal_count(&text_hints, APPLIANCE_SIGNAL_TOKENS),
            text_hints: text_hints.into_iter().collect(),
            ttl_hint,
        }
    }
}

impl CpeKey {
    fn parse(raw: &str) -> Option<Self> {
        let normalized = normalize_cpe_line(raw);
        let payload = normalized.strip_prefix("cpe:/")?;
        let mut parts = payload.split(':');
        let part = parts.next()?.chars().next()?;
        let vendor = normalize_token(parts.next()?);
        let product = normalize_token(parts.next()?);
        if vendor.is_empty() || product.is_empty() {
            return None;
        }

        Some(Self {
            part,
            vendor,
            product,
            normalized,
        })
    }
}

fn flush_block(
    block: &FingerprintBlock,
    class_index: &mut BTreeMap<String, OsClassAggregate>,
    stats: &mut OsFingerprintStats,
) {
    stats.fingerprints_loaded += 1;
    stats.cpes_loaded += block.cpes.len();

    for class_line in &block.classes {
        let Some((vendor, family, generation, device_type)) = parse_class_line(class_line) else {
            continue;
        };
        let key = format!(
            "{}|{}|{}|{}",
            normalize_token(&vendor),
            normalize_token(&family),
            normalize_token(&generation),
            normalize_token(&device_type)
        );
        let entry = class_index.entry(key).or_default();
        entry.vendor = vendor;
        entry.family = family;
        entry.generation = generation;
        entry.device_type = device_type;
        entry.occurrences += 1;
        entry.name_tokens.extend(normalized_tokens(&block.name));
        entry.cpes.extend(block.cpes.iter().cloned());
    }
}

fn parse_class_line(raw: &str) -> Option<(String, String, String, String)> {
    let mut parts = raw.split('|').map(|part| part.trim());
    let vendor = parts.next()?.to_string();
    let family = parts.next().unwrap_or_default().to_string();
    let generation = parts.next().unwrap_or_default().to_string();
    let device_type = parts.next().unwrap_or_default().to_string();

    if vendor.is_empty() && family.is_empty() && generation.is_empty() && device_type.is_empty() {
        None
    } else {
        Some((vendor, family, generation, device_type))
    }
}

fn normalize_cpe_line(raw: &str) -> String {
    raw.split_whitespace()
        .next()
        .unwrap_or_default()
        .trim()
        .trim_end_matches(" auto")
        .to_ascii_lowercase()
}

fn score_class(class: &OsClassRecord, evidence: &HostEvidence) -> (usize, &'static str, usize) {
    let mut best = (0usize, "passive-service-correlation", 1usize);

    for cpe in &evidence.cpe_hints {
        let score = cpe_score(class, cpe);
        if score > best.0 {
            best = (score, "passive-cpe-correlation", 3);
        }
    }

    for hint_tokens in &evidence.os_hints {
        let (score, precision) = service_hint_score(class, hint_tokens);
        if score > best.0 {
            best = (score, "passive-service-correlation", precision);
        }
    }

    let (text_score, source, precision) = text_hint_score(class, &evidence.text_hints);
    if (evidence.os_hints.is_empty() && text_score > best.0) || (best.0 == 0 && text_score > 0) {
        best = (text_score, source, precision);
    }

    best
}

fn cpe_score(class: &OsClassRecord, cpe: &CpeKey) -> usize {
    if class.cpes.iter().any(|item| item == &cpe.normalized) {
        return 170 + class.occurrences.min(20);
    }

    let direct_cpe_keys = class
        .cpes
        .iter()
        .filter_map(|item| CpeKey::parse(item))
        .collect::<Vec<_>>();

    if direct_cpe_keys.iter().any(|item| {
        item.part == cpe.part && item.vendor == cpe.vendor && item.product == cpe.product
    }) {
        return 156 + class.occurrences.min(16);
    }

    if direct_cpe_keys.iter().any(|item| item.vendor == cpe.vendor) {
        let product_tokens = normalized_tokens(&cpe.product);
        let overlap = token_overlap(&class.tokens, &product_tokens);
        if overlap > 0 {
            return 132 + overlap * 10 + class.occurrences.min(12);
        }
    }

    0
}

fn service_hint_score(class: &OsClassRecord, hint_tokens: &[String]) -> (usize, usize) {
    if hint_tokens.is_empty() {
        return (0, 1);
    }

    let vendor_overlap = token_overlap(&class.vendor_tokens, hint_tokens);
    let family_overlap = token_overlap(&class.family_tokens, hint_tokens);
    let generation_overlap = token_overlap(&class.generation_tokens, hint_tokens);
    let device_overlap = token_overlap(&class.device_type_tokens, hint_tokens);

    if vendor_overlap == 0 && family_overlap == 0 {
        return (0, 1);
    }

    let mut score =
        vendor_overlap * 34 + family_overlap * 52 + generation_overlap * 40 + device_overlap * 10;
    if vendor_overlap > 0 && family_overlap > 0 {
        score += 22;
    }
    if generation_overlap > 0 {
        score += 16;
    }
    if hint_tokens.len() == 1 && family_overlap == 1 && generation_overlap == 0 {
        score = score.saturating_sub(14);
    }
    score += class.occurrences.min(10);

    let precision = if generation_overlap > 0 {
        3
    } else if device_overlap > 0 {
        2
    } else {
        1
    };

    (score, precision)
}

fn text_hint_score(class: &OsClassRecord, text_hints: &[String]) -> (usize, &'static str, usize) {
    if text_hints.is_empty() {
        return (0, "passive-banner-correlation", 1);
    }

    let name_overlap = token_overlap(&class.name_tokens, text_hints);
    let vendor_overlap = token_overlap(&class.vendor_tokens, text_hints);
    let family_overlap = token_overlap(&class.family_tokens, text_hints);
    let generation_overlap = token_overlap(&class.generation_tokens, text_hints);
    let total_overlap = token_overlap(&class.tokens, text_hints);

    if total_overlap == 0 || (name_overlap == 0 && vendor_overlap == 0 && family_overlap == 0) {
        return (0, "passive-banner-correlation", 1);
    }

    let mut score = name_overlap * 36
        + family_overlap * 28
        + generation_overlap * 22
        + vendor_overlap * 18
        + total_overlap * 6
        + class.occurrences.min(10);
    if name_overlap > 0 && (family_overlap > 0 || generation_overlap > 0) {
        score += 18;
    }
    if generation_overlap > 0 {
        score += 12;
    }

    let source = if name_overlap > 0 {
        "passive-fingerprint-correlation"
    } else {
        "passive-banner-correlation"
    };
    let precision = if generation_overlap > 0 || name_overlap >= 2 {
        3
    } else if family_overlap > 0 && vendor_overlap > 0 {
        2
    } else {
        1
    };

    (score, source, precision)
}

fn vendor_boost(class: &OsClassRecord, evidence: &HostEvidence) -> usize {
    if evidence.vendor_hints.is_empty()
        || token_overlap(&class.vendor_tokens, &evidence.vendor_hints) == 0
    {
        0
    } else {
        10
    }
}

fn device_type_boost(class: &OsClassRecord, evidence: &HostEvidence) -> usize {
    if evidence.device_type_hints.is_empty()
        || token_overlap(&class.device_type_tokens, &evidence.device_type_hints) == 0
    {
        0
    } else {
        8
    }
}

fn platform_signal_boost(class: &OsClassRecord, evidence: &HostEvidence) -> usize {
    let mut boost = 0usize;

    if evidence.windows_signals > 0
        && class
            .tokens
            .iter()
            .any(|token| matches!(token.as_str(), "windows" | "microsoft"))
    {
        boost += 12 + evidence.windows_signals.min(4) * 6;
    }

    if evidence.unix_signals > 0
        && class
            .tokens
            .iter()
            .any(|token| matches!(token.as_str(), "linux" | "unix" | "bsd" | "solaris"))
    {
        boost += 10 + evidence.unix_signals.min(4) * 5;
    }

    if evidence.printer_signals > 0
        && class
            .device_type_tokens
            .iter()
            .any(|token| token == "printer")
    {
        boost += 10 + evidence.printer_signals.min(3) * 5;
    }

    if evidence.appliance_signals > 0
        && class.device_type_tokens.iter().any(|token| {
            matches!(
                token.as_str(),
                "router" | "switch" | "firewall" | "bridge" | "broadband" | "wap"
            )
        })
    {
        boost += 8 + evidence.appliance_signals.min(3) * 4;
    }

    boost
}

fn ttl_boost(class: &OsClassRecord, evidence: &HostEvidence, base_score: usize) -> usize {
    let Some(ttl) = evidence.ttl_hint else {
        return 0;
    };
    if base_score < 90 {
        return 0;
    }

    if ttl <= 64
        && class
            .tokens
            .iter()
            .any(|token| matches!(token.as_str(), "linux" | "unix" | "bsd" | "solaris"))
    {
        return 6;
    }

    if (65..=128).contains(&ttl)
        && class
            .tokens
            .iter()
            .any(|token| matches!(token.as_str(), "windows" | "microsoft"))
    {
        return 8;
    }

    0
}

fn confidence_from_score(score: usize, source: &str) -> f32 {
    let base = match source {
        "passive-cpe-correlation" => 0.76f32,
        "passive-fingerprint-correlation" => 0.67f32,
        _ => 0.61f32,
    };
    let scaled = (score as f32 / 220.0).clamp(0.0, 1.0);
    (base + scaled * 0.22).min(0.98)
}

fn token_overlap(left: &[String], right: &[String]) -> usize {
    right.iter().filter(|token| left.contains(token)).count()
}

fn normalized_tokens(raw: &str) -> Vec<String> {
    let mut cleaned = String::with_capacity(raw.len());
    for ch in raw.chars() {
        if ch.is_ascii_alphanumeric() {
            cleaned.push(ch.to_ascii_lowercase());
        } else {
            cleaned.push(' ');
        }
    }

    cleaned
        .split_whitespace()
        .map(normalize_token)
        .filter(|token| token.len() > 1 && !is_stop_token(token))
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

fn extend_token_set(bucket: &mut BTreeSet<String>, raw: &str) {
    bucket.extend(normalized_tokens(raw));
}

fn normalize_token(raw: &str) -> String {
    raw.chars()
        .filter(|ch| ch.is_ascii_alphanumeric())
        .flat_map(|ch| ch.to_lowercase())
        .collect::<String>()
}

fn is_stop_token(token: &str) -> bool {
    matches!(
        token,
        "and"
            | "auto"
            | "device"
            | "family"
            | "host"
            | "inc"
            | "network"
            | "series"
            | "software"
            | "system"
            | "systems"
            | "the"
            | "version"
    )
}

fn push_unique_part(parts: &mut Vec<String>, value: &str) {
    if value.trim().is_empty() {
        return;
    }
    if parts
        .iter()
        .any(|existing| existing.eq_ignore_ascii_case(value.trim()))
    {
        return;
    }
    parts.push(value.trim().to_string());
}

fn generic_device_type(value: &str) -> bool {
    matches!(
        value.trim().to_ascii_lowercase().as_str(),
        "" | "general purpose" | "specialized"
    )
}

fn signal_count(tokens: &BTreeSet<String>, patterns: &[&str]) -> usize {
    tokens
        .iter()
        .filter(|token| patterns.contains(&token.as_str()))
        .count()
}

const WINDOWS_SIGNAL_TOKENS: &[&str] = &[
    "exchange",
    "iis",
    "microsoft",
    "microsoftds",
    "msrpc",
    "netbios",
    "rdp",
    "winrm",
    "windows",
    "wsman",
];

const UNIX_SIGNAL_TOKENS: &[&str] = &[
    "bsd", "courier", "debian", "dovecot", "exim", "freebsd", "linux", "nfs", "openbsd", "openssh",
    "postfix", "rpcbind", "solaris", "ubuntu", "unix",
];

const PRINTER_SIGNAL_TOKENS: &[&str] = &["ipp", "jetdirect", "pjl", "printer", "printserver"];

const APPLIANCE_SIGNAL_TOKENS: &[&str] = &[
    "appliance",
    "cisco",
    "firewall",
    "fortinet",
    "junos",
    "mikrotik",
    "router",
    "routeros",
    "switch",
    "ubiquiti",
];

fn candidate_nmap_roots() -> [PathBuf; 2] {
    [
        Path::new("intel-source/nmap").to_path_buf(),
        Path::new("temp/nmap").to_path_buf(),
    ]
}

#[cfg(test)]
mod tests {
    use super::OsFingerprintDatabase;
    use crate::models::{HostOsGuess, HostResult, PortFinding, PortState, ServiceIdentity};

    fn empty_host() -> HostResult {
        HostResult {
            target: "example".to_string(),
            ip: "192.0.2.10".to_string(),
            reverse_dns: None,
            observed_mac: None,
            device_class: None,
            device_vendor: None,
            operating_system: None,
            phantom_device_check: None,
            safety_actions: Vec::new(),
            warnings: Vec::new(),
            ports: Vec::new(),
            risk_score: 0,
            insights: Vec::new(),
            defensive_advice: Vec::new(),
            learning_notes: Vec::new(),
            lua_findings: Vec::new(),
        }
    }

    #[test]
    fn parses_unique_classes_and_cpes() {
        let db = OsFingerprintDatabase::from_os_db(
            "Fingerprint Windows desktop\n\
             Class Microsoft | Windows | 11 | general purpose\n\
             CPE cpe:/o:microsoft:windows_11 auto\n\
             Fingerprint Router\n\
             Class Linux | Linux | 4.X | broadband router\n\
             CPE cpe:/o:linux:linux_kernel:4\n",
        );

        let stats = db.stats();
        assert_eq!(stats.fingerprints_loaded, 2);
        assert_eq!(stats.classes_loaded, 2);
        assert_eq!(stats.cpes_loaded, 2);
    }

    #[test]
    fn guesses_from_service_os_hint() {
        let db = OsFingerprintDatabase::from_os_db(
            "Fingerprint Windows desktop\n\
             Class Microsoft | Windows | 11 | general purpose\n\
             CPE cpe:/o:microsoft:windows_11 auto\n\
             Fingerprint Linux server\n\
             Class Linux | Linux | 6.X | general purpose\n\
             CPE cpe:/o:linux:linux_kernel:6\n",
        );
        let mut host = empty_host();
        host.ports.push(PortFinding {
            port: 445,
            protocol: "tcp".to_string(),
            state: PortState::Open,
            service: Some("microsoft-ds".to_string()),
            service_identity: Some(ServiceIdentity {
                product: Some("SMB".to_string()),
                version: None,
                info: None,
                hostname: None,
                operating_system: Some("Windows 11".to_string()),
                device_type: None,
                cpes: Vec::new(),
            }),
            banner: None,
            reason: "test".to_string(),
            matched_by: Some("test".to_string()),
            confidence: Some(0.8),
            vulnerability_hints: Vec::new(),
            educational_note: None,
            latency_ms: None,
            explanation: None,
        });

        let guess = db.guess_host(&host, Some(117)).expect("os guess");
        assert_eq!(guess.label, "Microsoft Windows 11");
        assert_eq!(guess.source, "passive-service-correlation");
    }

    #[test]
    fn prefers_exact_cpe_correlation() {
        let db = OsFingerprintDatabase::from_os_db(
            "Fingerprint Router\n\
             Class Linux | Linux | 4.X | broadband router\n\
             CPE cpe:/o:linux:linux_kernel:4\n\
             Fingerprint Generic\n\
             Class Linux | Linux | 6.X | general purpose\n\
             CPE cpe:/o:linux:linux_kernel:6\n",
        );
        let mut host = empty_host();
        host.device_class = Some("broadband router".to_string());
        host.operating_system = Some(HostOsGuess {
            label: "stale".to_string(),
            source: "old".to_string(),
            confidence: 0.1,
            cpes: Vec::new(),
        });
        host.ports.push(PortFinding {
            port: 443,
            protocol: "tcp".to_string(),
            state: PortState::Open,
            service: Some("https".to_string()),
            service_identity: Some(ServiceIdentity {
                product: Some("router-os".to_string()),
                version: None,
                info: None,
                hostname: None,
                operating_system: Some("Linux".to_string()),
                device_type: Some("router".to_string()),
                cpes: vec!["cpe:/o:linux:linux_kernel:4".to_string()],
            }),
            banner: None,
            reason: "test".to_string(),
            matched_by: Some("test".to_string()),
            confidence: Some(0.8),
            vulnerability_hints: Vec::new(),
            educational_note: None,
            latency_ms: None,
            explanation: None,
        });

        let guess = db.guess_host(&host, Some(61)).expect("cpe-backed os guess");
        assert_eq!(guess.label, "Linux 4.X broadband router");
        assert_eq!(guess.source, "passive-cpe-correlation");
    }

    #[test]
    fn fingerprints_from_banner_text_without_explicit_os_field() {
        let db = OsFingerprintDatabase::from_os_db(
            "Fingerprint Ubuntu Linux 22.04 server\n\
             Class Linux | Linux | Ubuntu 22.04 | general purpose\n\
             Fingerprint Windows Server 2022\n\
             Class Microsoft | Windows | Server 2022 | general purpose\n",
        );
        let mut host = empty_host();
        host.reverse_dns = Some("git-ubuntu-01.example".to_string());
        host.ports.push(PortFinding {
            port: 22,
            protocol: "tcp".to_string(),
            state: PortState::Open,
            service: Some("ssh".to_string()),
            service_identity: Some(ServiceIdentity {
                product: Some("OpenSSH".to_string()),
                version: Some("9.6p1".to_string()),
                info: Some("Ubuntu-3ubuntu13.8".to_string()),
                hostname: None,
                operating_system: None,
                device_type: None,
                cpes: vec!["cpe:/a:openbsd:openssh:9.6p1".to_string()],
            }),
            banner: Some("SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.8".to_string()),
            reason: "test".to_string(),
            matched_by: Some("test".to_string()),
            confidence: Some(0.78),
            vulnerability_hints: Vec::new(),
            educational_note: None,
            latency_ms: None,
            explanation: None,
        });

        let guess = db
            .guess_host(&host, Some(58))
            .expect("banner-backed os guess");
        assert_eq!(guess.label, "Linux Ubuntu 22.04");
        assert_eq!(guess.source, "passive-fingerprint-correlation");
    }

    #[test]
    fn platform_signals_and_banner_text_favor_windows_hosts() {
        let db = OsFingerprintDatabase::from_os_db(
            "Fingerprint Windows Server 2019\n\
             Class Microsoft | Windows | Server 2019 | general purpose\n\
             Fingerprint Linux server\n\
             Class Linux | Linux | 6.X | general purpose\n",
        );
        let mut host = empty_host();
        host.reverse_dns = Some("exchange-mbx-01.corp.example".to_string());
        host.ports.push(PortFinding {
            port: 80,
            protocol: "tcp".to_string(),
            state: PortState::Open,
            service: Some("http".to_string()),
            service_identity: Some(ServiceIdentity {
                product: Some("Microsoft IIS".to_string()),
                version: Some("10.0".to_string()),
                info: Some("Microsoft-IIS/10.0".to_string()),
                hostname: None,
                operating_system: Some("Windows".to_string()),
                device_type: None,
                cpes: Vec::new(),
            }),
            banner: Some("HTTP/1.1 200 OK Server: Microsoft-IIS/10.0".to_string()),
            reason: "test".to_string(),
            matched_by: Some("test".to_string()),
            confidence: Some(0.82),
            vulnerability_hints: Vec::new(),
            educational_note: None,
            latency_ms: None,
            explanation: None,
        });
        host.ports.push(PortFinding {
            port: 445,
            protocol: "tcp".to_string(),
            state: PortState::Open,
            service: Some("microsoft-ds".to_string()),
            service_identity: Some(ServiceIdentity {
                product: Some("SMB".to_string()),
                version: None,
                info: Some("Microsoft file sharing".to_string()),
                hostname: None,
                operating_system: None,
                device_type: None,
                cpes: Vec::new(),
            }),
            banner: None,
            reason: "test".to_string(),
            matched_by: Some("test".to_string()),
            confidence: Some(0.74),
            vulnerability_hints: Vec::new(),
            educational_note: None,
            latency_ms: None,
            explanation: None,
        });

        let guess = db.guess_host(&host, Some(118)).expect("windows os guess");
        assert_eq!(guess.label, "Microsoft Windows");
        assert_ne!(guess.source, "passive-cpe-correlation");
    }
}

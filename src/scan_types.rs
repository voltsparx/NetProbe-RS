#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScanTypeStatus {
    Implemented,
    Partial,
    Planned,
}

impl ScanTypeStatus {
    fn as_str(self) -> &'static str {
        match self {
            ScanTypeStatus::Implemented => "implemented",
            ScanTypeStatus::Partial => "partial",
            ScanTypeStatus::Planned => "planned",
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct ScanTypeEntry {
    pub id: &'static str,
    pub category: &'static str,
    pub status: ScanTypeStatus,
    pub flags: &'static [&'static str],
    pub aliases: &'static [&'static str],
    pub summary: &'static str,
    pub docs: &'static [&'static str],
}

const SCAN_TYPES: &[ScanTypeEntry] = &[
    ScanTypeEntry {
        id: "arp",
        category: "discovery",
        status: ScanTypeStatus::Implemented,
        flags: &["--arp", "--arp-scan", "-PR"],
        aliases: &["local-neighbor-discovery"],
        summary: "local IPv4 ARP neighbor discovery for first-touch reachability and device context.",
        docs: &["docs/scan-types-overview.md"],
    },
    ScanTypeEntry {
        id: "ping-scan",
        category: "discovery",
        status: ScanTypeStatus::Partial,
        flags: &["-sn", "--ping-scan"],
        aliases: &["host-discovery-only"],
        summary: "host-up discovery without a follow-up port scan is available as a lightweight fetcher-driven lane, but it does not yet match Nmap's full multi-probe host-discovery behavior.",
        docs: &["cooking-reverse-engineering/nmap-scan-encyclopedia.txt"],
    },
    ScanTypeEntry {
        id: "icmp-echo",
        category: "discovery",
        status: ScanTypeStatus::Partial,
        flags: &["-PE", "internal/fetcher"],
        aliases: &["ping", "echo-request"],
        summary: "ICMP reachability exists in the fetcher/crafter plane, but is not yet a dedicated top-level scan flag.",
        docs: &["docs/scan-types-overview.md"],
    },
    ScanTypeEntry {
        id: "icmp-timestamp",
        category: "discovery",
        status: ScanTypeStatus::Planned,
        flags: &["-PP"],
        aliases: &["timestamp-ping"],
        summary: "ICMP timestamp discovery is tracked in the catalog, but not yet implemented as a dedicated probe family.",
        docs: &["cooking-reverse-engineering/nmap-scan-encyclopedia.txt"],
    },
    ScanTypeEntry {
        id: "icmp-netmask",
        category: "discovery",
        status: ScanTypeStatus::Planned,
        flags: &["-PM"],
        aliases: &["netmask-ping"],
        summary: "ICMP netmask discovery is cataloged from the encyclopedia and is not a live runtime lane.",
        docs: &["cooking-reverse-engineering/nmap-scan-encyclopedia.txt"],
    },
    ScanTypeEntry {
        id: "tcp-ping",
        category: "discovery",
        status: ScanTypeStatus::Planned,
        flags: &["planned", "-PS", "-PA"],
        aliases: &["tcp-syn-ping", "tcp-ack-ping"],
        summary: "host discovery via small TCP probes to common ports is listed in framework inventory but not exposed as a dedicated scan lane yet.",
        docs: &["docs/scan-types-overview.md"],
    },
    ScanTypeEntry {
        id: "tcp-syn-ping",
        category: "discovery",
        status: ScanTypeStatus::Planned,
        flags: &["-PS <ports>"],
        aliases: &["tcp-ping", "syn-ping"],
        summary: "TCP SYN host discovery is cataloged from the Nmap encyclopedia and awaits a dedicated discovery-only lane.",
        docs: &["cooking-reverse-engineering/nmap-scan-encyclopedia.txt"],
    },
    ScanTypeEntry {
        id: "tcp-ack-ping",
        category: "discovery",
        status: ScanTypeStatus::Planned,
        flags: &["-PA <ports>"],
        aliases: &["tcp-ping", "ack-ping"],
        summary: "TCP ACK host discovery is cataloged from the Nmap encyclopedia and currently remains a non-executable entry.",
        docs: &["cooking-reverse-engineering/nmap-scan-encyclopedia.txt"],
    },
    ScanTypeEntry {
        id: "udp-ping",
        category: "discovery",
        status: ScanTypeStatus::Planned,
        flags: &["-PU <ports>"],
        aliases: &["udp-host-discovery"],
        summary: "UDP host discovery is listed in framework inventory, but the current runtime only exposes UDP as a port-scan lane.",
        docs: &["cooking-reverse-engineering/nmap-scan-encyclopedia.txt"],
    },
    ScanTypeEntry {
        id: "sctp-init-ping",
        category: "discovery",
        status: ScanTypeStatus::Planned,
        flags: &["-PY <ports>"],
        aliases: &["sctp-ping"],
        summary: "SCTP INIT host discovery is cataloged from the encyclopedia and not yet exposed as a runtime discovery lane.",
        docs: &["cooking-reverse-engineering/nmap-scan-encyclopedia.txt"],
    },
    ScanTypeEntry {
        id: "ip-proto-ping",
        category: "discovery",
        status: ScanTypeStatus::Planned,
        flags: &["-PO <proto>"],
        aliases: &["protocol-ping"],
        summary: "IP protocol ping is documented in the framework catalog, but not implemented as a discovery-only probe family.",
        docs: &["cooking-reverse-engineering/nmap-scan-encyclopedia.txt"],
    },
    ScanTypeEntry {
        id: "connect",
        category: "classic",
        status: ScanTypeStatus::Implemented,
        flags: &["--connect", "--connect-scan", "-sT"],
        aliases: &["tcp-connect"],
        summary: "user-space TCP connect scanning without privileged raw packets.",
        docs: &["docs/scan-types-overview.md"],
    },
    ScanTypeEntry {
        id: "syn",
        category: "classic",
        status: ScanTypeStatus::Implemented,
        flags: &["--syn", "--syn-scan", "--stealth", "--stealth-scan", "-sS"],
        aliases: &["half-open", "traditional-stealth-scan"],
        summary: "privileged SYN scanning with controlled-firehose scheduling and hybrid enrichment.",
        docs: &["docs/scan-types-overview.md"],
    },
    ScanTypeEntry {
        id: "udp",
        category: "classic",
        status: ScanTypeStatus::Implemented,
        flags: &["--udp", "--udp-scan", "-sU"],
        aliases: &["udp-probe"],
        summary: "UDP probing within the async path, still bounded by safety guardrails and adaptive retries.",
        docs: &["docs/scan-types-overview.md"],
    },
    ScanTypeEntry {
        id: "ack",
        category: "classic",
        status: ScanTypeStatus::Planned,
        flags: &["planned --ack", "-sA"],
        aliases: &["ack-scan"],
        summary: "firewall-mapping ACK scan is cataloged but does not yet have a dedicated raw-probe engine.",
        docs: &["self-assesment/scan-combo.txt"],
    },
    ScanTypeEntry {
        id: "null",
        category: "classic",
        status: ScanTypeStatus::Planned,
        flags: &["planned --null", "-sN"],
        aliases: &["null-scan"],
        summary: "NULL flag scan is part of the framework inventory and combo recipes, but not a live engine yet.",
        docs: &["self-assesment/scan-combo.txt"],
    },
    ScanTypeEntry {
        id: "fin",
        category: "classic",
        status: ScanTypeStatus::Planned,
        flags: &["planned --fin", "-sF"],
        aliases: &["fin-scan"],
        summary: "FIN scan is listed as a classic raw-flag scan and remains a planned engine.",
        docs: &["self-assesment/scan-combo.txt"],
    },
    ScanTypeEntry {
        id: "xmas",
        category: "classic",
        status: ScanTypeStatus::Planned,
        flags: &["planned --xmas", "-sX"],
        aliases: &["xmas-scan"],
        summary: "Xmas (FIN/PSH/URG) scan is cataloged for future raw-flag support and combo recipes.",
        docs: &["self-assesment/scan-combo.txt"],
    },
    ScanTypeEntry {
        id: "maimon",
        category: "classic",
        status: ScanTypeStatus::Planned,
        flags: &["-sM"],
        aliases: &["fin-ack-scan"],
        summary: "Maimon FIN/ACK scanning is cataloged from the encyclopedia, but remains non-executable in the current framework.",
        docs: &["cooking-reverse-engineering/nmap-scan-encyclopedia.txt"],
    },
    ScanTypeEntry {
        id: "custom-scanflags",
        category: "classic",
        status: ScanTypeStatus::Planned,
        flags: &["--scanflags <flags>"],
        aliases: &["custom-tcp-flags"],
        summary: "manually composed TCP flag sets are documented in the catalog, but not exposed as a runtime lane.",
        docs: &[
            "cooking-reverse-engineering/nmap-scan-encyclopedia.txt",
            "cooking-reverse-engineering/packet-factory.txt",
        ],
    },
    ScanTypeEntry {
        id: "zombie",
        category: "classic",
        status: ScanTypeStatus::Planned,
        flags: &["planned --zombie <host>", "-sI <zombie>"],
        aliases: &["idle", "idle-scan", "zombie-reflection"],
        summary: "idle/zombie scan via predictable IPID deltas is documented from Nmap reverse-engineering, but remains framework inventory only for now.",
        docs: &[
            "cooking-reverse-engineering/zombie-scan-from-nmap.txt",
            "self-assesment/scan-combo.txt",
        ],
    },
    ScanTypeEntry {
        id: "ip-protocol",
        category: "classic",
        status: ScanTypeStatus::Planned,
        flags: &["planned --ip-protocol", "-sO"],
        aliases: &["protocol-scan"],
        summary: "IP protocol scanning is tracked in the all-rounder catalog but not implemented as a runtime lane yet.",
        docs: &["docs/scan-types-overview.md"],
    },
    ScanTypeEntry {
        id: "sctp-init",
        category: "classic",
        status: ScanTypeStatus::Planned,
        flags: &["planned --sctp-init", "-sY"],
        aliases: &["sctp-scan"],
        summary: "SCTP INIT scanning is listed for telecom-oriented coverage and remains a planned engine.",
        docs: &["docs/scan-types-overview.md"],
    },
    ScanTypeEntry {
        id: "sctp-cookie",
        category: "classic",
        status: ScanTypeStatus::Planned,
        flags: &["-sZ"],
        aliases: &["sctp-cookie-echo"],
        summary: "SCTP COOKIE-ECHO scanning is cataloged from the encyclopedia and is not yet an executable lane.",
        docs: &["cooking-reverse-engineering/nmap-scan-encyclopedia.txt"],
    },
    ScanTypeEntry {
        id: "ftp-bounce",
        category: "evasion",
        status: ScanTypeStatus::Planned,
        flags: &["-b <proxy>"],
        aliases: &["bounce-scan"],
        summary: "legacy FTP bounce proxying is cataloged for completeness, but not implemented as a runtime path.",
        docs: &["cooking-reverse-engineering/nmap-scan-encyclopedia.txt"],
    },
    ScanTypeEntry {
        id: "window",
        category: "evasion",
        status: ScanTypeStatus::Planned,
        flags: &["-sW"],
        aliases: &["tcp-window-scan"],
        summary: "window-size-based firewall mapping is cataloged from the encyclopedia and remains non-executable in the current build.",
        docs: &["cooking-reverse-engineering/nmap-scan-encyclopedia.txt"],
    },
    ScanTypeEntry {
        id: "fragment",
        category: "evasion",
        status: ScanTypeStatus::Planned,
        flags: &["-f", "--mtu <val>"],
        aliases: &["packet-fragmentation"],
        summary: "packet fragmentation and custom MTU evasions are cataloged for reference and not exposed as a runtime capability.",
        docs: &["cooking-reverse-engineering/nmap-scan-encyclopedia.txt"],
    },
    ScanTypeEntry {
        id: "decoy",
        category: "evasion",
        status: ScanTypeStatus::Planned,
        flags: &["-D <decoy1,decoy2,...>", "--decoy <list>"],
        aliases: &["decoy-scan"],
        summary: "decoy source masking is documented in the catalog, but not executable in the framework runtime.",
        docs: &["cooking-reverse-engineering/nmap-scan-encyclopedia.txt"],
    },
    ScanTypeEntry {
        id: "spoof-source",
        category: "evasion",
        status: ScanTypeStatus::Planned,
        flags: &["-S <ip>", "--spoof-source <ip>"],
        aliases: &["source-spoof"],
        summary: "source-address spoofing is cataloged from the encyclopedia and intentionally not exposed as a runtime path.",
        docs: &["cooking-reverse-engineering/nmap-scan-encyclopedia.txt"],
    },
    ScanTypeEntry {
        id: "interface-bind",
        category: "evasion",
        status: ScanTypeStatus::Planned,
        flags: &["-e <iface>", "--interface <iface>"],
        aliases: &["force-interface"],
        summary: "forced interface selection is cataloged from the encyclopedia and does not have a dedicated CLI/runtime lane yet.",
        docs: &["cooking-reverse-engineering/nmap-scan-encyclopedia.txt"],
    },
    ScanTypeEntry {
        id: "source-port-pin",
        category: "evasion",
        status: ScanTypeStatus::Planned,
        flags: &["-g <port>", "--source-port <port>"],
        aliases: &["source-port"],
        summary: "pinned source-port behavior is cataloged from the encyclopedia and intentionally not exposed as a runtime feature.",
        docs: &["cooking-reverse-engineering/nmap-scan-encyclopedia.txt"],
    },
    ScanTypeEntry {
        id: "banner",
        category: "enrichment",
        status: ScanTypeStatus::Implemented,
        flags: &["--service-detect", "--banners", "-sV"],
        aliases: &["banner-grab", "service-version"],
        summary: "open-port banner and service identity capture backed by knowledge registries.",
        docs: &["docs/service-detection-intelligence.md"],
    },
    ScanTypeEntry {
        id: "os-fingerprint",
        category: "enrichment",
        status: ScanTypeStatus::Partial,
        flags: &["--os-detect", "--os-fingerprint", "-O"],
        aliases: &["os-detect"],
        summary: "passive OS/profile correlation from service, CPE, TTL, and fingerprint databases.",
        docs: &["docs/service-knowledge-architecture.md"],
    },
    ScanTypeEntry {
        id: "script-scan",
        category: "enrichment",
        status: ScanTypeStatus::Partial,
        flags: &["-sC", "--lua-script <path>"],
        aliases: &["default-script-scan", "nse-like"],
        summary: "the framework exposes Lua hooks, but does not provide Nmap default-script parity; the encyclopedia entry is cataloged as a partial fit.",
        docs: &["cooking-reverse-engineering/nmap-scan-encyclopedia.txt"],
    },
    ScanTypeEntry {
        id: "traceroute",
        category: "enrichment",
        status: ScanTypeStatus::Planned,
        flags: &["--traceroute"],
        aliases: &["trace-route"],
        summary: "path tracing is listed in the encyclopedia catalog, but is not yet a dedicated follow-up lane.",
        docs: &["cooking-reverse-engineering/nmap-scan-encyclopedia.txt"],
    },
    ScanTypeEntry {
        id: "aggressive-suite",
        category: "enrichment",
        status: ScanTypeStatus::Implemented,
        flags: &["-A", "--aggressive"],
        aliases: &["aggressive"],
        summary: "maps to the framework's deeper service/version/OS-oriented profile rather than full Nmap aggressive parity.",
        docs: &["cooking-reverse-engineering/nmap-scan-encyclopedia.txt"],
    },
    ScanTypeEntry {
        id: "hybrid",
        category: "hybrid",
        status: ScanTypeStatus::Implemented,
        flags: &["--hybrid", "--masscan-hybrid"],
        aliases: &["controlled-firehose", "masscan-controlled"],
        summary: "masscan-style discovery fused with nmap-style enrichment inside one orchestrated bundle.",
        docs: &["docs/framework-identity.md", "docs/defensive-performance.md"],
    },
    ScanTypeEntry {
        id: "phantom",
        category: "tbns",
        status: ScanTypeStatus::Implemented,
        flags: &["--phantom", "--phantom-scan"],
        aliases: &["device-check"],
        summary: "least-contact TBNS device-check stage for first-touch safety decisions.",
        docs: &["docs/phantom-scan.md"],
    },
    ScanTypeEntry {
        id: "kis",
        category: "tbns",
        status: ScanTypeStatus::Implemented,
        flags: &["--kis", "--kis-scan"],
        aliases: &["kinetic-impedance-scan"],
        summary: "low-impact timing and impedance profile for cautious classification.",
        docs: &["docs/kis-scan.md"],
    },
    ScanTypeEntry {
        id: "sar",
        category: "tbns",
        status: ScanTypeStatus::Implemented,
        flags: &["--sar", "--sar-scan", "--sars"],
        aliases: &["spectral-adaptive-response"],
        summary: "low-impact response-shape and timing-delta observation profile.",
        docs: &["docs/sar-scan.md"],
    },
    ScanTypeEntry {
        id: "tbns",
        category: "tbns",
        status: ScanTypeStatus::Implemented,
        flags: &["family"],
        aliases: &["tri-blue-network-scans"],
        summary: "shared low-impact family grouping phantom, kis, and sar under strict safety.",
        docs: &["docs/tbns.md"],
    },
    ScanTypeEntry {
        id: "idf",
        category: "defensive",
        status: ScanTypeStatus::Implemented,
        flags: &["--idf", "--idf-scan", "--dummy-scan", "--fog-scan"],
        aliases: &["inert-decoy-fog"],
        summary: "defensive fog/decoy profile kept inside a soft, low-impact runtime envelope.",
        docs: &["self-assesment/introducing-literal-new-scan-types-for-defensive-sec/idf-scan/idf-scan-doc.txt"],
    },
    ScanTypeEntry {
        id: "mirror",
        category: "defensive",
        status: ScanTypeStatus::Implemented,
        flags: &["--mirror", "--mirror-scan"],
        aliases: &["reflective-hybrid"],
        summary: "reflective hybrid correlation profile with guarded callback notes and safer enrichment posture.",
        docs: &["self-assesment/introducing-literal-new-scan-types-for-defensive-sec/mirror-scan/mirror-scan-doc.txt"],
    },
    ScanTypeEntry {
        id: "callback-ping",
        category: "defensive",
        status: ScanTypeStatus::Implemented,
        flags: &["--callback-ping", "--callback", "--cb-ping"],
        aliases: &["mesh-callback"],
        summary: "guarded callback/reachability confirmation path for follow-up and mesh-style workflows.",
        docs: &["self-assesment/introducing-literal-new-scan-types-for-defensive-sec/callback-ping/callback-ping-doc.txt"],
    },
    ScanTypeEntry {
        id: "ghost-recon",
        category: "combo",
        status: ScanTypeStatus::Planned,
        flags: &["--phantom --idf --stealth --null"],
        aliases: &[],
        summary: "scan-combo recipe for minimalist NULL-style defensive recon; cataloged as a composed recipe.",
        docs: &["self-assesment/scan-combo.txt"],
    },
    ScanTypeEntry {
        id: "kinetic-fingerprint",
        category: "combo",
        status: ScanTypeStatus::Planned,
        flags: &["--kis --sars --syn --ack"],
        aliases: &["hardware-id"],
        summary: "scan-combo recipe for timing/impedance-heavy hardware characterization.",
        docs: &["self-assesment/scan-combo.txt"],
    },
    ScanTypeEntry {
        id: "vanguard-bypass",
        category: "combo",
        status: ScanTypeStatus::Planned,
        flags: &["--phantom --kis --tcp --fin"],
        aliases: &[],
        summary: "scan-combo recipe combining timing noise and classic FIN concepts; catalog only for now.",
        docs: &["self-assesment/scan-combo.txt"],
    },
    ScanTypeEntry {
        id: "zombie-reflection",
        category: "combo",
        status: ScanTypeStatus::Planned,
        flags: &["--zombie <host> --ack --phantom --stealth"],
        aliases: &[],
        summary: "scan-combo recipe built around the classic idle/zombie concept and Phantom observation.",
        docs: &[
            "self-assesment/scan-combo.txt",
            "cooking-reverse-engineering/zombie-scan-from-nmap.txt",
        ],
    },
    ScanTypeEntry {
        id: "xmas-collapse",
        category: "combo",
        status: ScanTypeStatus::Planned,
        flags: &["--xmas --kis --sars --tcp"],
        aliases: &[],
        summary: "scan-combo recipe using Xmas flag semantics plus KIS/SAR timing concepts.",
        docs: &["self-assesment/scan-combo.txt"],
    },
    ScanTypeEntry {
        id: "sovereign-callback",
        category: "combo",
        status: ScanTypeStatus::Planned,
        flags: &["--callback-ping --idf --sars"],
        aliases: &[],
        summary: "scan-combo recipe for callback validation and identity-aware mesh confirmation.",
        docs: &["self-assesment/scan-combo.txt"],
    },
    ScanTypeEntry {
        id: "null-resonance",
        category: "combo",
        status: ScanTypeStatus::Planned,
        flags: &["--null --phantom --sars"],
        aliases: &[],
        summary: "scan-combo recipe for minimalist NULL-style probing plus SAR observation.",
        docs: &["self-assesment/scan-combo.txt"],
    },
    ScanTypeEntry {
        id: "timing-profile",
        category: "timing",
        status: ScanTypeStatus::Implemented,
        flags: &["-T0..-T5"],
        aliases: &["paranoid", "sneaky", "polite", "normal", "aggressive-timing", "insane"],
        summary: "Nmap timing levels map into internal profile defaults from stealth through aggressive envelopes.",
        docs: &["cooking-reverse-engineering/nmap-scan-encyclopedia.txt"],
    },
];

pub fn render_scan_type_catalog(raw_query: Option<&str>) -> String {
    let query = raw_query.map(normalize_token);
    let matches = query
        .as_deref()
        .filter(|value| !value.is_empty() && *value != "all")
        .map(find_matches)
        .unwrap_or_else(|| SCAN_TYPES.iter().collect());

    let mut out = String::new();
    out.push_str("NProbe-RS scan type catalog\n");
    out.push_str("Status values: implemented | partial | planned\n");
    out.push_str(
        "This catalog merges live scan lanes, defensive profiles, enrichment modes, and documented encyclopedia entries.\n\n",
    );

    if matches.is_empty() {
        out.push_str("No scan type matched that query.\n");
        out.push_str(
            "Try: --scan-type syn | --scan-type phantom | --scan-type zombie | --scan-type -sI | --scan-type all\n",
        );
        return out;
    }

    let categories = [
        "discovery",
        "classic",
        "evasion",
        "enrichment",
        "hybrid",
        "tbns",
        "defensive",
        "combo",
        "timing",
    ];

    for category in categories {
        let mut section = matches
            .iter()
            .copied()
            .filter(|entry| entry.category == category)
            .collect::<Vec<_>>();
        if section.is_empty() {
            continue;
        }
        section.sort_by_key(|entry| entry.id);

        out.push_str(&format!("{}:\n", title_case(category)));
        for entry in section {
            out.push_str(&format!(
                "- {} [{}]\n  flags: {}\n  aliases: {}\n  summary: {}\n  detail: docs/scan-types/{}.md\n  refs: {}\n",
                entry.id,
                entry.status.as_str(),
                join_or_none(entry.flags),
                join_or_none(entry.aliases),
                entry.summary,
                entry.id,
                join_or_none(entry.docs)
            ));
        }
        out.push('\n');
    }

    out.push_str("Examples:\n");
    out.push_str("  nprobe-rs --scan-type\n");
    out.push_str("  nprobe-rs --scan-type zombie\n");
    out.push_str("  nprobe-rs --scan-type -sI\n");
    out.push_str("  nprobe-rs --scan-type phantom\n");
    out
}

fn find_matches(query: &str) -> Vec<&'static ScanTypeEntry> {
    SCAN_TYPES
        .iter()
        .filter(|entry| {
            normalize_token(entry.id) == query
                || entry
                    .flags
                    .iter()
                    .any(|flag| normalize_token(flag).contains(query))
                || entry
                    .aliases
                    .iter()
                    .any(|alias| normalize_token(alias) == query)
        })
        .collect()
}

fn title_case(input: &str) -> String {
    input
        .split('-')
        .map(|part| {
            let mut chars = part.chars();
            match chars.next() {
                Some(first) => {
                    let mut title = String::new();
                    title.push(first.to_ascii_uppercase());
                    title.extend(chars);
                    title
                }
                None => String::new(),
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
}

fn join_or_none(values: &[&str]) -> String {
    if values.is_empty() {
        "none".to_string()
    } else {
        values.join(", ")
    }
}

fn normalize_token(raw: &str) -> String {
    raw.trim()
        .trim_matches('"')
        .trim_start_matches('-')
        .replace([' ', '_'], "-")
        .to_ascii_lowercase()
}

#[cfg(test)]
mod tests {
    use super::render_scan_type_catalog;

    #[test]
    fn catalog_lists_live_and_planned_scan_types() {
        let rendered = render_scan_type_catalog(None);
        assert!(rendered.contains("syn [implemented]"));
        assert!(rendered.contains("zombie [planned]"));
        assert!(rendered.contains("phantom [implemented]"));
        assert!(rendered.contains("timing-profile [implemented]"));
    }

    #[test]
    fn catalog_query_filters_to_zombie_material() {
        let rendered = render_scan_type_catalog(Some("zombie"));
        assert!(rendered.contains("zombie [planned]"));
        assert!(rendered.contains("zombie-scan-from-nmap"));
        assert!(!rendered.contains("phantom [implemented]"));
    }

    #[test]
    fn catalog_query_matches_nmap_shortcut_alias() {
        let rendered = render_scan_type_catalog(Some("-sI"));
        assert!(rendered.contains("zombie [planned]"));
        assert!(rendered.contains("detail: docs/scan-types/zombie.md"));
    }

    #[test]
    fn catalog_query_matches_supported_nmap_alias() {
        let rendered = render_scan_type_catalog(Some("-PR"));
        assert!(rendered.contains("arp [implemented]"));
        assert!(rendered.contains("detail: docs/scan-types/arp.md"));
    }
}

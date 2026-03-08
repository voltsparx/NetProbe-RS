// Flow sketch: input -> core processing -> output model
// Pseudo-block:
//   read input -> process safely -> return deterministic output
// the CLI is a polite bouncer: clear args only.

use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsString;
use std::io::{self, IsTerminal, Write};
use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};

use chrono::{DateTime, NaiveDate, Utc};
use clap::{Args, Parser, Subcommand, ValueEnum};

use crate::config::{
    ActionableDiffItem, ScanSessionRecord, SessionActionableDiff, SessionRecordFilters,
};
use crate::engines::phantom_preflight;
use crate::error::{NProbeError, NProbeResult};
use crate::models::{ReportFormat, ScanProfile, ScanRequest};
use crate::platform::self_integrity::IntegrityStatus;
use crate::scan_types;

#[derive(Debug, Clone, Copy, ValueEnum)]
enum FileType {
    Txt,
    Json,
    Html,
    Csv,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum SeverityFilter {
    Review,
    Moderate,
    High,
    Critical,
}

impl SeverityFilter {
    fn as_actionable_severity(self) -> crate::reporter::actionable::ActionableSeverity {
        match self {
            SeverityFilter::Review => crate::reporter::actionable::ActionableSeverity::Review,
            SeverityFilter::Moderate => crate::reporter::actionable::ActionableSeverity::Moderate,
            SeverityFilter::High => crate::reporter::actionable::ActionableSeverity::High,
            SeverityFilter::Critical => crate::reporter::actionable::ActionableSeverity::Critical,
        }
    }
}

impl FileType {
    fn as_report_format(self) -> ReportFormat {
        match self {
            FileType::Txt => ReportFormat::Txt,
            FileType::Json => ReportFormat::Json,
            FileType::Html => ReportFormat::Html,
            FileType::Csv => ReportFormat::Csv,
        }
    }
}

#[derive(Debug, Parser)]
#[command(
    name = "nprobe-rs",
    version,
    about = "NProbe-RS: Reverse-Engineered scanner in safe, explainable Rust",
    override_usage = "nprobe-rs <target> [OPTIONS]\n       nprobe-rs scan <target> [OPTIONS]\n       nprobe-rs interactive\n       nprobe-rs integrity [OPTIONS]\n       nprobe-rs sessions [OPTIONS]",
    after_help = "Nmap-style shortcuts supported: -sU, -sS, -sV, -O, -A, -T0..-T5, -p-",
    arg_required_else_help = true
)]
pub struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Debug, Subcommand)]
enum Commands {
    Scan(Box<ScanArgs>),
    #[command(visible_alias = "learn", visible_alias = "wizard")]
    Interactive(InteractiveArgs),
    Integrity(IntegrityArgs),
    Sessions(Box<SessionArgs>),
}

#[derive(Debug, Clone)]
pub enum CliAction {
    Scan(Box<ScanRequest>),
    Integrity(IntegrityCommand),
    Sessions(SessionCommand),
}

#[derive(Debug, Clone)]
pub enum SessionCommand {
    List {
        limit: usize,
        filters: SessionRecordFilters,
    },
    Show {
        session_id: String,
    },
    Diff {
        older_session_id: String,
        newer_session_id: String,
        session_filters: SessionRecordFilters,
        ip_filter: Option<String>,
        target_filter: Option<String>,
        severity_filter: Option<crate::reporter::actionable::ActionableSeverity>,
        report_format: ReportFormat,
        output_path: Option<PathBuf>,
    },
}

#[derive(Debug, Clone)]
pub enum IntegrityCommand {
    Status,
    Reseal,
}

#[derive(Debug, Args)]
struct ScanArgs {
    #[arg(help = "Target host (IP or hostname)")]
    target: String,

    #[arg(
        short = 'p',
        long = "ports",
        help = "Port list like 22,80,443 or 1-1024"
    )]
    ports: Option<String>,

    #[arg(
        long = "all-ports",
        visible_alias = "p-",
        help = "Scan ports 1-65535 (Nmap: -p-)"
    )]
    all_ports: bool,

    #[arg(short = 't', long = "top-ports", help = "Scan N most common TCP ports")]
    top_ports: Option<usize>,

    #[arg(
        long = "ping-scan",
        visible_aliases = ["host-discovery", "discovery-only"],
        help = "Discovery-only host up check; do not perform a port scan (Nmap: -sn)"
    )]
    ping_scan: bool,

    #[arg(
        short = 'U',
        long = "udp",
        visible_aliases = ["sU", "udp-scan"],
        help = "Add UDP probing (Nmap: -sU)"
    )]
    udp: bool,

    #[arg(
        short = 'S',
        long = "syn",
        visible_aliases = ["sS", "syn-scan", "half-open", "stealth", "stealth-scan"],
        conflicts_with = "connect",
        help = "Use privileged TCP probing (Nmap: -sS). Will auto-prompt for sudo/su if required"
    )]
    syn: bool,

    #[arg(
        long = "connect",
        visible_aliases = ["sT", "connect-scan", "tcp-connect"],
        conflicts_with_all = ["syn", "aggressive", "aggressive_root", "privileged_probes", "root_only"],
        help = "Use user-space TCP connect scanning (Nmap: -sT)"
    )]
    connect: bool,

    #[arg(
        long = "arp",
        visible_alias = "arp-scan",
        help = "Enable ARP neighbor discovery for local IPv4 targets"
    )]
    arp: bool,

    #[arg(
        short = 'r',
        long = "reverse-dns",
        help = "Enable PTR reverse DNS lookups"
    )]
    reverse_dns: bool,

    #[arg(
        short = 'n',
        long = "no-dns",
        help = "Skip reverse DNS lookups (Nmap-compatible)"
    )]
    no_dns: bool,

    #[arg(
        long = "no-host-discovery",
        visible_alias = "Pn",
        hide = true,
        help = "Nmap compatibility: current scan flow already avoids a separate ping-only discovery phase"
    )]
    no_host_discovery: bool,

    #[arg(
        short = 'N',
        long = "no-service-detect",
        help = "Disable banner/service detection"
    )]
    no_service_detect: bool,

    #[arg(
        long = "service-detect",
        visible_aliases = ["sV", "banners", "service-version", "version-detect"],
        help = "Enable banner/service detection (Nmap: -sV)"
    )]
    service_detect: bool,

    #[arg(
        long = "os-detect",
        visible_aliases = ["os-fingerprint", "fingerprint-os"],
        help = "Bias the run toward richer passive OS/profile correlation (Nmap: -O)"
    )]
    os_detect: bool,

    #[arg(
        short = 'e',
        long = "explain",
        help = "Show concise per-port explanation lines in scan output"
    )]
    explain: bool,

    #[arg(
        short = 'v',
        long = "verbose",
        help = "Show full terminal output sections"
    )]
    verbose: bool,

    #[arg(
        short = 'f',
        long = "file-type",
        value_enum,
        help = "Report format for file export: txt, csv, html, json"
    )]
    file_type: Option<FileType>,

    #[arg(long = "report", value_enum, hide = true)]
    report_legacy: Option<ReportFormat>,

    #[arg(short = 'P', long = "profile", value_enum)]
    profile: Option<ScanProfile>,

    #[arg(
        short = 'A',
        long = "aggressive",
        help = "Aggressive scan mode (Nmap: -A). Uses deeper probes and may require root"
    )]
    aggressive: bool,

    #[arg(
        short = 'R',
        long = "root-only",
        visible_alias = "termux-root",
        hide = true,
        help = "Termux/mobile root preset: enables privileged probes with mobile-safe defaults"
    )]
    root_only: bool,

    #[arg(
        short = 'g',
        long = "aggressive-root",
        visible_aliases = ["aggresive-root", "agg-root"],
        hide = true,
        help = "Enable root-required aggressive scan extensions"
    )]
    aggressive_root: bool,

    #[arg(
        short = 'k',
        long = "privileged-probes",
        visible_aliases = ["priv-probes", "pp"],
        hide = true,
        help = "Use privileged source-port probing (requires root/sudo)"
    )]
    privileged_probes: bool,

    #[arg(
        short = 'l',
        long = "lab-mode",
        help = "Only allow local/private targets"
    )]
    lab_mode: bool,

    #[arg(
        short = 'a',
        long = "allow-external",
        visible_aliases = ["allow-public", "force-internet"],
        help = "Acknowledge and allow scanning public IP targets"
    )]
    allow_external: bool,

    #[arg(
        short = 's',
        long = "strict-safety",
        help = "Block scan instead of warning when external target safety checks fail"
    )]
    strict_safety: bool,

    #[arg(
        short = 'o',
        long = "output",
        help = "Output file name (example: scan-report)"
    )]
    output: Option<String>,

    #[arg(
        short = 'L',
        long = "location",
        help = "Directory where output file should be stored"
    )]
    location: Option<PathBuf>,

    #[arg(short = 'x', long = "lua-script", help = "Lua hook file path")]
    lua_script: Option<PathBuf>,

    #[arg(
        long = "callback-ping",
        visible_aliases = ["callback", "cb-ping"],
        help = "Record a guarded reachability callback note after host discovery"
    )]
    callback_ping: bool,

    #[arg(short = 'w', long = "timeout-ms", help = "Probe timeout in ms")]
    timeout_ms: Option<u64>,

    #[arg(short = 'c', long = "concurrency", help = "Max concurrent probes")]
    concurrency: Option<usize>,

    #[arg(
        short = 'd',
        long = "delay-ms",
        help = "Delay between probe dispatches in ms"
    )]
    delay_ms: Option<u64>,

    #[arg(
        long = "timing-template",
        hide = true,
        value_parser = clap::value_parser!(u8).range(0..=5)
    )]
    timing_template: Option<u8>,

    #[arg(
        long = "rate",
        visible_aliases = ["rate-pps", "max-rate", "min-rate"],
        num_args = 0..=1,
        default_missing_value = "100",
        help = "Probe dispatch rate target in packets per second (bare --rate defaults to 100)"
    )]
    rate_limit_pps: Option<u32>,

    #[arg(
        long = "gpu-rate",
        num_args = 0..=1,
        default_missing_value = "100",
        help = "Rate ceiling for GPU/parallel packet crafters (bare --gpu-rate defaults to 100); currently also caps the fused packet-crafter path"
    )]
    gpu_rate_pps: Option<u32>,

    #[arg(
        long = "gpu-burst",
        visible_alias = "gpu-burst-size",
        help = "Burst ceiling for GPU/parallel packet crafters; currently also caps the fused packet-crafter path"
    )]
    gpu_burst_size: Option<usize>,

    #[arg(
        long = "gpu-timestamp",
        help = "Enable timestamp-paced scheduling for GPU/parallel packet crafters; currently also paces the fused packet-crafter path"
    )]
    gpu_timestamp: bool,

    #[arg(
        long = "gpu-schedule-random",
        help = "Randomize GPU/parallel crafter scheduling order; currently also randomizes the fused packet-crafter path"
    )]
    gpu_schedule_random: bool,

    #[arg(
        long = "assess-hardware",
        help = "Assess local hardware compatibility, health, and safe raw/GPU ceilings without transmitting scan packets"
    )]
    assess_hardware: bool,

    #[arg(
        long = "override-mode",
        help = "Power-user override that disables adaptive auto-throttles and emergency brakes after explicit interactive confirmations"
    )]
    override_mode: bool,

    #[arg(long = "burst-size", help = "Token-bucket burst size for rate control")]
    burst_size: Option<usize>,

    #[arg(long = "max-retries", help = "Adaptive retry limit per probe")]
    max_retries: Option<u8>,

    #[arg(
        long = "total-shards",
        help = "Total shard count for distributed scans"
    )]
    total_shards: Option<u16>,

    #[arg(
        long = "shard-index",
        help = "Shard index in range [0, total-shards-1]"
    )]
    shard_index: Option<u16>,

    #[arg(
        long = "scan-seed",
        help = "Deterministic seed for shuffled probe ordering"
    )]
    scan_seed: Option<u64>,

    #[arg(
        long = "resume",
        help = "Resume from existing shard checkpoint when available"
    )]
    resume: bool,

    #[arg(
        long = "fresh-scan",
        conflicts_with = "resume",
        help = "Ignore and reset shard checkpoint before scanning"
    )]
    fresh_scan: bool,
}

#[derive(Debug, Args)]
struct SessionArgs {
    #[arg(long = "limit", default_value_t = 20, help = "Max sessions to list")]
    limit: usize,

    #[arg(long = "show", help = "Show a specific session by id")]
    session_id: Option<String>,

    #[arg(
        long = "diff",
        value_names = ["OLDER", "NEWER"],
        num_args = 2,
        help = "Compare actionable findings between two sessions"
    )]
    diff: Option<Vec<String>>,

    #[arg(long = "ip", help = "Filter session diff to one IP")]
    ip_filter: Option<String>,

    #[arg(
        long = "target-contains",
        help = "Filter session diff to targets containing this text"
    )]
    target_filter: Option<String>,

    #[arg(
        long = "profile",
        help = "Filter session history by profile, or require both diff sessions to use this profile"
    )]
    profile_filter: Option<String>,

    #[arg(
        long = "updated-after",
        help = "Filter sessions updated on or after this RFC3339/date value"
    )]
    updated_after: Option<String>,

    #[arg(
        long = "updated-before",
        help = "Filter sessions updated on or before this RFC3339/date value"
    )]
    updated_before: Option<String>,

    #[arg(
        long = "severity",
        value_enum,
        help = "Minimum severity to include in session diff: review, moderate, high, critical"
    )]
    severity_filter: Option<SeverityFilter>,

    #[arg(
        short = 'f',
        long = "file-type",
        value_enum,
        help = "Session diff export format: txt, json, html"
    )]
    file_type: Option<FileType>,

    #[arg(short = 'o', long = "output", help = "Session diff output file name")]
    output: Option<String>,

    #[arg(
        short = 'L',
        long = "location",
        help = "Directory for session diff export"
    )]
    location: Option<PathBuf>,
}

#[derive(Debug, Args, Default)]
struct InteractiveArgs {}

#[derive(Debug, Args)]
struct IntegrityArgs {
    #[arg(
        long = "reseal",
        help = "Trust the current build and executable as the new integrity baseline"
    )]
    reseal: bool,
}

const INTERACTIVE_BANNER: &str = r#"    _   ______             __               ____  _____
   / | / / __ \_________  / /_  ___        / __ \/ ___/
  /  |/ / /_/ / ___/ __ \/ __ \/ _ \______/ /_/ /\__ \
 / /|  / ____/ /  / /_/ / /_/ /  __/_____/ _, _/___/ /
/_/ |_/_/   /_/   \____/_.___/\___/     /_/ |_|/____/
"#;

impl Cli {
    pub fn parse_normalized() -> Self {
        let args: Vec<OsString> = std::env::args_os().collect();
        Self::parse_from(normalize_args(args))
    }

    pub fn into_action(self) -> NProbeResult<CliAction> {
        match self.command {
            Commands::Scan(scan) => Ok(CliAction::Scan(Box::new(scan.into_request()?))),
            Commands::Interactive(args) => Ok(CliAction::Scan(Box::new(args.into_request()?))),
            Commands::Integrity(args) => args.into_action(),
            Commands::Sessions(args) => args.into_action(),
        }
    }
}

pub fn maybe_render_flag_explain_mode() -> Option<String> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.is_empty() {
        return None;
    }

    let first = args[0].as_str();
    let (enabled, inline_value) = if let Some((flag, value)) = first.split_once('=') {
        (flag == "--explain", Some(value.to_string()))
    } else {
        (first == "--explain", None)
    };

    if !enabled {
        return None;
    }

    // Keep legacy behavior for `--explain --flag`, but never hijack real scan invocations.
    if let Some(inline) = inline_value {
        if inline.trim().is_empty() {
            return Some(render_flag_explain(Some("--explain")));
        }
        return Some(render_flag_explain(Some(inline.as_str())));
    }

    if args.len() == 1 {
        return Some(render_flag_explain(Some("--explain")));
    }

    if args.len() == 2 && args[1].starts_with('-') {
        return Some(render_flag_explain(Some(args[1].as_str())));
    }

    None
}

pub fn maybe_render_flag_help_mode() -> Option<String> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.is_empty() {
        return None;
    }

    let first = args[0].as_str();
    let inline = if let Some((flag, value)) = first.split_once('=') {
        if flag == "--flag-help" {
            Some(value.to_string())
        } else {
            None
        }
    } else {
        None
    };

    if let Some(value) = inline {
        let query = if value.trim().is_empty() {
            "--scan"
        } else {
            value.as_str()
        };
        return Some(render_flag_explain(Some(query)));
    }

    if first != "--flag-help" {
        return None;
    }

    if args.len() == 1 {
        return Some(render_flag_explain(Some("--scan")));
    }

    if args.len() == 2 {
        return Some(render_flag_explain(Some(args[1].as_str())));
    }

    None
}

pub fn maybe_render_quick_help_mode() -> Option<String> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.len() != 1 {
        return None;
    }

    let token = args[0].as_str();
    if token != "-h" && token != "--help" {
        return None;
    }

    Some(
        "Usage:\n  nprobe-rs <target> [options]\n  nprobe-rs interactive\n  nprobe-rs integrity [--reseal]\n  nprobe-rs sessions [--limit N]\n  nprobe-rs sessions --show <session-id>\n  nprobe-rs sessions --diff <older-session-id> <newer-session-id>\n\nCommon options:\n  -p, --ports <list|range>   Select ports (example: -p 22,80,443)\n      --all-ports            Scan ports 1-65535 (Nmap: -p-)\n      --ping-scan            Discovery-only host up check (Nmap: -sn)\n  -U, --udp                  Enable UDP probes (Nmap: -sU)\n  -S, --syn                  Enable privileged TCP probes (Nmap: -sS)\n      --connect              Force user-space TCP connect scanning (Nmap: -sT)\n      --service-detect       Enable banner/service detection (Nmap: -sV, Masscan: --banners)\n      --os-detect            Bias toward richer passive OS correlation (Nmap: -O)\n      --arp                  Enable ARP neighbor discovery (local IPv4)\n      --callback-ping        Record guarded post-discovery callback notes\n      --phantom/--sar/--kis  TBNS defensive scan concepts\n      --idf/--mirror         Additional defensive scan concepts\n      --hybrid               Controlled masscan+nmap fusion mode\n  -A, --aggressive           Aggressive mode (Nmap: -A)\n  -w, --timeout-ms <ms>      Probe timeout in milliseconds\n      --rate [num]           Stabilized raw/firehose target in packets per second (bare flag = 100)\n      --gpu-rate [num]       GPU/parallel crafter ceiling in packets per second (bare flag = 100)\n      --gpu-burst <num>      GPU/parallel crafter burst ceiling\n      --gpu-timestamp        Timestamp-pace the GPU/fused packet scheduler\n      --gpu-schedule-random  Randomize GPU/fused packet scheduling order\n      --assess-hardware      Assess local hardware and print safe raw/GPU ceilings only\n      --override-mode        Ask for explicit confirmations, then bypass adaptive throttles and emergency brakes\n      --scan-type [name]     List framework scan types, or query one specific type\n      --burst-size <num>     Token-bucket burst limit\n      --max-retries <num>    Adaptive retries per probe (0..20)\n      --total-shards <num>   Total shard count for distributed scans\n      --shard-index <num>    Current shard index (requires total-shards)\n      --scan-seed <num>      Deterministic port shuffle seed\n      --resume               Resume from shard checkpoint\n      --fresh-scan           Ignore/reset shard checkpoint for this run\n  -r, --reverse-dns          Enable reverse DNS lookups\n  -n, --no-dns               Disable reverse DNS lookups\n  -e, --explain              Add concise per-port rationale in output\n  -v, --verbose              Show full output sections\n  -f, --file-type <type>     Export format: txt|json|html|csv\n  -o, --output <name>        Output filename\n  -L, --location <dir>       Output directory\n\nLearner mode:\n  nprobe-rs interactive      Guided prompt mode with banner and safe defaults\n  nprobe-rs learn            Alias for interactive mode\n\nScan type catalog:\n  nprobe-rs --scan-type\n  nprobe-rs --scan-type zombie\n  nprobe-rs --scan-type -sI\n\nIntegrity:\n  nprobe-rs integrity\n  nprobe-rs integrity --reseal\n\nSession history:\n  nprobe-rs sessions --limit 20\n  nprobe-rs sessions --show <session-id>\n  nprobe-rs sessions --diff <older-session-id> <newer-session-id>\n      Optional session filters: --profile <name> --updated-after <ts> --updated-before <ts>\n      Optional diff filters:    --ip <addr> --target-contains <text> --severity <level>\n      Optional diff export:     -f txt|json|html -o <name> -L <dir>\n\nNmap-style shortcuts accepted:\n  -sn  -sU  -sS  -sT  -sV  -O  -Pn  -PR  -A  -T0..-T5  -p-\n\nCatalog-only encyclopedia entries:\n  Use `nprobe-rs --scan-type <name|flag>` for scan families that are documented but not executable.\n\nFlag docs mode:\n  nprobe-rs --flag-help --scan\n  nprobe-rs --flag-help -sU\n  nprobe-rs --explain --scan   (legacy alias)\n\nCompatibility:\n  nprobe-rs scan <target> [options] still works.".to_string(),
    )
}

pub fn maybe_render_scan_type_mode() -> Option<String> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.is_empty() {
        return None;
    }

    let first = args[0].as_str();
    let inline = if let Some((flag, value)) = first.split_once('=') {
        if flag == "--scan-type" || flag == "--scan-types" {
            Some(value.to_string())
        } else {
            None
        }
    } else {
        None
    };

    if let Some(value) = inline {
        let query = if value.trim().is_empty() {
            None
        } else {
            Some(value.as_str())
        };
        return Some(scan_types::render_scan_type_catalog(query));
    }

    if first != "--scan-type" && first != "--scan-types" {
        return None;
    }

    if args.len() == 1 {
        return Some(scan_types::render_scan_type_catalog(None));
    }

    if args.len() == 2 {
        return Some(scan_types::render_scan_type_catalog(Some(args[1].as_str())));
    }

    None
}

#[derive(Debug, Clone, Copy)]
struct CatalogedScanGate {
    token: &'static str,
    scan_id: &'static str,
    label: &'static str,
    risky: bool,
}

const CATALOGED_SCAN_GATES: &[CatalogedScanGate] = &[
    CatalogedScanGate {
        token: "-PS",
        scan_id: "tcp-syn-ping",
        label: "TCP SYN Ping",
        risky: false,
    },
    CatalogedScanGate {
        token: "-PA",
        scan_id: "tcp-ack-ping",
        label: "TCP ACK Ping",
        risky: false,
    },
    CatalogedScanGate {
        token: "-PU",
        scan_id: "udp-ping",
        label: "UDP Ping",
        risky: false,
    },
    CatalogedScanGate {
        token: "-PY",
        scan_id: "sctp-init-ping",
        label: "SCTP INIT Ping",
        risky: false,
    },
    CatalogedScanGate {
        token: "-PE",
        scan_id: "icmp-echo",
        label: "ICMP Echo Ping",
        risky: false,
    },
    CatalogedScanGate {
        token: "-PP",
        scan_id: "icmp-timestamp",
        label: "ICMP Timestamp Ping",
        risky: false,
    },
    CatalogedScanGate {
        token: "-PM",
        scan_id: "icmp-netmask",
        label: "ICMP Netmask Ping",
        risky: false,
    },
    CatalogedScanGate {
        token: "-PO",
        scan_id: "ip-proto-ping",
        label: "IP Protocol Ping",
        risky: false,
    },
    CatalogedScanGate {
        token: "-sY",
        scan_id: "sctp-init",
        label: "SCTP INIT Scan",
        risky: false,
    },
    CatalogedScanGate {
        token: "-sZ",
        scan_id: "sctp-cookie",
        label: "SCTP COOKIE Scan",
        risky: false,
    },
    CatalogedScanGate {
        token: "-sO",
        scan_id: "ip-protocol",
        label: "IP Protocol Scan",
        risky: false,
    },
    CatalogedScanGate {
        token: "-sC",
        scan_id: "script-scan",
        label: "Script Scan",
        risky: false,
    },
    CatalogedScanGate {
        token: "--traceroute",
        scan_id: "traceroute",
        label: "Traceroute",
        risky: false,
    },
    CatalogedScanGate {
        token: "-sA",
        scan_id: "ack",
        label: "ACK Scan",
        risky: true,
    },
    CatalogedScanGate {
        token: "-sN",
        scan_id: "null",
        label: "NULL Scan",
        risky: true,
    },
    CatalogedScanGate {
        token: "-sF",
        scan_id: "fin",
        label: "FIN Scan",
        risky: true,
    },
    CatalogedScanGate {
        token: "-sX",
        scan_id: "xmas",
        label: "Xmas Scan",
        risky: true,
    },
    CatalogedScanGate {
        token: "-sM",
        scan_id: "maimon",
        label: "Maimon Scan",
        risky: true,
    },
    CatalogedScanGate {
        token: "--scanflags",
        scan_id: "custom-scanflags",
        label: "Custom TCP Scanflags",
        risky: true,
    },
    CatalogedScanGate {
        token: "-sW",
        scan_id: "window",
        label: "Window Scan",
        risky: true,
    },
    CatalogedScanGate {
        token: "-sI",
        scan_id: "zombie",
        label: "Idle/Zombie Scan",
        risky: true,
    },
    CatalogedScanGate {
        token: "--zombie",
        scan_id: "zombie",
        label: "Idle/Zombie Scan",
        risky: true,
    },
    CatalogedScanGate {
        token: "-f",
        scan_id: "fragment",
        label: "Fragmented Packet Scan",
        risky: true,
    },
    CatalogedScanGate {
        token: "--mtu",
        scan_id: "fragment",
        label: "Custom MTU Fragmentation",
        risky: true,
    },
    CatalogedScanGate {
        token: "-D",
        scan_id: "decoy",
        label: "Decoy Scan",
        risky: true,
    },
    CatalogedScanGate {
        token: "--decoy",
        scan_id: "decoy",
        label: "Decoy Scan",
        risky: true,
    },
    CatalogedScanGate {
        token: "-b",
        scan_id: "ftp-bounce",
        label: "FTP Bounce Scan",
        risky: true,
    },
    CatalogedScanGate {
        token: "--spoof-source",
        scan_id: "spoof-source",
        label: "Spoofed Source Scan",
        risky: true,
    },
    CatalogedScanGate {
        token: "--interface",
        scan_id: "interface-bind",
        label: "Forced Interface Scan",
        risky: true,
    },
    CatalogedScanGate {
        token: "--source-port",
        scan_id: "source-port-pin",
        label: "Pinned Source Port Scan",
        risky: true,
    },
];

pub fn maybe_reject_cataloged_scan_mode() -> Option<NProbeError> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    detect_cataloged_scan_gate(&args)
}

fn detect_cataloged_scan_gate(args: &[String]) -> Option<NProbeError> {
    for raw in args {
        let token = raw
            .split_once('=')
            .map(|(left, _)| left)
            .unwrap_or(raw.as_str());
        if let Some(gate) = CATALOGED_SCAN_GATES
            .iter()
            .find(|candidate| candidate.token.eq_ignore_ascii_case(token))
        {
            let detail = if gate.risky {
                format!(
                    "{} ({}) is cataloged in NProbe-RS, but this build does not execute stealth, spoofing, or firewall-evasion scan modes. Inspect it with `--scan-type {}` instead.",
                    gate.label, gate.token, gate.scan_id
                )
            } else {
                format!(
                    "{} ({}) is cataloged in NProbe-RS, but there is no executable lane for it yet. Inspect it with `--scan-type {}` instead.",
                    gate.label, gate.token, gate.scan_id
                )
            };
            return Some(if gate.risky {
                NProbeError::Safety(detail)
            } else {
                NProbeError::Cli(detail)
            });
        }
    }
    None
}

impl SessionArgs {
    fn into_action(self) -> NProbeResult<CliAction> {
        if self.limit == 0 {
            return Err(NProbeError::Cli(
                "--limit must be greater than 0".to_string(),
            ));
        }

        let session_filters = build_session_record_filters(
            self.profile_filter,
            self.updated_after,
            self.updated_before,
        )?;

        if let Some(values) = self.diff {
            if self.session_id.is_some() {
                return Err(NProbeError::Cli(
                    "--diff cannot be used together with --show".to_string(),
                ));
            }
            let older = values.first().map(String::as_str).unwrap_or("").trim();
            let newer = values.get(1).map(String::as_str).unwrap_or("").trim();
            if older.is_empty() || newer.is_empty() {
                return Err(NProbeError::Cli(
                    "--diff requires two non-empty session ids".to_string(),
                ));
            }

            let report_format = match self.file_type.unwrap_or(FileType::Txt) {
                FileType::Txt => ReportFormat::Txt,
                FileType::Json => ReportFormat::Json,
                FileType::Html => ReportFormat::Html,
                FileType::Csv => {
                    return Err(NProbeError::Cli(
                        "session diff export does not support csv; use txt, json, or html"
                            .to_string(),
                    ));
                }
            };
            let output_requested = self.output.is_some() || self.location.is_some();
            let output_path = build_output_path(
                self.output.as_deref(),
                self.location.as_deref(),
                report_format,
                output_requested,
                true,
            )?;

            return Ok(CliAction::Sessions(SessionCommand::Diff {
                older_session_id: older.to_string(),
                newer_session_id: newer.to_string(),
                session_filters,
                ip_filter: self.ip_filter.filter(|value| !value.trim().is_empty()),
                target_filter: self.target_filter.filter(|value| !value.trim().is_empty()),
                severity_filter: self
                    .severity_filter
                    .map(SeverityFilter::as_actionable_severity),
                report_format,
                output_path,
            }));
        }

        if self.ip_filter.is_some()
            || self.target_filter.is_some()
            || self.severity_filter.is_some()
            || self.file_type.is_some()
            || self.output.is_some()
            || self.location.is_some()
        {
            return Err(NProbeError::Cli(
                "session diff filters and export flags require --diff".to_string(),
            ));
        }

        if let Some(session_id) = self.session_id {
            let trimmed = session_id.trim();
            if trimmed.is_empty() {
                return Err(NProbeError::Cli(
                    "--show requires a non-empty session id".to_string(),
                ));
            }
            if session_filters.is_active() {
                return Err(NProbeError::Cli(
                    "session history filters require --diff or plain sessions listing, not --show"
                        .to_string(),
                ));
            }
            return Ok(CliAction::Sessions(SessionCommand::Show {
                session_id: trimmed.to_string(),
            }));
        }

        Ok(CliAction::Sessions(SessionCommand::List {
            limit: self.limit,
            filters: session_filters,
        }))
    }
}

impl IntegrityArgs {
    fn into_action(self) -> NProbeResult<CliAction> {
        Ok(CliAction::Integrity(if self.reseal {
            IntegrityCommand::Reseal
        } else {
            IntegrityCommand::Status
        }))
    }
}

fn render_flag_explain(raw_query: Option<&str>) -> String {
    let key = raw_query
        .map(|value| value.trim().trim_start_matches('-').to_ascii_lowercase())
        .unwrap_or_else(|| "scan".to_string());

    let body = match key.as_str() {
        "scan" => {
            "Default scan mode. Use `nprobe-rs <target>` without the `scan` subcommand."
        }
        "st" | "connect" => {
            "Force user-space TCP connect scanning (`-sT` or `--connect`) without privileged raw probing."
        }
        "pn" | "no-host-discovery" => {
            "Compatibility flag (`-Pn` or `--no-host-discovery`). Current nprobe-rs scanning already avoids a separate ping-only discovery phase."
        }
        "sn" | "pingscan" | "ping-scan" | "hostdiscovery" | "host-discovery" | "discoveryonly" | "discovery-only" => {
            "Discovery-only mode (`-sn` or `--ping-scan`). NProbe-RS verifies host presence through the lightweight fetcher plane and does not perform a port scan."
        }
        "p" | "ports" => "Select ports or ranges. Example: `-p 22,80,443` or `-p 1-1024`.",
        "s" | "su" | "udp" => "Enable UDP probing (`-sU` or `--udp`).",
        "ss" | "syn" => {
            "Enable privileged TCP probing (`-sS` or `--syn`). If needed, the tool re-runs with sudo/su."
        }
        "sv" | "servicedetect" | "service-detect" | "banners" => {
            "Enable banner/service detection (`-sV`, `--service-detect`, or Masscan-style `--banners`)."
        }
        "o" | "osdetect" | "os-detect" => {
            "Bias the run toward richer passive OS/profile reporting (`-O` or `--os-detect`)."
        }
        "arp" => "Enable ARP neighbor discovery for local IPv4 targets (`--arp`).",
        "callback" | "callbackping" | "callback-ping" | "cbping" | "cb-ping" => {
            "Add a guarded post-discovery callback note using the fetcher plane (`--callback-ping`)."
        }
        "phantom" | "phantomscan" | "phantom-scan" => {
            "Select the TBNS Phantom first-touch profile (`--phantom` or `--phantom-scan`)."
        }
        "sar" | "sars" | "sarscan" | "sar-scan" => {
            "Select the TBNS SAR observation profile (`--sar`, `--sar-scan`, or `--sars`)."
        }
        "kis" | "kisscan" | "kis-scan" => {
            "Select the TBNS KIS timing-observation profile (`--kis` or `--kis-scan`)."
        }
        "idf" | "idfscan" | "idf-scan" | "dummyscan" | "dummy-scan" | "fogscan" | "fog-scan" => {
            "Select the inert-decoy-fog defensive profile (`--idf`, `--idf-scan`, or `--dummy-scan`)."
        }
        "mirror" | "mirrorscan" | "mirror-scan" => {
            "Select the reflective hybrid correlation profile (`--mirror` or `--mirror-scan`)."
        }
        "hybrid" | "hybridscan" | "hybrid-scan" | "masscanhybrid" | "masscan-hybrid" | "masscancontrolled" | "masscan-controlled" => {
            "Select the controlled masscan+nmap fusion profile (`--hybrid` or `--masscan-hybrid`)."
        }
        "a" | "aggressive" => {
            "Aggressive mode (`-A`): enables deeper detection and root-required probe paths."
        }
        "t" | "timing" => {
            "Timing profile (`-T0`..`-T5`). NProbe-RS now preserves a dedicated timing template so scan pacing, timeout, retries, and concurrency shift even when the broader scan profile stays the same."
        }
        "p-" | "all-ports" => "Scan all TCP ports 1-65535 (`-p-` or `--all-ports`).",
        "rate" | "ratepps" | "rate-pps" | "maxrate" | "max-rate" | "minrate" | "min-rate" => {
            "Set the stabilized probe/firehose target in packets/sec (`--rate`, `--rate-pps`, `--max-rate`, or `--min-rate`). If you pass bare `--rate` without a number, it defaults to 100 PPS. Lower values reduce scan pressure."
        }
        "gpurate" | "gpu-rate" => {
            "Set the GPU/parallel crafter rate ceiling (`--gpu-rate`). If you pass bare `--gpu-rate` without a number, it defaults to 100 PPS. On current builds it still caps the fused packet-crafter path even without a dedicated GPU backend."
        }
        "gpuburst" | "gpu-burst" | "gpu-burst-size" => {
            "Set the GPU/parallel crafter burst ceiling (`--gpu-burst`). On current builds it also caps the fused packet-crafter token bucket."
        }
        "gputimestamp" | "gpu-timestamp" => {
            "Enable timestamp-paced GPU/parallel scheduling (`--gpu-timestamp`). On current builds it also adds timestamp pacing to the fused packet-crafter path."
        }
        "gpuschedulerandom" | "gpu-schedule-random" => {
            "Randomize GPU/parallel scheduling order (`--gpu-schedule-random`). On current builds it also randomizes the fused packet-crafter chunk order."
        }
        "assesshardware" | "assess-hardware" => {
            "Assess local hardware compatibility and safe ceilings (`--assess-hardware`). This mode reports recommended raw and GPU limits and does not transmit scan packets."
        }
        "overridemode" | "override-mode" => {
            "Power-user override (`--override-mode`). Requires interactive confirmations, then bypasses adaptive local throttles, target fragility brakes, and runtime emergency brakes for raw/GPU acceleration paths. Hard prerequisites like permissions and platform support still apply."
        }
        "scantype" | "scan-type" | "scan-types" => {
            "List framework scan types (`--scan-type`) or inspect one entry (`--scan-type zombie`). The catalog shows implemented, partial, and planned scan families plus combo recipes."
        }
        "burstsize" | "burst-size" => {
            "Set token-bucket burst size (`--burst-size`) to smooth short-term packet bursts."
        }
        "maxretries" | "max-retries" => {
            "Adaptive retry limit per probe (`--max-retries`, range: 0..20)."
        }
        "totalshards" | "total-shards" => {
            "Enable distributed scanning with total shard count (`--total-shards`)."
        }
        "shardindex" | "shard-index" => {
            "Select shard index for this node (`--shard-index`, requires `--total-shards`)."
        }
        "scanseed" | "scan-seed" => {
            "Use deterministic seed for shuffled probe order (`--scan-seed`)."
        }
        "resume" => "Resume from existing shard checkpoint when available (`--resume`).",
        "freshscan" | "fresh-scan" => {
            "Ignore/reset shard checkpoint and start from scratch (`--fresh-scan`)."
        }
        "v" | "verbose" => "Show extended terminal sections (`-v` or `--verbose`).",
        "e" | "explain" => {
            "When used in scans, `--explain` adds concise per-port rationale lines in output."
        }
        _ => {
            "Unknown flag. Try one of: --scan, -p, -sU, -sS, -sT, -Pn, -A, -T4, -p-, -v, --explain. Tip: use --flag-help <flag>."
        }
    };

    format!(
        "Flag help for `{}`\n\n{}\n\nExamples:\n  nprobe-rs 192.168.1.10\n  nprobe-rs -sU -p 53,161 192.168.1.10\n  nprobe-rs -A -T4 10.0.0.5\n  nprobe-rs --explain --scan",
        raw_query.unwrap_or("--scan"),
        body
    )
}

pub fn render_integrity_status(status: &IntegrityStatus) -> String {
    let mut out = String::new();
    out.push_str("nprobe-rs integrity status\n");
    out.push_str(&format!("state={}\n", status.state));
    out.push_str(&format!("baseline_present={}\n", status.baseline_present));
    out.push_str(&format!(
        "source_tree_verified={}\n",
        status.source_tree_verified
    ));
    out.push_str(&format!("files_checked={}\n", status.files_checked));
    out.push_str(&format!("manifest_sha256={}\n", status.manifest_sha256));
    out.push_str(&format!("executable_sha256={}\n", status.executable_sha256));
    out.push_str(&format!("executable_path={}\n", status.executable_path));
    if !status.notes.is_empty() {
        out.push_str("notes:\n");
        for note in &status.notes {
            out.push_str(&format!("- {note}\n"));
        }
    }
    out
}

impl ScanArgs {
    fn into_request(self) -> NProbeResult<ScanRequest> {
        if matches!(self.rate_limit_pps, Some(0)) {
            return Err(NProbeError::Cli(
                "--rate must be greater than 0".to_string(),
            ));
        }
        if matches!(self.gpu_rate_pps, Some(0)) {
            return Err(NProbeError::Cli(
                "--gpu-rate must be greater than 0".to_string(),
            ));
        }
        if matches!(self.gpu_burst_size, Some(0)) {
            return Err(NProbeError::Cli(
                "--gpu-burst must be greater than 0".to_string(),
            ));
        }
        if matches!(self.burst_size, Some(0)) {
            return Err(NProbeError::Cli(
                "--burst-size must be greater than 0".to_string(),
            ));
        }
        if let Some(retries) = self.max_retries {
            if retries > 20 {
                return Err(NProbeError::Cli(
                    "--max-retries must be between 0 and 20".to_string(),
                ));
            }
        }

        if matches!(self.total_shards, Some(0) | Some(1)) {
            return Err(NProbeError::Cli(
                "--total-shards must be at least 2".to_string(),
            ));
        }
        if self.shard_index.is_some() && self.total_shards.is_none() {
            return Err(NProbeError::Cli(
                "--shard-index requires --total-shards".to_string(),
            ));
        }
        if let (Some(total), Some(index)) = (self.total_shards, self.shard_index) {
            if index >= total {
                return Err(NProbeError::Cli(format!(
                    "--shard-index must be < --total-shards (got index={}, total={})",
                    index, total
                )));
            }
        }

        let (mut ports, top_ports) = if self.all_ports {
            ((1u16..=65535).collect(), None)
        } else if let Some(raw) = self.ports.as_deref() {
            (parse_ports(raw)?, None)
        } else if let Some(top) = self.top_ports {
            (Vec::new(), Some(top.max(1)))
        } else {
            (Vec::new(), None)
        };

        if self.root_only
            && self
                .profile
                .is_some_and(|value| !matches!(value, ScanProfile::RootOnly))
        {
            return Err(NProbeError::Cli(
                "--root-only conflicts with --profile values other than root-only".to_string(),
            ));
        }

        let root_only = self.root_only || matches!(self.profile, Some(ScanProfile::RootOnly));
        let mut effective_aggressive_root = self.aggressive || self.aggressive_root || root_only;
        let mut effective_privileged_probes =
            self.syn || self.privileged_probes || self.aggressive || root_only;

        let timing_template = self.timing_template;
        let profile_explicit = self.profile.is_some()
            || self.root_only
            || self.aggressive
            || timing_template.is_some();
        let profile = if root_only {
            ScanProfile::RootOnly
        } else if (self.aggressive || self.aggressive_root) && self.profile.is_none() {
            ScanProfile::Aggressive
        } else {
            self.profile.unwrap_or_else(|| {
                timing_template
                    .and_then(map_timing_to_profile)
                    .unwrap_or(ScanProfile::Balanced)
            })
        };

        let mut report_format = self
            .file_type
            .map(FileType::as_report_format)
            .or(self.report_legacy)
            .unwrap_or(ReportFormat::Cli);
        let output_requested =
            self.output.is_some() || self.location.is_some() || self.file_type.is_some();

        if let Some(output_name) = self.output.as_deref() {
            if self.file_type.is_none() && self.report_legacy.is_none() {
                if let Some(ext_fmt) = Path::new(output_name)
                    .extension()
                    .and_then(|value| value.to_str())
                    .and_then(ReportFormat::from_extension)
                {
                    report_format = ext_fmt;
                }
            }
        }

        if output_requested && matches!(report_format, ReportFormat::Cli) {
            report_format = ReportFormat::Txt;
        }

        let output_path = build_output_path(
            self.output.as_deref(),
            self.location.as_deref(),
            report_format,
            output_requested,
            self.file_type.is_some(),
        )?;

        let mut timeout_ms = self.timeout_ms;
        let mut concurrency = self.concurrency;
        let mut delay_ms = self.delay_ms;
        let rate_explicit = self.rate_limit_pps.is_some();
        let mut rate_limit_pps = self.rate_limit_pps;
        let gpu_rate_explicit = self.gpu_rate_pps.is_some();
        let gpu_rate_pps = self.gpu_rate_pps;
        let gpu_burst_size = self.gpu_burst_size;
        let gpu_timestamp = self.gpu_timestamp;
        let gpu_schedule_random = self.gpu_schedule_random;
        let override_mode = self.override_mode;
        let mut burst_size = self.burst_size;
        let mut max_retries = self.max_retries;
        let total_shards = self.total_shards;
        let shard_index = self.shard_index.or_else(|| total_shards.map(|_| 0));
        let scan_seed = self.scan_seed;
        let resume_from_checkpoint = self.resume || !self.fresh_scan;
        let fresh_scan = self.fresh_scan;
        let mut top_ports = top_ports;
        let mut lab_mode = self.lab_mode;
        let mut strict_safety = self.strict_safety;
        let ping_scan = self.ping_scan;
        let mut service_detection =
            self.service_detect || effective_aggressive_root || !self.no_service_detect;
        if self.os_detect {
            service_detection = true;
        }
        if matches!(profile, ScanProfile::Mirror) && !self.no_service_detect {
            service_detection = true;
        }
        if matches!(profile, ScanProfile::Idf) {
            lab_mode = true;
            strict_safety = true;
            service_detection = false;
        }
        if ping_scan {
            ports.clear();
            top_ports = None;
            effective_aggressive_root = false;
            effective_privileged_probes = false;
            service_detection = false;
        }
        if !ping_scan && ports.is_empty() && top_ports.is_none() {
            top_ports = match profile {
                ScanProfile::Idf => profile.concept_port_budget(),
                ScanProfile::Mirror => Some(64),
                _ => top_ports,
            };
        }
        let explain = self.explain || self.os_detect;
        let callback_ping = self.callback_ping || matches!(profile, ScanProfile::Mirror);

        if root_only {
            if timeout_ms.is_none() {
                timeout_ms = Some(ScanProfile::RootOnly.defaults().timeout_ms);
            }
            if concurrency.is_none() {
                concurrency = Some(ScanProfile::RootOnly.defaults().concurrency);
            }
            if delay_ms.is_none() {
                delay_ms = Some(ScanProfile::RootOnly.defaults().delay_ms);
            }
            if ports.is_empty() && top_ports.is_none() {
                top_ports = Some(200);
            }
            if rate_limit_pps.is_none() {
                rate_limit_pps = Some(2_000);
            }
            if burst_size.is_none() {
                burst_size = Some(64);
            }
            if max_retries.is_none() {
                max_retries = Some(2);
            }
        }

        if override_mode {
            let raw_lane_override = effective_privileged_probes || effective_aggressive_root;
            let gpu_lane_override = gpu_rate_explicit
                || gpu_burst_size.is_some()
                || gpu_timestamp
                || gpu_schedule_random;
            confirm_override_mode(raw_lane_override, gpu_lane_override)?;
        }

        Ok(ScanRequest {
            target: self.target,
            session_id: None,
            ports,
            top_ports,
            ping_scan,
            include_udp: !ping_scan && (self.udp || effective_aggressive_root),
            reverse_dns: self.reverse_dns && !self.no_dns,
            service_detection,
            explain,
            verbose: self.verbose,
            report_format,
            profile,
            profile_explicit,
            root_only,
            aggressive_root: effective_aggressive_root,
            privileged_probes: effective_privileged_probes,
            arp_discovery: self.arp,
            callback_ping,
            lab_mode,
            allow_external: self.allow_external,
            strict_safety,
            output_path,
            lua_script: self.lua_script,
            timeout_ms,
            concurrency,
            delay_ms,
            timing_template,
            rate_limit_pps,
            rate_explicit,
            gpu_rate_pps,
            gpu_rate_explicit,
            gpu_burst_size,
            gpu_timestamp,
            gpu_schedule_random,
            assess_hardware: self.assess_hardware,
            override_mode,
            burst_size,
            max_retries,
            total_shards,
            shard_index,
            scan_seed,
            resume_from_checkpoint,
            fresh_scan,
        })
    }
}

impl InteractiveArgs {
    fn into_request(self) -> NProbeResult<ScanRequest> {
        if !io::stdin().is_terminal() || !io::stdout().is_terminal() {
            return Err(NProbeError::Cli(
                "interactive mode requires a terminal because it prompts for beginner-friendly scan choices".to_string(),
            ));
        }
        println!("{INTERACTIVE_BANNER}");
        println!("[i] Interactive learner mode");
        println!("[i] Safe defaults: TBNS-first, strict-safety on, private-scope mode on");
        println!("[i] This mode is meant for beginners and learners using prompt-based setup.\n");

        let target = prompt_nonempty("Target host or CIDR")?;
        let profile = prompt_profile_choice()?;
        let (ports, top_ports) = prompt_port_selection(profile)?;
        let strict_safety = prompt_yes_no("Keep strict safety enabled", true)?;
        let lab_mode = prompt_yes_no("Limit this run to private/local targets", true)?;
        let explain = prompt_yes_no("Show concise explanations in results", true)?;
        let verbose = prompt_yes_no("Show learner sections (warnings, notes, advice)", true)?;
        let reverse_dns = prompt_yes_no("Enable reverse DNS lookups", false)?;
        let arp_discovery = if target.contains('/') || looks_like_private_ipv4_target(&target) {
            prompt_yes_no(
                "Enable ARP neighbor discovery for local IPv4 targets",
                false,
            )?
        } else {
            false
        };
        let service_detection = if strict_safety || profile.is_low_impact_concept() {
            false
        } else {
            prompt_yes_no("Enable deeper service detection", false)?
        };

        let port_summary = if let Some(top) = top_ports {
            format!("top-{top}")
        } else {
            format!("custom {} ports", ports.len())
        };
        let planned_port_count = top_ports.unwrap_or(ports.len()).max(1);
        let phantom_preview = phantom_preflight::preview(
            profile,
            planned_port_count,
            strict_safety,
            service_detection,
        );
        println!(
            "\n[+] Plan: target={} profile={} family={} scope={} ports={} strict-safety={} explain={} verbose={}",
            target,
            profile.as_str(),
            profile.scan_family(),
            if lab_mode { "private/local" } else { "user-selected" },
            port_summary,
            strict_safety,
            explain,
            verbose
        );
        println!(
            "[i] Phantom device check preview: stage=pending sample-budget={} payload-budget={} strict-safety={}",
            phantom_preview.sample_budget,
            phantom_preview.initial_payload_budget,
            phantom_preview.strict_safety
        );
        for note in &phantom_preview.notes {
            println!("    - {note}");
        }

        if !prompt_yes_no("Start scan now", true)? {
            return Err(NProbeError::Cli("interactive scan cancelled".to_string()));
        }

        Ok(ScanRequest {
            target,
            session_id: None,
            ports,
            top_ports,
            ping_scan: false,
            include_udp: false,
            reverse_dns,
            service_detection,
            explain,
            verbose,
            report_format: ReportFormat::Cli,
            profile,
            profile_explicit: true,
            root_only: false,
            aggressive_root: false,
            privileged_probes: false,
            arp_discovery,
            callback_ping: false,
            lab_mode,
            allow_external: false,
            strict_safety,
            output_path: None,
            lua_script: None,
            timeout_ms: None,
            concurrency: None,
            delay_ms: None,
            timing_template: None,
            rate_limit_pps: None,
            rate_explicit: false,
            gpu_rate_pps: None,
            gpu_rate_explicit: false,
            gpu_burst_size: None,
            gpu_timestamp: false,
            gpu_schedule_random: false,
            assess_hardware: false,
            override_mode: false,
            burst_size: None,
            max_retries: None,
            total_shards: None,
            shard_index: None,
            scan_seed: None,
            resume_from_checkpoint: true,
            fresh_scan: false,
        })
    }
}

fn normalize_args(args: Vec<OsString>) -> Vec<OsString> {
    if args.is_empty() {
        return args;
    }

    let mut normalized = Vec::with_capacity(args.len() + 2);
    normalized.push(args[0].clone());

    let mut mapped = Vec::new();
    let mut idx = 1usize;
    while idx < args.len() {
        let token = args[idx].to_string_lossy().to_string();
        match token.as_str() {
            "--scan" => {}
            "-sn" => mapped.push("--ping-scan".into()),
            "-sU" => mapped.push("--udp".into()),
            "-sS" => mapped.push("--syn".into()),
            "-sT" => mapped.push("--connect".into()),
            "-O" => mapped.push("--os-detect".into()),
            "-A" => mapped.push("--aggressive".into()),
            "-p-" => mapped.push("--all-ports".into()),
            "-sV" => mapped.push("--service-detect".into()),
            "-Pn" => mapped.push("--no-host-discovery".into()),
            "-PR" => mapped.push("--arp".into()),
            "--phantom" | "--phantom-scan" => {
                mapped.push("--profile".into());
                mapped.push("phantom".into());
            }
            "--sar" | "--sar-scan" | "--sars" => {
                mapped.push("--profile".into());
                mapped.push("sar".into());
            }
            "--kis" | "--kis-scan" => {
                mapped.push("--profile".into());
                mapped.push("kis".into());
            }
            "--idf" | "--idf-scan" | "--dummy-scan" | "--fog-scan" => {
                mapped.push("--profile".into());
                mapped.push("idf".into());
            }
            "--mirror" | "--mirror-scan" => {
                mapped.push("--profile".into());
                mapped.push("mirror".into());
            }
            "--hybrid" | "--hybrid-scan" | "--masscan-hybrid" | "--masscan-controlled" => {
                mapped.push("--profile".into());
                mapped.push("hybrid".into());
            }
            "-T" => {
                if idx + 1 < args.len() {
                    let level = args[idx + 1].to_string_lossy().to_string();
                    if let Some(level) = parse_timing_level(level.as_str()) {
                        mapped.push("--timing-template".into());
                        mapped.push(level.to_string().into());
                        idx += 1;
                    } else {
                        mapped.push(args[idx].clone());
                    }
                } else {
                    mapped.push(args[idx].clone());
                }
            }
            _ => {
                if token.starts_with("-T") && token.len() == 3 {
                    if let Some(level) = parse_timing_level(&token[2..]) {
                        mapped.push("--timing-template".into());
                        mapped.push(level.to_string().into());
                    } else {
                        mapped.push(args[idx].clone());
                    }
                } else {
                    mapped.push(args[idx].clone());
                }
            }
        }
        idx += 1;
    }

    if should_inject_scan(&mapped) {
        normalized.push("scan".into());
    }
    normalized.extend(mapped);
    normalized
}

fn should_inject_scan(mapped: &[OsString]) -> bool {
    if mapped.is_empty() {
        return false;
    }

    let first = mapped[0].to_string_lossy();
    !matches!(
        first.as_ref(),
        "scan"
            | "interactive"
            | "learn"
            | "wizard"
            | "integrity"
            | "sessions"
            | "-h"
            | "--help"
            | "-V"
            | "--version"
    )
}

fn prompt_nonempty(label: &str) -> NProbeResult<String> {
    loop {
        let value = prompt_line(label)?;
        if !value.trim().is_empty() {
            return Ok(value.trim().to_string());
        }
        println!("[!] Please enter a non-empty value.");
    }
}

fn prompt_line(label: &str) -> NProbeResult<String> {
    print!("{label}: ");
    io::stdout().flush().map_err(NProbeError::Io)?;
    let mut input = String::new();
    io::stdin().read_line(&mut input).map_err(NProbeError::Io)?;
    Ok(input.trim().to_string())
}

fn prompt_yes_no(label: &str, default_yes: bool) -> NProbeResult<bool> {
    loop {
        let suffix = if default_yes { "[Y/n]" } else { "[y/N]" };
        let value = prompt_line(&format!("{label} {suffix}"))?;
        if value.is_empty() {
            return Ok(default_yes);
        }
        match value.to_ascii_lowercase().as_str() {
            "y" | "yes" => return Ok(true),
            "n" | "no" => return Ok(false),
            _ => println!("[!] Enter yes or no."),
        }
    }
}

fn confirm_override_mode(raw_lane: bool, gpu_lane: bool) -> NProbeResult<()> {
    if cfg!(test) {
        return Ok(());
    }

    if !io::stdin().is_terminal() || !io::stdout().is_terminal() {
        return Err(NProbeError::Cli(
            "--override-mode requires an interactive terminal because it asks for explicit risk confirmations".to_string(),
        ));
    }

    println!("[!] Override mode requested.");
    println!(
        "[!] This bypasses adaptive safety governors, local auto-throttles, and emergency-brake enforcement."
    );
    println!(
        "[!] Cons: fragile targets can be overloaded, packet bursts can spike abruptly, and this host can become unstable under sustained acceleration."
    );
    if !prompt_yes_no("Continue with override mode", false)? {
        return Err(NProbeError::Cli("override mode cancelled".to_string()));
    }

    if raw_lane {
        println!("[!] Raw/kernel-bypass override risks:");
        println!(
            "    - Blackrock-shuffled packet crafting can ignore target fragility signals and device-profile pacing."
        );
        println!(
            "    - The masscan-style firehose can transmit with fewer brakes, which can destabilize fragile hosts."
        );
        if !prompt_yes_no(
            "Disable adaptive raw packet safety governors for this run",
            false,
        )? {
            return Err(NProbeError::Cli("override mode cancelled".to_string()));
        }
    }

    if gpu_lane {
        println!("[!] GPU/parallel override risks:");
        println!(
            "    - GPU/parallel crafters can outrun the CPU/NIC bridge and bypass local health pacing."
        );
        println!(
            "    - Local thermal, memory, and queue pressure can rise faster because emergency auto-throttles are disabled."
        );
        if !prompt_yes_no(
            "Disable adaptive GPU/parallel safety governors for this run",
            false,
        )? {
            return Err(NProbeError::Cli("override mode cancelled".to_string()));
        }
    }

    Ok(())
}

fn prompt_profile_choice() -> NProbeResult<ScanProfile> {
    println!("Profiles:");
    println!("  1. phantom  (TBNS device-check, least-contact, recommended)");
    println!("  2. kis      (TBNS identity hints, timing-focused)");
    println!("  3. sar      (TBNS logic observation, timing-delta)");
    println!("  4. idf      (TBNS inert-decoy-fog, sparse low-impact)");
    println!("  5. mirror   (core reflective hybrid correlation)");
    println!("  6. stealth  (core cautious scan)");
    println!("  7. balanced (core general scan)");
    loop {
        let value = prompt_line("Choose profile [1-7]")?;
        let normalized = if value.is_empty() {
            "1"
        } else {
            value.as_str()
        };
        let profile = match normalized.to_ascii_lowercase().as_str() {
            "1" | "phantom" => Some(ScanProfile::Phantom),
            "2" | "kis" => Some(ScanProfile::Kis),
            "3" | "sar" => Some(ScanProfile::Sar),
            "4" | "idf" => Some(ScanProfile::Idf),
            "5" | "mirror" => Some(ScanProfile::Mirror),
            "6" | "stealth" => Some(ScanProfile::Stealth),
            "7" | "balanced" => Some(ScanProfile::Balanced),
            _ => None,
        };
        if let Some(profile) = profile {
            return Ok(profile);
        }
        println!("[!] Choose one of: 1, 2, 3, 4, 5, 6, 7.");
    }
}

fn prompt_port_selection(profile: ScanProfile) -> NProbeResult<(Vec<u16>, Option<usize>)> {
    if let Some(budget) = profile.concept_port_budget() {
        let smaller = (budget / 2).max(1);
        println!("Port scope:");
        println!("  1. top-{smaller} (recommended)");
        println!("  2. top-{budget}");
        println!("  3. custom list/range");
        loop {
            let value = prompt_line("Choose port scope [1-3]")?;
            let normalized = if value.is_empty() {
                "1"
            } else {
                value.as_str()
            };
            match normalized {
                "1" => return Ok((Vec::new(), Some(smaller))),
                "2" => return Ok((Vec::new(), Some(budget))),
                "3" => {
                    let raw = prompt_nonempty("Enter ports like 22,80,443 or 1-32")?;
                    return Ok((parse_ports(&raw)?, None));
                }
                _ => println!("[!] Choose one of: 1, 2, 3."),
            }
        }
    }

    println!("Port scope:");
    println!("  1. top-25 (recommended)");
    println!("  2. top-100");
    println!("  3. custom list/range");
    loop {
        let value = prompt_line("Choose port scope [1-3]")?;
        let normalized = if value.is_empty() {
            "1"
        } else {
            value.as_str()
        };
        match normalized {
            "1" => return Ok((Vec::new(), Some(25))),
            "2" => return Ok((Vec::new(), Some(100))),
            "3" => {
                let raw = prompt_nonempty("Enter ports like 22,80,443 or 1-1024")?;
                return Ok((parse_ports(&raw)?, None));
            }
            _ => println!("[!] Choose one of: 1, 2, 3."),
        }
    }
}

fn looks_like_private_ipv4_target(target: &str) -> bool {
    let token = target.trim().split('/').next().unwrap_or("").trim();
    token
        .parse::<Ipv4Addr>()
        .map(|ip| ip.is_private() || ip.is_link_local())
        .unwrap_or(false)
}

pub fn render_session_list(
    records: &[ScanSessionRecord],
    filters: &SessionRecordFilters,
) -> String {
    let mut out = String::new();
    out.push_str("nprobe-rs session history\n");
    append_session_filter_summary(&mut out, filters);
    if records.is_empty() {
        if filters.is_active() {
            out.push_str("No persisted sessions matched the active filters.\n");
        } else {
            out.push_str("No persisted sessions found.\n");
        }
        return out;
    }

    out.push_str(&format!(
        "{:<33} {:<12} {:<12} {:<25} {}\n",
        "SESSION ID", "PROFILE", "STATUS", "UPDATED", "TARGET"
    ));
    out.push_str(&format!(
        "{:-<33} {:-<12} {:-<12} {:-<25} {:-<20}\n",
        "", "", "", "", ""
    ));

    for record in records {
        out.push_str(&format!(
            "{:<33} {:<12} {:<12} {:<25} {}\n",
            truncate_cell(&record.session_id, 33),
            truncate_cell(&record.profile, 12),
            record.status.as_str(),
            truncate_cell(&record.updated_at, 25),
            record.target
        ));
        if let Some(category) = &record.failure_category {
            out.push_str(&format!("  failure_category={category}\n"));
        }
    }

    out
}

pub fn render_session_detail(record: &ScanSessionRecord) -> String {
    let mut out = String::new();
    out.push_str("nprobe-rs session detail\n");
    out.push_str(&format!("session_id={}\n", record.session_id));
    out.push_str(&format!("status={}\n", record.status.as_str()));
    out.push_str(&format!("target={}\n", record.target));
    out.push_str(&format!("profile={}\n", record.profile));
    out.push_str(&format!("report_format={}\n", record.report_format));
    out.push_str(&format!("started_at={}\n", record.started_at));
    out.push_str(&format!("updated_at={}\n", record.updated_at));
    out.push_str(&format!(
        "finished_at={}\n",
        record.finished_at.as_deref().unwrap_or("n/a")
    ));
    out.push_str(&format!(
        "scan_seed={}\n",
        record
            .scan_seed
            .map(|value| value.to_string())
            .unwrap_or_else(|| "n/a".to_string())
    ));
    out.push_str(&format!(
        "shards={}/{}\n",
        record
            .shard_index
            .map(|value| value.to_string())
            .unwrap_or_else(|| "n/a".to_string()),
        record
            .total_shards
            .map(|value| value.to_string())
            .unwrap_or_else(|| "n/a".to_string())
    ));
    out.push_str(&format!(
        "rate_limit_pps={}\n",
        record
            .rate_limit_pps
            .map(|value| value.to_string())
            .unwrap_or_else(|| "n/a".to_string())
    ));
    out.push_str(&format!(
        "burst_size={}\n",
        record
            .burst_size
            .map(|value| value.to_string())
            .unwrap_or_else(|| "n/a".to_string())
    ));
    out.push_str(&format!(
        "max_retries={}\n",
        record
            .max_retries
            .map(|value| value.to_string())
            .unwrap_or_else(|| "n/a".to_string())
    ));
    out.push_str(&format!(
        "output_path={}\n",
        record.output_path.as_deref().unwrap_or("n/a")
    ));
    out.push_str(&format!(
        "host_count={}\n",
        record
            .host_count
            .map(|value| value.to_string())
            .unwrap_or_else(|| "n/a".to_string())
    ));
    out.push_str(&format!(
        "responded_hosts={}\n",
        record
            .responded_hosts
            .map(|value| value.to_string())
            .unwrap_or_else(|| "n/a".to_string())
    ));
    out.push_str(&format!(
        "duration_ms={}\n",
        record
            .duration_ms
            .map(|value| value.to_string())
            .unwrap_or_else(|| "n/a".to_string())
    ));
    out.push_str(&format!(
        "host_snapshot_count={}\n",
        record
            .host_snapshot_count
            .map(|value| value.to_string())
            .unwrap_or_else(|| "n/a".to_string())
    ));
    if let Some(category) = &record.failure_category {
        out.push_str(&format!("failure_category={category}\n"));
    }
    if let Some(hint) = &record.recovery_hint {
        out.push_str(&format!("recovery_hint={hint}\n"));
    }
    if !record.notes.is_empty() {
        out.push_str("notes:\n");
        for note in &record.notes {
            out.push_str(&format!("- {note}\n"));
        }
    }
    out
}

pub fn render_session_diff(diff: &SessionActionableDiff) -> String {
    let mut out = String::new();
    out.push_str("nprobe-rs actionable session diff\n");
    out.push_str(&format!(
        "older_session={} newer_session={}\n",
        diff.older.session_id, diff.newer.session_id
    ));
    out.push_str(&format!(
        "older_target={} newer_target={}\n",
        diff.older.target, diff.newer.target
    ));
    out.push_str(&format!(
        "summary added={} resolved={} escalated={} reduced={} unchanged={}\n",
        diff.added.len(),
        diff.resolved.len(),
        diff.escalated.len(),
        diff.reduced.len(),
        diff.unchanged
    ));
    append_session_filter_summary(&mut out, &diff.session_filters);
    if let Some(ip_filter) = &diff.ip_filter {
        out.push_str(&format!("ip_filter={ip_filter}\n"));
    }
    if let Some(target_filter) = &diff.target_filter {
        out.push_str(&format!("target_filter={target_filter}\n"));
    }
    if let Some(severity_filter) = diff.severity_filter {
        out.push_str(&format!("severity_filter={}\n", severity_filter.as_str()));
    }

    append_diff_section(&mut out, "New issues", &diff.added);
    append_diff_section(&mut out, "Resolved issues", &diff.resolved);
    append_diff_section(&mut out, "Escalated issues", &diff.escalated);
    append_diff_section(&mut out, "Reduced issues", &diff.reduced);

    out
}

pub fn render_session_diff_json(diff: &SessionActionableDiff) -> NProbeResult<String> {
    Ok(serde_json::to_string_pretty(diff)?)
}

pub fn render_session_diff_html(diff: &SessionActionableDiff) -> String {
    let mut html = String::new();
    html.push_str("<!doctype html><html><head><meta charset=\"utf-8\">");
    html.push_str("<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">");
    html.push_str("<title>NProbe-RS Session Diff</title>");
    html.push_str("<style>");
    html.push_str(
        ":root{--bg:#f5f7fb;--panel:#ffffff;--ink:#182332;--muted:#66758a;--critical:#8f2d2d;--high:#a3581a;--moderate:#735f13;--review:#3f648f;}
        body{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;background:linear-gradient(120deg,#f5f7fb,#eaf0f7);color:var(--ink);margin:0;padding:24px;}
        .wrap{max-width:1100px;margin:0 auto;}
        .card{background:var(--panel);border:1px solid #e5ebf2;border-radius:14px;padding:18px;margin-bottom:18px;box-shadow:0 6px 20px rgba(10,20,40,.06);}
        .meta{color:var(--muted);font-size:14px;line-height:1.6}
        h1,h2,h3{margin:0 0 10px 0}
        ul{margin:8px 0 0 18px}
        details{margin-top:10px;border-top:1px solid #eef2f7;padding-top:10px}
        summary{cursor:pointer;font-weight:700;list-style:none}
        .sev{display:inline-block;padding:2px 8px;border-radius:999px;font-size:11px;font-weight:700;text-transform:uppercase;letter-spacing:.04em;margin-right:8px}
        .sev-critical{background:#f7dfdf;color:var(--critical)}
        .sev-high{background:#f8e7d7;color:var(--high)}
        .sev-moderate{background:#f5edcf;color:var(--moderate)}
        .sev-review{background:#dde8f7;color:var(--review)}
        code{background:#eef3f8;padding:1px 5px;border-radius:6px}
        </style></head><body><div class=\"wrap\">",
    );
    html.push_str("<div class=\"card\">");
    html.push_str("<h1>NProbe-RS Actionable Session Diff</h1>");
    html.push_str(&format!(
        "<div class=\"meta\">Older session: <code>{}</code><br>Newer session: <code>{}</code><br>Older target: {}<br>Newer target: {}<br>Summary: added {} | resolved {} | escalated {} | reduced {} | unchanged {}</div>",
        escape_html(&diff.older.session_id),
        escape_html(&diff.newer.session_id),
        escape_html(&diff.older.target),
        escape_html(&diff.newer.target),
        diff.added.len(),
        diff.resolved.len(),
        diff.escalated.len(),
        diff.reduced.len(),
        diff.unchanged
    ));
    append_session_filter_summary_html(&mut html, &diff.session_filters);
    if let Some(ip_filter) = &diff.ip_filter {
        html.push_str(&format!(
            "<div class=\"meta\">IP filter: <code>{}</code></div>",
            escape_html(ip_filter)
        ));
    }
    if let Some(target_filter) = &diff.target_filter {
        html.push_str(&format!(
            "<div class=\"meta\">Target filter: <code>{}</code></div>",
            escape_html(target_filter)
        ));
    }
    if let Some(severity_filter) = diff.severity_filter {
        html.push_str(&format!(
            "<div class=\"meta\">Minimum severity: <code>{}</code></div>",
            escape_html(severity_filter.as_str())
        ));
    }
    html.push_str("</div>");

    append_diff_section_html(&mut html, "New issues", &diff.added);
    append_diff_section_html(&mut html, "Resolved issues", &diff.resolved);
    append_diff_section_html(&mut html, "Escalated issues", &diff.escalated);
    append_diff_section_html(&mut html, "Reduced issues", &diff.reduced);

    html.push_str("</div></body></html>");
    html
}

fn truncate_cell(value: &str, width: usize) -> String {
    let mut chars = value.chars();
    let truncated: String = chars.by_ref().take(width.saturating_sub(1)).collect();
    if chars.next().is_some() && width > 1 {
        format!("{truncated}~")
    } else {
        value.to_string()
    }
}

#[derive(Debug, Default, Clone, Copy)]
struct SeverityCounts {
    critical: usize,
    high: usize,
    moderate: usize,
    review: usize,
}

impl SeverityCounts {
    fn add(&mut self, severity: crate::reporter::actionable::ActionableSeverity) {
        match severity {
            crate::reporter::actionable::ActionableSeverity::Critical => self.critical += 1,
            crate::reporter::actionable::ActionableSeverity::High => self.high += 1,
            crate::reporter::actionable::ActionableSeverity::Moderate => self.moderate += 1,
            crate::reporter::actionable::ActionableSeverity::Review => self.review += 1,
        }
    }
}

fn append_session_filter_summary(out: &mut String, filters: &SessionRecordFilters) {
    if !filters.is_active() {
        return;
    }

    out.push_str("filters:\n");
    if let Some(profile_filter) = &filters.profile_filter {
        out.push_str(&format!("  profile={profile_filter}\n"));
    }
    if let Some(updated_after) = filters.updated_after {
        out.push_str(&format!("  updated_after={}\n", updated_after.to_rfc3339()));
    }
    if let Some(updated_before) = filters.updated_before {
        out.push_str(&format!(
            "  updated_before={}\n",
            updated_before.to_rfc3339()
        ));
    }
}

fn append_session_filter_summary_html(html: &mut String, filters: &SessionRecordFilters) {
    if !filters.is_active() {
        return;
    }

    if let Some(profile_filter) = &filters.profile_filter {
        html.push_str(&format!(
            "<div class=\"meta\">Profile filter: <code>{}</code></div>",
            escape_html(profile_filter)
        ));
    }
    if let Some(updated_after) = filters.updated_after {
        html.push_str(&format!(
            "<div class=\"meta\">Updated after: <code>{}</code></div>",
            escape_html(&updated_after.to_rfc3339())
        ));
    }
    if let Some(updated_before) = filters.updated_before {
        html.push_str(&format!(
            "<div class=\"meta\">Updated before: <code>{}</code></div>",
            escape_html(&updated_before.to_rfc3339())
        ));
    }
}

fn diff_section_counts(items: &[ActionableDiffItem]) -> (usize, SeverityCounts) {
    let mut hosts = BTreeSet::new();
    let mut counts = SeverityCounts::default();
    for item in items {
        hosts.insert((item.ip.as_str(), item.target.as_str()));
        counts.add(diff_item_effective_severity(item));
    }
    (hosts.len(), counts)
}

fn diff_host_severity_counts(items: &[&ActionableDiffItem]) -> SeverityCounts {
    let mut counts = SeverityCounts::default();
    for item in items {
        counts.add(diff_item_effective_severity(item));
    }
    counts
}

fn render_severity_counts_inline(counts: SeverityCounts) -> String {
    format!(
        "critical {} | high {} | moderate {} | review {}",
        counts.critical, counts.high, counts.moderate, counts.review
    )
}

fn append_diff_section(out: &mut String, title: &str, items: &[ActionableDiffItem]) {
    if items.is_empty() {
        return;
    }

    let (host_count, severity_counts) = diff_section_counts(items);
    out.push_str(&format!("{title}:\n"));
    out.push_str(&format!(
        "  hosts={} items={} {}\n",
        host_count,
        items.len(),
        render_severity_counts_inline(severity_counts)
    ));
    for item in items {
        let severity = match (item.severity_before, item.severity_after) {
            (Some(before), Some(after)) if before != after => {
                format!("{}->{}", before.as_str(), after.as_str())
            }
            (_, Some(after)) => after.as_str().to_string(),
            (Some(before), None) => before.as_str().to_string(),
            (None, None) => "review".to_string(),
        };
        out.push_str(&format!(
            "- [{}] {} ({}) {}\n",
            severity, item.ip, item.target, item.issue
        ));
        if let Some(after) = item.action_after.as_deref() {
            out.push_str(&format!("  next={after}\n"));
        } else if let Some(before) = item.action_before.as_deref() {
            out.push_str(&format!("  previous={before}\n"));
        }
    }
}

fn append_diff_section_html(html: &mut String, title: &str, items: &[ActionableDiffItem]) {
    if items.is_empty() {
        return;
    }

    let mut groups: BTreeMap<(String, String), Vec<&ActionableDiffItem>> = BTreeMap::new();
    for item in items {
        groups
            .entry((item.ip.clone(), item.target.clone()))
            .or_default()
            .push(item);
    }

    let (host_count, section_counts) = diff_section_counts(items);
    html.push_str(&format!("<div class=\"card\"><h2>{}</h2>", title));
    html.push_str(&format!(
        "<div class=\"meta\">Hosts: {} | Items: {} | {}</div>",
        host_count,
        items.len(),
        escape_html(&render_severity_counts_inline(section_counts))
    ));
    for ((ip, target), host_items) in groups {
        let host_counts = diff_host_severity_counts(&host_items);
        let highest = host_items
            .iter()
            .filter_map(|item| item.severity_after.or(item.severity_before))
            .max_by_key(|severity| severity.rank());
        let highest = highest.unwrap_or(crate::reporter::actionable::ActionableSeverity::Review);
        let open_attr = if host_items.iter().any(|item| {
            matches!(
                item.severity_after.or(item.severity_before),
                Some(crate::reporter::actionable::ActionableSeverity::Critical)
            )
        }) {
            " open"
        } else {
            ""
        };

        html.push_str(&format!(
            "<details{}><summary><span class=\"sev sev-{}\">{}</span>{} ({}) - {} item(s) <span class=\"meta\">{}</span></summary><ul>",
            open_attr,
            escape_html(highest.as_str()),
            escape_html(highest.as_str()),
            escape_html(&ip),
            escape_html(&target),
            host_items.len(),
            escape_html(&render_severity_counts_inline(host_counts))
        ));

        for item in host_items {
            let severity_label = diff_item_severity_label(item);
            let severity_css = diff_item_css_severity(item);
            html.push_str(&format!(
                "<li><span class=\"sev sev-{}\">{}</span>{}",
                escape_html(severity_css),
                escape_html(&severity_label),
                escape_html(&item.issue)
            ));
            if let Some(after) = item.action_after.as_deref() {
                html.push_str(&format!(
                    "<br><span class=\"meta\">Next: {}</span>",
                    escape_html(after)
                ));
            } else if let Some(before) = item.action_before.as_deref() {
                html.push_str(&format!(
                    "<br><span class=\"meta\">Previous: {}</span>",
                    escape_html(before)
                ));
            }
            html.push_str("</li>");
        }

        html.push_str("</ul></details>");
    }
    html.push_str("</div>");
}

fn escape_html(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for ch in input.chars() {
        match ch {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            _ => out.push(ch),
        }
    }
    out
}

fn diff_item_severity_label(item: &ActionableDiffItem) -> String {
    match (item.severity_before, item.severity_after) {
        (Some(before), Some(after)) if before != after => {
            format!("{}->{}", before.as_str(), after.as_str())
        }
        (_, Some(after)) => after.as_str().to_string(),
        (Some(before), None) => before.as_str().to_string(),
        (None, None) => "review".to_string(),
    }
}

fn diff_item_effective_severity(
    item: &ActionableDiffItem,
) -> crate::reporter::actionable::ActionableSeverity {
    item.severity_after
        .or(item.severity_before)
        .unwrap_or(crate::reporter::actionable::ActionableSeverity::Review)
}

fn diff_item_css_severity(item: &ActionableDiffItem) -> &'static str {
    diff_item_effective_severity(item).as_str()
}

fn parse_timing_level(level: &str) -> Option<u8> {
    match level.trim() {
        "0" => Some(0),
        "1" => Some(1),
        "2" => Some(2),
        "3" => Some(3),
        "4" => Some(4),
        "5" => Some(5),
        _ => None,
    }
}

fn map_timing_to_profile(level: u8) -> Option<ScanProfile> {
    match level {
        0 | 1 => Some(ScanProfile::Stealth),
        2 | 3 => Some(ScanProfile::Balanced),
        4 => Some(ScanProfile::Turbo),
        5 => Some(ScanProfile::Aggressive),
        _ => None,
    }
}

fn build_output_path(
    output_name: Option<&str>,
    location: Option<&Path>,
    format: ReportFormat,
    output_requested: bool,
    force_extension: bool,
) -> NProbeResult<Option<PathBuf>> {
    if !output_requested {
        return Ok(None);
    }

    let base_dir = if let Some(path) = location {
        path.to_path_buf()
    } else {
        std::env::current_dir().map_err(|err| {
            NProbeError::Cli(format!("failed to read current working directory: {err}"))
        })?
    };

    let file_name = match output_name {
        Some(value) if value.trim().is_empty() => {
            return Err(NProbeError::Cli(
                "--output cannot be empty or whitespace".to_string(),
            ));
        }
        Some(value) => value.to_string(),
        None => {
            let stamp = Utc::now().format("%Y%m%d-%H%M%S");
            format!("nprobe-report-{stamp}.{}", format.extension())
        }
    };

    let mut output_path = PathBuf::from(file_name);
    if !output_path.is_absolute() {
        output_path = base_dir.join(output_path);
    }

    if force_extension || output_path.extension().is_none() {
        output_path.set_extension(format.extension());
    }

    Ok(Some(output_path))
}

fn build_session_record_filters(
    profile_filter: Option<String>,
    updated_after: Option<String>,
    updated_before: Option<String>,
) -> NProbeResult<SessionRecordFilters> {
    let filters = SessionRecordFilters {
        profile_filter: profile_filter
            .map(|value| value.trim().to_ascii_lowercase())
            .filter(|value| !value.is_empty()),
        updated_after: updated_after
            .as_deref()
            .map(|value| parse_session_time_filter(value, false))
            .transpose()?,
        updated_before: updated_before
            .as_deref()
            .map(|value| parse_session_time_filter(value, true))
            .transpose()?,
    };

    if let (Some(updated_after), Some(updated_before)) =
        (filters.updated_after, filters.updated_before)
    {
        if updated_after > updated_before {
            return Err(NProbeError::Cli(
                "--updated-after must be earlier than or equal to --updated-before".to_string(),
            ));
        }
    }

    Ok(filters)
}

fn parse_session_time_filter(raw: &str, end_of_day: bool) -> NProbeResult<DateTime<Utc>> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err(NProbeError::Cli(
            "session time filters cannot be empty".to_string(),
        ));
    }

    if let Ok(timestamp) = DateTime::parse_from_rfc3339(trimmed) {
        return Ok(timestamp.with_timezone(&Utc));
    }

    if let Ok(date) = NaiveDate::parse_from_str(trimmed, "%Y-%m-%d") {
        let naive = if end_of_day {
            date.and_hms_milli_opt(23, 59, 59, 999)
        } else {
            date.and_hms_opt(0, 0, 0)
        }
        .ok_or_else(|| {
            NProbeError::Cli(format!(
                "failed to normalize date-only session filter '{trimmed}'"
            ))
        })?;
        return Ok(DateTime::<Utc>::from_naive_utc_and_offset(naive, Utc));
    }

    Err(NProbeError::Cli(format!(
        "invalid session timestamp '{trimmed}'. Use RFC3339 like 2026-03-07T10:30:00Z or date-only like 2026-03-07"
    )))
}

fn parse_ports(raw: &str) -> NProbeResult<Vec<u16>> {
    let mut ports = BTreeSet::new();
    for token in raw.split(',').map(str::trim).filter(|t| !t.is_empty()) {
        if let Some((start, end)) = token.split_once('-') {
            let start_port = parse_port(start)?;
            let end_port = parse_port(end)?;
            if start_port > end_port {
                return Err(NProbeError::Cli(format!(
                    "invalid port range '{token}': start > end"
                )));
            }
            for port in start_port..=end_port {
                ports.insert(port);
            }
            continue;
        }
        ports.insert(parse_port(token)?);
    }

    if ports.is_empty() {
        return Err(NProbeError::Cli("no valid ports provided".to_string()));
    }

    Ok(ports.into_iter().collect())
}

fn parse_port(raw: &str) -> NProbeResult<u16> {
    raw.parse::<u16>()
        .map_err(|_| NProbeError::Cli(format!("invalid port '{raw}'")))
        .and_then(|port| {
            if port == 0 {
                Err(NProbeError::Cli("port 0 is not scannable".to_string()))
            } else {
                Ok(port)
            }
        })
}

#[cfg(test)]
mod tests {
    use super::{
        detect_cataloged_scan_gate, looks_like_private_ipv4_target, normalize_args,
        render_integrity_status, should_inject_scan, Cli, CliAction, SessionCommand,
    };
    use crate::models::ScanProfile;
    use crate::platform::self_integrity::IntegrityStatus;
    use crate::reporter::actionable::ActionableSeverity;
    use clap::Parser;
    use std::ffi::OsString;

    #[test]
    fn normalize_args_keeps_interactive_subcommands() {
        let args = vec![OsString::from("nprobe-rs"), OsString::from("interactive")];
        let normalized = normalize_args(args);
        assert_eq!(normalized[1].to_string_lossy(), "interactive");

        let learn = vec![OsString::from("nprobe-rs"), OsString::from("learn")];
        let normalized_learn = normalize_args(learn);
        assert_eq!(normalized_learn[1].to_string_lossy(), "learn");
        assert!(!should_inject_scan(&normalized_learn[1..]));
    }

    #[test]
    fn private_ipv4_helper_is_precise() {
        assert!(looks_like_private_ipv4_target("10.0.0.5"));
        assert!(looks_like_private_ipv4_target("192.168.1.0/24"));
        assert!(!looks_like_private_ipv4_target("172.2.0.1"));
        assert!(!looks_like_private_ipv4_target("example.com"));
    }

    #[test]
    fn normalize_args_maps_nmap_connect_and_no_ping_aliases() {
        let args = vec![
            OsString::from("nprobe-rs"),
            OsString::from("-sT"),
            OsString::from("-Pn"),
            OsString::from("10.0.0.5"),
        ];
        let normalized = normalize_args(args);
        let rendered = normalized
            .iter()
            .map(|value| value.to_string_lossy().to_string())
            .collect::<Vec<_>>();
        assert!(rendered.contains(&"--connect".to_string()));
        assert!(rendered.contains(&"--no-host-discovery".to_string()));
    }

    #[test]
    fn normalize_args_maps_ping_scan_and_timing_aliases() {
        let args = vec![
            OsString::from("nprobe-rs"),
            OsString::from("-sn"),
            OsString::from("-T4"),
            OsString::from("10.0.0.5"),
        ];
        let normalized = normalize_args(args);
        let rendered = normalized
            .iter()
            .map(|value| value.to_string_lossy().to_string())
            .collect::<Vec<_>>();
        assert!(rendered.contains(&"--ping-scan".to_string()));
        assert!(rendered.contains(&"--timing-template".to_string()));
        assert!(rendered.contains(&"4".to_string()));
    }

    #[test]
    fn normalize_args_maps_nmap_arp_alias() {
        let args = vec![
            OsString::from("nprobe-rs"),
            OsString::from("-PR"),
            OsString::from("10.0.0.5"),
        ];
        let normalized = normalize_args(args);
        let rendered = normalized
            .iter()
            .map(|value| value.to_string_lossy().to_string())
            .collect::<Vec<_>>();
        assert!(rendered.contains(&"--arp".to_string()));
    }

    #[test]
    fn normalize_args_maps_profile_and_os_aliases() {
        let args = vec![
            OsString::from("nprobe-rs"),
            OsString::from("--idf-scan"),
            OsString::from("--mirror-scan"),
            OsString::from("-O"),
            OsString::from("10.0.0.5"),
        ];
        let normalized = normalize_args(args);
        let rendered = normalized
            .iter()
            .map(|value| value.to_string_lossy().to_string())
            .collect::<Vec<_>>();
        assert!(rendered.contains(&"--profile".to_string()));
        assert!(rendered.contains(&"idf".to_string()));
        assert!(rendered.contains(&"mirror".to_string()));
        assert!(rendered.contains(&"--os-detect".to_string()));
    }

    #[test]
    fn normalize_args_keeps_integrity_subcommand() {
        let args = vec![OsString::from("nprobe-rs"), OsString::from("integrity")];
        let normalized = normalize_args(args);
        assert_eq!(normalized[1].to_string_lossy(), "integrity");
        assert!(!should_inject_scan(&normalized[1..]));
    }

    #[test]
    fn sessions_diff_parses_into_diff_command() {
        let cli = Cli::parse_from([
            "nprobe-rs",
            "sessions",
            "--diff",
            "older-session",
            "newer-session",
            "--profile",
            "phantom",
            "--updated-after",
            "2026-03-01",
            "--updated-before",
            "2026-03-07",
            "--severity",
            "high",
        ]);
        let action = cli.into_action().expect("cli action should parse");
        match action {
            CliAction::Sessions(SessionCommand::Diff {
                older_session_id,
                newer_session_id,
                session_filters,
                severity_filter,
                ..
            }) => {
                assert_eq!(older_session_id, "older-session");
                assert_eq!(newer_session_id, "newer-session");
                assert_eq!(session_filters.profile_filter.as_deref(), Some("phantom"));
                assert!(session_filters.updated_after.is_some());
                assert!(session_filters.updated_before.is_some());
                assert_eq!(severity_filter, Some(ActionableSeverity::High));
            }
            other => panic!("unexpected action: {other:?}"),
        }
    }

    #[test]
    fn callback_ping_and_mirror_profile_parse_into_request() {
        let argv = normalize_args(vec![
            OsString::from("nprobe-rs"),
            OsString::from("10.0.0.5"),
            OsString::from("--mirror-scan"),
            OsString::from("--callback-ping"),
        ]);
        let cli = Cli::parse_from(argv);
        let action = cli.into_action().expect("cli action should parse");
        match action {
            CliAction::Scan(request) => {
                assert_eq!(request.profile, ScanProfile::Mirror);
                assert!(request.callback_ping);
            }
            other => panic!("unexpected action: {other:?}"),
        }
    }

    #[test]
    fn traditional_scan_aliases_parse_directly() {
        let cli = Cli::parse_from([
            "nprobe-rs",
            "scan",
            "10.0.0.5",
            "--syn-scan",
            "--udp-scan",
            "--service-version",
            "--os-fingerprint",
        ]);
        let action = cli.into_action().expect("cli action should parse");
        match action {
            CliAction::Scan(request) => {
                assert!(request.privileged_probes);
                assert!(request.include_udp);
                assert!(request.service_detection);
                assert!(request.explain);
            }
            other => panic!("unexpected action: {other:?}"),
        }
    }

    #[test]
    fn ping_scan_mode_parses_as_discovery_only() {
        let cli = Cli::parse_from(["nprobe-rs", "scan", "10.0.0.5", "--ping-scan", "-p", "80"]);
        let action = cli.into_action().expect("cli action should parse");
        match action {
            CliAction::Scan(request) => {
                assert!(request.ping_scan);
                assert!(request.ports.is_empty());
                assert_eq!(request.top_ports, None);
                assert!(!request.service_detection);
            }
            other => panic!("unexpected action: {other:?}"),
        }
    }

    #[test]
    fn timing_template_parses_from_hidden_runtime_flag() {
        let cli = Cli::parse_from(["nprobe-rs", "scan", "10.0.0.5", "--timing-template", "4"]);
        let action = cli.into_action().expect("cli action should parse");
        match action {
            CliAction::Scan(request) => {
                assert_eq!(request.timing_template, Some(4));
                assert_eq!(request.profile, ScanProfile::Turbo);
            }
            other => panic!("unexpected action: {other:?}"),
        }
    }

    #[test]
    fn stealth_scan_alias_maps_to_syn_lane() {
        let cli = Cli::parse_from(["nprobe-rs", "scan", "10.0.0.5", "--stealth-scan"]);
        let action = cli.into_action().expect("cli action should parse");
        match action {
            CliAction::Scan(request) => {
                assert!(request.privileged_probes);
            }
            other => panic!("unexpected action: {other:?}"),
        }
    }

    #[test]
    fn rate_flags_parse_into_explicit_caps() {
        let cli = Cli::parse_from([
            "nprobe-rs",
            "scan",
            "10.0.0.5",
            "--rate",
            "250",
            "--gpu-rate",
            "120",
        ]);
        let action = cli.into_action().expect("cli action should parse");
        match action {
            CliAction::Scan(request) => {
                assert_eq!(request.rate_limit_pps, Some(250));
                assert!(request.rate_explicit);
                assert_eq!(request.gpu_rate_pps, Some(120));
                assert!(request.gpu_rate_explicit);
            }
            other => panic!("unexpected action: {other:?}"),
        }
    }

    #[test]
    fn bare_rate_flags_default_to_100_pps() {
        let cli = Cli::parse_from(["nprobe-rs", "scan", "10.0.0.5", "--rate", "--gpu-rate"]);
        let action = cli.into_action().expect("cli action should parse");
        match action {
            CliAction::Scan(request) => {
                assert_eq!(request.rate_limit_pps, Some(100));
                assert!(request.rate_explicit);
                assert_eq!(request.gpu_rate_pps, Some(100));
                assert!(request.gpu_rate_explicit);
            }
            other => panic!("unexpected action: {other:?}"),
        }
    }

    #[test]
    fn gpu_control_flags_parse_into_request() {
        let cli = Cli::parse_from([
            "nprobe-rs",
            "scan",
            "10.0.0.5",
            "--gpu-burst",
            "3",
            "--gpu-timestamp",
            "--gpu-schedule-random",
        ]);
        let action = cli.into_action().expect("cli action should parse");
        match action {
            CliAction::Scan(request) => {
                assert_eq!(request.gpu_burst_size, Some(3));
                assert!(request.gpu_timestamp);
                assert!(request.gpu_schedule_random);
            }
            other => panic!("unexpected action: {other:?}"),
        }
    }

    #[test]
    fn assess_hardware_flag_parses_into_request() {
        let cli = Cli::parse_from(["nprobe-rs", "scan", "10.0.0.5", "--assess-hardware"]);
        let action = cli.into_action().expect("cli action should parse");
        match action {
            CliAction::Scan(request) => {
                assert!(request.assess_hardware);
            }
            other => panic!("unexpected action: {other:?}"),
        }
    }

    #[test]
    fn override_mode_flag_parses_into_request() {
        let cli = Cli::parse_from(["nprobe-rs", "scan", "10.0.0.5", "--override-mode"]);
        let action = cli.into_action().expect("cli action should parse");
        match action {
            CliAction::Scan(request) => {
                assert!(request.override_mode);
            }
            other => panic!("unexpected action: {other:?}"),
        }
    }

    #[test]
    fn detect_cataloged_scan_gate_blocks_risky_idle_scan_flag() {
        let err = detect_cataloged_scan_gate(&["-sI".to_string(), "192.0.2.10".to_string()])
            .expect("gate should reject idle scan");
        let rendered = err.user_message();
        assert!(rendered.contains("Idle/Zombie Scan"));
        assert!(rendered.contains("stealth, spoofing, or firewall-evasion"));
        assert!(rendered.contains("--scan-type zombie"));
    }

    #[test]
    fn detect_cataloged_scan_gate_allows_live_ping_scan_flag() {
        let err = detect_cataloged_scan_gate(&["-sn".to_string(), "192.0.2.10".to_string()]);
        assert!(err.is_none());
    }

    #[test]
    fn sessions_list_accepts_profile_and_time_filters() {
        let cli = Cli::parse_from([
            "nprobe-rs",
            "sessions",
            "--limit",
            "5",
            "--profile",
            "balanced",
            "--updated-after",
            "2026-03-01T00:00:00Z",
        ]);
        let action = cli.into_action().expect("cli action should parse");
        match action {
            CliAction::Sessions(SessionCommand::List { limit, filters }) => {
                assert_eq!(limit, 5);
                assert_eq!(filters.profile_filter.as_deref(), Some("balanced"));
                assert!(filters.updated_after.is_some());
                assert!(filters.updated_before.is_none());
            }
            other => panic!("unexpected action: {other:?}"),
        }
    }

    #[test]
    fn integrity_status_renderer_is_operator_readable() {
        let rendered = render_integrity_status(&IntegrityStatus {
            state: "trusted".to_string(),
            manifest_sha256: "abc123".to_string(),
            executable_sha256: "def456".to_string(),
            files_checked: 4,
            source_tree_verified: true,
            baseline_present: true,
            executable_path: "/tmp/nprobe-rs".to_string(),
            notes: vec!["baseline matches".to_string()],
        });
        assert!(rendered.contains("state=trusted"));
        assert!(rendered.contains("baseline matches"));
    }
}

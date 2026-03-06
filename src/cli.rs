// Flow sketch: input -> core processing -> output model
// Pseudo-block:
//   read input -> process safely -> return deterministic output
// the CLI is a polite bouncer: clear args only.

use std::collections::BTreeSet;
use std::ffi::OsString;
use std::path::{Path, PathBuf};

use chrono::Utc;
use clap::{Args, Parser, Subcommand, ValueEnum};

use crate::error::{NProbeError, NProbeResult};
use crate::models::{ReportFormat, ScanProfile, ScanRequest};

#[derive(Debug, Clone, Copy, ValueEnum)]
enum FileType {
    Txt,
    Json,
    Html,
    Csv,
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
    about = "NProbe-RS: Nmap-inspired scanner in safe, explainable Rust",
    override_usage = "nprobe-rs <target> [OPTIONS]\n       nprobe-rs scan <target> [OPTIONS]",
    after_help = "Nmap-style shortcuts supported: -sU, -sS, -A, -T0..-T5, -p-",
    arg_required_else_help = true
)]
pub struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Debug, Subcommand)]
enum Commands {
    Scan(ScanArgs),
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
        short = 'U',
        long = "udp",
        visible_alias = "sU",
        help = "Add UDP probing (Nmap: -sU)"
    )]
    udp: bool,

    #[arg(
        short = 'S',
        long = "syn",
        visible_alias = "sS",
        help = "Use privileged TCP probing (Nmap: -sS). Will auto-prompt for sudo/su if required"
    )]
    syn: bool,

    #[arg(
        long = "arp",
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
        short = 'N',
        long = "no-service-detect",
        help = "Disable banner/service detection"
    )]
    no_service_detect: bool,

    #[arg(
        long = "service-detect",
        visible_alias = "sV",
        help = "Enable banner/service detection (Nmap: -sV)"
    )]
    service_detect: bool,

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
        visible_alias = "allow-public",
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
        long = "rate-pps",
        help = "Probe dispatch rate target (packets per second)"
    )]
    rate_limit_pps: Option<u32>,

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

impl Cli {
    pub fn parse_normalized() -> Self {
        let args: Vec<OsString> = std::env::args_os().collect();
        Self::parse_from(normalize_args(args))
    }

    pub fn into_request(self) -> NProbeResult<ScanRequest> {
        match self.command {
            Commands::Scan(scan) => scan.into_request(),
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
        "Usage:\n  nprobe-rs <target> [options]\n\nCommon options:\n  -p, --ports <list|range>   Select ports (example: -p 22,80,443)\n      --all-ports            Scan ports 1-65535 (Nmap: -p-)\n  -U, --udp                  Enable UDP probes (Nmap: -sU)\n  -S, --syn                  Enable privileged TCP probes (Nmap: -sS)\n      --arp                  Enable ARP neighbor discovery (local IPv4)\n  -A, --aggressive           Aggressive mode (Nmap: -A)\n  -w, --timeout-ms <ms>      Probe timeout in milliseconds\n      --rate-pps <num>       Dispatch rate target in packets per second\n      --burst-size <num>     Token-bucket burst limit\n      --max-retries <num>    Adaptive retries per probe (0..20)\n      --total-shards <num>   Total shard count for distributed scans\n      --shard-index <num>    Current shard index (requires total-shards)\n      --scan-seed <num>      Deterministic port shuffle seed\n      --resume               Resume from shard checkpoint\n      --fresh-scan           Ignore/reset shard checkpoint for this run\n  -r, --reverse-dns          Enable reverse DNS lookups\n  -n, --no-dns               Disable reverse DNS lookups\n  -e, --explain              Add concise per-port rationale in output\n  -v, --verbose              Show full output sections\n  -f, --file-type <type>     Export format: txt|json|html|csv\n  -o, --output <name>        Output filename\n  -L, --location <dir>       Output directory\n\nNmap-style shortcuts accepted:\n  -sU  -sS  -A  -T0..-T5  -p-\n\nFlag docs mode:\n  nprobe-rs --flag-help --scan\n  nprobe-rs --flag-help -sU\n  nprobe-rs --explain --scan   (legacy alias)\n\nCompatibility:\n  nprobe-rs scan <target> [options] still works.".to_string(),
    )
}

fn render_flag_explain(raw_query: Option<&str>) -> String {
    let key = raw_query
        .map(|value| value.trim().trim_start_matches('-').to_ascii_lowercase())
        .unwrap_or_else(|| "scan".to_string());

    let body = match key.as_str() {
        "scan" => {
            "Default scan mode. Use `nprobe-rs <target>` without the `scan` subcommand."
        }
        "p" | "ports" => "Select ports or ranges. Example: `-p 22,80,443` or `-p 1-1024`.",
        "s" | "su" | "udp" => "Enable UDP probing (`-sU` or `--udp`).",
        "ss" | "syn" => {
            "Enable privileged TCP probing (`-sS` or `--syn`). If needed, the tool re-runs with sudo/su."
        }
        "arp" => "Enable ARP neighbor discovery for local IPv4 targets (`--arp`).",
        "a" | "aggressive" => {
            "Aggressive mode (`-A`): enables deeper detection and root-required probe paths."
        }
        "t" | "timing" => {
            "Timing profile (`-T0`..`-T5`). Mapped to internal profiles from stealth to aggressive."
        }
        "p-" | "all-ports" => "Scan all TCP ports 1-65535 (`-p-` or `--all-ports`).",
        "ratepps" | "rate-pps" => {
            "Set probe dispatch rate target in packets/sec (`--rate-pps`). Lower values reduce scan pressure."
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
            "Unknown flag. Try one of: --scan, -p, -sU, -sS, -A, -T4, -p-, -v, --explain. Tip: use --flag-help <flag>."
        }
    };

    format!(
        "Flag help for `{}`\n\n{}\n\nExamples:\n  nprobe-rs 192.168.1.10\n  nprobe-rs -sU -p 53,161 192.168.1.10\n  nprobe-rs -A -T4 10.0.0.5\n  nprobe-rs --explain --scan",
        raw_query.unwrap_or("--scan"),
        body
    )
}

impl ScanArgs {
    fn into_request(self) -> NProbeResult<ScanRequest> {
        if matches!(self.rate_limit_pps, Some(0)) {
            return Err(NProbeError::Cli(
                "--rate-pps must be greater than 0".to_string(),
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

        let (ports, top_ports) = if self.all_ports {
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
        let effective_aggressive_root = self.aggressive || self.aggressive_root || root_only;
        let effective_privileged_probes =
            self.syn || self.privileged_probes || self.aggressive || root_only;

        let profile_explicit = self.profile.is_some() || self.root_only || self.aggressive;
        let profile = if root_only {
            ScanProfile::RootOnly
        } else if (self.aggressive || self.aggressive_root) && self.profile.is_none() {
            ScanProfile::Aggressive
        } else {
            self.profile.unwrap_or(ScanProfile::Balanced)
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
        let mut rate_limit_pps = self.rate_limit_pps;
        let mut burst_size = self.burst_size;
        let mut max_retries = self.max_retries;
        let total_shards = self.total_shards;
        let shard_index = self.shard_index.or_else(|| total_shards.map(|_| 0));
        let scan_seed = self.scan_seed;
        let resume_from_checkpoint = self.resume || !self.fresh_scan;
        let fresh_scan = self.fresh_scan;
        let mut top_ports = top_ports;

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

        Ok(ScanRequest {
            target: self.target,
            ports,
            top_ports,
            include_udp: self.udp || effective_aggressive_root,
            reverse_dns: self.reverse_dns && !self.no_dns,
            service_detection: self.service_detect
                || effective_aggressive_root
                || !self.no_service_detect,
            explain: self.explain,
            verbose: self.verbose,
            report_format,
            profile,
            profile_explicit,
            root_only,
            aggressive_root: effective_aggressive_root,
            privileged_probes: effective_privileged_probes,
            arp_discovery: self.arp,
            lab_mode: self.lab_mode,
            allow_external: self.allow_external,
            strict_safety: self.strict_safety,
            output_path,
            lua_script: self.lua_script,
            timeout_ms,
            concurrency,
            delay_ms,
            rate_limit_pps,
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
            "-sU" => mapped.push("--udp".into()),
            "-sS" => mapped.push("--syn".into()),
            "-A" => mapped.push("--aggressive".into()),
            "-p-" => mapped.push("--all-ports".into()),
            "-sV" => mapped.push("--service-detect".into()),
            "-T" => {
                if idx + 1 < args.len() {
                    let level = args[idx + 1].to_string_lossy().to_string();
                    if let Some(profile) = map_timing_to_profile(level.as_str()) {
                        mapped.push("--profile".into());
                        mapped.push(profile.into());
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
                    if let Some(profile) = map_timing_to_profile(&token[2..]) {
                        mapped.push("--profile".into());
                        mapped.push(profile.into());
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
        "scan" | "-h" | "--help" | "-V" | "--version"
    )
}

fn map_timing_to_profile(level: &str) -> Option<&'static str> {
    match level.trim() {
        "0" | "1" => Some("stealth"),
        "2" | "3" => Some("balanced"),
        "4" => Some("turbo"),
        "5" => Some("aggressive"),
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

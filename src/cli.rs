use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use chrono::Utc;
use clap::{Args, Parser, Subcommand, ValueEnum};

use crate::error::{NetProbeError, NetProbeResult};
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
    name = "recon",
    version,
    about = "NetProbe-RS: Nmap-inspired scanner in safe, explainable Rust",
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

    #[arg(long = "all-ports", help = "Scan ports 1-65535")]
    all_ports: bool,

    #[arg(long = "top-ports", help = "Scan N most common TCP ports")]
    top_ports: Option<usize>,

    #[arg(long = "udp", help = "Add UDP probing")]
    udp: bool,

    #[arg(long = "reverse-dns", help = "Enable PTR reverse DNS lookups")]
    reverse_dns: bool,

    #[arg(long = "no-service-detect", help = "Disable banner/service detection")]
    no_service_detect: bool,

    #[arg(long = "explain", help = "Show explain-mode per finding")]
    explain: bool,

    #[arg(
        long = "file-type",
        value_enum,
        help = "Report format for file export: txt, csv, html, json"
    )]
    file_type: Option<FileType>,

    #[arg(long = "report", value_enum, hide = true)]
    report_legacy: Option<ReportFormat>,

    #[arg(long = "profile", value_enum)]
    profile: Option<ScanProfile>,

    #[arg(
        long = "root-only",
        help = "Termux/mobile root preset: enables privileged probes with mobile-safe defaults"
    )]
    root_only: bool,

    #[arg(
        long = "aggressive-root",
        visible_alias = "aggresive-root",
        help = "Enable root-required aggressive scan extensions"
    )]
    aggressive_root: bool,

    #[arg(
        long = "privileged-probes",
        help = "Use privileged source-port probing (requires root/sudo)"
    )]
    privileged_probes: bool,

    #[arg(long = "lab-mode", help = "Only allow local/private targets")]
    lab_mode: bool,

    #[arg(
        long = "allow-external",
        help = "Acknowledge and allow scanning public IP targets"
    )]
    allow_external: bool,

    #[arg(
        long = "strict-safety",
        help = "Block scan instead of warning when external target safety checks fail"
    )]
    strict_safety: bool,

    #[arg(long = "output", help = "Output file name (example: scan-report)")]
    output: Option<String>,

    #[arg(
        long = "location",
        help = "Directory where output file should be stored"
    )]
    location: Option<PathBuf>,

    #[arg(long = "lua-script", help = "Lua hook file path")]
    lua_script: Option<PathBuf>,

    #[arg(long = "timeout-ms", help = "Probe timeout in ms")]
    timeout_ms: Option<u64>,

    #[arg(long = "concurrency", help = "Max concurrent probes")]
    concurrency: Option<usize>,

    #[arg(long = "delay-ms", help = "Delay between probe dispatches in ms")]
    delay_ms: Option<u64>,
}

impl Cli {
    pub fn into_request(self) -> NetProbeResult<ScanRequest> {
        match self.command {
            Commands::Scan(scan) => scan.into_request(),
        }
    }
}

impl ScanArgs {
    fn into_request(self) -> NetProbeResult<ScanRequest> {
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
            return Err(NetProbeError::Cli(
                "--root-only conflicts with --profile values other than root-only".to_string(),
            ));
        }

        let root_only = self.root_only || matches!(self.profile, Some(ScanProfile::RootOnly));
        let effective_aggressive_root = self.aggressive_root || root_only;
        let effective_privileged_probes = self.privileged_probes || root_only;

        let profile_explicit = self.profile.is_some() || self.root_only;
        let profile = if root_only {
            ScanProfile::RootOnly
        } else if self.aggressive_root && self.profile.is_none() {
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
        }

        Ok(ScanRequest {
            target: self.target,
            ports,
            top_ports,
            include_udp: self.udp || effective_aggressive_root,
            reverse_dns: self.reverse_dns,
            service_detection: effective_aggressive_root || !self.no_service_detect,
            explain: self.explain,
            report_format,
            profile,
            profile_explicit,
            root_only,
            aggressive_root: effective_aggressive_root,
            privileged_probes: effective_privileged_probes,
            lab_mode: self.lab_mode,
            allow_external: self.allow_external,
            strict_safety: self.strict_safety,
            output_path,
            lua_script: self.lua_script,
            timeout_ms,
            concurrency,
            delay_ms,
        })
    }
}

fn build_output_path(
    output_name: Option<&str>,
    location: Option<&Path>,
    format: ReportFormat,
    output_requested: bool,
    force_extension: bool,
) -> NetProbeResult<Option<PathBuf>> {
    if !output_requested {
        return Ok(None);
    }

    let base_dir = if let Some(path) = location {
        path.to_path_buf()
    } else {
        std::env::current_dir().map_err(|err| {
            NetProbeError::Cli(format!("failed to read current working directory: {err}"))
        })?
    };

    let file_name = match output_name {
        Some(value) if value.trim().is_empty() => {
            return Err(NetProbeError::Cli(
                "--output cannot be empty or whitespace".to_string(),
            ));
        }
        Some(value) => value.to_string(),
        None => {
            let stamp = Utc::now().format("%Y%m%d-%H%M%S");
            format!("netprobe-report-{stamp}.{}", format.extension())
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

fn parse_ports(raw: &str) -> NetProbeResult<Vec<u16>> {
    let mut ports = BTreeSet::new();
    for token in raw.split(',').map(str::trim).filter(|t| !t.is_empty()) {
        if let Some((start, end)) = token.split_once('-') {
            let start_port = parse_port(start)?;
            let end_port = parse_port(end)?;
            if start_port > end_port {
                return Err(NetProbeError::Cli(format!(
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
        return Err(NetProbeError::Cli("no valid ports provided".to_string()));
    }

    Ok(ports.into_iter().collect())
}

fn parse_port(raw: &str) -> NetProbeResult<u16> {
    raw.parse::<u16>()
        .map_err(|_| NetProbeError::Cli(format!("invalid port '{raw}'")))
        .and_then(|port| {
            if port == 0 {
                Err(NetProbeError::Cli("port 0 is not scannable".to_string()))
            } else {
                Ok(port)
            }
        })
}

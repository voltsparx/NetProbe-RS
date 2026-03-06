// Flow sketch: input -> core processing -> output model
// Pseudo-block:
//   read input -> process safely -> return deterministic output

use std::fmt;
use std::path::PathBuf;
use std::time::Duration;

use chrono::{DateTime, Utc};
use clap::ValueEnum;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, Serialize, Deserialize, ValueEnum)]
#[serde(rename_all = "lowercase")]
pub enum ReportFormat {
    Cli,
    Txt,
    Json,
    Html,
    Csv,
}

impl ReportFormat {
    pub fn extension(self) -> &'static str {
        match self {
            ReportFormat::Cli => "txt",
            ReportFormat::Txt => "txt",
            ReportFormat::Json => "json",
            ReportFormat::Html => "html",
            ReportFormat::Csv => "csv",
        }
    }

    pub fn from_extension(raw: &str) -> Option<Self> {
        match raw.trim_start_matches('.').to_ascii_lowercase().as_str() {
            "txt" | "log" => Some(ReportFormat::Txt),
            "json" => Some(ReportFormat::Json),
            "html" | "htm" => Some(ReportFormat::Html),
            "csv" => Some(ReportFormat::Csv),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, ValueEnum)]
#[serde(rename_all = "lowercase")]
pub enum ScanProfile {
    Stealth,
    Balanced,
    Turbo,
    Aggressive,
    RootOnly,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct ProfileDefaults {
    pub concurrency: usize,
    pub timeout_ms: u64,
    pub delay_ms: u64,
}

impl ScanProfile {
    pub fn defaults(self) -> ProfileDefaults {
        match self {
            ScanProfile::Stealth => ProfileDefaults {
                concurrency: 32,
                timeout_ms: 3000,
                delay_ms: 30,
            },
            ScanProfile::Balanced => ProfileDefaults {
                concurrency: 128,
                timeout_ms: 1200,
                delay_ms: 5,
            },
            ScanProfile::Turbo => ProfileDefaults {
                concurrency: 512,
                timeout_ms: 700,
                delay_ms: 0,
            },
            ScanProfile::Aggressive => ProfileDefaults {
                concurrency: 768,
                timeout_ms: 550,
                delay_ms: 0,
            },
            ScanProfile::RootOnly => ProfileDefaults {
                concurrency: 72,
                timeout_ms: 1800,
                delay_ms: 8,
            },
        }
    }
}

#[derive(Debug, Clone)]
pub struct RuntimeSettings {
    pub concurrency: usize,
    pub timeout: Duration,
    pub delay: Duration,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanRequest {
    pub target: String,
    pub session_id: Option<String>,
    pub ports: Vec<u16>,
    pub top_ports: Option<usize>,
    pub include_udp: bool,
    pub reverse_dns: bool,
    pub service_detection: bool,
    pub explain: bool,
    pub verbose: bool,
    pub report_format: ReportFormat,
    pub profile: ScanProfile,
    pub profile_explicit: bool,
    pub root_only: bool,
    pub aggressive_root: bool,
    pub privileged_probes: bool,
    pub arp_discovery: bool,
    pub lab_mode: bool,
    pub allow_external: bool,
    pub strict_safety: bool,
    pub output_path: Option<PathBuf>,
    pub lua_script: Option<PathBuf>,
    pub timeout_ms: Option<u64>,
    pub concurrency: Option<usize>,
    pub delay_ms: Option<u64>,
    pub rate_limit_pps: Option<u32>,
    pub burst_size: Option<usize>,
    pub max_retries: Option<u8>,
    pub total_shards: Option<u16>,
    pub shard_index: Option<u16>,
    pub scan_seed: Option<u64>,
    pub resume_from_checkpoint: bool,
    pub fresh_scan: bool,
}

impl ScanRequest {
    pub fn runtime_settings(&self) -> RuntimeSettings {
        let defaults = self.profile.defaults();
        RuntimeSettings {
            concurrency: self
                .concurrency
                .unwrap_or(defaults.concurrency)
                .clamp(1, 4096),
            timeout: Duration::from_millis(self.timeout_ms.unwrap_or(defaults.timeout_ms)),
            delay: Duration::from_millis(self.delay_ms.unwrap_or(defaults.delay_ms)),
        }
    }

    pub fn requires_root(&self) -> bool {
        self.aggressive_root || self.privileged_probes
    }

    pub fn effective_privileged_probes(&self) -> bool {
        self.privileged_probes || self.aggressive_root
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PortState {
    Open,
    Closed,
    Filtered,
    OpenOrFiltered,
}

impl PortState {
    pub fn as_str(&self) -> &'static str {
        match self {
            PortState::Open => "open",
            PortState::Closed => "closed",
            PortState::Filtered => "filtered",
            PortState::OpenOrFiltered => "open|filtered",
        }
    }
}

impl fmt::Display for PortState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PortFinding {
    pub port: u16,
    pub protocol: String,
    pub state: PortState,
    pub service: Option<String>,
    pub banner: Option<String>,
    pub reason: String,
    pub matched_by: Option<String>,
    pub confidence: Option<f32>,
    pub educational_note: Option<String>,
    pub latency_ms: Option<u128>,
    pub explanation: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HostResult {
    pub target: String,
    pub ip: String,
    pub reverse_dns: Option<String>,
    pub observed_mac: Option<String>,
    pub device_class: Option<String>,
    pub device_vendor: Option<String>,
    #[serde(default)]
    pub safety_actions: Vec<String>,
    pub warnings: Vec<String>,
    pub ports: Vec<PortFinding>,
    pub risk_score: u8,
    #[serde(rename = "insights", alias = "ai_findings")]
    pub insights: Vec<String>,
    pub defensive_advice: Vec<String>,
    pub learning_notes: Vec<String>,
    pub lua_findings: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EngineStats {
    pub async_engine_tasks: usize,
    pub thread_pool_tasks: usize,
    pub parallel_tasks: usize,
    pub lua_hooks_ran: bool,
    pub framework_role: String,
    pub teaching_mode: bool,
    pub execution_mode: String,
    pub scan_persona: String,
    pub configured_rate_pps: u32,
    pub configured_burst_size: usize,
    pub max_retries: u8,
    pub host_parallelism: usize,
    pub total_shards: u16,
    pub shard_index: u16,
    pub shard_dimension: String,
    pub scan_seed: Option<u64>,
    pub checkpoint_enabled: bool,
    pub checkpoint_unit_label: String,
    pub checkpoint_planned_units: usize,
    pub checkpoint_completed_units: usize,
    pub checkpoint_resumed_units: usize,
    pub safety_envelope_active: bool,
    pub public_target_policy_applied: bool,
    pub profiled_hosts: usize,
    pub fragile_hosts: usize,
    pub safety_ports_suppressed: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanRequestSummary {
    pub target: String,
    pub port_count: usize,
    pub include_udp: bool,
    pub explain: bool,
    pub verbose: bool,
    pub profile: ScanProfile,
    pub root_only: bool,
    pub aggressive_root: bool,
    pub privileged_probes: bool,
    pub arp_discovery: bool,
    pub report_format: ReportFormat,
    pub lab_mode: bool,
    pub total_shards: Option<u16>,
    pub shard_index: Option<u16>,
    pub scan_seed: Option<u64>,
    pub resume_from_checkpoint: bool,
    pub fresh_scan: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanMetadata {
    pub session_id: Option<String>,
    pub started_at: DateTime<Utc>,
    pub finished_at: DateTime<Utc>,
    pub duration_ms: i64,
    pub engine_stats: EngineStats,
    pub knowledge: KnowledgeStats,
    pub platform: PlatformStats,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KnowledgeStats {
    pub services_loaded: usize,
    pub ranked_tcp_ports: usize,
    pub probe_payloads_loaded: usize,
    pub fingerprint_rules_loaded: usize,
    pub fingerprint_rules_compiled: usize,
    pub fingerprint_rules_skipped: usize,
    pub nse_scripts_seen: usize,
    pub nselib_modules_seen: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlatformStats {
    pub capability_total: usize,
    pub implemented: usize,
    pub partial: usize,
    pub planned: usize,
    pub intentionally_excluded: usize,
    pub tool_families: Vec<String>,
    pub capability_domains: Vec<String>,
    pub guardrail_statement: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanReport {
    pub metadata: ScanMetadata,
    pub request: ScanRequestSummary,
    pub hosts: Vec<HostResult>,
}

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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ValueEnum)]
#[serde(rename_all = "lowercase")]
pub enum ScanProfile {
    Stealth,
    Phantom,
    Sar,
    Kis,
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
    pub fn as_str(self) -> &'static str {
        match self {
            ScanProfile::Stealth => "stealth",
            ScanProfile::Phantom => "phantom",
            ScanProfile::Sar => "sar",
            ScanProfile::Kis => "kis",
            ScanProfile::Balanced => "balanced",
            ScanProfile::Turbo => "turbo",
            ScanProfile::Aggressive => "aggressive",
            ScanProfile::RootOnly => "root-only",
        }
    }

    pub fn is_low_impact_concept(self) -> bool {
        matches!(
            self,
            ScanProfile::Phantom | ScanProfile::Sar | ScanProfile::Kis
        )
    }

    pub fn scan_family(self) -> &'static str {
        if self.is_low_impact_concept() {
            "tbns"
        } else {
            "core"
        }
    }

    pub fn tbns_chapter(self) -> Option<&'static str> {
        match self {
            ScanProfile::Phantom => Some("device-check"),
            ScanProfile::Sar => Some("logic"),
            ScanProfile::Kis => Some("identity"),
            _ => None,
        }
    }

    pub fn concept_port_budget(self) -> Option<usize> {
        match self {
            ScanProfile::Phantom => Some(24),
            ScanProfile::Sar => Some(32),
            ScanProfile::Kis => Some(16),
            _ => None,
        }
    }

    pub fn defaults(self) -> ProfileDefaults {
        match self {
            ScanProfile::Stealth => ProfileDefaults {
                concurrency: 32,
                timeout_ms: 3000,
                delay_ms: 30,
            },
            ScanProfile::Phantom => ProfileDefaults {
                concurrency: 8,
                timeout_ms: 2600,
                delay_ms: 120,
            },
            ScanProfile::Sar => ProfileDefaults {
                concurrency: 10,
                timeout_ms: 2400,
                delay_ms: 80,
            },
            ScanProfile::Kis => ProfileDefaults {
                concurrency: 6,
                timeout_ms: 3200,
                delay_ms: 150,
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
    #[serde(default)]
    pub service_identity: Option<ServiceIdentity>,
    pub banner: Option<String>,
    pub reason: String,
    pub matched_by: Option<String>,
    pub confidence: Option<f32>,
    #[serde(default)]
    pub vulnerability_hints: Vec<String>,
    pub educational_note: Option<String>,
    pub latency_ms: Option<u128>,
    pub explanation: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ServiceIdentity {
    pub product: Option<String>,
    pub version: Option<String>,
    pub info: Option<String>,
    pub hostname: Option<String>,
    pub operating_system: Option<String>,
    pub device_type: Option<String>,
    #[serde(default)]
    pub cpes: Vec<String>,
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
    pub phantom_device_check: Option<PhantomDeviceCheckSummary>,
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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PhantomDeviceCheckSummary {
    pub stage: String,
    pub responsive_ports: Option<usize>,
    pub sampled_ports: Option<usize>,
    pub timeout_ports: Option<usize>,
    pub avg_latency_ms: Option<u64>,
    pub payload_budget: Option<usize>,
    pub passive_follow_up: bool,
}

impl HostResult {
    pub fn phantom_device_check_summary(&self) -> Option<PhantomDeviceCheckSummary> {
        if let Some(summary) = self.phantom_device_check.clone() {
            return Some(summary);
        }

        parse_legacy_phantom_device_check(self)
    }

    pub fn merge_phantom_device_check(&mut self, incoming: Option<PhantomDeviceCheckSummary>) {
        let Some(incoming) = incoming else {
            return;
        };

        self.phantom_device_check = Some(match self.phantom_device_check.take() {
            Some(existing) => merge_phantom_device_check_summaries(existing, incoming),
            None => incoming,
        });
    }
}

fn parse_legacy_phantom_device_check(host: &HostResult) -> Option<PhantomDeviceCheckSummary> {
    let stage = host
        .safety_actions
        .iter()
        .find_map(|action| action.strip_prefix("phantom-preflight:stage="))
        .map(str::to_string)?;

    let mut summary = PhantomDeviceCheckSummary {
        stage,
        responsive_ports: None,
        sampled_ports: None,
        timeout_ports: None,
        avg_latency_ms: None,
        payload_budget: None,
        passive_follow_up: host
            .safety_actions
            .iter()
            .any(|action| action == "phantom-preflight:passive-follow-up"),
    };

    if let Some(payload_action) = host
        .safety_actions
        .iter()
        .find(|action| action.starts_with("phantom-preflight:payload-budget:"))
    {
        summary.payload_budget = parse_payload_budget_action(payload_action);
    }

    if let Some(warning) = host
        .warnings
        .iter()
        .find(|warning| warning.starts_with("phantom preflight stage="))
    {
        populate_device_check_from_warning(&mut summary, warning);
    }

    Some(summary)
}

fn merge_phantom_device_check_summaries(
    existing: PhantomDeviceCheckSummary,
    incoming: PhantomDeviceCheckSummary,
) -> PhantomDeviceCheckSummary {
    PhantomDeviceCheckSummary {
        stage: stricter_device_check_stage(&existing.stage, &incoming.stage).to_string(),
        responsive_ports: max_optional_usize(existing.responsive_ports, incoming.responsive_ports),
        sampled_ports: max_optional_usize(existing.sampled_ports, incoming.sampled_ports),
        timeout_ports: max_optional_usize(existing.timeout_ports, incoming.timeout_ports),
        avg_latency_ms: max_optional_u64(existing.avg_latency_ms, incoming.avg_latency_ms),
        payload_budget: min_optional_usize(existing.payload_budget, incoming.payload_budget),
        passive_follow_up: existing.passive_follow_up || incoming.passive_follow_up,
    }
}

fn stricter_device_check_stage<'a>(left: &'a str, right: &'a str) -> &'a str {
    if device_check_stage_rank(left) <= device_check_stage_rank(right) {
        left
    } else {
        right
    }
}

fn device_check_stage_rank(stage: &str) -> u8 {
    match stage {
        "soft" => 0,
        "guarded" => 1,
        "balanced" => 2,
        _ => 3,
    }
}

fn max_optional_usize(left: Option<usize>, right: Option<usize>) -> Option<usize> {
    match (left, right) {
        (Some(a), Some(b)) => Some(a.max(b)),
        (Some(a), None) => Some(a),
        (None, Some(b)) => Some(b),
        (None, None) => None,
    }
}

fn min_optional_usize(left: Option<usize>, right: Option<usize>) -> Option<usize> {
    match (left, right) {
        (Some(a), Some(b)) => Some(a.min(b)),
        (Some(a), None) => Some(a),
        (None, Some(b)) => Some(b),
        (None, None) => None,
    }
}

fn max_optional_u64(left: Option<u64>, right: Option<u64>) -> Option<u64> {
    match (left, right) {
        (Some(a), Some(b)) => Some(a.max(b)),
        (Some(a), None) => Some(a),
        (None, Some(b)) => Some(b),
        (None, None) => None,
    }
}

fn parse_payload_budget_action(action: &str) -> Option<usize> {
    let payloads = action.strip_prefix("phantom-preflight:payload-budget:")?;
    if let Some((_, after)) = payloads.split_once("->") {
        return after.parse().ok();
    }
    payloads.parse().ok()
}

fn populate_device_check_from_warning(summary: &mut PhantomDeviceCheckSummary, warning: &str) {
    for token in warning.split_whitespace() {
        if let Some(value) = token.strip_prefix("responsive=") {
            if let Some((responsive, sampled)) = value.split_once('/') {
                summary.responsive_ports = responsive.parse().ok();
                summary.sampled_ports = sampled.parse().ok();
            }
        } else if let Some(value) = token.strip_prefix("timeout=") {
            summary.timeout_ports = value.parse().ok();
        } else if let Some(value) = token.strip_prefix("avg-latency=") {
            let cleaned = value.trim_end_matches("ms");
            if cleaned != "n/a" {
                summary.avg_latency_ms = cleaned.parse().ok();
            }
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EngineStats {
    pub async_engine_tasks: usize,
    pub thread_pool_tasks: usize,
    pub parallel_tasks: usize,
    pub lua_hooks_ran: bool,
    pub integrity_checked: bool,
    pub integrity_state: String,
    pub integrity_manifest: String,
    pub resource_policy: String,
    pub scan_bundle: String,
    pub scan_bundle_stages: Vec<String>,
    pub framework_role: String,
    pub scan_family: String,
    pub safety_model: String,
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

#[cfg(test)]
mod tests {
    use super::{HostResult, ScanProfile};

    #[test]
    fn tbns_profiles_report_family_and_chapter() {
        assert_eq!(ScanProfile::Phantom.scan_family(), "tbns");
        assert_eq!(ScanProfile::Kis.scan_family(), "tbns");
        assert_eq!(ScanProfile::Sar.scan_family(), "tbns");
        assert_eq!(ScanProfile::Phantom.tbns_chapter(), Some("device-check"));
        assert_eq!(ScanProfile::Kis.tbns_chapter(), Some("identity"));
        assert_eq!(ScanProfile::Sar.tbns_chapter(), Some("logic"));
        assert_eq!(ScanProfile::Balanced.scan_family(), "core");
        assert_eq!(ScanProfile::Balanced.tbns_chapter(), None);
    }

    #[test]
    fn phantom_device_check_summary_extracts_stage_and_budget() {
        let host = HostResult {
            target: "example".to_string(),
            ip: "10.0.0.1".to_string(),
            reverse_dns: None,
            observed_mac: None,
            device_class: None,
            device_vendor: None,
            phantom_device_check: None,
            safety_actions: vec![
                "phantom-preflight:stage=guarded".to_string(),
                "phantom-preflight:payload-budget:4->1".to_string(),
                "phantom-preflight:passive-follow-up".to_string(),
            ],
            warnings: vec![
                "phantom preflight stage=guarded responsive=1/3 timeout=2 avg-latency=91ms"
                    .to_string(),
            ],
            ports: Vec::new(),
            risk_score: 0,
            insights: Vec::new(),
            defensive_advice: Vec::new(),
            learning_notes: Vec::new(),
            lua_findings: Vec::new(),
        };

        let summary = host
            .phantom_device_check_summary()
            .expect("phantom summary should exist");
        assert_eq!(summary.stage, "guarded");
        assert_eq!(summary.responsive_ports, Some(1));
        assert_eq!(summary.sampled_ports, Some(3));
        assert_eq!(summary.timeout_ports, Some(2));
        assert_eq!(summary.avg_latency_ms, Some(91));
        assert_eq!(summary.payload_budget, Some(1));
        assert!(summary.passive_follow_up);
    }
}

// Flow sketch: input -> core processing -> output model
// Pseudo-block:
//   read input -> process safely -> return deterministic output

use std::collections::BTreeMap;
use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process;

use chrono::Utc;
use serde::{Deserialize, Serialize};

use crate::error::{NProbeError, NProbeResult};
use crate::models::{ScanProfile, ScanReport, ScanRequest};
use crate::platform::sql_persistence;
use crate::reporter::actionable::ActionableSeverity;

const CONFIG_DIR_NAME: &str = ".nprobe-rs-config";
const CONFIG_FILE_NAME: &str = "config.ini";
const CHECKPOINT_DIR_NAME: &str = "checkpoints";
const SESSION_DIR_NAME: &str = "sessions";
const SHARD_CHECKPOINT_VERSION: u8 = 1;
const SCAN_SESSION_VERSION: u8 = 1;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShardCheckpointState {
    pub version: u8,
    pub signature: String,
    pub target: String,
    pub total_shards: u16,
    pub shard_index: u16,
    pub shard_dimension: String,
    #[serde(default = "default_checkpoint_unit_kind")]
    pub unit_kind: String,
    #[serde(default, alias = "planned_hosts")]
    pub planned_units: Vec<String>,
    #[serde(default, alias = "completed_hosts")]
    pub completed_units: Vec<String>,
    pub port_count: usize,
    pub scan_seed: Option<u64>,
    pub updated_at: String,
}

#[derive(Debug, Clone)]
pub struct ShardCheckpointArgs {
    pub signature: String,
    pub target: String,
    pub total_shards: u16,
    pub shard_index: u16,
    pub shard_dimension: String,
    pub unit_kind: String,
    pub planned_units: Vec<String>,
    pub completed_units: Vec<String>,
    pub port_count: usize,
    pub scan_seed: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ScanSessionStatus {
    Running,
    Completed,
    Interrupted,
    Failed,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanSessionRecord {
    pub version: u8,
    pub session_id: String,
    pub status: ScanSessionStatus,
    pub target: String,
    pub profile: String,
    pub report_format: String,
    pub started_at: String,
    pub updated_at: String,
    pub finished_at: Option<String>,
    pub scan_seed: Option<u64>,
    pub total_shards: Option<u16>,
    pub shard_index: Option<u16>,
    pub rate_limit_pps: Option<u32>,
    pub burst_size: Option<usize>,
    pub max_retries: Option<u8>,
    pub output_path: Option<String>,
    pub host_count: Option<usize>,
    pub responded_hosts: Option<usize>,
    pub duration_ms: Option<i64>,
    #[serde(default)]
    pub host_snapshot_count: Option<usize>,
    pub failure_category: Option<String>,
    pub recovery_hint: Option<String>,
    #[serde(default)]
    pub notes: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ActionableDiffItem {
    pub ip: String,
    pub target: String,
    pub issue: String,
    pub severity_before: Option<ActionableSeverity>,
    pub severity_after: Option<ActionableSeverity>,
    pub action_before: Option<String>,
    pub action_after: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct SessionActionableDiff {
    pub older: ScanSessionRecord,
    pub newer: ScanSessionRecord,
    pub ip_filter: Option<String>,
    pub target_filter: Option<String>,
    pub severity_filter: Option<ActionableSeverity>,
    pub added: Vec<ActionableDiffItem>,
    pub resolved: Vec<ActionableDiffItem>,
    pub escalated: Vec<ActionableDiffItem>,
    pub reduced: Vec<ActionableDiffItem>,
    pub unchanged: usize,
}

impl ScanSessionStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            ScanSessionStatus::Running => "running",
            ScanSessionStatus::Completed => "completed",
            ScanSessionStatus::Interrupted => "interrupted",
            ScanSessionStatus::Failed => "failed",
        }
    }
}

impl ShardCheckpointState {
    pub fn new(args: ShardCheckpointArgs) -> Self {
        Self {
            version: SHARD_CHECKPOINT_VERSION,
            signature: args.signature,
            target: args.target,
            total_shards: args.total_shards,
            shard_index: args.shard_index,
            shard_dimension: args.shard_dimension,
            unit_kind: args.unit_kind,
            planned_units: args.planned_units,
            completed_units: args.completed_units,
            port_count: args.port_count,
            scan_seed: args.scan_seed,
            updated_at: Utc::now().to_rfc3339(),
        }
    }
}

impl ScanSessionRecord {
    fn from_request(request: &ScanRequest) -> NProbeResult<Self> {
        let session_id = request.session_id.clone().ok_or_else(|| {
            NProbeError::Config("missing session_id while creating session record".to_string())
        })?;
        let started_at = Utc::now().to_rfc3339();
        Ok(Self {
            version: SCAN_SESSION_VERSION,
            session_id,
            status: ScanSessionStatus::Running,
            target: request.target.clone(),
            profile: format!("{:?}", request.profile).to_ascii_lowercase(),
            report_format: format!("{:?}", request.report_format).to_ascii_lowercase(),
            started_at: started_at.clone(),
            updated_at: started_at,
            finished_at: None,
            scan_seed: request.scan_seed,
            total_shards: request.total_shards,
            shard_index: request.shard_index,
            rate_limit_pps: request.rate_limit_pps,
            burst_size: request.burst_size,
            max_retries: request.max_retries,
            output_path: request
                .output_path
                .as_ref()
                .map(|path| path.display().to_string()),
            host_count: None,
            responded_hosts: None,
            duration_ms: None,
            host_snapshot_count: None,
            failure_category: None,
            recovery_hint: None,
            notes: Vec::new(),
        })
    }
}

fn default_checkpoint_unit_kind() -> String {
    "hosts".to_string()
}

pub fn apply_defaults(request: &mut ScanRequest) -> NProbeResult<()> {
    let kv = load_or_default_map()?;

    if !request.profile_explicit {
        if let Some(profile) = kv.get("default_profile").and_then(|raw| parse_profile(raw)) {
            request.profile = profile;
        }
    }

    if matches!(request.profile, ScanProfile::RootOnly) {
        request.root_only = true;
        request.aggressive_root = true;
        request.privileged_probes = true;
        if request.timeout_ms.is_none() {
            request.timeout_ms = Some(ScanProfile::RootOnly.defaults().timeout_ms);
        }
        if request.concurrency.is_none() {
            request.concurrency = Some(ScanProfile::RootOnly.defaults().concurrency);
        }
        if request.delay_ms.is_none() {
            request.delay_ms = Some(ScanProfile::RootOnly.defaults().delay_ms);
        }
        if request.top_ports.is_none() && request.ports.is_empty() {
            request.top_ports = Some(200);
        }
    }

    if request.top_ports.is_none() && request.ports.is_empty() {
        if let Some(value) = kv
            .get("default_top_ports")
            .and_then(|v| v.parse::<usize>().ok())
        {
            request.top_ports = Some(value.max(1));
        }
    }

    if request.timeout_ms.is_none() {
        request.timeout_ms = kv
            .get("default_timeout_ms")
            .and_then(|v| v.parse::<u64>().ok())
            .filter(|v| *v > 0);
    }

    if request.concurrency.is_none() {
        request.concurrency = kv
            .get("default_concurrency")
            .and_then(|v| v.parse::<usize>().ok())
            .filter(|v| *v > 0);
    }

    if request.delay_ms.is_none() {
        request.delay_ms = kv
            .get("default_delay_ms")
            .and_then(|v| v.parse::<u64>().ok());
    }

    if request.rate_limit_pps.is_none() {
        request.rate_limit_pps = kv
            .get("default_rate_pps")
            .and_then(|v| v.parse::<u32>().ok())
            .filter(|v| *v > 0);
    }

    if request.burst_size.is_none() {
        request.burst_size = kv
            .get("default_burst_size")
            .and_then(|v| v.parse::<usize>().ok())
            .filter(|v| *v > 0);
    }

    if request.max_retries.is_none() {
        request.max_retries = kv
            .get("default_max_retries")
            .and_then(|v| v.parse::<u8>().ok())
            .filter(|v| *v <= 20);
    }

    if request.top_ports.is_none() && request.ports.is_empty() {
        request.top_ports = Some(100);
    }

    Ok(())
}

pub fn init_and_update(request: &ScanRequest) -> NProbeResult<PathBuf> {
    let config_dir = resolve_config_dir()?;
    fs::create_dir_all(&config_dir)?;
    let config_path = config_dir.join(CONFIG_FILE_NAME);
    let db_path = sql_persistence::database_path(&config_dir);

    let mut kv = if config_path.exists() {
        load_ini_map(&config_path)?
    } else {
        default_config_map()
    };

    update_runtime_values(&mut kv, request);
    write_ini_map(&config_path, &kv)?;
    let updated_at = Utc::now().to_rfc3339();
    sql_persistence::upsert_runtime_kv_bulk(&db_path, kv.iter(), &updated_at)?;

    Ok(config_path)
}

pub fn ensure_session_id(request: &mut ScanRequest) {
    if request.session_id.is_none() {
        request.session_id = Some(generate_session_id(request));
    }
}

pub fn start_scan_session(request: &ScanRequest) -> NProbeResult<ScanSessionRecord> {
    let record = ScanSessionRecord::from_request(request)?;
    save_scan_session(&record)?;
    Ok(record)
}

pub fn list_scan_sessions(limit: usize) -> NProbeResult<Vec<ScanSessionRecord>> {
    if limit == 0 {
        return Ok(Vec::new());
    }

    let config_dir = resolve_config_dir()?;
    let db_path = sql_persistence::database_path(&config_dir);
    if db_path.exists() {
        let records = sql_persistence::list_sessions(&db_path, limit)?;
        if !records.is_empty() {
            return Ok(records);
        }
    }

    let session_dir = config_dir.join(SESSION_DIR_NAME);
    if !session_dir.exists() {
        return Ok(Vec::new());
    }

    let mut records = Vec::new();
    for entry in fs::read_dir(session_dir)? {
        let entry = entry?;
        let path = entry.path();
        if !entry.file_type()?.is_file()
            || path.extension().and_then(|value| value.to_str()) != Some("json")
        {
            continue;
        }

        let Ok(body) = fs::read_to_string(&path) else {
            continue;
        };
        let Ok(record) = serde_json::from_str::<ScanSessionRecord>(&body) else {
            continue;
        };
        records.push(record);
    }

    records.sort_by(|left, right| {
        right
            .updated_at
            .cmp(&left.updated_at)
            .then_with(|| right.session_id.cmp(&left.session_id))
    });
    records.truncate(limit);
    Ok(records)
}

pub fn load_scan_session(session_id: &str) -> NProbeResult<Option<ScanSessionRecord>> {
    let db_path = sql_persistence::database_path(&resolve_config_dir()?);
    if db_path.exists() {
        if let Some(record) = sql_persistence::load_session(&db_path, session_id)? {
            return Ok(Some(record));
        }
    }

    let session_path = session_file_path(session_id)?;
    if !session_path.exists() {
        return Ok(None);
    }

    let body = fs::read_to_string(&session_path)?;
    let record = serde_json::from_str::<ScanSessionRecord>(&body).map_err(|err| {
        NProbeError::Config(format!(
            "failed to parse session record '{}': {err}",
            session_path.display()
        ))
    })?;
    Ok(Some(record))
}

pub fn diff_session_actionables(
    older_session_id: &str,
    newer_session_id: &str,
    ip_filter: Option<&str>,
    target_filter: Option<&str>,
    severity_filter: Option<ActionableSeverity>,
) -> NProbeResult<SessionActionableDiff> {
    let older = load_scan_session(older_session_id)?
        .ok_or_else(|| NProbeError::Cli(format!("session '{older_session_id}' was not found")))?;
    let newer = load_scan_session(newer_session_id)?
        .ok_or_else(|| NProbeError::Cli(format!("session '{newer_session_id}' was not found")))?;

    let db_path = sql_persistence::database_path(&resolve_config_dir()?);
    if !db_path.exists() {
        return Err(NProbeError::Config(
            "sqlite persistence database is missing; no actionable diff data is available"
                .to_string(),
        ));
    }

    let older_records = filter_actionable_records(
        sql_persistence::load_actionable_snapshots(&db_path, older_session_id)?,
        ip_filter,
        target_filter,
        severity_filter,
    );
    let newer_records = filter_actionable_records(
        sql_persistence::load_actionable_snapshots(&db_path, newer_session_id)?,
        ip_filter,
        target_filter,
        severity_filter,
    );

    let older_map = older_records
        .into_iter()
        .map(|record| ((record.ip.clone(), record.issue.clone()), record))
        .collect::<BTreeMap<_, _>>();
    let newer_map = newer_records
        .into_iter()
        .map(|record| ((record.ip.clone(), record.issue.clone()), record))
        .collect::<BTreeMap<_, _>>();

    let mut added = Vec::new();
    let mut resolved = Vec::new();
    let mut escalated = Vec::new();
    let mut reduced = Vec::new();
    let mut unchanged = 0usize;

    for (key, newer_record) in &newer_map {
        match older_map.get(key) {
            None => added.push(diff_item(None, Some(newer_record))),
            Some(older_record) => {
                if newer_record.severity.rank() > older_record.severity.rank() {
                    escalated.push(diff_item(Some(older_record), Some(newer_record)));
                } else if newer_record.severity.rank() < older_record.severity.rank() {
                    reduced.push(diff_item(Some(older_record), Some(newer_record)));
                } else {
                    unchanged += 1;
                }
            }
        }
    }

    for (key, older_record) in &older_map {
        if !newer_map.contains_key(key) {
            resolved.push(diff_item(Some(older_record), None));
        }
    }

    sort_diff_items(&mut added);
    sort_diff_items(&mut resolved);
    sort_diff_items(&mut escalated);
    sort_diff_items(&mut reduced);

    Ok(SessionActionableDiff {
        older,
        newer,
        ip_filter: ip_filter.map(str::to_string),
        target_filter: target_filter.map(str::to_string),
        severity_filter,
        added,
        resolved,
        escalated,
        reduced,
        unchanged,
    })
}

pub fn complete_scan_session(
    record: &mut ScanSessionRecord,
    report: &ScanReport,
    interrupted: bool,
) -> NProbeResult<PathBuf> {
    let responded_hosts = report
        .hosts
        .iter()
        .filter(|host| {
            host.ports.iter().any(|port| {
                matches!(
                    port.state,
                    crate::models::PortState::Open | crate::models::PortState::Closed
                )
            })
        })
        .count();
    record.status = if interrupted {
        ScanSessionStatus::Interrupted
    } else {
        ScanSessionStatus::Completed
    };
    record.updated_at = Utc::now().to_rfc3339();
    record.finished_at = Some(report.metadata.finished_at.to_rfc3339());
    record.host_count = Some(report.hosts.len());
    record.responded_hosts = Some(responded_hosts);
    record.duration_ms = Some(report.metadata.duration_ms);
    record.host_snapshot_count = Some(report.hosts.len());
    record.failure_category = None;
    record.recovery_hint = None;
    record.notes.push(if interrupted {
        "scan interrupted by stop signal; partial report persisted".to_string()
    } else {
        "scan completed successfully".to_string()
    });
    record.notes.sort_unstable();
    record.notes.dedup();
    save_scan_session(record)
}

pub fn fail_scan_session(
    record: &mut ScanSessionRecord,
    error: &NProbeError,
    interrupted: bool,
) -> NProbeResult<PathBuf> {
    record.status = if interrupted {
        ScanSessionStatus::Interrupted
    } else {
        ScanSessionStatus::Failed
    };
    record.updated_at = Utc::now().to_rfc3339();
    record.finished_at = Some(record.updated_at.clone());
    record.host_snapshot_count = count_host_snapshots_for_session(&record.session_id).ok();
    record.failure_category = Some(error.category().to_string());
    record.recovery_hint = Some(error.recovery_hint().to_string());
    record.notes.push(format!(
        "terminal-status: {}",
        sanitize_value(&error.to_string())
    ));
    record.notes.sort_unstable();
    record.notes.dedup();
    save_scan_session(record)
}

pub fn load_shard_checkpoint(signature: &str) -> NProbeResult<Option<ShardCheckpointState>> {
    let db_path = sql_persistence::database_path(&resolve_config_dir()?);
    if db_path.exists() {
        if let Some(state) = sql_persistence::load_checkpoint(&db_path, signature)? {
            return Ok(Some(state));
        }
    }

    let checkpoint_path = shard_checkpoint_path(signature)?;
    if !checkpoint_path.exists() {
        return Ok(None);
    }

    let body = fs::read_to_string(&checkpoint_path)?;
    let parsed = serde_json::from_str::<ShardCheckpointState>(&body).map_err(|err| {
        NProbeError::Config(format!(
            "failed to parse shard checkpoint '{}': {err}",
            checkpoint_path.display()
        ))
    })?;

    if parsed.signature != signature || parsed.version != SHARD_CHECKPOINT_VERSION {
        return Ok(None);
    }

    Ok(Some(parsed))
}

pub fn save_shard_checkpoint(state: &ShardCheckpointState) -> NProbeResult<PathBuf> {
    let checkpoint_path = shard_checkpoint_path(&state.signature)?;
    let parent = checkpoint_path.parent().ok_or_else(|| {
        NProbeError::Config("invalid checkpoint path without parent directory".to_string())
    })?;
    fs::create_dir_all(parent)?;

    let tmp_path = parent.join(format!("{}.tmp", checkpoint_file_name(&state.signature)));
    let mut state_to_save = state.clone();
    state_to_save.updated_at = Utc::now().to_rfc3339();

    let body = serde_json::to_string_pretty(&state_to_save)?;
    fs::write(&tmp_path, body)?;

    if checkpoint_path.exists() {
        let _ = fs::remove_file(&checkpoint_path);
    }
    fs::rename(&tmp_path, &checkpoint_path).map_err(|err| {
        let _ = fs::remove_file(&tmp_path);
        NProbeError::Io(err)
    })?;
    let db_path = sql_persistence::database_path(&resolve_config_dir()?);
    sql_persistence::save_checkpoint(&db_path, &state_to_save)?;

    Ok(checkpoint_path)
}

pub fn clear_shard_checkpoint(signature: &str) -> NProbeResult<()> {
    let checkpoint_path = shard_checkpoint_path(signature)?;
    if checkpoint_path.exists() {
        fs::remove_file(checkpoint_path)?;
    }
    let db_path = sql_persistence::database_path(&resolve_config_dir()?);
    if db_path.exists() {
        sql_persistence::delete_checkpoint(&db_path, signature)?;
    }
    Ok(())
}

pub struct HostSnapshotWriter {
    inner: sql_persistence::HostSnapshotWriter,
}

impl HostSnapshotWriter {
    pub fn save(
        &mut self,
        session_id: &str,
        host: &crate::models::HostResult,
        phase: &str,
    ) -> NProbeResult<()> {
        let updated_at = Utc::now().to_rfc3339();
        self.inner.save(session_id, host, phase, &updated_at)
    }
}

pub fn open_host_snapshot_writer() -> NProbeResult<HostSnapshotWriter> {
    let db_path = sql_persistence::database_path(&resolve_config_dir()?);
    Ok(HostSnapshotWriter {
        inner: sql_persistence::HostSnapshotWriter::open(&db_path)?,
    })
}

fn diff_item(
    before: Option<&sql_persistence::ActionableSnapshotRecord>,
    after: Option<&sql_persistence::ActionableSnapshotRecord>,
) -> ActionableDiffItem {
    let anchor = after
        .or(before)
        .expect("diff item requires at least one record");
    ActionableDiffItem {
        ip: anchor.ip.clone(),
        target: anchor.target.clone(),
        issue: anchor.issue.clone(),
        severity_before: before.map(|record| record.severity),
        severity_after: after.map(|record| record.severity),
        action_before: before.map(|record| record.action.clone()),
        action_after: after.map(|record| record.action.clone()),
    }
}

fn sort_diff_items(items: &mut [ActionableDiffItem]) {
    items.sort_by(|left, right| {
        right
            .severity_after
            .or(right.severity_before)
            .map(|severity| severity.rank())
            .unwrap_or(0)
            .cmp(
                &left
                    .severity_after
                    .or(left.severity_before)
                    .map(|severity| severity.rank())
                    .unwrap_or(0),
            )
            .then_with(|| left.ip.cmp(&right.ip))
            .then_with(|| left.issue.cmp(&right.issue))
    });
}

fn filter_actionable_records(
    records: Vec<sql_persistence::ActionableSnapshotRecord>,
    ip_filter: Option<&str>,
    target_filter: Option<&str>,
    severity_filter: Option<ActionableSeverity>,
) -> Vec<sql_persistence::ActionableSnapshotRecord> {
    let ip_filter = ip_filter
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string);
    let target_filter = target_filter
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(|value| value.to_ascii_lowercase());

    records
        .into_iter()
        .filter(|record| {
            let ip_ok = ip_filter
                .as_deref()
                .map(|expected| record.ip == expected)
                .unwrap_or(true);
            let target_ok = target_filter
                .as_deref()
                .map(|needle| record.target.to_ascii_lowercase().contains(needle))
                .unwrap_or(true);
            let severity_ok = severity_filter
                .map(|minimum| record.severity.rank() >= minimum.rank())
                .unwrap_or(true);
            ip_ok && target_ok && severity_ok
        })
        .collect()
}

fn update_runtime_values(kv: &mut BTreeMap<String, String>, request: &ScanRequest) {
    kv.insert("config_version".to_string(), "1".to_string());
    kv.insert("last_run_utc".to_string(), Utc::now().to_rfc3339());
    kv.insert("last_target".to_string(), request.target.clone());
    kv.insert(
        "last_session_id".to_string(),
        request.session_id.clone().unwrap_or_default(),
    );
    kv.insert(
        "last_profile".to_string(),
        format!("{:?}", request.profile).to_ascii_lowercase(),
    );
    kv.insert(
        "last_profile_explicit".to_string(),
        request.profile_explicit.to_string(),
    );
    kv.insert("last_root_only".to_string(), request.root_only.to_string());
    kv.insert(
        "last_aggressive_root".to_string(),
        request.aggressive_root.to_string(),
    );
    kv.insert(
        "last_privileged_probes".to_string(),
        request.privileged_probes.to_string(),
    );
    kv.insert(
        "last_file_type".to_string(),
        format!("{:?}", request.report_format).to_ascii_lowercase(),
    );
    kv.insert("last_explain".to_string(), request.explain.to_string());
    kv.insert(
        "last_udp_enabled".to_string(),
        request.include_udp.to_string(),
    );
    kv.insert(
        "last_reverse_dns".to_string(),
        request.reverse_dns.to_string(),
    );
    kv.insert("last_lab_mode".to_string(), request.lab_mode.to_string());
    kv.insert(
        "last_allow_external".to_string(),
        request.allow_external.to_string(),
    );
    kv.insert(
        "last_strict_safety".to_string(),
        request.strict_safety.to_string(),
    );
    kv.insert(
        "last_output_path".to_string(),
        request
            .output_path
            .as_ref()
            .map(|p| p.display().to_string())
            .unwrap_or_default(),
    );
    kv.insert(
        "last_rate_pps".to_string(),
        request
            .rate_limit_pps
            .map(|v| v.to_string())
            .unwrap_or_default(),
    );
    kv.insert(
        "last_burst_size".to_string(),
        request
            .burst_size
            .map(|v| v.to_string())
            .unwrap_or_default(),
    );
    kv.insert(
        "last_max_retries".to_string(),
        request
            .max_retries
            .map(|v| v.to_string())
            .unwrap_or_default(),
    );
    kv.insert(
        "last_total_shards".to_string(),
        request
            .total_shards
            .map(|v| v.to_string())
            .unwrap_or_default(),
    );
    kv.insert(
        "last_shard_index".to_string(),
        request
            .shard_index
            .map(|v| v.to_string())
            .unwrap_or_default(),
    );
    kv.insert(
        "last_scan_seed".to_string(),
        request.scan_seed.map(|v| v.to_string()).unwrap_or_default(),
    );
    kv.insert(
        "last_resume_checkpoint".to_string(),
        request.resume_from_checkpoint.to_string(),
    );
    kv.insert(
        "last_fresh_scan".to_string(),
        request.fresh_scan.to_string(),
    );

    let run_count = kv
        .get("run_count")
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(0)
        .saturating_add(1);
    kv.insert("run_count".to_string(), run_count.to_string());
}

fn resolve_config_dir() -> NProbeResult<PathBuf> {
    if let Some(custom) = env::var_os("NPROBE_RS_CONFIG_HOME") {
        return Ok(PathBuf::from(custom).join(CONFIG_DIR_NAME));
    }

    if let Some(home) = detect_home_dir() {
        return Ok(home.join(CONFIG_DIR_NAME));
    }

    Err(NProbeError::Config(
        "could not resolve user home directory for config".to_string(),
    ))
}

pub fn config_dir() -> NProbeResult<PathBuf> {
    resolve_config_dir()
}

fn shard_checkpoint_path(signature: &str) -> NProbeResult<PathBuf> {
    Ok(resolve_config_dir()?
        .join(CHECKPOINT_DIR_NAME)
        .join(checkpoint_file_name(signature)))
}

fn session_file_path(session_id: &str) -> NProbeResult<PathBuf> {
    Ok(resolve_config_dir()?
        .join(SESSION_DIR_NAME)
        .join(session_file_name(session_id)))
}

fn checkpoint_file_name(signature: &str) -> String {
    format!("shard-{signature}.json")
}

fn session_file_name(session_id: &str) -> String {
    format!("session-{session_id}.json")
}

fn detect_home_dir() -> Option<PathBuf> {
    if let Some(home) = env::var_os("HOME") {
        return Some(PathBuf::from(home));
    }

    #[cfg(windows)]
    {
        if let Some(profile) = env::var_os("USERPROFILE") {
            return Some(PathBuf::from(profile));
        }

        let drive = env::var_os("HOMEDRIVE");
        let path = env::var_os("HOMEPATH");
        if let (Some(drive), Some(path)) = (drive, path) {
            let mut out = PathBuf::from(drive);
            out.push(path);
            return Some(out);
        }
    }

    None
}

fn default_config_map() -> BTreeMap<String, String> {
    let mut map = BTreeMap::new();
    map.insert("config_version".to_string(), "1".to_string());
    map.insert("run_count".to_string(), "0".to_string());
    map.insert("default_profile".to_string(), "balanced".to_string());
    map.insert("default_top_ports".to_string(), "100".to_string());
    map.insert("default_timeout_ms".to_string(), "1200".to_string());
    map.insert("default_concurrency".to_string(), "128".to_string());
    map.insert("default_delay_ms".to_string(), "5".to_string());
    map.insert("default_rate_pps".to_string(), "0".to_string());
    map.insert("default_burst_size".to_string(), "0".to_string());
    map.insert("default_max_retries".to_string(), "0".to_string());
    map.insert("default_file_type".to_string(), "txt".to_string());
    map.insert("default_lab_mode".to_string(), "false".to_string());
    map.insert("default_allow_external".to_string(), "false".to_string());
    map.insert("default_strict_safety".to_string(), "false".to_string());
    map.insert("auto_export_default".to_string(), "false".to_string());
    map.insert("default_output_location".to_string(), "cwd".to_string());
    map
}

fn load_or_default_map() -> NProbeResult<BTreeMap<String, String>> {
    let config_dir = resolve_config_dir()?;
    let config_path = config_dir.join(CONFIG_FILE_NAME);
    if config_path.exists() {
        load_ini_map(&config_path)
    } else {
        Ok(default_config_map())
    }
}

fn load_ini_map(path: &Path) -> NProbeResult<BTreeMap<String, String>> {
    let content = fs::read_to_string(path)?;
    let mut map = BTreeMap::new();
    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') || trimmed.starts_with(';') {
            continue;
        }
        if trimmed.starts_with('[') && trimmed.ends_with(']') {
            continue;
        }
        if let Some((k, v)) = trimmed.split_once('=') {
            map.insert(k.trim().to_string(), v.trim().to_string());
        }
    }
    Ok(map)
}

fn write_ini_map(path: &Path, map: &BTreeMap<String, String>) -> NProbeResult<()> {
    let mut body = String::new();
    body.push_str("[nprobe-rs]\n");
    for (k, v) in map {
        let val = sanitize_value(v);
        body.push_str(k);
        body.push('=');
        body.push_str(&val);
        body.push('\n');
    }

    let parent = path.parent().ok_or_else(|| {
        NProbeError::Config("invalid config path without parent directory".to_string())
    })?;
    let tmp_path = parent.join(format!("{}.tmp", CONFIG_FILE_NAME));
    fs::write(&tmp_path, body)?;
    if path.exists() {
        let _ = fs::remove_file(path);
    }
    fs::rename(&tmp_path, path).map_err(|err| {
        let _ = fs::remove_file(&tmp_path);
        NProbeError::Io(err)
    })?;
    Ok(())
}

fn sanitize_value(value: &str) -> String {
    value.replace(['\n', '\r'], " ")
}

fn generate_session_id(request: &ScanRequest) -> String {
    let timestamp = Utc::now().format("%Y%m%d%H%M%S").to_string();
    let mut seed_input = String::new();
    seed_input.push_str(&request.target);
    seed_input.push('|');
    seed_input.push_str(&format!("{:?}", request.profile));
    seed_input.push('|');
    seed_input.push_str(
        &request
            .scan_seed
            .map(|value| value.to_string())
            .unwrap_or_else(|| "none".to_string()),
    );
    seed_input.push('|');
    seed_input.push_str(&process::id().to_string());
    seed_input.push('|');
    seed_input.push_str(&timestamp);

    format!("scan-{timestamp}-{:016x}", fnv1a64(seed_input.as_bytes()))
}

fn save_scan_session(record: &ScanSessionRecord) -> NProbeResult<PathBuf> {
    let session_path = session_file_path(&record.session_id)?;
    let parent = session_path.parent().ok_or_else(|| {
        NProbeError::Config("invalid session path without parent directory".to_string())
    })?;
    fs::create_dir_all(parent)?;

    let tmp_path = parent.join(format!("{}.tmp", session_file_name(&record.session_id)));
    let mut record_to_save = record.clone();
    record_to_save.updated_at = Utc::now().to_rfc3339();
    record_to_save.host_snapshot_count = count_host_snapshots_for_session(&record.session_id).ok();
    let body = serde_json::to_string_pretty(&record_to_save)?;
    fs::write(&tmp_path, body)?;

    if session_path.exists() {
        let _ = fs::remove_file(&session_path);
    }
    fs::rename(&tmp_path, &session_path).map_err(|err| {
        let _ = fs::remove_file(&tmp_path);
        NProbeError::Io(err)
    })?;
    let db_path = sql_persistence::database_path(&resolve_config_dir()?);
    sql_persistence::save_session(&db_path, &record_to_save)?;

    Ok(session_path)
}

fn count_host_snapshots_for_session(session_id: &str) -> NProbeResult<usize> {
    let db_path = sql_persistence::database_path(&resolve_config_dir()?);
    if !db_path.exists() {
        return Ok(0);
    }
    sql_persistence::count_host_snapshots(&db_path, session_id)
}

fn fnv1a64(bytes: &[u8]) -> u64 {
    const OFFSET_BASIS: u64 = 0xcbf2_9ce4_8422_2325;
    const PRIME: u64 = 0x0000_0100_0000_01b3;

    let mut hash = OFFSET_BASIS;
    for byte in bytes {
        hash ^= *byte as u64;
        hash = hash.wrapping_mul(PRIME);
    }
    hash
}

fn parse_profile(raw: &str) -> Option<ScanProfile> {
    match raw.trim().to_ascii_lowercase().as_str() {
        "stealth" => Some(ScanProfile::Stealth),
        "phantom" | "phantom-scan" | "phantom_scan" => Some(ScanProfile::Phantom),
        "sar" | "sar-scan" | "sar_scan" => Some(ScanProfile::Sar),
        "kis" | "kis-scan" | "kis_scan" => Some(ScanProfile::Kis),
        "balanced" => Some(ScanProfile::Balanced),
        "turbo" => Some(ScanProfile::Turbo),
        "aggressive" => Some(ScanProfile::Aggressive),
        "root-only" | "root_only" | "rootonly" => Some(ScanProfile::RootOnly),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::parse_profile;
    use crate::models::ScanProfile;

    #[test]
    fn parse_profile_accepts_low_impact_concepts() {
        assert!(matches!(
            parse_profile("phantom"),
            Some(ScanProfile::Phantom)
        ));
        assert!(matches!(parse_profile("sar-scan"), Some(ScanProfile::Sar)));
        assert!(matches!(parse_profile("kis_scan"), Some(ScanProfile::Kis)));
    }
}

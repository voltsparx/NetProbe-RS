// Flow sketch: input -> core processing -> output model
// Pseudo-block:
//   read input -> process safely -> return deterministic output

use std::collections::BTreeMap;
use std::env;
use std::fs;
use std::path::{Path, PathBuf};

use chrono::Utc;
use serde::{Deserialize, Serialize};

use crate::error::{NProbeError, NProbeResult};
use crate::models::{ScanProfile, ScanRequest};

const CONFIG_DIR_NAME: &str = ".nprobe-rs-config";
const CONFIG_FILE_NAME: &str = "config.ini";
const CHECKPOINT_DIR_NAME: &str = "checkpoints";
const SHARD_CHECKPOINT_VERSION: u8 = 1;

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

    let mut kv = if config_path.exists() {
        load_ini_map(&config_path)?
    } else {
        default_config_map()
    };

    update_runtime_values(&mut kv, request);
    write_ini_map(&config_path, &kv)?;

    Ok(config_path)
}

pub fn load_shard_checkpoint(signature: &str) -> NProbeResult<Option<ShardCheckpointState>> {
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

    Ok(checkpoint_path)
}

pub fn clear_shard_checkpoint(signature: &str) -> NProbeResult<()> {
    let checkpoint_path = shard_checkpoint_path(signature)?;
    if checkpoint_path.exists() {
        fs::remove_file(checkpoint_path)?;
    }
    Ok(())
}

fn update_runtime_values(kv: &mut BTreeMap<String, String>, request: &ScanRequest) {
    kv.insert("config_version".to_string(), "1".to_string());
    kv.insert("last_run_utc".to_string(), Utc::now().to_rfc3339());
    kv.insert("last_target".to_string(), request.target.clone());
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

fn shard_checkpoint_path(signature: &str) -> NProbeResult<PathBuf> {
    Ok(resolve_config_dir()?
        .join(CHECKPOINT_DIR_NAME)
        .join(checkpoint_file_name(signature)))
}

fn checkpoint_file_name(signature: &str) -> String {
    format!("shard-{signature}.json")
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

fn parse_profile(raw: &str) -> Option<ScanProfile> {
    match raw.trim().to_ascii_lowercase().as_str() {
        "stealth" => Some(ScanProfile::Stealth),
        "balanced" => Some(ScanProfile::Balanced),
        "turbo" => Some(ScanProfile::Turbo),
        "aggressive" => Some(ScanProfile::Aggressive),
        "root-only" | "root_only" | "rootonly" => Some(ScanProfile::RootOnly),
        _ => None,
    }
}

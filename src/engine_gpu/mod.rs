use std::env;
use std::fs;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::error::{NProbeError, NProbeResult};
use crate::models::ScanRequest;

const HYBRID_SHADER_KERNEL: &str = "hybrid_syn_scaffold.wgsl";
const GPU_WORKGROUP_SIZE: usize = 64;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum GpuPlatformTier {
    Tier1Linux,
    Tier2Windows,
    Tier3Fallback,
}

impl GpuPlatformTier {
    pub fn as_str(self) -> &'static str {
        match self {
            GpuPlatformTier::Tier1Linux => "tier1-linux",
            GpuPlatformTier::Tier2Windows => "tier2-windows",
            GpuPlatformTier::Tier3Fallback => "tier3-fallback",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum GpuHybridLane {
    Inactive,
    CpuFallback,
    AssistedHybrid,
    ComputeHybridScaffold,
}

impl GpuHybridLane {
    pub fn as_str(self) -> &'static str {
        match self {
            GpuHybridLane::Inactive => "inactive",
            GpuHybridLane::CpuFallback => "cpu-fallback",
            GpuHybridLane::AssistedHybrid => "assisted-hybrid",
            GpuHybridLane::ComputeHybridScaffold => "compute-hybrid-scaffold",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ActionTriggerCondition {
    pub port: Option<u16>,
    pub state: Option<String>,
    pub ip_range: Option<String>,
    pub total_found: Option<usize>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ActionTriggerKind {
    Shell,
    Notify,
    UiEffect,
    Unknown(String),
}

impl ActionTriggerKind {
    fn from_raw(raw: &str) -> Self {
        match raw.trim().trim_matches('"').to_ascii_lowercase().as_str() {
            "shell" => Self::Shell,
            "notify" => Self::Notify,
            "ui_effect" | "uieffect" => Self::UiEffect,
            other => Self::Unknown(other.to_string()),
        }
    }

    #[allow(dead_code)]
    pub fn as_str(&self) -> &str {
        match self {
            ActionTriggerKind::Shell => "shell",
            ActionTriggerKind::Notify => "notify",
            ActionTriggerKind::UiEffect => "ui_effect",
            ActionTriggerKind::Unknown(value) => value.as_str(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ActionTrigger {
    pub name: String,
    pub condition: ActionTriggerCondition,
    pub kind: ActionTriggerKind,
    pub payload: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ActionTriggerManifest {
    pub path: PathBuf,
    pub triggers: Vec<ActionTrigger>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct GpuDispatchPlan {
    pub workgroup_size: usize,
    pub dispatch_window: usize,
    pub staging_slots: usize,
    pub schedule_randomized: bool,
    pub timestamp_pacing: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HybridGpuPlan {
    pub requested: bool,
    pub lane: GpuHybridLane,
    pub platform_tier: GpuPlatformTier,
    pub backend_label: String,
    pub shader_kernel: String,
    pub visualizer_mode: String,
    pub action_trigger_count: usize,
    pub action_trigger_source: Option<String>,
    pub notes: Vec<String>,
}

impl Default for HybridGpuPlan {
    fn default() -> Self {
        Self {
            requested: false,
            lane: GpuHybridLane::Inactive,
            platform_tier: current_platform_tier(),
            backend_label: "cpu-only".to_string(),
            shader_kernel: HYBRID_SHADER_KERNEL.to_string(),
            visualizer_mode: "inactive".to_string(),
            action_trigger_count: 0,
            action_trigger_source: None,
            notes: Vec::new(),
        }
    }
}

#[allow(dead_code)]
pub fn hybrid_shader_source() -> &'static str {
    include_str!("hybrid_syn_scaffold.wgsl")
}

pub fn gpu_requested(request: &ScanRequest) -> bool {
    request.gpu_rate_explicit
        || request.gpu_burst_size.is_some()
        || request.gpu_timestamp
        || request.gpu_schedule_random
}

pub fn plan_hybrid_runtime(
    request: &ScanRequest,
    execution_mode: &str,
    target_count: usize,
    port_count: usize,
) -> NProbeResult<HybridGpuPlan> {
    let requested = gpu_requested(request);
    let platform_tier = current_platform_tier();
    let backend_label = preferred_backend_label(platform_tier, execution_mode);
    let visualizer_mode = if requested || target_count > 1 {
        "instance-buffer-scaffold"
    } else {
        "inactive"
    };
    let action_manifest = if requested {
        discover_action_triggers()?
    } else {
        None
    };
    let mut notes = Vec::new();

    if requested {
        notes.push(format!(
            "gpu hybrid planner active: lane={} backend={} tier={} kernel={} targets={} ports={}",
            preferred_lane(requested, execution_mode, platform_tier).as_str(),
            backend_label,
            platform_tier.as_str(),
            HYBRID_SHADER_KERNEL,
            target_count,
            port_count
        ));
        notes.push(format!(
            "gpu hybrid planner seeded a {}-thread workgroup scaffold for packet crafting and convergence staging",
            GPU_WORKGROUP_SIZE
        ));
    }

    if platform_tier == GpuPlatformTier::Tier3Fallback {
        notes.push(
            "gpu hybrid planner marked this platform as tier-3 fallback; CPU/raw-socket execution remains authoritative while GPU scaffolding stays non-intrusive"
                .to_string(),
        );
    }

    let (action_trigger_count, action_trigger_source) = if let Some(manifest) = action_manifest {
        notes.push(format!(
            "gpu action triggers loaded: {} trigger(s) from {}",
            manifest.triggers.len(),
            manifest.path.display()
        ));
        (
            manifest.triggers.len(),
            Some(manifest.path.display().to_string()),
        )
    } else {
        if requested {
            notes.push(
                "gpu action triggers not loaded: no gpu action manifest was discovered; shell/notify/ui hooks remain dormant"
                    .to_string(),
            );
        }
        (0, None)
    };

    Ok(HybridGpuPlan {
        requested,
        lane: preferred_lane(requested, execution_mode, platform_tier),
        platform_tier,
        backend_label,
        shader_kernel: HYBRID_SHADER_KERNEL.to_string(),
        visualizer_mode: visualizer_mode.to_string(),
        action_trigger_count,
        action_trigger_source,
        notes,
    })
}

pub fn derive_dispatch_plan(
    request: &ScanRequest,
    target_count: usize,
    burst_size: usize,
) -> Option<GpuDispatchPlan> {
    if !gpu_requested(request) || target_count == 0 {
        return None;
    }

    let burst = request.gpu_burst_size.unwrap_or(burst_size).max(1);
    let dispatch_window = burst
        .saturating_mul(GPU_WORKGROUP_SIZE)
        .min(target_count.max(1))
        .max(1);
    let staging_slots = dispatch_window.next_power_of_two().min(65_536);

    Some(GpuDispatchPlan {
        workgroup_size: GPU_WORKGROUP_SIZE,
        dispatch_window,
        staging_slots,
        schedule_randomized: request.gpu_schedule_random,
        timestamp_pacing: request.gpu_timestamp,
    })
}

fn preferred_lane(
    requested: bool,
    execution_mode: &str,
    platform_tier: GpuPlatformTier,
) -> GpuHybridLane {
    if !requested {
        return GpuHybridLane::Inactive;
    }

    match execution_mode {
        "packet-blast" | "hybrid" => match platform_tier {
            GpuPlatformTier::Tier1Linux => GpuHybridLane::ComputeHybridScaffold,
            GpuPlatformTier::Tier2Windows => GpuHybridLane::AssistedHybrid,
            GpuPlatformTier::Tier3Fallback => GpuHybridLane::CpuFallback,
        },
        _ => GpuHybridLane::CpuFallback,
    }
}

fn preferred_backend_label(platform_tier: GpuPlatformTier, execution_mode: &str) -> String {
    match (platform_tier, execution_mode) {
        (GpuPlatformTier::Tier1Linux, "packet-blast" | "hybrid") => {
            if cfg!(feature = "afxdp") {
                "wgsl-scaffold+afxdp-bridge".to_string()
            } else {
                "wgsl-scaffold+raw-socket-bridge".to_string()
            }
        }
        (GpuPlatformTier::Tier2Windows, "packet-blast" | "hybrid") => {
            "wgsl-scaffold+windivert-bridge".to_string()
        }
        (GpuPlatformTier::Tier3Fallback, _) => "wgsl-scaffold+cpu-fallback".to_string(),
        _ => "cpu-governed-fallback".to_string(),
    }
}

fn current_platform_tier() -> GpuPlatformTier {
    if cfg!(target_os = "linux") {
        GpuPlatformTier::Tier1Linux
    } else if cfg!(target_os = "windows") {
        GpuPlatformTier::Tier2Windows
    } else {
        GpuPlatformTier::Tier3Fallback
    }
}

fn discover_action_triggers() -> NProbeResult<Option<ActionTriggerManifest>> {
    if let Some(path) = env::var_os("NPROBE_RS_GPU_ACTIONS") {
        let path = PathBuf::from(path);
        if !path.exists() {
            return Err(NProbeError::Gpu(format!(
                "GPU action trigger manifest was requested via NPROBE_RS_GPU_ACTIONS, but no file was found at {}. Point the variable to a readable manifest or unset it.",
                path.display()
            )));
        }
        return load_action_triggers(&path).map(Some);
    }

    let candidates = [
        PathBuf::from(".nprobe-rs-config/gpu-actions.yaml"),
        PathBuf::from(".nprobe-rs-config/action-trigger.yaml"),
        PathBuf::from("gpu-actions.yaml"),
        PathBuf::from("action-trigger.yaml"),
        PathBuf::from("self-assesment/gpu-accelerated-engine-arch/action-trigger.txt"),
    ];

    for path in candidates {
        if path.exists() {
            return load_action_triggers(&path).map(Some);
        }
    }

    Ok(None)
}

fn load_action_triggers(path: &Path) -> NProbeResult<ActionTriggerManifest> {
    let raw = fs::read_to_string(path).map_err(|err| {
        NProbeError::Gpu(format!(
            "Could not read GPU action trigger manifest {}. Check file permissions and path validity. Root cause: {err}",
            path.display()
        ))
    })?;
    let triggers = parse_action_triggers(&raw).map_err(|err| {
        NProbeError::Gpu(format!(
            "GPU action trigger manifest {} is malformed. {}",
            path.display(),
            gpu_error_detail(err)
        ))
    })?;
    if triggers.is_empty() {
        return Err(NProbeError::Gpu(format!(
            "GPU action trigger manifest {} did not define any valid triggers. Expected entries under 'triggers:' with name, condition, and action sections.",
            path.display()
        )));
    }
    Ok(ActionTriggerManifest {
        path: path.to_path_buf(),
        triggers,
    })
}

fn parse_action_triggers(raw: &str) -> NProbeResult<Vec<ActionTrigger>> {
    let mut triggers = Vec::new();
    let mut current = ParsedTrigger::default();

    for line in raw.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }

        if let Some(value) = trimmed.strip_prefix("- name:") {
            if let Some(trigger) = current.finish()? {
                triggers.push(trigger);
            }
            current = ParsedTrigger {
                name: clean_scalar(value).to_string(),
                ..ParsedTrigger::default()
            };
            continue;
        }

        if current.name.is_empty() {
            continue;
        }

        if let Some(value) = trimmed.strip_prefix("port:") {
            current.port = clean_scalar(value).parse().ok();
        } else if let Some(value) = trimmed.strip_prefix("state:") {
            current.state = Some(clean_scalar(value).to_string());
        } else if let Some(value) = trimmed.strip_prefix("ip_range:") {
            current.ip_range = Some(clean_scalar(value).to_string());
        } else if let Some(value) = trimmed.strip_prefix("total_found:") {
            current.total_found = clean_scalar(value).parse().ok();
        } else if let Some(value) = trimmed.strip_prefix("type:") {
            current.kind = Some(ActionTriggerKind::from_raw(value));
        } else if let Some(value) = trimmed.strip_prefix("exec:") {
            current.payload = Some(clean_scalar(value).to_string());
            current.payload_source = Some("exec".to_string());
        } else if let Some(value) = trimmed.strip_prefix("message:") {
            current.payload = Some(clean_scalar(value).to_string());
            current.payload_source = Some("message".to_string());
        } else if let Some(value) = trimmed.strip_prefix("effect:") {
            current.payload = Some(clean_scalar(value).to_string());
            current.payload_source = Some("effect".to_string());
        }
    }

    if let Some(trigger) = current.finish()? {
        triggers.push(trigger);
    }

    Ok(triggers)
}

fn gpu_error_detail(err: NProbeError) -> String {
    match err {
        NProbeError::Gpu(message)
        | NProbeError::Cli(message)
        | NProbeError::Parse(message)
        | NProbeError::Safety(message)
        | NProbeError::Config(message) => message,
        other => other.to_string(),
    }
}

fn clean_scalar(raw: &str) -> &str {
    strip_inline_comment(raw)
        .trim()
        .trim_matches('"')
        .trim_matches('\'')
}

fn strip_inline_comment(raw: &str) -> &str {
    let mut in_single = false;
    let mut in_double = false;

    for (idx, ch) in raw.char_indices() {
        match ch {
            '\'' if !in_double => in_single = !in_single,
            '"' if !in_single => in_double = !in_double,
            '#' if !in_single && !in_double => return &raw[..idx],
            _ => {}
        }
    }

    raw
}

#[derive(Debug, Default)]
struct ParsedTrigger {
    name: String,
    port: Option<u16>,
    state: Option<String>,
    ip_range: Option<String>,
    total_found: Option<usize>,
    kind: Option<ActionTriggerKind>,
    payload: Option<String>,
    payload_source: Option<String>,
}

impl ParsedTrigger {
    fn finish(&mut self) -> NProbeResult<Option<ActionTrigger>> {
        if self.name.is_empty() {
            return Ok(None);
        }

        let kind = self.kind.clone().ok_or_else(|| {
            NProbeError::Gpu(format!(
                "trigger '{}' is missing action.type. Expected one of: shell, notify, ui_effect.",
                self.name
            ))
        })?;
        if let ActionTriggerKind::Unknown(value) = &kind {
            return Err(NProbeError::Gpu(format!(
                "trigger '{}' uses unsupported action.type '{}'. Expected one of: shell, notify, ui_effect.",
                self.name, value
            )));
        }
        let payload = self.payload.clone().ok_or_else(|| {
            NProbeError::Gpu(format!(
                "trigger '{}' is missing an action payload. Expected exec, message, or effect under action.",
                self.name
            ))
        })?;
        let payload_source = self.payload_source.clone().ok_or_else(|| {
            NProbeError::Gpu(format!(
                "trigger '{}' is missing an action payload field. Expected action.exec, action.message, or action.effect.",
                self.name
            ))
        })?;
        validate_trigger_payload(&self.name, &kind, &payload_source)?;
        if self.port.is_none()
            && self.state.is_none()
            && self.ip_range.is_none()
            && self.total_found.is_none()
        {
            return Err(NProbeError::Gpu(format!(
                "trigger '{}' does not define any condition fields. Add port/state, ip_range, or total_found so the GPU hybrid lane knows when to fire it.",
                self.name
            )));
        }
        let trigger = ActionTrigger {
            name: std::mem::take(&mut self.name),
            condition: ActionTriggerCondition {
                port: self.port.take(),
                state: self.state.take(),
                ip_range: self.ip_range.take(),
                total_found: self.total_found.take(),
            },
            kind,
            payload,
        };
        self.kind = None;
        self.payload = None;
        self.payload_source = None;
        Ok(Some(trigger))
    }
}

fn validate_trigger_payload(
    name: &str,
    kind: &ActionTriggerKind,
    payload_source: &str,
) -> NProbeResult<()> {
    let expected = match kind {
        ActionTriggerKind::Shell => "exec",
        ActionTriggerKind::Notify => "message",
        ActionTriggerKind::UiEffect => "effect",
        ActionTriggerKind::Unknown(_) => return Ok(()),
    };
    if payload_source == expected {
        return Ok(());
    }

    Err(NProbeError::Gpu(format!(
        "trigger '{}' uses action.{} but action.type '{}' requires action.{}.",
        name,
        payload_source,
        kind.as_str(),
        expected
    )))
}

#[cfg(test)]
mod tests {
    use super::{derive_dispatch_plan, parse_action_triggers, plan_hybrid_runtime};
    use crate::error::NProbeError;
    use crate::models::{ReportFormat, ScanProfile, ScanRequest};

    fn base_request() -> ScanRequest {
        ScanRequest {
            target: "127.0.0.1".to_string(),
            session_id: None,
            ports: vec![22, 80, 443],
            top_ports: None,
            ping_scan: false,
            include_udp: false,
            reverse_dns: false,
            service_detection: true,
            explain: false,
            verbose: false,
            report_format: ReportFormat::Cli,
            profile: ScanProfile::Balanced,
            profile_explicit: false,
            root_only: false,
            aggressive_root: false,
            privileged_probes: false,
            arp_discovery: false,
            lab_mode: false,
            allow_external: false,
            strict_safety: false,
            output_path: None,
            lua_script: None,
            callback_ping: false,
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
        }
    }

    #[test]
    fn hybrid_plan_stays_inactive_without_gpu_request() {
        let request = base_request();
        let plan = plan_hybrid_runtime(&request, "hybrid", 8, 128).expect("hybrid plan");
        assert!(!plan.requested);
        assert_eq!(plan.lane.as_str(), "inactive");
    }

    #[test]
    fn hybrid_plan_enables_compute_scaffold_for_gpu_requests() {
        let mut request = base_request();
        request.gpu_rate_pps = Some(100);
        request.gpu_rate_explicit = true;
        let plan = plan_hybrid_runtime(&request, "packet-blast", 16, 256).expect("hybrid plan");
        assert!(plan.requested);
        assert!(plan.backend_label.contains("wgsl-scaffold"));
    }

    #[test]
    fn dispatch_plan_uses_workgroup_alignment() {
        let mut request = base_request();
        request.gpu_burst_size = Some(2);
        let dispatch = derive_dispatch_plan(&request, 500, 4).expect("dispatch plan");
        assert_eq!(dispatch.workgroup_size, 64);
        assert_eq!(dispatch.dispatch_window, 128);
    }

    #[test]
    fn action_trigger_parser_reads_yaml_like_scaffold() {
        let raw = r#"
triggers:
  - name: "Auto-Exploit Web"
    condition:
      port: 80
      state: "open"
    action:
      type: "shell"
      exec: "curl -I http://{ip}"
  - name: "GPU Convergence Event"
    condition:
      total_found: 100
    action:
      type: "ui_effect"
      effect: "flash_screen"
"#;
        let triggers = parse_action_triggers(raw).expect("parsed triggers");
        assert_eq!(triggers.len(), 2);
        assert_eq!(triggers[0].condition.port, Some(80));
        assert_eq!(triggers[1].condition.total_found, Some(100));
        assert_eq!(triggers[1].kind.as_str(), "ui_effect");
    }

    #[test]
    fn action_trigger_parser_reports_missing_type_clearly() {
        let raw = r#"
triggers:
  - name: "Broken Trigger"
    condition:
      port: 80
    action:
      exec: "curl -I http://{ip}"
"#;
        let err = parse_action_triggers(raw).expect_err("parser should fail");
        match err {
            NProbeError::Gpu(message) => {
                assert!(message.contains("missing action.type"));
                assert!(message.contains("shell, notify, ui_effect"));
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn action_trigger_parser_reports_wrong_payload_field_clearly() {
        let raw = r#"
triggers:
  - name: "Wrong Payload"
    condition:
      total_found: 5
    action:
      type: "notify"
      exec: "curl -I http://{ip}"
"#;
        let err = parse_action_triggers(raw).expect_err("parser should fail");
        match err {
            NProbeError::Gpu(message) => {
                assert!(message.contains("action.exec"));
                assert!(message.contains("requires action.message"));
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn action_trigger_parser_allows_inline_comments_after_values() {
        let raw = r#"
triggers:
  - name: "GPU Convergence Event"
    condition:
      total_found: 100 # Trigger when 100 targets are found
    action:
      type: "ui_effect"
      effect: "flash_screen"
"#;
        let triggers = parse_action_triggers(raw).expect("parsed triggers");
        assert_eq!(triggers.len(), 1);
        assert_eq!(triggers[0].condition.total_found, Some(100));
    }
}

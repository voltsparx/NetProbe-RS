use std::time::{Duration, Instant};

#[cfg(unix)]
use std::process::Command;

use sysinfo::{CpuRefreshKind, MemoryRefreshKind, RefreshKind, System};

use crate::error::{NProbeError, NProbeResult};
use crate::models::{LocalSystemStats, ScanRequest};

const MONITOR_SAMPLE_INTERVAL: Duration = Duration::from_millis(900);

#[derive(Debug, Clone, Copy)]
struct LocalSystemSample {
    cpu_threads: usize,
    cpu_usage_pct: f32,
    total_memory_mib: u64,
    available_memory_mib: u64,
}

#[derive(Debug, Clone)]
pub struct RuntimeHealthAdjustment {
    pub health_stage: String,
    pub rate_cap_pps: u32,
    pub burst_cap: usize,
    pub worker_cap: usize,
    pub delay_floor: Duration,
    pub emergency_brake_reason: Option<String>,
    pub notes: Vec<String>,
}

pub struct RuntimeHealthMonitor {
    system: System,
    last_refresh: Instant,
    last_signature: Option<String>,
}

impl RuntimeHealthMonitor {
    pub fn new() -> Self {
        let mut system = new_system();
        system.refresh_memory();
        system.refresh_cpu_all();

        Self {
            system,
            last_refresh: Instant::now()
                .checked_sub(MONITOR_SAMPLE_INTERVAL)
                .unwrap_or_else(Instant::now),
            last_signature: None,
        }
    }

    pub fn sample_raw_path(
        &mut self,
        current_rate_pps: u64,
        current_burst: usize,
        current_workers: usize,
        current_delay: Duration,
    ) -> Option<RuntimeHealthAdjustment> {
        if self.last_refresh.elapsed() < MONITOR_SAMPLE_INTERVAL {
            return None;
        }

        self.last_refresh = Instant::now();
        self.system.refresh_memory();
        self.system.refresh_cpu_all();

        let stats = derive_stats_from_sample(sample_from_system(&self.system), false);
        let rate_cap_pps = stats.recommended_raw_rate_pps.max(1);
        let burst_cap = stats.recommended_raw_burst.max(1);
        let worker_cap = stats.recommended_concurrency.max(1);
        let delay_floor = Duration::from_millis(stats.recommended_delay_ms);
        let mut notes = Vec::new();

        if current_rate_pps > rate_cap_pps as u64 {
            notes.push(format!(
                "intelligence adjusted packet-crafter rate from {}pps toward {}pps because local CPU usage is {:.0}% and only {} MiB of memory is currently free",
                current_rate_pps,
                rate_cap_pps,
                stats.cpu_usage_pct,
                stats.available_memory_mib
            ));
        }
        if current_burst > burst_cap {
            notes.push(format!(
                "intelligence tightened packet-crafter burst size from {} to {} because the local health stage is {}",
                current_burst,
                burst_cap,
                stats.health_stage
            ));
        }
        if current_workers > worker_cap {
            notes.push(format!(
                "intelligence reduced packet-crafter worker parallelism from {} to {} because the local system can safely sustain fewer concurrent crafters right now",
                current_workers,
                worker_cap
            ));
        }
        if current_delay < delay_floor {
            notes.push(format!(
                "intelligence raised packet-crafter cool-down from {}ms to {}ms because the local health monitor detected {} pressure",
                current_delay.as_millis(),
                delay_floor.as_millis(),
                stats.health_stage
            ));
        }
        if let Some(reason) = stats
            .emergency_brake_reason
            .clone()
            .filter(|_| stats.emergency_brake_triggered)
        {
            notes.push(format!(
                "emergency brake engaged during packet crafting because {}",
                reason
            ));
        }

        if notes.is_empty() {
            return None;
        }

        let signature = format!(
            "{}:{}:{}:{}:{}:{}",
            stats.health_stage,
            rate_cap_pps,
            burst_cap,
            worker_cap,
            delay_floor.as_millis(),
            stats.emergency_brake_triggered
        );
        if self.last_signature.as_deref() == Some(signature.as_str()) {
            return None;
        }
        self.last_signature = Some(signature);

        Some(RuntimeHealthAdjustment {
            health_stage: stats.health_stage,
            rate_cap_pps,
            burst_cap,
            worker_cap,
            delay_floor,
            emergency_brake_reason: stats.emergency_brake_reason,
            notes,
        })
    }
}

pub fn assess_request() -> LocalSystemStats {
    let mut system = new_system();
    warm_cpu_sampler(&mut system);
    derive_stats_from_sample(sample_from_system(&system), false)
}

pub fn apply_request_governor(
    request: &mut ScanRequest,
    stats: &mut LocalSystemStats,
    warnings: &mut Vec<String>,
) -> NProbeResult<()> {
    if request.assess_hardware {
        push_adjustment(
            stats,
            warnings,
            "hardware assessment mode active: nprobe-rs will only inspect the local system and suggest safe ceilings; no scan packets will be transmitted".to_string(),
        );
    }

    for note in stats.compatibility_notes.clone() {
        if !warnings.iter().any(|warning| warning == &note) {
            warnings.push(note);
        }
    }

    if request.override_mode {
        push_adjustment(
            stats,
            warnings,
            "override mode active: pre-execution local system limits are advisory only; nprobe-rs will not auto-reduce requested rate/burst/concurrency before launch, but runtime overflow protection for accelerated packet crafters remains active".to_string(),
        );
        if request.effective_privileged_probes() && !stats.raw_packet_supported {
            push_adjustment(
                stats,
                warnings,
                "override mode cannot manufacture raw packet capability; missing platform support or privileges still block the kernel-bypass lane".to_string(),
            );
        }
        if gpu_requested_without_backend(request) && !stats.gpu_hybrid_supported {
            push_adjustment(
                stats,
                warnings,
                "override mode cannot manufacture GPU capability; unsupported GPU paths still fall back when the platform cannot sustain them".to_string(),
            );
        }
        return Ok(());
    }

    if request.effective_privileged_probes() && !stats.raw_packet_supported {
        request.privileged_probes = false;
        request.aggressive_root = false;
        push_adjustment(
            stats,
            warnings,
            format!(
                "fault isolation disabled the raw kernel-bypass lane because this host is not currently ready for privileged raw access; CPU {:.0}% | free memory {} MiB",
                stats.cpu_usage_pct,
                stats.available_memory_mib
            ),
        );
    }

    if request.gpu_rate_explicit && !stats.gpu_hybrid_supported {
        push_adjustment(
            stats,
            warnings,
            format!(
                "fault isolation kept the GPU lane in governed CPU fallback because platform tier {} cannot run the active GPU hybrid scaffold cleanly",
                stats.platform_tier
            ),
        );
    }

    cap_u32_option(
        &mut request.rate_limit_pps,
        stats.recommended_raw_rate_pps,
        "raw rate",
        stats,
        warnings,
    );
    cap_usize_option(
        &mut request.burst_size,
        stats.recommended_raw_burst,
        "raw burst",
        stats,
        warnings,
    );
    cap_usize_option(
        &mut request.concurrency,
        stats.recommended_concurrency,
        "probe concurrency",
        stats,
        warnings,
    );
    raise_delay_floor(request, stats, warnings);

    if request.gpu_rate_explicit {
        cap_u32_option(
            &mut request.gpu_rate_pps,
            stats.recommended_gpu_rate_pps,
            "gpu rate",
            stats,
            warnings,
        );
    }
    if request.gpu_burst_size.is_some() {
        cap_usize_option(
            &mut request.gpu_burst_size,
            stats.recommended_gpu_burst,
            "gpu burst",
            stats,
            warnings,
        );
    }

    if let Some(reason) = stats
        .emergency_brake_reason
        .clone()
        .filter(|_| stats.emergency_brake_triggered)
    {
        push_adjustment(
            stats,
            warnings,
            format!(
                "emergency brake engaged before scan execution because {}",
                reason
            ),
        );
        if !request.assess_hardware {
            return Err(NProbeError::Safety(format!(
                "local emergency brake engaged: {}",
                reason
            )));
        }
    }

    Ok(())
}

fn gpu_requested_without_backend(request: &ScanRequest) -> bool {
    request.gpu_rate_explicit
        || request.gpu_burst_size.is_some()
        || request.gpu_timestamp
        || request.gpu_schedule_random
}

fn new_system() -> System {
    System::new_with_specifics(
        RefreshKind::nothing()
            .with_cpu(CpuRefreshKind::everything())
            .with_memory(MemoryRefreshKind::everything()),
    )
}

fn warm_cpu_sampler(system: &mut System) {
    system.refresh_memory();
    system.refresh_cpu_all();
    std::thread::sleep(Duration::from_millis(120));
    system.refresh_cpu_all();
}

fn sample_from_system(system: &System) -> LocalSystemSample {
    let cpu_threads = system
        .cpus()
        .len()
        .max(
            std::thread::available_parallelism()
                .map(|value| value.get())
                .unwrap_or(1),
        )
        .max(1);

    LocalSystemSample {
        cpu_threads,
        cpu_usage_pct: system.global_cpu_usage(),
        total_memory_mib: memory_units_to_mib(system.total_memory()),
        available_memory_mib: memory_units_to_mib(system.available_memory()),
    }
}

fn memory_units_to_mib(raw: u64) -> u64 {
    if raw > (1u64 << 32) {
        raw / (1024 * 1024)
    } else {
        raw / 1024
    }
}

fn derive_stats_from_sample(sample: LocalSystemSample, assessment_mode: bool) -> LocalSystemStats {
    let hardware_profile = classify_hardware_profile(sample.cpu_threads, sample.total_memory_mib);
    let health_stage = classify_health_stage(
        sample.cpu_usage_pct,
        sample.available_memory_mib,
        sample.total_memory_mib,
    );
    let platform_tier = platform_tier_label().to_string();
    let raw_packet_supported = raw_packet_ready();
    let gpu_hybrid_supported = gpu_platform_ready();
    let fault_isolation_mode =
        "per-host degradation + gpu-lane fallback + local-health governor".to_string();

    let (
        mut recommended_raw_rate_pps,
        mut recommended_raw_burst,
        mut recommended_gpu_rate_pps,
        mut recommended_gpu_burst,
        mut recommended_concurrency,
        mut recommended_delay_ms,
    ) = base_limits_for_profile(hardware_profile);

    match health_stage {
        "guarded" => {
            recommended_raw_rate_pps = (recommended_raw_rate_pps / 2).max(100);
            recommended_raw_burst = (recommended_raw_burst / 2).max(1);
            recommended_gpu_rate_pps = (recommended_gpu_rate_pps / 2).max(100);
            recommended_gpu_burst = (recommended_gpu_burst / 2).max(1);
            recommended_concurrency = (recommended_concurrency / 2).max(2);
            recommended_delay_ms = recommended_delay_ms.max(20);
        }
        "critical" => {
            recommended_raw_rate_pps = (recommended_raw_rate_pps / 4).max(100);
            recommended_raw_burst = (recommended_raw_burst / 4).max(1);
            recommended_gpu_rate_pps = (recommended_gpu_rate_pps / 4).max(100);
            recommended_gpu_burst = (recommended_gpu_burst / 4).max(1);
            recommended_concurrency = (recommended_concurrency / 4).max(2);
            recommended_delay_ms = recommended_delay_ms.max(50);
        }
        "emergency" => {
            recommended_raw_rate_pps = 50;
            recommended_raw_burst = 1;
            recommended_gpu_rate_pps = 50;
            recommended_gpu_burst = 1;
            recommended_concurrency = 1;
            recommended_delay_ms = 150;
        }
        _ => {}
    }

    let emergency_brake_reason = emergency_brake_reason(
        sample.cpu_usage_pct,
        sample.available_memory_mib,
        sample.total_memory_mib,
    );
    let emergency_brake_triggered = emergency_brake_reason.is_some();

    let mut compatibility_notes = Vec::new();
    if raw_packet_supported {
        compatibility_notes.push(format!(
            "raw packet lane is available on this host; keep the kernel-bypass packet crafters at or below {}pps with burst {} unless later telemetry justifies more",
            recommended_raw_rate_pps,
            recommended_raw_burst
        ));
    } else {
        compatibility_notes.push(
            "raw packet lane is not currently available on this host; kernel-bypass crafting needs a supported platform plus elevated raw-socket access"
                .to_string(),
        );
    }
    if gpu_hybrid_supported {
        compatibility_notes.push(format!(
            "gpu hybrid lane is scaffold-ready on this platform; current builds still use a governed bridge, so keep GPU ceilings at or below {}pps with burst {}",
            recommended_gpu_rate_pps,
            recommended_gpu_burst
        ));
    } else {
        compatibility_notes.push(
            "gpu hybrid lane is in fallback mode on this platform; nprobe-rs will stay on the governed CPU path instead of attempting active GPU execution"
                .to_string(),
        );
    }

    LocalSystemStats {
        assessment_mode,
        hardware_profile: hardware_profile.to_string(),
        health_stage: health_stage.to_string(),
        platform_tier,
        raw_packet_supported,
        gpu_hybrid_supported,
        fault_isolation_mode,
        cpu_threads: sample.cpu_threads,
        cpu_usage_pct: sample.cpu_usage_pct,
        total_memory_mib: sample.total_memory_mib,
        available_memory_mib: sample.available_memory_mib,
        recommended_raw_rate_pps,
        recommended_raw_burst,
        recommended_gpu_rate_pps,
        recommended_gpu_burst,
        recommended_concurrency,
        recommended_delay_ms,
        emergency_brake_armed: true,
        emergency_brake_triggered,
        emergency_brake_reason,
        compatibility_notes,
        adjustments: Vec::new(),
    }
}

fn base_limits_for_profile(profile: &str) -> (u32, usize, u32, usize, usize, u64) {
    match profile {
        "minimal" => (100, 1, 100, 1, 4, 40),
        "constrained" => (400, 4, 400, 4, 16, 20),
        "balanced" => (1_500, 12, 2_500, 16, 64, 5),
        _ => (5_000, 24, 8_000, 32, 128, 0),
    }
}

fn classify_hardware_profile(cpu_threads: usize, total_memory_mib: u64) -> &'static str {
    if cpu_threads <= 4 || total_memory_mib < 8_192 {
        "minimal"
    } else if cpu_threads <= 8 || total_memory_mib < 16_384 {
        "constrained"
    } else if cpu_threads <= 16 || total_memory_mib < 32_768 {
        "balanced"
    } else {
        "high-throughput"
    }
}

fn classify_health_stage(
    cpu_usage_pct: f32,
    available_memory_mib: u64,
    total_memory_mib: u64,
) -> &'static str {
    let free_ratio = if total_memory_mib == 0 {
        0.0
    } else {
        available_memory_mib as f32 / total_memory_mib as f32
    };

    if cpu_usage_pct >= 95.0 || free_ratio <= 0.04 || available_memory_mib <= 384 {
        "emergency"
    } else if cpu_usage_pct >= 85.0 || free_ratio <= 0.08 || available_memory_mib <= 768 {
        "critical"
    } else if cpu_usage_pct >= 70.0 || free_ratio <= 0.15 || available_memory_mib <= 1_536 {
        "guarded"
    } else {
        "balanced"
    }
}

fn emergency_brake_reason(
    cpu_usage_pct: f32,
    available_memory_mib: u64,
    total_memory_mib: u64,
) -> Option<String> {
    let free_ratio = if total_memory_mib == 0 {
        0.0
    } else {
        available_memory_mib as f32 / total_memory_mib as f32
    };

    if cpu_usage_pct >= 95.0 && available_memory_mib <= 768 {
        Some(format!(
            "local CPU load is {:.0}% and free memory is only {} MiB, so more packet crafting would risk destabilizing this machine",
            cpu_usage_pct,
            available_memory_mib
        ))
    } else if free_ratio <= 0.04 || available_memory_mib <= 384 {
        Some(format!(
            "free memory dropped to {} MiB, which is below the emergency floor for safe packet-crafter operation",
            available_memory_mib
        ))
    } else {
        None
    }
}

fn platform_tier_label() -> &'static str {
    if cfg!(target_os = "linux") {
        "tier1-linux"
    } else if cfg!(target_os = "windows") {
        "tier2-windows"
    } else {
        "tier3-fallback"
    }
}

fn gpu_platform_ready() -> bool {
    matches!(platform_tier_label(), "tier1-linux" | "tier2-windows")
}

fn raw_packet_ready() -> bool {
    let os_supported = cfg!(target_os = "linux") || cfg!(target_os = "windows");
    if !os_supported {
        return false;
    }

    if cfg!(target_os = "windows") {
        return true;
    }

    #[cfg(unix)]
    {
        return Command::new("id")
            .arg("-u")
            .output()
            .ok()
            .and_then(|output| String::from_utf8(output.stdout).ok())
            .and_then(|raw| raw.trim().parse::<u32>().ok())
            == Some(0);
    }

    #[allow(unreachable_code)]
    false
}

fn raise_delay_floor(
    request: &mut ScanRequest,
    stats: &mut LocalSystemStats,
    warnings: &mut Vec<String>,
) {
    let current = request.delay_ms.unwrap_or_default();
    if current >= stats.recommended_delay_ms {
        return;
    }

    request.delay_ms = Some(stats.recommended_delay_ms);
    push_adjustment(
        stats,
        warnings,
        format!(
            "intelligence raised probe cool-down from {}ms to {}ms because the local system health stage is {}",
            current,
            stats.recommended_delay_ms,
            stats.health_stage
        ),
    );
}

fn cap_u32_option(
    current: &mut Option<u32>,
    cap: u32,
    label: &str,
    stats: &mut LocalSystemStats,
    warnings: &mut Vec<String>,
) {
    let Some(existing) = *current else {
        return;
    };
    if existing <= cap || cap == 0 {
        return;
    }

    *current = Some(cap);
    push_adjustment(
        stats,
        warnings,
        format!(
            "intelligence reduced {} from {} to {} because local CPU usage is {:.0}% and free memory is {} MiB",
            label,
            existing,
            cap,
            stats.cpu_usage_pct,
            stats.available_memory_mib
        ),
    );
}

fn cap_usize_option(
    current: &mut Option<usize>,
    cap: usize,
    label: &str,
    stats: &mut LocalSystemStats,
    warnings: &mut Vec<String>,
) {
    let Some(existing) = *current else {
        return;
    };
    if existing <= cap || cap == 0 {
        return;
    }

    *current = Some(cap);
    push_adjustment(
        stats,
        warnings,
        format!(
            "intelligence reduced {} from {} to {} because the local hardware profile is {} and the current health stage is {}",
            label,
            existing,
            cap,
            stats.hardware_profile,
            stats.health_stage
        ),
    );
}

fn push_adjustment(stats: &mut LocalSystemStats, warnings: &mut Vec<String>, message: String) {
    if !stats
        .adjustments
        .iter()
        .any(|existing| existing == &message)
    {
        stats.adjustments.push(message.clone());
    }
    if !warnings.iter().any(|existing| existing == &message) {
        warnings.push(message);
    }
}

#[cfg(test)]
mod tests {
    use super::{apply_request_governor, derive_stats_from_sample, LocalSystemSample};
    use crate::models::{ReportFormat, ScanProfile, ScanRequest};

    fn base_request() -> ScanRequest {
        ScanRequest {
            target: "127.0.0.1".to_string(),
            target_inputs: Vec::new(),
            exclude_targets: Vec::new(),
            session_id: None,
            ports: vec![22, 80, 443],
            excluded_ports: Vec::new(),
            top_ports: None,
            port_ratio: None,
            list_scan: false,
            ping_scan: false,
            traceroute: false,
            include_udp: false,
            reverse_dns: false,
            service_detection: true,
            version_intensity: None,
            version_trace: false,
            explain: false,
            verbose: false,
            report_format: ReportFormat::Cli,
            profile: ScanProfile::Balanced,
            profile_explicit: false,
            root_only: false,
            aggressive_root: false,
            privileged_probes: false,
            arp_discovery: false,
            callback_ping: false,
            lab_mode: false,
            allow_external: false,
            strict_safety: false,
            output_path: None,
            lua_script: None,
            source_port: None,
            sequential_port_order: false,
            timeout_ms: None,
            concurrency: Some(128),
            delay_ms: Some(0),
            timing_template: None,
            rate_limit_pps: Some(5_000),
            rate_explicit: true,
            gpu_rate_pps: Some(8_000),
            gpu_rate_explicit: true,
            gpu_burst_size: Some(32),
            gpu_timestamp: false,
            gpu_schedule_random: false,
            gpu_action_manifest: None,
            assess_hardware: false,
            override_mode: false,
            burst_size: Some(32),
            max_retries: None,
            total_shards: None,
            shard_index: None,
            scan_seed: None,
            resume_from_checkpoint: true,
            fresh_scan: false,
        }
    }

    #[test]
    fn constrained_system_caps_requested_rates() {
        let sample = LocalSystemSample {
            cpu_threads: 8,
            cpu_usage_pct: 82.0,
            total_memory_mib: 16_384,
            available_memory_mib: 1_024,
        };
        let mut stats = derive_stats_from_sample(sample, false);
        let mut request = base_request();
        let mut warnings = Vec::new();

        apply_request_governor(&mut request, &mut stats, &mut warnings)
            .expect("governor should succeed");

        assert!(request.rate_limit_pps.unwrap_or_default() <= stats.recommended_raw_rate_pps);
        assert!(request.gpu_rate_pps.unwrap_or_default() <= stats.recommended_gpu_rate_pps);
        assert!(warnings
            .iter()
            .any(|warning| warning.contains("intelligence reduced raw rate")));
    }

    #[test]
    fn emergency_memory_floor_triggers_brake() {
        let sample = LocalSystemSample {
            cpu_threads: 4,
            cpu_usage_pct: 61.0,
            total_memory_mib: 4_096,
            available_memory_mib: 256,
        };
        let stats = derive_stats_from_sample(sample, false);

        assert!(stats.emergency_brake_triggered);
        assert!(stats
            .emergency_brake_reason
            .as_deref()
            .is_some_and(|reason| reason.contains("free memory")));
    }

    #[test]
    fn assessment_mode_records_local_only_operation() {
        let sample = LocalSystemSample {
            cpu_threads: 16,
            cpu_usage_pct: 22.0,
            total_memory_mib: 32_768,
            available_memory_mib: 18_000,
        };
        let mut stats = derive_stats_from_sample(sample, true);
        let mut request = base_request();
        request.assess_hardware = true;
        let mut warnings = Vec::new();

        apply_request_governor(&mut request, &mut stats, &mut warnings)
            .expect("assessment mode should not fail");

        assert!(stats.assessment_mode);
        assert!(warnings
            .iter()
            .any(|warning| warning.contains("hardware assessment mode active")));
    }

    #[test]
    fn override_mode_keeps_requested_limits_intact() {
        let sample = LocalSystemSample {
            cpu_threads: 4,
            cpu_usage_pct: 88.0,
            total_memory_mib: 8_192,
            available_memory_mib: 700,
        };
        let mut stats = derive_stats_from_sample(sample, false);
        let mut request = base_request();
        request.override_mode = true;
        let mut warnings = Vec::new();

        let requested_rate = request.rate_limit_pps;
        let requested_gpu_rate = request.gpu_rate_pps;
        let requested_burst = request.burst_size;
        apply_request_governor(&mut request, &mut stats, &mut warnings)
            .expect("override mode should bypass local caps");

        assert_eq!(request.rate_limit_pps, requested_rate);
        assert_eq!(request.gpu_rate_pps, requested_gpu_rate);
        assert_eq!(request.burst_size, requested_burst);
        assert!(warnings
            .iter()
            .any(|warning| warning.contains("override mode active")));
    }
}

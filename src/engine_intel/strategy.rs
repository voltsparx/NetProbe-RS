// Strategy engine: chooses execution mode and performance tuning per scan.

use std::time::Duration;

use crate::engines::resource_governor;
use crate::models::{ScanProfile, ScanRequest};

#[allow(dead_code)] // used only by the tests and may not be referenced in a normal build
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExecutionMode {
    Async,
    Hybrid,
    PacketBlast,
}

impl ExecutionMode {
    pub fn as_str(self) -> &'static str {
        match self {
            ExecutionMode::Async => "async",
            ExecutionMode::Hybrid => "hybrid",
            ExecutionMode::PacketBlast => "packet-blast",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScanPersona {
    StealthSafe,
    PhantomMinimal,
    SarObserve,
    KisObserve,
    IdfFog,
    MirrorReflective,
    Discovery,
    Audit,
    MassScan,
}

impl ScanPersona {
    pub fn as_str(self) -> &'static str {
        match self {
            ScanPersona::StealthSafe => "stealth-safe",
            ScanPersona::PhantomMinimal => "phantom-minimal",
            ScanPersona::SarObserve => "sar-observe",
            ScanPersona::KisObserve => "kis-observe",
            ScanPersona::IdfFog => "idf-fog",
            ScanPersona::MirrorReflective => "mirror-reflective",
            ScanPersona::Discovery => "discovery",
            ScanPersona::Audit => "audit",
            ScanPersona::MassScan => "mass-scan",
        }
    }
}

#[derive(Debug, Clone)]
pub struct ScanStrategy {
    pub mode: ExecutionMode,
    pub persona: ScanPersona,
    pub resource_policy: String,
    pub rate_limit_pps: u32,
    pub burst_size: usize,
    pub max_retries: u8,
    pub recommended_concurrency: usize,
    pub recommended_timeout: Duration,
    pub recommended_delay: Duration,
    pub notes: Vec<String>,
}

pub fn plan(request: &ScanRequest, host_count: usize, port_count: usize) -> ScanStrategy {
    let protocol_multiplier = if request.include_udp { 2usize } else { 1usize };
    let probe_volume = host_count
        .max(1)
        .saturating_mul(port_count.max(1))
        .saturating_mul(protocol_multiplier);
    let packet_blast_allowed = request.effective_privileged_probes()
        && !request.strict_safety
        && !request.service_detection
        && !request.ping_scan;

    let mut mode = if request.ping_scan {
        ExecutionMode::Async
    } else {
        match request.profile {
            ScanProfile::Stealth => ExecutionMode::Async,
            ScanProfile::Phantom | ScanProfile::Sar | ScanProfile::Kis | ScanProfile::Idf => {
                ExecutionMode::Async
            }
            ScanProfile::Mirror => ExecutionMode::Hybrid,
            ScanProfile::Balanced => {
                if probe_volume >= 6_000 {
                    ExecutionMode::Hybrid
                } else {
                    ExecutionMode::Async
                }
            }
            ScanProfile::Turbo
            | ScanProfile::Aggressive
            | ScanProfile::RootOnly
            | ScanProfile::Hybrid => ExecutionMode::Hybrid,
        }
    };

    if request.strict_safety && mode == ExecutionMode::PacketBlast {
        mode = ExecutionMode::Hybrid;
    }

    let persona = if request.ping_scan {
        ScanPersona::Discovery
    } else {
        match request.profile {
            ScanProfile::Phantom => ScanPersona::PhantomMinimal,
            ScanProfile::Sar => ScanPersona::SarObserve,
            ScanProfile::Kis => ScanPersona::KisObserve,
            ScanProfile::Idf => ScanPersona::IdfFog,
            ScanProfile::Mirror => ScanPersona::MirrorReflective,
            _ => {
                if matches!(request.profile, ScanProfile::Stealth)
                    || request.strict_safety
                    || request.lab_mode
                {
                    ScanPersona::StealthSafe
                } else if request.lab_mode
                    && mode == ExecutionMode::PacketBlast
                    && probe_volume >= 200_000
                {
                    ScanPersona::MassScan
                } else if request.service_detection
                    && matches!(request.profile, ScanProfile::Aggressive)
                {
                    ScanPersona::Audit
                } else {
                    ScanPersona::Discovery
                }
            }
        }
    };

    let (mut rate_limit_pps, mut burst_size, mut max_retries) = match mode {
        ExecutionMode::Async => (2_400, 48, 1),
        ExecutionMode::Hybrid => (9_000, 160, 2),
        ExecutionMode::PacketBlast => (80_000, 1024, 1),
    };

    let mut recommended_concurrency = match mode {
        ExecutionMode::Async => 128,
        ExecutionMode::Hybrid => 320,
        ExecutionMode::PacketBlast => 768,
    };
    let mut recommended_timeout = match mode {
        ExecutionMode::Async => Duration::from_millis(1400),
        ExecutionMode::Hybrid => Duration::from_millis(950),
        ExecutionMode::PacketBlast => Duration::from_millis(700),
    };
    let mut recommended_delay = match mode {
        ExecutionMode::Async => Duration::from_millis(5),
        ExecutionMode::Hybrid => Duration::from_millis(1),
        ExecutionMode::PacketBlast => Duration::from_millis(0),
    };

    match persona {
        ScanPersona::StealthSafe => {
            rate_limit_pps = rate_limit_pps.min(2_000);
            burst_size = burst_size.min(64);
            max_retries = max_retries.max(2);
            recommended_delay = recommended_delay.max(Duration::from_millis(10));
            recommended_timeout = recommended_timeout.max(Duration::from_millis(1800));
            recommended_concurrency = recommended_concurrency.min(64);
        }
        ScanPersona::PhantomMinimal => {
            rate_limit_pps = 96;
            burst_size = 1;
            max_retries = 1;
            recommended_delay = Duration::from_millis(120);
            recommended_timeout = Duration::from_millis(2600);
            recommended_concurrency = 4;
        }
        ScanPersona::SarObserve => {
            rate_limit_pps = 144;
            burst_size = 2;
            max_retries = 1;
            recommended_delay = Duration::from_millis(80);
            recommended_timeout = Duration::from_millis(2400);
            recommended_concurrency = 6;
        }
        ScanPersona::KisObserve => {
            rate_limit_pps = 72;
            burst_size = 1;
            max_retries = 1;
            recommended_delay = Duration::from_millis(150);
            recommended_timeout = Duration::from_millis(3200);
            recommended_concurrency = 4;
        }
        ScanPersona::IdfFog => {
            rate_limit_pps = 48;
            burst_size = 1;
            max_retries = 1;
            recommended_delay = Duration::from_millis(180);
            recommended_timeout = Duration::from_millis(2800);
            recommended_concurrency = 2;
        }
        ScanPersona::MirrorReflective => {
            rate_limit_pps = rate_limit_pps.min(3_000);
            burst_size = burst_size.min(48);
            max_retries = max_retries.max(2);
            recommended_delay = recommended_delay.max(Duration::from_millis(12));
            recommended_timeout = recommended_timeout.max(Duration::from_millis(1400));
            recommended_concurrency = recommended_concurrency.min(64);
        }
        ScanPersona::Discovery => {
            rate_limit_pps = rate_limit_pps.min(20_000);
            burst_size = burst_size.min(256);
            recommended_concurrency = recommended_concurrency.min(256);
        }
        ScanPersona::Audit => {
            max_retries = max_retries.max(2);
            recommended_timeout = recommended_timeout.max(Duration::from_millis(900));
            recommended_concurrency = recommended_concurrency.min(512);
        }
        ScanPersona::MassScan => {
            rate_limit_pps = rate_limit_pps.max(100_000);
            burst_size = burst_size.max(1024);
            max_retries = max_retries.min(1);
            recommended_delay = Duration::ZERO;
        }
    }

    if request.ping_scan {
        rate_limit_pps = rate_limit_pps.min(256);
        burst_size = burst_size.min(8);
        max_retries = max_retries.max(2);
        recommended_delay = recommended_delay.max(Duration::from_millis(50));
        recommended_timeout = recommended_timeout.max(Duration::from_millis(1800));
        recommended_concurrency = recommended_concurrency.min(16);
    }

    if let Some(level) = request.timing_template {
        match level {
            0 => {
                mode = ExecutionMode::Async;
                rate_limit_pps = rate_limit_pps.min(12);
                burst_size = burst_size.min(1);
                max_retries = max_retries.max(3);
                recommended_delay = recommended_delay.max(Duration::from_millis(300));
                recommended_timeout = recommended_timeout.max(Duration::from_millis(5000));
                recommended_concurrency = recommended_concurrency.min(1);
            }
            1 => {
                mode = ExecutionMode::Async;
                rate_limit_pps = rate_limit_pps.min(48);
                burst_size = burst_size.min(2);
                max_retries = max_retries.max(3);
                recommended_delay = recommended_delay.max(Duration::from_millis(150));
                recommended_timeout = recommended_timeout.max(Duration::from_millis(4000));
                recommended_concurrency = recommended_concurrency.min(2);
            }
            2 => {
                mode = ExecutionMode::Async;
                rate_limit_pps = rate_limit_pps.min(256);
                burst_size = burst_size.min(8);
                max_retries = max_retries.max(2);
                recommended_delay = recommended_delay.max(Duration::from_millis(40));
                recommended_timeout = recommended_timeout.max(Duration::from_millis(2500));
                recommended_concurrency = recommended_concurrency.min(12);
            }
            3 => {}
            4 => {
                rate_limit_pps = rate_limit_pps.max(4_000);
                burst_size = burst_size.max(96);
                max_retries = max_retries.min(2);
                recommended_delay = recommended_delay.min(Duration::from_millis(1));
                recommended_timeout = recommended_timeout.min(Duration::from_millis(900));
                recommended_concurrency = recommended_concurrency.max(96);
            }
            5 => {
                rate_limit_pps = rate_limit_pps.max(12_000);
                burst_size = burst_size.max(192);
                max_retries = max_retries.min(1);
                recommended_delay = Duration::ZERO;
                recommended_timeout = recommended_timeout.min(Duration::from_millis(700));
                recommended_concurrency = recommended_concurrency.max(192);
            }
            _ => {}
        }
    }

    let resource_plan = resource_governor::plan(request.profile, mode, host_count, port_count);
    rate_limit_pps = rate_limit_pps.min(resource_plan.rate_cap_pps);
    burst_size = burst_size.min(resource_plan.burst_cap);
    recommended_concurrency = recommended_concurrency.min(resource_plan.concurrency_cap);

    if matches!(request.profile, ScanProfile::Stealth) {
        recommended_concurrency = recommended_concurrency.min(48);
        recommended_timeout = recommended_timeout.max(Duration::from_millis(2200));
        recommended_delay = recommended_delay.max(Duration::from_millis(20));
    }

    if request.lab_mode {
        recommended_concurrency = recommended_concurrency.min(192);
    }

    let notes = vec![
        format!(
            "strategy selected: mode={} persona={} (estimated probes={})",
            mode.as_str(),
            persona.as_str(),
            probe_volume
        ),
        format!(
            "hybrid fusion lane: {}",
            match mode {
                ExecutionMode::Async => {
                    "nmap-style controlled discovery and fingerprinting"
                }
                ExecutionMode::Hybrid => {
                    "masscan-style discovery front-end plus nmap-style service and OS correlation"
                }
                ExecutionMode::PacketBlast => {
                    "masscan-style raw discovery with later nmap-style knowledge follow-up disabled in this defensive mode"
                }
            }
        ),
        format!(
            "packet-blast allowed={} (privileged={} strict-safety={} service-detection={})",
            packet_blast_allowed,
            request.effective_privileged_probes(),
            request.strict_safety,
            request.service_detection
        ),
        "defensive balance policy: packet-blast scheduling is disabled; speed comes from controlled multi-host parallelism and hybrid async execution"
            .to_string(),
        format!(
            "resource governor: policy={} cpu_threads={} concurrency_cap={} rate_cap={}pps burst_cap={}",
            resource_plan.resource_policy,
            resource_plan.cpu_threads,
            resource_plan.concurrency_cap,
            resource_plan.rate_cap_pps,
            resource_plan.burst_cap
        ),
        format!(
            "rate target={}pps burst={} retries={}",
            rate_limit_pps, burst_size, max_retries
        ),
        format!(
            "timing template={}",
            request
                .timing_template
                .map(|level| format!("T{}", level))
                .unwrap_or_else(|| "default".to_string())
        ),
    ];

    ScanStrategy {
        mode,
        persona,
        resource_policy: resource_plan.resource_policy,
        rate_limit_pps,
        burst_size,
        max_retries,
        recommended_concurrency,
        recommended_timeout,
        recommended_delay,
        notes,
    }
}

pub fn apply_runtime_overrides(request: &mut ScanRequest, strategy: &ScanStrategy) {
    if request.concurrency.is_none() {
        request.concurrency = Some(strategy.recommended_concurrency);
    }

    if request.timeout_ms.is_none() {
        request.timeout_ms = Some(strategy.recommended_timeout.as_millis() as u64);
    }

    if request.delay_ms.is_none() {
        request.delay_ms = Some(strategy.recommended_delay.as_millis() as u64);
    }

    if request.rate_limit_pps.is_none() {
        request.rate_limit_pps = Some(strategy.rate_limit_pps);
    }

    if request.burst_size.is_none() {
        request.burst_size = Some(strategy.burst_size);
    }

    if request.max_retries.is_none() {
        request.max_retries = Some(strategy.max_retries);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{ReportFormat, ScanRequest};

    fn base_request() -> ScanRequest {
        ScanRequest {
            target: "127.0.0.1".to_string(),
            session_id: None,
            ports: vec![22, 80, 443],
            top_ports: None,
            ping_scan: false,
            traceroute: false,
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
            callback_ping: false,
            lab_mode: false,
            allow_external: false,
            strict_safety: false,
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
        }
    }

    #[test]
    fn large_volume_without_privileged_raw_path_prefers_hybrid() {
        let request = base_request();
        let strategy = plan(&request, 128, 512);
        assert_eq!(strategy.mode, ExecutionMode::Hybrid);
    }

    #[test]
    fn aggressive_profiles_stay_hybrid_under_defensive_balance_policy() {
        let mut request = base_request();
        request.privileged_probes = true;
        request.service_detection = false;
        request.profile = ScanProfile::Aggressive;
        let strategy = plan(&request, 256, 1024);
        assert_eq!(strategy.mode, ExecutionMode::Hybrid);
    }

    #[test]
    fn phantom_profile_stays_async_and_low_impact() {
        let mut request = base_request();
        request.profile = ScanProfile::Phantom;
        let strategy = plan(&request, 64, 128);
        assert_eq!(strategy.mode, ExecutionMode::Async);
        assert_eq!(strategy.persona, ScanPersona::PhantomMinimal);
        assert_eq!(strategy.burst_size, 1);
        assert_eq!(strategy.max_retries, 1);
    }

    #[test]
    fn idf_profile_stays_async_and_soft() {
        let mut request = base_request();
        request.profile = ScanProfile::Idf;
        request.lab_mode = true;
        request.strict_safety = true;
        let strategy = plan(&request, 16, 12);
        assert_eq!(strategy.mode, ExecutionMode::Async);
        assert_eq!(strategy.persona, ScanPersona::IdfFog);
        assert!(strategy.rate_limit_pps <= 64);
    }

    #[test]
    fn mirror_profile_prefers_hybrid_correlation() {
        let mut request = base_request();
        request.profile = ScanProfile::Mirror;
        let strategy = plan(&request, 32, 128);
        assert_eq!(strategy.mode, ExecutionMode::Hybrid);
        assert_eq!(strategy.persona, ScanPersona::MirrorReflective);
    }

    #[test]
    fn strict_safety_keeps_aggressive_profiles_out_of_packet_blast_mode() {
        let mut request = base_request();
        request.strict_safety = true;
        request.profile = ScanProfile::Aggressive;
        let strategy = plan(&request, 256, 1024);
        assert_ne!(strategy.mode, ExecutionMode::PacketBlast);
    }

    #[test]
    fn ping_scan_forces_async_discovery_envelope() {
        let mut request = base_request();
        request.ping_scan = true;
        request.profile = ScanProfile::Aggressive;
        request.service_detection = false;
        request.privileged_probes = true;
        let strategy = plan(&request, 32, 0);
        assert_eq!(strategy.mode, ExecutionMode::Async);
        assert_eq!(strategy.persona, ScanPersona::Discovery);
        assert!(strategy.rate_limit_pps <= 256);
    }

    #[test]
    fn timing_template_t4_raises_rate_floor() {
        let mut request = base_request();
        request.timing_template = Some(4);
        let strategy = plan(&request, 32, 128);
        assert!(strategy.rate_limit_pps >= 4_000);
        assert!(strategy.recommended_timeout <= Duration::from_millis(900));
        assert!(strategy
            .notes
            .iter()
            .any(|note| note.contains("timing template=T4")));
    }
}

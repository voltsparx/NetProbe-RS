// Strategy engine: chooses execution mode and performance tuning per scan.

use std::time::Duration;

use crate::models::{ScanProfile, ScanRequest};

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

#[derive(Debug, Clone)]
pub struct ScanStrategy {
    pub mode: ExecutionMode,
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

    let mut mode = match request.profile {
        ScanProfile::Stealth => ExecutionMode::Async,
        ScanProfile::Balanced => {
            if probe_volume >= 40_000 {
                ExecutionMode::PacketBlast
            } else if probe_volume >= 6_000 {
                ExecutionMode::Hybrid
            } else {
                ExecutionMode::Async
            }
        }
        ScanProfile::Turbo => {
            if probe_volume >= 22_000 {
                ExecutionMode::PacketBlast
            } else {
                ExecutionMode::Hybrid
            }
        }
        ScanProfile::Aggressive => ExecutionMode::PacketBlast,
        ScanProfile::RootOnly => {
            if probe_volume >= 14_000 {
                ExecutionMode::PacketBlast
            } else {
                ExecutionMode::Hybrid
            }
        }
    };

    if request.strict_safety && mode == ExecutionMode::PacketBlast {
        mode = ExecutionMode::Hybrid;
    }

    let (rate_limit_pps, burst_size, max_retries) = match mode {
        ExecutionMode::Async => (1_500, 32, 1),
        ExecutionMode::Hybrid => (6_000, 96, 2),
        ExecutionMode::PacketBlast => (20_000, 256, 1),
    };

    let mut recommended_concurrency = match mode {
        ExecutionMode::Async => 96,
        ExecutionMode::Hybrid => 256,
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
            "strategy selected: mode={} (estimated probes={})",
            mode.as_str(),
            probe_volume
        ),
        format!(
            "rate target={}pps burst={} retries={}",
            rate_limit_pps, burst_size, max_retries
        ),
    ];

    ScanStrategy {
        mode,
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
            ports: vec![22, 80, 443],
            top_ports: None,
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
            lab_mode: false,
            allow_external: false,
            strict_safety: false,
            output_path: None,
            lua_script: None,
            timeout_ms: None,
            concurrency: None,
            delay_ms: None,
            rate_limit_pps: None,
            burst_size: None,
            max_retries: None,
            total_shards: None,
            shard_index: None,
            scan_seed: None,
        }
    }

    #[test]
    fn large_volume_prefers_packet_blast() {
        let request = base_request();
        let strategy = plan(&request, 128, 512);
        assert_eq!(strategy.mode, ExecutionMode::PacketBlast);
    }

    #[test]
    fn strict_safety_blocks_packet_blast_mode() {
        let mut request = base_request();
        request.strict_safety = true;
        request.profile = ScanProfile::Aggressive;
        let strategy = plan(&request, 256, 1024);
        assert_ne!(strategy.mode, ExecutionMode::PacketBlast);
    }
}

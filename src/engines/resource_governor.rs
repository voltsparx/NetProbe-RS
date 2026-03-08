use crate::engine_intel::strategy::ExecutionMode;
use crate::models::ScanProfile;

#[derive(Debug, Clone)]
pub struct ResourceGovernorPlan {
    pub cpu_threads: usize,
    pub resource_policy: String,
    pub concurrency_cap: usize,
    pub rate_cap_pps: u32,
    pub burst_cap: usize,
}

pub fn plan(
    profile: ScanProfile,
    mode: ExecutionMode,
    host_count: usize,
    port_count: usize,
) -> ResourceGovernorPlan {
    let cpu_threads = std::thread::available_parallelism()
        .map(|value| value.get())
        .unwrap_or(4)
        .max(1);
    let scan_volume = host_count.max(1).saturating_mul(port_count.max(1));

    let host_pressure = if scan_volume >= 65_536 {
        3usize
    } else if scan_volume >= 16_384 {
        2
    } else {
        1
    };

    let cpu_factor = match cpu_threads {
        0..=2 => 2usize,
        3..=4 => 3,
        5..=8 => 5,
        9..=16 => 7,
        _ => 9,
    };

    let profile_factor = match profile {
        ScanProfile::Phantom => 1usize,
        ScanProfile::Kis => 1,
        ScanProfile::Idf => 1,
        ScanProfile::Sar => 2,
        ScanProfile::Stealth => 2,
        ScanProfile::Mirror => 3,
        ScanProfile::Balanced | ScanProfile::Hybrid => 4,
        ScanProfile::Turbo => 6,
        ScanProfile::Aggressive => 7,
        ScanProfile::RootOnly => 5,
    };

    let mode_factor = match mode {
        ExecutionMode::Async => 1usize,
        ExecutionMode::Hybrid => 2,
        ExecutionMode::PacketBlast => 2,
    };

    let concurrency_cap = (cpu_factor * profile_factor * mode_factor * host_pressure).clamp(4, 512);

    let rate_cap_pps = match profile {
        ScanProfile::Phantom => 128,
        ScanProfile::Kis => 96,
        ScanProfile::Idf => 64,
        ScanProfile::Sar => 180,
        ScanProfile::Stealth => (cpu_threads as u32 * 450).clamp(600, 4_000),
        ScanProfile::Mirror => (cpu_threads as u32 * 650).clamp(1_200, 6_000),
        ScanProfile::Balanced | ScanProfile::Hybrid => {
            (cpu_threads as u32 * 1_200).clamp(2_000, 14_000)
        }
        ScanProfile::Turbo => (cpu_threads as u32 * 1_600).clamp(4_000, 18_000),
        ScanProfile::Aggressive => (cpu_threads as u32 * 1_900).clamp(5_000, 22_000),
        ScanProfile::RootOnly => (cpu_threads as u32 * 900).clamp(2_000, 10_000),
    };

    let burst_cap = match profile {
        ScanProfile::Phantom | ScanProfile::Kis | ScanProfile::Idf => 1,
        ScanProfile::Sar => 2,
        ScanProfile::Stealth => 24,
        ScanProfile::Mirror => (cpu_threads * 8).clamp(16, 64),
        ScanProfile::Balanced | ScanProfile::Hybrid => (cpu_threads * 12).clamp(32, 192),
        ScanProfile::Turbo | ScanProfile::Aggressive => (cpu_threads * 16).clamp(48, 256),
        ScanProfile::RootOnly => (cpu_threads * 10).clamp(24, 128),
    };

    let resource_policy = match profile {
        ScanProfile::Phantom | ScanProfile::Kis | ScanProfile::Sar | ScanProfile::Idf => {
            format!("tbns-low-impact/cpu{cpu_threads}")
        }
        ScanProfile::Stealth => format!("cautious-parallel/cpu{cpu_threads}"),
        ScanProfile::Mirror => format!("reflective-hybrid/cpu{cpu_threads}"),
        ScanProfile::Balanced | ScanProfile::Hybrid => {
            format!("balanced-multi-host/cpu{cpu_threads}")
        }
        ScanProfile::Turbo | ScanProfile::Aggressive => {
            format!("high-coverage-hybrid/cpu{cpu_threads}")
        }
        ScanProfile::RootOnly => format!("privileged-controlled/cpu{cpu_threads}"),
    };

    ResourceGovernorPlan {
        cpu_threads,
        resource_policy,
        concurrency_cap,
        rate_cap_pps,
        burst_cap,
    }
}

#[cfg(test)]
mod tests {
    use super::plan;
    use crate::engine_intel::strategy::ExecutionMode;
    use crate::models::ScanProfile;

    #[test]
    fn tbns_profiles_stay_tightly_capped() {
        let plan = plan(ScanProfile::Phantom, ExecutionMode::Async, 32, 32);
        assert!(plan.rate_cap_pps <= 128);
        assert_eq!(plan.burst_cap, 1);
    }

    #[test]
    fn balanced_profile_gets_multi_host_policy() {
        let plan = plan(ScanProfile::Balanced, ExecutionMode::Hybrid, 256, 256);
        assert!(plan.concurrency_cap >= 16);
        assert!(plan.resource_policy.contains("balanced-multi-host"));
    }
}

use std::time::Duration;

use crate::engine_intel::device_profile::DeviceClass;
use crate::models::ScanProfile;

#[derive(Debug, Clone)]
pub struct BioResponseDecision {
    pub stage: String,
    pub rate_cap_pps: u32,
    pub concurrency_cap: usize,
    pub delay_floor: Duration,
    pub service_detection_allowed: bool,
    pub notes: Vec<String>,
}

pub fn decide(
    profile: ScanProfile,
    strict_safety: bool,
    device_class: Option<DeviceClass>,
    requested_rate_pps: u32,
    requested_concurrency: usize,
    requested_delay: Duration,
) -> BioResponseDecision {
    let mut rate_cap_pps = requested_rate_pps.max(1);
    let mut concurrency_cap = requested_concurrency.max(1);
    let mut delay_floor = requested_delay;
    let mut service_detection_allowed = true;
    let mut notes = Vec::new();

    match profile {
        ScanProfile::Phantom => {
            rate_cap_pps = rate_cap_pps.min(96);
            concurrency_cap = concurrency_cap.min(4);
            delay_floor = delay_floor.max(Duration::from_millis(120));
            service_detection_allowed = false;
            notes.push(
                "bio-response: phantom profile locked to first-touch pacing for least-contact discovery"
                    .to_string(),
            );
        }
        ScanProfile::Kis => {
            rate_cap_pps = rate_cap_pps.min(72);
            concurrency_cap = concurrency_cap.min(4);
            delay_floor = delay_floor.max(Duration::from_millis(150));
            service_detection_allowed = false;
            notes.push(
                "bio-response: kis profile stayed in timing-observation mode and withheld deeper service probes"
                    .to_string(),
            );
        }
        ScanProfile::Sar => {
            rate_cap_pps = rate_cap_pps.min(144);
            concurrency_cap = concurrency_cap.min(6);
            delay_floor = delay_floor.max(Duration::from_millis(80));
            service_detection_allowed = false;
            notes.push(
                "bio-response: sar profile stayed in response-shape observation mode with reduced follow-up depth"
                    .to_string(),
            );
        }
        ScanProfile::Stealth => {
            rate_cap_pps = rate_cap_pps.min(2_000);
            concurrency_cap = concurrency_cap.min(48);
            delay_floor = delay_floor.max(Duration::from_millis(20));
        }
        ScanProfile::Balanced | ScanProfile::Hybrid => {
            rate_cap_pps = rate_cap_pps.min(8_000);
            concurrency_cap = concurrency_cap.min(96);
        }
        ScanProfile::Turbo => {
            rate_cap_pps = rate_cap_pps.min(12_000);
            concurrency_cap = concurrency_cap.min(160);
        }
        ScanProfile::Aggressive => {
            rate_cap_pps = rate_cap_pps.min(14_000);
            concurrency_cap = concurrency_cap.min(192);
        }
        ScanProfile::RootOnly => {
            rate_cap_pps = rate_cap_pps.min(6_000);
            concurrency_cap = concurrency_cap.min(72);
        }
    }

    match device_class {
        Some(DeviceClass::FragileEmbedded) => {
            rate_cap_pps = rate_cap_pps.min(64);
            concurrency_cap = concurrency_cap.min(2);
            delay_floor = delay_floor.max(Duration::from_millis(180));
            service_detection_allowed = false;
            notes.push(
                "bio-response: fragile embedded target forced soft-touch mode to avoid stressing low-power hardware"
                    .to_string(),
            );
        }
        Some(DeviceClass::PrinterSensitive) => {
            rate_cap_pps = rate_cap_pps.min(96);
            concurrency_cap = concurrency_cap.min(4);
            delay_floor = delay_floor.max(Duration::from_millis(120));
            service_detection_allowed = false;
            notes.push(
                "bio-response: printer-sensitive target kept on conservative pacing and passive follow-up"
                    .to_string(),
            );
        }
        Some(DeviceClass::Enterprise) => {
            notes.push(
                "bio-response: enterprise-class target remained eligible for broader but still controlled coverage"
                    .to_string(),
            );
        }
        Some(DeviceClass::Generic) => {
            notes.push(
                "bio-response: generic target classification kept the scan in a balanced but still cautious envelope"
                    .to_string(),
            );
        }
        None => {
            notes.push(
                "bio-response: target classification remained unknown, so the governor preserved conservative assumptions"
                    .to_string(),
            );
        }
    }

    if strict_safety {
        rate_cap_pps = rate_cap_pps.min(250);
        concurrency_cap = concurrency_cap.min(8);
        delay_floor = delay_floor.max(Duration::from_millis(40));
        if !matches!(device_class, Some(DeviceClass::Enterprise)) {
            service_detection_allowed = false;
        }
        notes.push(
            "bio-response: strict-safety tightened host concurrency and rate caps until resilience evidence was stronger"
                .to_string(),
        );
    }

    let stage = if rate_cap_pps <= 128 {
        "soft"
    } else if rate_cap_pps <= 2_000 {
        "guarded"
    } else {
        "balanced"
    };

    BioResponseDecision {
        stage: stage.to_string(),
        rate_cap_pps,
        concurrency_cap,
        delay_floor,
        service_detection_allowed,
        notes,
    }
}

#[cfg(test)]
mod tests {
    use super::decide;
    use crate::engine_intel::device_profile::DeviceClass;
    use crate::models::ScanProfile;
    use std::time::Duration;

    #[test]
    fn fragile_devices_force_soft_mode() {
        let decision = decide(
            ScanProfile::Balanced,
            false,
            Some(DeviceClass::FragileEmbedded),
            8_000,
            64,
            Duration::ZERO,
        );
        assert_eq!(decision.stage, "soft");
        assert!(decision.rate_cap_pps <= 64);
        assert!(!decision.service_detection_allowed);
    }

    #[test]
    fn enterprise_targets_can_stay_balanced() {
        let decision = decide(
            ScanProfile::Balanced,
            false,
            Some(DeviceClass::Enterprise),
            8_000,
            128,
            Duration::from_millis(5),
        );
        assert_eq!(decision.stage, "balanced");
        assert!(decision.rate_cap_pps >= 2_000);
    }
}

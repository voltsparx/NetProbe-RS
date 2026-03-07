use std::io;
use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, Instant};

use tokio::net::TcpStream;
use tokio::time::timeout;

use crate::engine_intel::device_profile::DeviceClass;
use crate::models::{PhantomDeviceCheckSummary, ScanProfile};

#[derive(Debug, Clone)]
pub struct PhantomPreflightDecision {
    pub stage: String,
    pub sampled_ports: Vec<u16>,
    pub responsive_ports: usize,
    pub timeout_ports: usize,
    pub avg_latency_ms: Option<u64>,
    pub rate_cap_pps: u32,
    pub concurrency_cap: usize,
    pub delay_floor: Duration,
    pub fingerprint_payload_budget: usize,
    pub service_detection_allowed: bool,
    pub notes: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct PhantomPreflightInput<'a> {
    pub target: IpAddr,
    pub ports: &'a [u16],
    pub requested_timeout: Duration,
    pub requested_rate_pps: u32,
    pub requested_concurrency: usize,
    pub requested_delay: Duration,
    pub service_detection_requested: bool,
    pub strict_safety: bool,
    pub profile: ScanProfile,
    pub device_class: Option<DeviceClass>,
}

#[derive(Debug, Clone)]
pub struct PhantomPreflightPreview {
    pub sample_budget: usize,
    pub initial_payload_budget: usize,
    pub strict_safety: bool,
    pub notes: Vec<String>,
}

#[derive(Debug, Clone)]
struct Observation {
    port: u16,
    outcome: ObservationOutcome,
}

#[derive(Debug, Clone, Copy)]
enum ObservationOutcome {
    Responsive(Duration),
    Timeout,
    Error,
}

pub async fn run(input: PhantomPreflightInput<'_>) -> PhantomPreflightDecision {
    let PhantomPreflightInput {
        target,
        ports,
        requested_timeout,
        requested_rate_pps,
        requested_concurrency,
        requested_delay,
        service_detection_requested,
        strict_safety,
        profile,
        device_class,
    } = input;

    let sample_budget = sample_budget(profile, device_class);
    let sampled_ports = sample_ports(ports, sample_budget);
    if sampled_ports.is_empty() {
        return PhantomPreflightDecision {
            stage: "guarded".to_string(),
            sampled_ports,
            responsive_ports: 0,
            timeout_ports: 0,
            avg_latency_ms: None,
            rate_cap_pps: requested_rate_pps.max(1),
            concurrency_cap: requested_concurrency.max(1),
            delay_floor: requested_delay,
            fingerprint_payload_budget: 1,
            service_detection_allowed: false,
            notes: vec![
                "phantom preflight skipped because the host had no candidate ports to sample"
                    .to_string(),
            ],
        };
    }

    let timeout_value =
        requested_timeout.clamp(Duration::from_millis(220), Duration::from_millis(900));
    let inter_probe_delay = requested_delay.max(preflight_delay(profile, device_class));
    let mut observations = Vec::with_capacity(sampled_ports.len());

    for (index, port) in sampled_ports.iter().copied().enumerate() {
        let outcome = observe_port(target, port, timeout_value).await;
        observations.push(Observation { port, outcome });
        if index + 1 < sampled_ports.len() && !inter_probe_delay.is_zero() {
            tokio::time::sleep(inter_probe_delay).await;
        }
    }

    derive_decision(
        sampled_ports,
        observations,
        requested_rate_pps,
        requested_concurrency,
        requested_delay,
        service_detection_requested,
        strict_safety,
        profile,
        device_class,
    )
}

pub fn preview(
    profile: ScanProfile,
    port_count: usize,
    strict_safety: bool,
    service_detection_requested: bool,
) -> PhantomPreflightPreview {
    let sample_budget = sample_budget(profile, None).min(port_count.max(1));
    let initial_payload_budget = match profile {
        ScanProfile::Phantom => 0,
        ScanProfile::Kis | ScanProfile::Sar => 1,
        ScanProfile::Stealth => 2,
        ScanProfile::Balanced | ScanProfile::Turbo | ScanProfile::Aggressive => 4,
        ScanProfile::RootOnly => 3,
    };
    let mut notes = vec![format!(
        "Every host starts with Phantom device-check: up to {} low-contact checks before the main scan chooses rate, delay, and follow-up depth.",
        sample_budget
    )];
    if strict_safety {
        notes.push(
            "Strict safety is on, so the device-check will keep unknown or unstable hosts in a softer envelope."
                .to_string(),
        );
    }
    if !service_detection_requested {
        notes.push(
            "Service follow-up starts passive for this run; Phantom still decides whether the host looks stable enough for later enrichment."
                .to_string(),
        );
    } else {
        notes.push(format!(
            "If the host looks resilient, active follow-up payloads can use a budget up to {} after the device check.",
            initial_payload_budget
        ));
    }

    PhantomPreflightPreview {
        sample_budget,
        initial_payload_budget,
        strict_safety,
        notes,
    }
}

impl PhantomPreflightDecision {
    pub fn summary(&self) -> PhantomDeviceCheckSummary {
        PhantomDeviceCheckSummary {
            stage: self.stage.clone(),
            responsive_ports: Some(self.responsive_ports),
            sampled_ports: Some(self.sampled_ports.len()),
            timeout_ports: Some(self.timeout_ports),
            avg_latency_ms: self.avg_latency_ms,
            payload_budget: Some(self.fingerprint_payload_budget),
            passive_follow_up: !self.service_detection_allowed,
        }
    }
}

async fn observe_port(target: IpAddr, port: u16, timeout_value: Duration) -> ObservationOutcome {
    let start = Instant::now();
    match timeout(
        timeout_value,
        TcpStream::connect(SocketAddr::new(target, port)),
    )
    .await
    {
        Ok(Ok(_)) => ObservationOutcome::Responsive(start.elapsed()),
        Ok(Err(err)) => match err.kind() {
            io::ErrorKind::ConnectionRefused => ObservationOutcome::Responsive(start.elapsed()),
            io::ErrorKind::TimedOut
            | io::ErrorKind::ConnectionAborted
            | io::ErrorKind::ConnectionReset
            | io::ErrorKind::HostUnreachable
            | io::ErrorKind::NetworkUnreachable => ObservationOutcome::Timeout,
            _ => ObservationOutcome::Error,
        },
        Err(_) => ObservationOutcome::Timeout,
    }
}

#[allow(clippy::too_many_arguments)]
fn derive_decision(
    sampled_ports: Vec<u16>,
    observations: Vec<Observation>,
    requested_rate_pps: u32,
    requested_concurrency: usize,
    requested_delay: Duration,
    service_detection_requested: bool,
    strict_safety: bool,
    profile: ScanProfile,
    device_class: Option<DeviceClass>,
) -> PhantomPreflightDecision {
    let responsive_latencies = observations
        .iter()
        .filter_map(|observation| match observation.outcome {
            ObservationOutcome::Responsive(latency) => Some(latency),
            ObservationOutcome::Timeout | ObservationOutcome::Error => None,
        })
        .collect::<Vec<_>>();
    let responsive_ports = responsive_latencies.len();
    let timeout_ports = observations
        .iter()
        .filter(|observation| matches!(observation.outcome, ObservationOutcome::Timeout))
        .count();
    let error_ports = observations
        .iter()
        .filter(|observation| matches!(observation.outcome, ObservationOutcome::Error))
        .count();
    let avg_latency_ms = if responsive_latencies.is_empty() {
        None
    } else {
        Some(
            responsive_latencies
                .iter()
                .map(|latency| latency.as_millis() as u64)
                .sum::<u64>()
                / responsive_latencies.len() as u64,
        )
    };
    let sample_count = observations.len().max(1);
    let response_ratio = responsive_ports as f64 / sample_count as f64;
    let avg_latency = avg_latency_ms.unwrap_or(u64::MAX);

    let mut notes = vec![format!(
        "phantom preflight sampled ports {:?}: responsive={} timeout={} error={} avg-latency={}ms",
        sampled_ports,
        responsive_ports,
        timeout_ports,
        error_ports,
        avg_latency_ms
            .map(|latency| latency.to_string())
            .unwrap_or_else(|| "n/a".to_string())
    )];
    if timeout_ports > 0 {
        let timed_out_ports = observations
            .iter()
            .filter_map(|observation| {
                if matches!(observation.outcome, ObservationOutcome::Timeout) {
                    Some(observation.port)
                } else {
                    None
                }
            })
            .collect::<Vec<_>>();
        notes.push(format!(
            "phantom preflight held the host in a safer envelope because ports {:?} did not answer within the preflight window",
            timed_out_ports
        ));
    }

    let force_soft = matches!(
        device_class,
        Some(DeviceClass::FragileEmbedded) | Some(DeviceClass::PrinterSensitive)
    ) || matches!(profile, ScanProfile::Phantom | ScanProfile::Kis)
        || responsive_ports == 0
        || timeout_ports >= sample_count.saturating_sub(1);

    let mut stage = if force_soft {
        "soft"
    } else if strict_safety
        || response_ratio < 0.70
        || avg_latency > 180
        || error_ports > 0
        || matches!(profile, ScanProfile::Sar | ScanProfile::Stealth)
    {
        "guarded"
    } else {
        "balanced"
    };

    if matches!(device_class, Some(DeviceClass::Enterprise))
        && stage == "guarded"
        && !strict_safety
        && response_ratio >= 1.0
        && avg_latency <= 120
        && error_ports == 0
    {
        stage = "balanced";
    }

    let (stage_rate_pps, stage_concurrency, stage_delay, stage_payload_budget, stage_services) =
        match stage {
            "soft" => match device_class {
                Some(DeviceClass::FragileEmbedded) => {
                    (48_u32, 2_usize, Duration::from_millis(180), 0_usize, false)
                }
                Some(DeviceClass::PrinterSensitive) => {
                    (72_u32, 4_usize, Duration::from_millis(120), 0_usize, false)
                }
                Some(DeviceClass::Enterprise) => {
                    (160_u32, 6_usize, Duration::from_millis(90), 1_usize, false)
                }
                Some(DeviceClass::Generic) | None => {
                    (96_u32, 4_usize, Duration::from_millis(90), 0_usize, false)
                }
            },
            "guarded" => match device_class {
                Some(DeviceClass::FragileEmbedded) => {
                    (64_u32, 2_usize, Duration::from_millis(180), 0_usize, false)
                }
                Some(DeviceClass::PrinterSensitive) => {
                    (96_u32, 4_usize, Duration::from_millis(120), 0_usize, false)
                }
                Some(DeviceClass::Enterprise) => (
                    2_000_u32,
                    24_usize,
                    Duration::from_millis(20),
                    2_usize,
                    service_detection_requested && !strict_safety,
                ),
                Some(DeviceClass::Generic) | None => {
                    (480_u32, 12_usize, Duration::from_millis(35), 1_usize, false)
                }
            },
            _ => match device_class {
                Some(DeviceClass::Enterprise) => (
                    4_000_u32,
                    48_usize,
                    Duration::from_millis(5),
                    4_usize,
                    service_detection_requested,
                ),
                Some(DeviceClass::FragileEmbedded) => {
                    (64_u32, 2_usize, Duration::from_millis(180), 0_usize, false)
                }
                Some(DeviceClass::PrinterSensitive) => {
                    (120_u32, 6_usize, Duration::from_millis(80), 1_usize, false)
                }
                Some(DeviceClass::Generic) | None => (
                    1_200_u32,
                    16_usize,
                    Duration::from_millis(12),
                    2_usize,
                    service_detection_requested && !strict_safety,
                ),
            },
        };

    let profile_payload_budget = match profile {
        ScanProfile::Phantom => 0,
        ScanProfile::Kis => 1,
        ScanProfile::Sar => 1,
        ScanProfile::Stealth => 2,
        ScanProfile::Balanced | ScanProfile::Turbo | ScanProfile::Aggressive => 4,
        ScanProfile::RootOnly => 3,
    };

    let rate_cap_pps = requested_rate_pps.max(1).min(stage_rate_pps.max(1));
    let concurrency_cap = requested_concurrency.max(1).min(stage_concurrency.max(1));
    let delay_floor = requested_delay.max(stage_delay);
    let fingerprint_payload_budget = stage_payload_budget.min(profile_payload_budget);
    let service_detection_allowed = service_detection_requested && stage_services;

    notes.push(format!(
        "phantom preflight stage={} rate<={}pps concurrency<={} delay>={}ms payload-budget={} service-detection={}",
        stage,
        rate_cap_pps,
        concurrency_cap,
        delay_floor.as_millis(),
        fingerprint_payload_budget,
        if service_detection_allowed {
            "enabled"
        } else {
            "held"
        }
    ));

    PhantomPreflightDecision {
        stage: stage.to_string(),
        sampled_ports,
        responsive_ports,
        timeout_ports,
        avg_latency_ms,
        rate_cap_pps,
        concurrency_cap,
        delay_floor,
        fingerprint_payload_budget,
        service_detection_allowed,
        notes,
    }
}

fn sample_budget(profile: ScanProfile, device_class: Option<DeviceClass>) -> usize {
    match (profile, device_class) {
        (ScanProfile::Phantom | ScanProfile::Kis, _) => 2,
        (_, Some(DeviceClass::FragileEmbedded) | Some(DeviceClass::PrinterSensitive)) => 2,
        (_, Some(DeviceClass::Enterprise)) => 4,
        _ => 3,
    }
}

fn preflight_delay(profile: ScanProfile, device_class: Option<DeviceClass>) -> Duration {
    match (profile, device_class) {
        (_, Some(DeviceClass::FragileEmbedded)) => Duration::from_millis(60),
        (_, Some(DeviceClass::PrinterSensitive)) => Duration::from_millis(45),
        (ScanProfile::Phantom | ScanProfile::Kis, _) => Duration::from_millis(35),
        _ => Duration::from_millis(15),
    }
}

fn sample_ports(ports: &[u16], sample_budget: usize) -> Vec<u16> {
    if ports.is_empty() || sample_budget == 0 {
        return Vec::new();
    }
    if ports.len() <= sample_budget {
        return ports.to_vec();
    }

    let mut sampled = Vec::with_capacity(sample_budget);
    let last_index = ports.len() - 1;
    let indexes = match sample_budget {
        1 => vec![0],
        2 => vec![0, last_index],
        3 => vec![0, ports.len() / 2, last_index],
        _ => vec![0, ports.len() / 3, (ports.len() * 2) / 3, last_index],
    };

    for index in indexes {
        let port = ports[index];
        if !sampled.contains(&port) {
            sampled.push(port);
        }
    }

    if sampled.len() < sample_budget {
        for port in ports {
            if !sampled.contains(port) {
                sampled.push(*port);
                if sampled.len() == sample_budget {
                    break;
                }
            }
        }
    }

    sampled
}

#[cfg(test)]
mod tests {
    use super::{derive_decision, sample_ports, Observation, ObservationOutcome};
    use crate::engine_intel::device_profile::DeviceClass;
    use crate::models::ScanProfile;
    use std::time::Duration;

    #[test]
    fn sample_ports_spreads_across_target_scope() {
        let ports = vec![22, 53, 80, 135, 443, 445, 3389];
        let sampled = sample_ports(&ports, 3);
        assert_eq!(sampled, vec![22, 135, 3389]);
    }

    #[test]
    fn all_timeouts_force_soft_mode() {
        let decision = derive_decision(
            vec![22, 80, 443],
            vec![
                Observation {
                    port: 22,
                    outcome: ObservationOutcome::Timeout,
                },
                Observation {
                    port: 80,
                    outcome: ObservationOutcome::Timeout,
                },
                Observation {
                    port: 443,
                    outcome: ObservationOutcome::Timeout,
                },
            ],
            8_000,
            128,
            Duration::ZERO,
            true,
            false,
            ScanProfile::Balanced,
            None,
        );
        assert_eq!(decision.stage, "soft");
        assert!(decision.rate_cap_pps <= 96);
        assert_eq!(decision.fingerprint_payload_budget, 0);
        assert!(!decision.service_detection_allowed);
    }

    #[test]
    fn enterprise_fast_responses_can_stay_balanced() {
        let decision = derive_decision(
            vec![22, 80, 443, 8443],
            vec![
                Observation {
                    port: 22,
                    outcome: ObservationOutcome::Responsive(Duration::from_millis(24)),
                },
                Observation {
                    port: 80,
                    outcome: ObservationOutcome::Responsive(Duration::from_millis(26)),
                },
                Observation {
                    port: 443,
                    outcome: ObservationOutcome::Responsive(Duration::from_millis(28)),
                },
                Observation {
                    port: 8443,
                    outcome: ObservationOutcome::Responsive(Duration::from_millis(30)),
                },
            ],
            8_000,
            128,
            Duration::from_millis(1),
            true,
            false,
            ScanProfile::Balanced,
            Some(DeviceClass::Enterprise),
        );
        assert_eq!(decision.stage, "balanced");
        assert!(decision.rate_cap_pps >= 4_000);
        assert_eq!(decision.fingerprint_payload_budget, 4);
        assert!(decision.service_detection_allowed);
    }
}

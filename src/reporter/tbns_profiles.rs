use crate::models::{HostResult, PortState, ScanProfile};

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct PortStateCounts {
    open: usize,
    closed: usize,
    filtered: usize,
    unfiltered: usize,
    open_or_filtered: usize,
}

impl PortStateCounts {
    fn observed_ports(self) -> usize {
        self.open + self.closed + self.filtered + self.unfiltered + self.open_or_filtered
    }

    fn responsive_ports(self) -> usize {
        self.open + self.closed + self.unfiltered
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct LatencyBand {
    samples: usize,
    min_ms: u128,
    max_ms: u128,
    avg_ms: u128,
    span_ms: u128,
}

pub fn annotate_host(profile: ScanProfile, callback_ping: bool, host: &mut HostResult) {
    match profile {
        ScanProfile::Phantom => annotate_phantom(host),
        ScanProfile::Kis => annotate_kis(host),
        ScanProfile::Sar => annotate_sar(host),
        ScanProfile::Idf => annotate_idf(host),
        _ => {}
    }

    if callback_ping {
        annotate_callback_ping(host);
    }
}

fn annotate_phantom(host: &mut HostResult) {
    let Some(summary) = host.phantom_device_check_summary() else {
        return;
    };

    host.insights.push(format!(
        "phantom device-check: '{}' envelope after {} of {} low-contact replies",
        summary.stage,
        summary.responsive_ports.unwrap_or(0),
        summary.sampled_ports.unwrap_or(0)
    ));
}

fn annotate_kis(host: &mut HostResult) {
    let counts = collect_port_state_counts(host);
    if let Some(latency_band) = observe_latency_band(host) {
        host.insights.push(format!(
            "kis identity hints: {} latency band across {} reply samples ({}-{} ms, avg {} ms)",
            classify_latency_band(latency_band),
            latency_band.samples,
            latency_band.min_ms,
            latency_band.max_ms,
            latency_band.avg_ms
        ));
    } else if counts.responsive_ports() > 0 {
        host.insights.push(format!(
            "kis identity hints: {} responsive replies were observed on the guarded lane, but no stable per-port latency samples were available",
            counts.responsive_ports()
        ));
    }

    if let Some(operating_system) = host.operating_system.as_ref() {
        host.learning_notes.push(format!(
            "Learning: KIS stayed passive and correlated timing hints with the '{}' profile guess from {}.",
            operating_system.label, operating_system.source
        ));
    } else {
        host.learning_notes.push(
            "Learning: KIS in this build is a timing-observation profile. It derives cautious identity hints from reply cadence instead of forcing deeper active fingerprint probes."
                .to_string(),
        );
    }
}

fn annotate_sar(host: &mut HostResult) {
    let counts = collect_port_state_counts(host);
    if counts.observed_ports() == 0 {
        return;
    }

    host.insights.push(format!(
        "sar response-shape: {} (open={} closed={} filtered={} unfiltered={} open|filtered={})",
        classify_response_shape(counts),
        counts.open,
        counts.closed,
        counts.filtered,
        counts.unfiltered,
        counts.open_or_filtered
    ));
    host.learning_notes.push(
        "Learning: SAR in this build is observational. It summarizes how the target replied under low pressure instead of throttling or modifying third-party traffic."
            .to_string(),
    );
}

fn annotate_idf(host: &mut HostResult) {
    host.insights.push(format!(
        "idf sparse sampling: {} checkpoint(s) recorded inside the guarded port budget",
        host.ports.len()
    ));
    host.learning_notes.push(
        "Learning: IDF in this build means sparse sampling, diffused port order, and strict pacing only. It does not emit synthetic fog packets, spoofed traffic, or malformed decoys."
            .to_string(),
    );
}

fn annotate_callback_ping(host: &mut HostResult) {
    let counts = collect_port_state_counts(host);
    let icmp_confirmed = host
        .insights
        .iter()
        .any(|insight| insight.starts_with("icmp reachability confirmed"));
    let arp_confirmed = host
        .insights
        .iter()
        .any(|insight| insight.starts_with("arp neighbor:"));
    let tcp_confirmed = host
        .insights
        .iter()
        .any(|insight| insight.starts_with("tcp discovery:"));
    let primary_lane_confirmed = arp_confirmed || tcp_confirmed || counts.responsive_ports() > 0;

    if icmp_confirmed {
        let classification = if primary_lane_confirmed {
            "standard-stack"
        } else {
            "icmp-only"
        };
        host.insights.push(format!(
            "callback ping classification: {classification} guarded confirmation"
        ));
        host.learning_notes.push(
            "Learning: callback ping here is a bounded post-discovery confirmation on the fetcher plane, not a reflex injection path."
                .to_string(),
        );
    } else if primary_lane_confirmed {
        host.insights.push(
            "callback ping classification: guarded lane stayed quiet while the primary discovery lane still answered"
                .to_string(),
        );
        host.learning_notes.push(
            "Learning: asymmetric callback results usually mean ICMP was filtered or deprioritized while TCP or ARP still provided host-up evidence."
                .to_string(),
        );
    } else {
        host.learning_notes.push(
            "Learning: callback ping remains intentionally low-impact in this build, so a negative result is treated as inconclusive rather than forced with extra traffic."
                .to_string(),
        );
    }
}

fn collect_port_state_counts(host: &HostResult) -> PortStateCounts {
    let mut counts = PortStateCounts::default();
    for port in &host.ports {
        match port.state {
            PortState::Open => counts.open += 1,
            PortState::Closed => counts.closed += 1,
            PortState::Filtered => counts.filtered += 1,
            PortState::Unfiltered => counts.unfiltered += 1,
            PortState::OpenOrFiltered => counts.open_or_filtered += 1,
        }
    }
    counts
}

fn observe_latency_band(host: &HostResult) -> Option<LatencyBand> {
    let mut samples = 0usize;
    let mut min_ms = u128::MAX;
    let mut max_ms = 0u128;
    let mut sum_ms = 0u128;

    for latency_ms in host.ports.iter().filter_map(|port| port.latency_ms) {
        samples += 1;
        min_ms = min_ms.min(latency_ms);
        max_ms = max_ms.max(latency_ms);
        sum_ms = sum_ms.saturating_add(latency_ms);
    }

    if samples == 0 {
        return None;
    }

    let avg_ms = sum_ms / samples as u128;
    Some(LatencyBand {
        samples,
        min_ms,
        max_ms,
        avg_ms,
        span_ms: max_ms.saturating_sub(min_ms),
    })
}

fn classify_latency_band(latency_band: LatencyBand) -> &'static str {
    if latency_band.span_ms <= 8 {
        "steady"
    } else if latency_band.span_ms <= 35 {
        "mixed"
    } else {
        "bursty"
    }
}

fn classify_response_shape(counts: PortStateCounts) -> &'static str {
    if counts.filtered + counts.open_or_filtered >= counts.open + counts.closed
        && (counts.filtered + counts.open_or_filtered) > 0
    {
        "drop-heavy"
    } else if counts.closed + counts.unfiltered > counts.open {
        "rejective"
    } else if counts.open > 0 && counts.filtered > 0 {
        "mixed-guarded"
    } else if counts.open > 0 {
        "service-forward"
    } else {
        "low-signal"
    }
}

#[cfg(test)]
mod tests {
    use super::annotate_host;
    use crate::models::{HostOsGuess, HostResult, PortFinding, PortState, ScanProfile};

    fn host_with_ports(ports: Vec<PortFinding>) -> HostResult {
        HostResult {
            target: "example".to_string(),
            ip: "10.0.0.7".to_string(),
            reverse_dns: None,
            observed_mac: None,
            device_class: None,
            device_vendor: None,
            operating_system: None,
            phantom_device_check: None,
            safety_actions: Vec::new(),
            warnings: Vec::new(),
            ports,
            risk_score: 0,
            insights: Vec::new(),
            defensive_advice: Vec::new(),
            learning_notes: Vec::new(),
            lua_findings: Vec::new(),
        }
    }

    fn port(port: u16, state: PortState, latency_ms: Option<u128>) -> PortFinding {
        PortFinding {
            port,
            protocol: "tcp".to_string(),
            state,
            service: None,
            service_identity: None,
            banner: None,
            reason: "test".to_string(),
            matched_by: None,
            confidence: None,
            vulnerability_hints: Vec::new(),
            educational_note: None,
            latency_ms,
            explanation: None,
        }
    }

    #[test]
    fn kis_profile_adds_timing_identity_hint() {
        let mut host = host_with_ports(vec![
            port(22, PortState::Open, Some(18)),
            port(80, PortState::Closed, Some(22)),
            port(443, PortState::Open, Some(25)),
        ]);
        host.operating_system = Some(HostOsGuess {
            label: "Linux".to_string(),
            source: "ttl".to_string(),
            confidence: 0.64,
            cpes: Vec::new(),
        });

        annotate_host(ScanProfile::Kis, false, &mut host);

        assert!(host
            .insights
            .iter()
            .any(|insight| insight.starts_with("kis identity hints: steady latency band")));
        assert!(host
            .learning_notes
            .iter()
            .any(|note| note.contains("correlated timing hints with the 'Linux' profile guess")));
    }

    #[test]
    fn sar_profile_summarizes_response_shape() {
        let mut host = host_with_ports(vec![
            port(22, PortState::Filtered, None),
            port(80, PortState::Open, Some(15)),
            port(443, PortState::OpenOrFiltered, None),
        ]);

        annotate_host(ScanProfile::Sar, false, &mut host);

        assert!(host
            .insights
            .iter()
            .any(|insight| insight.contains("sar response-shape: drop-heavy")));
        assert!(host
            .learning_notes
            .iter()
            .any(|note| note.contains("observational")));
    }

    #[test]
    fn idf_and_callback_ping_stay_on_safe_runtime_path() {
        let mut host = host_with_ports(vec![port(443, PortState::Open, Some(31))]);
        host.insights
            .push("icmp reachability confirmed (31.0 ms)".to_string());

        annotate_host(ScanProfile::Idf, true, &mut host);

        assert!(host
            .insights
            .iter()
            .any(|insight| insight.starts_with("idf sparse sampling: 1 checkpoint")));
        assert!(host
            .insights
            .iter()
            .any(|insight| insight.contains("callback ping classification: standard-stack")));
        assert!(host
            .learning_notes
            .iter()
            .any(|note| note.contains("does not emit synthetic fog packets")));
    }
}

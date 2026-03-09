use std::collections::BTreeSet;

use crate::models::HostResult;

pub fn collect(host: &HostResult, notes: &mut BTreeSet<String>) {
    if let Some(tbns_action) = host
        .safety_actions
        .iter()
        .find(|action| action.starts_with("tbns:"))
    {
        notes.insert(format!(
            "Learning: {tbns_action} kept this host inside the Tri-Blue Network Scans family, favoring low-impact validation over aggressive completeness."
        ));
        notes.insert(
            "Learning: TBNS is the framework's fragile-device path: Phantom for first touch, KIS for cautious identity hints, and SAR for response-shape observation."
                .to_string(),
        );

        if let Some(profile_note) = profile_learning_note(tbns_action) {
            notes.insert(profile_note.to_string());
        }
    }

    if let Some(summary) = host.phantom_device_check_summary() {
        notes.insert(format!(
            "Learning: Phantom acted as the device-check stage here. It sampled {} of {} low-contact checks before choosing the '{}' scan envelope.",
            summary.responsive_ports.unwrap_or(0),
            summary.sampled_ports.unwrap_or(0),
            summary.stage
        ));
        if let Some(avg_latency_ms) = summary.avg_latency_ms {
            notes.insert(format!(
                "Learning: the device-check average latency was {} ms, which helped decide the safe rate and follow-up depth.",
                avg_latency_ms
            ));
        }
        if let Some(payload_budget) = summary.payload_budget {
            notes.insert(format!(
                "Learning: active follow-up payloads were capped to {} after the Phantom device check.",
                payload_budget
            ));
        }
        if summary.passive_follow_up {
            notes.insert(
                "Learning: Phantom kept this host in passive follow-up mode because the device-check results did not justify deeper active probing."
                    .to_string(),
            );
        }
    }
}

fn profile_learning_note(tbns_action: &str) -> Option<&'static str> {
    if tbns_action.starts_with("tbns:phantom:") {
        return Some(
            "Learning: Phantom is the TBNS first-touch chapter. It validates response stability before allowing broader follow-up.",
        );
    }
    if tbns_action.starts_with("tbns:kis:") {
        return Some(
            "Learning: KIS is the TBNS identity chapter. It favors timing and passive stack hints over deeper active fingerprint forcing.",
        );
    }
    if tbns_action.starts_with("tbns:sar:") {
        return Some(
            "Learning: SAR is the TBNS logic chapter. It observes response shape under low pressure instead of manipulating third-party traffic.",
        );
    }
    if tbns_action.starts_with("tbns:idf:") {
        return Some(
            "Learning: IDF is the TBNS fog chapter here, implemented as sparse guarded sampling and diffused port order rather than synthetic decoy traffic.",
        );
    }
    None
}

#[cfg(test)]
mod tests {
    use super::collect;
    use std::collections::BTreeSet;

    use crate::models::HostResult;

    fn host_with_action(action: &str) -> HostResult {
        HostResult {
            target: "example".to_string(),
            ip: "10.0.0.9".to_string(),
            reverse_dns: None,
            observed_mac: None,
            device_class: None,
            device_vendor: None,
            operating_system: None,
            phantom_device_check: None,
            safety_actions: vec![action.to_string()],
            warnings: Vec::new(),
            ports: Vec::new(),
            risk_score: 0,
            insights: Vec::new(),
            defensive_advice: Vec::new(),
            learning_notes: Vec::new(),
            lua_findings: Vec::new(),
        }
    }

    #[test]
    fn kis_profile_contributes_identity_chapter_note() {
        let host = host_with_action("tbns:kis:chapter=identity");
        let mut notes = BTreeSet::new();

        collect(&host, &mut notes);

        assert!(notes
            .iter()
            .any(|note| note.contains("KIS is the TBNS identity chapter")));
    }

    #[test]
    fn idf_profile_contributes_safe_fog_note() {
        let host = host_with_action("tbns:idf:chapter=fog");
        let mut notes = BTreeSet::new();

        collect(&host, &mut notes);

        assert!(notes
            .iter()
            .any(|note| note.contains("diffused port order")));
    }
}

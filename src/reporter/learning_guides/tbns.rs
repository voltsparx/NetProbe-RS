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

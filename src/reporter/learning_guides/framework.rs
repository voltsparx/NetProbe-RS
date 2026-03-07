use std::collections::BTreeSet;

use crate::models::{HostResult, PortState};

pub fn collect(host: &HostResult, notes: &mut BTreeSet<String>) {
    let open_count = host
        .ports
        .iter()
        .filter(|p| matches!(p.state, PortState::Open | PortState::OpenOrFiltered))
        .count();

    if open_count == 0 {
        notes.insert(
            "Learning: a fully closed result still matters; it confirms reachable host behavior and filtering posture."
                .to_string(),
        );
    } else {
        notes.insert(format!(
            "Learning: {} reachable service(s) were observed; prioritize least-privilege exposure and confirm each one has a real business need.",
            open_count
        ));
    }

    notes.insert(
        "Learning: nprobe-rs is staged on purpose: discovery first, safety checks second, deeper validation only after the host looks resilient."
            .to_string(),
    );

    if host.learning_notes.is_empty() {
        notes.insert(
            "Learning path: beginners can repeat this scan in `interactive` mode; specialists can use Nmap-style flags that map to the same safe semantics."
                .to_string(),
        );
    }
}

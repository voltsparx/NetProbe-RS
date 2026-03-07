use std::collections::BTreeSet;

use crate::models::HostResult;

pub fn collect(host: &HostResult, notes: &mut BTreeSet<String>) {
    if let Some(device_class) = host.device_class.as_deref() {
        match device_class {
            "fragile-embedded" => {
                notes.insert(
                    "Learning: fragile embedded targets were scanned in reduced-pressure mode to avoid disrupting low-power systems."
                        .to_string(),
                );
            }
            "printer-sensitive" => {
                notes.insert(
                    "Learning: printer-like targets can misbehave on legacy print ports, so nprobe-rs preserved safety by suppressing risky probes."
                        .to_string(),
                );
            }
            "enterprise" => {
                notes.insert(
                    "Learning: enterprise-class hardware tolerated broader discovery, but exposure still requires human review and segmentation checks."
                        .to_string(),
                );
            }
            _ => {
                notes.insert(
                    "Learning: the device profile stayed generic, so the framework kept conservative assumptions and limited follow-up pressure."
                        .to_string(),
                );
            }
        }
    }

    if !host.safety_actions.is_empty() {
        notes.insert(format!(
            "Learning: safety automation applied {} runtime action(s) for this host.",
            host.safety_actions.len()
        ));
    }

    if host
        .safety_actions
        .iter()
        .any(|action| action.contains("passive"))
    {
        notes.insert(
            "Learning: deeper active fingerprinting was intentionally withheld until the host looked resilient enough for safe follow-up."
                .to_string(),
        );
    }
}

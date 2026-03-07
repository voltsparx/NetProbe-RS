// Flow sketch: ports -> scoring/findings/guidance -> insights
// Pseudo-block:
//   read input -> process safely -> return deterministic output

use crate::models::{HostResult, PortState};
use crate::reporter::actionable;

pub fn generate_findings(host: &HostResult) -> Vec<String> {
    let mut findings = Vec::new();
    let open_ports = host
        .ports
        .iter()
        .filter(|p| matches!(p.state, PortState::Open | PortState::OpenOrFiltered))
        .count();

    if open_ports == 0 {
        findings.push("No open or open|filtered ports detected in selected scope".to_string());
        return findings;
    }

    for item in actionable::collect(host) {
        findings.push(format!("Issue [{}]: {}", item.severity, item.issue));
    }

    if findings.is_empty() {
        findings.push(
            "No obvious high-signal exposure pattern stood out beyond the detected open services."
                .to_string(),
        );
    }

    findings
}

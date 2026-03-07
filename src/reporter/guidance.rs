// Flow sketch: ports -> scoring/findings/guidance -> insights
// Pseudo-block:
//   read input -> process safely -> return deterministic output

use std::collections::BTreeSet;

use crate::models::HostResult;
use crate::reporter::actionable;

pub fn build_advice(host: &HostResult) -> Vec<String> {
    let mut advice = BTreeSet::new();
    for item in actionable::collect(host) {
        advice.insert(item.action);
    }

    if advice.is_empty() {
        advice.insert(
            "Maintain host firewall defaults, keep patching current, and continue periodic baseline scans."
                .to_string(),
        );
    }

    advice.into_iter().collect()
}

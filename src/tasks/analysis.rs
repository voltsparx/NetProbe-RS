// Flow sketch: host target -> task pipeline -> enriched host result
// Pseudo-block:
//   read input -> process safely -> return deterministic output

use crate::reporter::{findings, guidance, learning, reasoning};
use crate::engines::parallel;
use crate::models::HostResult;

pub fn run(host: &mut HostResult, explain_mode: bool) -> usize {
    let (risk_score, mut insights, parallel_tasks) =
        parallel::compute_risk_and_signals(&host.ports);
    host.risk_score = risk_score;

    insights.extend(findings::generate_findings(host));
    insights.sort();
    insights.dedup();
    host.insights = insights;
    host.defensive_advice = guidance::build_advice(host);
    learning::attach_port_notes(&mut host.ports);
    host.learning_notes = learning::build_learning_notes(host);

    if explain_mode {
        reasoning::attach_explanations(&mut host.ports);
    }

    parallel_tasks
}


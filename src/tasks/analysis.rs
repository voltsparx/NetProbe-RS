// Flow sketch: host target -> task pipeline -> enriched host result
// Pseudo-block:
//   read input -> process safely -> return deterministic output

use crate::engines::parallel;
use crate::models::HostResult;
use crate::reporter::{findings, guidance, learning, reasoning, service_intelligence};

pub fn run(host: &mut HostResult, explain_mode: bool) -> usize {
    service_intelligence::annotate_ports(&mut host.ports);
    let (risk_score, mut insights, parallel_tasks) =
        parallel::compute_risk_and_signals(&host.ports);
    host.risk_score = risk_score;

    insights.extend(findings::generate_findings(host));
    let intel = service_intelligence::analyze_host(host);
    insights.extend(intel.insights);
    insights.sort();
    insights.dedup();
    host.insights = insights;
    host.defensive_advice = guidance::build_advice(host);
    host.defensive_advice.extend(intel.advice);
    host.defensive_advice.sort();
    host.defensive_advice.dedup();
    learning::attach_port_notes(&mut host.ports);
    host.learning_notes = learning::build_learning_notes(host);
    host.learning_notes.extend(intel.learning);
    host.learning_notes.sort();
    host.learning_notes.dedup();

    if explain_mode {
        reasoning::attach_explanations(&mut host.ports);
    }

    parallel_tasks
}

use crate::ai::{advice, explain, rules, teacher};
use crate::engines::parallel;
use crate::models::HostResult;

pub fn run(host: &mut HostResult, explain_mode: bool) -> usize {
    let (risk_score, mut findings, parallel_tasks) =
        parallel::compute_risk_and_signals(&host.ports);
    host.risk_score = risk_score;

    findings.extend(rules::generate_findings(host));
    findings.sort();
    findings.dedup();
    host.ai_findings = findings;
    host.defensive_advice = advice::build_advice(host);
    teacher::attach_port_notes(&mut host.ports);
    host.learning_notes = teacher::build_learning_notes(host);

    if explain_mode {
        explain::attach_explanations(&mut host.ports);
    }

    parallel_tasks
}

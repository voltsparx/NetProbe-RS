use crate::models::{PortState, ScanReport};

pub fn render(report: &ScanReport) -> String {
    let mut out = String::new();
    out.push_str("NetProbe-RS Scan Report\n");
    out.push_str("=======================\n");
    out.push_str(&format!(
        "Started : {}\nFinished: {}\nDuration: {} ms\n\n",
        report.metadata.started_at, report.metadata.finished_at, report.metadata.duration_ms
    ));

    out.push_str(&format!(
        "Engine stats -> async:{} thread:{} parallel:{} lua:{}\n\n",
        report.metadata.engine_stats.async_engine_tasks,
        report.metadata.engine_stats.thread_pool_tasks,
        report.metadata.engine_stats.parallel_tasks,
        report.metadata.engine_stats.lua_hooks_ran
    ));
    out.push_str(&format!(
        "Knowledge -> services:{} top_ports:{} payloads:{} rules:{}/{} skipped:{} nse:{} nselib:{}\n\n",
        report.metadata.knowledge.services_loaded,
        report.metadata.knowledge.ranked_tcp_ports,
        report.metadata.knowledge.probe_payloads_loaded,
        report.metadata.knowledge.fingerprint_rules_compiled,
        report.metadata.knowledge.fingerprint_rules_loaded,
        report.metadata.knowledge.fingerprint_rules_skipped,
        report.metadata.knowledge.nse_scripts_seen,
        report.metadata.knowledge.nselib_modules_seen
    ));

    for host in &report.hosts {
        out.push_str(&format!("Target: {} ({})\n", host.target, host.ip));
        if let Some(reverse) = &host.reverse_dns {
            out.push_str(&format!("Reverse DNS: {}\n", reverse));
        }
        if !host.warnings.is_empty() {
            for warning in &host.warnings {
                out.push_str(&format!("Warning: {}\n", warning));
            }
        }
        out.push_str(&format!(
            "Open-like ports: {}\nRisk score: {}/100\n\n",
            host.open_port_count(),
            host.risk_score
        ));

        out.push_str("PORT     STATE           SERVICE            REASON\n");
        out.push_str("----     -----           -------            ------\n");
        for p in &host.ports {
            let service = p.service.as_deref().unwrap_or("unknown");
            out.push_str(&format!(
                "{:>5}/{} {:<15} {:<18} {}\n",
                p.port, p.protocol, p.state, service, p.reason
            ));
            if let Some(banner) = &p.banner {
                out.push_str(&format!("           banner: {}\n", banner));
            }
            if let Some(source) = &p.matched_by {
                let confidence = p
                    .confidence
                    .map(|v| format!("{:.2}", v))
                    .unwrap_or_else(|| "n/a".to_string());
                out.push_str(&format!(
                    "           fingerprint: {} (confidence {})\n",
                    source, confidence
                ));
            }
            if let Some(note) = &p.educational_note {
                out.push_str(&format!("           learn: {}\n", note));
            }
            if let Some(explanation) = &p.explanation {
                out.push_str(&format!("           why: {}\n", explanation));
            }
        }

        if !host.ai_findings.is_empty() {
            out.push_str("\nInsights:\n");
            for finding in &host.ai_findings {
                out.push_str(&format!("- {}\n", finding));
            }
        }

        if !host.lua_findings.is_empty() {
            out.push_str("\nLua Findings:\n");
            for finding in &host.lua_findings {
                out.push_str(&format!("- {}\n", finding));
            }
        }

        if !host.learning_notes.is_empty() {
            out.push_str("\nLearning Notes:\n");
            for note in &host.learning_notes {
                out.push_str(&format!("- {}\n", note));
            }
        }

        if !host.defensive_advice.is_empty() {
            out.push_str("\nDefensive Advice:\n");
            for advice in &host.defensive_advice {
                out.push_str(&format!("- {}\n", advice));
            }
        }
        out.push('\n');
    }

    let open_total: usize = report
        .hosts
        .iter()
        .map(|h| {
            h.ports
                .iter()
                .filter(|p| matches!(p.state, PortState::Open | PortState::OpenOrFiltered))
                .count()
        })
        .sum();

    out.push_str(&format!(
        "Summary: {} host(s), {} open/open|filtered finding(s)\n",
        report.hosts.len(),
        open_total
    ));
    out
}

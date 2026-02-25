use crate::models::ScanReport;

pub fn render(report: &ScanReport) -> String {
    let mut out = String::new();
    out.push_str("netprobe-rs text report\n");
    out.push_str(&format!(
        "started={} finished={} duration_ms={}\n",
        report.metadata.started_at, report.metadata.finished_at, report.metadata.duration_ms
    ));
    out.push_str(&format!(
        "async_tasks={} thread_tasks={} parallel_tasks={} lua_hooks={}\n",
        report.metadata.engine_stats.async_engine_tasks,
        report.metadata.engine_stats.thread_pool_tasks,
        report.metadata.engine_stats.parallel_tasks,
        report.metadata.engine_stats.lua_hooks_ran
    ));
    out.push_str(&format!(
        "knowledge services={} top_ports={} payloads={} rules_compiled={} rules_total={} rules_skipped={} nse={} nselib={}\n",
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
        out.push_str(&format!(
            "host target={} ip={} risk={}\n",
            host.target, host.ip, host.risk_score
        ));
        for warning in &host.warnings {
            out.push_str(&format!("warning={}\n", warning));
        }
        for port in &host.ports {
            out.push_str(&format!(
                "port={} proto={} state={} service={} reason={} matched_by={} confidence={}\n",
                port.port,
                port.protocol,
                port.state,
                port.service.as_deref().unwrap_or("unknown"),
                port.reason,
                port.matched_by.as_deref().unwrap_or("unknown"),
                port.confidence
                    .map(|v| format!("{v:.2}"))
                    .unwrap_or_else(|| "n/a".to_string())
            ));
        }
        for finding in &host.ai_findings {
            out.push_str(&format!("insight={}\n", finding));
        }
        for note in &host.learning_notes {
            out.push_str(&format!("learning={}\n", note));
        }
        for advice in &host.defensive_advice {
            out.push_str(&format!("advice={}\n", advice));
        }
    }

    out
}

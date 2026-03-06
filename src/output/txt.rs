// Flow sketch: scan report -> renderer -> user-facing output
// Pseudo-block:
//   read input -> process safely -> return deterministic output

use crate::models::ScanReport;

pub fn render(report: &ScanReport) -> String {
    let mut out = String::new();
    out.push_str("nprobe-rs text report\n");
    if let Some(session_id) = &report.metadata.session_id {
        out.push_str(&format!("session_id={session_id}\n"));
    }
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
        "framework_role={} teaching_mode={} safety_envelope={} public_target_policy={} profiled_hosts={} fragile_hosts={} suppressed_ports={}\n",
        report.metadata.engine_stats.framework_role,
        report.metadata.engine_stats.teaching_mode,
        report.metadata.engine_stats.safety_envelope_active,
        report.metadata.engine_stats.public_target_policy_applied,
        report.metadata.engine_stats.profiled_hosts,
        report.metadata.engine_stats.fragile_hosts,
        report.metadata.engine_stats.safety_ports_suppressed
    ));
    out.push_str(&format!(
        "platform capability_total={} implemented={} partial={} planned={} excluded={} tool_families={} domains={}\n",
        report.metadata.platform.capability_total,
        report.metadata.platform.implemented,
        report.metadata.platform.partial,
        report.metadata.platform.planned,
        report.metadata.platform.intentionally_excluded,
        report.metadata.platform.tool_families.join(","),
        report.metadata.platform.capability_domains.join(",")
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
        if host.device_class.is_some() || host.observed_mac.is_some() {
            out.push_str(&format!(
                "device class={} vendor={} mac={}\n",
                host.device_class.as_deref().unwrap_or("unknown"),
                host.device_vendor.as_deref().unwrap_or("unknown"),
                host.observed_mac.as_deref().unwrap_or("unknown")
            ));
        }
        for action in &host.safety_actions {
            out.push_str(&format!("safety_action={}\n", action));
        }
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
        for finding in &host.insights {
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

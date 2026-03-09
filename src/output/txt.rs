// Flow sketch: scan report -> renderer -> user-facing output
// Pseudo-block:
//   read input -> process safely -> return deterministic output

use crate::models::ScanReport;
use crate::output::{
    actionable_summary_line, good_next_steps, host_discovery_confirmed, host_discovery_evidence,
    host_os_profile, host_traceroute_summary, key_issue_lines, open_service_inventory,
    phantom_device_check_summary, service_detail_lines, service_label,
};

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
    out.push_str(&format!("override_mode={}\n", report.request.override_mode));
    out.push_str(&format!(
        "request list_scan={} ping_scan={} traceroute={} sequential_port_order={} timing_template={}\n",
        report.request.list_scan,
        report.request.ping_scan,
        report.request.traceroute,
        report.request.sequential_port_order,
        report
            .request
            .timing_template
            .map(|level| format!("T{}", level))
            .unwrap_or_else(|| "default".to_string())
    ));
    out.push_str(&format!(
        "async_tasks={} thread_tasks={} parallel_tasks={} lua_hooks={} integrity_checked={} integrity_state={} integrity_manifest={}\n",
        report.metadata.engine_stats.async_engine_tasks,
        report.metadata.engine_stats.thread_pool_tasks,
        report.metadata.engine_stats.parallel_tasks,
        report.metadata.engine_stats.lua_hooks_ran,
        report.metadata.engine_stats.integrity_checked,
        report.metadata.engine_stats.integrity_state,
        report.metadata.engine_stats.integrity_manifest
    ));
    out.push_str(&format!(
        "framework_role={} scan_family={} safety_model={} scan_bundle={} resource_policy={} teaching_mode={} safety_envelope={} public_target_policy={} profiled_hosts={} fragile_hosts={} suppressed_ports={}\n",
        report.metadata.engine_stats.framework_role,
        report.metadata.engine_stats.scan_family,
        report.metadata.engine_stats.safety_model,
        report.metadata.engine_stats.scan_bundle,
        report.metadata.engine_stats.resource_policy,
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
    out.push_str(
        "workflow_lanes=learners:interactive,fragile_unknown:tbns,specialists:nmap-compatible-safe-flags,audits:balanced-stealth\n",
    );
    out.push_str(&format!(
        "hybrid_acceleration={} backend={} tier={} visualizer={} shader={} action_triggers={}\n",
        report.metadata.engine_stats.gpu_hybrid_lane,
        report.metadata.engine_stats.gpu_hybrid_backend,
        report.metadata.engine_stats.gpu_platform_tier,
        report.metadata.engine_stats.gpu_visualizer_mode,
        report.metadata.engine_stats.gpu_shader_kernel,
        report.metadata.engine_stats.gpu_action_triggers_loaded
    ));
    out.push_str(&format!(
        "local_system assessment_mode={} hardware_profile={} health_stage={} platform_tier={} raw_packet_supported={} gpu_hybrid_supported={} fault_isolation={} cpu_threads={} cpu_usage_pct={:.0} total_memory_mib={} available_memory_mib={} safe_raw_rate_pps={} safe_raw_burst={} safe_gpu_rate_pps={} safe_gpu_burst={} safe_concurrency={} safe_delay_ms={} emergency_brake_triggered={} emergency_brake_reason={}\n",
        report.metadata.local_system.assessment_mode,
        report.metadata.local_system.hardware_profile,
        report.metadata.local_system.health_stage,
        report.metadata.local_system.platform_tier,
        report.metadata.local_system.raw_packet_supported,
        report.metadata.local_system.gpu_hybrid_supported,
        report.metadata.local_system.fault_isolation_mode,
        report.metadata.local_system.cpu_threads,
        report.metadata.local_system.cpu_usage_pct,
        report.metadata.local_system.total_memory_mib,
        report.metadata.local_system.available_memory_mib,
        report.metadata.local_system.recommended_raw_rate_pps,
        report.metadata.local_system.recommended_raw_burst,
        report.metadata.local_system.recommended_gpu_rate_pps,
        report.metadata.local_system.recommended_gpu_burst,
        report.metadata.local_system.recommended_concurrency,
        report.metadata.local_system.recommended_delay_ms,
        report.metadata.local_system.emergency_brake_triggered,
        report
            .metadata
            .local_system
            .emergency_brake_reason
            .as_deref()
            .unwrap_or("n/a")
    ));
    for note in &report.metadata.local_system.compatibility_notes {
        out.push_str(&format!("local_compatibility={}\n", note));
    }
    for note in &report.metadata.local_system.adjustments {
        out.push_str(&format!("local_adjustment={}\n", note));
    }
    if !report.metadata.engine_stats.scan_bundle_stages.is_empty() {
        out.push_str(&format!(
            "scan_bundle_stages={}\n",
            report.metadata.engine_stats.scan_bundle_stages.join(">")
        ));
    }
    out.push_str(&format!(
        "knowledge services={} top_ports={} payloads={} rules_compiled={} rules_total={} rules_skipped={} nse={} nselib={} os_signatures={} os_classes={} os_cpes={}\n",
        report.metadata.knowledge.services_loaded,
        report.metadata.knowledge.ranked_tcp_ports,
        report.metadata.knowledge.probe_payloads_loaded,
        report.metadata.knowledge.fingerprint_rules_compiled,
        report.metadata.knowledge.fingerprint_rules_loaded,
        report.metadata.knowledge.fingerprint_rules_skipped,
        report.metadata.knowledge.nse_scripts_seen,
        report.metadata.knowledge.nselib_modules_seen,
        report.metadata.knowledge.os_fingerprint_signatures_loaded,
        report.metadata.knowledge.os_fingerprint_classes_loaded,
        report.metadata.knowledge.os_fingerprint_cpes_loaded
    ));

    for host in &report.hosts {
        out.push_str(&format!(
            "host target={} ip={} risk={}\n",
            host.target, host.ip, host.risk_score
        ));
        if let Some(os_profile) = host_os_profile(host) {
            out.push_str(&format!("os_profile={os_profile}\n"));
        }
        if host.device_class.is_some() || host.observed_mac.is_some() {
            out.push_str(&format!(
                "device class={} vendor={} mac={}\n",
                host.device_class.as_deref().unwrap_or("unknown"),
                host.device_vendor.as_deref().unwrap_or("unknown"),
                host.observed_mac.as_deref().unwrap_or("unknown")
            ));
        }
        if let Some(summary) = phantom_device_check_summary(host) {
            out.push_str(&format!(
                "device_check profile=phantom stage={} responsive={}/{} timeout={} avg_latency_ms={} payload_budget={} passive_follow_up={}\n",
                summary.stage,
                summary.responsive_ports.unwrap_or(0),
                summary.sampled_ports.unwrap_or(0),
                summary.timeout_ports.unwrap_or(0),
                summary
                    .avg_latency_ms
                    .map(|latency| latency.to_string())
                    .unwrap_or_else(|| "n/a".to_string()),
                summary
                    .payload_budget
                    .map(|budget| budget.to_string())
                    .unwrap_or_else(|| "n/a".to_string()),
                summary.passive_follow_up
            ));
        }
        out.push_str(&format!(
            "host_discovery_confirmed={}\n",
            host_discovery_confirmed(host)
        ));
        for evidence in host_discovery_evidence(host) {
            out.push_str(&format!("discovery_evidence={}\n", evidence));
        }
        if let Some(traceroute) = host_traceroute_summary(host) {
            out.push_str(&format!("traceroute={}\n", traceroute));
        }
        if let Some(summary) = actionable_summary_line(host) {
            out.push_str(&format!("actionable_summary={summary}\n"));
        }
        for service in open_service_inventory(host) {
            out.push_str(&format!("open_service={service}\n"));
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
                service_label(port),
                port.reason,
                port.matched_by.as_deref().unwrap_or("unknown"),
                port.confidence
                    .map(|v| format!("{v:.2}"))
                    .unwrap_or_else(|| "n/a".to_string())
            ));
            for detail in service_detail_lines(port) {
                out.push_str(&format!("service_detail={}\n", detail));
            }
        }
        for issue in key_issue_lines(host) {
            out.push_str(&format!("issue={}\n", issue));
        }
        for step in good_next_steps(host) {
            out.push_str(&format!("next_step={}\n", step));
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

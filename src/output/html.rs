// Flow sketch: scan report -> renderer -> user-facing output
// Pseudo-block:
//   read input -> process safely -> return deterministic output
// html output wears a suit so results can meet management.

use crate::models::ScanReport;
use crate::output::{
    actionable_summary_line, good_next_steps, host_discovery_confirmed, host_discovery_evidence,
    host_os_profile, host_traceroute_summary, phantom_device_check_summary, service_detail_lines,
    service_label, top_actionable_items,
};

pub fn render(report: &ScanReport) -> String {
    let mut html = String::new();
    html.push_str("<!doctype html><html><head><meta charset=\"utf-8\">");
    html.push_str("<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">");
    html.push_str("<title>NProbe-RS Report</title>");
    html.push_str("<style>");
    html.push_str(
        ":root{--bg:#f6f8fb;--panel:#ffffff;--ink:#16212f;--muted:#6a7789;--accent:#0f7a6e;--warn:#8f3f2e;--critical:#8f2d2d;--high:#a3581a;--moderate:#735f13;--review:#3f648f;}
        body{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;background:linear-gradient(120deg,#f6f8fb,#edf2f8);color:var(--ink);margin:0;padding:24px;}
        .wrap{max-width:1100px;margin:0 auto;}
        .card{background:var(--panel);border:1px solid #e6ebf2;border-radius:14px;padding:18px;margin-bottom:18px;box-shadow:0 6px 20px rgba(10,20,40,.06);}
        h1,h2{margin:0 0 8px 0}
        .meta{color:var(--muted);font-size:14px}
        table{width:100%;border-collapse:collapse;margin-top:10px}
        th,td{padding:8px;border-bottom:1px solid #ecf1f7;text-align:left;font-size:13px;vertical-align:top}
        th{color:#33465c}
        .pill{display:inline-block;padding:2px 8px;border-radius:999px;background:#e7f8f4;color:var(--accent);font-size:12px}
        .sev{display:inline-block;padding:2px 8px;border-radius:999px;font-size:11px;font-weight:700;text-transform:uppercase;letter-spacing:.04em;margin-right:8px}
        .sev-critical{background:#f7dfdf;color:var(--critical)}
        .sev-high{background:#f8e7d7;color:var(--high)}
        .sev-moderate{background:#f5edcf;color:var(--moderate)}
        .sev-review{background:#dde8f7;color:var(--review)}
        .warn{color:var(--warn)}
        ul{margin:6px 0 0 18px}
        </style></head><body><div class=\"wrap\">",
    );

    html.push_str("<div class=\"card\">");
    html.push_str("<h1>NProbe-RS Report</h1>");
    if let Some(session_id) = &report.metadata.session_id {
        html.push_str(&format!(
            "<div class=\"meta\">Session: {}</div>",
            esc(session_id)
        ));
    }
    html.push_str(&format!(
        "<div class=\"meta\">Started: {}<br>Finished: {}<br>Duration: {} ms</div>",
        report.metadata.started_at, report.metadata.finished_at, report.metadata.duration_ms
    ));
    html.push_str(&format!(
        "<div class=\"meta\">Override mode: {}</div>",
        if report.request.override_mode {
            "active"
        } else {
            "off"
        }
    ));
    html.push_str(&format!(
        "<div class=\"meta\">Request mode: ping-scan={} | traceroute={} | timing={}</div>",
        report.request.ping_scan,
        report.request.traceroute,
        esc(&report
            .request
            .timing_template
            .map(|level| format!("T{}", level))
            .unwrap_or_else(|| "default".to_string()))
    ));
    html.push_str(&format!(
        "<div class=\"meta\">Async tasks: {} | Thread tasks: {} | Parallel tasks: {} | Lua hooks: {} | Integrity: {} ({})</div>",
        report.metadata.engine_stats.async_engine_tasks,
        report.metadata.engine_stats.thread_pool_tasks,
        report.metadata.engine_stats.parallel_tasks,
        report.metadata.engine_stats.lua_hooks_ran,
        esc(&report.metadata.engine_stats.integrity_state),
        esc(&report.metadata.engine_stats.integrity_manifest)
    ));
    html.push_str(&format!(
        "<div class=\"meta\">Role: {} | Family: {} | Safety model: {} | Bundle: {} | Resources: {} | Teaching: {} | Safety envelope: {} | Public target policy: {} | Profiled hosts: {} | Fragile hosts: {} | Suppressed ports: {}</div>",
        esc(&report.metadata.engine_stats.framework_role),
        esc(&report.metadata.engine_stats.scan_family),
        esc(&report.metadata.engine_stats.safety_model),
        esc(&report.metadata.engine_stats.scan_bundle),
        esc(&report.metadata.engine_stats.resource_policy),
        report.metadata.engine_stats.teaching_mode,
        report.metadata.engine_stats.safety_envelope_active,
        report.metadata.engine_stats.public_target_policy_applied,
        report.metadata.engine_stats.profiled_hosts,
        report.metadata.engine_stats.fragile_hosts,
        report.metadata.engine_stats.safety_ports_suppressed
    ));
    html.push_str(&format!(
        "<div class=\"meta\">Platform coverage: {} capabilities | tool families {} | domains {} | implemented {} | partial {} | planned {} | excluded {}</div>",
        report.metadata.platform.capability_total,
        report.metadata.platform.tool_families.len(),
        report.metadata.platform.capability_domains.len(),
        report.metadata.platform.implemented,
        report.metadata.platform.partial,
        report.metadata.platform.planned,
        report.metadata.platform.intentionally_excluded
    ));
    html.push_str("<div class=\"meta\">Workflow lanes: learners=interactive | fragile/unknown=phantom/kis/sar | specialists=nmap-style safe flags | audits=balanced/stealth</div>");
    html.push_str(&format!(
        "<div class=\"meta\">Hybrid acceleration: {} | Backend: {} | Tier: {} | Visualizer: {} | Shader: {} | Action triggers: {}</div>",
        esc(&report.metadata.engine_stats.gpu_hybrid_lane),
        esc(&report.metadata.engine_stats.gpu_hybrid_backend),
        esc(&report.metadata.engine_stats.gpu_platform_tier),
        esc(&report.metadata.engine_stats.gpu_visualizer_mode),
        esc(&report.metadata.engine_stats.gpu_shader_kernel),
        report.metadata.engine_stats.gpu_action_triggers_loaded
    ));
    html.push_str(&format!(
        "<div class=\"meta\">Local system: profile={} | health={} | platform={} | raw={} | gpu={} | cpu={:.0}% across {} threads | memory={} MiB free / {} MiB total | safe raw={}pps burst {} | safe gpu={}pps burst {} | safe concurrency={} | delay floor={}ms | fault isolation={} | emergency brake={}</div>",
        esc(&report.metadata.local_system.hardware_profile),
        esc(&report.metadata.local_system.health_stage),
        esc(&report.metadata.local_system.platform_tier),
        if report.metadata.local_system.raw_packet_supported {
            "ready"
        } else {
            "not-ready"
        },
        if report.metadata.local_system.gpu_hybrid_supported {
            "scaffold-ready"
        } else {
            "fallback"
        },
        report.metadata.local_system.cpu_usage_pct,
        report.metadata.local_system.cpu_threads,
        report.metadata.local_system.available_memory_mib,
        report.metadata.local_system.total_memory_mib,
        report.metadata.local_system.recommended_raw_rate_pps,
        report.metadata.local_system.recommended_raw_burst,
        report.metadata.local_system.recommended_gpu_rate_pps,
        report.metadata.local_system.recommended_gpu_burst,
        report.metadata.local_system.recommended_concurrency,
        report.metadata.local_system.recommended_delay_ms,
        esc(&report.metadata.local_system.fault_isolation_mode),
        esc(if report.metadata.local_system.emergency_brake_triggered {
            report
                .metadata
                .local_system
                .emergency_brake_reason
                .as_deref()
                .unwrap_or("triggered")
        } else {
            "armed/not-triggered"
        })
    ));
    if report.metadata.local_system.assessment_mode {
        html.push_str("<div class=\"meta\">Hardware assessment mode: no scan packets were transmitted; this report is local safety guidance only.</div>");
    }
    if !report.metadata.local_system.compatibility_notes.is_empty() {
        html.push_str("<h2>Local Compatibility Notes</h2><ul>");
        for note in &report.metadata.local_system.compatibility_notes {
            html.push_str(&format!("<li>{}</li>", esc(note)));
        }
        html.push_str("</ul>");
    }
    if !report.metadata.local_system.adjustments.is_empty() {
        html.push_str("<h2>Local Safety Adjustments</h2><ul>");
        for note in &report.metadata.local_system.adjustments {
            html.push_str(&format!("<li>{}</li>", esc(note)));
        }
        html.push_str("</ul>");
    }
    if !report.metadata.engine_stats.scan_bundle_stages.is_empty() {
        html.push_str(&format!(
            "<div class=\"meta\">Bundle stages: {}</div>",
            esc(&report.metadata.engine_stats.scan_bundle_stages.join(" -> "))
        ));
    }
    html.push_str(&format!(
        "<div class=\"meta\">Knowledge: services {} | top ports {} | payloads {} | rules {}/{} (skipped {}) | NSE scripts {} | NSE libs {} | OS signatures {} | OS classes {} | OS CPEs {}</div>",
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
    html.push_str("</div>");

    for host in &report.hosts {
        html.push_str("<div class=\"card\">");
        html.push_str(&format!(
            "<h2>{}</h2><div class=\"meta\">IP: {} | Risk: <span class=\"pill\">{}/100</span></div>",
            esc(&host.target),
            esc(&host.ip),
            host.risk_score
        ));
        if let Some(reverse) = &host.reverse_dns {
            html.push_str(&format!(
                "<div class=\"meta\">Reverse DNS: {}</div>",
                esc(reverse)
            ));
        }
        if let Some(os_profile) = host_os_profile(host) {
            html.push_str(&format!(
                "<div class=\"meta\">OS/profile: {}</div>",
                esc(&os_profile)
            ));
        }
        if host.device_class.is_some() || host.observed_mac.is_some() {
            html.push_str(&format!(
                "<div class=\"meta\">Device profile: class={} | vendor={} | mac={}</div>",
                esc(host.device_class.as_deref().unwrap_or("unknown")),
                esc(host.device_vendor.as_deref().unwrap_or("unknown")),
                esc(host.observed_mac.as_deref().unwrap_or("unknown"))
            ));
        }
        if let Some(summary) = phantom_device_check_summary(host) {
            html.push_str(&format!(
                "<div class=\"meta\">Device check: Phantom stage={} | responsive={}/{} | timeout={} | avg latency={} ms | payload budget={} | passive follow-up={}</div>",
                esc(&summary.stage),
                summary.responsive_ports.unwrap_or(0),
                summary.sampled_ports.unwrap_or(0),
                summary.timeout_ports.unwrap_or(0),
                esc(&summary
                    .avg_latency_ms
                    .map(|latency| latency.to_string())
                    .unwrap_or_else(|| "n/a".to_string())),
                esc(&summary
                    .payload_budget
                    .map(|budget| budget.to_string())
                    .unwrap_or_else(|| "n/a".to_string())),
                if summary.passive_follow_up { "yes" } else { "no" }
            ));
        }
        html.push_str(&format!(
            "<div class=\"meta\">Discovery confirmed: {}</div>",
            host_discovery_confirmed(host)
        ));
        let discovery_evidence = host_discovery_evidence(host);
        if !discovery_evidence.is_empty() {
            html.push_str("<h3>Discovery Evidence</h3><ul>");
            for line in &discovery_evidence {
                html.push_str(&format!("<li>{}</li>", esc(line)));
            }
            html.push_str("</ul>");
        }
        if let Some(traceroute) = host_traceroute_summary(host) {
            html.push_str(&format!(
                "<div class=\"meta\">Path trace: {}</div>",
                esc(&traceroute)
            ));
        }
        if let Some(summary) = actionable_summary_line(host) {
            html.push_str(&format!(
                "<div class=\"meta\">Actionable findings: {}</div>",
                esc(&summary)
            ));
        }
        for warning in &host.warnings {
            html.push_str(&format!(
                "<div class=\"meta warn\">Warning: {}</div>",
                esc(warning)
            ));
        }
        if !host.safety_actions.is_empty() {
            html.push_str("<h3>Safety Actions</h3><ul>");
            for action in &host.safety_actions {
                html.push_str(&format!("<li>{}</li>", esc(action)));
            }
            html.push_str("</ul>");
        }

        html.push_str("<table><thead><tr><th>Port</th><th>Proto</th><th>State</th><th>Service</th><th>Reason</th><th>Banner</th><th>Fingerprint</th><th>Learn</th></tr></thead><tbody>");
        for p in &host.ports {
            html.push_str(&format!(
                "<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{} ({})</td><td>{}</td></tr>",
                p.port,
                esc(&p.protocol),
                esc(&p.state.to_string()),
                esc(&service_label(p)),
                esc(&p.reason),
                esc(p.banner.as_deref().unwrap_or("")),
                esc(p.matched_by.as_deref().unwrap_or("unknown")),
                p.confidence
                    .map(|v| format!("{v:.2}"))
                    .unwrap_or_else(|| "n/a".to_string()),
                esc(p.educational_note.as_deref().unwrap_or(""))
            ));
            let details = service_detail_lines(p);
            if !details.is_empty() {
                html.push_str("<tr><td></td><td colspan=\"7\"><ul>");
                for detail in details {
                    html.push_str(&format!("<li>{}</li>", esc(&detail)));
                }
                html.push_str("</ul></td></tr>");
            }
        }
        html.push_str("</tbody></table>");

        let key_issues = top_actionable_items(host);
        if !key_issues.is_empty() {
            html.push_str("<h3>What Looks Wrong</h3><ul>");
            for issue in &key_issues {
                html.push_str(&format!(
                    "<li><span class=\"sev sev-{}\">{}</span>{}</li>",
                    esc(issue.severity.as_str()),
                    esc(issue.severity.as_str()),
                    esc(&issue.issue)
                ));
            }
            html.push_str("</ul>");
        }
        let next_steps = good_next_steps(host);
        if !next_steps.is_empty() {
            html.push_str("<h3>Good Next Steps</h3><ul>");
            for step in &next_steps {
                html.push_str(&format!("<li>{}</li>", esc(step)));
            }
            html.push_str("</ul>");
        }

        if !host.insights.is_empty() {
            html.push_str("<h3>Insights</h3><ul>");
            for finding in &host.insights {
                html.push_str(&format!("<li>{}</li>", esc(finding)));
            }
            html.push_str("</ul>");
        }
        if !host.lua_findings.is_empty() {
            html.push_str("<h3>Lua Findings</h3><ul>");
            for finding in &host.lua_findings {
                html.push_str(&format!("<li>{}</li>", esc(finding)));
            }
            html.push_str("</ul>");
        }
        if !host.learning_notes.is_empty() {
            html.push_str("<h3>Learning Notes</h3><ul>");
            for note in &host.learning_notes {
                html.push_str(&format!("<li>{}</li>", esc(note)));
            }
            html.push_str("</ul>");
        }
        if !host.defensive_advice.is_empty() {
            html.push_str("<h3>Defensive Advice</h3><ul>");
            for advice in &host.defensive_advice {
                html.push_str(&format!("<li>{}</li>", esc(advice)));
            }
            html.push_str("</ul>");
        }
        html.push_str("</div>");
    }

    html.push_str("</div></body></html>");
    html
}

fn esc(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for ch in input.chars() {
        match ch {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            _ => out.push(ch),
        }
    }
    out
}

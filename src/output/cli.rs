// Flow sketch: scan report -> renderer -> user-facing output
// Pseudo-block:
//   read input -> process safely -> return deterministic output

use crate::models::{PortFinding, PortState, ScanReport};
use crate::output::{
    actionable_summary_line, good_next_steps, host_os_profile, key_issue_lines,
    phantom_device_check_summary, service_detail_lines, service_label,
};

pub fn render(report: &ScanReport) -> String {
    let mut out = String::new();
    out.push_str(&format!(
        "Starting nprobe-rs {} at {}\n",
        env!("CARGO_PKG_VERSION"),
        report.metadata.started_at
    ));
    if let Some(session_id) = &report.metadata.session_id {
        out.push_str(&format!("Session: {session_id}\n"));
    }
    let shard_display = report.metadata.engine_stats.shard_index.saturating_add(1);
    out.push_str(&format!(
        "Engine mode: {} | rate: {} pps (burst {}) | retries: {} | host parallelism: {} | shard: {}/{} ({})\n",
        report.metadata.engine_stats.execution_mode,
        report.metadata.engine_stats.configured_rate_pps,
        report.metadata.engine_stats.configured_burst_size,
        report.metadata.engine_stats.max_retries,
        report.metadata.engine_stats.host_parallelism,
        shard_display,
        report.metadata.engine_stats.total_shards,
        report.metadata.engine_stats.shard_dimension
    ));
    out.push_str(&format!(
        "Role: {} | family: {} | safety model: {} | bundle: {} | resources: {} | integrity: {} ({}) | teaching: {} | safety envelope: {} | public-target policy: {} | profiled hosts: {} | fragile hosts: {} | suppressed ports: {}\n",
        report.metadata.engine_stats.framework_role,
        report.metadata.engine_stats.scan_family,
        report.metadata.engine_stats.safety_model,
        report.metadata.engine_stats.scan_bundle,
        report.metadata.engine_stats.resource_policy,
        report.metadata.engine_stats.integrity_state,
        report.metadata.engine_stats.integrity_manifest,
        if report.metadata.engine_stats.teaching_mode {
            "on"
        } else {
            "off"
        },
        if report.metadata.engine_stats.safety_envelope_active {
            "active"
        } else {
            "baseline"
        },
        if report.metadata.engine_stats.public_target_policy_applied {
            "applied"
        } else {
            "not-needed"
        },
        report.metadata.engine_stats.profiled_hosts,
        report.metadata.engine_stats.fragile_hosts,
        report.metadata.engine_stats.safety_ports_suppressed
    ));
    out.push_str(&format!(
        "Platform coverage: {} capabilities across {} tool families and {} domains (implemented {} | partial {} | planned {} | excluded {})\n",
        report.metadata.platform.capability_total,
        report.metadata.platform.tool_families.len(),
        report.metadata.platform.capability_domains.len(),
        report.metadata.platform.implemented,
        report.metadata.platform.partial,
        report.metadata.platform.planned,
        report.metadata.platform.intentionally_excluded
    ));
    out.push_str(
        "Workflow lanes: learners=interactive | fragile/unknown=phantom/kis/sar | specialists=nmap-style flags with safe semantics | audits=balanced/stealth\n",
    );
    if !report.metadata.engine_stats.scan_bundle_stages.is_empty() {
        out.push_str(&format!(
            "Bundle stages: {}\n",
            report.metadata.engine_stats.scan_bundle_stages.join(" -> ")
        ));
    }
    out.push_str(&format!(
        "Knowledge: services {} | payloads {} | rules {}/{} | NSE {} | nselib {} | OS signatures {} | OS classes {} | OS CPEs {}\n",
        report.metadata.knowledge.services_loaded,
        report.metadata.knowledge.probe_payloads_loaded,
        report.metadata.knowledge.fingerprint_rules_compiled,
        report.metadata.knowledge.fingerprint_rules_loaded,
        report.metadata.knowledge.nse_scripts_seen,
        report.metadata.knowledge.nselib_modules_seen,
        report.metadata.knowledge.os_fingerprint_signatures_loaded,
        report.metadata.knowledge.os_fingerprint_classes_loaded,
        report.metadata.knowledge.os_fingerprint_cpes_loaded
    ));

    if let Some(seed) = report.metadata.engine_stats.scan_seed {
        out.push_str(&format!("Scan seed: {seed}\n"));
    }
    if report.metadata.engine_stats.checkpoint_enabled {
        out.push_str(&format!(
            "Shard progress: {}/{} {} complete (resumed {})\n",
            report.metadata.engine_stats.checkpoint_completed_units,
            report.metadata.engine_stats.checkpoint_planned_units,
            report.metadata.engine_stats.checkpoint_unit_label,
            report.metadata.engine_stats.checkpoint_resumed_units
        ));
    }

    for host in &report.hosts {
        out.push_str(&format!(
            "\nNProbe scan report for {} ({})\n",
            host.target, host.ip
        ));
        let definite_response = host
            .ports
            .iter()
            .any(|p| matches!(p.state, PortState::Open | PortState::Closed));
        let ambiguous_response = host
            .ports
            .iter()
            .any(|p| matches!(p.state, PortState::OpenOrFiltered));

        if definite_response {
            out.push_str("Host is up.\n");
        } else if ambiguous_response {
            out.push_str("Host status: up or filtered (no definitive response).\n");
        } else {
            out.push_str("Host status: no definitive response (filtered or down).\n");
        }

        if let Some(reverse) = &host.reverse_dns {
            out.push_str(&format!("rDNS: {}\n", reverse));
        }
        if let Some(os_profile) = host_os_profile(host) {
            out.push_str(&format!("OS/profile: {os_profile}\n"));
        }
        if host.device_class.is_some() || host.observed_mac.is_some() {
            out.push_str(&format!(
                "Device profile: class={} vendor={} mac={}\n",
                host.device_class.as_deref().unwrap_or("unknown"),
                host.device_vendor.as_deref().unwrap_or("unknown"),
                host.observed_mac.as_deref().unwrap_or("unknown")
            ));
        }
        if let Some(summary) = phantom_device_check_summary(host) {
            out.push_str(&format!(
                "Device check: phantom stage={} responsive={}/{} timeout={} avg-latency={}ms payload-budget={} passive-follow-up={}\n",
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
                if summary.passive_follow_up { "yes" } else { "no" }
            ));
        }

        let open_like: Vec<&PortFinding> = host
            .ports
            .iter()
            .filter(|p| matches!(p.state, PortState::Open | PortState::OpenOrFiltered))
            .collect();
        let hidden = host.ports.len().saturating_sub(open_like.len());

        if open_like.is_empty() {
            out.push_str(&format!(
                "All {} scanned ports are closed or filtered\n",
                host.ports.len()
            ));
        } else {
            if hidden > 0 {
                out.push_str(&format!("Not shown: {} closed/filtered ports\n", hidden));
            }

            out.push_str("PORT     STATE         SERVICE\n");
            out.push_str("----     -----         -------\n");
            for p in &open_like {
                out.push_str(&format!(
                    "{:>5}/{} {:<13} {}\n",
                    p.port,
                    p.protocol,
                    p.state,
                    service_label(p)
                ));
            }
        }

        out.push_str(&format!("Risk score: {}/100\n", host.risk_score));
        if let Some(summary) = actionable_summary_line(host) {
            out.push_str(&format!("Actionable findings: {summary}\n"));
        }

        let key_issues = key_issue_lines(host);
        if !key_issues.is_empty() {
            out.push_str("What looks wrong:\n");
            for issue in &key_issues {
                out.push_str(&format!("- {}\n", issue));
            }
        }

        let next_steps = good_next_steps(host);
        if !next_steps.is_empty() {
            out.push_str("Good next steps:\n");
            for step in &next_steps {
                out.push_str(&format!("- {}\n", step));
            }
        }

        if report.request.explain && !open_like.is_empty() {
            out.push_str("Why these ports matter:\n");
            for p in &open_like {
                let reason = p.explanation.as_deref().unwrap_or(&p.reason);
                out.push_str(&format!("- {}/{}: {}\n", p.port, p.protocol, reason));
            }
        }

        if report.request.verbose {
            let detailed_ports: Vec<&PortFinding> = host
                .ports
                .iter()
                .filter(|p| !service_detail_lines(p).is_empty())
                .collect();
            if !detailed_ports.is_empty() {
                out.push_str("Service Details:\n");
                for port in detailed_ports {
                    out.push_str(&format!(
                        "- {}/{} {}\n",
                        port.port,
                        port.protocol,
                        service_label(port)
                    ));
                    for detail in service_detail_lines(port) {
                        out.push_str(&format!("  {detail}\n"));
                    }
                }
            }
            if !host.warnings.is_empty() {
                out.push_str("Warnings:\n");
                for warning in &host.warnings {
                    out.push_str(&format!("- {}\n", warning));
                }
            }
            if !host.safety_actions.is_empty() {
                out.push_str("Safety Actions:\n");
                for action in &host.safety_actions {
                    out.push_str(&format!("- {}\n", action));
                }
            }
            if !host.insights.is_empty() {
                out.push_str("Insights:\n");
                for insight in &host.insights {
                    out.push_str(&format!("- {}\n", insight));
                }
            }
            if !host.lua_findings.is_empty() {
                out.push_str("Lua Findings:\n");
                for finding in &host.lua_findings {
                    out.push_str(&format!("- {}\n", finding));
                }
            }
            if !host.learning_notes.is_empty() {
                out.push_str("Learning Notes:\n");
                for note in &host.learning_notes {
                    out.push_str(&format!("- {}\n", note));
                }
            }
            if !host.defensive_advice.is_empty() {
                out.push_str("Defensive Advice:\n");
                for advice in &host.defensive_advice {
                    out.push_str(&format!("- {}\n", advice));
                }
            }
        } else if !host.warnings.is_empty() {
            out.push_str(&format!(
                "Warnings: {} (use -v for detailed sections)\n",
                host.warnings.len()
            ));
        } else if !host.safety_actions.is_empty() {
            out.push_str(&format!(
                "Safety actions: {} (use -v for detailed sections)\n",
                host.safety_actions.len()
            ));
        }
    }

    let scanned = report.hosts.len();
    let hosts_responded = report
        .hosts
        .iter()
        .filter(|h| {
            h.ports
                .iter()
                .any(|p| matches!(p.state, PortState::Open | PortState::Closed))
        })
        .count();
    let seconds = report.metadata.duration_ms.max(0) as f64 / 1000.0;
    let ip_word = if scanned == 1 { "address" } else { "addresses" };
    let host_word = if hosts_responded == 1 {
        "host"
    } else {
        "hosts"
    };

    out.push_str(&format!(
        "\nNProbe done: {} IP {} ({} {} responded) scanned in {:.2} seconds\n",
        scanned, ip_word, hosts_responded, host_word, seconds
    ));
    out
}

// Flow sketch: scan report -> renderer -> user-facing output
// Pseudo-block:
//   read input -> process safely -> return deterministic output

use crate::models::{PortFinding, PortState, ScanReport};

pub fn render(report: &ScanReport) -> String {
    let mut out = String::new();
    out.push_str(&format!(
        "Starting nprobe-rs {} at {}\n",
        env!("CARGO_PKG_VERSION"),
        report.metadata.started_at
    ));
    out.push_str(&format!(
        "Engine mode: {} | rate target: {} pps | retries: {} | host parallelism: {}\n",
        report.metadata.engine_stats.execution_mode,
        report.metadata.engine_stats.configured_rate_pps,
        report.metadata.engine_stats.max_retries,
        report.metadata.engine_stats.host_parallelism
    ));

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
                    p.service.as_deref().unwrap_or("unknown")
                ));
            }
        }

        out.push_str(&format!("Risk score: {}/100\n", host.risk_score));

        if report.request.explain && !open_like.is_empty() {
            out.push_str("Why these ports matter:\n");
            for p in &open_like {
                let reason = p.explanation.as_deref().unwrap_or(&p.reason);
                out.push_str(&format!("- {}/{}: {}\n", p.port, p.protocol, reason));
            }
        }

        if report.request.verbose {
            if !host.warnings.is_empty() {
                out.push_str("Warnings:\n");
                for warning in &host.warnings {
                    out.push_str(&format!("- {}\n", warning));
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
    let host_word = if hosts_responded == 1 { "host" } else { "hosts" };

    out.push_str(&format!(
        "\nNProbe done: {} IP {} ({} {} responded) scanned in {:.2} seconds\n",
        scanned, ip_word, hosts_responded, host_word, seconds
    ));
    out
}

use crate::models::ScanReport;

pub fn render(report: &ScanReport) -> String {
    let mut html = String::new();
    html.push_str("<!doctype html><html><head><meta charset=\"utf-8\">");
    html.push_str("<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">");
    html.push_str("<title>NetProbe-RS Report</title>");
    html.push_str("<style>");
    html.push_str(
        ":root{--bg:#f6f8fb;--panel:#ffffff;--ink:#16212f;--muted:#6a7789;--accent:#0f7a6e;--warn:#8f3f2e;}
        body{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;background:linear-gradient(120deg,#f6f8fb,#edf2f8);color:var(--ink);margin:0;padding:24px;}
        .wrap{max-width:1100px;margin:0 auto;}
        .card{background:var(--panel);border:1px solid #e6ebf2;border-radius:14px;padding:18px;margin-bottom:18px;box-shadow:0 6px 20px rgba(10,20,40,.06);}
        h1,h2{margin:0 0 8px 0}
        .meta{color:var(--muted);font-size:14px}
        table{width:100%;border-collapse:collapse;margin-top:10px}
        th,td{padding:8px;border-bottom:1px solid #ecf1f7;text-align:left;font-size:13px;vertical-align:top}
        th{color:#33465c}
        .pill{display:inline-block;padding:2px 8px;border-radius:999px;background:#e7f8f4;color:var(--accent);font-size:12px}
        .warn{color:var(--warn)}
        ul{margin:6px 0 0 18px}
        </style></head><body><div class=\"wrap\">",
    );

    html.push_str("<div class=\"card\">");
    html.push_str("<h1>NetProbe-RS Report</h1>");
    html.push_str(&format!(
        "<div class=\"meta\">Started: {}<br>Finished: {}<br>Duration: {} ms</div>",
        report.metadata.started_at, report.metadata.finished_at, report.metadata.duration_ms
    ));
    html.push_str(&format!(
        "<div class=\"meta\">Async tasks: {} | Thread tasks: {} | Parallel tasks: {} | Lua hooks: {}</div>",
        report.metadata.engine_stats.async_engine_tasks,
        report.metadata.engine_stats.thread_pool_tasks,
        report.metadata.engine_stats.parallel_tasks,
        report.metadata.engine_stats.lua_hooks_ran
    ));
    html.push_str(&format!(
        "<div class=\"meta\">Knowledge: services {} | top ports {} | payloads {} | rules {}/{} (skipped {}) | NSE scripts {} | NSE libs {}</div>",
        report.metadata.knowledge.services_loaded,
        report.metadata.knowledge.ranked_tcp_ports,
        report.metadata.knowledge.probe_payloads_loaded,
        report.metadata.knowledge.fingerprint_rules_compiled,
        report.metadata.knowledge.fingerprint_rules_loaded,
        report.metadata.knowledge.fingerprint_rules_skipped,
        report.metadata.knowledge.nse_scripts_seen,
        report.metadata.knowledge.nselib_modules_seen
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
        for warning in &host.warnings {
            html.push_str(&format!(
                "<div class=\"meta warn\">Warning: {}</div>",
                esc(warning)
            ));
        }

        html.push_str("<table><thead><tr><th>Port</th><th>Proto</th><th>State</th><th>Service</th><th>Reason</th><th>Banner</th><th>Fingerprint</th><th>Learn</th></tr></thead><tbody>");
        for p in &host.ports {
            html.push_str(&format!(
                "<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{} ({})</td><td>{}</td></tr>",
                p.port,
                esc(&p.protocol),
                esc(&p.state.to_string()),
                esc(p.service.as_deref().unwrap_or("unknown")),
                esc(&p.reason),
                esc(p.banner.as_deref().unwrap_or("")),
                esc(p.matched_by.as_deref().unwrap_or("unknown")),
                p.confidence
                    .map(|v| format!("{v:.2}"))
                    .unwrap_or_else(|| "n/a".to_string()),
                esc(p.educational_note.as_deref().unwrap_or(""))
            ));
        }
        html.push_str("</tbody></table>");

        if !host.ai_findings.is_empty() {
            html.push_str("<h3>Insights</h3><ul>");
            for finding in &host.ai_findings {
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

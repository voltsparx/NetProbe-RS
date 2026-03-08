// Flow sketch: scan report -> renderer -> user-facing output
// Pseudo-block:
//   read input -> process safely -> return deterministic output

use std::path::Path;

use crate::engines::thread_pool;
use crate::error::NProbeResult;
use crate::models::{
    HostResult, PhantomDeviceCheckSummary, PortFinding, PortState, ReportFormat, ScanReport,
};
use crate::reporter::actionable;
use crate::reporter::actionable::ActionableItem;

pub mod cli;
pub mod csv;
pub mod html;
pub mod json;
pub mod txt;

pub(crate) fn phantom_device_check_summary(host: &HostResult) -> Option<PhantomDeviceCheckSummary> {
    host.phantom_device_check_summary()
}

pub(crate) fn host_os_profile(host: &HostResult) -> Option<String> {
    host.operating_system.as_ref().map(|guess| {
        format!(
            "{} (source={} confidence={:.2})",
            guess.label, guess.source, guess.confidence
        )
    })
}

pub(crate) fn service_label(port: &PortFinding) -> String {
    match (&port.service, &port.service_identity) {
        (Some(service), Some(identity)) => {
            let mut label = service.clone();
            if let Some(product) = &identity.product {
                label.push_str(" [");
                label.push_str(product);
                if let Some(version) = &identity.version {
                    label.push(' ');
                    label.push_str(version);
                }
                label.push(']');
            }
            label
        }
        (Some(service), None) => service.clone(),
        (None, Some(identity)) => {
            if let Some(product) = &identity.product {
                if let Some(version) = &identity.version {
                    format!("{product} {version}")
                } else {
                    product.clone()
                }
            } else {
                "unknown".to_string()
            }
        }
        (None, None) => "unknown".to_string(),
    }
}

pub(crate) fn service_detail_lines(port: &PortFinding) -> Vec<String> {
    let mut lines = Vec::new();
    if let Some(identity) = &port.service_identity {
        if let Some(product) = &identity.product {
            let mut detail = format!("product={product}");
            if let Some(version) = &identity.version {
                detail.push_str(&format!(" version={version}"));
            }
            lines.push(detail);
        } else if let Some(version) = &identity.version {
            lines.push(format!("version={version}"));
        }
        if let Some(info) = &identity.info {
            lines.push(format!("info={info}"));
        }
        if let Some(hostname) = &identity.hostname {
            lines.push(format!("host={hostname}"));
        }
        if let Some(os) = &identity.operating_system {
            lines.push(format!("os={os}"));
        }
        if let Some(device_type) = &identity.device_type {
            lines.push(format!("device={device_type}"));
        }
        if !identity.cpes.is_empty() {
            lines.push(format!("cpe={}", identity.cpes.join(", ")));
        }
    }
    for hint in &port.vulnerability_hints {
        lines.push(format!("hint={hint}"));
    }
    lines
}

pub(crate) fn open_service_inventory(host: &HostResult) -> Vec<String> {
    let mut services = host
        .ports
        .iter()
        .filter(|port| matches!(port.state, PortState::Open | PortState::OpenOrFiltered))
        .map(|port| format!("{}/{} {}", port.port, port.protocol, service_label(port)))
        .collect::<Vec<_>>();
    services.sort();
    services.dedup();
    services
}

pub(crate) fn host_discovery_confirmed(host: &HostResult) -> bool {
    host.ports
        .iter()
        .any(|port| matches!(port.state, PortState::Open | PortState::Closed))
        || host
            .safety_actions
            .iter()
            .any(|action| action == "host-discovery:confirmed-up")
}

pub(crate) fn host_discovery_evidence(host: &HostResult) -> Vec<String> {
    let mut evidence = host
        .insights
        .iter()
        .filter(|line| {
            line.starts_with("icmp reachability confirmed")
                || line.starts_with("arp neighbor:")
                || line.starts_with("tcp discovery:")
        })
        .cloned()
        .collect::<Vec<_>>();
    evidence.sort();
    evidence.dedup();
    evidence
}

pub(crate) fn host_traceroute_summary(host: &HostResult) -> Option<String> {
    host.insights
        .iter()
        .find(|line| line.starts_with("traceroute:"))
        .cloned()
}

pub(crate) fn key_issue_lines(host: &HostResult) -> Vec<String> {
    top_actionable_items(host)
        .into_iter()
        .take(5)
        .map(|item| format!("[{}] {}", item.severity, item.issue))
        .collect()
}

pub(crate) fn good_next_steps(host: &HostResult) -> Vec<String> {
    let mut steps = Vec::new();
    for item in top_actionable_items(host) {
        if steps.iter().any(|existing| existing == &item.action) {
            continue;
        }
        steps.push(item.action);
        if steps.len() >= 5 {
            break;
        }
    }
    if steps.is_empty() {
        steps.extend(host.defensive_advice.iter().take(5).cloned());
    }
    steps
}

pub(crate) fn top_actionable_items(host: &HostResult) -> Vec<ActionableItem> {
    actionable::collect(host).into_iter().take(5).collect()
}

pub(crate) fn actionable_summary_line(host: &HostResult) -> Option<String> {
    let summary = actionable::summarize(host);
    if summary.total == 0 {
        return None;
    }
    Some(format!(
        "critical={} high={} moderate={} review={}",
        summary.critical, summary.high, summary.moderate, summary.review
    ))
}

pub fn render(report: &ScanReport, format: ReportFormat) -> NProbeResult<String> {
    match format {
        ReportFormat::Cli => Ok(cli::render(report)),
        ReportFormat::Txt => Ok(txt::render(report)),
        ReportFormat::Json => json::render(report),
        ReportFormat::Html => Ok(html::render(report)),
        ReportFormat::Csv => csv::render(report),
    }
}

pub async fn emit(
    body: &str,
    format: ReportFormat,
    output_path: Option<&Path>,
) -> NProbeResult<()> {
    match output_path {
        Some(path) => {
            thread_pool::write_output(path, body).await?;
            if matches!(format, ReportFormat::Cli) {
                println!("{body}");
            } else {
                println!("report written: {}", path.display());
            }
        }
        None => println!("{body}"),
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{
        host_discovery_confirmed, host_discovery_evidence, host_traceroute_summary,
        open_service_inventory,
    };
    use crate::models::{HostResult, PortFinding, PortState, ServiceIdentity};

    #[test]
    fn open_service_inventory_lists_open_ports_with_labels() {
        let host = HostResult {
            target: "example".to_string(),
            ip: "10.0.0.5".to_string(),
            reverse_dns: None,
            observed_mac: None,
            device_class: None,
            device_vendor: None,
            operating_system: None,
            phantom_device_check: None,
            safety_actions: Vec::new(),
            warnings: Vec::new(),
            ports: vec![
                PortFinding {
                    port: 22,
                    protocol: "tcp".to_string(),
                    state: PortState::Open,
                    service: Some("ssh".to_string()),
                    service_identity: None,
                    banner: None,
                    reason: "open".to_string(),
                    matched_by: None,
                    confidence: None,
                    vulnerability_hints: Vec::new(),
                    educational_note: None,
                    latency_ms: None,
                    explanation: None,
                },
                PortFinding {
                    port: 443,
                    protocol: "tcp".to_string(),
                    state: PortState::Open,
                    service: Some("https".to_string()),
                    service_identity: Some(ServiceIdentity {
                        product: Some("nginx".to_string()),
                        version: Some("1.25".to_string()),
                        ..ServiceIdentity::default()
                    }),
                    banner: None,
                    reason: "open".to_string(),
                    matched_by: None,
                    confidence: None,
                    vulnerability_hints: Vec::new(),
                    educational_note: None,
                    latency_ms: None,
                    explanation: None,
                },
                PortFinding {
                    port: 53,
                    protocol: "udp".to_string(),
                    state: PortState::Closed,
                    service: Some("domain".to_string()),
                    service_identity: None,
                    banner: None,
                    reason: "closed".to_string(),
                    matched_by: None,
                    confidence: None,
                    vulnerability_hints: Vec::new(),
                    educational_note: None,
                    latency_ms: None,
                    explanation: None,
                },
            ],
            risk_score: 0,
            insights: Vec::new(),
            defensive_advice: Vec::new(),
            learning_notes: Vec::new(),
            lua_findings: Vec::new(),
        };

        let inventory = open_service_inventory(&host);
        assert_eq!(inventory.len(), 2);
        assert!(inventory.iter().any(|line| line == "22/tcp ssh"));
        assert!(inventory
            .iter()
            .any(|line| line == "443/tcp https [nginx 1.25]"));
    }

    #[test]
    fn discovery_helpers_use_safety_actions_and_insights() {
        let host = HostResult {
            target: "example".to_string(),
            ip: "10.0.0.5".to_string(),
            reverse_dns: None,
            observed_mac: None,
            device_class: None,
            device_vendor: None,
            operating_system: None,
            phantom_device_check: None,
            safety_actions: vec!["host-discovery:confirmed-up".to_string()],
            warnings: Vec::new(),
            ports: Vec::new(),
            risk_score: 0,
            insights: vec![
                "icmp reachability confirmed (2.4 ms)".to_string(),
                "tcp discovery: 10.0.0.5:80 refused a lightweight connect probe, which still confirms the host stack is reachable".to_string(),
            ],
            defensive_advice: Vec::new(),
            learning_notes: Vec::new(),
            lua_findings: Vec::new(),
        };

        assert!(host_discovery_confirmed(&host));
        let evidence = host_discovery_evidence(&host);
        assert_eq!(evidence.len(), 2);
        assert!(evidence
            .iter()
            .any(|line| line.starts_with("icmp reachability confirmed")));
        assert!(evidence
            .iter()
            .any(|line| line.starts_with("tcp discovery:")));
    }

    #[test]
    fn traceroute_helper_surfaces_prefixed_insight() {
        let host = HostResult {
            target: "example".to_string(),
            ip: "10.0.0.9".to_string(),
            reverse_dns: None,
            observed_mac: None,
            device_class: None,
            device_vendor: None,
            operating_system: None,
            phantom_device_check: None,
            safety_actions: Vec::new(),
            warnings: Vec::new(),
            ports: Vec::new(),
            risk_score: 0,
            insights: vec![
                "traceroute: observed 3 hop(s) toward 10.0.0.9 via 10.0.0.1 -> 10.0.0.9"
                    .to_string(),
            ],
            defensive_advice: Vec::new(),
            learning_notes: Vec::new(),
            lua_findings: Vec::new(),
        };

        assert_eq!(
            host_traceroute_summary(&host).as_deref(),
            Some("traceroute: observed 3 hop(s) toward 10.0.0.9 via 10.0.0.1 -> 10.0.0.9")
        );
    }
}

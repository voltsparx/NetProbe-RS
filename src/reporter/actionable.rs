use std::collections::BTreeSet;
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::models::{HostResult, PortFinding, PortState};
use crate::reporter::service_knowledge;

#[derive(Debug, Clone, Copy, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ActionableSeverity {
    Review,
    Moderate,
    High,
    Critical,
}

impl ActionableSeverity {
    pub fn as_str(self) -> &'static str {
        match self {
            ActionableSeverity::Review => "review",
            ActionableSeverity::Moderate => "moderate",
            ActionableSeverity::High => "high",
            ActionableSeverity::Critical => "critical",
        }
    }

    pub fn rank(self) -> u8 {
        match self {
            ActionableSeverity::Critical => 4,
            ActionableSeverity::High => 3,
            ActionableSeverity::Moderate => 2,
            ActionableSeverity::Review => 1,
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "review" => Some(ActionableSeverity::Review),
            "moderate" => Some(ActionableSeverity::Moderate),
            "high" => Some(ActionableSeverity::High),
            "critical" => Some(ActionableSeverity::Critical),
            _ => None,
        }
    }
}

impl fmt::Display for ActionableSeverity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
pub struct ActionableItem {
    pub severity: ActionableSeverity,
    pub issue: String,
    pub action: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ActionableSummary {
    #[serde(default)]
    pub items: Vec<ActionableItem>,
    pub total: usize,
    pub critical: usize,
    pub high: usize,
    pub moderate: usize,
    pub review: usize,
}

pub fn collect(host: &HostResult) -> Vec<ActionableItem> {
    let open_ports = host
        .ports
        .iter()
        .filter(|port| matches!(port.state, PortState::Open | PortState::OpenOrFiltered))
        .collect::<Vec<_>>();

    let mut items = BTreeSet::new();

    if open_ports.len() >= 20 {
        insert_item(
            &mut items,
            ActionableSeverity::High,
            "The host exposes a very broad network service surface, which increases attack-path options and weakens segmentation assumptions.",
            "Reduce listener sprawl, disable unused services, and move admin-only protocols behind dedicated management paths.",
        );
    } else if open_ports.len() >= 8 {
        insert_item(
            &mut items,
            ActionableSeverity::Moderate,
            "The host exposes a moderate number of reachable services, so role drift or stale listeners are worth reviewing.",
            "Confirm the host role, remove listeners that do not match that role, and review host firewall policy against the intended baseline.",
        );
    }

    let service_names = open_ports
        .iter()
        .filter_map(|port| port.service.as_deref())
        .map(|service| service.to_ascii_lowercase())
        .collect::<BTreeSet<_>>();

    if service_names.contains("ftp") && service_names.contains("ssh") {
        insert_item(
            &mut items,
            ActionableSeverity::Moderate,
            "Both legacy and modern remote administration channels are exposed, which often signals incomplete migration away from weaker protocols.",
            "Retire legacy remote administration paths, keep SSH tightly scoped, and document the approved management entrypoint.",
        );
    }

    if service_names.contains("http") && !service_names.contains("https") {
        insert_item(
            &mut items,
            ActionableSeverity::Moderate,
            "HTTP is reachable without HTTPS being observed in the scanned scope, so plaintext access or downgrade paths may still exist.",
            "Redirect HTTP to HTTPS, review whether admin routes are exposed, and confirm that TLS is the enforced management and user path.",
        );
    }

    for port in open_ports {
        for hint in &port.vulnerability_hints {
            items.insert(ActionableItem {
                severity: severity_for_hint(port, hint),
                issue: format!(
                    "{}/{} {}: {}",
                    port.port,
                    port.protocol,
                    service_name(port),
                    hint
                ),
                action: action_for_hint(port, hint),
            });
        }

        if port.port == 23 || service_is(port, "telnet") {
            items.insert(ActionableItem {
                severity: ActionableSeverity::Critical,
                issue: format!(
                    "{}/{} {} exposes plaintext remote administration traffic.",
                    port.port,
                    port.protocol,
                    service_name(port)
                ),
                action: "Replace Telnet with SSH or another encrypted admin path, and isolate any unavoidable legacy endpoint behind strict network policy.".to_string(),
            });
        }

        if matches!(port.port, 139 | 445)
            || service_is(port, "microsoft-ds")
            || service_is(port, "netbios-ssn")
        {
            items.insert(ActionableItem {
                severity: ActionableSeverity::High,
                issue: format!(
                    "{}/{} {} exposes Windows file-sharing or identity-facing surface beyond the host boundary.",
                    port.port,
                    port.protocol,
                    service_name(port)
                ),
                action: "Restrict SMB and NetBIOS exposure to trusted segments, remove guest-style access, and verify that the host truly needs file-sharing reachability.".to_string(),
            });
        }

        if matches!(port.port, 3306 | 5432 | 27017 | 6379)
            || service_is(port, "mysql")
            || service_is(port, "postgresql")
            || service_is(port, "mongodb")
            || service_is(port, "redis")
        {
            items.insert(ActionableItem {
                severity: ActionableSeverity::High,
                issue: format!(
                    "{}/{} {} is reachable as a network data service, which raises credential, backup, and admin-surface risk.",
                    port.port,
                    port.protocol,
                    service_name(port)
                ),
                action: "Keep databases and data stores on private interfaces, require authentication, and limit reachability to application or management tiers only.".to_string(),
            });
        }

        if matches!(port.port, 3389 | 5900) || service_is(port, "ms-wbt-server") {
            items.insert(ActionableItem {
                severity: ActionableSeverity::Moderate,
                issue: format!(
                    "{}/{} {} exposes an interactive remote desktop surface.",
                    port.port,
                    port.protocol,
                    service_name(port)
                ),
                action: "Gate remote desktop access behind VPN or jump-host controls, enforce MFA, and verify that remote admin exposure is intentionally documented.".to_string(),
            });
        }
    }

    let mut items = items.into_iter().collect::<Vec<_>>();
    items.sort_by(|left, right| {
        right
            .severity
            .rank()
            .cmp(&left.severity.rank())
            .then_with(|| left.issue.cmp(&right.issue))
            .then_with(|| left.action.cmp(&right.action))
    });
    items
}

pub fn summarize(host: &HostResult) -> ActionableSummary {
    summarize_items(&collect(host))
}

pub fn summarize_items(items: &[ActionableItem]) -> ActionableSummary {
    let mut summary = ActionableSummary {
        items: items.to_vec(),
        total: items.len(),
        ..ActionableSummary::default()
    };

    for item in items {
        match item.severity {
            ActionableSeverity::Critical => summary.critical += 1,
            ActionableSeverity::High => summary.high += 1,
            ActionableSeverity::Moderate => summary.moderate += 1,
            ActionableSeverity::Review => summary.review += 1,
        }
    }

    summary
}

fn insert_item(
    items: &mut BTreeSet<ActionableItem>,
    severity: ActionableSeverity,
    issue: &str,
    action: &str,
) {
    items.insert(ActionableItem {
        severity,
        issue: issue.to_string(),
        action: action.to_string(),
    });
}

fn action_for_hint(port: &PortFinding, hint: &str) -> String {
    if hint.contains("plaintext") || hint.contains("legacy or plaintext") {
        return "Replace plaintext administration protocols with encrypted equivalents or isolate them behind tightly controlled management paths.".to_string();
    }
    if hint.contains("data service reachable") {
        return "Keep data services on private interfaces, require authentication, and verify that backups and admin APIs are not broadly reachable.".to_string();
    }
    if hint.contains("web application or admin surface") {
        return "Review exposed web login surfaces, enforce MFA where possible, and prefer VPN or jump-host access for administration.".to_string();
    }
    if hint.contains("network infrastructure management surface") {
        return "Move infrastructure management to dedicated admin networks and verify that default credentials and legacy TLS are gone.".to_string();
    }
    if hint.contains("embedded printing surface") {
        return "Keep printer management on trusted device VLANs, disable unused services, and review firmware support before deeper checks.".to_string();
    }
    if hint.contains("mail service exposed") {
        return "Restrict mail services to intended roles, require authentication and TLS, and confirm relay behavior is limited to known senders.".to_string();
    }

    default_action_for_port(port)
}

fn severity_for_hint(port: &PortFinding, hint: &str) -> ActionableSeverity {
    if hint.contains("plaintext") || hint.contains("legacy or plaintext") {
        return ActionableSeverity::Critical;
    }
    if hint.contains("data service reachable")
        || hint.contains("network infrastructure management surface")
    {
        return ActionableSeverity::High;
    }
    if hint.contains("web application or admin surface")
        || hint.contains("mail service exposed")
        || hint.contains("embedded printing surface")
    {
        return ActionableSeverity::Moderate;
    }
    if hint.contains("legacy Apache")
        || hint.contains("legacy OpenSSL")
        || hint.contains("older IIS")
        || hint.contains("older ProFTPD")
    {
        return ActionableSeverity::High;
    }

    match port.port {
        23 | 21 | 139 | 445 | 3306 | 5432 | 27017 | 6379 => ActionableSeverity::High,
        80 | 8080 | 3389 | 5900 => ActionableSeverity::Moderate,
        _ => ActionableSeverity::Review,
    }
}

fn default_action_for_port(port: &PortFinding) -> String {
    match port.port {
        22 => {
            "Restrict SSH by source IP, disable password login, and enforce key-based authentication."
                .to_string()
        }
        21 | 23 => "Replace FTP or Telnet with encrypted alternatives and isolate any legacy endpoints behind strict network controls.".to_string(),
        80 | 8080 => "Redirect HTTP to HTTPS and review whether any web administration surface is exposed more broadly than intended.".to_string(),
        443 | 8443 => {
            "Harden TLS policy, review certificate posture, and remove weak compatibility modes."
                .to_string()
        }
        445 | 139 => {
            "Limit SMB and NetBIOS access to trusted VLANs and remove guest-style or anonymous access paths."
                .to_string()
        }
        3306 | 5432 | 27017 | 6379 => {
            "Keep databases off public interfaces and enforce both authentication and network ACLs."
                .to_string()
        }
        3389 | 5900 => {
            "Gate remote desktop access behind a VPN or jump host and enforce MFA for administration."
                .to_string()
        }
        _ => "Review whether this service belongs on this host, who needs network reachability to it, and whether segmentation matches that intent.".to_string(),
    }
}

fn service_is(port: &PortFinding, expected: &str) -> bool {
    port.service
        .as_deref()
        .map(|service| service.eq_ignore_ascii_case(expected))
        .unwrap_or(false)
}

fn service_name(port: &PortFinding) -> String {
    match &port.service_identity {
        Some(identity) => service_knowledge::describe_identity(port.service.as_deref(), identity),
        None => port
            .service
            .clone()
            .unwrap_or_else(|| "unknown service".to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{HostResult, ServiceIdentity};

    #[test]
    fn actionable_items_include_telnet_guidance() {
        let host = HostResult {
            target: "legacy-device".to_string(),
            ip: "10.0.0.5".to_string(),
            reverse_dns: None,
            observed_mac: None,
            device_class: None,
            device_vendor: None,
            phantom_device_check: None,
            safety_actions: Vec::new(),
            warnings: Vec::new(),
            ports: vec![PortFinding {
                port: 23,
                protocol: "tcp".to_string(),
                state: PortState::Open,
                service: Some("telnet".to_string()),
                service_identity: Some(ServiceIdentity::default()),
                banner: None,
                reason: "test".to_string(),
                matched_by: None,
                confidence: None,
                vulnerability_hints: vec![
                    "legacy or plaintext remote service exposed; verify that encrypted replacements or strict segmentation are in place.".to_string(),
                ],
                educational_note: None,
                latency_ms: None,
                explanation: None,
            }],
            risk_score: 0,
            insights: Vec::new(),
            defensive_advice: Vec::new(),
            learning_notes: Vec::new(),
            lua_findings: Vec::new(),
        };

        let items = collect(&host);
        assert!(items
            .iter()
            .any(|item| item.issue.contains("plaintext remote administration")));
        assert!(items.iter().any(|item| item.action.contains("encrypted")));
        assert!(items
            .iter()
            .any(|item| item.severity == ActionableSeverity::Critical));
    }

    #[test]
    fn summarize_counts_severity_levels() {
        let items = vec![
            ActionableItem {
                severity: ActionableSeverity::Critical,
                issue: "a".to_string(),
                action: "b".to_string(),
            },
            ActionableItem {
                severity: ActionableSeverity::High,
                issue: "c".to_string(),
                action: "d".to_string(),
            },
            ActionableItem {
                severity: ActionableSeverity::Review,
                issue: "e".to_string(),
                action: "f".to_string(),
            },
        ];

        let summary = summarize_items(&items);
        assert_eq!(summary.total, 3);
        assert_eq!(summary.critical, 1);
        assert_eq!(summary.high, 1);
        assert_eq!(summary.moderate, 0);
        assert_eq!(summary.review, 1);
    }
}

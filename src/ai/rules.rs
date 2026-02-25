use std::collections::BTreeSet;

use crate::models::{HostResult, PortState};

pub fn generate_findings(host: &HostResult) -> Vec<String> {
    let mut findings = Vec::new();
    let open_ports = host
        .ports
        .iter()
        .filter(|p| matches!(p.state, PortState::Open | PortState::OpenOrFiltered))
        .count();

    if open_ports == 0 {
        findings.push("No open or open|filtered ports detected in selected scope".to_string());
        return findings;
    }

    if open_ports >= 20 {
        findings.push("Very broad exposed port surface observed".to_string());
    } else if open_ports >= 8 {
        findings.push("Moderate exposed service footprint observed".to_string());
    }

    let mut open_services = BTreeSet::new();
    for port in &host.ports {
        if matches!(port.state, PortState::Open | PortState::OpenOrFiltered) {
            if let Some(service) = &port.service {
                open_services.insert(service.to_ascii_lowercase());
            }
        }
    }

    if open_services.contains("ftp") && open_services.contains("ssh") {
        findings.push("Legacy and modern remote admin channels are both exposed".to_string());
    }
    if open_services.contains("telnet") {
        findings.push("Telnet exposure indicates weak transport security posture".to_string());
    }
    if open_services.contains("http") && !open_services.contains("https") {
        findings.push("HTTP is exposed without HTTPS observed in scanned scope".to_string());
    }
    if open_services.contains("microsoft-ds") || open_services.contains("netbios-ssn") {
        findings.push("Windows file-sharing ports are reachable".to_string());
    }
    if open_services.contains("mysql") || open_services.contains("postgresql") {
        findings.push("Database service is reachable over the network".to_string());
    }

    findings
}

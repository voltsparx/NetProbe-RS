use std::collections::BTreeSet;

use crate::models::{HostResult, PortState};

pub fn build_advice(host: &HostResult) -> Vec<String> {
    let mut advice = BTreeSet::new();
    for finding in &host.ports {
        if !matches!(finding.state, PortState::Open | PortState::OpenOrFiltered) {
            continue;
        }

        match finding.port {
            22 => {
                advice.insert(
                    "Restrict SSH by source IP, disable password login, and enforce key auth"
                        .to_string(),
                );
            }
            21 | 23 => {
                advice.insert(
                    "Replace FTP/Telnet with encrypted alternatives and isolate legacy endpoints"
                        .to_string(),
                );
            }
            80 | 8080 => {
                advice.insert(
                    "Redirect HTTP to HTTPS and review exposed web admin interfaces".to_string(),
                );
            }
            443 | 8443 => {
                advice.insert("Harden TLS configuration and disable weak ciphers".to_string());
            }
            445 | 139 => {
                advice.insert(
                    "Limit SMB/NetBIOS access to trusted VLANs and disable guest share access"
                        .to_string(),
                );
            }
            3306 | 5432 | 27017 | 6379 => {
                advice.insert(
                    "Keep databases off public interfaces and require network ACL + authentication"
                        .to_string(),
                );
            }
            3389 | 5900 => {
                advice.insert(
                    "Gate remote desktop access behind VPN/jump-host and enforce MFA".to_string(),
                );
            }
            _ => {}
        }

        if let Some(service) = &finding.service {
            if service.eq_ignore_ascii_case("smtp") {
                advice.insert(
                    "Enable SMTP auth/TLS and restrict relay behavior to known senders".to_string(),
                );
            }
        }
    }

    if advice.is_empty() {
        advice.insert(
            "Maintain host firewall defaults and continue periodic baseline scans".to_string(),
        );
    }

    advice.into_iter().collect()
}

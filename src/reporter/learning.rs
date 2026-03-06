// Flow sketch: ports -> scoring/findings/guidance -> insights
// Pseudo-block:
//   read input -> process safely -> return deterministic output

use std::collections::BTreeSet;

use crate::models::{HostResult, PortFinding, PortState};

pub fn attach_port_notes(ports: &mut [PortFinding]) {
    for finding in ports {
        finding.educational_note = teaching_note_for(finding);
    }
}

pub fn build_learning_notes(host: &HostResult) -> Vec<String> {
    let mut notes = BTreeSet::new();
    let open_count = host
        .ports
        .iter()
        .filter(|p| matches!(p.state, PortState::Open | PortState::OpenOrFiltered))
        .count();
    if open_count == 0 {
        notes.insert(
            "Learning: a fully closed result still matters; it confirms reachable host behavior and filtering posture."
                .to_string(),
        );
    } else {
        notes.insert(format!(
            "Learning: {} reachable service(s) were observed; prioritize least-privilege exposure.",
            open_count
        ));
    }

    for p in &host.ports {
        if !matches!(p.state, PortState::Open | PortState::OpenOrFiltered) {
            continue;
        }
        if let Some(service) = &p.service {
            if service.eq_ignore_ascii_case("http") || service.eq_ignore_ascii_case("https") {
                notes.insert(
                    "Learning: web services should be reviewed for auth, TLS policy, and exposed admin paths."
                        .to_string(),
                );
            }
            if service.eq_ignore_ascii_case("ssh") {
                notes.insert(
                    "Learning: SSH is safer than Telnet but still high impact if brute-force protections are weak."
                        .to_string(),
                );
            }
            if service.eq_ignore_ascii_case("dns") || service.eq_ignore_ascii_case("domain") {
                notes.insert(
                    "Learning: exposed DNS can leak internal structure and should enforce recursion controls."
                        .to_string(),
                );
            }
        }
    }

    if let Some(device_class) = host.device_class.as_deref() {
        match device_class {
            "fragile-embedded" => {
                notes.insert(
                    "Learning: fragile embedded targets were scanned in a reduced-pressure mode to avoid disrupting low-power systems."
                        .to_string(),
                );
            }
            "printer-sensitive" => {
                notes.insert(
                    "Learning: printer-like targets can misbehave on legacy print ports, so nprobe-rs preserved safety by suppressing risky probes."
                        .to_string(),
                );
            }
            "enterprise" => {
                notes.insert(
                    "Learning: enterprise-class hardware tolerates broader discovery, but service exposure still needs human review."
                        .to_string(),
                );
            }
            _ => {
                notes.insert(
                    "Learning: the device profile remained generic, so the framework kept conservative assumptions."
                        .to_string(),
                );
            }
        }
    }

    if !host.safety_actions.is_empty() {
        notes.insert(format!(
            "Learning: safety automation applied {} runtime action(s) for this host.",
            host.safety_actions.len()
        ));
    }

    notes.into_iter().collect()
}

fn teaching_note_for(finding: &PortFinding) -> Option<String> {
    let state_prefix = match finding.state {
        PortState::Open => "Teach: open means the service accepted interaction",
        PortState::Closed => "Teach: closed means host replied but nothing is listening",
        PortState::Filtered => "Teach: filtered usually means firewall or packet loss",
        PortState::OpenOrFiltered => "Teach: open|filtered is common for UDP ambiguity",
    };

    let service_note = if let Some(service) = &finding.service {
        match service.to_ascii_lowercase().as_str() {
            "ssh" => "SSH is encrypted remote administration.",
            "telnet" => "Telnet is plaintext and high risk on untrusted networks.",
            "ftp" => "FTP often exposes plaintext credentials unless wrapped.",
            "http" => "HTTP should usually be redirected to HTTPS.",
            "https" => "HTTPS security depends on certificate and cipher policy.",
            "smtp" => "SMTP requires anti-relay controls and TLS hardening.",
            "microsoft-ds" => "SMB exposure can increase lateral movement risk.",
            "mysql" | "postgresql" => "Databases should be restricted to trusted network zones.",
            _ => "Service identified from port or fingerprint evidence.",
        }
    } else {
        "Service could not be confidently identified."
    };

    Some(format!("{state_prefix}. {service_note}"))
}

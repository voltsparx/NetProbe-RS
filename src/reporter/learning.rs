// Flow sketch: ports -> scoring/findings/guidance -> insights
// Pseudo-block:
//   read input -> process safely -> return deterministic output

use crate::models::{HostResult, PortFinding, PortState};
use crate::reporter::learning_guides;

pub fn attach_port_notes(ports: &mut [PortFinding]) {
    for finding in ports {
        finding.educational_note = teaching_note_for(finding);
    }
}

pub fn build_learning_notes(host: &HostResult) -> Vec<String> {
    learning_guides::build_host_notes(host)
}

fn teaching_note_for(finding: &PortFinding) -> Option<String> {
    let state_prefix = match finding.state {
        PortState::Open => "Teach: open means the service accepted interaction",
        PortState::Closed => "Teach: closed means host replied but nothing is listening",
        PortState::Filtered => "Teach: filtered usually means firewall or packet loss",
        PortState::Unfiltered => {
            "Teach: unfiltered means the host replied to a filter-mapping probe, but this does not prove an open service"
        }
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

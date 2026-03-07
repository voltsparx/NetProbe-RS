use std::collections::BTreeSet;

use crate::models::{HostResult, PortState};

pub fn collect(host: &HostResult, notes: &mut BTreeSet<String>) {
    for port in &host.ports {
        if !matches!(port.state, PortState::Open | PortState::OpenOrFiltered) {
            continue;
        }

        if let Some(service) = &port.service {
            match service.to_ascii_lowercase().as_str() {
                "http" | "https" => {
                    notes.insert(
                        "Learning: web services should be reviewed for authentication boundaries, TLS policy, and exposed admin paths."
                            .to_string(),
                    );
                }
                "ssh" => {
                    notes.insert(
                        "Learning: SSH is preferable to Telnet, but it still needs key hygiene, MFA where possible, and brute-force protection."
                            .to_string(),
                    );
                }
                "dns" | "domain" => {
                    notes.insert(
                        "Learning: exposed DNS can leak internal structure and should enforce recursion and transfer controls."
                            .to_string(),
                    );
                }
                "microsoft-ds" | "netbios-ssn" => {
                    notes.insert(
                        "Learning: SMB exposure increases lateral movement risk; restrict it to trusted zones and remove legacy protocol support."
                            .to_string(),
                    );
                }
                "telnet" => {
                    notes.insert(
                        "Learning: Telnet is plaintext administration. Replace it with SSH or an authenticated management channel."
                            .to_string(),
                    );
                }
                "ftp" | "ftp-data" => {
                    notes.insert(
                        "Learning: FTP often exposes plaintext credentials and data. Prefer SFTP or another encrypted transfer workflow."
                            .to_string(),
                    );
                }
                "imap" | "pop3" | "submission" | "smtp" | "smtps" => {
                    notes.insert(
                        "Learning: mail services should enforce authentication, TLS, anti-relay controls, and tight exposure boundaries."
                            .to_string(),
                    );
                }
                "ldap" => {
                    notes.insert(
                        "Learning: LDAP often holds identity-critical data. Restrict who can reach it and prefer LDAPS or StartTLS where possible."
                            .to_string(),
                    );
                }
                "snmp" => {
                    notes.insert(
                        "Learning: SNMP can leak high-value operational data. Prefer SNMPv3 and restrict access to management networks."
                            .to_string(),
                    );
                }
                "mysql" | "postgresql" | "mongodb" | "redis" | "memcached" => {
                    notes.insert(
                        "Learning: data stores should not sit on broad network edges. Use ACLs, authentication, and private network placement."
                            .to_string(),
                    );
                }
                "ms-wbt-server" | "vnc" => {
                    notes.insert(
                        "Learning: remote desktop services should sit behind VPN or jump-host controls and require strong authentication."
                            .to_string(),
                    );
                }
                "ipp" => {
                    notes.insert(
                        "Learning: printing services can be fragile and chatty. Restrict them to trusted device zones and monitor exposed admin paths."
                            .to_string(),
                    );
                }
                "ntp" | "syslog" => {
                    notes.insert(
                        "Learning: infrastructure services can aid time sync and visibility, but they also reveal topology and should stay inside trusted zones."
                            .to_string(),
                    );
                }
                "msrpc" | "rpcbind" => {
                    notes.insert(
                        "Learning: RPC-style services expand lateral movement paths. Segment them tightly and remove anything not actively required."
                            .to_string(),
                    );
                }
                _ => {}
            }

            notes.insert(format!(
                "Learning: service `{}` was identified from port or fingerprint evidence; confirm whether that exposure is expected before acting on it.",
                service
            ));
        }
    }
}

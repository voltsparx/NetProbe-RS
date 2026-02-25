use std::collections::BTreeSet;

use rayon::prelude::*;

use crate::ai::risk;
use crate::models::{PortFinding, PortState};

pub fn compute_risk_and_signals(ports: &[PortFinding]) -> (u8, Vec<String>, usize) {
    let raw_score: u32 = ports.par_iter().map(risk::score_port).sum();
    let risk_score = risk::normalize(raw_score);

    let services: BTreeSet<String> = ports
        .par_iter()
        .filter(|p| matches!(p.state, PortState::Open | PortState::OpenOrFiltered))
        .filter_map(|p| p.service.clone())
        .collect();

    let mut findings = Vec::new();
    if services.contains("ftp") {
        findings.push("FTP detected: plaintext credential exposure risk".to_string());
    }
    if services.contains("telnet") {
        findings.push("Telnet detected: remote admin over plaintext channel".to_string());
    }
    if services.contains("microsoft-ds") || services.contains("netbios-ssn") {
        findings.push("SMB/NetBIOS reachable: lateral movement exposure increased".to_string());
    }
    if services.contains("ms-wbt-server") || services.contains("ssh") {
        findings.push("Remote administration interfaces are exposed".to_string());
    }

    if ports
        .iter()
        .filter(|p| matches!(p.state, PortState::Open))
        .count()
        >= 12
    {
        findings.push("Large open-port footprint observed".to_string());
    }

    (risk_score, findings, ports.len() + 1)
}

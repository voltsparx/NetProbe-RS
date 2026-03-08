use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use crate::models::{HostResult, PortFinding, PortState, ServiceIdentity};
use crate::reporter::advisory_catalog;

mod identity;
mod signals;

pub use identity::{derive_identity_from_banner, describe_identity};
use signals::{advice_for_port, common_exposure_hints, learning_for_port, version_hints};

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ServiceKnowledgeRecord {
    pub port: u16,
    pub protocol: String,
    pub state: String,
    pub label: String,
    pub service: Option<String>,
    pub matched_by: Option<String>,
    pub confidence: Option<f32>,
    #[serde(default)]
    pub identity: Option<ServiceIdentity>,
    #[serde(default)]
    pub hints: Vec<String>,
    #[serde(default)]
    pub observations: Vec<String>,
    #[serde(default)]
    pub advice: Vec<String>,
    #[serde(default)]
    pub learning: Vec<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct HostServiceKnowledgeSummary {
    #[serde(default)]
    pub records: Vec<ServiceKnowledgeRecord>,
    pub service_count: usize,
    pub identified_service_count: usize,
    pub cpe_count: usize,
    pub advisory_count: usize,
}

#[derive(Debug, Clone, Default)]
pub struct ServiceKnowledgeReport {
    pub insights: Vec<String>,
    pub advice: Vec<String>,
    pub learning: Vec<String>,
}

pub fn annotate_ports(ports: &mut [PortFinding]) {
    for port in ports {
        if !matches!(port.state, PortState::Open | PortState::OpenOrFiltered) {
            continue;
        }

        if port.service_identity.is_none() {
            port.service_identity =
                derive_identity_from_banner(port.banner.as_deref(), port.service.as_deref());
        }

        let advisory = advisory_catalog::collect(port);
        let mut hints = BTreeSet::new();
        hints.extend(common_exposure_hints(port));
        hints.extend(version_hints(port));
        hints.extend(advisory.hints);
        port.vulnerability_hints = hints.into_iter().collect();
    }
}

pub fn analyze_host(host: &HostResult) -> ServiceKnowledgeReport {
    let summary = summarize_host(host);
    let mut insights = BTreeSet::new();
    let mut advice = BTreeSet::new();
    let mut learning = BTreeSet::new();

    for record in &summary.records {
        insights.insert(format!(
            "Service map: {}/{} appears to be {}.",
            record.port, record.protocol, record.label
        ));

        if let Some(identity) = &record.identity {
            if !identity.cpes.is_empty() {
                insights.insert(format!(
                    "Service map: {}/{} carries CPE evidence {}.",
                    record.port,
                    record.protocol,
                    identity.cpes.join(", ")
                ));
            }
        }

        for hint in &record.hints {
            insights.insert(format!(
                "Exposure hint on {}/{}: {}",
                record.port, record.protocol, hint
            ));
        }

        insights.extend(record.observations.iter().cloned());
        advice.extend(record.advice.iter().cloned());
        learning.extend(record.learning.iter().cloned());
    }

    ServiceKnowledgeReport {
        insights: insights.into_iter().collect(),
        advice: advice.into_iter().collect(),
        learning: learning.into_iter().collect(),
    }
}

pub fn summarize_host(host: &HostResult) -> HostServiceKnowledgeSummary {
    let records = host
        .ports
        .iter()
        .filter_map(build_record)
        .collect::<Vec<_>>();

    let identified_service_count = records
        .iter()
        .filter(|record| record.service.is_some() || record.identity.is_some())
        .count();
    let cpe_count = records
        .iter()
        .map(|record| {
            record
                .identity
                .as_ref()
                .map(|identity| identity.cpes.len())
                .unwrap_or(0)
        })
        .sum();
    let mut advisory_items = BTreeSet::new();
    for record in &records {
        advisory_items.extend(record.hints.iter().cloned());
        advisory_items.extend(record.observations.iter().cloned());
        advisory_items.extend(record.advice.iter().cloned());
    }

    HostServiceKnowledgeSummary {
        service_count: records.len(),
        identified_service_count,
        cpe_count,
        advisory_count: advisory_items.len(),
        records,
    }
}

fn build_record(port: &PortFinding) -> Option<ServiceKnowledgeRecord> {
    if !matches!(port.state, PortState::Open | PortState::OpenOrFiltered) {
        return None;
    }

    let identity = port.service_identity.clone();
    let advisory = advisory_catalog::collect(port);
    let mut observations = BTreeSet::new();
    let mut advice = advice_for_port(port);
    let mut learning = learning_for_port(port);

    observations.extend(advisory.observations);
    advice.extend(advisory.advice);
    learning.extend(advisory.learning);

    let label = match &identity {
        Some(identity) => describe_identity(port.service.as_deref(), identity),
        None => port
            .service
            .clone()
            .unwrap_or_else(|| "unknown service".to_string()),
    };

    Some(ServiceKnowledgeRecord {
        port: port.port,
        protocol: port.protocol.clone(),
        state: port.state.as_str().to_string(),
        label,
        service: port.service.clone(),
        matched_by: port.matched_by.clone(),
        confidence: port.confidence,
        identity,
        hints: port.vulnerability_hints.clone(),
        observations: observations.into_iter().collect(),
        advice: advice.into_iter().collect(),
        learning: learning.into_iter().collect(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn summarizes_service_knowledge_for_host() {
        let mut ports = vec![PortFinding {
            port: 443,
            protocol: "tcp".to_string(),
            state: PortState::Open,
            service: Some("https".to_string()),
            service_identity: Some(ServiceIdentity {
                product: Some("nginx".to_string()),
                version: Some("1.25.3".to_string()),
                info: None,
                hostname: None,
                operating_system: None,
                device_type: None,
                cpes: vec!["cpe:/a:nginx:nginx:1.25.3".to_string()],
            }),
            banner: None,
            reason: "test".to_string(),
            matched_by: Some("nmap-service-probes".to_string()),
            confidence: Some(0.91),
            vulnerability_hints: Vec::new(),
            educational_note: None,
            latency_ms: None,
            explanation: None,
        }];

        annotate_ports(&mut ports);

        let host = HostResult {
            target: "example.org".to_string(),
            ip: "192.168.1.10".to_string(),
            reverse_dns: None,
            observed_mac: None,
            device_class: Some("enterprise".to_string()),
            device_vendor: None,
            operating_system: None,
            phantom_device_check: None,
            safety_actions: Vec::new(),
            warnings: Vec::new(),
            ports,
            risk_score: 0,
            insights: Vec::new(),
            defensive_advice: Vec::new(),
            learning_notes: Vec::new(),
            lua_findings: Vec::new(),
        };

        let summary = summarize_host(&host);
        assert_eq!(summary.service_count, 1);
        assert_eq!(summary.identified_service_count, 1);
        assert_eq!(summary.cpe_count, 1);
        assert!(summary.advisory_count > 0);
        assert_eq!(summary.records[0].label, "nginx 1.25.3");
    }
}

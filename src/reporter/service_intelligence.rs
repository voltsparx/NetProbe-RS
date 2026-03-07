pub use crate::reporter::service_knowledge::{summarize_host, HostServiceKnowledgeSummary};

use crate::models::{HostResult, PortFinding};
use crate::reporter::service_knowledge;

pub type ServiceIntelligenceReport = service_knowledge::ServiceKnowledgeReport;

pub fn annotate_ports(ports: &mut [PortFinding]) {
    service_knowledge::annotate_ports(ports);
}

pub fn analyze_host(host: &HostResult) -> ServiceIntelligenceReport {
    service_knowledge::analyze_host(host)
}

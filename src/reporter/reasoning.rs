// Flow sketch: ports -> scoring/findings/guidance -> insights
// Pseudo-block:
//   read input -> process safely -> return deterministic output
// explanations translate packet noise into human words.

use crate::models::{PortFinding, PortState};

pub fn attach_explanations(ports: &mut [PortFinding]) {
    for finding in ports {
        finding.explanation = Some(explain_port(finding));
    }
}

fn explain_port(finding: &PortFinding) -> String {
    let state_reason = match finding.state {
        PortState::Open => {
            "Open state means the service accepted network interaction on this port"
        }
        PortState::Closed => "Closed state means target responded but no service is listening",
        PortState::Filtered => {
            "Filtered state means packet loss, firewall filtering, or probe timeout blocked certainty"
        }
        PortState::OpenOrFiltered => {
            "Open|filtered means UDP probing saw no definitive close signal"
        }
    };

    if let Some(service) = &finding.service {
        let mut base = format!(
            "{state_reason}; identified service hint is '{service}' and reason='{}'",
            finding.reason
        );
        if let Some(identity) = &finding.service_identity {
            let mut identity_parts = Vec::new();
            if let Some(product) = &identity.product {
                identity_parts.push(product.clone());
            }
            if let Some(version) = &identity.version {
                identity_parts.push(format!("version={version}"));
            }
            if let Some(info) = &identity.info {
                identity_parts.push(info.clone());
            }
            if let Some(device_type) = &identity.device_type {
                identity_parts.push(format!("device={device_type}"));
            }
            if let Some(os) = &identity.operating_system {
                identity_parts.push(format!("os={os}"));
            }
            if !identity.cpes.is_empty() {
                identity_parts.push(format!("cpe={}", identity.cpes.join(",")));
            }
            if !identity_parts.is_empty() {
                base.push_str(&format!("; identity={}", identity_parts.join(" | ")));
            }
        }
        if let Some(matched_by) = &finding.matched_by {
            if let Some(confidence) = finding.confidence {
                base.push_str(&format!(
                    "; detection source={matched_by}, confidence={confidence:.2}"
                ));
            } else {
                base.push_str(&format!("; detection source={matched_by}"));
            }
        }
        if !finding.vulnerability_hints.is_empty() {
            base.push_str(&format!(
                "; exposure hints={}",
                finding.vulnerability_hints.join(" | ")
            ));
        }
        base
    } else {
        format!("{state_reason}; reason='{}'", finding.reason)
    }
}

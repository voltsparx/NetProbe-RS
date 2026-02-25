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
        if let Some(matched_by) = &finding.matched_by {
            if let Some(confidence) = finding.confidence {
                base.push_str(&format!(
                    "; detection source={matched_by}, confidence={confidence:.2}"
                ));
            } else {
                base.push_str(&format!("; detection source={matched_by}"));
            }
        }
        base
    } else {
        format!("{state_reason}; reason='{}'", finding.reason)
    }
}

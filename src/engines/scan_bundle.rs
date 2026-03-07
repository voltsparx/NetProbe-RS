use crate::models::ScanProfile;

#[derive(Debug, Clone)]
pub struct ScanBundlePlan {
    pub name: String,
    pub stages: Vec<String>,
    pub summary: String,
}

pub fn plan(profile: ScanProfile, service_detection: bool, strict_safety: bool) -> ScanBundlePlan {
    match profile {
        ScanProfile::Phantom => ScanBundlePlan {
            name: "tbns-phantom-first-touch".to_string(),
            stages: vec![
                "passive-anchor".to_string(),
                "phantom-device-check".to_string(),
                "bio-response-evaluate".to_string(),
            ],
            summary:
                "least-contact bundle: device-check the target, evaluate resilience, then decide whether broader follow-up is safe"
                    .to_string(),
        },
        ScanProfile::Kis => ScanBundlePlan {
            name: "tbns-kis-identity".to_string(),
            stages: vec![
                "passive-anchor".to_string(),
                "kinetic-identity-hints".to_string(),
                "bio-response-evaluate".to_string(),
            ],
            summary:
                "timing-observation bundle: gather cautious identity hints, then defer deeper checks until safe"
                    .to_string(),
        },
        ScanProfile::Sar => ScanBundlePlan {
            name: "tbns-sar-observe".to_string(),
            stages: vec![
                "passive-anchor".to_string(),
                "response-shape-observe".to_string(),
                "bio-response-evaluate".to_string(),
            ],
            summary:
                "decision-delta bundle: observe response logic under low pressure, then stop or escalate safely"
                    .to_string(),
        },
        ScanProfile::Stealth => ScanBundlePlan {
            name: "cautious-discovery".to_string(),
            stages: vec![
                "host-discovery".to_string(),
                "service-map".to_string(),
                "explain-report".to_string(),
            ],
            summary:
                "cautious bundle: slow discovery with conservative timing and clear reporting".to_string(),
        },
        _ => {
            let mut stages = vec!["host-discovery".to_string(), "service-map".to_string()];
            if service_detection && !strict_safety {
                stages.push("narrow-enrichment".to_string());
            }
            stages.push("explain-report".to_string());
            ScanBundlePlan {
                name: if strict_safety {
                    "guarded-multi-stage".to_string()
                } else {
                    "balanced-multi-stage".to_string()
                },
                stages,
                summary:
                    "fast defensive bundle: broad discovery first, then evidence-based follow-up on interesting hosts"
                        .to_string(),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::plan;
    use crate::models::ScanProfile;

    #[test]
    fn phantom_bundle_stays_low_impact() {
        let bundle = plan(ScanProfile::Phantom, false, true);
        assert_eq!(bundle.name, "tbns-phantom-first-touch");
        assert_eq!(bundle.stages.len(), 3);
    }

    #[test]
    fn balanced_bundle_adds_enrichment_when_allowed() {
        let bundle = plan(ScanProfile::Balanced, true, false);
        assert!(bundle
            .stages
            .iter()
            .any(|stage| stage == "narrow-enrichment"));
    }
}

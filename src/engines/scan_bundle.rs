use crate::engine_intel::strategy::ExecutionMode;
use crate::models::ScanProfile;

#[derive(Debug, Clone)]
pub struct ScanBundlePlan {
    pub name: String,
    pub stages: Vec<String>,
    pub summary: String,
}

pub fn plan(
    profile: ScanProfile,
    execution_mode: ExecutionMode,
    service_detection: bool,
    strict_safety: bool,
) -> ScanBundlePlan {
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
        ScanProfile::Idf => ScanBundlePlan {
            name: "tbns-idf-fog".to_string(),
            stages: vec![
                "passive-anchor".to_string(),
                "idf-sparse-sampling".to_string(),
                "blackrock-fog-order".to_string(),
                "bio-response-evaluate".to_string(),
            ],
            summary:
                "fog bundle: low-impact sparse discovery with extra ordering entropy and strict defensive pacing"
                    .to_string(),
        },
        ScanProfile::Mirror => ScanBundlePlan {
            name: "mirror-hybrid-correlation".to_string(),
            stages: vec![
                "masscan-style-discovery".to_string(),
                "mirror-correlation".to_string(),
                "nmap-service-map".to_string(),
                "nmap-os-catalog".to_string(),
                "explain-report".to_string(),
            ],
            summary:
                "reflective bundle: controlled hybrid discovery that emphasizes service and OS correlation without active deception"
                    .to_string(),
        },
        ScanProfile::Stealth => ScanBundlePlan {
            name: "cautious-discovery".to_string(),
            stages: vec![
                "host-discovery".to_string(),
                "nmap-service-map".to_string(),
                "explain-report".to_string(),
            ],
            summary:
                "cautious bundle: slow discovery with conservative timing and clear reporting".to_string(),
        },
        _ => {
            let mut stages = match execution_mode {
                ExecutionMode::Async => {
                    vec!["host-discovery".to_string(), "nmap-service-map".to_string()]
                }
                ExecutionMode::Hybrid | ExecutionMode::PacketBlast => vec![
                    "masscan-style-discovery".to_string(),
                    "nmap-service-map".to_string(),
                ],
            };
            if service_detection && !strict_safety {
                stages.push("nmap-os-catalog".to_string());
                stages.push("narrow-enrichment".to_string());
            }
            stages.push("explain-report".to_string());
            ScanBundlePlan {
                name: match execution_mode {
                    ExecutionMode::Async => {
                        if strict_safety {
                            "guarded-multi-stage".to_string()
                        } else {
                            "balanced-multi-stage".to_string()
                        }
                    }
                    ExecutionMode::Hybrid | ExecutionMode::PacketBlast => {
                        if strict_safety {
                            "guarded-masscan-nmap-hybrid".to_string()
                        } else {
                            "masscan-nmap-hybrid".to_string()
                        }
                    }
                },
                stages,
                summary: match execution_mode {
                    ExecutionMode::Async => "fast defensive bundle: broad discovery first, then evidence-based follow-up on interesting hosts"
                        .to_string(),
                    ExecutionMode::Hybrid | ExecutionMode::PacketBlast => "hybrid bundle: masscan-style discovery front-end with nmap-style service, OS, and enrichment follow-through"
                        .to_string(),
                },
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::plan;
    use crate::engine_intel::strategy::ExecutionMode;
    use crate::models::ScanProfile;

    #[test]
    fn phantom_bundle_stays_low_impact() {
        let bundle = plan(ScanProfile::Phantom, ExecutionMode::Async, false, true);
        assert_eq!(bundle.name, "tbns-phantom-first-touch");
        assert_eq!(bundle.stages.len(), 3);
    }

    #[test]
    fn balanced_bundle_adds_enrichment_when_allowed() {
        let bundle = plan(ScanProfile::Balanced, ExecutionMode::Async, true, false);
        assert!(bundle
            .stages
            .iter()
            .any(|stage| stage == "narrow-enrichment"));
    }

    #[test]
    fn hybrid_bundle_exposes_masscan_nmap_fusion() {
        let bundle = plan(ScanProfile::Hybrid, ExecutionMode::Hybrid, true, false);
        assert_eq!(bundle.name, "masscan-nmap-hybrid");
        assert!(bundle
            .stages
            .iter()
            .any(|stage| stage == "masscan-style-discovery"));
        assert!(bundle.stages.iter().any(|stage| stage == "nmap-os-catalog"));
    }

    #[test]
    fn idf_bundle_stays_low_impact() {
        let bundle = plan(ScanProfile::Idf, ExecutionMode::Async, false, true);
        assert_eq!(bundle.name, "tbns-idf-fog");
        assert!(bundle
            .stages
            .iter()
            .any(|stage| stage == "blackrock-fog-order"));
    }
}

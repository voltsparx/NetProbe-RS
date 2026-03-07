use crate::models::PortFinding;

#[derive(Debug, Clone, Default)]
pub struct AdvisoryBundle {
    pub observations: Vec<String>,
    pub hints: Vec<String>,
    pub advice: Vec<String>,
    pub learning: Vec<String>,
}

struct AdvisoryRule {
    cpe_prefixes: &'static [&'static str],
    product_keywords: &'static [&'static str],
    services: &'static [&'static str],
    observations: &'static [&'static str],
    hints: &'static [&'static str],
    advice: &'static [&'static str],
    learning: &'static [&'static str],
}

const RULES: &[AdvisoryRule] = &[
    AdvisoryRule {
        cpe_prefixes: &["cpe:/a:nginx:nginx"],
        product_keywords: &["nginx"],
        services: &["http", "https", "http-proxy"],
        observations: &[
            "Nginx-class web service identified; review virtual host exposure, admin endpoints, and reverse-proxy trust settings.",
        ],
        hints: &[
            "reverse-proxy or web edge service detected; confirm upstream trust, header handling, and TLS termination policy.",
        ],
        advice: &[
            "Review Nginx listener scope, stale default sites, admin routes, and whether TLS, HSTS, and proxy headers are configured intentionally.",
        ],
        learning: &[
            "Learning: Nginx often sits at the edge of an application stack, so exposure review should include both the proxy and what it forwards to.",
        ],
    },
    AdvisoryRule {
        cpe_prefixes: &["cpe:/a:apache:http_server"],
        product_keywords: &["apache", "httpd"],
        services: &["http", "https"],
        observations: &[
            "Apache HTTP service identified; check module surface, legacy compatibility settings, and admin content exposure.",
        ],
        hints: &[
            "modular web server detected; unsupported modules and inherited defaults can widen the exposure surface.",
        ],
        advice: &[
            "Review enabled Apache modules, directory indexing, server-status exposure, legacy virtual hosts, and patch support status.",
        ],
        learning: &[
            "Learning: Apache identity alone is not a vulnerability result, but it narrows where to look for configuration drift and legacy web content.",
        ],
    },
    AdvisoryRule {
        cpe_prefixes: &["cpe:/a:microsoft:iis", "cpe:/a:microsoft:internet_information_services"],
        product_keywords: &["iis", "internet information services"],
        services: &["http", "https"],
        observations: &[
            "IIS-class web service identified; confirm support lifecycle, WebDAV policy, and management interface exposure.",
        ],
        hints: &[
            "Microsoft web stack detected; historical risk often comes from old application pools, WebDAV, or legacy ASP.NET content.",
        ],
        advice: &[
            "Verify IIS version support status, disable unused modules like WebDAV where possible, and review admin/auth endpoints behind reverse proxies or VPN.",
        ],
        learning: &[
            "Learning: IIS findings become more useful when combined with site role, authentication model, and TLS policy rather than port state alone.",
        ],
    },
    AdvisoryRule {
        cpe_prefixes: &["cpe:/a:openssl:openssl"],
        product_keywords: &["openssl"],
        services: &[],
        observations: &[
            "OpenSSL component evidence observed; this helps anchor TLS stack age and maintenance expectations.",
        ],
        hints: &[
            "TLS library identity was exposed by the service; verify whether the deployed crypto stack is still inside vendor support.",
        ],
        advice: &[
            "Review the TLS library lifecycle, protocol versions, certificates, and whether weak compatibility modes are still enabled.",
        ],
        learning: &[
            "Learning: OpenSSL evidence is component intelligence, not a vulnerability verdict. It tells you which crypto stack to review first.",
        ],
    },
    AdvisoryRule {
        cpe_prefixes: &["cpe:/a:microsoft:sql_server"],
        product_keywords: &["sql server", "microsoft sql"],
        services: &["ms-sql-s"],
        observations: &[
            "Microsoft SQL Server evidence observed; treat the host as a data-bearing asset with privileged lateral-movement value.",
        ],
        hints: &[
            "database and administration surface detected; review network ACLs, authentication model, encryption, and linked management features.",
        ],
        advice: &[
            "Restrict SQL Server exposure to application or management tiers, review service accounts, disable unused surface area, and verify current cumulative updates.",
        ],
        learning: &[
            "Learning: database exposure risk is usually about trust boundaries, backups, credentials, and admin features, not just the listening port.",
        ],
    },
    AdvisoryRule {
        cpe_prefixes: &["cpe:/a:mongodb:mongodb"],
        product_keywords: &["mongodb"],
        services: &["mongodb"],
        observations: &[
            "MongoDB-class service identified; check whether it is intentionally network-reachable and whether HTTP or admin surfaces are still enabled.",
        ],
        hints: &[
            "document store exposure detected; verify authentication, replica/member reachability, and interface binding policy.",
        ],
        advice: &[
            "Keep MongoDB on private interfaces, require authentication, and review cluster, backup, and admin tooling exposure separately from application traffic.",
        ],
        learning: &[
            "Learning: MongoDB findings are most useful when combined with deployment role, replica status, and whether the instance is meant to be internet-facing.",
        ],
    },
    AdvisoryRule {
        cpe_prefixes: &["cpe:/a:mysql:mysql", "cpe:/a:oracle:mysql"],
        product_keywords: &["mysql"],
        services: &["mysql"],
        observations: &[
            "MySQL-class service identified; verify whether direct client reachability is intended outside the application tier.",
        ],
        hints: &[
            "relational data service detected; review interface binding, privileged accounts, TLS, and remote admin exposure.",
        ],
        advice: &[
            "Restrict MySQL reachability, remove broad network access, enforce strong authentication, and review replication and backup endpoints.",
        ],
        learning: &[
            "Learning: with databases, the highest-value findings usually come from who can reach them, not just whether the service answered.",
        ],
    },
    AdvisoryRule {
        cpe_prefixes: &["cpe:/a:postgresql:postgresql"],
        product_keywords: &["postgresql", "postgres"],
        services: &["postgresql"],
        observations: &[
            "PostgreSQL-class service identified; verify access scope, SSL policy, and whether administrative roles are exposed beyond trusted zones.",
        ],
        hints: &[
            "relational data service detected; review client trust rules, admin tooling reachability, and extension surface.",
        ],
        advice: &[
            "Review PostgreSQL host-based access rules, TLS settings, superuser exposure, and whether operational interfaces are separated from application traffic.",
        ],
        learning: &[
            "Learning: PostgreSQL security posture depends heavily on host-based trust rules and role design, not just patch state.",
        ],
    },
    AdvisoryRule {
        cpe_prefixes: &["cpe:/a:redis:redis"],
        product_keywords: &["redis"],
        services: &["redis"],
        observations: &[
            "Redis-class service identified; verify that it is not broadly reachable and that operational controls match its role.",
        ],
        hints: &[
            "in-memory data service detected; review exposure carefully because it is often intended only for local or tightly trusted use.",
        ],
        advice: &[
            "Keep Redis on private or loopback interfaces where possible, require authentication where supported, and review persistence and replica exposure.",
        ],
        learning: &[
            "Learning: Redis is frequently deployed as an internal component, so broad network reachability is often more important than version trivia.",
        ],
    },
    AdvisoryRule {
        cpe_prefixes: &["cpe:/a:miniupnp_project:miniupnpd"],
        product_keywords: &["miniupnp", "upnp"],
        services: &["upnp"],
        observations: &[
            "UPnP management surface identified; review whether device discovery and port-mapping features are intentionally exposed.",
        ],
        hints: &[
            "automatic discovery or forwarding surface detected; these services should stay on trusted local networks only.",
        ],
        advice: &[
            "Restrict UPnP to trusted LAN segments, disable it on unnecessary devices, and review whether automatic port mappings are allowed at all.",
        ],
        learning: &[
            "Learning: UPnP is usually a convenience protocol, so the main question is whether the discovery and control plane should exist on that network at all.",
        ],
    },
    AdvisoryRule {
        cpe_prefixes: &["cpe:/h:hp:", "cpe:/h:xerox:", "cpe:/h:brother:", "cpe:/h:canon:"],
        product_keywords: &["laserjet", "photosmart", "officejet", "printer"],
        services: &["ipp"],
        observations: &[
            "Printer or print appliance identity observed; handle follow-up gently and review admin interface exposure from a device-safety perspective.",
        ],
        hints: &[
            "embedded print device detected; separate user print traffic from management access and review default services carefully.",
        ],
        advice: &[
            "Keep printer management on trusted device VLANs, disable unused web or telnet interfaces, and review firmware support status before deeper checks.",
        ],
        learning: &[
            "Learning: print devices are a good example of why NProbe-RS treats fragile hardware differently before deeper probing.",
        ],
    },
    AdvisoryRule {
        cpe_prefixes: &["cpe:/h:cisco:", "cpe:/h:juniper:", "cpe:/h:fortinet:", "cpe:/h:aruba:", "cpe:/h:netgear:"],
        product_keywords: &["router", "switch", "firewall", "vpn", "screenos", "fortigate"],
        services: &[],
        observations: &[
            "Network appliance identity observed; management exposure here has outsized impact on trust boundaries and visibility.",
        ],
        hints: &[
            "infrastructure or security appliance detected; review management-plane reachability, AAA, logging, and firmware lifecycle first.",
        ],
        advice: &[
            "Restrict appliance administration to dedicated management paths, enforce MFA and centralized auth where possible, and verify firmware support status.",
        ],
        learning: &[
            "Learning: infrastructure findings matter because a single appliance often controls many downstream assets and trust decisions.",
        ],
    },
];

pub fn collect(port: &PortFinding) -> AdvisoryBundle {
    let mut bundle = AdvisoryBundle::default();
    let service = port
        .service
        .as_deref()
        .unwrap_or_default()
        .to_ascii_lowercase();
    let product = port
        .service_identity
        .as_ref()
        .and_then(|identity| identity.product.as_deref())
        .unwrap_or_default()
        .to_ascii_lowercase();
    let cpes = port
        .service_identity
        .as_ref()
        .map(|identity| {
            identity
                .cpes
                .iter()
                .map(|cpe| cpe.to_ascii_lowercase())
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();

    for rule in RULES {
        let cpe_match = rule.cpe_prefixes.iter().any(|prefix| {
            cpes.iter()
                .any(|cpe| cpe.starts_with(&prefix.to_ascii_lowercase()))
        });
        let product_match = rule
            .product_keywords
            .iter()
            .any(|needle| !needle.is_empty() && product.contains(&needle.to_ascii_lowercase()));
        let service_match = rule
            .services
            .iter()
            .any(|candidate| service == candidate.to_ascii_lowercase());

        if !(cpe_match || product_match || service_match) {
            continue;
        }

        bundle
            .observations
            .extend(rule.observations.iter().map(|value| (*value).to_string()));
        bundle
            .hints
            .extend(rule.hints.iter().map(|value| (*value).to_string()));
        bundle
            .advice
            .extend(rule.advice.iter().map(|value| (*value).to_string()));
        bundle
            .learning
            .extend(rule.learning.iter().map(|value| (*value).to_string()));
    }

    bundle
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{PortFinding, PortState, ServiceIdentity};

    #[test]
    fn advisory_catalog_matches_cpe_prefix() {
        let port = PortFinding {
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
            matched_by: None,
            confidence: None,
            vulnerability_hints: Vec::new(),
            educational_note: None,
            latency_ms: None,
            explanation: None,
        };

        let bundle = collect(&port);
        assert!(bundle
            .observations
            .iter()
            .any(|line| line.to_ascii_lowercase().contains("nginx")));
        assert!(!bundle.advice.is_empty());
    }
}

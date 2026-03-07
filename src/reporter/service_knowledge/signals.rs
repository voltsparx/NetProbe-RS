use std::collections::BTreeSet;

use crate::models::PortFinding;

pub fn common_exposure_hints(port: &PortFinding) -> BTreeSet<String> {
    let mut hints = BTreeSet::new();
    let service = port
        .service
        .as_deref()
        .unwrap_or_default()
        .to_ascii_lowercase();
    let banner = port
        .banner
        .as_deref()
        .unwrap_or_default()
        .to_ascii_lowercase();
    let device_type = port
        .service_identity
        .as_ref()
        .and_then(|identity| identity.device_type.as_deref())
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

    if matches!(service.as_str(), "telnet" | "ftp") {
        hints.insert(
            "legacy or plaintext remote service exposed; verify that encrypted replacements or strict segmentation are in place."
                .to_string(),
        );
    }

    if matches!(
        service.as_str(),
        "pop3" | "imap" | "smtp" | "submission" | "smtps"
    ) {
        hints.insert(
            "mail service exposed; review authentication, relay controls, and TLS posture for this interface."
                .to_string(),
        );
    }

    if matches!(
        service.as_str(),
        "microsoft-ds" | "netbios-ssn" | "ldap" | "msrpc"
    ) {
        hints.insert(
            "identity or file-sharing surface exposed; review segmentation, trust boundaries, and least-privilege access."
                .to_string(),
        );
    }

    if matches!(
        service.as_str(),
        "redis" | "mongodb" | "memcached" | "mysql" | "postgresql" | "elasticsearch"
    ) {
        hints.insert(
            "data service reachable over the network; confirm authentication, interface binding, and admin exposure policy."
                .to_string(),
        );
    }

    if service == "http" || service == "https" || banner.contains("server:") {
        hints.insert(
            "web application or admin surface detected; review authentication boundaries, TLS policy, and default credentials."
                .to_string(),
        );
    }

    if device_type.contains("printer")
        || cpes
            .iter()
            .any(|cpe| cpe.contains(":printer") || cpe.contains(":laserjet"))
    {
        hints.insert(
            "embedded printing surface detected; keep it on trusted device zones and review firmware age before deep probing."
                .to_string(),
        );
    }

    if cpes
        .iter()
        .any(|cpe| cpe.contains(":router") || cpe.contains(":firewall"))
        || matches!(device_type.as_str(), "router" | "firewall" | "switch")
    {
        hints.insert(
            "network infrastructure management surface detected; restrict it to management paths and verify logging and MFA."
                .to_string(),
        );
    }

    hints
}

pub fn version_hints(port: &PortFinding) -> BTreeSet<String> {
    let mut hints = BTreeSet::new();
    let identity = match &port.service_identity {
        Some(identity) => identity,
        None => return hints,
    };

    let product = identity
        .product
        .as_deref()
        .unwrap_or_default()
        .to_ascii_lowercase();
    let version = identity
        .version
        .as_deref()
        .unwrap_or_default()
        .to_ascii_lowercase();
    let banner = port
        .banner
        .as_deref()
        .unwrap_or_default()
        .to_ascii_lowercase();

    if (product.contains("apache") || banner.contains("apache/2.2"))
        && (version.starts_with("1.")
            || version.starts_with("2.0")
            || version.starts_with("2.1")
            || version.starts_with("2.2")
            || banner.contains("apache/2.2"))
    {
        hints.insert(
            "legacy Apache generation detected; review for unsupported modules and patch-level drift."
                .to_string(),
        );
    }

    if (product.contains("openssl")
        || banner.contains("openssl/1.0")
        || banner.contains("openssl/0."))
        && (version.starts_with("0.")
            || version.starts_with("1.0")
            || banner.contains("openssl/1.0")
            || banner.contains("openssl/0."))
    {
        hints.insert(
            "legacy OpenSSL family evidence observed; verify TLS stack support status and current patching."
                .to_string(),
        );
    }

    if (product.contains("internet information services") || product.contains("iis"))
        && (version.starts_with("5.") || version.starts_with("6.") || version.starts_with("7.0"))
    {
        hints.insert(
            "older IIS generation detected; confirm that the host is still supported and review historical web exposure issues."
                .to_string(),
        );
    }

    if product.contains("proftpd") && version.starts_with("1.3.3") {
        hints.insert(
            "older ProFTPD build family detected; review patch level and remove anonymous or plaintext workflows."
                .to_string(),
        );
    }

    hints
}

pub fn advice_for_port(port: &PortFinding) -> BTreeSet<String> {
    let mut advice = BTreeSet::new();
    for hint in &port.vulnerability_hints {
        if hint.contains("plaintext") || hint.contains("legacy or plaintext") {
            advice.insert(
                "Replace plaintext administration protocols with encrypted equivalents or isolate them behind tightly controlled management paths."
                    .to_string(),
            );
        }
        if hint.contains("data service reachable") {
            advice.insert(
                "Keep data services on private interfaces, require authentication, and verify that backups and admin APIs are not broadly reachable."
                    .to_string(),
            );
        }
        if hint.contains("web application or admin surface") {
            advice.insert(
                "Review exposed web login surfaces, enforce MFA where possible, and prefer VPN or jump-host access for administration."
                    .to_string(),
            );
        }
        if hint.contains("network infrastructure management surface") {
            advice.insert(
                "Move infrastructure management to dedicated admin networks and verify that default credentials and legacy TLS are gone."
                    .to_string(),
            );
        }
    }
    advice
}

pub fn learning_for_port(port: &PortFinding) -> BTreeSet<String> {
    let mut learning = BTreeSet::new();
    if let Some(identity) = &port.service_identity {
        learning.insert(format!(
            "Learning: service identity on {}/{} came from banner and probe evidence, not just the default port map.",
            port.port, port.protocol
        ));
        if !identity.cpes.is_empty() {
            learning.insert(format!(
                "Learning: CPE strings are a normalized software or hardware label that can be matched to advisories and asset inventories: {}.",
                identity.cpes.join(", ")
            ));
        }
    }
    if !port.vulnerability_hints.is_empty() {
        learning.insert(format!(
            "Learning: NProbe-RS uses non-invasive exposure hints for {}/{} instead of exploit-style vulnerability checks in the default path.",
            port.port, port.protocol
        ));
    }
    learning
}

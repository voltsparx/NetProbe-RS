use crate::models::ServiceIdentity;

pub fn describe_identity(service: Option<&str>, identity: &ServiceIdentity) -> String {
    let mut parts = Vec::new();

    if let Some(product) = &identity.product {
        let mut label = product.clone();
        if let Some(version) = &identity.version {
            label.push(' ');
            label.push_str(version);
        }
        parts.push(label);
    } else if let Some(service) = service {
        parts.push(service.to_string());
    }

    if let Some(info) = &identity.info {
        parts.push(info.clone());
    }
    if let Some(device_type) = &identity.device_type {
        parts.push(format!("device={device_type}"));
    }
    if let Some(os) = &identity.operating_system {
        parts.push(format!("os={os}"));
    }
    if let Some(hostname) = &identity.hostname {
        parts.push(format!("host={hostname}"));
    }

    if parts.is_empty() {
        service.unwrap_or("unknown service").to_string()
    } else {
        parts.join(" | ")
    }
}

pub fn derive_identity_from_banner(
    banner: Option<&str>,
    service: Option<&str>,
) -> Option<ServiceIdentity> {
    let banner = banner?.trim();
    if banner.is_empty() {
        return None;
    }

    let lower = banner.to_ascii_lowercase();
    if lower.starts_with("ssh-") {
        let version = banner.split('-').nth(2).map(str::trim).map(str::to_string);
        return Some(ServiceIdentity {
            product: Some("SSH".to_string()),
            version,
            info: Some(banner.to_string()),
            ..ServiceIdentity::default()
        });
    }

    if let Some(server_idx) = lower.find("server:") {
        let server = banner[server_idx + 7..]
            .split_whitespace()
            .next()
            .unwrap_or("")
            .trim_matches(',');
        if let Some((product, version)) = split_product_version(server) {
            return Some(ServiceIdentity {
                product: Some(product),
                version,
                info: service.map(|value| format!("banner-derived {value}")),
                ..ServiceIdentity::default()
            });
        }
    }

    if let Some((product, version)) = split_product_version(banner) {
        return Some(ServiceIdentity {
            product: Some(product),
            version,
            info: service.map(|value| format!("banner-derived {value}")),
            ..ServiceIdentity::default()
        });
    }

    None
}

fn split_product_version(raw: &str) -> Option<(String, Option<String>)> {
    let raw = raw.trim();
    if raw.is_empty() {
        return None;
    }

    if let Some((product, version)) = raw.split_once('/') {
        return Some((product.trim().to_string(), clean_version(version)));
    }
    if let Some((product, version)) = raw.split_once('_') {
        if product.chars().all(|ch| ch.is_ascii_alphabetic()) {
            return Some((product.trim().to_string(), clean_version(version)));
        }
    }

    None
}

fn clean_version(raw: &str) -> Option<String> {
    let version = raw
        .trim()
        .trim_matches(|ch: char| ch == ')' || ch == '(' || ch == ';');
    if version.is_empty() {
        None
    } else {
        Some(version.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derives_identity_from_server_banner() {
        let identity = derive_identity_from_banner(
            Some("HTTP/1.1 200 OK\r\nServer: nginx/1.25.4\r\n"),
            Some("https"),
        )
        .expect("banner should derive identity");

        assert_eq!(identity.product.as_deref(), Some("nginx"));
        assert_eq!(identity.version.as_deref(), Some("1.25.4"));
    }
}

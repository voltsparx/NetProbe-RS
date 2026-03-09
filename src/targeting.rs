use std::fs;
use std::net::Ipv4Addr;
use std::path::Path;

use crate::error::{NProbeError, NProbeResult};

pub fn split_target_expression(raw: &str) -> Vec<String> {
    raw.split(|value: char| value == ',' || value == ';' || value.is_whitespace())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
        .collect()
}

pub fn load_target_file(path: &Path) -> NProbeResult<Vec<String>> {
    let body = fs::read_to_string(path).map_err(|err| {
        NProbeError::Cli(format!(
            "failed to read target list '{}': {err}",
            path.display()
        ))
    })?;

    let mut targets = Vec::new();
    for line in body.lines() {
        let trimmed = line.split('#').next().unwrap_or("").trim();
        if trimmed.is_empty() {
            continue;
        }
        targets.extend(split_target_expression(trimmed));
    }

    if targets.is_empty() {
        return Err(NProbeError::Cli(format!(
            "target list '{}' did not contain any usable targets",
            path.display()
        )));
    }

    Ok(targets)
}

pub fn expand_ipv4_range(raw: &str, max_hosts: usize) -> Option<(Vec<Ipv4Addr>, bool)> {
    let octets = raw.split('.').collect::<Vec<_>>();
    if octets.len() != 4 {
        return None;
    }

    let mut parts = Vec::with_capacity(4);
    for octet in octets {
        parts.push(parse_octet(octet)?);
    }

    let mut out = Vec::new();
    let max_hosts = max_hosts.max(1);
    let mut truncated = false;
    for a in parts[0].0..=parts[0].1 {
        for b in parts[1].0..=parts[1].1 {
            for c in parts[2].0..=parts[2].1 {
                for d in parts[3].0..=parts[3].1 {
                    if out.len() >= max_hosts {
                        truncated = true;
                        return Some((out, truncated));
                    }
                    out.push(Ipv4Addr::new(a, b, c, d));
                }
            }
        }
    }

    Some((out, truncated))
}

pub fn parse_hostname_prefix(raw: &str) -> Option<(&str, u8)> {
    let (host, prefix_raw) = raw.trim().split_once('/')?;
    if host.is_empty()
        || host.contains(':')
        || host.parse::<Ipv4Addr>().is_ok()
        || host.contains('-')
        || host.contains('/')
    {
        return None;
    }

    let prefix = prefix_raw.parse::<u8>().ok()?;
    if prefix > 32 {
        return None;
    }

    Some((host, prefix))
}

pub fn expand_ipv4_prefix(ip: Ipv4Addr, prefix_len: u8, max_hosts: usize) -> (Vec<Ipv4Addr>, bool) {
    let mask = if prefix_len == 0 {
        0
    } else {
        u32::MAX << (32 - prefix_len)
    };
    let network = Ipv4Addr::from(u32::from(ip) & mask);
    enumerate_ipv4_hosts(network, prefix_len, max_hosts)
}

pub fn random_public_ipv4_targets(count: usize, seed: Option<u64>) -> Vec<String> {
    let mut state = seed.unwrap_or(0x4e50_5253_5241_4e44);
    let mut targets = Vec::new();
    let mut seen = std::collections::BTreeSet::new();
    let count = count.max(1).min(4096);

    while targets.len() < count {
        state = xorshift64(state);
        let candidate = Ipv4Addr::from((state as u32).max(1));
        if !is_random_target_candidate(candidate) || !seen.insert(candidate) {
            continue;
        }
        targets.push(candidate.to_string());
    }

    targets
}

fn parse_octet(raw: &str) -> Option<(u8, u8)> {
    if let Some((start_raw, end_raw)) = raw.split_once('-') {
        let start = start_raw.parse::<u8>().ok()?;
        let end = end_raw.parse::<u8>().ok()?;
        if start > end {
            return None;
        }
        Some((start, end))
    } else {
        let value = raw.parse::<u8>().ok()?;
        Some((value, value))
    }
}

fn enumerate_ipv4_hosts(
    network: Ipv4Addr,
    prefix_len: u8,
    max_hosts: usize,
) -> (Vec<Ipv4Addr>, bool) {
    let network_num = u32::from(network);
    let host_bits = 32 - prefix_len as u32;
    let range_size = 1u64 << host_bits;
    let (start, count) = if prefix_len >= 31 {
        (network_num, range_size)
    } else {
        (network_num.saturating_add(1), range_size.saturating_sub(2))
    };

    let take = count.min(max_hosts.max(1) as u64);
    let mut hosts = Vec::with_capacity(take as usize);
    for offset in 0..take {
        hosts.push(Ipv4Addr::from(start.saturating_add(offset as u32)));
    }
    (hosts, count > take)
}

fn is_random_target_candidate(ip: Ipv4Addr) -> bool {
    let [a, b, c, d] = ip.octets();

    if d == 0 || d == 255 {
        return false;
    }

    if ip.is_private()
        || ip.is_loopback()
        || ip.is_link_local()
        || ip.is_multicast()
        || ip.is_unspecified()
        || a == 0
        || a >= 224
    {
        return false;
    }

    if (a == 100 && (64..=127).contains(&b))
        || (a == 169 && b == 254)
        || (a == 172 && (16..=31).contains(&b))
        || (a == 192 && b == 0 && c == 0)
        || (a == 192 && b == 0 && c == 2)
        || (a == 192 && b == 88 && c == 99)
        || (a == 198 && b == 18)
        || (a == 198 && b == 19)
        || (a == 198 && b == 51 && c == 100)
        || (a == 203 && b == 0 && c == 113)
        || (a == 240 && b == 0 && c == 0)
    {
        return false;
    }

    true
}

fn xorshift64(mut value: u64) -> u64 {
    if value == 0 {
        value = 0x9e37_79b9_7f4a_7c15;
    }
    value ^= value << 13;
    value ^= value >> 7;
    value ^= value << 17;
    value
}

#[cfg(test)]
mod tests {
    use super::{
        expand_ipv4_prefix, expand_ipv4_range, parse_hostname_prefix, random_public_ipv4_targets,
        split_target_expression,
    };
    use std::net::Ipv4Addr;

    #[test]
    fn target_expression_splits_on_commas_semicolons_and_spaces() {
        let tokens = split_target_expression("scanme.nmap.org; 192.168.0.1,10.0.0.1");
        assert_eq!(
            tokens,
            vec![
                "scanme.nmap.org".to_string(),
                "192.168.0.1".to_string(),
                "10.0.0.1".to_string()
            ]
        );
    }

    #[test]
    fn ipv4_ranges_expand_and_truncate() {
        let (hosts, truncated) =
            expand_ipv4_range("10.0.0-1.1-254", 5).expect("range should parse");
        assert_eq!(
            hosts,
            vec![
                Ipv4Addr::new(10, 0, 0, 1),
                Ipv4Addr::new(10, 0, 0, 2),
                Ipv4Addr::new(10, 0, 0, 3),
                Ipv4Addr::new(10, 0, 0, 4),
                Ipv4Addr::new(10, 0, 0, 5)
            ]
        );
        assert!(truncated);
    }

    #[test]
    fn hostname_prefix_parser_accepts_name_slash_prefix() {
        assert_eq!(
            parse_hostname_prefix("scanme.nmap.org/24"),
            Some(("scanme.nmap.org", 24))
        );
        assert_eq!(parse_hostname_prefix("192.168.1.10/24"), None);
    }

    #[test]
    fn ipv4_prefix_expansion_uses_host_space() {
        let (hosts, truncated) = expand_ipv4_prefix(Ipv4Addr::new(192, 168, 1, 20), 30, 16);
        assert_eq!(
            hosts,
            vec![
                Ipv4Addr::new(192, 168, 1, 21),
                Ipv4Addr::new(192, 168, 1, 22)
            ]
        );
        assert!(!truncated);
    }

    #[test]
    fn random_public_targets_are_deterministic() {
        let first = random_public_ipv4_targets(4, Some(7));
        let second = random_public_ipv4_targets(4, Some(7));
        assert_eq!(first, second);
        assert_eq!(first.len(), 4);
        assert!(first.iter().all(|value| !value.starts_with("10.")));
    }
}

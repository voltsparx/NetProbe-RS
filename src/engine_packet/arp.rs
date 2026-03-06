// ARP neighbor helpers for local IPv4 enrichment.

use std::collections::BTreeMap;
use std::io;
use std::net::{Ipv4Addr, UdpSocket};
use std::process::Command;
use std::thread;
use std::time::Duration;

const BROADCAST_MAC: &str = "ff:ff:ff:ff:ff:ff";
const UNSPECIFIED_MAC: &str = "00:00:00:00:00:00";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ipv4Cidr {
    network: Ipv4Addr,
    prefix_len: u8,
}

impl Ipv4Cidr {
    pub fn network(self) -> Ipv4Addr {
        self.network
    }

    pub fn host_capacity(self) -> u64 {
        let host_bits = 32 - self.prefix_len as u32;
        if self.prefix_len >= 31 {
            1u64 << host_bits
        } else {
            (1u64 << host_bits).saturating_sub(2)
        }
    }

    pub fn expand_hosts(self, max_hosts: usize) -> (Vec<Ipv4Addr>, bool) {
        enumerate_hosts(self.network, self.prefix_len, max_hosts.max(1))
    }
}

#[derive(Debug, Clone)]
pub struct ArpSweepReport {
    pub requested_hosts: usize,
    pub attempted_hosts: usize,
    pub discovered_hosts: Vec<Ipv4Addr>,
    pub truncated: bool,
}

pub fn parse_ipv4_cidr(raw: &str) -> Option<Ipv4Cidr> {
    let (ip_raw, prefix_raw) = raw.trim().split_once('/')?;
    let ip = ip_raw.parse::<Ipv4Addr>().ok()?;
    let prefix_len = prefix_raw.parse::<u8>().ok()?;
    if prefix_len > 32 {
        return None;
    }

    let mask = prefix_to_mask(prefix_len);
    let network = Ipv4Addr::from(u32::from(ip) & mask);
    Some(Ipv4Cidr {
        network,
        prefix_len,
    })
}

pub fn is_lan_ipv4(target: Ipv4Addr) -> bool {
    target.is_private() || target.is_link_local()
}

pub fn resolve_neighbor_mac(
    target: Ipv4Addr,
    settle_timeout: Duration,
) -> io::Result<Option<String>> {
    trigger_neighbor_resolution_batch(&[target])?;
    if !settle_timeout.is_zero() {
        thread::sleep(settle_timeout.min(Duration::from_millis(500)));
    }

    let table = read_neighbor_table_all()?;
    let neighbors = extract_neighbor_map(&table);
    Ok(neighbors.get(&target).cloned())
}

pub fn sweep_ipv4_cidr(
    cidr: Ipv4Cidr,
    settle_timeout: Duration,
    max_hosts: usize,
) -> io::Result<ArpSweepReport> {
    let (targets, truncated) = cidr.expand_hosts(max_hosts);
    if targets.is_empty() {
        return Ok(ArpSweepReport {
            requested_hosts: 0,
            attempted_hosts: 0,
            discovered_hosts: Vec::new(),
            truncated,
        });
    }

    let attempted_hosts = targets.len();
    trigger_neighbor_resolution_batch(&targets)?;
    if !settle_timeout.is_zero() {
        thread::sleep(settle_timeout.min(Duration::from_millis(800)));
    }

    let table = read_neighbor_table_all()?;
    let neighbors = extract_neighbor_map(&table);
    let mut discovered_hosts = targets
        .iter()
        .copied()
        .filter(|target| neighbors.contains_key(target))
        .collect::<Vec<_>>();
    discovered_hosts.sort_unstable();
    discovered_hosts.dedup();

    Ok(ArpSweepReport {
        requested_hosts: cidr.host_capacity().min(usize::MAX as u64) as usize,
        attempted_hosts,
        discovered_hosts,
        truncated,
    })
}

fn prefix_to_mask(prefix_len: u8) -> u32 {
    if prefix_len == 0 {
        0
    } else {
        u32::MAX << (32 - prefix_len)
    }
}

fn enumerate_hosts(network: Ipv4Addr, prefix_len: u8, max_hosts: usize) -> (Vec<Ipv4Addr>, bool) {
    let network_num = u32::from(network);
    let host_bits = 32 - prefix_len as u32;
    let range_size = 1u64 << host_bits;
    let (start, count) = if prefix_len >= 31 {
        (network_num, range_size)
    } else {
        (network_num.saturating_add(1), range_size.saturating_sub(2))
    };

    let take = count.min(max_hosts as u64);
    let mut hosts = Vec::with_capacity(take as usize);
    for offset in 0..take {
        hosts.push(Ipv4Addr::from(start.saturating_add(offset as u32)));
    }
    (hosts, count > take)
}

fn trigger_neighbor_resolution_batch(targets: &[Ipv4Addr]) -> io::Result<()> {
    let socket = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0))?;
    for target in targets {
        let _ = socket.send_to(&[0u8], (*target, 9));
    }
    Ok(())
}

fn read_neighbor_table_all() -> io::Result<String> {
    #[cfg(windows)]
    {
        let output = Command::new("arp").args(["-a"]).output();
        match output {
            Ok(out) => Ok(String::from_utf8_lossy(&out.stdout).into_owned()),
            Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(String::new()),
            Err(err) => Err(err),
        }
    }

    #[cfg(not(windows))]
    {
        let ip_output = Command::new("ip").args(["neigh", "show"]).output();
        if let Ok(output) = ip_output {
            if output.status.success() {
                let text = String::from_utf8_lossy(&output.stdout).into_owned();
                if !text.trim().is_empty() {
                    return Ok(text);
                }
            }
        }

        let arp_output = Command::new("arp").args(["-an"]).output();
        match arp_output {
            Ok(out) => Ok(String::from_utf8_lossy(&out.stdout).into_owned()),
            Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(String::new()),
            Err(err) => Err(err),
        }
    }
}

fn extract_neighbor_map(table: &str) -> BTreeMap<Ipv4Addr, String> {
    let mut neighbors = BTreeMap::<Ipv4Addr, String>::new();
    for line in table.lines() {
        let mut found_ip = None;
        let mut found_mac = None;
        for token in line.split_whitespace() {
            if found_ip.is_none() {
                found_ip = normalize_ipv4_token(token);
            }
            if found_mac.is_none() {
                found_mac = normalize_mac_token(token);
            }
            if found_ip.is_some() && found_mac.is_some() {
                break;
            }
        }

        if let (Some(ip), Some(mac)) = (found_ip, found_mac) {
            if mac != BROADCAST_MAC && mac != UNSPECIFIED_MAC {
                neighbors.insert(ip, mac);
            }
        }
    }
    neighbors
}

fn normalize_ipv4_token(raw: &str) -> Option<Ipv4Addr> {
    let token = raw.trim_matches(|value: char| {
        value == '(' || value == ')' || value == '[' || value == ']' || value == ',' || value == ';'
    });
    token.parse::<Ipv4Addr>().ok()
}

fn normalize_mac_token(raw: &str) -> Option<String> {
    let token = raw.trim_matches(|value: char| {
        value == '(' || value == ')' || value == '[' || value == ']' || value == ',' || value == ';'
    });
    let separator = if token.contains(':') {
        ':'
    } else if token.contains('-') {
        '-'
    } else {
        return None;
    };

    let pieces = token.split(separator).collect::<Vec<_>>();
    if pieces.len() != 6 {
        return None;
    }

    let mut normalized = Vec::with_capacity(6);
    for piece in pieces {
        if piece.len() != 2 || !piece.chars().all(|value| value.is_ascii_hexdigit()) {
            return None;
        }
        normalized.push(piece.to_ascii_lowercase());
    }
    Some(normalized.join(":"))
}

#[cfg(test)]
mod tests {
    use super::{
        extract_neighbor_map, normalize_mac_token, parse_ipv4_cidr, prefix_to_mask, Ipv4Cidr,
    };
    use std::net::Ipv4Addr;

    fn cidr(network: [u8; 4], prefix: u8) -> Ipv4Cidr {
        Ipv4Cidr {
            network: Ipv4Addr::from(network),
            prefix_len: prefix,
        }
    }

    #[test]
    fn parses_unix_mac_format() {
        let mac = normalize_mac_token("aa:bb:cc:dd:ee:ff");
        assert_eq!(mac.as_deref(), Some("aa:bb:cc:dd:ee:ff"));
    }

    #[test]
    fn parses_windows_mac_format() {
        let mac = normalize_mac_token("AA-BB-CC-DD-EE-FF");
        assert_eq!(mac.as_deref(), Some("aa:bb:cc:dd:ee:ff"));
    }

    #[test]
    fn parses_ipv4_cidr_and_masks_network() {
        let parsed = parse_ipv4_cidr("192.168.10.55/24").expect("cidr parsed");
        assert_eq!(parsed.network(), Ipv4Addr::new(192, 168, 10, 0));
        assert_eq!(parsed.host_capacity(), 254);
    }

    #[test]
    fn expands_hosts_without_network_and_broadcast() {
        let cidr = cidr([192, 168, 1, 0], 24);
        let (hosts, truncated) = cidr.expand_hosts(512);
        assert!(!truncated);
        assert_eq!(hosts.len(), 254);
        assert_eq!(hosts.first(), Some(&Ipv4Addr::new(192, 168, 1, 1)));
        assert_eq!(hosts.last(), Some(&Ipv4Addr::new(192, 168, 1, 254)));
    }

    #[test]
    fn expands_point_to_point_prefixes() {
        let cidr = cidr([10, 0, 0, 0], 31);
        let (hosts, truncated) = cidr.expand_hosts(16);
        assert!(!truncated);
        assert_eq!(
            hosts,
            vec![Ipv4Addr::new(10, 0, 0, 0), Ipv4Addr::new(10, 0, 0, 1)]
        );
    }

    #[test]
    fn extracts_neighbors_from_mixed_table_output() {
        let table = "192.168.1.12 dev wlan0 lladdr 04:52:c7:30:22:9a REACHABLE\n  10.0.0.1           00-11-22-33-44-55   dynamic";
        let neighbors = extract_neighbor_map(table);
        assert_eq!(
            neighbors
                .get(&Ipv4Addr::new(192, 168, 1, 12))
                .map(|v| v.as_str()),
            Some("04:52:c7:30:22:9a")
        );
        assert_eq!(
            neighbors
                .get(&Ipv4Addr::new(10, 0, 0, 1))
                .map(|v| v.as_str()),
            Some("00:11:22:33:44:55")
        );
    }

    #[test]
    fn prefix_mask_handles_zero_prefix() {
        assert_eq!(prefix_to_mask(0), 0);
        assert_eq!(prefix_to_mask(32), u32::MAX);
    }
}

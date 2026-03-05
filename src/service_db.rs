// Flow sketch: input -> core processing -> output model
// Pseudo-block:
//   read input -> process safely -> return deterministic output

use std::cmp::Ordering;
use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::Path;

#[derive(Debug, Clone)]
pub struct ServiceRegistry {
    services: HashMap<(u16, String), String>,
    ranked_tcp_ports: Vec<u16>,
}

impl ServiceRegistry {
    pub fn load() -> Self {
        let nmap_services = Path::new("temp/nmap/nmap-services");
        if let Ok(content) = fs::read_to_string(nmap_services) {
            return Self::from_nmap_services(&content);
        }
        Self::fallback()
    }

    pub fn lookup(&self, port: u16, protocol: &str) -> Option<&str> {
        let key = (port, protocol.to_ascii_lowercase());
        self.services.get(&key).map(String::as_str)
    }

    pub fn top_tcp_ports(&self, count: usize) -> Vec<u16> {
        self.ranked_tcp_ports
            .iter()
            .copied()
            .take(count.max(1))
            .collect()
    }

    pub fn service_count(&self) -> usize {
        self.services.len()
    }

    pub fn ranked_port_count(&self) -> usize {
        self.ranked_tcp_ports.len()
    }

    fn from_nmap_services(content: &str) -> Self {
        let mut services = HashMap::new();
        let mut ranking = Vec::<(u16, f64)>::new();

        for line in content.lines() {
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with('#') {
                continue;
            }

            let mut cols = trimmed.split_whitespace();
            let service_name = match cols.next() {
                Some(value) => value.to_string(),
                None => continue,
            };
            let port_proto = match cols.next() {
                Some(value) => value,
                None => continue,
            };
            let freq = cols
                .next()
                .and_then(|v| v.parse::<f64>().ok())
                .unwrap_or(0.0);

            let (port_raw, proto_raw) = match port_proto.split_once('/') {
                Some(value) => value,
                None => continue,
            };
            let Ok(port) = port_raw.parse::<u16>() else {
                continue;
            };
            let proto = proto_raw.to_ascii_lowercase();

            services
                .entry((port, proto.clone()))
                .or_insert(service_name);
            if proto == "tcp" {
                ranking.push((port, freq));
            }
        }

        ranking.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(Ordering::Equal));
        let mut seen = HashSet::new();
        let mut ranked_tcp_ports = Vec::with_capacity(ranking.len());
        for (port, _) in ranking {
            if seen.insert(port) {
                ranked_tcp_ports.push(port);
            }
        }

        if ranked_tcp_ports.is_empty() {
            return Self::fallback();
        }

        Self {
            services,
            ranked_tcp_ports,
        }
    }

    fn fallback() -> Self {
        let top_ports = vec![
            80, 443, 22, 21, 25, 53, 110, 143, 445, 3306, 3389, 8080, 8443, 139, 23, 135, 111, 993,
            995, 1723, 5900, 587, 465, 8000, 5901, 1025, 554, 8008, 8888, 2000, 1026, 81, 179,
            32768, 5000, 5432, 1027, 6001, 8009, 49152, 1028, 4444, 49153, 26, 7, 646, 515, 389,
            631, 49154, 427, 199, 1029, 37, 888, 49155, 113, 9930, 8081, 2049, 6000, 1024, 4000,
            5870, 5060, 49156, 2001, 6002, 10000, 32769, 3128, 5800, 4650, 49157, 5902, 2048,
            27017, 161, 162, 123, 69, 500, 520, 1900, 5353, 67, 68, 514, 177, 4500, 1701,
        ];
        let mut services = HashMap::new();
        let common = [
            (20, "tcp", "ftp-data"),
            (21, "tcp", "ftp"),
            (22, "tcp", "ssh"),
            (23, "tcp", "telnet"),
            (25, "tcp", "smtp"),
            (53, "tcp", "domain"),
            (53, "udp", "domain"),
            (80, "tcp", "http"),
            (110, "tcp", "pop3"),
            (123, "udp", "ntp"),
            (135, "tcp", "msrpc"),
            (139, "tcp", "netbios-ssn"),
            (143, "tcp", "imap"),
            (161, "udp", "snmp"),
            (389, "tcp", "ldap"),
            (443, "tcp", "https"),
            (445, "tcp", "microsoft-ds"),
            (465, "tcp", "smtps"),
            (514, "udp", "syslog"),
            (587, "tcp", "submission"),
            (631, "tcp", "ipp"),
            (3306, "tcp", "mysql"),
            (3389, "tcp", "ms-wbt-server"),
            (5432, "tcp", "postgresql"),
            (5900, "tcp", "vnc"),
            (8080, "tcp", "http-proxy"),
            (8443, "tcp", "https-alt"),
        ];
        for (port, proto, name) in common {
            services.insert((port, proto.to_string()), name.to_string());
        }

        Self {
            services,
            ranked_tcp_ports: top_ports,
        }
    }
}

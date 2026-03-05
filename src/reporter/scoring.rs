// Flow sketch: ports -> scoring/findings/guidance -> insights
// Pseudo-block:
//   read input -> process safely -> return deterministic output
// risk points are seasoning, not destiny.

use crate::models::{PortFinding, PortState};

pub fn score_port(port: &PortFinding) -> u32 {
    if !matches!(port.state, PortState::Open | PortState::OpenOrFiltered) {
        return 0;
    }

    let mut score = 3u32;
    score += match port.port {
        21 | 23 => 20,
        22 | 3389 | 5900 => 14,
        445 | 139 => 16,
        3306 | 5432 | 27017 | 6379 => 12,
        80 | 443 | 8080 | 8443 => 6,
        _ => 2,
    };

    if let Some(service) = &port.service {
        let s = service.as_str();
        if matches!(s, "ftp" | "telnet" | "pop3" | "imap" | "smtp") {
            score += 8;
        }
        if matches!(s, "ms-wbt-server" | "ssh" | "vnc" | "microsoft-ds") {
            score += 5;
        }
    }

    if let Some(banner) = &port.banner {
        if banner.contains("Apache/2.2")
            || banner.contains("OpenSSL/1.0")
            || banner.contains("ProFTPD 1.3.3")
        {
            score += 8;
        }
    }

    score
}

pub fn normalize(raw_score: u32) -> u8 {
    let scaled = (raw_score as f64 * 0.72).round() as u32;
    scaled.min(100) as u8
}

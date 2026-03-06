use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeviceClass {
    FragileEmbedded,
    Enterprise,
    PrinterSensitive,
    Generic,
}

impl fmt::Display for DeviceClass {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let text = match self {
            DeviceClass::FragileEmbedded => "fragile-embedded",
            DeviceClass::Enterprise => "enterprise",
            DeviceClass::PrinterSensitive => "printer-sensitive",
            DeviceClass::Generic => "generic",
        };
        f.write_str(text)
    }
}

#[derive(Debug, Clone, Copy)]
pub struct DeviceProfile {
    pub class: DeviceClass,
    pub vendor: Option<&'static str>,
    pub max_pps: Option<u32>,
    pub safety_blacklist: &'static [u16],
}

impl DeviceProfile {
    pub fn describe(self) -> String {
        let vendor = self.vendor.unwrap_or("unknown-vendor");
        let pps = self
            .max_pps
            .map(|value| value.to_string())
            .unwrap_or_else(|| "unbounded".to_string());
        format!(
            "device-profile class={} vendor={} max-pps={} blacklist={:?}",
            self.class, vendor, pps, self.safety_blacklist
        )
    }

    pub fn is_fragile(self) -> bool {
        matches!(
            self.class,
            DeviceClass::FragileEmbedded | DeviceClass::PrinterSensitive
        )
    }

    pub fn async_concurrency_cap(self) -> Option<usize> {
        match self.class {
            DeviceClass::FragileEmbedded => Some(4),
            DeviceClass::PrinterSensitive => Some(8),
            DeviceClass::Enterprise => Some(128),
            DeviceClass::Generic => Some(16),
        }
    }

    pub fn allows_active_fingerprinting(self) -> bool {
        matches!(self.class, DeviceClass::Enterprise)
    }
}

const UNIVERSAL_SAFETY_BLACKLIST: &[u16] = &[9100];

const ESPRESSIF_OUIS: &[[u8; 3]] = &[
    [0x24, 0x0a, 0xc4],
    [0x7c, 0xdf, 0xa1],
    [0xac, 0x67, 0xb2],
    [0x84, 0xf3, 0xeb],
];

const ARDUINO_OUIS: &[[u8; 3]] = &[[0xa8, 0x61, 0x0a], [0x90, 0xa2, 0xda]];

const CISCO_OUIS: &[[u8; 3]] = &[[0x00, 0x1b, 0x54], [0x00, 0x25, 0x45], [0x00, 0x40, 0x96]];

const DELL_OUIS: &[[u8; 3]] = &[[0x00, 0x14, 0x22], [0xf8, 0xbc, 0x12], [0xb8, 0xac, 0x6f]];

const PRINTER_OUIS: &[[u8; 3]] = &[
    [0x00, 0x1f, 0x29], // HP
    [0x00, 0x80, 0x92], // Brother
    [0x00, 0x1e, 0x8f], // Canon
];

pub fn parse_oui(mac: &str) -> Option<[u8; 3]> {
    let token = mac.trim();
    let sep = if token.contains(':') {
        ':'
    } else if token.contains('-') {
        '-'
    } else {
        return None;
    };

    let parts = token.split(sep).collect::<Vec<_>>();
    if parts.len() < 3 {
        return None;
    }

    let mut oui = [0u8; 3];
    for (index, part) in parts.iter().take(3).enumerate() {
        if part.len() != 2 {
            return None;
        }
        oui[index] = u8::from_str_radix(part, 16).ok()?;
    }
    Some(oui)
}

pub fn classify_mac(mac: &str) -> DeviceProfile {
    let Some(oui) = parse_oui(mac) else {
        return DeviceProfile {
            class: DeviceClass::Generic,
            vendor: None,
            max_pps: None,
            safety_blacklist: &[],
        };
    };

    classify_oui(oui)
}

fn classify_oui(oui: [u8; 3]) -> DeviceProfile {
    if ESPRESSIF_OUIS.contains(&oui) || ARDUINO_OUIS.contains(&oui) {
        return DeviceProfile {
            class: DeviceClass::FragileEmbedded,
            vendor: Some("embedded-iot"),
            max_pps: Some(25),
            safety_blacklist: UNIVERSAL_SAFETY_BLACKLIST,
        };
    }

    if PRINTER_OUIS.contains(&oui) {
        return DeviceProfile {
            class: DeviceClass::PrinterSensitive,
            vendor: Some("printer-family"),
            max_pps: Some(100),
            safety_blacklist: UNIVERSAL_SAFETY_BLACKLIST,
        };
    }

    if CISCO_OUIS.contains(&oui) {
        return DeviceProfile {
            class: DeviceClass::Enterprise,
            vendor: Some("cisco"),
            max_pps: Some(5_000),
            safety_blacklist: UNIVERSAL_SAFETY_BLACKLIST,
        };
    }

    if DELL_OUIS.contains(&oui) {
        return DeviceProfile {
            class: DeviceClass::Enterprise,
            vendor: Some("dell"),
            max_pps: Some(5_000),
            safety_blacklist: UNIVERSAL_SAFETY_BLACKLIST,
        };
    }

    DeviceProfile {
        class: DeviceClass::Generic,
        vendor: Some("unknown"),
        max_pps: Some(500),
        safety_blacklist: UNIVERSAL_SAFETY_BLACKLIST,
    }
}

#[cfg(test)]
mod tests {
    use super::{classify_mac, parse_oui, DeviceClass};

    #[test]
    fn parse_oui_accepts_mac_formats() {
        assert_eq!(parse_oui("24:0A:C4:11:22:33"), Some([0x24, 0x0a, 0xc4]));
        assert_eq!(parse_oui("00-1B-54-11-22-33"), Some([0x00, 0x1b, 0x54]));
        assert!(parse_oui("bad-mac").is_none());
    }

    #[test]
    fn classify_embedded_and_enterprise() {
        let embedded = classify_mac("24:0A:C4:11:22:33");
        let enterprise = classify_mac("00:1B:54:11:22:33");
        assert_eq!(embedded.class, DeviceClass::FragileEmbedded);
        assert_eq!(enterprise.class, DeviceClass::Enterprise);
    }
}

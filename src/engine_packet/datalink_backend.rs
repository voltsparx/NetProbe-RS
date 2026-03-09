// Layer-2 backend: sends crafted Ethernet+IPv4+TCP frames directly on interface.

#[cfg(target_os = "linux")]
mod imp {
    use std::io;
    use std::io::ErrorKind;
    use std::net::{IpAddr, Ipv4Addr};
    use std::time::{Duration, Instant};

    use pnet_datalink::{
        self, Channel, Config as DatalinkConfig, DataLinkReceiver, DataLinkSender, MacAddr,
        NetworkInterface,
    };
    use pnet_packet::ethernet::{EtherTypes, EthernetPacket, MutableEthernetPacket};
    use pnet_packet::{MutablePacket, Packet};

    use crate::engine_packet::arp;
    use crate::engine_packet::datalink_backend::parse_mac_bytes;
    use crate::engine_packet::syn_scanner::{RawRxBackend, RawTxBackend};

    pub struct DatalinkRawTx {
        tx: Box<dyn DataLinkSender>,
        source_mac: MacAddr,
        destination_mac: MacAddr,
    }

    pub struct DatalinkRawRx {
        rx: Box<dyn DataLinkReceiver>,
        ipv4_buffer: Vec<u8>,
    }

    pub fn open_layer2_backends(
        source_ip: Ipv4Addr,
        target_ip: Ipv4Addr,
    ) -> io::Result<(DatalinkRawTx, DatalinkRawRx)> {
        let interface = interface_for_source_ip(source_ip)?;
        let source_mac = interface.mac.ok_or_else(|| {
            io::Error::new(
                ErrorKind::AddrNotAvailable,
                format!("interface '{}' has no MAC address", interface.name),
            )
        })?;
        let destination_mac = resolve_destination_mac(target_ip)?;

        let config = DatalinkConfig {
            read_timeout: Some(Duration::from_millis(50)),
            read_buffer_size: 4 * 1024 * 1024,
            write_buffer_size: 2 * 1024 * 1024,
            ..DatalinkConfig::default()
        };

        match pnet_datalink::channel(&interface, config)? {
            Channel::Ethernet(tx, rx) => Ok((
                DatalinkRawTx {
                    tx,
                    source_mac,
                    destination_mac,
                },
                DatalinkRawRx {
                    rx,
                    ipv4_buffer: vec![0u8; 65_535],
                },
            )),
            _ => Err(io::Error::other("unsupported datalink channel type")),
        }
    }

    impl RawTxBackend for DatalinkRawTx {
        fn send_ipv4(&mut self, packet: &[u8], _target: Ipv4Addr) -> io::Result<()> {
            let mut frame_map_failed = false;
            let send_result = self.tx.build_and_send(1, 14 + packet.len(), &mut |frame| {
                if let Some(mut eth) = MutableEthernetPacket::new(frame) {
                    eth.set_source(self.source_mac);
                    eth.set_destination(self.destination_mac);
                    eth.set_ethertype(EtherTypes::Ipv4);
                    eth.payload_mut().copy_from_slice(packet);
                } else {
                    frame_map_failed = true;
                }
            });

            if frame_map_failed {
                return Err(io::Error::other("failed to map ethernet frame buffer"));
            }

            match send_result {
                Some(Ok(())) => Ok(()),
                Some(Err(err)) => Err(err),
                None => Err(io::Error::new(
                    ErrorKind::WouldBlock,
                    "datalink sender had insufficient buffer capacity",
                )),
            }
        }
    }

    impl RawRxBackend for DatalinkRawRx {
        fn recv_ipv4(&mut self, timeout: Duration) -> io::Result<Option<&[u8]>> {
            let deadline = Instant::now() + timeout;
            loop {
                match self.rx.next() {
                    Ok(frame) => {
                        if let Some(eth) = EthernetPacket::new(frame) {
                            if eth.get_ethertype() == EtherTypes::Ipv4 {
                                let payload = eth.payload();
                                if payload.len() > self.ipv4_buffer.len() {
                                    return Err(io::Error::other(
                                        "received frame larger than preallocated buffer",
                                    ));
                                }
                                self.ipv4_buffer[..payload.len()].copy_from_slice(payload);
                                return Ok(Some(&self.ipv4_buffer[..payload.len()]));
                            }
                        }
                    }
                    Err(err)
                        if err.kind() == ErrorKind::TimedOut
                            || err.kind() == ErrorKind::WouldBlock
                            || err.kind() == ErrorKind::Interrupted =>
                    {
                        if Instant::now() >= deadline {
                            return Ok(None);
                        }
                    }
                    Err(err) => return Err(err),
                }

                if Instant::now() >= deadline {
                    return Ok(None);
                }
            }
        }
    }

    fn interface_for_source_ip(source_ip: Ipv4Addr) -> io::Result<NetworkInterface> {
        let interfaces = pnet_datalink::interfaces();
        interfaces
            .into_iter()
            .find(|iface| {
                iface.is_up()
                    && !iface.is_loopback()
                    && iface
                        .ips
                        .iter()
                        .any(|network| network.ip() == IpAddr::V4(source_ip))
            })
            .ok_or_else(|| {
                io::Error::new(
                    ErrorKind::NotFound,
                    format!("no active interface found for source ip {}", source_ip),
                )
            })
    }

    fn resolve_destination_mac(target_ip: Ipv4Addr) -> io::Result<MacAddr> {
        if !arp::is_lan_ipv4(target_ip) {
            return Err(io::Error::new(
                ErrorKind::AddrNotAvailable,
                format!(
                    "target {} is not local/private link for direct L2 frame delivery",
                    target_ip
                ),
            ));
        }

        let mac_text = arp::resolve_neighbor_mac(target_ip, Duration::from_millis(220))?
            .ok_or_else(|| {
                io::Error::new(
                    ErrorKind::NotFound,
                    format!("no neighbor MAC found for {}", target_ip),
                )
            })?;

        let bytes = parse_mac_bytes(&mac_text).ok_or_else(|| {
            io::Error::new(
                ErrorKind::InvalidData,
                format!("failed to parse mac address '{}'", mac_text),
            )
        })?;
        Ok(MacAddr::new(
            bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5],
        ))
    }
}

#[cfg(not(target_os = "linux"))]
mod imp {
    use std::io;
    use std::net::Ipv4Addr;
    use std::time::Duration;

    use crate::engine_packet::syn_scanner::{RawRxBackend, RawTxBackend};

    pub struct DatalinkRawTx;
    pub struct DatalinkRawRx;

    pub fn open_layer2_backends(
        _source_ip: Ipv4Addr,
        _target_ip: Ipv4Addr,
    ) -> io::Result<(DatalinkRawTx, DatalinkRawRx)> {
        Err(io::Error::other(
            "direct layer-2 backend is currently supported on Linux hosts only",
        ))
    }

    impl RawTxBackend for DatalinkRawTx {
        fn send_ipv4(&mut self, _packet: &[u8], _target: Ipv4Addr) -> io::Result<()> {
            Err(io::Error::other(
                "layer-2 backend unavailable on this platform",
            ))
        }
    }

    impl RawRxBackend for DatalinkRawRx {
        fn recv_ipv4(&mut self, _timeout: Duration) -> io::Result<Option<&[u8]>> {
            Ok(None)
        }
    }
}

pub use imp::open_layer2_backends;

#[cfg(any(target_os = "linux", test))]
fn parse_mac_bytes(raw: &str) -> Option<[u8; 6]> {
    let token = raw.trim();
    let sep = if token.contains(':') { ':' } else { '-' };
    let pieces = token.split(sep).collect::<Vec<_>>();
    if pieces.len() != 6 {
        return None;
    }

    let mut bytes = [0u8; 6];
    for (idx, piece) in pieces.iter().enumerate() {
        if piece.len() != 2 {
            return None;
        }
        bytes[idx] = u8::from_str_radix(piece, 16).ok()?;
    }
    Some(bytes)
}

#[cfg(test)]
mod tests {
    use super::parse_mac_bytes;

    #[test]
    fn mac_parser_accepts_colon_and_dash() {
        assert!(parse_mac_bytes("aa:bb:cc:dd:ee:ff").is_some());
        assert!(parse_mac_bytes("AA-BB-CC-DD-EE-FF").is_some());
        assert!(parse_mac_bytes("bad-mac").is_none());
    }
}

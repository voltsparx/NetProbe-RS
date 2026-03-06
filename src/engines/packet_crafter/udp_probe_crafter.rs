use std::io;
use std::net::Ipv4Addr;

use pnet_packet::ip::IpNextHeaderProtocols;
use pnet_packet::ipv4::{self, MutableIpv4Packet};
use pnet_packet::udp::{ipv4_checksum, MutableUdpPacket};
use pnet_packet::MutablePacket;

const IPV4_HEADER_LEN: usize = 20;
const UDP_HEADER_LEN: usize = 8;
const UDP_PACKET_LEN: usize = IPV4_HEADER_LEN + UDP_HEADER_LEN;

#[derive(Debug)]
pub struct UdpProbeCrafter {
    source_ip: Ipv4Addr,
    source_port: u16,
    buffer: [u8; UDP_PACKET_LEN],
}

impl UdpProbeCrafter {
    pub fn new(source_ip: Ipv4Addr, source_port: u16) -> io::Result<Self> {
        let mut buffer = [0u8; UDP_PACKET_LEN];
        let mut ipv4_packet = MutableIpv4Packet::new(&mut buffer)
            .ok_or_else(|| io::Error::other("failed to create ipv4 udp packet"))?;
        ipv4_packet.set_version(4);
        ipv4_packet.set_header_length((IPV4_HEADER_LEN / 4) as u8);
        ipv4_packet.set_total_length(UDP_PACKET_LEN as u16);
        ipv4_packet.set_ttl(64);
        ipv4_packet.set_next_level_protocol(IpNextHeaderProtocols::Udp);
        ipv4_packet.set_source(source_ip);
        ipv4_packet.set_destination(Ipv4Addr::UNSPECIFIED);

        Ok(Self {
            source_ip,
            source_port,
            buffer,
        })
    }

    pub fn craft_probe(&mut self, target_ip: Ipv4Addr, target_port: u16) -> io::Result<&[u8]> {
        let mut ipv4_packet = MutableIpv4Packet::new(&mut self.buffer)
            .ok_or_else(|| io::Error::other("failed to map ipv4 udp packet"))?;
        ipv4_packet.set_source(self.source_ip);
        ipv4_packet.set_destination(target_ip);
        ipv4_packet.set_checksum(0);

        {
            let mut udp_packet = MutableUdpPacket::new(ipv4_packet.payload_mut())
                .ok_or_else(|| io::Error::other("failed to map udp packet"))?;
            udp_packet.set_source(self.source_port);
            udp_packet.set_destination(target_port);
            udp_packet.set_length(UDP_HEADER_LEN as u16);
            udp_packet.set_checksum(0);
            let checksum = ipv4_checksum(&udp_packet.to_immutable(), &self.source_ip, &target_ip);
            udp_packet.set_checksum(checksum);
        }

        let checksum = ipv4::checksum(&ipv4_packet.to_immutable());
        ipv4_packet.set_checksum(checksum);
        Ok(&self.buffer)
    }
}

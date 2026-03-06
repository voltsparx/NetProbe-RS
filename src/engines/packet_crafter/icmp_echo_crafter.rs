use std::io;
use std::net::Ipv4Addr;

use pnet_packet::icmp::{checksum, IcmpTypes, MutableIcmpPacket};
use pnet_packet::ip::IpNextHeaderProtocols;
use pnet_packet::ipv4::{self, MutableIpv4Packet};
use pnet_packet::MutablePacket;

const IPV4_HEADER_LEN: usize = 20;
const ICMP_HEADER_LEN: usize = 8;
const ICMP_PACKET_LEN: usize = IPV4_HEADER_LEN + ICMP_HEADER_LEN;

#[derive(Debug)]
pub struct IcmpEchoCrafter {
    source_ip: Ipv4Addr,
    buffer: [u8; ICMP_PACKET_LEN],
}

impl IcmpEchoCrafter {
    pub fn new(source_ip: Ipv4Addr) -> io::Result<Self> {
        let mut buffer = [0u8; ICMP_PACKET_LEN];
        let mut ipv4_packet = MutableIpv4Packet::new(&mut buffer)
            .ok_or_else(|| io::Error::other("failed to create ipv4 icmp packet"))?;
        ipv4_packet.set_version(4);
        ipv4_packet.set_header_length((IPV4_HEADER_LEN / 4) as u8);
        ipv4_packet.set_total_length(ICMP_PACKET_LEN as u16);
        ipv4_packet.set_ttl(64);
        ipv4_packet.set_next_level_protocol(IpNextHeaderProtocols::Icmp);
        ipv4_packet.set_source(source_ip);
        ipv4_packet.set_destination(Ipv4Addr::UNSPECIFIED);

        Ok(Self { source_ip, buffer })
    }

    pub fn craft_echo(&mut self, target_ip: Ipv4Addr, id: u16, seq: u16) -> io::Result<&[u8]> {
        let mut ipv4_packet = MutableIpv4Packet::new(&mut self.buffer)
            .ok_or_else(|| io::Error::other("failed to map ipv4 icmp packet"))?;
        ipv4_packet.set_source(self.source_ip);
        ipv4_packet.set_destination(target_ip);
        ipv4_packet.set_checksum(0);

        {
            let mut icmp_packet = MutableIcmpPacket::new(ipv4_packet.payload_mut())
                .ok_or_else(|| io::Error::other("failed to map icmp packet"))?;
            icmp_packet.set_icmp_type(IcmpTypes::EchoRequest);
            icmp_packet.set_icmp_code(pnet_packet::icmp::IcmpCode(0));

            let payload = icmp_packet.packet_mut();
            payload[4] = (id >> 8) as u8;
            payload[5] = id as u8;
            payload[6] = (seq >> 8) as u8;
            payload[7] = seq as u8;

            icmp_packet.set_checksum(0);
            let csum = checksum(&icmp_packet.to_immutable());
            icmp_packet.set_checksum(csum);
        }

        let checksum = ipv4::checksum(&ipv4_packet.to_immutable());
        ipv4_packet.set_checksum(checksum);
        Ok(&self.buffer)
    }
}

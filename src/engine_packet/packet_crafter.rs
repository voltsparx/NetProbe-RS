// Masscan-style packet crafter: reuse a fixed packet template, mutate hot fields only.

use std::io;
use std::net::Ipv4Addr;

use pnet_packet::ip::IpNextHeaderProtocols;
use pnet_packet::ipv4::{self, MutableIpv4Packet};
use pnet_packet::tcp::{ipv4_checksum, MutableTcpPacket, TcpFlags};
use pnet_packet::MutablePacket;

const IPV4_HEADER_LEN: usize = 20;
const TCP_HEADER_LEN: usize = 20;
const SYN_PACKET_LEN: usize = IPV4_HEADER_LEN + TCP_HEADER_LEN;

#[derive(Debug)]
pub struct SynPacketCrafter {
    source_ip: Ipv4Addr,
    source_port: u16,
    buffer: [u8; SYN_PACKET_LEN],
}

impl SynPacketCrafter {
    pub fn new(source_ip: Ipv4Addr, source_port: u16) -> io::Result<Self> {
        let mut buffer = [0u8; SYN_PACKET_LEN];
        {
            let mut ipv4_packet = MutableIpv4Packet::new(&mut buffer)
                .ok_or_else(|| io::Error::other("failed to allocate ipv4 packet"))?;
            ipv4_packet.set_version(4);
            ipv4_packet.set_header_length((IPV4_HEADER_LEN / 4) as u8);
            ipv4_packet.set_total_length(SYN_PACKET_LEN as u16);
            ipv4_packet.set_ttl(64);
            ipv4_packet.set_next_level_protocol(IpNextHeaderProtocols::Tcp);
            ipv4_packet.set_source(source_ip);
            ipv4_packet.set_destination(Ipv4Addr::UNSPECIFIED);
            ipv4_packet.set_identification(0);
            ipv4_packet.set_flags(0);
            ipv4_packet.set_fragment_offset(0);

            let mut tcp_packet = MutableTcpPacket::new(ipv4_packet.payload_mut())
                .ok_or_else(|| io::Error::other("failed to allocate tcp packet"))?;
            tcp_packet.set_source(source_port);
            tcp_packet.set_destination(0);
            tcp_packet.set_sequence(0);
            tcp_packet.set_acknowledgement(0);
            tcp_packet.set_data_offset((TCP_HEADER_LEN / 4) as u8);
            tcp_packet.set_flags(TcpFlags::SYN);
            tcp_packet.set_window(64_240);
            tcp_packet.set_urgent_ptr(0);
        }

        Ok(Self {
            source_ip,
            source_port,
            buffer,
        })
    }

    pub fn craft_syn(
        &mut self,
        target_ip: Ipv4Addr,
        target_port: u16,
        sequence: u32,
    ) -> io::Result<&[u8]> {
        let mut ipv4_packet = MutableIpv4Packet::new(&mut self.buffer)
            .ok_or_else(|| io::Error::other("failed to map ipv4 packet"))?;
        ipv4_packet.set_source(self.source_ip);
        ipv4_packet.set_destination(target_ip);
        ipv4_packet.set_checksum(0);

        {
            let mut tcp_packet = MutableTcpPacket::new(ipv4_packet.payload_mut())
                .ok_or_else(|| io::Error::other("failed to map tcp packet"))?;
            tcp_packet.set_source(self.source_port);
            tcp_packet.set_destination(target_port);
            tcp_packet.set_sequence(sequence);
            tcp_packet.set_acknowledgement(0);
            tcp_packet.set_flags(TcpFlags::SYN);
            tcp_packet.set_checksum(0);
            let checksum = ipv4_checksum(&tcp_packet.to_immutable(), &self.source_ip, &target_ip);
            tcp_packet.set_checksum(checksum);
        }

        let checksum = ipv4::checksum(&ipv4_packet.to_immutable());
        ipv4_packet.set_checksum(checksum);
        Ok(&self.buffer)
    }
}

pub fn syn_cookie_sequence(target_ip: Ipv4Addr, target_port: u16, seed: u64) -> u32 {
    let mut value = seed ^ 0xcbf2_9ce4_8422_2325;
    for byte in target_ip.octets() {
        value ^= byte as u64;
        value = value.wrapping_mul(0x0000_0100_0000_01b3);
    }
    value ^= target_port as u64;
    value = value.wrapping_mul(0x0000_0100_0000_01b3);
    (value as u32).wrapping_add(((value >> 32) as u32).rotate_left(13))
}

pub fn syn_cookie_ack_expected(target_ip: Ipv4Addr, target_port: u16, seed: u64) -> u32 {
    syn_cookie_sequence(target_ip, target_port, seed).wrapping_add(1)
}

#[cfg(test)]
mod tests {
    use super::{syn_cookie_ack_expected, syn_cookie_sequence, SynPacketCrafter};
    use pnet_packet::ipv4::Ipv4Packet;
    use pnet_packet::tcp::{TcpFlags, TcpPacket};
    use pnet_packet::Packet;
    use std::net::Ipv4Addr;

    #[test]
    fn crafter_sets_target_and_syn_fields() {
        let mut crafter = SynPacketCrafter::new(Ipv4Addr::new(10, 0, 0, 5), 41000).expect("init");
        let packet = crafter
            .craft_syn(Ipv4Addr::new(10, 0, 0, 77), 443, 123456)
            .expect("craft");

        let ipv4 = Ipv4Packet::new(packet).expect("ipv4");
        let tcp = TcpPacket::new(ipv4.payload()).expect("tcp");
        assert_eq!(ipv4.get_destination(), Ipv4Addr::new(10, 0, 0, 77));
        assert_eq!(tcp.get_destination(), 443);
        assert_eq!(tcp.get_sequence(), 123456);
        assert_eq!(tcp.get_flags(), TcpFlags::SYN);
    }

    #[test]
    fn cookie_ack_matches_sequence_plus_one() {
        let seq = syn_cookie_sequence(Ipv4Addr::new(1, 2, 3, 4), 80, 99);
        let ack = syn_cookie_ack_expected(Ipv4Addr::new(1, 2, 3, 4), 80, 99);
        assert_eq!(ack, seq.wrapping_add(1));
    }
}

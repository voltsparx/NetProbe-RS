use std::io;
use std::net::Ipv4Addr;

use pnet_packet::ip::IpNextHeaderProtocols;
use pnet_packet::ipv4::{self, MutableIpv4Packet};
use pnet_packet::tcp::{ipv4_checksum, MutableTcpPacket};
use pnet_packet::MutablePacket;

const IPV4_HEADER_LEN: usize = 20;
const TCP_HEADER_LEN: usize = 20;
const IPV4_TCP_FRAME_LEN: usize = IPV4_HEADER_LEN + TCP_HEADER_LEN;

fn write_raw_tcp_header(
    packet: &mut MutableTcpPacket<'_>,
    src_port: u16,
    dest_port: u16,
    seq_num: u32,
    ack_num: u32,
    tcp_flags: u8,
    window_size: u16,
) {
    packet.set_source(src_port);
    packet.set_destination(dest_port);
    packet.set_sequence(seq_num);
    packet.set_acknowledgement(ack_num);
    packet.set_data_offset((TCP_HEADER_LEN / 4) as u8);
    packet.set_flags(tcp_flags);
    packet.set_window(window_size);
    packet.set_urgent_ptr(0);
}

pub fn generate_reference_frame(
    src_ip: Ipv4Addr,
    dest_ip: Ipv4Addr,
    src_port: u16,
    dest_port: u16,
    tcp_flags: u8,
    seq_num: u32,
    ack_num: u32,
    window_size: u16,
) -> io::Result<Vec<u8>> {
    let mut buffer = vec![0u8; IPV4_TCP_FRAME_LEN];
    let mut ipv4_packet = MutableIpv4Packet::new(&mut buffer)
        .ok_or_else(|| io::Error::other("failed to allocate ipv4 reference frame"))?;

    ipv4_packet.set_version(4);
    ipv4_packet.set_header_length((IPV4_HEADER_LEN / 4) as u8);
    ipv4_packet.set_total_length(IPV4_TCP_FRAME_LEN as u16);
    ipv4_packet.set_ttl(64);
    ipv4_packet.set_next_level_protocol(IpNextHeaderProtocols::Tcp);
    ipv4_packet.set_source(src_ip);
    ipv4_packet.set_destination(dest_ip);
    ipv4_packet.set_identification(0);
    ipv4_packet.set_flags(0);
    ipv4_packet.set_fragment_offset(0);
    ipv4_packet.set_checksum(0);

    {
        let mut tcp_packet = MutableTcpPacket::new(ipv4_packet.payload_mut())
            .ok_or_else(|| io::Error::other("failed to allocate tcp reference frame"))?;
        write_raw_tcp_header(
            &mut tcp_packet,
            src_port,
            dest_port,
            seq_num,
            ack_num,
            tcp_flags,
            window_size,
        );
        tcp_packet.set_checksum(0);
        let checksum = ipv4_checksum(&tcp_packet.to_immutable(), &src_ip, &dest_ip);
        tcp_packet.set_checksum(checksum);
    }

    let checksum = ipv4::checksum(&ipv4_packet.to_immutable());
    ipv4_packet.set_checksum(checksum);

    Ok(buffer)
}

#[cfg(test)]
mod tests {
    use super::generate_reference_frame;
    use pnet_packet::ipv4::Ipv4Packet;
    use pnet_packet::tcp::{TcpFlags, TcpPacket};
    use pnet_packet::Packet;
    use std::net::Ipv4Addr;

    #[test]
    fn reference_frame_serializes_ipv4_and_tcp_fields() {
        let frame = generate_reference_frame(
            Ipv4Addr::new(192, 0, 2, 10),
            Ipv4Addr::new(198, 51, 100, 25),
            41000,
            443,
            TcpFlags::SYN,
            123_456,
            0,
            32_768,
        )
        .expect("frame");

        let ipv4 = Ipv4Packet::new(&frame).expect("ipv4");
        let tcp = TcpPacket::new(ipv4.payload()).expect("tcp");
        assert_eq!(ipv4.get_source(), Ipv4Addr::new(192, 0, 2, 10));
        assert_eq!(ipv4.get_destination(), Ipv4Addr::new(198, 51, 100, 25));
        assert_eq!(tcp.get_source(), 41000);
        assert_eq!(tcp.get_destination(), 443);
        assert_eq!(tcp.get_sequence(), 123_456);
        assert_eq!(tcp.get_acknowledgement(), 0);
        assert_eq!(tcp.get_flags(), TcpFlags::SYN);
        assert_eq!(tcp.get_window(), 32_768);
    }

    #[test]
    fn reference_frame_preserves_raw_flag_bitmask() {
        let frame = generate_reference_frame(
            Ipv4Addr::new(10, 10, 1, 4),
            Ipv4Addr::new(10, 10, 1, 8),
            50000,
            22,
            TcpFlags::FIN | TcpFlags::PSH | TcpFlags::URG,
            77,
            99,
            1024,
        )
        .expect("frame");

        let ipv4 = Ipv4Packet::new(&frame).expect("ipv4");
        let tcp = TcpPacket::new(ipv4.payload()).expect("tcp");
        assert_eq!(tcp.get_flags(), TcpFlags::FIN | TcpFlags::PSH | TcpFlags::URG);
        assert_eq!(tcp.get_acknowledgement(), 99);
        assert_eq!(tcp.get_window(), 1024);
        assert_ne!(ipv4.get_checksum(), 0);
        assert_ne!(tcp.get_checksum(), 0);
    }
}

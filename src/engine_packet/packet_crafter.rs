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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(dead_code)] // Stage 1 exposes the probe catalog before scanner integration lands.
pub enum TcpAuditProbe {
    Syn,
    FirewallRuleGapIdentification,
    StatelessFilterDropPolicyValidation,
    Fin,
    IllegalRfcFlagCombinationTesting,
    FinAck,
    Custom {
        flags: u8,
        acknowledgement: u32,
    },
}

impl TcpAuditProbe {
    pub fn label(self) -> &'static str {
        match self {
            TcpAuditProbe::Syn => "syn",
            TcpAuditProbe::FirewallRuleGapIdentification => "firewall-rule-gap-identification",
            TcpAuditProbe::StatelessFilterDropPolicyValidation => {
                "stateless-filter-drop-policy-validation"
            }
            TcpAuditProbe::Fin => "fin",
            TcpAuditProbe::IllegalRfcFlagCombinationTesting => {
                "illegal-rfc-flag-combination-testing"
            }
            TcpAuditProbe::FinAck => "fin-ack",
            TcpAuditProbe::Custom { .. } => "custom",
        }
    }

    fn flags(self) -> u8 {
        match self {
            TcpAuditProbe::Syn => TcpFlags::SYN,
            TcpAuditProbe::FirewallRuleGapIdentification => TcpFlags::ACK,
            TcpAuditProbe::StatelessFilterDropPolicyValidation => 0,
            TcpAuditProbe::Fin => TcpFlags::FIN,
            TcpAuditProbe::IllegalRfcFlagCombinationTesting => {
                TcpFlags::FIN | TcpFlags::PSH | TcpFlags::URG
            }
            TcpAuditProbe::FinAck => TcpFlags::FIN | TcpFlags::ACK,
            TcpAuditProbe::Custom { flags, .. } => flags,
        }
    }

    fn acknowledgement(self) -> u32 {
        match self {
            TcpAuditProbe::FirewallRuleGapIdentification => 1,
            TcpAuditProbe::FinAck => 1,
            TcpAuditProbe::Custom { acknowledgement, .. } => acknowledgement,
            _ => 0,
        }
    }
}

// OfflineValidation / Protocol Simulation only:
// this builder intentionally writes caller-provided TCP flag and acknowledgement
// values without sanitization so fixtures, pcaps, and simulators can model
// arbitrary header states while live transmission paths remain separate.
pub fn build_raw_tcp_header(
    packet: &mut MutableTcpPacket<'_>,
    source_port: u16,
    target_port: u16,
    sequence: u32,
    acknowledgement: u32,
    flags: u8,
) {
    packet.set_source(source_port);
    packet.set_destination(target_port);
    packet.set_sequence(sequence);
    packet.set_acknowledgement(acknowledgement);
    packet.set_data_offset((TCP_HEADER_LEN / 4) as u8);
    packet.set_flags(flags);
    packet.set_window(64_240);
    packet.set_urgent_ptr(0);
}

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
            build_raw_tcp_header(
                &mut tcp_packet,
                source_port,
                0,
                0,
                0,
                TcpAuditProbe::Syn.flags(),
            );
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
        self.craft_probe(target_ip, target_port, sequence, TcpAuditProbe::Syn)
    }

    pub fn craft_probe(
        &mut self,
        target_ip: Ipv4Addr,
        target_port: u16,
        sequence: u32,
        probe: TcpAuditProbe,
    ) -> io::Result<&[u8]> {
        let mut ipv4_packet = MutableIpv4Packet::new(&mut self.buffer)
            .ok_or_else(|| io::Error::other("failed to map ipv4 packet"))?;
        ipv4_packet.set_source(self.source_ip);
        ipv4_packet.set_destination(target_ip);
        ipv4_packet.set_checksum(0);

        {
            let mut tcp_packet = MutableTcpPacket::new(ipv4_packet.payload_mut())
                .ok_or_else(|| io::Error::other("failed to map tcp packet"))?;
            build_raw_tcp_header(
                &mut tcp_packet,
                self.source_port,
                target_port,
                sequence,
                probe.acknowledgement(),
                probe.flags(),
            );
            tcp_packet.set_checksum(0);
            let checksum = ipv4_checksum(&tcp_packet.to_immutable(), &self.source_ip, &target_ip);
            tcp_packet.set_checksum(checksum);
        }

        let checksum = ipv4::checksum(&ipv4_packet.to_immutable());
        ipv4_packet.set_checksum(checksum);
        Ok(&self.buffer)
    }

    pub fn craft_firewall_rule_gap_probe(
        &mut self,
        target_ip: Ipv4Addr,
        target_port: u16,
        sequence: u32,
    ) -> io::Result<&[u8]> {
        self.craft_probe(
            target_ip,
            target_port,
            sequence,
            TcpAuditProbe::FirewallRuleGapIdentification,
        )
    }

    pub fn craft_stateless_filter_drop_probe(
        &mut self,
        target_ip: Ipv4Addr,
        target_port: u16,
        sequence: u32,
    ) -> io::Result<&[u8]> {
        self.craft_probe(
            target_ip,
            target_port,
            sequence,
            TcpAuditProbe::StatelessFilterDropPolicyValidation,
        )
    }

    #[allow(dead_code)] // Planned scanner wiring will consume this in a follow-up step.
    pub fn craft_fin(
        &mut self,
        target_ip: Ipv4Addr,
        target_port: u16,
        sequence: u32,
    ) -> io::Result<&[u8]> {
        self.craft_probe(target_ip, target_port, sequence, TcpAuditProbe::Fin)
    }

    pub fn craft_illegal_rfc_flag_probe(
        &mut self,
        target_ip: Ipv4Addr,
        target_port: u16,
        sequence: u32,
    ) -> io::Result<&[u8]> {
        self.craft_probe(
            target_ip,
            target_port,
            sequence,
            TcpAuditProbe::IllegalRfcFlagCombinationTesting,
        )
    }

    #[allow(dead_code)] // Planned scanner wiring will consume this in a follow-up step.
    pub fn craft_fin_ack(
        &mut self,
        target_ip: Ipv4Addr,
        target_port: u16,
        sequence: u32,
    ) -> io::Result<&[u8]> {
        self.craft_probe(target_ip, target_port, sequence, TcpAuditProbe::FinAck)
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
    use super::{
        build_raw_tcp_header, syn_cookie_ack_expected, syn_cookie_sequence, SynPacketCrafter,
        TcpAuditProbe, TCP_HEADER_LEN,
    };
    use pnet_packet::ipv4::Ipv4Packet;
    use pnet_packet::tcp::{MutableTcpPacket, TcpFlags, TcpPacket};
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
    fn crafter_supports_firewall_rule_gap_probe() {
        let mut crafter = SynPacketCrafter::new(Ipv4Addr::new(10, 1, 0, 5), 42000).expect("init");
        let packet = crafter
            .craft_firewall_rule_gap_probe(Ipv4Addr::new(10, 1, 0, 77), 80, 77)
            .expect("craft");

        let ipv4 = Ipv4Packet::new(packet).expect("ipv4");
        let tcp = TcpPacket::new(ipv4.payload()).expect("tcp");
        assert_eq!(tcp.get_flags(), TcpFlags::ACK);
        assert_eq!(tcp.get_acknowledgement(), 1);
    }

    #[test]
    fn crafter_supports_stateless_filter_drop_probe() {
        let mut crafter = SynPacketCrafter::new(Ipv4Addr::new(10, 1, 0, 5), 42000).expect("init");
        let packet = crafter
            .craft_stateless_filter_drop_probe(Ipv4Addr::new(10, 1, 0, 77), 80, 77)
            .expect("craft");

        let ipv4 = Ipv4Packet::new(packet).expect("ipv4");
        let tcp = TcpPacket::new(ipv4.payload()).expect("tcp");
        assert_eq!(tcp.get_flags(), 0);
        assert_eq!(tcp.get_acknowledgement(), 0);
    }

    #[test]
    fn crafter_supports_illegal_rfc_flag_probe() {
        let mut crafter = SynPacketCrafter::new(Ipv4Addr::new(10, 1, 0, 5), 42000).expect("init");
        let packet = crafter
            .craft_illegal_rfc_flag_probe(Ipv4Addr::new(10, 1, 0, 77), 80, 77)
            .expect("craft");

        let ipv4 = Ipv4Packet::new(packet).expect("ipv4");
        let tcp = TcpPacket::new(ipv4.payload()).expect("tcp");
        assert_eq!(tcp.get_flags(), TcpFlags::FIN | TcpFlags::PSH | TcpFlags::URG);
    }

    #[test]
    fn crafter_supports_custom_probe_flags() {
        let mut crafter = SynPacketCrafter::new(Ipv4Addr::new(10, 1, 0, 5), 42000).expect("init");
        let packet = crafter
            .craft_probe(
                Ipv4Addr::new(10, 1, 0, 77),
                80,
                77,
                TcpAuditProbe::Custom {
                    flags: TcpFlags::RST | TcpFlags::PSH,
                    acknowledgement: 9,
                },
            )
            .expect("craft");

        let ipv4 = Ipv4Packet::new(packet).expect("ipv4");
        let tcp = TcpPacket::new(ipv4.payload()).expect("tcp");
        assert_eq!(tcp.get_flags(), TcpFlags::RST | TcpFlags::PSH);
        assert_eq!(tcp.get_acknowledgement(), 9);
    }

    #[test]
    fn cookie_ack_matches_sequence_plus_one() {
        let seq = syn_cookie_sequence(Ipv4Addr::new(1, 2, 3, 4), 80, 99);
        let ack = syn_cookie_ack_expected(Ipv4Addr::new(1, 2, 3, 4), 80, 99);
        assert_eq!(ack, seq.wrapping_add(1));
    }

    #[test]
    fn audit_probe_labels_match_catalog_terms() {
        assert_eq!(
            TcpAuditProbe::StatelessFilterDropPolicyValidation.label(),
            "stateless-filter-drop-policy-validation"
        );
        assert_eq!(
            TcpAuditProbe::IllegalRfcFlagCombinationTesting.label(),
            "illegal-rfc-flag-combination-testing"
        );
    }

    #[test]
    fn raw_tcp_header_builder_preserves_unvalidated_inputs() {
        let mut buffer = [0u8; TCP_HEADER_LEN];
        let mut tcp = MutableTcpPacket::new(&mut buffer).expect("tcp");
        build_raw_tcp_header(
            &mut tcp,
            41000,
            8080,
            1234,
            9876,
            TcpFlags::FIN | TcpFlags::PSH | TcpFlags::URG,
        );

        let parsed = TcpPacket::new(tcp.packet()).expect("parsed tcp");
        assert_eq!(parsed.get_source(), 41000);
        assert_eq!(parsed.get_destination(), 8080);
        assert_eq!(parsed.get_sequence(), 1234);
        assert_eq!(parsed.get_acknowledgement(), 9876);
        assert_eq!(
            parsed.get_flags(),
            TcpFlags::FIN | TcpFlags::PSH | TcpFlags::URG
        );
    }

    #[test]
    fn raw_tcp_header_builder_allows_null_flag_protocol_simulation() {
        let mut buffer = [0u8; TCP_HEADER_LEN];
        let mut tcp = MutableTcpPacket::new(&mut buffer).expect("tcp");
        build_raw_tcp_header(&mut tcp, 41000, 22, 77, 0, 0);

        let parsed = TcpPacket::new(tcp.packet()).expect("parsed tcp");
        assert_eq!(parsed.get_flags(), 0);
        assert_eq!(parsed.get_acknowledgement(), 0);
    }
}

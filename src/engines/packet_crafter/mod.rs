#![allow(dead_code)]

pub mod arp_request_crafter;
pub mod icmp_echo_crafter;
pub mod tcp_ack_crafter;
pub mod tcp_syn_crafter;
pub mod tcp_syn_crafters;
pub mod udp_probe_crafter;

#[derive(Debug, Clone, Copy)]
pub struct PacketCrafterRegistry {
    pub tcp_syn: bool,
    pub tcp_ack: bool,
    pub udp_probe: bool,
    pub icmp_echo: bool,
    pub arp_request: bool,
}

impl Default for PacketCrafterRegistry {
    fn default() -> Self {
        Self {
            tcp_syn: true,
            tcp_ack: true,
            udp_probe: true,
            icmp_echo: true,
            arp_request: true,
        }
    }
}

impl PacketCrafterRegistry {
    pub fn active_count(self) -> usize {
        usize::from(self.tcp_syn)
            + usize::from(self.tcp_ack)
            + usize::from(self.udp_probe)
            + usize::from(self.icmp_echo)
            + usize::from(self.arp_request)
    }
}

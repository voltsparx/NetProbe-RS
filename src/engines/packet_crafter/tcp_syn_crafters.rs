use std::net::Ipv4Addr;

pub type TcpSynCrafter = super::tcp_syn_crafter::TcpSynCrafter;

#[inline]
pub fn stateless_syn_cookie_sequence(target_ip: Ipv4Addr, target_port: u16, seed: u64) -> u32 {
    super::tcp_syn_crafter::stateless_syn_cookie_sequence(target_ip, target_port, seed)
}

#[inline]
pub fn stateless_syn_cookie_ack_expected(target_ip: Ipv4Addr, target_port: u16, seed: u64) -> u32 {
    super::tcp_syn_crafter::stateless_syn_cookie_ack_expected(target_ip, target_port, seed)
}

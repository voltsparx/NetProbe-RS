use std::io;
use std::net::Ipv4Addr;

use crate::engine_packet::packet_crafter::{
    syn_cookie_ack_expected, syn_cookie_sequence, SynPacketCrafter,
};

#[derive(Debug)]
pub struct TcpSynCrafter {
    inner: SynPacketCrafter,
}

impl TcpSynCrafter {
    pub fn new(source_ip: Ipv4Addr, source_port: u16) -> io::Result<Self> {
        Ok(Self {
            inner: SynPacketCrafter::new(source_ip, source_port)?,
        })
    }

    pub fn craft_syn(
        &mut self,
        target_ip: Ipv4Addr,
        target_port: u16,
        sequence: u32,
    ) -> io::Result<&[u8]> {
        self.inner.craft_syn(target_ip, target_port, sequence)
    }
}

pub fn stateless_syn_cookie_sequence(target_ip: Ipv4Addr, target_port: u16, seed: u64) -> u32 {
    syn_cookie_sequence(target_ip, target_port, seed)
}

pub fn stateless_syn_cookie_ack_expected(target_ip: Ipv4Addr, target_port: u16, seed: u64) -> u32 {
    syn_cookie_ack_expected(target_ip, target_port, seed)
}

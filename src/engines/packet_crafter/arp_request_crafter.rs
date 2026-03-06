use std::io;
use std::net::Ipv4Addr;

const ARP_ETH_FRAME_LEN: usize = 42;

#[derive(Debug)]
pub struct ArpRequestCrafter {
    source_mac: [u8; 6],
    source_ip: Ipv4Addr,
    buffer: [u8; ARP_ETH_FRAME_LEN],
}

impl ArpRequestCrafter {
    pub fn new(source_mac: [u8; 6], source_ip: Ipv4Addr) -> io::Result<Self> {
        let mut buffer = [0u8; ARP_ETH_FRAME_LEN];

        // Ethernet header
        buffer[0..6].copy_from_slice(&[0xff; 6]); // broadcast
        buffer[6..12].copy_from_slice(&source_mac);
        buffer[12..14].copy_from_slice(&[0x08, 0x06]); // ARP ethertype

        // ARP payload layout
        buffer[14..16].copy_from_slice(&[0x00, 0x01]); // Ethernet
        buffer[16..18].copy_from_slice(&[0x08, 0x00]); // IPv4
        buffer[18] = 6; // MAC length
        buffer[19] = 4; // IPv4 length
        buffer[20..22].copy_from_slice(&[0x00, 0x01]); // opcode request

        Ok(Self {
            source_mac,
            source_ip,
            buffer,
        })
    }

    pub fn craft_request(&mut self, target_ip: Ipv4Addr) -> &[u8] {
        // sender hw/proto
        self.buffer[22..28].copy_from_slice(&self.source_mac);
        self.buffer[28..32].copy_from_slice(&self.source_ip.octets());
        // target hw/proto
        self.buffer[32..38].fill(0);
        self.buffer[38..42].copy_from_slice(&target_ip.octets());
        &self.buffer
    }
}

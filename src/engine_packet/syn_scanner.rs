// Raw SYN scanner foundation: TX/RX split, token-bucket pacing, and IPv4 TCP packet craft/parse.

use std::collections::BTreeMap;
use std::io;
use std::net::Ipv4Addr;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use std::thread;
use std::time::Duration;

use crossbeam_channel::bounded;
use pnet_packet::ip::IpNextHeaderProtocols;
use pnet_packet::ipv4::{self, Ipv4Packet, MutableIpv4Packet};
use pnet_packet::tcp::{ipv4_checksum, MutableTcpPacket, TcpFlags, TcpPacket};
use pnet_packet::{MutablePacket, Packet};

use crate::engine_packet::blackrock::BlackrockPermutation;
use crate::engine_packet::rate_limiter::TokenBucket;

const IPV4_HEADER_LEN: usize = 20;
const TCP_HEADER_LEN: usize = 20;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RawPortState {
    Open,
    Closed,
    Unknown,
}

#[derive(Debug, Clone, Copy)]
#[allow(dead_code)] // consumed by forthcoming orchestration/report integration
pub struct RawSynResult {
    pub ip: Ipv4Addr,
    pub port: u16,
    pub state: RawPortState,
    pub ttl: u8,
    pub flags: u8,
}

#[derive(Debug, Clone)]
pub struct RawSynScannerConfig {
    pub source_ip: Ipv4Addr,
    pub source_port: u16,
    pub rate_pps: u64,
    pub burst_size: usize,
    pub rx_grace: Duration,
    pub scan_seed: u64,
}

impl Default for RawSynScannerConfig {
    fn default() -> Self {
        Self {
            source_ip: Ipv4Addr::UNSPECIFIED,
            source_port: 40000,
            rate_pps: 10_000,
            burst_size: 256,
            rx_grace: Duration::from_millis(250),
            scan_seed: 0x4e50_5253_5343_414e,
        }
    }
}

pub trait RawTxBackend: Send + 'static {
    fn send_ipv4(&mut self, packet: &[u8], target: Ipv4Addr) -> io::Result<()>;
}

pub trait RawRxBackend: Send + 'static {
    fn recv_ipv4(&mut self, timeout: Duration) -> io::Result<Option<Vec<u8>>>;
}

#[derive(Debug, Clone)]
pub struct RawSynScanner {
    config: RawSynScannerConfig,
}

impl RawSynScanner {
    pub fn new(config: RawSynScannerConfig) -> Self {
        Self { config }
    }

    pub fn run_with_backends<TX, RX>(
        &self,
        mut tx_backend: TX,
        mut rx_backend: RX,
        targets: &[(Ipv4Addr, u16)],
    ) -> io::Result<Vec<RawSynResult>>
    where
        TX: RawTxBackend,
        RX: RawRxBackend,
    {
        if targets.is_empty() {
            return Ok(Vec::new());
        }

        let expected_source_port = self.config.source_port;
        let scan_seed = self.config.scan_seed;
        let source_ip = self.config.source_ip;
        let rate_pps = self.config.rate_pps;
        let burst_size = self.config.burst_size;
        let tx_targets = targets.to_vec();

        let (result_tx, result_rx) = bounded::<RawSynResult>(targets.len().max(64));
        let (error_tx, error_rx) = bounded::<io::Error>(4);
        let stop = Arc::new(AtomicBool::new(false));
        let tx_stop = Arc::clone(&stop);
        let rx_stop = Arc::clone(&stop);
        let tx_error = error_tx.clone();
        let rx_error = error_tx;

        let tx_thread = thread::spawn(move || {
            let mut limiter = TokenBucket::new(rate_pps, burst_size);
            let permutation = BlackrockPermutation::new(tx_targets.len(), scan_seed);

            for idx in permutation {
                if tx_stop.load(Ordering::Relaxed) {
                    break;
                }

                let (target_ip, target_port) = tx_targets[idx];
                limiter.acquire_blocking(1);

                let sequence = sequence_for(target_ip, target_port, scan_seed);
                match build_syn_ipv4_packet(
                    source_ip,
                    target_ip,
                    expected_source_port,
                    target_port,
                    sequence,
                ) {
                    Ok(packet) => {
                        if let Err(err) = tx_backend.send_ipv4(&packet, target_ip) {
                            let _ = tx_error.send(err);
                            break;
                        }
                    }
                    Err(err) => {
                        let _ = tx_error.send(err);
                        break;
                    }
                }
            }
        });

        let rx_thread = thread::spawn(move || {
            while !rx_stop.load(Ordering::Relaxed) {
                match rx_backend.recv_ipv4(Duration::from_millis(50)) {
                    Ok(Some(frame)) => {
                        if let Some(parsed) = parse_syn_response(&frame, expected_source_port) {
                            let _ = result_tx.send(parsed);
                        }
                    }
                    Ok(None) => {}
                    Err(err) => {
                        let _ = rx_error.send(err);
                        break;
                    }
                }
            }
        });

        tx_thread
            .join()
            .map_err(|_| io::Error::other("raw tx thread panicked"))?;
        thread::sleep(self.config.rx_grace);
        stop.store(true, Ordering::Relaxed);
        rx_thread
            .join()
            .map_err(|_| io::Error::other("raw rx thread panicked"))?;

        if let Ok(err) = error_rx.try_recv() {
            return Err(err);
        }

        let mut dedup = BTreeMap::<(Ipv4Addr, u16), RawSynResult>::new();
        for result in result_rx.try_iter() {
            let key = (result.ip, result.port);
            dedup
                .entry(key)
                .and_modify(|existing| {
                    if existing.state != RawPortState::Open && result.state == RawPortState::Open {
                        *existing = result;
                    }
                })
                .or_insert(result);
        }
        Ok(dedup.into_values().collect())
    }
}

pub fn build_syn_ipv4_packet(
    source_ip: Ipv4Addr,
    target_ip: Ipv4Addr,
    source_port: u16,
    target_port: u16,
    sequence: u32,
) -> io::Result<Vec<u8>> {
    build_tcp_ipv4_packet(
        source_ip,
        target_ip,
        source_port,
        target_port,
        sequence,
        0,
        TcpFlags::SYN,
    )
}

pub fn parse_syn_response(frame: &[u8], expected_source_port: u16) -> Option<RawSynResult> {
    let ipv4_packet = Ipv4Packet::new(frame)?;
    if ipv4_packet.get_next_level_protocol() != IpNextHeaderProtocols::Tcp {
        return None;
    }

    let tcp_packet = TcpPacket::new(ipv4_packet.payload())?;
    if tcp_packet.get_destination() != expected_source_port {
        return None;
    }

    let flags = tcp_packet.get_flags();
    let state = if flags & (TcpFlags::SYN | TcpFlags::ACK) == (TcpFlags::SYN | TcpFlags::ACK) {
        RawPortState::Open
    } else if flags & TcpFlags::RST == TcpFlags::RST {
        RawPortState::Closed
    } else {
        RawPortState::Unknown
    };

    Some(RawSynResult {
        ip: ipv4_packet.get_source(),
        port: tcp_packet.get_source(),
        state,
        ttl: ipv4_packet.get_ttl(),
        flags,
    })
}

fn build_tcp_ipv4_packet(
    source_ip: Ipv4Addr,
    target_ip: Ipv4Addr,
    source_port: u16,
    target_port: u16,
    sequence: u32,
    acknowledgement: u32,
    flags: u8,
) -> io::Result<Vec<u8>> {
    let mut buffer = vec![0u8; IPV4_HEADER_LEN + TCP_HEADER_LEN];
    let mut ipv4_packet = MutableIpv4Packet::new(&mut buffer)
        .ok_or_else(|| io::Error::other("failed to allocate ipv4 packet"))?;

    ipv4_packet.set_version(4);
    ipv4_packet.set_header_length((IPV4_HEADER_LEN / 4) as u8);
    ipv4_packet.set_total_length((IPV4_HEADER_LEN + TCP_HEADER_LEN) as u16);
    ipv4_packet.set_ttl(64);
    ipv4_packet.set_next_level_protocol(IpNextHeaderProtocols::Tcp);
    ipv4_packet.set_source(source_ip);
    ipv4_packet.set_destination(target_ip);

    {
        let mut tcp_packet = MutableTcpPacket::new(ipv4_packet.payload_mut())
            .ok_or_else(|| io::Error::other("failed to allocate tcp packet"))?;
        tcp_packet.set_source(source_port);
        tcp_packet.set_destination(target_port);
        tcp_packet.set_sequence(sequence);
        tcp_packet.set_acknowledgement(acknowledgement);
        tcp_packet.set_data_offset((TCP_HEADER_LEN / 4) as u8);
        tcp_packet.set_flags(flags);
        tcp_packet.set_window(64_240);
        tcp_packet.set_urgent_ptr(0);
        let checksum = ipv4_checksum(&tcp_packet.to_immutable(), &source_ip, &target_ip);
        tcp_packet.set_checksum(checksum);
    }

    let checksum = ipv4::checksum(&ipv4_packet.to_immutable());
    ipv4_packet.set_checksum(checksum);

    Ok(buffer)
}

fn sequence_for(target_ip: Ipv4Addr, target_port: u16, seed: u64) -> u32 {
    let mut value = seed ^ 0xcbf2_9ce4_8422_2325;
    for byte in target_ip.octets() {
        value ^= byte as u64;
        value = value.wrapping_mul(0x0000_0100_0000_01b3);
    }
    value ^= target_port as u64;
    value = value.wrapping_mul(0x0000_0100_0000_01b3);
    (value as u32).wrapping_add(((value >> 32) as u32).rotate_left(13))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;
    use std::sync::{Arc, Mutex};
    use std::time::Instant;

    #[derive(Clone)]
    struct MockTxBackend {
        responses: Arc<Mutex<VecDeque<Vec<u8>>>>,
    }

    impl RawTxBackend for MockTxBackend {
        fn send_ipv4(&mut self, packet: &[u8], _target: Ipv4Addr) -> io::Result<()> {
            let ipv4 = Ipv4Packet::new(packet)
                .ok_or_else(|| io::Error::other("invalid tx ipv4 packet"))?;
            let tcp = TcpPacket::new(ipv4.payload())
                .ok_or_else(|| io::Error::other("invalid tx tcp packet"))?;

            let target_port = tcp.get_destination();
            let response_flags = if target_port % 2 == 0 {
                TcpFlags::SYN | TcpFlags::ACK
            } else {
                TcpFlags::RST | TcpFlags::ACK
            };

            let response = build_tcp_ipv4_packet(
                ipv4.get_destination(),
                ipv4.get_source(),
                target_port,
                tcp.get_source(),
                100,
                tcp.get_sequence().wrapping_add(1),
                response_flags,
            )?;
            self.responses
                .lock()
                .map_err(|_| io::Error::other("response queue poisoned"))?
                .push_back(response);
            Ok(())
        }
    }

    #[derive(Clone)]
    struct MockRxBackend {
        responses: Arc<Mutex<VecDeque<Vec<u8>>>>,
    }

    impl RawRxBackend for MockRxBackend {
        fn recv_ipv4(&mut self, timeout: Duration) -> io::Result<Option<Vec<u8>>> {
            let started = Instant::now();
            loop {
                if let Some(frame) = self
                    .responses
                    .lock()
                    .map_err(|_| io::Error::other("response queue poisoned"))?
                    .pop_front()
                {
                    return Ok(Some(frame));
                }

                if started.elapsed() >= timeout {
                    return Ok(None);
                }
                thread::sleep(Duration::from_millis(1));
            }
        }
    }

    #[test]
    fn build_packet_sets_syn_flag() {
        let packet = build_syn_ipv4_packet(
            Ipv4Addr::new(10, 0, 0, 1),
            Ipv4Addr::new(10, 0, 0, 2),
            44000,
            443,
            12345,
        )
        .expect("packet should build");

        let ipv4 = Ipv4Packet::new(&packet).expect("ipv4");
        let tcp = TcpPacket::new(ipv4.payload()).expect("tcp");
        assert_eq!(tcp.get_flags(), TcpFlags::SYN);
    }

    #[test]
    fn parse_response_recognizes_open_and_closed() {
        let open_packet = build_tcp_ipv4_packet(
            Ipv4Addr::new(1, 1, 1, 1),
            Ipv4Addr::new(2, 2, 2, 2),
            80,
            40000,
            7,
            1,
            TcpFlags::SYN | TcpFlags::ACK,
        )
        .expect("open packet");
        let closed_packet = build_tcp_ipv4_packet(
            Ipv4Addr::new(1, 1, 1, 1),
            Ipv4Addr::new(2, 2, 2, 2),
            81,
            40000,
            7,
            1,
            TcpFlags::RST | TcpFlags::ACK,
        )
        .expect("closed packet");

        let open = parse_syn_response(&open_packet, 40000).expect("open parsed");
        let closed = parse_syn_response(&closed_packet, 40000).expect("closed parsed");
        assert_eq!(open.state, RawPortState::Open);
        assert_eq!(closed.state, RawPortState::Closed);
    }

    #[test]
    fn tx_rx_split_returns_deduped_results() {
        let responses = Arc::new(Mutex::new(VecDeque::new()));
        let tx = MockTxBackend {
            responses: Arc::clone(&responses),
        };
        let rx = MockRxBackend { responses };

        let scanner = RawSynScanner::new(RawSynScannerConfig {
            source_ip: Ipv4Addr::new(10, 0, 0, 5),
            source_port: 40000,
            rate_pps: 1000,
            burst_size: 16,
            rx_grace: Duration::from_millis(40),
            scan_seed: 123,
        });

        let results = scanner
            .run_with_backends(
                tx,
                rx,
                &[
                    (Ipv4Addr::new(10, 0, 0, 10), 80),
                    (Ipv4Addr::new(10, 0, 0, 10), 81),
                    (Ipv4Addr::new(10, 0, 0, 10), 82),
                    (Ipv4Addr::new(10, 0, 0, 10), 80),
                ],
            )
            .expect("scan should succeed");

        let open_count = results
            .iter()
            .filter(|value| value.state == RawPortState::Open)
            .count();
        let closed_count = results
            .iter()
            .filter(|value| value.state == RawPortState::Closed)
            .count();
        assert!(open_count >= 2);
        assert!(closed_count >= 1);
    }
}

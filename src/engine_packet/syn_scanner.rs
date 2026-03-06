// Raw SYN scanner foundation: TX/RX split, token-bucket pacing, and IPv4 TCP packet craft/parse.

use std::collections::HashMap;
use std::io;
use std::net::Ipv4Addr;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use std::thread;
use std::time::Duration;

use crossbeam_queue::ArrayQueue;
use pnet_packet::ip::IpNextHeaderProtocols;
use pnet_packet::ipv4::Ipv4Packet;
use pnet_packet::tcp::{TcpFlags, TcpPacket};
use pnet_packet::Packet;

#[cfg(test)]
use pnet_packet::ipv4::{self, MutableIpv4Packet};
#[cfg(test)]
use pnet_packet::tcp::{ipv4_checksum, MutableTcpPacket};
#[cfg(test)]
use pnet_packet::MutablePacket;

use crate::engine_packet::blackrock::BlackrockPermutation;
use crate::engine_packet::rate_limiter::{AdaptiveThrottler, TokenBucket};
use crate::engines::packet_crafter::tcp_syn_crafter::{
    stateless_syn_cookie_ack_expected, stateless_syn_cookie_sequence, TcpSynCrafter,
};

#[cfg(test)]
const IPV4_HEADER_LEN: usize = 20;
#[cfg(test)]
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
    pub tx_workers: usize,
    pub tx_batch_size: usize,
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
            tx_workers: 1,
            tx_batch_size: 32,
            rx_grace: Duration::from_millis(250),
            scan_seed: 0x4e50_5253_5343_414e,
        }
    }
}

pub trait RawTxBackend: Send + 'static {
    fn send_ipv4(&mut self, packet: &[u8], target: Ipv4Addr) -> io::Result<()>;
}

pub trait RawRxBackend: Send + 'static {
    fn recv_ipv4(&mut self, timeout: Duration) -> io::Result<Option<&[u8]>>;
}

#[derive(Debug, Clone)]
pub struct RawSynScanner {
    config: RawSynScannerConfig,
}

impl RawSynScanner {
    pub fn new(config: RawSynScannerConfig) -> Self {
        Self { config }
    }

    pub fn effective_tx_workers(&self, target_count: usize) -> usize {
        let mut workers = self.config.tx_workers.max(1).min(target_count.max(1));
        if self.config.rate_pps > 0 {
            workers = workers.min(self.config.rate_pps as usize);
        }
        workers.max(1)
    }

    #[cfg_attr(not(test), allow(dead_code))]
    pub fn run_with_backends<TX, RX>(
        &self,
        tx_backend: TX,
        rx_backend: RX,
        targets: &[(Ipv4Addr, u16)],
    ) -> io::Result<Vec<RawSynResult>>
    where
        TX: RawTxBackend,
        RX: RawRxBackend,
    {
        self.run_with_tx_backends(vec![Box::new(tx_backend)], rx_backend, targets)
    }

    pub fn run_with_tx_factory<RX, F>(
        &self,
        mut tx_factory: F,
        rx_backend: RX,
        targets: &[(Ipv4Addr, u16)],
    ) -> io::Result<Vec<RawSynResult>>
    where
        RX: RawRxBackend,
        F: FnMut(usize) -> io::Result<Box<dyn RawTxBackend>>,
    {
        if targets.is_empty() {
            return Ok(Vec::new());
        }

        let workers = self.effective_tx_workers(targets.len());
        let mut tx_backends = Vec::<Box<dyn RawTxBackend>>::with_capacity(workers);
        for worker_id in 0..workers {
            tx_backends.push(tx_factory(worker_id)?);
        }

        self.run_with_tx_backends(tx_backends, rx_backend, targets)
    }

    fn run_with_tx_backends<RX>(
        &self,
        tx_backends: Vec<Box<dyn RawTxBackend>>,
        mut rx_backend: RX,
        targets: &[(Ipv4Addr, u16)],
    ) -> io::Result<Vec<RawSynResult>>
    where
        RX: RawRxBackend,
    {
        if targets.is_empty() {
            return Ok(Vec::new());
        }
        if tx_backends.is_empty() {
            return Err(io::Error::other("no tx backends provided"));
        }

        let expected_source_port = self.config.source_port;
        let scan_seed = self.config.scan_seed;
        let source_ip = self.config.source_ip;
        let rate_pps = self.config.rate_pps;
        let burst_size = self.config.burst_size.max(1);
        let tx_batch_size = self.config.tx_batch_size.max(1) as u64;
        let worker_count = tx_backends.len().min(targets.len().max(1));
        let tx_targets = Arc::new(targets.to_vec());
        let permutation = Arc::new(BlackrockPermutation::new(tx_targets.len(), scan_seed));

        let result_capacity = targets.len().saturating_mul(2).clamp(256, 262_144);
        let result_queue = Arc::new(ArrayQueue::<RawSynResult>::new(result_capacity));
        let error_queue = Arc::new(ArrayQueue::<io::Error>::new(worker_count.saturating_add(8)));
        let stop = Arc::new(AtomicBool::new(false));
        let rx_stop = Arc::clone(&stop);
        let rx_result_queue = Arc::clone(&result_queue);
        let rx_error_queue = Arc::clone(&error_queue);

        let rx_thread = thread::spawn(move || {
            while !rx_stop.load(Ordering::Relaxed) {
                match rx_backend.recv_ipv4(Duration::from_millis(50)) {
                    Ok(Some(frame)) => {
                        if let Some(parsed) =
                            parse_syn_response_with_cookie(frame, expected_source_port, scan_seed)
                        {
                            let _ = push_lock_free(&rx_result_queue, parsed, &rx_stop);
                        }
                    }
                    Ok(None) => {}
                    Err(err) => {
                        let _ = push_lock_free(&rx_error_queue, err, &rx_stop);
                        break;
                    }
                }
            }
        });

        let mut tx_threads = Vec::with_capacity(worker_count);
        for (worker_id, mut tx_backend) in tx_backends.into_iter().enumerate() {
            let tx_stop = Arc::clone(&stop);
            let tx_error_queue = Arc::clone(&error_queue);
            let tx_targets = Arc::clone(&tx_targets);
            let permutation = Arc::clone(&permutation);
            let worker_rate = split_u64(rate_pps, worker_count, worker_id);
            let worker_burst = split_usize(burst_size, worker_count, worker_id).max(1);

            let handle = thread::spawn(move || {
                let mut limiter = TokenBucket::new(worker_rate, worker_burst);
                let mut throttler = AdaptiveThrottler::new(worker_rate);
                let max_batch = tx_batch_size.max(1);
                let mut crafter = match TcpSynCrafter::new(source_ip, expected_source_port) {
                    Ok(value) => value,
                    Err(err) => {
                        tx_stop.store(true, Ordering::Relaxed);
                        let _ = push_lock_free(&tx_error_queue, err, &tx_stop);
                        return;
                    }
                };

                let mut logical_index = worker_id;
                let mut sent_packets = 0u64;
                while logical_index < tx_targets.len() {
                    if tx_stop.load(Ordering::Relaxed) {
                        break;
                    }

                    let adaptive_batch = throttler.next_batch(sent_packets, max_batch);
                    let permits = limiter.acquire_batch_blocking(adaptive_batch);
                    let mut dispatched = 0u64;
                    while dispatched < permits {
                        if logical_index >= tx_targets.len() || tx_stop.load(Ordering::Relaxed) {
                            break;
                        }

                        let permuted = permutation.at(logical_index);
                        logical_index = logical_index.saturating_add(worker_count);
                        let (target_ip, target_port) = tx_targets[permuted];
                        let sequence =
                            stateless_syn_cookie_sequence(target_ip, target_port, scan_seed);

                        match crafter.craft_syn(target_ip, target_port, sequence) {
                            Ok(packet) => {
                                if let Err(err) = tx_backend.send_ipv4(packet, target_ip) {
                                    tx_stop.store(true, Ordering::Relaxed);
                                    let _ = push_lock_free(&tx_error_queue, err, &tx_stop);
                                    return;
                                }
                            }
                            Err(err) => {
                                tx_stop.store(true, Ordering::Relaxed);
                                let _ = push_lock_free(&tx_error_queue, err, &tx_stop);
                                return;
                            }
                        }

                        dispatched += 1;
                        sent_packets = sent_packets.saturating_add(1);
                    }
                }
            });
            tx_threads.push(handle);
        }

        for handle in tx_threads {
            handle
                .join()
                .map_err(|_| io::Error::other("raw tx thread panicked"))?;
        }

        thread::sleep(self.config.rx_grace);
        stop.store(true, Ordering::Relaxed);
        rx_thread
            .join()
            .map_err(|_| io::Error::other("raw rx thread panicked"))?;

        if let Some(err) = error_queue.pop() {
            return Err(err);
        }

        let mut dedup = HashMap::<(Ipv4Addr, u16), RawSynResult>::with_capacity(targets.len());
        while let Some(result) = result_queue.pop() {
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
        let mut values = dedup.into_values().collect::<Vec<_>>();
        values.sort_unstable_by_key(|value| (u32::from(value.ip), value.port));
        Ok(values)
    }
}

fn split_u64(total: u64, workers: usize, worker_idx: usize) -> u64 {
    if workers <= 1 {
        return total;
    }

    let base = total / workers as u64;
    let extra = (worker_idx < (total % workers as u64) as usize) as u64;
    base + extra
}

fn split_usize(total: usize, workers: usize, worker_idx: usize) -> usize {
    if workers <= 1 {
        return total;
    }

    let base = total / workers;
    let extra = usize::from(worker_idx < (total % workers));
    base + extra
}

fn push_lock_free<T>(queue: &ArrayQueue<T>, item: T, stop: &AtomicBool) -> bool {
    let mut pending = item;
    loop {
        match queue.push(pending) {
            Ok(()) => return true,
            Err(value) => {
                if stop.load(Ordering::Relaxed) {
                    return false;
                }
                pending = value;
                thread::yield_now();
            }
        }
    }
}

#[cfg(test)]
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

#[cfg(test)]
pub fn parse_syn_response(frame: &[u8], expected_source_port: u16) -> Option<RawSynResult> {
    parse_syn_response_impl(frame, expected_source_port, None)
}

pub fn parse_syn_response_with_cookie(
    frame: &[u8],
    expected_source_port: u16,
    scan_seed: u64,
) -> Option<RawSynResult> {
    parse_syn_response_impl(frame, expected_source_port, Some(scan_seed))
}

fn parse_syn_response_impl(
    frame: &[u8],
    expected_source_port: u16,
    scan_seed: Option<u64>,
) -> Option<RawSynResult> {
    let ipv4_packet = Ipv4Packet::new(frame)?;
    if ipv4_packet.get_next_level_protocol() != IpNextHeaderProtocols::Tcp {
        return None;
    }

    let tcp_packet = TcpPacket::new(ipv4_packet.payload())?;
    if tcp_packet.get_destination() != expected_source_port {
        return None;
    }

    let flags = tcp_packet.get_flags();
    if let Some(seed) = scan_seed {
        if flags & TcpFlags::ACK == TcpFlags::ACK {
            let expected_ack = stateless_syn_cookie_ack_expected(
                ipv4_packet.get_source(),
                tcp_packet.get_source(),
                seed,
            );
            if tcp_packet.get_acknowledgement() != expected_ack {
                return None;
            }
        } else if flags & (TcpFlags::SYN | TcpFlags::RST) != 0 {
            // If this looks like a reply to SYN but has no ACK, ignore as unrelated/noisy traffic.
            return None;
        }
    }

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

#[cfg(test)]
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
        current_frame: Option<Vec<u8>>,
    }

    impl RawRxBackend for MockRxBackend {
        fn recv_ipv4(&mut self, timeout: Duration) -> io::Result<Option<&[u8]>> {
            let started = Instant::now();
            loop {
                if let Some(frame) = self
                    .responses
                    .lock()
                    .map_err(|_| io::Error::other("response queue poisoned"))?
                    .pop_front()
                {
                    self.current_frame = Some(frame);
                    return Ok(self.current_frame.as_deref());
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
    fn parse_response_with_cookie_rejects_bad_ack() {
        let seed = 12345;
        let src = Ipv4Addr::new(8, 8, 8, 8);
        let dst = Ipv4Addr::new(10, 0, 0, 7);
        let port = 443;
        let expected_ack = stateless_syn_cookie_ack_expected(src, port, seed);

        let valid = build_tcp_ipv4_packet(
            src,
            dst,
            port,
            40000,
            1,
            expected_ack,
            TcpFlags::SYN | TcpFlags::ACK,
        )
        .expect("valid packet");
        let invalid = build_tcp_ipv4_packet(
            src,
            dst,
            port,
            40000,
            1,
            expected_ack.wrapping_add(5),
            TcpFlags::SYN | TcpFlags::ACK,
        )
        .expect("invalid packet");

        assert!(parse_syn_response_with_cookie(&valid, 40000, seed).is_some());
        assert!(parse_syn_response_with_cookie(&invalid, 40000, seed).is_none());
    }

    #[test]
    fn tx_rx_split_returns_deduped_results() {
        let responses = Arc::new(Mutex::new(VecDeque::new()));
        let tx = MockTxBackend {
            responses: Arc::clone(&responses),
        };
        let rx = MockRxBackend {
            responses,
            current_frame: None,
        };

        let scanner = RawSynScanner::new(RawSynScannerConfig {
            source_ip: Ipv4Addr::new(10, 0, 0, 5),
            source_port: 40000,
            rate_pps: 1000,
            burst_size: 16,
            tx_workers: 1,
            tx_batch_size: 8,
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

    #[test]
    fn tx_factory_parallel_workers_return_results() {
        let responses = Arc::new(Mutex::new(VecDeque::new()));
        let rx = MockRxBackend {
            responses: Arc::clone(&responses),
            current_frame: None,
        };
        let tx_responses = Arc::clone(&responses);

        let scanner = RawSynScanner::new(RawSynScannerConfig {
            source_ip: Ipv4Addr::new(10, 0, 0, 5),
            source_port: 40000,
            rate_pps: 8000,
            burst_size: 64,
            tx_workers: 4,
            tx_batch_size: 16,
            rx_grace: Duration::from_millis(40),
            scan_seed: 321,
        });

        let results = scanner
            .run_with_tx_factory(
                move |_| {
                    Ok(Box::new(MockTxBackend {
                        responses: Arc::clone(&tx_responses),
                    }) as Box<dyn RawTxBackend>)
                },
                rx,
                &[
                    (Ipv4Addr::new(10, 0, 0, 10), 80),
                    (Ipv4Addr::new(10, 0, 0, 10), 81),
                    (Ipv4Addr::new(10, 0, 0, 10), 82),
                    (Ipv4Addr::new(10, 0, 0, 10), 83),
                    (Ipv4Addr::new(10, 0, 0, 10), 84),
                    (Ipv4Addr::new(10, 0, 0, 10), 85),
                ],
            )
            .expect("scan should succeed");

        assert!(results
            .iter()
            .any(|value| value.state == RawPortState::Open));
        assert!(results
            .iter()
            .any(|value| value.state == RawPortState::Closed));
    }
}

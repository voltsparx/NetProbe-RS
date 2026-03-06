// OS raw-socket backend for the packet engine.

use std::io;
use std::io::ErrorKind;
use std::mem::MaybeUninit;
use std::net::{Ipv4Addr, SocketAddrV4};
use std::time::Duration;

use socket2::{Domain, Protocol, SockAddr, Socket, Type};

use crate::engine_packet::syn_scanner::{RawRxBackend, RawTxBackend};

#[derive(Debug)]
pub struct RawSocketTx {
    socket: Socket,
}

#[derive(Debug)]
pub struct RawSocketRx {
    socket: Socket,
    buffer: Vec<MaybeUninit<u8>>,
    read_timeout: Option<Duration>,
}

impl RawSocketTx {
    pub fn new(source_ip: Ipv4Addr) -> io::Result<Self> {
        let socket = Socket::new(Domain::IPV4, Type::from(3), Some(Protocol::TCP))?;
        socket.bind(&SockAddr::from(SocketAddrV4::new(source_ip, 0)))?;
        let _ = socket.set_send_buffer_size(8 * 1024 * 1024);
        Ok(Self { socket })
    }
}

impl RawTxBackend for RawSocketTx {
    fn send_ipv4(&mut self, packet: &[u8], target: Ipv4Addr) -> io::Result<()> {
        self.socket
            .send_to(packet, &SockAddr::from(SocketAddrV4::new(target, 0)))
            .map(|_| ())
    }
}

impl RawSocketRx {
    pub fn new(bind_ip: Ipv4Addr) -> io::Result<Self> {
        let socket = Socket::new(Domain::IPV4, Type::from(3), Some(Protocol::TCP))?;
        socket.bind(&SockAddr::from(SocketAddrV4::new(bind_ip, 0)))?;
        let _ = socket.set_recv_buffer_size(16 * 1024 * 1024);
        Ok(Self {
            socket,
            buffer: vec![MaybeUninit::<u8>::uninit(); 65_535],
            read_timeout: None,
        })
    }
}

impl RawRxBackend for RawSocketRx {
    fn recv_ipv4(&mut self, timeout: Duration) -> io::Result<Option<&[u8]>> {
        if self.read_timeout != Some(timeout) {
            self.socket.set_read_timeout(Some(timeout))?;
            self.read_timeout = Some(timeout);
        }

        match self.socket.recv(&mut self.buffer) {
            Ok(read) => {
                if read == 0 {
                    Ok(None)
                } else {
                    // SAFETY: `recv` initialized the first `read` bytes in `self.buffer`.
                    let frame = unsafe {
                        std::slice::from_raw_parts(self.buffer.as_ptr() as *const u8, read)
                    };
                    Ok(Some(frame))
                }
            }
            Err(err)
                if err.kind() == ErrorKind::TimedOut
                    || err.kind() == ErrorKind::WouldBlock
                    || err.kind() == ErrorKind::Interrupted =>
            {
                Ok(None)
            }
            Err(err) => Err(err),
        }
    }
}

// AF_XDP backend scaffold for zero-copy TX/RX.
//
// This module provides an integration point for kernel-bypass packet I/O.
// The current implementation intentionally returns `Unsupported` until
// UMEM/XSK ring plumbing is wired with libxdp-sys/aya.

#[cfg(all(target_os = "linux", feature = "afxdp"))]
mod imp {
    use std::io;
    use std::io::ErrorKind;
    use std::net::Ipv4Addr;
    use std::time::Duration;

    use crate::engine_packet::syn_scanner::{RawRxBackend, RawTxBackend};

    #[derive(Debug)]
    pub struct AfxdpRawTx;

    #[derive(Debug, Default)]
    pub struct AfxdpRawRx;

    pub fn open_afxdp_backends(
        _source_ip: Ipv4Addr,
        _target_ip: Ipv4Addr,
    ) -> io::Result<(AfxdpRawTx, AfxdpRawRx)> {
        Err(io::Error::new(
            ErrorKind::Unsupported,
            "AF_XDP feature enabled, but UMEM/XSK wiring is not implemented yet. \
             Integrate libxdp-sys or aya and attach an XDP program to enable zero-copy packet I/O.",
        ))
    }

    impl RawTxBackend for AfxdpRawTx {
        fn send_ipv4(&mut self, _packet: &[u8], _target: Ipv4Addr) -> io::Result<()> {
            Err(io::Error::new(
                ErrorKind::Unsupported,
                "AF_XDP TX backend not initialized",
            ))
        }
    }

    impl RawRxBackend for AfxdpRawRx {
        fn recv_ipv4(&mut self, _timeout: Duration) -> io::Result<Option<&[u8]>> {
            Ok(None)
        }
    }
}

#[cfg(not(all(target_os = "linux", feature = "afxdp")))]
mod imp {
    use std::io;
    use std::io::ErrorKind;
    use std::net::Ipv4Addr;
    use std::time::Duration;

    use crate::engine_packet::syn_scanner::{RawRxBackend, RawTxBackend};

    #[derive(Debug)]
    pub struct AfxdpRawTx;

    #[derive(Debug, Default)]
    pub struct AfxdpRawRx;

    pub fn open_afxdp_backends(
        _source_ip: Ipv4Addr,
        _target_ip: Ipv4Addr,
    ) -> io::Result<(AfxdpRawTx, AfxdpRawRx)> {
        Err(io::Error::new(
            ErrorKind::Unsupported,
            "AF_XDP backend unavailable (requires linux + --features afxdp)",
        ))
    }

    impl RawTxBackend for AfxdpRawTx {
        fn send_ipv4(&mut self, _packet: &[u8], _target: Ipv4Addr) -> io::Result<()> {
            Err(io::Error::new(
                ErrorKind::Unsupported,
                "AF_XDP TX backend unavailable on this build",
            ))
        }
    }

    impl RawRxBackend for AfxdpRawRx {
        fn recv_ipv4(&mut self, _timeout: Duration) -> io::Result<Option<&[u8]>> {
            Ok(None)
        }
    }
}

pub use imp::open_afxdp_backends;

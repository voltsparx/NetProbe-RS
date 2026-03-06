// Packet engine foundation: deterministic ordering, rate pacing, and raw SYN scanning primitives.

pub mod arp;
pub mod blackrock;
pub mod port_scan;
pub mod rate_limiter;
pub mod socket_backend;
pub mod syn_scanner;

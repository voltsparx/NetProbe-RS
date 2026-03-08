// Packet engine foundation: deterministic ordering, rate pacing, and raw SYN scanning primitives.

pub mod afxdp_backend;
pub mod arp;
pub mod audit_fixture_generator;
pub mod blackrock;
pub mod datalink_backend;
pub mod intelligence_pipeline;
pub mod packet_crafter;
pub mod port_scan;
pub mod rate_limiter;
pub mod socket_backend;
pub mod syn_scanner;

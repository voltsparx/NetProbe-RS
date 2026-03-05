// Flow sketch: host target -> task pipeline -> enriched host result
// Pseudo-block:
//   read input -> process safely -> return deterministic output

pub mod analysis;
pub mod dns_lookup;
pub mod port_scan;
pub mod reporting;

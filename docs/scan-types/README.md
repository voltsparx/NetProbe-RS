# Scan Type Pages

This directory gives every framework scan type and combo recipe its own file.

Use it with:

- `nprobe-rs --scan-type`
- `nprobe-rs --scan-type <name>`

Status labels:

- `implemented`: live runtime path exists
- `partial`: some engine or data-plane support exists, but not a dedicated top-level lane
- `planned`: cataloged in the framework inventory, not yet a live engine

Core types:

- `arp`
- `icmp-echo`
- `tcp-ping`
- `connect`
- `syn`
- `udp`
- `ack`
- `ip-protocol`
- `sctp-init`
- `banner`
- `os-fingerprint`
- `hybrid`
- `phantom`
- `kis`
- `sar`
- `tbns`
- `idf`
- `mirror`
- `callback-ping`

Combo recipes:

- `kinetic-fingerprint`
- `sovereign-callback`

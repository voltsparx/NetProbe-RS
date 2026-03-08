# Intel-Source Capability Map

This document maps the major tool families under `intel-source/` into NProbe-RS platform domains.

It does not mean "copy every behavior exactly".
It means NProbe-RS should cover the useful framework-level capabilities those tools represent.

## Tool families seen under `intel-source/`

- `masscan`
- `nmap`
- `ipscan`
- `librenms`
- `nagioscore`
- `openvas-scanner`

## Safe capability mapping

### `masscan`

- High-speed asynchronous discovery
- TX/RX separation
- rate governance and adaptive stabilizer logic
- randomized traversal and low-memory scheduling

### `nmap`

- service fingerprint databases
- passive `nmap-os-db` correlation for host OS/profile hints
- explainable multi-format reporting
- scan profiles and engine selection
- controlled scripting and enrichment

### `ipscan`

- fetcher/plugin style enrichment chains
- operator-friendly workflow
- saved-run comparison and drift review

### `librenms`

- SNMP inventory and device enrichment
- topology and relationship modeling
- long-lived network observability direction

### `nagioscore`

- scheduled checks
- health-state thinking
- resilient orchestration and worker supervision

### `openvas-scanner`

- feed-oriented knowledge architecture
- daemon/API control plane concepts
- policy-driven findings correlation

## What NProbe-RS should include

- discovery engines
- intelligence and enrichment engines
- safety/stabilizer systems
- persistence and resume
- plugin and script boundaries
- monitoring/inventory direction
- teaching-first output and explanation
- platform metadata describing current parity

## What NProbe-RS should not absorb by default

- intrusive exploit-style checks
- privileged remote execution helpers
- unsafe vulnerability test execution pipelines

Those areas are intentionally excluded from the default framework scope.

## Current implementation direction

- capability parity is summarized in scan metadata
- host safety/profile decisions are part of the report model
- passive OS/profile hints now draw from `nmap-os-db` without claiming active OS-scan parity
- async and packet paths both apply device-aware safety policy
- checkpoint/resume already exists and should evolve into durable persistence

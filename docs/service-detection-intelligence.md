# Service Detection Intelligence

NProbe-RS now keeps its service-detection path inside the project. It does not require an external Nmap installation at runtime.

## Where Nmap service detection lives

Bundled reference sources in this repo:

- `intel-source/nmap/nmap-service-probes`
- `intel-source/nmap/nmap-services`
- `intel-source/nmap/service_scan.cc`
- `intel-source/nmap/service_scan.h`
- `intel-source/nmap/scripts/`
- `intel-source/nmap/nselib/`

Those files show the main Nmap pattern:

1. Port map seed from `nmap-services`
2. Probe payload database from `nmap-service-probes`
3. Regex-based match rules with product, version, info, hostname, OS, device type, and CPE metadata
4. Follow-on script ecosystem for deeper checks

## Where NProbe-RS now does the same class of work

- Port map loading: `src/service_db.rs`
- Probe and match database loading: `src/fingerprint_db.rs`
- Async detection path: `src/engine_async/scanner.rs`
- Packet-stage follow-up path: `src/engine_packet/intelligence_pipeline.rs`
- Defensive service intelligence layer: `src/reporter/service_intelligence.rs`
- Service knowledge subsystem: `src/reporter/service_knowledge/`
- Explanations and reporting: `src/reporter/reasoning.rs`, `src/output/`

## What NProbe-RS now carries through

For each detected service, NProbe-RS can now keep:

- service name
- product
- version
- info string
- hostname hint
- OS hint
- device type
- CPE list
- detection source
- confidence
- defensive exposure hints

It also has a native advisory layer inside the framework:

- CPE-prefix matching for common software and appliance families
- product and service keyword advisory matching
- defensive remediation guidance tied to the detected identity
- learner notes that explain why that service identity matters

Main native knowledge modules:

- `src/reporter/service_intelligence.rs`
- `src/reporter/service_knowledge/`
- `src/reporter/advisory_catalog.rs`

## Architecture

The service stack now uses a dual-plane model:

- `host_snapshots` keeps compact per-host service summary counts and a summary JSON blob
- `service_snapshots` keeps one durable record per detected service instance
- `actionable_snapshots` keeps severity-labeled issue/action pairs for historical comparison

Detailed architecture doc:

- [Service Knowledge Architecture](service-knowledge-architecture.md)

## Design boundary

NProbe-RS uses this intelligence for:

- identification
- safer classification
- defensive advice
- learning output
- asset and exposure mapping

It does not use this default path for intrusive exploit-style validation.

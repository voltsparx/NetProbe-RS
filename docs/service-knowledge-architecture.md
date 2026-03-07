# Service Knowledge Architecture

NProbe-RS now uses a dual-plane service intelligence architecture with a parallel actionable-findings layer.

## Why this shape

Typical scanners either:

- keep service identity only in transient memory, or
- dump everything into one host JSON payload

NProbe-RS now splits that into two useful planes:

1. `Host runtime plane`
- current host state
- risk score
- phantom device-check data
- compact service knowledge summary counts
- compact actionable summary counts by severity

2. `Service knowledge plane`
- one record per `(session_id, ip, port, protocol)`
- service label and match source
- identity metadata: product, version, hostname, OS hint, device type
- CPE evidence
- exposure hints
- defensive observations
- remediation advice
- learner notes

3. `Actionable findings plane`
- one record per defensible issue/action pair on a host
- typed severity: `critical`, `high`, `moderate`, `review`
- issue statement in plain language
- recommended next action in plain language

This is less common than a flat report model, but more effective for a defensive platform because it keeps scans explainable and historically comparable.

## Code layout

Runtime and analysis:

- `src/reporter/actionable.rs`
- `src/reporter/service_knowledge/mod.rs`
- `src/reporter/service_knowledge/identity.rs`
- `src/reporter/service_knowledge/signals.rs`
- `src/reporter/service_intelligence.rs`

Persistence:

- `src/platform/sql_persistence.rs`
- `migrations/001_persistence.sql`

Knowledge inputs:

- `src/reporter/advisory_catalog.rs`
- `src/fingerprint_db.rs`
- `src/service_db.rs`
- `intel-source/nmap/nmap-service-probes`
- `intel-source/nmap/nmap-services`

## Flow

1. Scan engines identify likely services.
2. `service_knowledge::annotate_ports()` enriches ports with identity and low-impact exposure hints.
3. `service_knowledge::analyze_host()` turns port evidence into host insights, advice, and learning notes.
4. SQL persistence stores:
- a compact per-host summary in `host_snapshots`
- detailed per-service records in `service_snapshots`
- severity-labeled issue/action records in `actionable_snapshots`

## Why this is effective

- reports stay readable
- history can compare services across scans
- history can compare what got worse, what was fixed, and which actions were recommended
- service intelligence does not have to be recomputed from scratch for every export
- advisory logic remains modular instead of becoming one monolithic reporter file
- future additions like diffing, service drift alerts, and asset lineage can build on the same structure

## Current stored fields

Per-host summary:

- `service_count`
- `identified_service_count`
- `cpe_count`
- `advisory_count`
- `service_summary_json`
- `actionable_count`
- `actionable_critical_count`
- `actionable_high_count`
- `actionable_moderate_count`
- `actionable_review_count`
- `actionable_summary_json`

Per-service snapshot:

- port and protocol
- service and label
- match source and confidence
- product and version
- hostname / OS / device type hints
- CPE JSON
- hints JSON
- observations JSON
- advice JSON
- learning JSON

Per-actionable snapshot:

- severity
- issue
- action
- target and phase metadata

## Boundary

This architecture supports:

- service identification
- defensive mapping
- remediation guidance
- learner-friendly explanation
- historical comparison

It does not turn the default path into exploit validation or aggressive service abuse.

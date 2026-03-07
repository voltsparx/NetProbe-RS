# Framework Identity

NProbe-RS is a defensive network audit framework, not just a port scanner.

## Identity

- safe enough for fragile and unknown devices
- useful enough for specialists performing broad internal audits
- teachable enough for learners who need explanations, not just raw results
- trustworthy enough for long-running enterprise use through integrity checks and session history

## What Makes It Enterprise-Oriented

- `TBNS` for low-impact first contact on unknown devices
- multi-stage scan bundles so the framework can sequence first touch, discovery, and narrow enrichment without forcing one scan style everywhere
- adaptive multi-host coverage instead of raw packet blasting
- integrity enforcement and reseal workflow
- session persistence and resumable work
- SQLite-backed host progress snapshots for long-running operations
- explainable output with defensive guidance
- honest operator ergonomics, including compatible flags where semantics really match

## Throughput Philosophy

NProbe-RS is optimized for balanced defensive throughput:

- faster coverage through controlled parallelism
- hybrid async execution where it stays safe
- device-aware throttling and suppression
- staged enrichment so expensive checks happen only when justified
- bio-response governor decisions that can soften or widen coverage per host based on resilience signals
- workload-aware host parallelism so the scanner uses local CPU efficiently instead of running fixed-pressure loops

## Non-Goals

- stealth or evasion mechanics
- raw mass-recon acceleration primitives
- unsafe defaults that trade target stability for scan speed

The framework's identity is not "quietest attacker tool." It is "strongest defensive audit platform that still explains itself."

# Defensive Performance

NProbe-RS is intentionally not optimized for raw packet blasting. It is optimized for fast, controlled defensive coverage.

## What "Fast" Means Here

- parallel scanning across multiple authorized hosts
- hybrid async scheduling for higher throughput
- device-aware rate and concurrency limits
- bio-response governor decisions per host
- workload-aware host parallelism based on CPU and port volume
- resume and checkpoint support to avoid wasting work

## What It Avoids

- packet-blast scheduling as a default runtime path
- stealth/evasion mechanics
- unsafe acceleration primitives whose main value is mass reconnaissance

## Why This Is Still Competitive

- unknown hosts are triaged before heavier probing
- fragile devices are slowed down automatically
- resilient systems can use higher safe concurrency
- the framework spends less effort on unnecessary follow-up work

The result is a balanced defensive posture: quick enough for incident response and broad internal audits, but constrained enough to stay explainable and lower-risk.

## Durability

- SQLite persistence uses `WAL` mode for session and checkpoint durability
- per-host snapshots are persisted during scans so long operations can be inspected and resumed with more context than a simple cursor

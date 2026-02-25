# NetProbe-RS Reverse Engineering A-Z (from `temp/nmap`)

This maps major Nmap internals in `temp/nmap` to Rust re-implementations in this project.

- A. Argument pipeline: `temp/nmap/main.cc`, `temp/nmap/nmap.cc` -> `src/cli.rs`
- B. Bootstrapping entrypoint: `temp/nmap/main.cc` -> `src/main.rs`
- C. Core orchestration (`nmap_main` flow): `temp/nmap/nmap.cc` -> `src/scheduler.rs`
- D. DNS strategy: `temp/nmap/nmap.cc` DNS options -> `src/engines/thread_pool.rs`, `src/tasks/dns_lookup.rs`
- E. Engine separation concept: scan/timing/service/NSE split -> `src/engines/*`
- F. Fast/top-port behavior: `--top-ports` in `temp/nmap/nmap.cc` + `nmap-services` frequency -> `src/service_db.rs`
- G. Guardrails/safety defaults (new): inspired by operator warnings in scanner UX -> `src/scheduler.rs`
- H. Host result model: `Target` + per-host output objects -> `src/models.rs` (`HostResult`)
- I. I/O blocking delegation: mixed blocking ops in C++ -> thread-pool offload in Rust
- J. JSON-as-core output model (new architecture choice) -> `src/models.rs` + `src/output/json.rs`
- K. Knowledge extraction from service tables: `temp/nmap/nmap-services` -> `ServiceRegistry`
- L. Lua extensibility: `temp/nmap/nse_main.cc` -> `src/engines/lua_engine.rs` + `lua/default_rules.lua`
- M. Multi-format reporting: `temp/nmap/output.cc` -> `src/output/{cli,txt,json,csv,html}.rs`
- N. NSE-style host context passing: `nse_main.cc` port/host table patterns -> host serialization into Lua
- O. Open/closed/filtered semantics: scan engine state logic -> `PortState` and async probe classification
- P. Probe dispatch engine: `temp/nmap/scan_engine.cc` -> `src/engines/async_engine.rs`
- Q. Queue/concurrency controls: timing/performance options -> semaphore + profile defaults
- R. Risk scoring overlay (new): derived from exposed service posture -> `src/ai/risk.rs`
- S. Service detection: `temp/nmap/service_scan.cc` + `nmap-service-probes` concept -> `src/fingerprint_db.rs` + `src/engines/async_engine.rs`
- T. Timeout/retry behavior: timing templates in Nmap -> profile-based timeout/delay in `ScanProfile`
- U. UDP ambiguity handling: open|filtered semantics from Nmap -> `PortState::OpenOrFiltered`
- V. Version/banner enrichment: service fingerprinting inspiration -> lightweight protocol payload probes
- W. Write-path isolation: output writer stage -> `src/tasks/reporting.rs` + `thread_pool::write_output`
- X. Explain-mode augmentation (new): convert state/reason to teachable output -> `src/ai/explain.rs`
- Y. Yield-to-analysis stage (new): post-scan parallel analysis -> `src/engines/parallel.rs`, `src/tasks/analysis.rs`
- Z. Zenmap-like human presentation intent: GUI/report readability from Nmap ecosystem -> `src/output/html.rs`

## CLI output controls added

- `--output <filename>`: output file base name.
- `--location <directory>`: output destination directory.
- `--file-type <txt|csv|html|json>`: export format.
- When `--location` is set but `--output` is omitted, file name auto-generates in that location.

## Licensing note

This project is a clean-room, Rust implementation inspired by architecture and behavior patterns from local Nmap source files in `temp/nmap`. It does not copy Nmap implementation code.

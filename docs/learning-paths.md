# Learning Paths

NProbe-RS is structured so one framework can serve different defensive users without forcing them through the same workflow.

## Learners

- Start with `nprobe-rs interactive`
- Use `phantom`, `kis`, or `sar` when the target is fragile or unknown
- Keep `--explain` and `--verbose` on to learn what each stage did and why

## Practitioners

- Use direct CLI entry: `nprobe-rs <target> [options]`
- Nmap-style aliases are supported where semantics are honest: `-sU`, `-sS`, `-sT`, `-sV`, `-Pn`, `-A`, `-T0..-T5`, `-p-`
- Prefer `balanced` or `stealth` for normal reviews

## Fragile Device Triage

- `phantom`: first-touch device check that decides safe rate, delay, and follow-up depth
- `kis`: cautious identity hints
- `sar`: response-shape and decision-delta observation

These are grouped as `TBNS` and stay inside low-impact guardrails.

## Balanced Performance

- No packet-blast scheduling in the default defensive strategy path
- Faster coverage comes from controlled multi-host parallelism and hybrid async scheduling
- Safety caps still reduce concurrency and rate when device profiling or strict safety requires it
- Bio-response governor decisions can keep unknown or fragile hosts in `soft` or `guarded` stages automatically

## Trust Model

- Startup integrity verification is enforced before sessions and scans
- Scan reports include integrity state so operators can see whether the runtime was verified
- Session history keeps defensive runs reviewable and resumable
- SQLite-backed host snapshots preserve progress during long scans, not just final reports

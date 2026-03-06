# Phantom Scan

`phantom` is the least-contact first-touch profile in NProbe-RS.

What it means:

- passive-first, minimal-impact defensive triage
- transparent operator identity
- no spoofing, no decoys, no third-party host involvement
- no privileged raw probing, no UDP, no deep fingerprinting

Runtime shape:

- async-only execution
- host parallelism fixed to a single host at a time
- active port budget capped to 24 ports
- concurrency capped to 4 tasks
- rate capped to 96 pps
- burst size capped to 1
- retries capped to 1
- delay floor of 120 ms
- timeout floor of 2600 ms

Purpose:

- touch unknown or fragile devices as little as possible
- gather basic reachability and low-impact timing evidence
- hand escalation decisions to the safety and intelligence layers

Non-goals:

- stealth or evasion
- anonymous scanning
- zombie-style behavior
- source hiding

If a device shows stress signals or remains unclassified, Phantom stays conservative and defers deeper probing.

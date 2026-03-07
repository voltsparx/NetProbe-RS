# Phantom Scan

`phantom` is the least-contact device-check profile in the `TBNS` family.

What it means:

- passive-first, minimal-impact defensive triage
- first-touch device check before broader scanning
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
- gather basic reachability, responsiveness, and low-impact timing evidence
- decide safe size, speed, rate, and follow-up depth for the real scan
- hand escalation decisions to the safety and intelligence layers

Non-goals:

- stealth or evasion
- anonymous scanning
- zombie-style behavior
- source hiding

If a device shows stress signals or remains unclassified, Phantom stays conservative, reduces payload budget, and defers deeper probing.

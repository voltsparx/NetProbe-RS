# KIS Scan

`kis` is a low-impact timing and impedance profile for cautious classification.

What it means:

- defensive timing observation with long waits and small packet budgets
- strict safety before any follow-up probing
- transparent attribution
- no claims of invisibility, zero logging, or exact version truth from timing alone

Runtime shape:

- async-only execution
- host parallelism fixed to a single host at a time
- active port budget capped to 16 ports
- concurrency capped to 4 tasks
- rate capped to 72 pps
- burst size capped to 1
- retries capped to 1
- delay floor of 150 ms
- timeout floor of 3200 ms

Purpose:

- observe how quickly and consistently a target reacts to minimal probes
- use timing shifts as a safety signal for whether to stop or continue
- support defensive triage on sensitive or low-power networks

Non-goals:

- exact fingerprinting from timing alone
- stealth or anonymity
- stealth-oriented TCP flag abuse

KIS is intentionally conservative and should be treated as a safety-first classification aid, not a complete scanner on its own.

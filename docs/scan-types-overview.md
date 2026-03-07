# Scan Types Overview

Release: `v4.5 "Rusty Nail"` | `2026 Edition`

This note explains the new scan types in one pass, then points to the detailed docs.

## Phantom

What it is:

- the framework's device-check stage
- the first contact every host goes through before broader scanning

How it works in brief:

- samples a small number of low-contact checks
- measures responsiveness, timeout pressure, and basic latency
- decides the safe scan envelope for rate, concurrency, delay, and payload budget

Detailed doc:

- [Phantom Scan](phantom-scan.md)

## KIS

What it is:

- a low-impact identity-hint scan inside the TBNS family

How it works in brief:

- stays conservative on timing and follow-up depth
- uses cautious observation to gather limited identity hints without pushing the target hard
- hands deeper decisions back to the safety and intelligence layers

Detailed doc:

- [KIS Scan](kis-scan.md)

## SAR

What it is:

- a low-impact response-shape observation scan inside the TBNS family

How it works in brief:

- watches how the target responds under small, controlled pressure
- uses that behavior to decide whether the system looks stable, fragile, or worth deeper review
- keeps follow-up bounded when the host does not look resilient

Detailed doc:

- [SAR Scan](sar-scan.md)

## TBNS

What it is:

- the shared low-impact family that groups `phantom`, `kis`, and `sar`

How it works in brief:

- transparent identity
- strict safety guardrails
- minimal packet budgets
- staged escalation only when the host looks stable enough

Detailed doc:

- [TBNS](tbns.md)

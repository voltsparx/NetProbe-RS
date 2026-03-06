## Defensive Safety Guardrails

This framework is intentionally biased toward defensive discovery and operator restraint.

Current structural guardrails:

- Public-target scans are capped to a small host budget and cannot be distributed with sharding.
- Public-target scans are forced into stealth-safe behavior with UDP, privileged raw probing, and deep service fingerprinting disabled.
- Strict-safety mode forces a stealth profile, suppresses deeper active fingerprinting, and reduces rate, burst, and concurrency budgets.
- Protected ports such as `9100/tcp` are skipped in safe/public scope to avoid triggering device side effects.
- Unknown devices are treated conservatively until the framework has evidence that they behave like resilient enterprise hardware.
- Fragile and printer-like devices receive lower rate caps, lower concurrency, and passive-only follow-up behavior.
- Packet-blast selection is no longer a volume-only escalation; it requires privileged low-impact conditions and disabled active fingerprinting.
- `phantom`, `sar`, and `kis` are implemented as low-impact defensive concepts only; they automatically enable strict safety, stay on async paths, and disable UDP, raw privileged probing, and deep fingerprinting.

Design intent:

- Prefer incomplete but safe discovery over disruptive completeness.
- Make broad or aggressive misuse materially harder without adding hidden unsafe bypasses.
- Keep the system explainable by surfacing every major guard decision in warnings, safety actions, session history, and learning notes.

# NProbe-RS Platform Intent

This note condenses the recurring themes scanned from:

- `intel-source/`
- `self-assesment/`
- `cooking-reverse-engineering/`
- `my-philosophy-for-nprobe-rs/`

It is intentionally product-focused rather than packet-focused.

## Identity

NProbe-RS is not just a scanner. It is a defensive learning platform with:

- multiple execution engines
- a coordinating fusion layer
- safety systems that are architectural, not cosmetic
- human-readable teaching output
- extensible enrichment and scripting

## Stable platform pillars

The four reference trees converge on the same requirements:

1. Engine isolation
Each engine should own one domain and communicate through stable interfaces.

2. Structural safety
Guardrails should live in runtime policy, rate control, and target validation.

3. Teaching-first reporting
Outputs should explain what happened, why it matters, and what to do next.

4. Progressive enrichment
Discovery should stay lightweight, then hand results to slower intelligence layers.

5. Ecosystem growth
Plugins, scripts, data packs, and saved reports matter as much as the scanner loop.

## Immediate implementation direction

Short-term work should keep moving in these safe directions:

- unify host safety policy across all engine paths
- persist richer run metadata and host safety decisions
- expand explain-mode and learning notes
- strengthen plugin and fetcher contracts
- add resumable state and durable session history
- keep public-target safeguards mandatory by default

## Non-goal

This repository should not optimize for destructive or unsafely aggressive behavior.
Performance work is acceptable only when paired with rate governance, visibility, and defensive use boundaries.

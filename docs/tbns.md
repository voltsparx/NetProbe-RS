# Tri-Blue Network Scans

`TBNS` means `Tri-Blue Network Scans`.

It is the low-impact defensive scan family in NProbe-RS:

- `phantom` as the device-check chapter that decides how much follow-up the host can safely tolerate
- `kis` for timing-based identity hints
- `sar` for response-shape and logic observation

The family rules are structural:

- transparent operator identity
- async-only execution
- strict-safety always on
- UDP disabled
- privileged raw probing disabled
- deep fingerprinting disabled until resilience evidence exists
- small packet budgets, low host parallelism, and early stop behavior

Design intent:

- protect fragile devices, including low-power embedded systems
- detect exposure and unsafe service posture without aggressive pressure
- make the framework harder to weaponize by keeping the family conservative by default

`TBNS` is a defensive safety family, not a stealth family.

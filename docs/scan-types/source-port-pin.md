# Source Port Pin

- Status: `implemented`
- Category: `evasion`
- Flags: `-g <port>`, `--source-port <port>`
- Summary: pins the outbound source port across async TCP/UDP probes and the raw packet-crafter lane.
- Notes: low source ports below `1024` still require elevation; `--source-port` now applies to both the user-space connect path and the kernel-bypass packet crafter.
- Canonical refs: `cooking-reverse-engineering/nmap-scan-encyclopedia.txt`

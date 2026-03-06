# SAR Scan

`sar` is a low-impact observation profile for response-shape and timing-delta analysis.

What it means:

- defensive observation of response timing changes
- minimal active validation under strict safety
- explicit operator identity
- no malformed pressure tactics, no stealth, no spoofing

Runtime shape:

- async-only execution
- host parallelism fixed to a single host at a time
- active port budget capped to 32 ports
- concurrency capped to 6 tasks
- rate capped to 144 pps
- burst size capped to 2
- retries capped to 1
- delay floor of 80 ms
- timeout floor of 2400 ms

Purpose:

- compare response timing across cautious first-contact probes
- detect when the target or middleboxes begin showing strain or policy changes
- stop early when the environment looks sensitive or unstable

Non-goals:

- forcing DPI or defense-stack burden
- bypassing monitoring
- making probes blend in with unrelated traffic

SAR is implemented here as safe timing observation, not as an evasion technique.

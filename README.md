# NetProbe-RS

`NetProbe-RS` is a Rust-native, explainable network reconnaissance tool inspired by Nmap's architecture and data files.

This repository includes:

- A reverse-engineered architecture mapping from `temp/nmap`.
- A modular Rust scanner with async scanning, thread-pool DNS, Rayon analysis, Lua hooks, and multi-format output.
- Fingerprint/probe loading from `temp/nmap/nmap-service-probes` and service/port mapping from `temp/nmap/nmap-services`.
- Educational AI notes, explain mode, and defensive guidance.
- Safety controls with flexible behavior (`--lab-mode`, `--allow-external`, `--strict-safety`).

## Quick start

```bash
cargo run -- scan 127.0.0.1 --explain
```

Common usage:

```bash
cargo run -- scan scanme.nmap.org --top-ports 100 --allow-external
cargo run -- scan 192.168.1.1 --ports 22,80,443 --profile stealth --explain --lab-mode
cargo run -- scan 10.0.0.5 --udp --lua-script scripts/example.lua --lab-mode
cargo run -- scan 127.0.0.1 --top-ports 20 --reverse-dns
cargo run -- scan 192.168.1.10 --profile aggressive --allow-external
cargo run -- scan 192.168.1.10 --aggressive-root --privileged-probes --allow-external
cargo run -- scan 192.168.1.10 --root-only --allow-external

# Output controls
cargo run -- scan 192.168.1.20 --output internal-audit --file-type json
cargo run -- scan 192.168.1.20 --output internal-audit --location ./reports --file-type html
cargo run -- scan 192.168.1.20 --location ./reports --file-type csv

# Shortcut aliases
cargo run -- scan 192.168.1.10 -R -a -o termux-scan -f json
cargo run -- scan 192.168.1.10 -g -k -a -t 200 -u
```

## Notes

- `temp/` is ignored in git so local reverse-engineering artifacts do not get committed.
- Service names and top-port ranking are loaded from `temp/nmap/nmap-services` when present, with built-in fallback defaults.
- Fingerprint rules and probe payloads are parsed from `temp/nmap/nmap-service-probes` where supported by Rust regex capabilities.
- On startup, NetProbe-RS creates `~/.netprobe-rs-config/config.ini` and stores persistent app configuration/last-run metadata there.
- By default it prints to console only and does not create scan output files unless `--output`, `--location`, or `--file-type` is provided.
- `--root-only` is a Termux/mobile-tuned preset: it enables privileged scanning, keeps safer runtime limits, and defaults to top 200 ports when no port scope is given.
- `--aggressive-root` and `--privileged-probes` require root/admin privileges; in Termux use a root shell (`su`/`tsu`) first.
- This project does not copy Nmap source code; it re-implements core ideas in Rust.

## Install helpers

Use cross-platform install scripts in `building-scripts/`:

- Linux/macOS: `./building-scripts/install.sh`
- Termux: `./building-scripts/install-termux.sh`
- Windows PowerShell: `.\building-scripts\install.ps1`
- Windows CMD: `building-scripts\install.bat`

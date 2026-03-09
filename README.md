# NProbe-RS

**NProbe-RS** is a Rust-native network scanner for authorized internal and lab use, with explainable output, defensive defaults, and multi-engine execution.

It reimplements familiar scanning workflows with a modern Rust architecture while helping users understand *why* results matter, not just what was found.

**Version**: v4.5 "Rusty Nail"  <br>
**Edition**: 2026 Edition  <br>
**Author**: voltsparx  <br>
**Contact**: voltsparx@gmail.com

---

## ✨ Why NProbe-RS?

NProbe-RS is designed to make network reconnaissance understandable and safe by default.

Instead of only reporting open ports, it explains findings, highlights risks, and provides defensive context — making it ideal for:

- 🎓 Students & learners
- 🛡️ Blue teams & defenders
- 🧪 Lab environments
- 🧑‍💻 Internal reviews
- 🔬 Security research

The project is publishable in its current supported scope as a defensive scanner. Concepts documented under `docs/scan-types/` are not automatically equivalent to live packet paths; use `nprobe-rs --scan-type` to inspect what is currently implemented versus cataloged.

---

## 🧩 Features

- 🔎 Explainable scan results with defensive guidance  
- 🎯 Nmap-style command flow (`nprobe-rs <target>`) and first-class `nprs` alias
- ⚡ Rust async engine for high-performance scanning  
- 🧵 Thread-pool DNS resolution  
- 🧠 Parallel analysis using Rayon  
- 🧪 Lua hooks for custom probes & automation  
- 📄 Multi-format output: CLI, TXT, JSON, HTML, CSV  
- 🚦 Cleaner terminal output (focused, less noisy by default)  
- 🛡️ Safety controls to prevent unintended scanning  
- 🔐 Auto privilege elevation for root-required scan modes on Linux/macOS (sudo/doas where available)
- ⚙️ Persistent configuration & last-run metadata  

---

## 📚 Scan Types

Use `nprobe-rs --scan-type` or `nprs --scan-type` for the canonical live catalog. Status values are `implemented`, `partial`, and `planned`.

Shortcut notes:

- Legacy Nmap host-discovery alias `-sP` is accepted as `--ping-scan`.
- Project-specific live scan shortcuts are also accepted: `-sPH` (phantom), `-sKI` (kis), `-sSR` (sar), `-sID` (idf), `-sMR` (mirror), `-sHY` (hybrid), `-sCB` (callback-ping).

Implemented runtime lanes:

- Discovery: `arp`
- Classic: `connect`, `syn`, `udp`
- Safe control/evasion-adjacent: `source-port-pin`
- Enrichment: `banner`, `aggressive-suite`
- Hybrid/timing: `hybrid`, `timing-profile`
- New project-specific defensive families: `phantom`, `kis`, `sar`, `tbns`, `idf`, `mirror`, `callback-ping`

Partial lanes:

- Discovery: `ping-scan`, `icmp-echo`
- Enrichment: `os-fingerprint`, `script-scan`, `traceroute`

Cataloged but not live runtime lanes:

- Discovery: `icmp-timestamp`, `icmp-netmask`, `tcp-ping`, `tcp-syn-ping`, `tcp-ack-ping`, `udp-ping`, `sctp-init-ping`, `ip-proto-ping`
- Classic: `ack`, `maimon`, `custom-scanflags`, `ip-protocol`, `sctp-init`, `sctp-cookie`
- Combo recipes: `kinetic-fingerprint`, `sovereign-callback`

Cataloged and intentionally not exposed as live runtime features:

- `ftp-bounce`, `window`, `fragment`, `decoy`, `spoof-source`, `interface-bind`

Overview and detailed docs:

- [Scan Types Overview](docs/scan-types-overview.md)
- [Phantom Scan](docs/phantom-scan.md)
- [KIS Scan](docs/kis-scan.md)
- [SAR Scan](docs/sar-scan.md)
- [TBNS Family](docs/tbns.md)
- [Service Detection Intelligence](docs/service-detection-intelligence.md)
- [Service Knowledge Architecture](docs/service-knowledge-architecture.md)

---

## 🛡️ Safety Controls

NProbe-RS promotes responsible usage through built-in safeguards:

- `--lab-mode` → restricts scans to safe lab environments  
- `--allow-external` → explicitly allow external targets  
- `--strict-safety` → enforces conservative scan behavior  

---

## 🚀 Quick Start

```bash
cargo run -- 127.0.0.1 --explain
cargo install --path .
# after install:
nprobe-rs 127.0.0.1 --top-ports 100
```

Installer scripts place both `nprobe-rs` and the short alias `nprs` on disk. `cargo install --path .` now installs both first-class binaries as well.

---

## ✅ Release Quality Gates

Run these before publishing or tagging a release:

```bash
cargo fmt --all -- --check
cargo check --all-targets
cargo test --all-targets
cargo build --release --bins
```

For the full release checklist, see [RELEASE.md](RELEASE.md).

GitHub Actions now validates the crate on Linux, macOS, and Windows, and tagged releases package both `nprobe-rs` and `nprs` with per-archive SHA-256 checksums.

---

## ⚙️ Acceleration Engines

- Governed async/user-space engine: available on Linux, macOS, and Windows.
- Raw packet crafting engine: available on Linux and Windows when elevated raw-socket access is present; the safety governor blocks the kernel-bypass lane when the host is not ready.
- AF_XDP zero-copy backend: Linux-only optional build path via `--features afxdp`; current builds treat it as a scaffolded backend and fall back automatically when the host cannot sustain it.
- GPU acceleration controls: Linux and Windows only; current builds use a governed hybrid bridge around the packet crafter envelope rather than a standalone GPU packet backend.
- macOS: GPU control flags are denied explicitly, and scans stay on the governed async/user-space lanes.

---

## 🧪 Common Usage

```bash
nprobe-rs scanme.nmap.org --top-ports 100 --allow-external
nprobe-rs 192.168.1.1 --ports 22,80,443 --profile stealth --explain --lab-mode
nprobe-rs 10.0.0.5 --udp --lua-script scripts/example.lua --lab-mode
nprobe-rs 127.0.0.1 --top-ports 20 --reverse-dns
nprobe-rs 192.168.1.10 --profile aggressive --allow-external
nprobe-rs 192.168.1.10 --aggressive-root --privileged-probes --allow-external
nprobe-rs 192.168.1.10 --root-only --allow-external
```

---

## 📄 Output Controls

```bash
nprobe-rs 192.168.1.20 --output scan-report --file-type json
nprobe-rs 192.168.1.20 --output scan-report --location ./reports --file-type html
nprobe-rs 192.168.1.20 --location ./reports --file-type csv
```

---

## ⚡ Shortcut Aliases

```bash
nprobe-rs 192.168.1.10 -A -o aggressive-scan -f json
nprobe-rs 192.168.1.10 -A -a -w 700 -U
nprobe-rs 192.168.1.10 -sU -p 53,161
nprobe-rs 192.168.1.10 -T4 -p-
```

---

## 🧾 Flag Help Mode

```bash
nprobe-rs --flag-help --scan
nprobe-rs --flag-help -sU
nprobe-rs --explain --scan   # legacy alias for flag docs mode
```

---

## 🧠 Example (Explain Mode)

```
Port 22/tcp open — SSH
Risk: Medium
Why: Remote access service exposed.
Guidance: Use key-based authentication and disable password login.
```

---

## ⚙️ How It Works

- Architecture study and reimplementation inspired by Nmap's design principles  
- Async scanning engine with adaptive concurrency  
- Multi-stage intelligence pipeline: raw discovery -> async probe narrowing -> targeted fingerprint matching  
- Service and port mapping with built-in defaults and optional local data loading  
- Fingerprint and probe parsing where supported  
- Modular design for extensibility and scripting  

---

## 📝 Notes

- `temp/` is ignored in git so local study artifacts are not committed.  
- Service names and top-port ranking load from `temp/nmap/nmap-services` when present.  
- Fingerprint rules and probe payloads parse from `temp/nmap/nmap-service-probes` where supported.  
- On startup, NProbe-RS creates `~/.nprobe-rs-config/config.ini` for persistent settings.  
- By default, output is printed to console unless `--output`, `--location`, or `--file-type` is provided.  
- `nprobe-rs scan <target>` is still supported for compatibility, but `nprobe-rs <target>` is preferred.  
- Timeout short flag is `-w` (`--timeout-ms`), while Nmap-style timing shortcuts use `-T0..-T5`.  
- Supported host platforms are Linux, macOS, and Windows.
- Root-required scan modes auto-attempt elevation on Linux and macOS when possible.

---

## 📦 Installation Helpers

Cross-platform install scripts are provided in `building-scripts/`. The flow now mirrors the common Nmap pattern: use native package-manager/source prerequisites on Unix, then install into a conventional bin directory; use the PowerShell/CMD installer path on Windows.

### Linux / macOS
```bash
./building-scripts/install.sh             # prompt mode
./building-scripts/install.sh deps
./building-scripts/install.sh install --install-deps
./building-scripts/install.sh install
./building-scripts/install.sh update
./building-scripts/install.sh test
./building-scripts/install.sh uninstall
```

Notes:

- Linux dependency installation uses the detected distro package manager.
- macOS dependency installation expects Xcode Command Line Tools plus Homebrew.
- `uninstall` removes both `nprobe-rs` and `nprs` from the detected install directory and can resolve script installs, PATH-visible installs, and the standard Cargo bin location. Pass `--install-dir` for a custom target.

### Windows PowerShell
```powershell
.\building-scripts\install.ps1             # prompt mode
.\building-scripts\install.ps1 deps
.\building-scripts\install.ps1 install -InstallDeps
.\building-scripts\install.ps1 install
.\building-scripts\install.ps1 update
.\building-scripts\install.ps1 test
.\building-scripts\install.ps1 uninstall
```

Notes:

- `uninstall` removes both `nprobe-rs.exe` and `nprs.exe` from the detected install directory and can resolve script installs, PATH-visible installs, and the standard Cargo bin location. Pass `-InstallDir` for a custom target. Cargo bin PATH entries are left intact.

### Windows CMD
```cmd
building-scripts\install.bat
building-scripts\install.bat install
building-scripts\install.bat uninstall
```

Installed command name:

- `nprobe-rs` and `nprs` (Linux/macOS)
- `nprobe-rs.exe` and `nprs.exe` (Windows)

---

## ⚖️ Legal & Ethical Use

NProbe-RS is intended for:

- authorized security testing
- lab environments
- educational use
- defensive security research

Always obtain proper authorization before scanning networks you do not own or manage.

This repository intentionally favors bounded, explainable, low-impact behavior over stealth, spoofing, or deceptive packet injection.

---

## 🛣️ Roadmap (Planned)

- 🧬 Service/version enrichment and better fingerprint confidence reporting  
- 🗺️ Network topology visualization  
- 🔄 Baseline comparison & drift detection  
- 🧠 Adaptive scan intelligence  
- 🚀 AF_XDP zero-copy packet backend (Linux, kernel-bypass path)  
- 📦 Prebuilt binaries for major platforms  

---

## 🤝 Contributing

Contributions, ideas, and feedback are welcome!

If you’d like to improve NProbe-RS, feel free to open an issue or submit a pull request.

---

## ⭐ Acknowledgment

NProbe-RS draws inspiration from the design principles of Nmap while reimplementing core ideas with a modern Rust architecture focused on safety, clarity, and extensibility.

---

## 📜 License

**SPDX-License-Identifier**

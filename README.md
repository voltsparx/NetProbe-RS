# NetProbe-RS

**NetProbe-RS** is a Rust-native, explainable network reconnaissance tool focused on learning, safety, and actionable insights.

It reimplements proven network scanning concepts with a modern, safe architecture while helping users understand *why* results matter — not just what was found.

**Version**: v1.3  <br>
**Author**: voltsparx  <br>
**Contact**: voltsparx@gmail.com

---

## ✨ Why NetProbe-RS?

NetProbe-RS is designed to make network reconnaissance understandable and safe by default.

Instead of only reporting open ports, it explains findings, highlights risks, and provides defensive context — making it ideal for:

- 🎓 Students & learners
- 🛡️ Blue teams & defenders
- 🧪 Lab environments
- 🧑‍💻 Internal audits
- 🔬 Security research

---

## 🧩 Features

- 🔎 Explainable scan results with defensive guidance  
- 🎯 Nmap-style command flow (`netprobe-rs <target>`) and short aliases  
- ⚡ Rust async engine for high-performance scanning  
- 🧵 Thread-pool DNS resolution  
- 🧠 Parallel analysis using Rayon  
- 🧪 Lua hooks for custom probes & automation  
- 📄 Multi-format output: CLI, TXT, JSON, HTML, CSV  
- 🚦 Cleaner terminal output (focused, less noisy by default)  
- 🛡️ Safety controls to prevent unintended scanning  
- 🔐 Auto privilege elevation for root-required scan modes (sudo/su/doas where available)  
- 📱 Termux/mobile-friendly presets  
- ⚙️ Persistent configuration & last-run metadata  

---

## 🛡️ Safety Controls

NetProbe-RS promotes responsible usage through built-in safeguards:

- `--lab-mode` → restricts scans to safe lab environments  
- `--allow-external` → explicitly allow external targets  
- `--strict-safety` → enforces conservative scan behavior  

---

## 🚀 Quick Start

```bash
cargo run -- 127.0.0.1 --explain
# after install:
netprobe-rs 127.0.0.1 --top-ports 100
```

---

## 🧪 Common Usage

```bash
netprobe-rs scanme.nmap.org --top-ports 100 --allow-external
netprobe-rs 192.168.1.1 --ports 22,80,443 --profile stealth --explain --lab-mode
netprobe-rs 10.0.0.5 --udp --lua-script scripts/example.lua --lab-mode
netprobe-rs 127.0.0.1 --top-ports 20 --reverse-dns
netprobe-rs 192.168.1.10 --profile aggressive --allow-external
netprobe-rs 192.168.1.10 --aggressive-root --privileged-probes --allow-external
netprobe-rs 192.168.1.10 --root-only --allow-external
```

---

## 📄 Output Controls

```bash
netprobe-rs 192.168.1.20 --output internal-audit --file-type json
netprobe-rs 192.168.1.20 --output internal-audit --location ./reports --file-type html
netprobe-rs 192.168.1.20 --location ./reports --file-type csv
```

---

## ⚡ Shortcut Aliases

```bash
netprobe-rs 192.168.1.10 -a -o termux-scan -f json
netprobe-rs 192.168.1.10 -A -a -w 700 -U
netprobe-rs 192.168.1.10 -sU -p 53,161
netprobe-rs 192.168.1.10 -T4 -p-
```

---

## 🧾 Flag Help Mode

```bash
netprobe-rs --flag-help --scan
netprobe-rs --flag-help -sU
netprobe-rs --explain --scan   # legacy alias for flag docs mode
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
- Service and port mapping with built-in defaults and optional local data loading  
- Fingerprint and probe parsing where supported  
- Modular design for extensibility and scripting  

---

## 📝 Notes

- `temp/` is ignored in git so local study artifacts are not committed.  
- Service names and top-port ranking load from `temp/nmap/nmap-services` when present.  
- Fingerprint rules and probe payloads parse from `temp/nmap/nmap-service-probes` where supported.  
- On startup, NetProbe-RS creates `~/.netprobe-rs-config/config.ini` for persistent settings.  
- By default, output is printed to console unless `--output`, `--location`, or `--file-type` is provided.  
- `netprobe-rs scan <target>` is still supported for compatibility, but `netprobe-rs <target>` is preferred.  
- Timeout short flag is `-w` (`--timeout-ms`), while Nmap-style timing shortcuts use `-T0..-T5`.  
- Root-required scan modes auto-attempt elevation on Unix-like systems when possible.  

### 📱 Termux / Mobile Presets

- `--root-only` enables privileged scanning with safer runtime limits  
- Defaults to top 200 ports when no scope is provided  
- For privileged probes, run inside a root shell (`su` / `tsu`)  

---

## 📦 Installation Helpers

Cross-platform install scripts are provided in `building-scripts/`:

### Linux/macOS
```bash
./building-scripts/install.sh             # prompt mode
./building-scripts/install.sh install
./building-scripts/install.sh update
./building-scripts/install.sh test
./building-scripts/install.sh uninstall
```

### Termux
```bash
./building-scripts/install-termux.sh      # prompt mode
./building-scripts/install-termux.sh install
```

### Windows PowerShell
```powershell
.\building-scripts\install.ps1             # prompt mode
.\building-scripts\install.ps1 install
.\building-scripts\install.ps1 update
.\building-scripts\install.ps1 test
.\building-scripts\install.ps1 uninstall
```

### Windows CMD
```cmd
building-scripts\install.bat
building-scripts\install.bat install
```

Installed command name:

- `netprobe-rs` (Linux/macOS/Termux)
- `netprobe-rs.exe` (Windows)

---

## ⚖️ Legal & Ethical Use

NetProbe-RS is intended for:

- authorized security testing
- lab environments
- educational use
- defensive security research

Always obtain proper authorization before scanning networks you do not own or manage.

---

## 🛣️ Roadmap (Planned)

- 🧬 Service/version enrichment and better fingerprint confidence reporting  
- 🗺️ Network topology visualization  
- 🔄 Baseline comparison & drift detection  
- 🧠 Adaptive scan intelligence  
- 📦 Prebuilt binaries for major platforms  

---

## 🤝 Contributing

Contributions, ideas, and feedback are welcome!

If you’d like to improve NetProbe-RS, feel free to open an issue or submit a pull request.

---

## ⭐ Acknowledgment

NetProbe-RS draws inspiration from the design principles of Nmap while reimplementing core ideas with a modern Rust architecture focused on safety, clarity, and extensibility.

---

## 📜 License

**MIT**

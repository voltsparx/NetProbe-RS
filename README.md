# NetProbe-RS

**NetProbe-RS** is a Rust-native, explainable network reconnaissance tool focused on learning, safety, and actionable insights.

It reimplements proven network scanning concepts with a modern, safe architecture while helping users understand *why* results matter — not just what was found.

**Author**: voltsparx
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
- ⚡ Rust async engine for high-performance scanning  
- 🧵 Thread-pool DNS resolution  
- 🧠 Parallel analysis using Rayon  
- 🧪 Lua hooks for custom probes & automation  
- 📄 Multi-format output: JSON, HTML, CSV  
- 🛡️ Safety controls to prevent unintended scanning  
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
cargo run -- scan 127.0.0.1 --explain
```

---

## 🧪 Common Usage

```bash
cargo run -- scan scanme.nmap.org --top-ports 100 --allow-external
cargo run -- scan 192.168.1.1 --ports 22,80,443 --profile stealth --explain --lab-mode
cargo run -- scan 10.0.0.5 --udp --lua-script scripts/example.lua --lab-mode
cargo run -- scan 127.0.0.1 --top-ports 20 --reverse-dns
cargo run -- scan 192.168.1.10 --profile aggressive --allow-external
cargo run -- scan 192.168.1.10 --aggressive-root --privileged-probes --allow-external
cargo run -- scan 192.168.1.10 --root-only --allow-external
```

---

## 📄 Output Controls

```bash
cargo run -- scan 192.168.1.20 --output internal-audit --file-type json
cargo run -- scan 192.168.1.20 --output internal-audit --location ./reports --file-type html
cargo run -- scan 192.168.1.20 --location ./reports --file-type csv
```

---

## ⚡ Shortcut Aliases

```bash
cargo run -- scan 192.168.1.10 -R -a -o termux-scan -f json
cargo run -- scan 192.168.1.10 -g -k -a -t 200 -u
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

### 📱 Termux / Mobile Presets

- `--root-only` enables privileged scanning with safer runtime limits  
- Defaults to top 200 ports when no scope is provided  
- For privileged probes, run inside a root shell (`su` / `tsu`)  

---

## 📦 Installation Helpers

Cross-platform install scripts are provided in `building-scripts/`:

### Linux/macOS
```bash
./building-scripts/install.sh
```

### Termux
```bash
./building-scripts/install-termux.sh
```

### Windows PowerShell
```powershell
.\building-scripts\install.ps1
```

### Windows CMD
```cmd
building-scripts\install.bat
```

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

- 📊 Risk scoring & attack surface summaries  
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

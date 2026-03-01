# building-scripts

Cross-platform lifecycle helpers for `netprobe-rs`.

## Phases

- `phase1` / `test`: build release and copy test binary to `build-<os>/` in repo root
- `phase2` / `install`: install to local/custom bin and optionally add install path to `PATH`
- `phase3` / `upgrade`: rebuild and replace installed binary
- `phase4` / `remove`: remove installed binary

## Linux / macOS

```bash
./building-scripts/install.sh phase1
./building-scripts/install.sh phase2
./building-scripts/install.sh phase3
./building-scripts/install.sh phase4
```

Options:

- `--install-dir <dir>` for custom install/remove target
- `--add-to-path` to add install directory to PATH without prompting
- `--no-path-update` to skip PATH changes

## Termux (Android)

```bash
chmod +x ./building-scripts/install-termux.sh
./building-scripts/install-termux.sh phase2
```

The Termux script installs dependencies first, then runs the same phase flow as `install.sh`.

## Windows PowerShell

```powershell
.\building-scripts\install.ps1 phase1
.\building-scripts\install.ps1 phase2
.\building-scripts\install.ps1 phase3
.\building-scripts\install.ps1 phase4
```

Options:

- `-InstallDir <dir>` for custom install/remove target
- `-AddToPath` to add install directory to PATH without prompting
- `-NoPathUpdate` to skip PATH changes
- `-Help` for usage

## Windows CMD

```cmd
building-scripts\install.bat phase2
```

## Result

Installed command name:

- `netprobe-rs` on Linux/macOS/Termux
- `netprobe-rs.exe` on Windows

Example:

```bash
netprobe-rs 192.168.1.10 --root-only --allow-external
```

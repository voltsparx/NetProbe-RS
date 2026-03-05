# building-scripts

Cross-platform lifecycle helpers for `nprobe-rs`.

## Actions

- `install`: install to local/custom bin and optionally add install path to `PATH`
- `update`: rebuild and replace installed binary
- `test`: build release and copy test binary to `build-<os>/` in repo root
- `uninstall`: remove installed binary

## Linux / macOS

```bash
./building-scripts/install.sh             # prompt mode
./building-scripts/install.sh install
./building-scripts/install.sh update
./building-scripts/install.sh test
./building-scripts/install.sh uninstall
```

Optional automation flags:

- `--install-dir <dir>` for custom install/uninstall target
- `--add-to-path` to add install directory to PATH without prompting
- `--no-path-update` to skip PATH changes

## Termux (Android)

```bash
chmod +x ./building-scripts/install-termux.sh
./building-scripts/install-termux.sh      # prompt mode
./building-scripts/install-termux.sh install
```

The Termux script installs dependencies first, then runs the same action flow as `install.sh`.

## Windows PowerShell

```powershell
.\building-scripts\install.ps1             # prompt mode
.\building-scripts\install.ps1 install
.\building-scripts\install.ps1 update
.\building-scripts\install.ps1 test
.\building-scripts\install.ps1 uninstall
```

Optional automation flags:

- `-InstallDir <dir>` for custom install/uninstall target
- `-AddToPath` to add install directory to PATH without prompting
- `-NoPathUpdate` to skip PATH changes
- `-Help` for usage

## Windows CMD

```cmd
building-scripts\install.bat
building-scripts\install.bat install
```

## Result

Installed command name:

- `nprobe-rs` on Linux/macOS/Termux
- `nprobe-rs.exe` on Windows

Example:

```bash
nprobe-rs 192.168.1.10 --root-only --allow-external
```

# building-scripts

Cross-platform install helpers for `netprobe-rs`.

## Linux / macOS

```bash
./building-scripts/install.sh
```

Optional environment variable:

- `NETPROBE_RS_INSTALL_DIR` (default: `~/.local/bin`)

## Termux (Android)

```bash
chmod +x ./building-scripts/install-termux.sh
./building-scripts/install-termux.sh
```

Optional environment variable:

- `NETPROBE_RS_INSTALL_DIR` (default: `$PREFIX/bin`)

## Windows PowerShell

```powershell
.\building-scripts\install.ps1
```

Optional parameter:

- `-InstallDir` (default: `$HOME\.local\bin`)

## Windows CMD

```cmd
building-scripts\install.bat
```

## Result

The scripts build release mode and install:

- `recon` on Linux/macOS
- `recon` on Termux
- `recon.exe` on Windows

to the selected install directory.

For Termux root-capable scans after install:

```bash
su -c "recon scan 192.168.1.10 --root-only --allow-external"
```

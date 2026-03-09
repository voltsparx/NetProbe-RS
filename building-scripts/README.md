# building-scripts

Cross-platform lifecycle helpers for `nprobe-rs`.

## Actions

- `deps`: install build dependencies on supported platforms
- `install`: install to local/custom bin and optionally add install path to `PATH`
- `update`: rebuild and replace installed binary
- `test`: build release and copy test binary to `build-<os>/` in repo root
- `uninstall`: remove installed binaries and optionally clean the PATH entry the helper added

## Linux / macOS

```bash
./building-scripts/install.sh             # prompt mode
./building-scripts/install.sh deps
./building-scripts/install.sh install --install-deps
./building-scripts/install.sh install
./building-scripts/install.sh update
./building-scripts/install.sh test
./building-scripts/install.sh uninstall
```

Optional automation flags:

- `--install-dir <dir>` for custom install/uninstall target
- `--install-deps` to install supported build dependencies before install/update/test
- `--add-to-path` to add install directory to PATH without prompting
- `--no-path-update` to skip PATH changes

Platform notes:

- Linux uses the detected distro package manager for `deps`.
- macOS expects Xcode Command Line Tools plus Homebrew for `deps`.
- Unix installs now place both `nprobe-rs` and the short alias `nprs` in the target bin directory.
- `uninstall` removes both binaries from the detected install directory and can resolve script installs, PATH-visible installs, and the standard Cargo bin path.

## Windows PowerShell

```powershell
.\building-scripts\install.ps1             # prompt mode
.\building-scripts\install.ps1 deps
.\building-scripts\install.ps1 install -InstallDeps
.\building-scripts\install.ps1 install
.\building-scripts\install.ps1 update
.\building-scripts\install.ps1 test
.\building-scripts\install.ps1 uninstall
```

Optional automation flags:

- `-InstallDir <dir>` for custom install/uninstall target
- `-InstallDeps` to install supported build dependencies before install/update/test
- `-AddToPath` to add install directory to PATH without prompting
- `-NoPathUpdate` to skip PATH changes
- `-Help` for usage
- `uninstall` removes both binaries from the detected install directory and can resolve script installs, PATH-visible installs, and the standard Cargo bin path. The helper leaves Cargo bin PATH entries intact.

## Windows CMD

```cmd
building-scripts\install.bat
building-scripts\install.bat install
building-scripts\install.bat uninstall
```

## Result

Installed command name:

- `nprobe-rs` and `nprs` on Linux/macOS
- `nprobe-rs.exe` and `nprs.exe` on Windows

## Engine Notes

- Raw packet crafting is available on Linux and Windows when privileged raw access is present.
- AF_XDP is an optional Linux-only kernel-bypass scaffold that falls back automatically when unavailable.
- GPU control flags are supported on Linux and Windows only; macOS explicitly denies them and stays on the governed async path.

Example:

```bash
nprobe-rs 192.168.1.10 --root-only --allow-external
```

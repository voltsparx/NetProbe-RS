param(
    [string]$InstallDir = "$HOME\.local\bin"
)

$ErrorActionPreference = "Stop"
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$RootDir = (Resolve-Path (Join-Path $ScriptDir "..")).Path
$Manifest = Join-Path $RootDir "Cargo.toml"

Write-Host "Building netprobe-rs (release)..."
cargo build --release --manifest-path $Manifest

$Primary = Join-Path $RootDir "target\release\netprobe-rs.exe"
$Fallback = Join-Path $RootDir "target\release\netprobe-rs"
$Source = if (Test-Path $Primary) { $Primary } elseif (Test-Path $Fallback) { $Fallback } else { $null }
if (-not $Source) {
    throw "Release binary not found. Expected: $Primary"
}

New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
$Dest = Join-Path $InstallDir "recon.exe"
Copy-Item -Path $Source -Destination $Dest -Force

Write-Host "Installed: $Dest"
Write-Host "Tip: add '$InstallDir' to PATH if needed."


# Flow sketch: phase selection -> build/install action -> CLI availability
# Pseudo-block:
#   choose phase -> execute action -> verify output
# PowerShell here acts like a librarian with admin keys.

param(
    [string]$Phase = "install",
    [string]$InstallDir = "",
    [switch]$AddToPath,
    [switch]$NoPathUpdate,
    [switch]$Help
)

$ErrorActionPreference = "Stop"
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$RootDir = (Resolve-Path (Join-Path $ScriptDir "..")).Path
$Manifest = Join-Path $RootDir "Cargo.toml"

function Show-Usage {
    @"
Usage:
  .\building-scripts\install.ps1 [phase] [options]

Phases:
  phase1 | test      Build a test binary into build-windows\ in repo root
  phase2 | install   Install binary to local/custom bin and optionally add PATH
  phase3 | upgrade   Rebuild and replace existing installed binary
  phase4 | remove    Remove installed binary

Options:
  -InstallDir <dir>  Install/remove target directory
  -AddToPath         Add install dir to PATH without prompting
  -NoPathUpdate      Do not modify PATH
  -Help              Show this help
"@ | Write-Host
}

function Resolve-Phase {
    param([string]$RawPhase)

    if ([string]::IsNullOrWhiteSpace($RawPhase)) {
        return "install"
    }

    switch ($RawPhase.ToLowerInvariant()) {
        "phase1" { return "test" }
        "test" { return "test" }
        "phase2" { return "install" }
        "install" { return "install" }
        "phase3" { return "upgrade" }
        "upgrade" { return "upgrade" }
        "phase4" { return "remove" }
        "remove" { return "remove" }
        "help" { return "help" }
        "-h" { return "help" }
        "--help" { return "help" }
        default { throw "Unknown phase '$RawPhase'. Use phase1|phase2|phase3|phase4 or test|install|upgrade|remove." }
    }
}

function ConvertTo-NormalizedPath {
    param([string]$Value)

    if ([string]::IsNullOrWhiteSpace($Value)) {
        return ""
    }

    $expanded = [Environment]::ExpandEnvironmentVariables($Value).Trim()
    if ($expanded.Length -gt 3) {
        $expanded = $expanded.TrimEnd("\")
    }
    return $expanded.ToLowerInvariant()
}

function Get-DefaultInstallDir {
    if (-not [string]::IsNullOrWhiteSpace($env:NETPROBE_RS_INSTALL_DIR)) {
        return $env:NETPROBE_RS_INSTALL_DIR
    }
    return (Join-Path $HOME ".local\bin")
}

function Get-ReleaseBinaryPath {
    $primary = Join-Path $RootDir "target\release\netprobe-rs.exe"
    $fallback = Join-Path $RootDir "target\release\netprobe-rs"
    if (Test-Path $primary) { return $primary }
    if (Test-Path $fallback) { return $fallback }
    throw "Release binary not found. Expected: $primary"
}

function Build-ReleaseBinary {
    $cargo = Get-Command cargo -ErrorAction SilentlyContinue
    if (-not $cargo) {
        throw "cargo was not found in PATH. Install Rust toolchain first: https://rustup.rs/"
    }

    Write-Host "Building netprobe-rs (release)..."
    & $cargo.Source build --release --manifest-path $Manifest
    if ($LASTEXITCODE -ne 0) {
        throw "cargo build failed with exit code $LASTEXITCODE"
    }

    return (Get-ReleaseBinaryPath)
}

function Request-InstallDir {
    param([string]$Provided)

    if (-not [string]::IsNullOrWhiteSpace($Provided)) {
        return $Provided
    }

    $defaultDir = Get-DefaultInstallDir
    Write-Host "Install target:"
    Write-Host "1) $defaultDir"
    Write-Host "2) custom path"
    $choice = Read-Host "Choose [1/2] (default: 1)"
    if ($choice -eq "2") {
        $customDir = Read-Host "Enter custom install directory"
        if ([string]::IsNullOrWhiteSpace($customDir)) {
            throw "Custom install directory cannot be empty."
        }
        return $customDir
    }
    return $defaultDir
}

function Get-PathUpdateMode {
    if ($AddToPath -and $NoPathUpdate) {
        throw "-AddToPath and -NoPathUpdate cannot be used together."
    }

    if ($AddToPath) { return "yes" }
    if ($NoPathUpdate) { return "no" }
    return "ask"
}

function Test-UserPathContains {
    param([string]$Directory)

    $target = ConvertTo-NormalizedPath $Directory
    $userPath = [Environment]::GetEnvironmentVariable("Path", "User")
    if ([string]::IsNullOrWhiteSpace($userPath)) {
        return $false
    }

    foreach ($entry in ($userPath -split ";")) {
        if ((ConvertTo-NormalizedPath $entry) -eq $target) {
            return $true
        }
    }

    return $false
}

function Add-DirectoryToUserPath {
    param([string]$Directory)

    if (Test-UserPathContains $Directory) {
        Write-Host "PATH already contains $Directory"
        return
    }

    $userPath = [Environment]::GetEnvironmentVariable("Path", "User")
    $newPath = if ([string]::IsNullOrWhiteSpace($userPath)) {
        $Directory
    } else {
        "$userPath;$Directory"
    }

    [Environment]::SetEnvironmentVariable("Path", $newPath, "User")
    if (-not (($env:Path -split ";") | Where-Object { (ConvertTo-NormalizedPath $_) -eq (ConvertTo-NormalizedPath $Directory) })) {
        $env:Path = "$env:Path;$Directory"
    }
    Write-Host "Added '$Directory' to user PATH."
}

function Remove-DirectoryFromUserPath {
    param([string]$Directory)

    $target = ConvertTo-NormalizedPath $Directory
    $userPath = [Environment]::GetEnvironmentVariable("Path", "User")
    if ([string]::IsNullOrWhiteSpace($userPath)) {
        return
    }

    $entries = @()
    foreach ($entry in ($userPath -split ";")) {
        if ([string]::IsNullOrWhiteSpace($entry)) {
            continue
        }
        if ((ConvertTo-NormalizedPath $entry) -ne $target) {
            $entries += $entry
        }
    }

    [Environment]::SetEnvironmentVariable("Path", ($entries -join ";"), "User")
    $env:Path = (($env:Path -split ";") | Where-Object {
        (ConvertTo-NormalizedPath $_) -ne $target
    }) -join ";"
    Write-Host "Removed '$Directory' from user PATH."
}

function Invoke-AddToPath {
    param([string]$Directory, [string]$Mode)

    if ($Mode -eq "no") {
        Write-Host "Skipped PATH update."
        return
    }

    $doAdd = $false
    if ($Mode -eq "yes") {
        $doAdd = $true
    } else {
        $answer = Read-Host "Add '$Directory' to PATH? [Y/n]"
        $doAdd = ($answer -notmatch "^(n|N)$")
    }

    if ($doAdd) {
        Add-DirectoryToUserPath $Directory
    } else {
        Write-Host "Skipped PATH update."
    }
}

function Invoke-RemoveFromPath {
    param([string]$Directory, [string]$Mode)

    if (-not (Test-UserPathContains $Directory)) {
        return
    }

    if ($Mode -eq "no") {
        return
    }

    $doRemove = $false
    if ($Mode -eq "yes") {
        $doRemove = $true
    } else {
        $answer = Read-Host "Remove '$Directory' from PATH? [y/N]"
        $doRemove = ($answer -match "^(y|Y)$")
    }

    if ($doRemove) {
        Remove-DirectoryFromUserPath $Directory
    }
}

function Install-BinaryToDirectory {
    param([string]$TargetDir)

    $source = Build-ReleaseBinary
    New-Item -ItemType Directory -Force -Path $TargetDir | Out-Null
    $dest = Join-Path $TargetDir "netprobe-rs.exe"
    Copy-Item -Path $source -Destination $dest -Force
    Write-Host "Installed: $dest"
}

function Resolve-InstalledBinaryPath {
    param([string]$ExplicitInstallDir)

    if (-not [string]::IsNullOrWhiteSpace($ExplicitInstallDir)) {
        return (Join-Path $ExplicitInstallDir "netprobe-rs.exe")
    }

    $command = Get-Command netprobe-rs -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($command -and $command.Source) {
        return $command.Source
    }

    return (Join-Path (Get-DefaultInstallDir) "netprobe-rs.exe")
}

$normalizedPhase = if ($Help) { "help" } else { Resolve-Phase $Phase }
if ($normalizedPhase -eq "help") {
    Show-Usage
    exit 0
}

if ($normalizedPhase -eq "remove" -and $AddToPath) {
    throw "-AddToPath is not valid with remove phase. Use -NoPathUpdate or omit PATH flags."
}

$pathMode = Get-PathUpdateMode

switch ($normalizedPhase) {
    "test" {
        $source = Build-ReleaseBinary
        $buildDir = Join-Path $RootDir "build-windows"
        New-Item -ItemType Directory -Force -Path $buildDir | Out-Null
        $dest = Join-Path $buildDir "netprobe-rs.exe"
        Copy-Item -Path $source -Destination $dest -Force
        Write-Host "Test binary ready: $dest"
    }
    "install" {
        $targetDir = Request-InstallDir $InstallDir
        Install-BinaryToDirectory $targetDir
        Invoke-AddToPath $targetDir $pathMode
    }
    "upgrade" {
        $installedBinary = Resolve-InstalledBinaryPath $InstallDir
        $targetDir = Split-Path -Parent $installedBinary
        Install-BinaryToDirectory $targetDir
        Invoke-AddToPath $targetDir $pathMode
        Write-Host "Upgrade complete."
    }
    "remove" {
        $installedBinary = Resolve-InstalledBinaryPath $InstallDir
        $targetDir = Split-Path -Parent $installedBinary
        if (Test-Path $installedBinary) {
            Remove-Item -Force $installedBinary
            Write-Host "Removed: $installedBinary"
        } else {
            Write-Host "No installed binary found at: $installedBinary"
        }
        Invoke-RemoveFromPath $targetDir $pathMode
    }
}


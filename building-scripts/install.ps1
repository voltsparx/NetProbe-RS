# Flow sketch: action selection -> build/install action -> CLI availability
# Pseudo-block:
#   choose action -> execute action -> verify output
# PowerShell here acts like a librarian with admin keys.

param(
    [string]$Action = "",
    [string]$InstallDir = "",
    [switch]$InstallDeps,
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
  .\building-scripts\install.ps1 [action] [options]

Actions:
  deps               Install build dependencies when winget/choco is available
  install            Install binary to local/custom bin and optionally add PATH
  update             Rebuild and replace existing installed binary
  test               Build a test binary into build-windows\ in repo root
  uninstall          Remove installed binary and optionally clean PATH entry

Prompt mode:
  Run without an action to choose from an interactive menu.

Compatibility aliases:
  phase1 -> test, phase2 -> install, phase3 -> update, phase4 -> uninstall
  upgrade -> update, remove -> uninstall, install-deps -> deps

Options:
  -InstallDir <dir>  Install/uninstall target directory
  -InstallDeps       Install build dependencies before install/update/test
  -AddToPath         Add install dir to PATH without prompting
  -NoPathUpdate      Do not modify PATH
  -Help              Show this help
"@ | Write-Host
}

function Resolve-Action {
    param([string]$RawAction)

    if ([string]::IsNullOrWhiteSpace($RawAction)) {
        return ""
    }

    switch ($RawAction.ToLowerInvariant()) {
        "phase1" { return "test" }
        "test" { return "test" }
        "phase2" { return "install" }
        "install" { return "install" }
        "phase3" { return "update" }
        "upgrade" { return "update" }
        "update" { return "update" }
        "phase4" { return "uninstall" }
        "remove" { return "uninstall" }
        "uninstall" { return "uninstall" }
        "deps" { return "deps" }
        "install-deps" { return "deps" }
        "help" { return "help" }
        "-h" { return "help" }
        "--help" { return "help" }
        default { throw "Unknown action '$RawAction'. Use install|update|test|uninstall." }
    }
}

function Request-Action {
    if ($Host.Name -match "ConsoleHost|Visual Studio Code Host") {
        Write-Host "Choose action:"
        Write-Host "1) install (local/custom + PATH prompt)"
        Write-Host "2) update"
        Write-Host "3) test"
        Write-Host "4) uninstall"
        Write-Host "5) deps (prepare build dependencies)"
        $choice = Read-Host "Choose [1/2/3/4/5] (default: 1)"
        switch ($choice) {
            "2" { return "update" }
            "3" { return "test" }
            "4" { return "uninstall" }
            "5" { return "deps" }
            default { return "install" }
        }
    }

    return "install"
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
    if (-not [string]::IsNullOrWhiteSpace($env:NPROBE_RS_INSTALL_DIR)) {
        return $env:NPROBE_RS_INSTALL_DIR
    }
    return (Join-Path $HOME ".local\bin")
}

function Get-ReleaseBinaryPath {
    $primary = Join-Path $RootDir "target\release\nprobe-rs.exe"
    $fallback = Join-Path $RootDir "target\release\nprobe-rs"
    if (Test-Path $primary) { return $primary }
    if (Test-Path $fallback) { return $fallback }
    throw "Release binary not found. Expected: $primary"
}

function Build-ReleaseBinary {
    if ($InstallDeps) {
        Ensure-WindowsBuildDeps
        $script:InstallDeps = $false
    }
    $cargo = Get-Command cargo -ErrorAction SilentlyContinue
    if (-not $cargo) {
        throw "cargo was not found in PATH. Install Rust toolchain first: https://rustup.rs/"
    }

    Write-Host "Building nprobe-rs (release)..."
    & $cargo.Source build --release --manifest-path $Manifest
    if ($LASTEXITCODE -ne 0) {
        throw "cargo build failed with exit code $LASTEXITCODE"
    }

    return (Get-ReleaseBinaryPath)
}

function Ensure-WindowsBuildDeps {
    $cargo = Get-Command cargo -ErrorAction SilentlyContinue
    if ($cargo) {
        Write-Host "Rust toolchain already available."
    } elseif (Get-Command winget -ErrorAction SilentlyContinue) {
        Write-Host "Installing Rust toolchain via winget..."
        winget install -e --id Rustlang.Rustup --accept-package-agreements --accept-source-agreements
    } elseif (Get-Command choco -ErrorAction SilentlyContinue) {
        Write-Host "Installing Rust toolchain via Chocolatey..."
        choco install -y rustup.install
    } else {
        throw "Neither cargo nor winget/choco is available. Install Rust from https://rustup.rs/ or install winget/choco first."
    }

    if (-not (Get-Command cargo -ErrorAction SilentlyContinue) -and (Test-Path "$HOME\.cargo\bin\cargo.exe")) {
        $env:Path = "$HOME\.cargo\bin;$env:Path"
    }
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
    $dest = Join-Path $TargetDir "nprobe-rs.exe"
    Copy-Item -Path $source -Destination $dest -Force
    Write-Host "Installed: $dest"
}

function Resolve-InstalledBinaryPath {
    param([string]$ExplicitInstallDir)

    if (-not [string]::IsNullOrWhiteSpace($ExplicitInstallDir)) {
        return (Join-Path $ExplicitInstallDir "nprobe-rs.exe")
    }

    $command = Get-Command nprobe-rs -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($command -and $command.Source) {
        return $command.Source
    }

    return (Join-Path (Get-DefaultInstallDir) "nprobe-rs.exe")
}

$normalizedAction = if ($Help) { "help" } else { Resolve-Action $Action }
if ($normalizedAction -eq "help") {
    Show-Usage
    exit 0
}

if ([string]::IsNullOrWhiteSpace($normalizedAction)) {
    $normalizedAction = Request-Action
}

$pathMode = Get-PathUpdateMode

switch ($normalizedAction) {
    "deps" {
        Ensure-WindowsBuildDeps
    }
    "test" {
        $source = Build-ReleaseBinary
        $buildDir = Join-Path $RootDir "build-windows"
        New-Item -ItemType Directory -Force -Path $buildDir | Out-Null
        $dest = Join-Path $buildDir "nprobe-rs.exe"
        Copy-Item -Path $source -Destination $dest -Force
        Write-Host "Test binary ready: $dest"
    }
    "install" {
        $targetDir = Request-InstallDir $InstallDir
        Install-BinaryToDirectory $targetDir
        Invoke-AddToPath $targetDir $pathMode
    }
    "update" {
        $installedBinary = Resolve-InstalledBinaryPath $InstallDir
        $targetDir = Split-Path -Parent $installedBinary
        Install-BinaryToDirectory $targetDir
        Invoke-AddToPath $targetDir $pathMode
        Write-Host "Update complete."
    }
    "uninstall" {
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


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
  uninstall          Remove installed binaries and optionally clean PATH entry

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
    if (-not [string]::IsNullOrWhiteSpace($env:LOCALAPPDATA)) {
        return (Join-Path $env:LOCALAPPDATA "Programs\nprobe-rs\bin")
    }
    return (Join-Path $HOME "AppData\Local\Programs\nprobe-rs\bin")
}

function Get-CargoBinDir {
    if (-not [string]::IsNullOrWhiteSpace($env:CARGO_HOME)) {
        return (Join-Path $env:CARGO_HOME "bin")
    }
    return (Join-Path $HOME ".cargo\bin")
}

function Test-IsCargoBinDir {
    param([string]$Directory)

    return (ConvertTo-NormalizedPath $Directory) -eq (ConvertTo-NormalizedPath (Get-CargoBinDir))
}

function Get-ReleaseBinaryPath {
    $primary = Join-Path $RootDir "target\release\nprobe-rs.exe"
    $fallback = Join-Path $RootDir "target\release\nprobe-rs"
    if (Test-Path $primary) { return $primary }
    if (Test-Path $fallback) { return $fallback }
    throw "Release binary not found. Expected: $primary"
}

function Get-ReleaseAliasBinaryPath {
    $primary = Join-Path $RootDir "target\release\nprs.exe"
    $fallback = Join-Path $RootDir "target\release\nprs"
    if (Test-Path $primary) { return $primary }
    if (Test-Path $fallback) { return $fallback }
    throw "Release alias binary not found. Expected: $primary"
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

    Write-Host "Building nprobe-rs and nprs (release)..."
    & $cargo.Source build --release --bins --manifest-path $Manifest
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
    $aliasSource = Get-ReleaseAliasBinaryPath
    New-Item -ItemType Directory -Force -Path $TargetDir | Out-Null
    $primary = Join-Path $TargetDir "nprobe-rs.exe"
    $alias = Join-Path $TargetDir "nprs.exe"
    Copy-Item -Path $source -Destination $primary -Force
    Copy-Item -Path $aliasSource -Destination $alias -Force
    Write-Host "Installed: $primary"
    Write-Host "Alias installed: $alias"
}

function Resolve-InstalledBinaryDirectory {
    param([string]$ExplicitInstallDir)

    if (-not [string]::IsNullOrWhiteSpace($ExplicitInstallDir)) {
        return $ExplicitInstallDir
    }

    $command = Get-Command nprobe-rs -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($command -and $command.Source) {
        return (Split-Path -Parent $command.Source)
    }

    $aliasCommand = Get-Command nprs -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($aliasCommand -and $aliasCommand.Source) {
        return (Split-Path -Parent $aliasCommand.Source)
    }

    $cargoBinDir = Get-CargoBinDir
    if ((Test-Path (Join-Path $cargoBinDir "nprobe-rs.exe")) -or (Test-Path (Join-Path $cargoBinDir "nprs.exe"))) {
        return $cargoBinDir
    }

    return (Get-DefaultInstallDir)
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
        $aliasSource = Get-ReleaseAliasBinaryPath
        $buildDir = Join-Path $RootDir "build-windows"
        New-Item -ItemType Directory -Force -Path $buildDir | Out-Null
        $dest = Join-Path $buildDir "nprobe-rs.exe"
        $alias = Join-Path $buildDir "nprs.exe"
        Copy-Item -Path $source -Destination $dest -Force
        Copy-Item -Path $aliasSource -Destination $alias -Force
        Write-Host "Test binary ready: $dest"
        Write-Host "Alias binary ready: $alias"
    }
    "install" {
        $targetDir = Request-InstallDir $InstallDir
        Install-BinaryToDirectory $targetDir
        Invoke-AddToPath $targetDir $pathMode
    }
    "update" {
        $targetDir = Resolve-InstalledBinaryDirectory $InstallDir
        Install-BinaryToDirectory $targetDir
        Invoke-AddToPath $targetDir $pathMode
        Write-Host "Update complete."
    }
    "uninstall" {
        $targetDir = Resolve-InstalledBinaryDirectory $InstallDir
        $installedBinary = Join-Path $targetDir "nprobe-rs.exe"
        $aliasBinary = Join-Path $targetDir "nprs.exe"
        $removed = $false
        if (Test-Path $installedBinary) {
            Remove-Item -Force $installedBinary
            Write-Host "Removed: $installedBinary"
            $removed = $true
        }
        if (Test-Path $aliasBinary) {
            Remove-Item -Force $aliasBinary
            Write-Host "Removed: $aliasBinary"
            $removed = $true
        }
        if (-not $removed) {
            Write-Host "No installed binaries found in: $targetDir"
        }
        if (Test-IsCargoBinDir $targetDir) {
            Write-Host "Skipped PATH removal for Cargo bin directory: $targetDir"
        } else {
            Invoke-RemoveFromPath $targetDir $pathMode
        }
    }
}


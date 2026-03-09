use std::process::Command;
use std::sync::OnceLock;

static ELEVATED_NETWORK_PRIVILEGES: OnceLock<bool> = OnceLock::new();

pub fn has_elevated_network_privileges() -> bool {
    *ELEVATED_NETWORK_PRIVILEGES.get_or_init(detect_elevated_network_privileges)
}

fn detect_elevated_network_privileges() -> bool {
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    {
        if let Some(uid) = std::env::var_os("EUID").or_else(|| std::env::var_os("UID")) {
            if uid.to_string_lossy().trim() == "0" {
                return true;
            }
        }

        return Command::new("id")
            .arg("-u")
            .output()
            .ok()
            .filter(|output| output.status.success())
            .and_then(|output| String::from_utf8(output.stdout).ok())
            .is_some_and(|stdout| stdout.trim() == "0");
    }

    #[cfg(windows)]
    {
        const SCRIPT: &str = "$ErrorActionPreference='Stop'; $p = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent()); if ($p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { '1' } else { '0' }";
        for shell in ["powershell.exe", "pwsh.exe"] {
            if let Ok(output) = Command::new(shell)
                .args(["-NoProfile", "-NonInteractive", "-Command", SCRIPT])
                .output()
            {
                if !output.status.success() {
                    continue;
                }
                if let Ok(stdout) = String::from_utf8(output.stdout) {
                    return stdout.trim() == "1";
                }
            }
        }
        return false;
    }

    #[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
    {
        false
    }
}

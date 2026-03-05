// Flow sketch: input -> core processing -> output model
// Pseudo-block:
//   read input -> process safely -> return deterministic output
// this file is traffic control for the whole scanner.

mod cli;
mod config;
mod core;
mod engine_async;
mod engine_intel;
mod engine_packet;
mod engine_parallel;
mod engine_plugin;
mod engine_probe;
mod engine_report;
mod engines;
mod error;
mod fingerprint_db;
mod models;
mod output;
mod reporter;
mod scheduler;
mod service_db;
mod tasks;
mod utils;

#[cfg(unix)]
use std::ffi::OsStr;
use std::ffi::OsString;
#[cfg(unix)]
use std::path::Path;
#[cfg(unix)]
use std::process::{Command, ExitStatus};

use crate::cli::Cli;
use crate::error::{NProbeError, NProbeResult};
use crate::models::ScanRequest;

#[tokio::main]
async fn main() {
    if let Err(err) = run().await {
        eprintln!("error: {err}");
        std::process::exit(1);
    }
}

async fn run() -> NProbeResult<()> {
    if let Some(help_text) = cli::maybe_render_quick_help_mode() {
        println!("{help_text}");
        return Ok(());
    }

    if let Some(explain_text) = cli::maybe_render_flag_help_mode() {
        println!("{explain_text}");
        return Ok(());
    }

    if let Some(explain_text) = cli::maybe_render_flag_explain_mode() {
        println!("{explain_text}");
        return Ok(());
    }

    let raw_args: Vec<OsString> = std::env::args_os().collect();
    let cli = Cli::parse_normalized();
    let mut request = cli.into_request()?;
    config::apply_defaults(&mut request)?;

    maybe_reexec_with_root(&request, &raw_args[1..])?;

    config::init_and_update(&request)?;
    core::orchestrator::run_scan(request).await?;
    Ok(())
}

fn maybe_reexec_with_root(request: &ScanRequest, raw_args: &[OsString]) -> NProbeResult<()> {
    #[cfg(not(unix))]
    let _ = raw_args;

    if !request.requires_root() || has_root_privileges() {
        return Ok(());
    }

    #[cfg(unix)]
    {
        if !has_interactive_tty() {
            return Err(NProbeError::Safety(
                "root privileges are required, but no interactive terminal is available for password prompt. Re-run with sudo/su manually."
                    .to_string(),
            ));
        }

        let exe = std::env::current_exe()?;

        if is_termux_env() {
            let command_line = build_shell_command(&exe, raw_args);
            let status = Command::new("su").arg("-c").arg(command_line).status()?;
            exit_with_status(status);
        }

        match Command::new("sudo").arg(&exe).args(raw_args).status() {
            Ok(status) => exit_with_status(status),
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
                match Command::new("doas").arg(&exe).args(raw_args).status() {
                    Ok(status) => exit_with_status(status),
                    Err(fallback) if fallback.kind() == std::io::ErrorKind::NotFound => {
                        return Err(NProbeError::Safety(
                            "root privileges are required but neither 'sudo' nor 'doas' was found. Run as root manually."
                                .to_string(),
                        ));
                    }
                    Err(fallback) => return Err(NProbeError::Io(fallback)),
                }
            }
            Err(err) => return Err(NProbeError::Io(err)),
        }
    }

    #[cfg(not(unix))]
    {
        Err(NProbeError::Safety(
            "this scan mode requires elevated privileges. Re-run from an admin shell.".to_string(),
        ))
    }
}

#[cfg(unix)]
fn has_interactive_tty() -> bool {
    use std::io::IsTerminal;
    std::io::stdin().is_terminal() && std::io::stderr().is_terminal()
}

#[cfg(unix)]
fn build_shell_command(exe: &Path, args: &[OsString]) -> String {
    let mut parts = Vec::with_capacity(args.len() + 1);
    parts.push(shell_quote(exe.as_os_str()));
    for arg in args {
        parts.push(shell_quote(arg));
    }
    parts.join(" ")
}

#[cfg(unix)]
fn shell_quote(value: &OsStr) -> String {
    let s = value.to_string_lossy();
    format!("'{}'", s.replace('\'', "'\\''"))
}

#[cfg(unix)]
fn exit_with_status(status: ExitStatus) -> ! {
    std::process::exit(status.code().unwrap_or(1));
}

fn has_root_privileges() -> bool {
    #[cfg(unix)]
    {
        if let Some(uid) = std::env::var_os("EUID").or_else(|| std::env::var_os("UID")) {
            if uid.to_string_lossy().trim() == "0" {
                return true;
            }
        }

        if let Ok(output) = Command::new("id").arg("-u").output() {
            if output.status.success() {
                return String::from_utf8_lossy(&output.stdout).trim() == "0";
            }
        }

        false
    }

    #[cfg(not(unix))]
    {
        false
    }
}

#[cfg(unix)]
fn is_termux_env() -> bool {
    if std::env::var_os("TERMUX_VERSION").is_some() {
        return true;
    }

    std::env::var_os("PREFIX")
        .map(|value| {
            value
                .to_string_lossy()
                .to_ascii_lowercase()
                .contains("com.termux")
        })
        .unwrap_or(false)
}

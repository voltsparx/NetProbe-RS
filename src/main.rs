// Flow sketch: input -> core processing -> output model
// Pseudo-block:
//   read input -> process safely -> return deterministic output
// this file is traffic control for the whole scanner.

mod cli;
mod config;
mod core;
mod engine_async;
mod engine_gpu;
mod engine_intel;
mod engine_packet;
mod engine_parallel;
mod engine_plugin;
mod engine_probe;
mod engine_report;
mod engines;
mod error;
mod fetchers;
mod fingerprint_db;
mod models;
mod os_fingerprint_db;
mod output;
mod platform;
mod reporter;
mod scan_types;
mod scheduler;
mod service_db;
mod targeting;
mod tasks;
mod utils;

#[cfg(unix)]
use std::ffi::OsStr;
use std::ffi::OsString;
#[cfg(unix)]
use std::path::Path;
#[cfg(unix)]
use std::process::{Command, ExitStatus};

use crate::cli::{Cli, CliAction, IntegrityCommand, SessionCommand};
use crate::error::{NProbeError, NProbeResult};
use crate::models::ScanRequest;
use crate::platform::self_integrity;

#[tokio::main]
async fn main() {
    if let Err(err) = run().await {
        eprintln!("{}", err.user_message());
        std::process::exit(1);
    }
}

async fn run() -> NProbeResult<()> {
    core::stop_signal::reset();
    core::stop_signal::install_ctrlc_handler()
        .map_err(|err| NProbeError::Config(format!("failed to install Ctrl+C handler: {err}")))?;

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

    if let Some(scan_type_text) = cli::maybe_render_scan_type_mode() {
        println!("{scan_type_text}");
        return Ok(());
    }

    if let Some(err) = cli::maybe_reject_cataloged_scan_mode() {
        return Err(err);
    }

    let cli = Cli::parse_normalized();
    let action = cli.into_action()?;

    if let CliAction::Integrity(command) = action {
        let status = match command {
            IntegrityCommand::Status => self_integrity::status()?,
            IntegrityCommand::Reseal => self_integrity::reseal_trusted_baseline()?,
        };
        println!("{}", cli::render_integrity_status(&status));
        return Ok(());
    }

    let integrity_status = self_integrity::enforce_startup()?;
    self_integrity::publish_runtime_status(&integrity_status);

    match action {
        CliAction::Integrity(_) => unreachable!("integrity action handled above"),
        CliAction::Sessions(SessionCommand::List { limit, filters }) => {
            let records = config::list_scan_sessions_filtered(limit, &filters)?;
            println!("{}", cli::render_session_list(&records, &filters));
            Ok(())
        }
        CliAction::Sessions(SessionCommand::Show { session_id }) => {
            let Some(record) = config::load_scan_session(&session_id)? else {
                return Err(NProbeError::Cli(format!(
                    "session '{session_id}' was not found"
                )));
            };
            println!("{}", cli::render_session_detail(&record));
            Ok(())
        }
        CliAction::Sessions(SessionCommand::Diff {
            older_session_id,
            newer_session_id,
            session_filters,
            ip_filter,
            target_filter,
            severity_filter,
            report_format,
            output_path,
        }) => {
            let diff = config::diff_session_actionables(
                &older_session_id,
                &newer_session_id,
                &session_filters,
                ip_filter.as_deref(),
                target_filter.as_deref(),
                severity_filter,
            )?;
            let body = match report_format {
                crate::models::ReportFormat::Txt | crate::models::ReportFormat::Cli => {
                    cli::render_session_diff(&diff)
                }
                crate::models::ReportFormat::Json => cli::render_session_diff_json(&diff)?,
                crate::models::ReportFormat::Html => cli::render_session_diff_html(&diff),
                crate::models::ReportFormat::Csv => unreachable!("session diff csv blocked in CLI"),
            };
            output::emit(&body, report_format, output_path.as_deref()).await?;
            Ok(())
        }
        CliAction::Scan(mut request) => {
            let raw_args: Vec<OsString> = std::env::args_os().collect();
            config::apply_defaults(&mut request)?;

            maybe_reexec_with_root(&request, &raw_args[1..])?;

            config::ensure_session_id(&mut request);
            config::init_and_update(&request)?;
            let mut session = config::start_scan_session(&request)?;
            let request = *request;

            match core::orchestrator::run_scan(request).await {
                Ok(report) => {
                    let interrupted = core::stop_signal::should_stop();
                    config::complete_scan_session(&mut session, &report, interrupted)?;
                    Ok(())
                }
                Err(err) => {
                    let interrupted = core::stop_signal::should_stop();
                    let _ = config::fail_scan_session(&mut session, &err, interrupted);
                    Err(err)
                }
            }
        }
    }
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

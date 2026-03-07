// Flow sketch: input -> core processing -> output model
// Pseudo-block:
//   read input -> process safely -> return deterministic output

use thiserror::Error;

pub type NProbeResult<T> = Result<T, NProbeError>;

#[derive(Debug, Error)]
pub enum NProbeError {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("csv error: {0}")]
    Csv(#[from] csv::Error),
    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("lua error: {0}")]
    Lua(#[from] mlua::Error),
    #[error("task join error: {0}")]
    Join(#[from] tokio::task::JoinError),
    #[error("cli error: {0}")]
    Cli(String),
    #[error("parse error: {0}")]
    Parse(String),
    #[error("safety check blocked scan: {0}")]
    Safety(String),
    #[error("config error: {0}")]
    Config(String),
}

impl NProbeError {
    pub fn category(&self) -> &'static str {
        match self {
            NProbeError::Io(_) => "io",
            NProbeError::Csv(_) | NProbeError::Json(_) => "data-format",
            NProbeError::Lua(_) => "script-runtime",
            NProbeError::Join(_) => "task-runtime",
            NProbeError::Cli(_) => "operator-input",
            NProbeError::Parse(_) => "input-parse",
            NProbeError::Safety(_) => "safety-guardrail",
            NProbeError::Config(_) => "configuration",
        }
    }

    pub fn recovery_hint(&self) -> &'static str {
        match self {
            NProbeError::Io(_) => "verify filesystem or device access, then retry the scan",
            NProbeError::Csv(_) | NProbeError::Json(_) => {
                "repair or replace malformed data files before retrying"
            }
            NProbeError::Lua(_) => "disable or fix the Lua hook, then rerun the scan",
            NProbeError::Join(_) => "retry the scan and inspect task panic paths if it repeats",
            NProbeError::Cli(_) => "correct the CLI flags or arguments and retry",
            NProbeError::Parse(_) => "correct the target, port selection, or input format",
            NProbeError::Safety(_) => {
                "adjust target scope or explicit safety flags to satisfy guardrails"
            }
            NProbeError::Config(_) => {
                "inspect configuration and session files under .nprobe-rs-config"
            }
        }
    }

    pub fn friendly_title(&self) -> &'static str {
        match self {
            NProbeError::Cli(_) | NProbeError::Parse(_) => {
                "NProbe-RS paused before starting the scan."
            }
            NProbeError::Safety(_) => {
                "NProbe-RS stopped this run to protect the target, the network, or your system."
            }
            NProbeError::Config(_) => {
                "NProbe-RS could not use part of its saved configuration or runtime state."
            }
            NProbeError::Io(_) | NProbeError::Csv(_) | NProbeError::Json(_) => {
                "NProbe-RS hit an environment or data problem while working."
            }
            NProbeError::Lua(_) => "A script component failed while the framework was running.",
            NProbeError::Join(_) => {
                "A background task stopped unexpectedly while the framework was running."
            }
        }
    }

    pub fn friendly_detail(&self) -> String {
        match self {
            NProbeError::Io(message) => format!("I/O detail: {message}"),
            NProbeError::Csv(message) => format!("CSV detail: {message}"),
            NProbeError::Json(message) => format!("JSON detail: {message}"),
            NProbeError::Lua(message) => format!("Lua detail: {message}"),
            NProbeError::Join(message) => format!("Task detail: {message}"),
            NProbeError::Cli(message)
            | NProbeError::Parse(message)
            | NProbeError::Safety(message)
            | NProbeError::Config(message) => message.clone(),
        }
    }

    pub fn user_message(&self) -> String {
        format!(
            "{}\nWhat went wrong: {}\nWhat you can do next: {}.",
            self.friendly_title(),
            self.friendly_detail(),
            self.recovery_hint()
        )
    }
}

use thiserror::Error;

pub type NetProbeResult<T> = Result<T, NetProbeError>;

#[derive(Debug, Error)]
pub enum NetProbeError {
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

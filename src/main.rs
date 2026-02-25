mod ai;
mod cli;
mod config;
mod engines;
mod error;
mod fingerprint_db;
mod models;
mod output;
mod scheduler;
mod service_db;
mod tasks;

use clap::Parser;

use crate::cli::Cli;
use crate::error::NetProbeResult;

#[tokio::main]
async fn main() {
    if let Err(err) = run().await {
        eprintln!("error: {err}");
        std::process::exit(1);
    }
}

async fn run() -> NetProbeResult<()> {
    let cli = Cli::parse();
    let mut request = cli.into_request()?;
    config::apply_defaults(&mut request)?;
    config::init_and_update(&request)?;
    scheduler::run_scan(request).await?;
    Ok(())
}

// Flow sketch: scan report -> renderer -> user-facing output
// Pseudo-block:
//   read input -> process safely -> return deterministic output

use std::path::Path;

use crate::engines::thread_pool;
use crate::error::NProbeResult;
use crate::models::{ReportFormat, ScanReport};

pub mod cli;
pub mod csv;
pub mod html;
pub mod json;
pub mod txt;

pub fn render(report: &ScanReport, format: ReportFormat) -> NProbeResult<String> {
    match format {
        ReportFormat::Cli => Ok(cli::render(report)),
        ReportFormat::Txt => Ok(txt::render(report)),
        ReportFormat::Json => json::render(report),
        ReportFormat::Html => Ok(html::render(report)),
        ReportFormat::Csv => csv::render(report),
    }
}

pub async fn emit(
    body: &str,
    format: ReportFormat,
    output_path: Option<&Path>,
) -> NProbeResult<()> {
    match output_path {
        Some(path) => {
            thread_pool::write_output(path, body).await?;
            if matches!(format, ReportFormat::Cli) {
                println!("{body}");
            } else {
                println!("report written: {}", path.display());
            }
        }
        None => println!("{body}"),
    }
    Ok(())
}


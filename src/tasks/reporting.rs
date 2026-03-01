// Flow sketch: host target -> task pipeline -> enriched host result
// Pseudo-block:
//   read input -> process safely -> return deterministic output

use std::path::Path;

use crate::error::NetProbeResult;
use crate::models::{ReportFormat, ScanReport};
use crate::output;

pub async fn run(
    report: &ScanReport,
    format: ReportFormat,
    output_path: Option<&Path>,
) -> NetProbeResult<()> {
    let rendered = output::render(report, format)?;
    output::emit(&rendered, format, output_path).await
}


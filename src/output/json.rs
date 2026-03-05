// Flow sketch: scan report -> renderer -> user-facing output
// Pseudo-block:
//   read input -> process safely -> return deterministic output

use crate::error::NProbeResult;
use crate::models::ScanReport;

pub fn render(report: &ScanReport) -> NProbeResult<String> {
    Ok(serde_json::to_string_pretty(report)?)
}

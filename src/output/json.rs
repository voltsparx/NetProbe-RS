use crate::error::NetProbeResult;
use crate::models::ScanReport;

pub fn render(report: &ScanReport) -> NetProbeResult<String> {
    Ok(serde_json::to_string_pretty(report)?)
}

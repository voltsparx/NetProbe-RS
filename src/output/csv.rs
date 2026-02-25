use crate::error::{NetProbeError, NetProbeResult};
use crate::models::ScanReport;
use serde::Serialize;

#[derive(Debug, Serialize)]
struct Row {
    target: String,
    ip: String,
    port: u16,
    protocol: String,
    state: String,
    service: String,
    reason: String,
    matched_by: String,
    confidence: String,
    educational_note: String,
    risk_score: u8,
}

pub fn render(report: &ScanReport) -> NetProbeResult<String> {
    let mut writer = csv::Writer::from_writer(Vec::new());

    for host in &report.hosts {
        for port in &host.ports {
            let row = Row {
                target: host.target.clone(),
                ip: host.ip.clone(),
                port: port.port,
                protocol: port.protocol.clone(),
                state: port.state.to_string(),
                service: port
                    .service
                    .clone()
                    .unwrap_or_else(|| "unknown".to_string()),
                reason: port.reason.clone(),
                matched_by: port
                    .matched_by
                    .clone()
                    .unwrap_or_else(|| "unknown".to_string()),
                confidence: port
                    .confidence
                    .map(|v| format!("{v:.2}"))
                    .unwrap_or_else(|| "n/a".to_string()),
                educational_note: port.educational_note.clone().unwrap_or_default(),
                risk_score: host.risk_score,
            };
            writer.serialize(row)?;
        }
    }

    let bytes = writer.into_inner().map_err(|err| err.into_error())?;
    String::from_utf8(bytes)
        .map_err(|err| NetProbeError::Parse(format!("utf8 conversion failed: {err}")))
}

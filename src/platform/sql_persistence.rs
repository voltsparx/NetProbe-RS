use std::path::Path;

use rusqlite::{params, Connection, OptionalExtension};

use crate::config::{ScanSessionRecord, ShardCheckpointState};
use crate::error::{NProbeError, NProbeResult};
use crate::models::HostResult;
use crate::reporter::actionable::{self, ActionableSeverity};
use crate::reporter::service_intelligence;

#[derive(Debug, Clone)]
pub struct ActionableSnapshotRecord {
    pub ip: String,
    pub target: String,
    pub severity: ActionableSeverity,
    pub issue: String,
    pub action: String,
}

const DB_FILE_NAME: &str = "nprobe-state.sqlite3";

pub fn database_path(config_dir: &Path) -> std::path::PathBuf {
    config_dir.join(DB_FILE_NAME)
}

pub fn upsert_runtime_kv_bulk<'a, I>(
    db_path: &Path,
    entries: I,
    updated_at: &str,
) -> NProbeResult<()>
where
    I: IntoIterator<Item = (&'a String, &'a String)>,
{
    let mut conn = open(db_path)?;
    let tx = conn.transaction().map_err(sql_err)?;
    {
        let mut stmt = tx
            .prepare(
                "INSERT INTO runtime_kv(key, value, updated_at) VALUES (?1, ?2, ?3)
                 ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at",
            )
            .map_err(sql_err)?;
        for (key, value) in entries {
            stmt.execute(params![key, value, updated_at])
                .map_err(sql_err)?;
        }
    }
    tx.commit().map_err(sql_err)?;
    Ok(())
}

pub fn save_session(db_path: &Path, record: &ScanSessionRecord) -> NProbeResult<()> {
    let conn = open(db_path)?;
    let json = serde_json::to_string(record)?;
    conn.execute(
        "INSERT INTO scan_sessions(session_id, status, updated_at, target, payload_json)
         VALUES (?1, ?2, ?3, ?4, ?5)
         ON CONFLICT(session_id) DO UPDATE SET
             status = excluded.status,
             updated_at = excluded.updated_at,
             target = excluded.target,
             payload_json = excluded.payload_json",
        params![
            record.session_id,
            record.status.as_str(),
            record.updated_at,
            record.target,
            json
        ],
    )
    .map_err(sql_err)?;
    Ok(())
}

pub fn list_sessions(db_path: &Path, limit: usize) -> NProbeResult<Vec<ScanSessionRecord>> {
    let conn = open(db_path)?;
    load_session_rows(
        &conn,
        "SELECT payload_json
         FROM scan_sessions
         ORDER BY updated_at DESC, session_id DESC
         LIMIT ?1",
        Some(limit as i64),
    )
}

pub fn list_all_sessions(db_path: &Path) -> NProbeResult<Vec<ScanSessionRecord>> {
    let conn = open(db_path)?;
    load_session_rows(
        &conn,
        "SELECT payload_json
         FROM scan_sessions
         ORDER BY updated_at DESC, session_id DESC",
        None,
    )
}

fn load_session_rows(
    conn: &Connection,
    query: &str,
    limit: Option<i64>,
) -> NProbeResult<Vec<ScanSessionRecord>> {
    let mut stmt = conn.prepare(query).map_err(sql_err)?;
    let payloads = if let Some(limit) = limit {
        let rows = stmt
            .query_map(params![limit], |row| row.get::<_, String>(0))
            .map_err(sql_err)?;
        let mut payloads = Vec::new();
        for row in rows {
            payloads.push(row.map_err(sql_err)?);
        }
        payloads
    } else {
        let rows = stmt
            .query_map([], |row| row.get::<_, String>(0))
            .map_err(sql_err)?;
        let mut payloads = Vec::new();
        for row in rows {
            payloads.push(row.map_err(sql_err)?);
        }
        payloads
    };

    let mut records = Vec::new();
    for body in payloads {
        let record = serde_json::from_str::<ScanSessionRecord>(&body).map_err(|err| {
            NProbeError::Config(format!("failed to parse SQL session payload: {err}"))
        })?;
        records.push(record);
    }
    Ok(records)
}

pub fn load_session(db_path: &Path, session_id: &str) -> NProbeResult<Option<ScanSessionRecord>> {
    let conn = open(db_path)?;
    let body = conn
        .query_row(
            "SELECT payload_json FROM scan_sessions WHERE session_id = ?1",
            params![session_id],
            |row| row.get::<_, String>(0),
        )
        .optional()
        .map_err(sql_err)?;

    body.map(|raw| {
        serde_json::from_str::<ScanSessionRecord>(&raw).map_err(|err| {
            NProbeError::Config(format!("failed to parse SQL session payload: {err}"))
        })
    })
    .transpose()
}

pub fn save_checkpoint(db_path: &Path, state: &ShardCheckpointState) -> NProbeResult<()> {
    let conn = open(db_path)?;
    let json = serde_json::to_string(state)?;
    conn.execute(
        "INSERT INTO shard_checkpoints(signature, updated_at, target, shard_dimension, payload_json)
         VALUES (?1, ?2, ?3, ?4, ?5)
         ON CONFLICT(signature) DO UPDATE SET
             updated_at = excluded.updated_at,
             target = excluded.target,
             shard_dimension = excluded.shard_dimension,
             payload_json = excluded.payload_json",
        params![
            state.signature,
            state.updated_at,
            state.target,
            state.shard_dimension,
            json
        ],
    )
    .map_err(sql_err)?;
    Ok(())
}

pub fn load_checkpoint(
    db_path: &Path,
    signature: &str,
) -> NProbeResult<Option<ShardCheckpointState>> {
    let conn = open(db_path)?;
    let body = conn
        .query_row(
            "SELECT payload_json FROM shard_checkpoints WHERE signature = ?1",
            params![signature],
            |row| row.get::<_, String>(0),
        )
        .optional()
        .map_err(sql_err)?;

    body.map(|raw| {
        serde_json::from_str::<ShardCheckpointState>(&raw).map_err(|err| {
            NProbeError::Config(format!("failed to parse SQL checkpoint payload: {err}"))
        })
    })
    .transpose()
}

pub fn delete_checkpoint(db_path: &Path, signature: &str) -> NProbeResult<()> {
    let conn = open(db_path)?;
    conn.execute(
        "DELETE FROM shard_checkpoints WHERE signature = ?1",
        params![signature],
    )
    .map_err(sql_err)?;
    Ok(())
}

pub struct HostSnapshotWriter {
    conn: Connection,
}

impl HostSnapshotWriter {
    pub fn open(db_path: &Path) -> NProbeResult<Self> {
        Ok(Self {
            conn: open(db_path)?,
        })
    }

    pub fn save(
        &mut self,
        session_id: &str,
        host: &HostResult,
        phase: &str,
        updated_at: &str,
    ) -> NProbeResult<()> {
        let payload_json = serde_json::to_string(host)?;
        let phantom_device_check = host.phantom_device_check_summary();
        let service_summary = service_intelligence::summarize_host(host);
        let service_summary_json = serde_json::to_string(&service_summary)?;
        let actionable_summary = actionable::summarize(host);
        let actionable_summary_json = serde_json::to_string(&actionable_summary)?;
        let open_ports = host
            .ports
            .iter()
            .filter(|port| {
                matches!(
                    port.state,
                    crate::models::PortState::Open | crate::models::PortState::OpenOrFiltered
                )
            })
            .count() as i64;
        let tx = self.conn.transaction().map_err(sql_err)?;
        tx.execute(
            "INSERT INTO host_snapshots(
                session_id, ip, updated_at, target, phase, device_class,
                phantom_stage, phantom_responsive_ports, phantom_sampled_ports,
                phantom_timeout_ports, phantom_avg_latency_ms, phantom_payload_budget,
                phantom_passive_follow_up, service_summary_json, service_count,
                identified_service_count, cpe_count, advisory_count,
                actionable_summary_json, actionable_count, actionable_critical_count,
                actionable_high_count, actionable_moderate_count, actionable_review_count,
                risk_score, open_ports, payload_json
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18, ?19, ?20, ?21, ?22, ?23, ?24, ?25, ?26, ?27)
             ON CONFLICT(session_id, ip) DO UPDATE SET
                updated_at = excluded.updated_at,
                target = excluded.target,
                phase = excluded.phase,
                device_class = excluded.device_class,
                phantom_stage = excluded.phantom_stage,
                phantom_responsive_ports = excluded.phantom_responsive_ports,
                phantom_sampled_ports = excluded.phantom_sampled_ports,
                phantom_timeout_ports = excluded.phantom_timeout_ports,
                phantom_avg_latency_ms = excluded.phantom_avg_latency_ms,
                phantom_payload_budget = excluded.phantom_payload_budget,
                phantom_passive_follow_up = excluded.phantom_passive_follow_up,
                service_summary_json = excluded.service_summary_json,
                service_count = excluded.service_count,
                identified_service_count = excluded.identified_service_count,
                cpe_count = excluded.cpe_count,
                advisory_count = excluded.advisory_count,
                actionable_summary_json = excluded.actionable_summary_json,
                actionable_count = excluded.actionable_count,
                actionable_critical_count = excluded.actionable_critical_count,
                actionable_high_count = excluded.actionable_high_count,
                actionable_moderate_count = excluded.actionable_moderate_count,
                actionable_review_count = excluded.actionable_review_count,
                risk_score = excluded.risk_score,
                open_ports = excluded.open_ports,
                payload_json = excluded.payload_json",
            params![
                session_id,
                host.ip,
                updated_at,
                host.target,
                phase,
                host.device_class.as_deref(),
                phantom_device_check
                    .as_ref()
                    .map(|summary| summary.stage.as_str()),
                phantom_device_check
                    .as_ref()
                    .and_then(|summary| summary.responsive_ports)
                    .map(|value| value as i64),
                phantom_device_check
                    .as_ref()
                    .and_then(|summary| summary.sampled_ports)
                    .map(|value| value as i64),
                phantom_device_check
                    .as_ref()
                    .and_then(|summary| summary.timeout_ports)
                    .map(|value| value as i64),
                phantom_device_check
                    .as_ref()
                    .and_then(|summary| summary.avg_latency_ms)
                    .map(|value| value as i64),
                phantom_device_check
                    .as_ref()
                    .and_then(|summary| summary.payload_budget)
                    .map(|value| value as i64),
                i64::from(
                    phantom_device_check
                        .as_ref()
                        .map(|summary| summary.passive_follow_up)
                        .unwrap_or(false),
                ),
                service_summary_json,
                service_summary.service_count as i64,
                service_summary.identified_service_count as i64,
                service_summary.cpe_count as i64,
                service_summary.advisory_count as i64,
                actionable_summary_json,
                actionable_summary.total as i64,
                actionable_summary.critical as i64,
                actionable_summary.high as i64,
                actionable_summary.moderate as i64,
                actionable_summary.review as i64,
                host.risk_score as i64,
                open_ports,
                payload_json
            ],
        )
        .map_err(sql_err)?;
        persist_service_snapshots(&tx, session_id, host, phase, updated_at, &service_summary)?;
        persist_actionable_snapshots(
            &tx,
            session_id,
            host,
            phase,
            updated_at,
            &actionable_summary,
        )?;
        tx.commit().map_err(sql_err)?;
        Ok(())
    }
}

fn persist_service_snapshots(
    tx: &rusqlite::Transaction<'_>,
    session_id: &str,
    host: &HostResult,
    phase: &str,
    updated_at: &str,
    summary: &service_intelligence::HostServiceKnowledgeSummary,
) -> NProbeResult<()> {
    tx.execute(
        "DELETE FROM service_snapshots WHERE session_id = ?1 AND ip = ?2",
        params![session_id, host.ip],
    )
    .map_err(sql_err)?;

    let mut stmt = tx
        .prepare(
            "INSERT INTO service_snapshots(
                session_id, ip, port, protocol, updated_at, target, phase, state,
                service, matched_by, confidence, label, product, version,
                hostname, operating_system, device_type, cpe_json, hints_json,
                observations_json, advice_json, learning_json
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18, ?19, ?20, ?21, ?22)
             ON CONFLICT(session_id, ip, port, protocol) DO UPDATE SET
                updated_at = excluded.updated_at,
                target = excluded.target,
                phase = excluded.phase,
                state = excluded.state,
                service = excluded.service,
                matched_by = excluded.matched_by,
                confidence = excluded.confidence,
                label = excluded.label,
                product = excluded.product,
                version = excluded.version,
                hostname = excluded.hostname,
                operating_system = excluded.operating_system,
                device_type = excluded.device_type,
                cpe_json = excluded.cpe_json,
                hints_json = excluded.hints_json,
                observations_json = excluded.observations_json,
                advice_json = excluded.advice_json,
                learning_json = excluded.learning_json",
        )
        .map_err(sql_err)?;

    for record in &summary.records {
        let identity = record.identity.as_ref();
        stmt.execute(params![
            session_id,
            host.ip,
            record.port as i64,
            record.protocol,
            updated_at,
            host.target,
            phase,
            record.state,
            record.service.as_deref(),
            record.matched_by.as_deref(),
            record.confidence,
            record.label,
            identity.and_then(|value| value.product.as_deref()),
            identity.and_then(|value| value.version.as_deref()),
            identity.and_then(|value| value.hostname.as_deref()),
            identity.and_then(|value| value.operating_system.as_deref()),
            identity.and_then(|value| value.device_type.as_deref()),
            serde_json::to_string(&identity.map(|value| value.cpes.clone()).unwrap_or_default())?,
            serde_json::to_string(&record.hints)?,
            serde_json::to_string(&record.observations)?,
            serde_json::to_string(&record.advice)?,
            serde_json::to_string(&record.learning)?,
        ])
        .map_err(sql_err)?;
    }

    Ok(())
}

fn persist_actionable_snapshots(
    tx: &rusqlite::Transaction<'_>,
    session_id: &str,
    host: &HostResult,
    phase: &str,
    updated_at: &str,
    summary: &actionable::ActionableSummary,
) -> NProbeResult<()> {
    tx.execute(
        "DELETE FROM actionable_snapshots WHERE session_id = ?1 AND ip = ?2",
        params![session_id, host.ip],
    )
    .map_err(sql_err)?;

    let mut stmt = tx
        .prepare(
            "INSERT INTO actionable_snapshots(
                session_id, ip, updated_at, target, phase, severity, issue, action
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
             ON CONFLICT(session_id, ip, severity, issue) DO UPDATE SET
                updated_at = excluded.updated_at,
                target = excluded.target,
                phase = excluded.phase,
                action = excluded.action",
        )
        .map_err(sql_err)?;

    for item in &summary.items {
        stmt.execute(params![
            session_id,
            host.ip,
            updated_at,
            host.target,
            phase,
            item.severity.as_str(),
            item.issue,
            item.action,
        ])
        .map_err(sql_err)?;
    }

    Ok(())
}

pub fn count_host_snapshots(db_path: &Path, session_id: &str) -> NProbeResult<usize> {
    let conn = open(db_path)?;
    let count = conn
        .query_row(
            "SELECT COUNT(*) FROM host_snapshots WHERE session_id = ?1",
            params![session_id],
            |row| row.get::<_, i64>(0),
        )
        .map_err(sql_err)?;
    Ok(count.max(0) as usize)
}

pub fn load_actionable_snapshots(
    db_path: &Path,
    session_id: &str,
) -> NProbeResult<Vec<ActionableSnapshotRecord>> {
    let conn = open(db_path)?;
    let mut stmt = conn
        .prepare(
            "SELECT ip, target, severity, issue, action
             FROM actionable_snapshots
             WHERE session_id = ?1
             ORDER BY ip ASC, severity DESC, issue ASC",
        )
        .map_err(sql_err)?;
    let rows = stmt
        .query_map(params![session_id], |row| {
            let severity_raw = row.get::<_, String>(2)?;
            let severity = ActionableSeverity::parse(&severity_raw).ok_or_else(|| {
                rusqlite::Error::FromSqlConversionFailure(
                    2,
                    rusqlite::types::Type::Text,
                    Box::new(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        format!("invalid actionable severity '{severity_raw}'"),
                    )),
                )
            })?;

            Ok(ActionableSnapshotRecord {
                ip: row.get(0)?,
                target: row.get(1)?,
                severity,
                issue: row.get(3)?,
                action: row.get(4)?,
            })
        })
        .map_err(sql_err)?;

    let mut records = Vec::new();
    for row in rows {
        records.push(row.map_err(sql_err)?);
    }
    Ok(records)
}

fn open(db_path: &Path) -> NProbeResult<Connection> {
    if let Some(parent) = db_path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let conn = Connection::open(db_path).map_err(sql_err)?;
    conn.pragma_update(None, "journal_mode", "WAL")
        .map_err(sql_err)?;
    conn.pragma_update(None, "synchronous", "NORMAL")
        .map_err(sql_err)?;
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS runtime_kv(
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL,
            updated_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS scan_sessions(
            session_id TEXT PRIMARY KEY,
            status TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            target TEXT NOT NULL,
            payload_json TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_scan_sessions_updated_at
            ON scan_sessions(updated_at DESC);
        CREATE TABLE IF NOT EXISTS shard_checkpoints(
            signature TEXT PRIMARY KEY,
            updated_at TEXT NOT NULL,
            target TEXT NOT NULL,
            shard_dimension TEXT NOT NULL,
            payload_json TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS host_snapshots(
            session_id TEXT NOT NULL,
            ip TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            target TEXT NOT NULL,
            phase TEXT NOT NULL,
            device_class TEXT,
            phantom_stage TEXT,
            phantom_responsive_ports INTEGER,
            phantom_sampled_ports INTEGER,
            phantom_timeout_ports INTEGER,
            phantom_avg_latency_ms INTEGER,
            phantom_payload_budget INTEGER,
            phantom_passive_follow_up INTEGER NOT NULL DEFAULT 0,
            service_summary_json TEXT,
            service_count INTEGER NOT NULL DEFAULT 0,
            identified_service_count INTEGER NOT NULL DEFAULT 0,
            cpe_count INTEGER NOT NULL DEFAULT 0,
            advisory_count INTEGER NOT NULL DEFAULT 0,
            actionable_summary_json TEXT,
            actionable_count INTEGER NOT NULL DEFAULT 0,
            actionable_critical_count INTEGER NOT NULL DEFAULT 0,
            actionable_high_count INTEGER NOT NULL DEFAULT 0,
            actionable_moderate_count INTEGER NOT NULL DEFAULT 0,
            actionable_review_count INTEGER NOT NULL DEFAULT 0,
            risk_score INTEGER NOT NULL,
            open_ports INTEGER NOT NULL,
            payload_json TEXT NOT NULL,
            PRIMARY KEY(session_id, ip)
        );
        CREATE TABLE IF NOT EXISTS service_snapshots(
            session_id TEXT NOT NULL,
            ip TEXT NOT NULL,
            port INTEGER NOT NULL,
            protocol TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            target TEXT NOT NULL,
            phase TEXT NOT NULL,
            state TEXT NOT NULL,
            service TEXT,
            matched_by TEXT,
            confidence REAL,
            label TEXT NOT NULL,
            product TEXT,
            version TEXT,
            hostname TEXT,
            operating_system TEXT,
            device_type TEXT,
            cpe_json TEXT NOT NULL,
            hints_json TEXT NOT NULL,
            observations_json TEXT NOT NULL,
            advice_json TEXT NOT NULL,
            learning_json TEXT NOT NULL,
            PRIMARY KEY(session_id, ip, port, protocol)
        );
        CREATE INDEX IF NOT EXISTS idx_service_snapshots_session_ip
            ON service_snapshots(session_id, ip);
        CREATE TABLE IF NOT EXISTS actionable_snapshots(
            session_id TEXT NOT NULL,
            ip TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            target TEXT NOT NULL,
            phase TEXT NOT NULL,
            severity TEXT NOT NULL,
            issue TEXT NOT NULL,
            action TEXT NOT NULL,
            PRIMARY KEY(session_id, ip, severity, issue)
        );
        CREATE INDEX IF NOT EXISTS idx_actionable_snapshots_session_ip
            ON actionable_snapshots(session_id, ip);",
    )
    .map_err(sql_err)?;
    ensure_host_snapshot_columns(&conn)?;
    Ok(conn)
}

fn ensure_host_snapshot_columns(conn: &Connection) -> NProbeResult<()> {
    let mut stmt = conn
        .prepare("PRAGMA table_info(host_snapshots)")
        .map_err(sql_err)?;
    let column_rows = stmt
        .query_map([], |row| row.get::<_, String>(1))
        .map_err(sql_err)?;
    let mut columns = Vec::new();
    for row in column_rows {
        columns.push(row.map_err(sql_err)?);
    }

    for (column, ddl) in [
        ("phantom_stage", "ALTER TABLE host_snapshots ADD COLUMN phantom_stage TEXT"),
        (
            "phantom_responsive_ports",
            "ALTER TABLE host_snapshots ADD COLUMN phantom_responsive_ports INTEGER",
        ),
        (
            "phantom_sampled_ports",
            "ALTER TABLE host_snapshots ADD COLUMN phantom_sampled_ports INTEGER",
        ),
        (
            "phantom_timeout_ports",
            "ALTER TABLE host_snapshots ADD COLUMN phantom_timeout_ports INTEGER",
        ),
        (
            "phantom_avg_latency_ms",
            "ALTER TABLE host_snapshots ADD COLUMN phantom_avg_latency_ms INTEGER",
        ),
        (
            "phantom_payload_budget",
            "ALTER TABLE host_snapshots ADD COLUMN phantom_payload_budget INTEGER",
        ),
        (
            "phantom_passive_follow_up",
            "ALTER TABLE host_snapshots ADD COLUMN phantom_passive_follow_up INTEGER NOT NULL DEFAULT 0",
        ),
        (
            "service_summary_json",
            "ALTER TABLE host_snapshots ADD COLUMN service_summary_json TEXT",
        ),
        (
            "service_count",
            "ALTER TABLE host_snapshots ADD COLUMN service_count INTEGER NOT NULL DEFAULT 0",
        ),
        (
            "identified_service_count",
            "ALTER TABLE host_snapshots ADD COLUMN identified_service_count INTEGER NOT NULL DEFAULT 0",
        ),
        (
            "cpe_count",
            "ALTER TABLE host_snapshots ADD COLUMN cpe_count INTEGER NOT NULL DEFAULT 0",
        ),
        (
            "advisory_count",
            "ALTER TABLE host_snapshots ADD COLUMN advisory_count INTEGER NOT NULL DEFAULT 0",
        ),
        (
            "actionable_summary_json",
            "ALTER TABLE host_snapshots ADD COLUMN actionable_summary_json TEXT",
        ),
        (
            "actionable_count",
            "ALTER TABLE host_snapshots ADD COLUMN actionable_count INTEGER NOT NULL DEFAULT 0",
        ),
        (
            "actionable_critical_count",
            "ALTER TABLE host_snapshots ADD COLUMN actionable_critical_count INTEGER NOT NULL DEFAULT 0",
        ),
        (
            "actionable_high_count",
            "ALTER TABLE host_snapshots ADD COLUMN actionable_high_count INTEGER NOT NULL DEFAULT 0",
        ),
        (
            "actionable_moderate_count",
            "ALTER TABLE host_snapshots ADD COLUMN actionable_moderate_count INTEGER NOT NULL DEFAULT 0",
        ),
        (
            "actionable_review_count",
            "ALTER TABLE host_snapshots ADD COLUMN actionable_review_count INTEGER NOT NULL DEFAULT 0",
        ),
    ] {
        if !columns.iter().any(|existing| existing == column) {
            conn.execute(ddl, []).map_err(sql_err)?;
        }
    }

    Ok(())
}

fn sql_err(err: rusqlite::Error) -> NProbeError {
    NProbeError::Config(format!("sqlite persistence error: {err}"))
}

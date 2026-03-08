PRAGMA journal_mode = WAL;
PRAGMA synchronous = NORMAL;

CREATE TABLE IF NOT EXISTS runtime_kv(
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
    host_operating_system TEXT,
    host_os_source TEXT,
    host_os_confidence REAL,
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
    ON actionable_snapshots(session_id, ip);

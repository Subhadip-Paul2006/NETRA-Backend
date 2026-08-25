-- NETRA Phase 3 Initial Storage Schema
-- Version: 1
-- Name: 001_initial_schema

-- 1. Schema Migrations Ledger
CREATE TABLE IF NOT EXISTS _netra_migrations (
    version             INTEGER PRIMARY KEY,
    name                TEXT NOT NULL,
    checksum            TEXT NOT NULL,
    applied_at          TEXT NOT NULL,
    execution_time_ms   INTEGER NOT NULL
);

-- 2. Local Configuration & Runtime Settings
CREATE TABLE IF NOT EXISTS local_config (
    key                 TEXT PRIMARY KEY,
    value_json          TEXT NOT NULL,
    value_type          TEXT NOT NULL,
    updated_at          TEXT NOT NULL
);

-- 3. Observation Queue (Transport-Neutral Local Buffering)
CREATE TABLE IF NOT EXISTS observation_queue (
    id                  TEXT PRIMARY KEY,       -- ObservationId (UUIDv7: obs_...)
    observation_type    TEXT NOT NULL,          -- e.g. "SCAN_NETWORK", "SCAN_PROCESSES"
    payload_json        TEXT NOT NULL,          -- Raw scan telemetry JSON
    sha256_hash         TEXT NOT NULL,          -- Deduplication and integrity hash
    status              TEXT NOT NULL,          -- "QUEUED", "IN_FLIGHT", "ACKNOWLEDGED", "DEAD_LETTER"
    retry_count         INTEGER NOT NULL DEFAULT 0,
    source_finding_id   TEXT,                   -- Optional provenance reference (application-level)
    created_at          TEXT NOT NULL,          -- ISO 8601 UTC timestamp
    updated_at          TEXT NOT NULL           -- ISO 8601 UTC timestamp
);

CREATE INDEX IF NOT EXISTS idx_obs_status_created 
ON observation_queue (status, created_at);

CREATE INDEX IF NOT EXISTS idx_obs_hash 
ON observation_queue (sha256_hash);

-- 4. Local Findings (Bounded Evidence Summary)
CREATE TABLE IF NOT EXISTS local_findings (
    fingerprint             TEXT PRIMARY KEY,   -- Deterministic SHA-256 (rule_id + target_key)
    rule_id                 TEXT NOT NULL,      -- e.g. "NET-001-PLAINTEXT-PORT"
    severity                TEXT NOT NULL,      -- "CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL"
    status                  TEXT NOT NULL,      -- "OPEN", "RESOLVED", "SUPPRESSED"
    title                   TEXT NOT NULL,      -- Human-readable finding summary
    evidence_summary_json   TEXT NOT NULL,      -- Bounded evidence summary (max 64KB)
    occurrence_count        INTEGER NOT NULL DEFAULT 1,
    first_seen              TEXT NOT NULL,      -- ISO 8601 UTC timestamp
    last_seen               TEXT NOT NULL       -- ISO 8601 UTC timestamp
);

CREATE INDEX IF NOT EXISTS idx_findings_status_severity 
ON local_findings (status, severity);

CREATE INDEX IF NOT EXISTS idx_findings_rule 
ON local_findings (rule_id);

-- Migration 002: Device Identity & Key Metadata Schema
-- Stores public cryptographic identity and key rotation lifecycle state.
-- PRIVATE KEYS ARE STRICTLY PROHIBITED FROM THIS DATABASE.

CREATE TABLE IF NOT EXISTS _netra_device_identity (
    device_id           TEXT PRIMARY KEY,
    active_key_id       TEXT NOT NULL,
    enrollment_status   TEXT NOT NULL, -- 'UNENROLLED', 'ENROLLED', 'REVOKED'
    enrolled_at         TEXT,
    gateway_url         TEXT,
    created_at          TEXT NOT NULL,
    updated_at          TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS _netra_key_metadata (
    key_id              TEXT PRIMARY KEY,
    device_id           TEXT NOT NULL REFERENCES _netra_device_identity(device_id),
    public_key_base64   TEXT NOT NULL,
    algorithm           TEXT NOT NULL DEFAULT 'Ed25519',
    status              TEXT NOT NULL, -- 'ACTIVE', 'ROTATING', 'RETIRED', 'REVOKED'
    created_at          TEXT NOT NULL,
    expires_at          TEXT NOT NULL,
    retired_at          TEXT
);

CREATE INDEX IF NOT EXISTS idx_key_metadata_device ON _netra_key_metadata(device_id);

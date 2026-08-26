use crate::storage::error::{StorageError, StorageResult};
use chrono::Utc;
use rusqlite::{params, Connection};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fmt;
use tracing::warn;

pub const MAX_EVIDENCE_SUMMARY_BYTES: usize = 65_536; // 64KB bounded evidence summary

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum FindingStatus {
    Open,
    Resolved,
    Suppressed,
}

impl FindingStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Open => "OPEN",
            Self::Resolved => "RESOLVED",
            Self::Suppressed => "SUPPRESSED",
        }
    }
}

impl std::str::FromStr for FindingStatus {
    type Err = StorageError;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        match s {
            "OPEN" => Ok(Self::Open),
            "RESOLVED" => Ok(Self::Resolved),
            "SUPPRESSED" => Ok(Self::Suppressed),
            other => Err(StorageError::NotFound(format!(
                "Invalid FindingStatus: {other}"
            ))),
        }
    }
}

impl fmt::Display for FindingStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum FindingSeverity {
    Critical,
    High,
    Medium,
    Low,
    Informational,
}

impl FindingSeverity {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Critical => "CRITICAL",
            Self::High => "HIGH",
            Self::Medium => "MEDIUM",
            Self::Low => "LOW",
            Self::Informational => "INFORMATIONAL",
        }
    }
}

impl std::str::FromStr for FindingSeverity {
    type Err = StorageError;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        match s {
            "CRITICAL" => Ok(Self::Critical),
            "HIGH" => Ok(Self::High),
            "MEDIUM" => Ok(Self::Medium),
            "LOW" => Ok(Self::Low),
            "INFORMATIONAL" => Ok(Self::Informational),
            other => Err(StorageError::NotFound(format!(
                "Invalid FindingSeverity: {other}"
            ))),
        }
    }
}

impl fmt::Display for FindingSeverity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FindingEntry {
    pub fingerprint: String,
    pub rule_id: String,
    pub severity: FindingSeverity,
    pub status: FindingStatus,
    pub title: String,
    pub evidence_summary_json: String,
    pub occurrence_count: i64,
    pub first_seen: String,
    pub last_seen: String,
}

pub struct FindingsRepository;

impl FindingsRepository {
    /// Generates a deterministic SHA-256 fingerprint for a posture finding.
    pub fn compute_fingerprint(rule_id: &str, target_key: &str, discriminator: &str) -> String {
        let mut hasher = Sha256::new();
        hasher.update(rule_id.as_bytes());
        hasher.update(b":");
        hasher.update(target_key.as_bytes());
        hasher.update(b":");
        hasher.update(discriminator.as_bytes());
        format!("{:x}", hasher.finalize())
    }

    /// Upserts a posture finding with deterministic fingerprint deduplication.
    ///
    /// If the finding is newly observed, it is inserted with `OPEN` status and `occurrence_count = 1`.
    /// If previously observed, `occurrence_count` is incremented, `last_seen` updated, and if it was
    /// previously `RESOLVED`, it is automatically reopened (`status = 'OPEN'`).
    pub fn upsert(
        conn: &Connection,
        rule_id: &str,
        severity: FindingSeverity,
        target_key: &str,
        discriminator: &str,
        title: &str,
        evidence_summary_json: &str,
    ) -> StorageResult<FindingEntry> {
        let fingerprint = Self::compute_fingerprint(rule_id, target_key, discriminator);
        let now = Utc::now().to_rfc3339();

        let bounded_evidence = if evidence_summary_json.len() > MAX_EVIDENCE_SUMMARY_BYTES {
            warn!(
                fingerprint = fingerprint.as_str(),
                size_bytes = evidence_summary_json.len(),
                "Evidence summary exceeds 64KB limit; storing truncated summary"
            );
            &evidence_summary_json[..MAX_EVIDENCE_SUMMARY_BYTES]
        } else {
            evidence_summary_json
        };

        conn.execute(
            "INSERT INTO local_findings (
                fingerprint, rule_id, severity, status, title, evidence_summary_json, occurrence_count, first_seen, last_seen
             ) VALUES (?1, ?2, ?3, 'OPEN', ?4, ?5, 1, ?6, ?6)
             ON CONFLICT(fingerprint) DO UPDATE SET
                last_seen = excluded.last_seen,
                occurrence_count = occurrence_count + 1,
                evidence_summary_json = excluded.evidence_summary_json,
                status = CASE WHEN status = 'RESOLVED' THEN 'OPEN' ELSE status END",
            params![
                &fingerprint,
                rule_id,
                severity.as_str(),
                title,
                bounded_evidence,
                &now
            ],
        )
        .map_err(StorageError::Database)?;

        Self::get(conn, &fingerprint)?.ok_or_else(|| {
            StorageError::NotFound(format!("Finding {fingerprint} not found after upsert"))
        })
    }

    /// Retrieves a finding by its deterministic fingerprint.
    pub fn get(conn: &Connection, fingerprint: &str) -> StorageResult<Option<FindingEntry>> {
        let mut stmt = conn
            .prepare(
                "SELECT fingerprint, rule_id, severity, status, title, evidence_summary_json, occurrence_count, first_seen, last_seen
                 FROM local_findings
                 WHERE fingerprint = ?1",
            )
            .map_err(StorageError::Database)?;

        let result = stmt
            .query_row([fingerprint], |row| {
                let sev_str: String = row.get(2)?;
                let status_str: String = row.get(3)?;
                Ok(FindingEntry {
                    fingerprint: row.get(0)?,
                    rule_id: row.get(1)?,
                    severity: sev_str.parse().unwrap_or(FindingSeverity::Medium),
                    status: status_str.parse().unwrap_or(FindingStatus::Open),
                    title: row.get(4)?,
                    evidence_summary_json: row.get(5)?,
                    occurrence_count: row.get(6)?,
                    first_seen: row.get(7)?,
                    last_seen: row.get(8)?,
                })
            })
            .map(Some)
            .or_else(|err| {
                if err == rusqlite::Error::QueryReturnedNoRows {
                    Ok(None)
                } else {
                    Err(StorageError::Database(err))
                }
            })?;

        Ok(result)
    }

    /// Lists findings filtered by status.
    pub fn list_by_status(
        conn: &Connection,
        status: FindingStatus,
    ) -> StorageResult<Vec<FindingEntry>> {
        let mut stmt = conn
            .prepare(
                "SELECT fingerprint, rule_id, severity, status, title, evidence_summary_json, occurrence_count, first_seen, last_seen
                 FROM local_findings
                 WHERE status = ?1
                 ORDER BY last_seen DESC",
            )
            .map_err(StorageError::Database)?;

        let rows = stmt
            .query_map([status.as_str()], |row| {
                let sev_str: String = row.get(2)?;
                let status_str: String = row.get(3)?;
                Ok(FindingEntry {
                    fingerprint: row.get(0)?,
                    rule_id: row.get(1)?,
                    severity: sev_str.parse().unwrap_or(FindingSeverity::Medium),
                    status: status_str.parse().unwrap_or(FindingStatus::Open),
                    title: row.get(4)?,
                    evidence_summary_json: row.get(5)?,
                    occurrence_count: row.get(6)?,
                    first_seen: row.get(7)?,
                    last_seen: row.get(8)?,
                })
            })
            .map_err(StorageError::Database)?;

        let mut entries = Vec::new();
        for row in rows {
            entries.push(row.map_err(StorageError::Database)?);
        }

        Ok(entries)
    }

    /// Lists all findings in the database ordered by last_seen descending.
    pub fn list_all(conn: &Connection) -> StorageResult<Vec<FindingEntry>> {
        let mut stmt = conn
            .prepare(
                "SELECT fingerprint, rule_id, severity, status, title, evidence_summary_json, occurrence_count, first_seen, last_seen
                 FROM local_findings
                 ORDER BY last_seen DESC",
            )
            .map_err(StorageError::Database)?;

        let rows = stmt
            .query_map([], |row| {
                let sev_str: String = row.get(2)?;
                let status_str: String = row.get(3)?;
                Ok(FindingEntry {
                    fingerprint: row.get(0)?,
                    rule_id: row.get(1)?,
                    severity: sev_str.parse().unwrap_or(FindingSeverity::Medium),
                    status: status_str.parse().unwrap_or(FindingStatus::Open),
                    title: row.get(4)?,
                    evidence_summary_json: row.get(5)?,
                    occurrence_count: row.get(6)?,
                    first_seen: row.get(7)?,
                    last_seen: row.get(8)?,
                })
            })
            .map_err(StorageError::Database)?;

        let mut entries = Vec::new();
        for row in rows {
            entries.push(row.map_err(StorageError::Database)?);
        }

        Ok(entries)
    }

    /// Marks an open finding as `RESOLVED`.
    pub fn resolve(conn: &Connection, fingerprint: &str) -> StorageResult<bool> {
        let now = Utc::now().to_rfc3339();
        let rows = conn
            .execute(
                "UPDATE local_findings SET status = 'RESOLVED', last_seen = ?1 WHERE fingerprint = ?2",
                params![&now, fingerprint],
            )
            .map_err(StorageError::Database)?;
        Ok(rows > 0)
    }

    /// Marks a finding as `SUPPRESSED`.
    pub fn suppress(conn: &Connection, fingerprint: &str) -> StorageResult<bool> {
        let now = Utc::now().to_rfc3339();
        let rows = conn
            .execute(
                "UPDATE local_findings SET status = 'SUPPRESSED', last_seen = ?1 WHERE fingerprint = ?2",
                params![&now, fingerprint],
            )
            .map_err(StorageError::Database)?;
        Ok(rows > 0)
    }

    /// Counts findings matching a specific status.
    pub fn count_by_status(conn: &Connection, status: FindingStatus) -> StorageResult<i64> {
        let count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM local_findings WHERE status = ?1",
                [status.as_str()],
                |row| row.get(0),
            )
            .map_err(StorageError::Database)?;

        Ok(count)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::migrations::MigrationEngine;

    fn setup_test_db() -> Connection {
        let mut conn = Connection::open_in_memory().unwrap();
        MigrationEngine::run_pending_migrations(&mut conn).unwrap();
        conn
    }

    #[test]
    fn test_findings_upsert_and_reopen_lifecycle() {
        let conn = setup_test_db();

        // 1. Upsert new finding
        let f1 = FindingsRepository::upsert(
            &conn,
            "NET-001",
            FindingSeverity::High,
            "0.0.0.0:23",
            "telnet_insecure",
            "Insecure Telnet Port Listening",
            "{\"port\": 23, \"process\": \"telnetd\"}",
        )
        .unwrap();

        assert_eq!(f1.status, FindingStatus::Open);
        assert_eq!(f1.occurrence_count, 1);

        // 2. Second observation increases occurrence_count
        let f2 = FindingsRepository::upsert(
            &conn,
            "NET-001",
            FindingSeverity::High,
            "0.0.0.0:23",
            "telnet_insecure",
            "Insecure Telnet Port Listening",
            "{\"port\": 23, \"process\": \"telnetd\"}",
        )
        .unwrap();

        assert_eq!(f2.fingerprint, f1.fingerprint);
        assert_eq!(f2.occurrence_count, 2);

        // 3. Resolve finding
        assert!(FindingsRepository::resolve(&conn, &f1.fingerprint).unwrap());
        let f_resolved = FindingsRepository::get(&conn, &f1.fingerprint)
            .unwrap()
            .unwrap();
        assert_eq!(f_resolved.status, FindingStatus::Resolved);

        // 4. Re-observing resolved finding automatically reopens it
        let f3 = FindingsRepository::upsert(
            &conn,
            "NET-001",
            FindingSeverity::High,
            "0.0.0.0:23",
            "telnet_insecure",
            "Insecure Telnet Port Listening",
            "{\"port\": 23, \"process\": \"telnetd\"}",
        )
        .unwrap();

        assert_eq!(f3.status, FindingStatus::Open);
        assert_eq!(f3.occurrence_count, 3);
    }
}

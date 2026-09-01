use crate::storage::error::{StorageError, StorageResult};
use chrono::Utc;
use rusqlite::{params, Connection};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashSet;
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

/// Query filter parameters for finding count aggregation.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct FindingsCountFilter {
    pub status: Option<FindingStatus>,
    pub severity: Option<FindingSeverity>,
    pub rule_id: Option<String>,
}

/// Breakdown of finding counts by lifecycle status.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct StatusCounts {
    pub open: i64,
    pub resolved: i64,
    pub suppressed: i64,
}

/// Breakdown of finding counts by severity level.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SeverityCounts {
    pub critical: i64,
    pub high: i64,
    pub medium: i64,
    pub low: i64,
    pub informational: i64,
}

/// Aggregate summary metrics for posture findings.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct FindingsSummaryStats {
    pub total: i64,
    pub by_status: StatusCounts,
    pub by_severity: SeverityCounts,
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

    /// Upserts a precomputed finding entry with deterministic fingerprint deduplication.
    ///
    /// Preserves the precomputed fingerprint and bounds the evidence summary JSON.
    pub fn upsert_entry(conn: &Connection, entry: &FindingEntry) -> StorageResult<FindingEntry> {
        let now = Utc::now().to_rfc3339();

        let bounded_evidence = if entry.evidence_summary_json.len() > MAX_EVIDENCE_SUMMARY_BYTES {
            warn!(
                fingerprint = entry.fingerprint.as_str(),
                size_bytes = entry.evidence_summary_json.len(),
                "Evidence summary exceeds 64KB limit; storing truncated summary"
            );
            &entry.evidence_summary_json[..MAX_EVIDENCE_SUMMARY_BYTES]
        } else {
            &entry.evidence_summary_json
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
                &entry.fingerprint,
                &entry.rule_id,
                entry.severity.as_str(),
                &entry.title,
                bounded_evidence,
                &now
            ],
        )
        .map_err(StorageError::Database)?;

        Self::get(conn, &entry.fingerprint)?.ok_or_else(|| {
            StorageError::NotFound(format!(
                "Finding {} not found after upsert",
                entry.fingerprint
            ))
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

    /// Reconciles findings for rules that were authoritatively evaluated in the current scan cycle.
    ///
    /// For each rule in `evaluated_rule_ids`:
    /// Any existing `OPEN` finding whose fingerprint is NOT present in `active_fingerprints`
    /// is transitioned to `RESOLVED` status with `last_seen = now`.
    ///
    /// Returns the number of findings marked as `RESOLVED`.
    pub fn reconcile_evaluated_rules(
        conn: &Connection,
        evaluated_rule_ids: &[&str],
        active_fingerprints: &HashSet<String>,
    ) -> StorageResult<usize> {
        if evaluated_rule_ids.is_empty() {
            return Ok(0);
        }

        let now = Utc::now().to_rfc3339();
        let mut resolved_count = 0;

        let mut stmt = conn
            .prepare(
                "SELECT fingerprint
                 FROM local_findings
                 WHERE status = 'OPEN' AND rule_id = ?1",
            )
            .map_err(StorageError::Database)?;

        let mut fingerprints_to_resolve = Vec::new();

        for &rule_id in evaluated_rule_ids {
            let rows = stmt
                .query_map([rule_id], |row| row.get::<_, String>(0))
                .map_err(StorageError::Database)?;

            for fp in rows {
                let fp = fp.map_err(StorageError::Database)?;
                if !active_fingerprints.contains(&fp) {
                    fingerprints_to_resolve.push(fp);
                }
            }
        }

        let mut update_stmt = conn
            .prepare(
                "UPDATE local_findings
                 SET status = 'RESOLVED', last_seen = ?1
                 WHERE fingerprint = ?2",
            )
            .map_err(StorageError::Database)?;

        for fp in fingerprints_to_resolve {
            let affected = update_stmt
                .execute(params![&now, &fp])
                .map_err(StorageError::Database)?;
            if affected > 0 {
                resolved_count += 1;
            }
        }

        Ok(resolved_count)
    }

    /// Computes aggregate finding counts grouped by status and severity using SQL aggregation.
    pub fn count_summary(
        conn: &Connection,
        filter: &FindingsCountFilter,
    ) -> StorageResult<FindingsSummaryStats> {
        let status_param = filter.status.as_ref().map(|s| s.as_str());
        let severity_param = filter.severity.as_ref().map(|s| s.as_str());
        let rule_param = filter.rule_id.as_deref();

        let mut stmt = conn
            .prepare(
                "SELECT status, severity, COUNT(*)
                 FROM local_findings
                 WHERE (?1 IS NULL OR status = ?1)
                   AND (?2 IS NULL OR severity = ?2)
                   AND (?3 IS NULL OR rule_id = ?3)
                 GROUP BY status, severity",
            )
            .map_err(StorageError::Database)?;

        let rows = stmt
            .query_map(params![status_param, severity_param, rule_param], |row| {
                let status_str: String = row.get(0)?;
                let sev_str: String = row.get(1)?;
                let count: i64 = row.get(2)?;
                Ok((status_str, sev_str, count))
            })
            .map_err(StorageError::Database)?;

        let mut stats = FindingsSummaryStats::default();

        for row in rows {
            let (status_str, sev_str, count) = row.map_err(StorageError::Database)?;
            stats.total += count;

            if let Ok(status) = status_str.parse::<FindingStatus>() {
                match status {
                    FindingStatus::Open => stats.by_status.open += count,
                    FindingStatus::Resolved => stats.by_status.resolved += count,
                    FindingStatus::Suppressed => stats.by_status.suppressed += count,
                }
            }

            if let Ok(severity) = sev_str.parse::<FindingSeverity>() {
                match severity {
                    FindingSeverity::Critical => stats.by_severity.critical += count,
                    FindingSeverity::High => stats.by_severity.high += count,
                    FindingSeverity::Medium => stats.by_severity.medium += count,
                    FindingSeverity::Low => stats.by_severity.low += count,
                    FindingSeverity::Informational => stats.by_severity.informational += count,
                }
            }
        }

        Ok(stats)
    }

    /// Deterministically resolves a full registered rule ID or canonical short rule ID.
    pub fn resolve_rule_id(input: &str) -> Option<String> {
        crate::rules::RuleEngine::resolve_rule_id(input)
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

    #[test]
    fn test_upsert_entry_and_reconciliation() {
        let conn = setup_test_db();

        let entry1 = FindingEntry {
            fingerprint: "fp_test_1".to_string(),
            rule_id: "NET-003".to_string(),
            severity: FindingSeverity::Medium,
            status: FindingStatus::Open,
            title: "Gateway Off Subnet 1".to_string(),
            evidence_summary_json: "{}".to_string(),
            occurrence_count: 1,
            first_seen: Utc::now().to_rfc3339(),
            last_seen: Utc::now().to_rfc3339(),
        };

        let entry2 = FindingEntry {
            fingerprint: "fp_test_2".to_string(),
            rule_id: "NET-003".to_string(),
            severity: FindingSeverity::Medium,
            status: FindingStatus::Open,
            title: "Gateway Off Subnet 2".to_string(),
            evidence_summary_json: "{}".to_string(),
            occurrence_count: 1,
            first_seen: Utc::now().to_rfc3339(),
            last_seen: Utc::now().to_rfc3339(),
        };

        let entry_dns = FindingEntry {
            fingerprint: "fp_dns_1".to_string(),
            rule_id: "NET-005".to_string(),
            severity: FindingSeverity::Low,
            status: FindingStatus::Open,
            title: "Invalid DNS Resolver".to_string(),
            evidence_summary_json: "{}".to_string(),
            occurrence_count: 1,
            first_seen: Utc::now().to_rfc3339(),
            last_seen: Utc::now().to_rfc3339(),
        };

        // Insert initial findings
        FindingsRepository::upsert_entry(&conn, &entry1).unwrap();
        FindingsRepository::upsert_entry(&conn, &entry2).unwrap();
        FindingsRepository::upsert_entry(&conn, &entry_dns).unwrap();

        assert_eq!(
            FindingsRepository::count_by_status(&conn, FindingStatus::Open).unwrap(),
            3
        );

        // Simulate next scan: NET-003 was evaluated, only fp_test_1 remains active (fp_test_2 fixed)
        // NET-005 was NOT evaluated (e.g. DNS scanner timed out) -> NOT in evaluated_rule_ids
        let mut active_fps = HashSet::new();
        active_fps.insert("fp_test_1".to_string());

        let evaluated_rules = vec!["NET-003"];
        let resolved_count =
            FindingsRepository::reconcile_evaluated_rules(&conn, &evaluated_rules, &active_fps)
                .unwrap();

        assert_eq!(resolved_count, 1, "Only fp_test_2 should be resolved");

        // Verify states
        let f1 = FindingsRepository::get(&conn, "fp_test_1")
            .unwrap()
            .unwrap();
        assert_eq!(f1.status, FindingStatus::Open);

        let f2 = FindingsRepository::get(&conn, "fp_test_2")
            .unwrap()
            .unwrap();
        assert_eq!(f2.status, FindingStatus::Resolved);

        let f_dns = FindingsRepository::get(&conn, "fp_dns_1").unwrap().unwrap();
        assert_eq!(
            f_dns.status,
            FindingStatus::Open,
            "Unevaluated DNS rule finding must remain OPEN"
        );
    }

    #[test]
    fn test_count_summary_aggregation() {
        let conn = setup_test_db();

        // 1. Empty database count
        let empty_stats =
            FindingsRepository::count_summary(&conn, &FindingsCountFilter::default()).unwrap();
        assert_eq!(empty_stats.total, 0);
        assert_eq!(empty_stats.by_status.open, 0);
        assert_eq!(empty_stats.by_status.resolved, 0);
        assert_eq!(empty_stats.by_status.suppressed, 0);
        assert_eq!(empty_stats.by_severity.critical, 0);
        assert_eq!(empty_stats.by_severity.high, 0);
        assert_eq!(empty_stats.by_severity.medium, 0);
        assert_eq!(empty_stats.by_severity.low, 0);
        assert_eq!(empty_stats.by_severity.informational, 0);

        // Populate database with diverse findings
        let entries = vec![
            FindingEntry {
                fingerprint: "fp_1".to_string(),
                rule_id: "NET-001-PLAINTEXT-PORT".to_string(),
                severity: FindingSeverity::High,
                status: FindingStatus::Open,
                title: "Plaintext Telnet".to_string(),
                evidence_summary_json: "{}".to_string(),
                occurrence_count: 1,
                first_seen: Utc::now().to_rfc3339(),
                last_seen: Utc::now().to_rfc3339(),
            },
            FindingEntry {
                fingerprint: "fp_2".to_string(),
                rule_id: "NET-002-UNRESTRICTED-DB".to_string(),
                severity: FindingSeverity::Critical,
                status: FindingStatus::Open,
                title: "Unrestricted DB".to_string(),
                evidence_summary_json: "{}".to_string(),
                occurrence_count: 2,
                first_seen: Utc::now().to_rfc3339(),
                last_seen: Utc::now().to_rfc3339(),
            },
            FindingEntry {
                fingerprint: "fp_3".to_string(),
                rule_id: "NET-003-GATEWAY-OFF-SUBNET".to_string(),
                severity: FindingSeverity::Medium,
                status: FindingStatus::Resolved,
                title: "Gateway Off Subnet".to_string(),
                evidence_summary_json: "{}".to_string(),
                occurrence_count: 1,
                first_seen: Utc::now().to_rfc3339(),
                last_seen: Utc::now().to_rfc3339(),
            },
            FindingEntry {
                fingerprint: "fp_4".to_string(),
                rule_id: "NET-005-INVALID-DNS-RESOLVER".to_string(),
                severity: FindingSeverity::Low,
                status: FindingStatus::Suppressed,
                title: "Invalid DNS".to_string(),
                evidence_summary_json: "{}".to_string(),
                occurrence_count: 1,
                first_seen: Utc::now().to_rfc3339(),
                last_seen: Utc::now().to_rfc3339(),
            },
            FindingEntry {
                fingerprint: "fp_5".to_string(),
                rule_id: "NET-005-INVALID-DNS-RESOLVER".to_string(),
                severity: FindingSeverity::Low,
                status: FindingStatus::Open,
                title: "Invalid DNS Secondary".to_string(),
                evidence_summary_json: "{}".to_string(),
                occurrence_count: 3,
                first_seen: Utc::now().to_rfc3339(),
                last_seen: Utc::now().to_rfc3339(),
            },
        ];

        for e in &entries {
            FindingsRepository::upsert_entry(&conn, e).unwrap();
        }
        FindingsRepository::resolve(&conn, "fp_3").unwrap();
        FindingsRepository::suppress(&conn, "fp_4").unwrap();

        // 2. Unfiltered total & breakdowns
        let all_stats =
            FindingsRepository::count_summary(&conn, &FindingsCountFilter::default()).unwrap();
        assert_eq!(all_stats.total, 5);
        assert_eq!(all_stats.by_status.open, 3);
        assert_eq!(all_stats.by_status.resolved, 1);
        assert_eq!(all_stats.by_status.suppressed, 1);
        assert_eq!(all_stats.by_severity.critical, 1);
        assert_eq!(all_stats.by_severity.high, 1);
        assert_eq!(all_stats.by_severity.medium, 1);
        assert_eq!(all_stats.by_severity.low, 2);
        assert_eq!(all_stats.by_severity.informational, 0);

        // 3. Status filter: OPEN
        let open_stats = FindingsRepository::count_summary(
            &conn,
            &FindingsCountFilter {
                status: Some(FindingStatus::Open),
                severity: None,
                rule_id: None,
            },
        )
        .unwrap();
        assert_eq!(open_stats.total, 3);
        assert_eq!(open_stats.by_status.open, 3);
        assert_eq!(open_stats.by_status.resolved, 0);
        assert_eq!(open_stats.by_status.suppressed, 0);
        assert_eq!(open_stats.by_severity.critical, 1);
        assert_eq!(open_stats.by_severity.high, 1);
        assert_eq!(open_stats.by_severity.low, 1);

        // 4. Severity filter: LOW
        let low_stats = FindingsRepository::count_summary(
            &conn,
            &FindingsCountFilter {
                status: None,
                severity: Some(FindingSeverity::Low),
                rule_id: None,
            },
        )
        .unwrap();
        assert_eq!(low_stats.total, 2);
        assert_eq!(low_stats.by_status.open, 1);
        assert_eq!(low_stats.by_status.suppressed, 1);
        assert_eq!(low_stats.by_severity.low, 2);

        // 5. Rule filter: NET-005-INVALID-DNS-RESOLVER
        let dns_stats = FindingsRepository::count_summary(
            &conn,
            &FindingsCountFilter {
                status: None,
                severity: None,
                rule_id: Some("NET-005-INVALID-DNS-RESOLVER".to_string()),
            },
        )
        .unwrap();
        assert_eq!(dns_stats.total, 2);
        assert_eq!(dns_stats.by_status.open, 1);
        assert_eq!(dns_stats.by_status.suppressed, 1);

        // 6. Combined filter: Status OPEN + Severity CRITICAL
        let crit_open_stats = FindingsRepository::count_summary(
            &conn,
            &FindingsCountFilter {
                status: Some(FindingStatus::Open),
                severity: Some(FindingSeverity::Critical),
                rule_id: None,
            },
        )
        .unwrap();
        assert_eq!(crit_open_stats.total, 1);
        assert_eq!(crit_open_stats.by_status.open, 1);
        assert_eq!(crit_open_stats.by_severity.critical, 1);

        // 7. Zero match filter
        let zero_stats = FindingsRepository::count_summary(
            &conn,
            &FindingsCountFilter {
                status: Some(FindingStatus::Resolved),
                severity: Some(FindingSeverity::Critical),
                rule_id: None,
            },
        )
        .unwrap();
        assert_eq!(zero_stats.total, 0);
        assert_eq!(zero_stats.by_status.open, 0);
        assert_eq!(zero_stats.by_status.resolved, 0);
        assert_eq!(zero_stats.by_severity.critical, 0);
    }
}

use crate::storage::error::{StorageError, StorageResult};
use chrono::{Duration as ChronoDuration, Utc};
use rusqlite::{params, Connection};
use std::fs;
use std::path::Path;
use tracing::{debug, warn};

pub const DEFAULT_MAX_STORAGE_BYTES: u64 = 524_288_000; // 500 MB
pub const PRUNE_HIGH_WATER_RATIO: f64 = 0.85; // 85% triggers proactive pruning
pub const PRUNE_CRITICAL_RATIO: f64 = 0.95; // 95% rejects non-critical enqueues
pub const PRUNE_SATURATION_RATIO: f64 = 1.00; // 100% full (only protected data remaining)

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QuotaStatus {
    Normal,
    HighWater,
    Critical,
    Saturated,
}

#[derive(Debug, Clone, Default)]
pub struct PruneReport {
    pub initial_bytes: u64,
    pub final_bytes: u64,
    pub pruned_ack_observations: usize,
    pub pruned_dead_letter_observations: usize,
    pub pruned_resolved_findings: usize,
    pub emergency_pruned_observations: usize,
}

pub struct StorageQuotaManager;

impl StorageQuotaManager {
    /// Calculates the total on-disk storage footprint of SQLite files (DB + WAL + SHM).
    pub fn calculate_storage_bytes(db_path: &Path) -> u64 {
        let parent_dir = db_path.parent().unwrap_or_else(|| Path::new("."));
        let base_name = db_path.file_name().unwrap_or_default().to_string_lossy();

        let mut total_bytes = 0;
        for suffix in ["", "-wal", "-shm"] {
            let file_path = parent_dir.join(format!("{base_name}{suffix}"));
            if let Ok(meta) = fs::metadata(&file_path) {
                total_bytes += meta.len();
            }
        }

        total_bytes
    }

    /// Evaluates the storage quota against configured limits and write criticality.
    pub fn check_quota(
        db_path: &Path,
        max_bytes: u64,
        is_critical_write: bool,
    ) -> StorageResult<QuotaStatus> {
        let current_bytes = Self::calculate_storage_bytes(db_path);

        if current_bytes >= max_bytes {
            warn!(
                current_bytes = current_bytes,
                max_bytes = max_bytes,
                "Storage quota is 100% saturated. Storage entering read-only degraded mode."
            );
            return Err(StorageError::QuotaSaturated {
                current_bytes,
                max_bytes,
            });
        }

        let critical_threshold = (max_bytes as f64 * PRUNE_CRITICAL_RATIO) as u64;
        if current_bytes >= critical_threshold && !is_critical_write {
            warn!(
                current_bytes = current_bytes,
                max_bytes = max_bytes,
                "Storage quota exceeded 95% critical threshold; rejecting non-critical enqueue."
            );
            return Err(StorageError::QuotaExceeded {
                current_bytes,
                max_bytes,
            });
        }

        let high_threshold = (max_bytes as f64 * PRUNE_HIGH_WATER_RATIO) as u64;
        if current_bytes >= high_threshold {
            return Ok(QuotaStatus::HighWater);
        }

        Ok(QuotaStatus::Normal)
    }

    /// Executes multi-tier state-aware queue pruning.
    ///
    /// # Safety and Invariants:
    /// - Strictly preserves `QUEUED` observations and `OPEN` findings.
    /// - Step 1: Prune `ACKNOWLEDGED` observations older than 7 days.
    /// - Step 2: Prune `DEAD_LETTER` observations older than 30 days.
    /// - Step 3: Prune `RESOLVED` / `SUPPRESSED` findings older than 90 days.
    /// - Step 4: If quota still exceeds critical threshold, emergency prune oldest `ACKNOWLEDGED` observations.
    pub fn execute_prune(
        conn: &Connection,
        db_path: &Path,
        max_bytes: u64,
    ) -> StorageResult<PruneReport> {
        let initial_bytes = Self::calculate_storage_bytes(db_path);
        let mut report = PruneReport {
            initial_bytes,
            ..Default::default()
        };

        let now = Utc::now();
        let ack_cutoff = (now - ChronoDuration::days(7)).to_rfc3339();
        let dead_cutoff = (now - ChronoDuration::days(30)).to_rfc3339();
        let findings_cutoff = (now - ChronoDuration::days(90)).to_rfc3339();

        // 1. Prune old ACKNOWLEDGED observations
        let count1 = conn
            .execute(
                "DELETE FROM observation_queue WHERE status = 'ACKNOWLEDGED' AND updated_at < ?1",
                params![&ack_cutoff],
            )
            .map_err(StorageError::Database)?;
        report.pruned_ack_observations = count1;

        // 2. Prune old DEAD_LETTER observations
        let count2 = conn
            .execute(
                "DELETE FROM observation_queue WHERE status = 'DEAD_LETTER' AND updated_at < ?1",
                params![&dead_cutoff],
            )
            .map_err(StorageError::Database)?;
        report.pruned_dead_letter_observations = count2;

        // 3. Prune old RESOLVED / SUPPRESSED findings
        let count3 = conn
            .execute(
                "DELETE FROM local_findings WHERE (status = 'RESOLVED' OR status = 'SUPPRESSED') AND last_seen < ?1",
                params![&findings_cutoff],
            )
            .map_err(StorageError::Database)?;
        report.pruned_resolved_findings = count3;

        // 4. Emergency Prune if capacity exceeds 95%
        let current_bytes = Self::calculate_storage_bytes(db_path);
        let critical_threshold = (max_bytes as f64 * PRUNE_CRITICAL_RATIO) as u64;

        if current_bytes >= critical_threshold {
            warn!(
                current_bytes = current_bytes,
                "Storage still above critical threshold; executing emergency purge of oldest acknowledged observations"
            );
            let count4 = conn
                .execute(
                    "DELETE FROM observation_queue
                     WHERE id IN (
                         SELECT id FROM observation_queue
                         WHERE status = 'ACKNOWLEDGED'
                         ORDER BY created_at ASC
                         LIMIT 500
                     )",
                    [],
                )
                .map_err(StorageError::Database)?;
            report.emergency_pruned_observations = count4;
        }

        report.final_bytes = Self::calculate_storage_bytes(db_path);

        debug!(
            initial_bytes = report.initial_bytes,
            final_bytes = report.final_bytes,
            pruned_ack = report.pruned_ack_observations,
            pruned_dead = report.pruned_dead_letter_observations,
            pruned_findings = report.pruned_resolved_findings,
            "State-aware storage pruning complete"
        );

        Ok(report)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::migrations::MigrationEngine;
    use crate::storage::repositories::{
        FindingSeverity, FindingStatus, FindingsRepository, ObservationQueueRepository,
    };
    use tempfile::tempdir;

    #[test]
    fn test_quota_pruner_protects_queued_and_open_records() {
        let dir = tempdir().unwrap();
        let db_path = dir.path().join("agent.db");
        let mut conn = Connection::open(&db_path).unwrap();
        MigrationEngine::run_pending_migrations(&mut conn).unwrap();

        // 1. Insert QUEUED observation (MUST NEVER BE DELETED)
        let queued_obs =
            ObservationQueueRepository::enqueue(&conn, "SCAN", "{\"queued\": true}", None).unwrap();

        // 2. Insert ACKNOWLEDGED observation with old timestamp
        let ack_obs =
            ObservationQueueRepository::enqueue(&conn, "SCAN", "{\"ack\": true}", None).unwrap();
        ObservationQueueRepository::mark_acknowledged(&conn, std::slice::from_ref(&ack_obs.id))
            .unwrap();
        // Set timestamp back 10 days
        let old_time = (Utc::now() - ChronoDuration::days(10)).to_rfc3339();
        conn.execute(
            "UPDATE observation_queue SET updated_at = ?1 WHERE id = ?2",
            params![&old_time, &ack_obs.id],
        )
        .unwrap();

        // 3. Insert OPEN finding (MUST NEVER BE DELETED)
        let open_finding = FindingsRepository::upsert(
            &conn,
            "RULE-1",
            FindingSeverity::High,
            "target1",
            "disc1",
            "Open finding",
            "{}",
        )
        .unwrap();

        // 4. Insert RESOLVED finding with old timestamp
        let resolved_finding = FindingsRepository::upsert(
            &conn,
            "RULE-2",
            FindingSeverity::Low,
            "target2",
            "disc2",
            "Resolved finding",
            "{}",
        )
        .unwrap();
        FindingsRepository::resolve(&conn, &resolved_finding.fingerprint).unwrap();
        let old_f_time = (Utc::now() - ChronoDuration::days(100)).to_rfc3339();
        conn.execute(
            "UPDATE local_findings SET last_seen = ?1 WHERE fingerprint = ?2",
            params![&old_f_time, &resolved_finding.fingerprint],
        )
        .unwrap();

        // Run Prune
        let report =
            StorageQuotaManager::execute_prune(&conn, &db_path, DEFAULT_MAX_STORAGE_BYTES).unwrap();
        assert_eq!(report.pruned_ack_observations, 1);
        assert_eq!(report.pruned_resolved_findings, 1);

        // Verify QUEUED observation is still intact
        let queued_left = ObservationQueueRepository::fetch_queued_batch(&conn, 10).unwrap();
        assert_eq!(queued_left.len(), 1);
        assert_eq!(queued_left[0].id, queued_obs.id);

        // Verify OPEN finding is still intact
        let open_left = FindingsRepository::get(&conn, &open_finding.fingerprint).unwrap();
        assert!(open_left.is_some());
        assert_eq!(open_left.unwrap().status, FindingStatus::Open);
    }
}

use crate::storage::error::{StorageError, StorageResult};
use chrono::Utc;
use rusqlite::Connection;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs::{self, File};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};
use tracing::{error, info, warn};

/// Quarantine forensic report recorded in `quarantine_meta.json`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuarantineMetadata {
    pub quarantined_at: String,
    pub original_db_path: String,
    pub corruption_reason: String,
    pub host_os: String,
    pub files: Vec<QuarantinedFileInfo>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuarantinedFileInfo {
    pub file_name: String,
    pub file_size_bytes: u64,
    pub sha256_hash: String,
}

pub struct IntegrityVerification;

impl IntegrityVerification {
    /// Tier 1: Fast schema and WAL probe (<1ms expected on NVMe).
    pub fn probe_tier1_fast(conn: &Connection) -> StorageResult<Duration> {
        let start = Instant::now();
        let _res: i64 = conn
            .query_row("SELECT 1 FROM _netra_migrations LIMIT 1", [], |row| {
                row.get(0)
            })
            .map_err(|e| StorageError::Corruption(format!("Tier 1 fast probe failed: {e}")))?;
        Ok(start.elapsed())
    }

    /// Tier 2: Quick structural check of page pointers and b-trees (<50ms expected).
    pub fn probe_tier2_quick_check(conn: &Connection) -> StorageResult<Duration> {
        let start = Instant::now();
        let mut stmt = conn
            .prepare("PRAGMA quick_check;")
            .map_err(StorageError::Database)?;

        let rows = stmt
            .query_map([], |row| row.get::<_, String>(0))
            .map_err(StorageError::Database)?;

        let mut errors = Vec::new();
        for row in rows {
            let val = row.map_err(StorageError::Database)?;
            if val != "ok" {
                errors.push(val);
            }
        }

        if !errors.is_empty() {
            return Err(StorageError::Corruption(format!(
                "PRAGMA quick_check returned errors: {}",
                errors.join("; ")
            )));
        }

        Ok(start.elapsed())
    }

    /// Tier 3: Deep integrity check including b-trees, free lists, and foreign keys.
    pub fn probe_tier3_deep_check(conn: &Connection) -> StorageResult<Vec<String>> {
        let mut issues = Vec::new();

        // 1. Full integrity_check
        let mut stmt = conn
            .prepare("PRAGMA integrity_check;")
            .map_err(StorageError::Database)?;

        let rows = stmt
            .query_map([], |row| row.get::<_, String>(0))
            .map_err(StorageError::Database)?;

        for row in rows {
            let val = row.map_err(StorageError::Database)?;
            if val != "ok" {
                issues.push(format!("integrity_check: {val}"));
            }
        }

        // 2. Foreign key check
        let mut fk_stmt = conn
            .prepare("PRAGMA foreign_key_check;")
            .map_err(StorageError::Database)?;

        let fk_rows = fk_stmt
            .query_map([], |row| {
                let table: String = row.get(0)?;
                let rowid: i64 = row.get(1)?;
                let parent: String = row.get(2)?;
                let fkid: i64 = row.get(3)?;
                Ok(format!(
                    "FK violation in table '{table}' row {rowid} referencing '{parent}' (fkid {fkid})"
                ))
            })
            .map_err(StorageError::Database)?;

        for row in fk_rows {
            issues.push(row.map_err(StorageError::Database)?);
        }

        Ok(issues)
    }
}

pub struct QuarantineManager;

impl QuarantineManager {
    /// Computes the SHA-256 hex hash of a local file.
    pub fn hash_file(path: &Path) -> StorageResult<String> {
        let mut file = File::open(path).map_err(StorageError::Io)?;
        let mut hasher = Sha256::new();
        let mut buffer = [0u8; 8192];

        loop {
            let n = file.read(&mut buffer).map_err(StorageError::Io)?;
            if n == 0 {
                break;
            }
            hasher.update(&buffer[..n]);
        }

        Ok(format!("{:x}", hasher.finalize()))
    }

    /// Executes the safe 6-step corruption quarantine protocol.
    ///
    /// # Safety and Invariants:
    /// - Assumes all SQLite handles are closed before invocation.
    /// - Creates a dedicated timestamped `quarantine_<TIMESTAMP>/` directory.
    /// - Moves/copies `agent.db`, `agent.db-wal`, `agent.db-shm` into the directory.
    /// - Records `quarantine_meta.json` with SHA-256 hashes for forensic preservation.
    /// - Never destroys or silently deletes corrupt files.
    pub fn execute_quarantine(db_path: &Path, corruption_reason: &str) -> StorageResult<PathBuf> {
        let parent_dir = db_path.parent().unwrap_or_else(|| Path::new("."));
        let timestamp_str = Utc::now().format("%Y%m%dT%H%M%SZ").to_string();
        let quarantine_dir = parent_dir.join(format!("quarantine_{timestamp_str}"));

        fs::create_dir_all(&quarantine_dir).map_err(StorageError::Io)?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = fs::set_permissions(&quarantine_dir, fs::Permissions::from_mode(0o700));
        }

        warn!(
            quarantine_dir = %quarantine_dir.display(),
            reason = corruption_reason,
            "Initiating database quarantine procedure"
        );

        let file_stems = ["", "-wal", "-shm"];
        let mut quarantined_files = Vec::new();

        for suffix in file_stems {
            let file_name = format!(
                "{}{}",
                db_path
                    .file_name()
                    .unwrap_or_default()
                    .to_string_lossy(),
                suffix
            );
            let src_file = parent_dir.join(&file_name);

            if src_file.exists() {
                let dest_file = quarantine_dir.join(&file_name);

                // Attempt move, fall back to copy + remove
                if fs::rename(&src_file, &dest_file).is_err() {
                    fs::copy(&src_file, &dest_file).map_err(StorageError::Io)?;
                    let _ = fs::remove_file(&src_file);
                }

                let size = fs::metadata(&dest_file)
                    .map(|m| m.len())
                    .unwrap_or(0);
                let hash = Self::hash_file(&dest_file).unwrap_or_else(|_| "hash_failed".to_string());

                quarantined_files.push(QuarantinedFileInfo {
                    file_name,
                    file_size_bytes: size,
                    sha256_hash: hash,
                });
            }
        }

        let metadata = QuarantineMetadata {
            quarantined_at: Utc::now().to_rfc3339(),
            original_db_path: db_path.display().to_string(),
            corruption_reason: corruption_reason.to_string(),
            host_os: std::env::consts::OS.to_string(),
            files: quarantined_files,
        };

        let meta_json = serde_json::to_string_pretty(&metadata)
            .map_err(|e| StorageError::Serialization(e.to_string()))?;
        let meta_path = quarantine_dir.join("quarantine_meta.json");
        fs::write(&meta_path, meta_json).map_err(StorageError::Io)?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = fs::set_permissions(&meta_path, fs::Permissions::from_mode(0o600));
        }

        info!(
            quarantine_dir = %quarantine_dir.display(),
            "Database successfully quarantined with forensic metadata recorded"
        );

        Ok(quarantine_dir)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_tier1_and_tier2_integrity_checks_on_healthy_db() {
        let conn = Connection::open_in_memory().unwrap();
        crate::storage::migrations::MigrationEngine::run_pending_migrations(
            &mut Connection::open_in_memory().unwrap(),
        )
        .unwrap();

        let mut fresh_conn = Connection::open_in_memory().unwrap();
        crate::storage::migrations::MigrationEngine::run_pending_migrations(&mut fresh_conn).unwrap();

        let t1 = IntegrityVerification::probe_tier1_fast(&fresh_conn);
        assert!(t1.is_ok());

        let t2 = IntegrityVerification::probe_tier2_quick_check(&fresh_conn);
        assert!(t2.is_ok());

        let t3 = IntegrityVerification::probe_tier3_deep_check(&fresh_conn).unwrap();
        assert!(issues_are_empty(&t3));
    }

    fn issues_are_empty(issues: &[String]) -> bool {
        issues.is_empty()
    }

    #[test]
    fn test_quarantine_directory_creates_meta_json_and_moves_files() {
        let dir = tempdir().unwrap();
        let db_path = dir.path().join("agent.db");
        let wal_path = dir.path().join("agent.db-wal");

        fs::write(&db_path, b"corrupted header bytes").unwrap();
        fs::write(&wal_path, b"corrupted wal bytes").unwrap();

        let q_dir = QuarantineManager::execute_quarantine(&db_path, "Simulated header corruption").unwrap();

        assert!(q_dir.exists());
        assert!(!db_path.exists());
        assert!(!wal_path.exists());
        assert!(q_dir.join("agent.db").exists());
        assert!(q_dir.join("agent.db-wal").exists());
        assert!(q_dir.join("quarantine_meta.json").exists());

        let meta_content = fs::read_to_string(q_dir.join("quarantine_meta.json")).unwrap();
        let meta: QuarantineMetadata = serde_json::from_str(&meta_content).unwrap();
        assert_eq!(meta.corruption_reason, "Simulated header corruption");
        assert_eq!(meta.files.len(), 2);
    }
}

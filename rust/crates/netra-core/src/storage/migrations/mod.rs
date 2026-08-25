use crate::storage::error::{StorageError, StorageResult};
use chrono::Utc;
use rusqlite::Connection;
use sha2::{Digest, Sha256};
use std::time::Instant;
use tracing::{debug, info};

pub struct Migration {
    pub version: i64,
    pub name: &'static str,
    pub sql: &'static str,
}

pub const MIGRATIONS: &[Migration] = &[Migration {
    version: 1,
    name: "001_initial_schema",
    sql: include_str!("sql/001_initial_schema.sql"),
}];

pub struct MigrationEngine;

impl MigrationEngine {
    /// Computes the SHA-256 hex checksum of a migration SQL payload.
    pub fn compute_checksum(sql: &str) -> String {
        let mut hasher = Sha256::new();
        hasher.update(sql.as_bytes());
        format!("{:x}", hasher.finalize())
    }

    /// Applies all pending schema migrations transactionally.
    ///
    /// # Errors
    /// Returns [`StorageError::Migration`] if an applied migration's checksum does
    /// not match the compiled migration SQL (tampering detection) or if SQL execution fails.
    pub fn run_pending_migrations(conn: &mut Connection) -> StorageResult<usize> {
        // Ensure migration tracking table exists
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS _netra_migrations (
                version             INTEGER PRIMARY KEY,
                name                TEXT NOT NULL,
                checksum            TEXT NOT NULL,
                applied_at          TEXT NOT NULL,
                execution_time_ms   INTEGER NOT NULL
            );",
        )
        .map_err(StorageError::Database)?;

        let mut applied_count = 0;

        for migration in MIGRATIONS {
            let expected_checksum = Self::compute_checksum(migration.sql);

            // Check if this migration was previously applied
            let existing: Option<(String, String)> = conn
                .query_row(
                    "SELECT checksum, applied_at FROM _netra_migrations WHERE version = ?1",
                    [migration.version],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )
                .map(Some)
                .or_else(|err| {
                    if err == rusqlite::Error::QueryReturnedNoRows {
                        Ok(None)
                    } else {
                        Err(StorageError::Database(err))
                    }
                })?;

            if let Some((stored_checksum, applied_at)) = existing {
                // Verify checksum integrity
                if stored_checksum != expected_checksum {
                    return Err(StorageError::Migration(format!(
                        "Checksum mismatch for migration v{} ('{}'). Stored: {}, Expected: {}. Tampering suspected.",
                        migration.version, migration.name, stored_checksum, expected_checksum
                    )));
                }
                debug!(
                    version = migration.version,
                    name = migration.name,
                    applied_at = applied_at.as_str(),
                    "Migration already applied and checksum verified"
                );
                continue;
            }

            // Apply pending migration inside an isolated transaction
            let start = Instant::now();
            let tx = conn.transaction().map_err(StorageError::Database)?;

            debug!(
                version = migration.version,
                name = migration.name,
                "Applying pending migration"
            );

            tx.execute_batch(migration.sql)
                .map_err(StorageError::Database)?;

            let execution_time_ms = start.elapsed().as_millis() as i64;
            let applied_at = Utc::now().to_rfc3339();

            tx.execute(
                "INSERT INTO _netra_migrations (version, name, checksum, applied_at, execution_time_ms)
                 VALUES (?1, ?2, ?3, ?4, ?5)",
                (
                    migration.version,
                    migration.name,
                    &expected_checksum,
                    &applied_at,
                    execution_time_ms,
                ),
            )
            .map_err(StorageError::Database)?;

            tx.commit().map_err(StorageError::Database)?;

            info!(
                version = migration.version,
                name = migration.name,
                duration_ms = execution_time_ms,
                "Schema migration applied successfully"
            );

            applied_count += 1;
        }

        Ok(applied_count)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_migration_checksum_deterministic() {
        let sql = "CREATE TABLE test (id INTEGER PRIMARY KEY);";
        let c1 = MigrationEngine::compute_checksum(sql);
        let c2 = MigrationEngine::compute_checksum(sql);
        assert_eq!(c1, c2);
        assert_eq!(c1.len(), 64);
    }

    #[test]
    fn test_migration_idempotent_execution() {
        let mut conn = Connection::open_in_memory().unwrap();
        let applied_first = MigrationEngine::run_pending_migrations(&mut conn).unwrap();
        assert_eq!(applied_first, 1);

        // Second run should be a no-op and apply 0 migrations
        let applied_second = MigrationEngine::run_pending_migrations(&mut conn).unwrap();
        assert_eq!(applied_second, 0);

        // Verify tables exist
        let count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM _netra_migrations WHERE version = 1",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(count, 1);
    }

    #[test]
    fn test_migration_checksum_tamper_detection() {
        let mut conn = Connection::open_in_memory().unwrap();
        MigrationEngine::run_pending_migrations(&mut conn).unwrap();

        // Corrupt checksum in database
        conn.execute(
            "UPDATE _netra_migrations SET checksum = 'tampered_checksum' WHERE version = 1",
            [],
        )
        .unwrap();

        // Re-running migration engine should detect tamper and error
        let result = MigrationEngine::run_pending_migrations(&mut conn);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Checksum mismatch"));
    }
}

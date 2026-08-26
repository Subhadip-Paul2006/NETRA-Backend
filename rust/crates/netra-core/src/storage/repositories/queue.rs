use crate::id::ObservationId;
use crate::storage::error::{StorageError, StorageResult};
use chrono::{Duration as ChronoDuration, Utc};
use rusqlite::{params, Connection};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fmt;

/// Transport-neutral observation queue status.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ObservationStatus {
    Queued,
    InFlight,
    Acknowledged,
    DeadLetter,
}

impl ObservationStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Queued => "QUEUED",
            Self::InFlight => "IN_FLIGHT",
            Self::Acknowledged => "ACKNOWLEDGED",
            Self::DeadLetter => "DEAD_LETTER",
        }
    }
}

impl std::str::FromStr for ObservationStatus {
    type Err = StorageError;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        match s {
            "QUEUED" => Ok(Self::Queued),
            "IN_FLIGHT" => Ok(Self::InFlight),
            "ACKNOWLEDGED" => Ok(Self::Acknowledged),
            "DEAD_LETTER" => Ok(Self::DeadLetter),
            other => Err(StorageError::NotFound(format!(
                "Invalid ObservationStatus: {other}"
            ))),
        }
    }
}

impl fmt::Display for ObservationStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// Durable observation record in local buffer queue.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ObservationEntry {
    pub id: String,
    pub observation_type: String,
    pub payload_json: String,
    pub sha256_hash: String,
    pub status: ObservationStatus,
    pub retry_count: i64,
    pub source_finding_id: Option<String>,
    pub created_at: String,
    pub updated_at: String,
}

pub struct ObservationQueueRepository;

impl ObservationQueueRepository {
    /// Computes the SHA-256 hex hash of observation type and payload.
    pub fn compute_hash(observation_type: &str, payload_json: &str) -> String {
        let mut hasher = Sha256::new();
        hasher.update(observation_type.as_bytes());
        hasher.update(b":");
        hasher.update(payload_json.as_bytes());
        format!("{:x}", hasher.finalize())
    }

    /// Enqueues a new observation telemetry record.
    ///
    /// Implements deduplication: if an identical observation is already `QUEUED`,
    /// updates `updated_at` without duplicating the row.
    pub fn enqueue(
        conn: &Connection,
        observation_type: &str,
        payload_json: &str,
        source_finding_id: Option<&str>,
    ) -> StorageResult<ObservationEntry> {
        let hash = Self::compute_hash(observation_type, payload_json);
        let now = Utc::now().to_rfc3339();

        // 1. Deduplication check against existing QUEUED observations
        let mut check_stmt = conn
            .prepare(
                "SELECT id, observation_type, payload_json, sha256_hash, status, retry_count, source_finding_id, created_at, updated_at
                 FROM observation_queue
                 WHERE sha256_hash = ?1 AND status = 'QUEUED'
                 LIMIT 1",
            )
            .map_err(StorageError::Database)?;

        let existing = check_stmt
            .query_row([&hash], |row| {
                let status_str: String = row.get(4)?;
                Ok(ObservationEntry {
                    id: row.get(0)?,
                    observation_type: row.get(1)?,
                    payload_json: row.get(2)?,
                    sha256_hash: row.get(3)?,
                    status: status_str.parse().unwrap_or(ObservationStatus::Queued),
                    retry_count: row.get(5)?,
                    source_finding_id: row.get(6)?,
                    created_at: row.get(7)?,
                    updated_at: row.get(8)?,
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

        if let Some(mut entry) = existing {
            // Update updated_at on existing queued row
            conn.execute(
                "UPDATE observation_queue SET updated_at = ?1 WHERE id = ?2",
                params![&now, &entry.id],
            )
            .map_err(StorageError::Database)?;
            entry.updated_at = now;
            return Ok(entry);
        }

        // 2. Insert new observation record
        let new_id = ObservationId::new().to_string();
        let entry = ObservationEntry {
            id: new_id.clone(),
            observation_type: observation_type.to_string(),
            payload_json: payload_json.to_string(),
            sha256_hash: hash.clone(),
            status: ObservationStatus::Queued,
            retry_count: 0,
            source_finding_id: source_finding_id.map(ToString::to_string),
            created_at: now.clone(),
            updated_at: now.clone(),
        };

        conn.execute(
            "INSERT INTO observation_queue (
                id, observation_type, payload_json, sha256_hash, status, retry_count, source_finding_id, created_at, updated_at
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            params![
                &entry.id,
                &entry.observation_type,
                &entry.payload_json,
                &entry.sha256_hash,
                entry.status.as_str(),
                entry.retry_count,
                &entry.source_finding_id,
                &entry.created_at,
                &entry.updated_at
            ],
        )
        .map_err(StorageError::Database)?;

        Ok(entry)
    }

    /// Fetches a batch of `QUEUED` observations in FIFO order.
    pub fn fetch_queued_batch(
        conn: &Connection,
        limit: usize,
    ) -> StorageResult<Vec<ObservationEntry>> {
        let mut stmt = conn
            .prepare(
                "SELECT id, observation_type, payload_json, sha256_hash, status, retry_count, source_finding_id, created_at, updated_at
                 FROM observation_queue
                 WHERE status = 'QUEUED'
                 ORDER BY created_at ASC
                 LIMIT ?1",
            )
            .map_err(StorageError::Database)?;

        let rows = stmt
            .query_map([limit as i64], |row| {
                let status_str: String = row.get(4)?;
                Ok(ObservationEntry {
                    id: row.get(0)?,
                    observation_type: row.get(1)?,
                    payload_json: row.get(2)?,
                    sha256_hash: row.get(3)?,
                    status: status_str.parse().unwrap_or(ObservationStatus::Queued),
                    retry_count: row.get(5)?,
                    source_finding_id: row.get(6)?,
                    created_at: row.get(7)?,
                    updated_at: row.get(8)?,
                })
            })
            .map_err(StorageError::Database)?;

        let mut entries = Vec::new();
        for row in rows {
            entries.push(row.map_err(StorageError::Database)?);
        }

        Ok(entries)
    }

    /// Marks a batch of observations as `IN_FLIGHT` and increments their retry count.
    pub fn mark_in_flight(conn: &Connection, ids: &[String]) -> StorageResult<usize> {
        if ids.is_empty() {
            return Ok(0);
        }
        let now = Utc::now().to_rfc3339();
        let mut updated = 0;

        for id in ids {
            let count = conn
                .execute(
                    "UPDATE observation_queue
                     SET status = 'IN_FLIGHT', retry_count = retry_count + 1, updated_at = ?1
                     WHERE id = ?2 AND status = 'QUEUED'",
                    params![&now, id],
                )
                .map_err(StorageError::Database)?;
            updated += count;
        }

        Ok(updated)
    }

    /// Marks observations as `ACKNOWLEDGED` upon successful transmission/processing.
    pub fn mark_acknowledged(conn: &Connection, ids: &[String]) -> StorageResult<usize> {
        if ids.is_empty() {
            return Ok(0);
        }
        let now = Utc::now().to_rfc3339();
        let mut updated = 0;

        for id in ids {
            let count = conn
                .execute(
                    "UPDATE observation_queue
                     SET status = 'ACKNOWLEDGED', updated_at = ?1
                     WHERE id = ?2",
                    params![&now, id],
                )
                .map_err(StorageError::Database)?;
            updated += count;
        }

        Ok(updated)
    }

    /// Marks unprocessable observations as `DEAD_LETTER`.
    pub fn mark_dead_letter(conn: &Connection, ids: &[String]) -> StorageResult<usize> {
        if ids.is_empty() {
            return Ok(0);
        }
        let now = Utc::now().to_rfc3339();
        let mut updated = 0;

        for id in ids {
            let count = conn
                .execute(
                    "UPDATE observation_queue
                     SET status = 'DEAD_LETTER', updated_at = ?1
                     WHERE id = ?2",
                    params![&now, id],
                )
                .map_err(StorageError::Database)?;
            updated += count;
        }

        Ok(updated)
    }

    /// Requeues stale `IN_FLIGHT` observations that timed out without acknowledgment.
    pub fn requeue_stale_in_flight(
        conn: &Connection,
        timeout_seconds: u64,
        max_retries: i64,
    ) -> StorageResult<usize> {
        let cutoff = Utc::now() - ChronoDuration::seconds(timeout_seconds as i64);
        let cutoff_str = cutoff.to_rfc3339();
        let now_str = Utc::now().to_rfc3339();

        // 1. Move exhausted retries to DEAD_LETTER
        conn.execute(
            "UPDATE observation_queue
             SET status = 'DEAD_LETTER', updated_at = ?1
             WHERE status = 'IN_FLIGHT' AND updated_at < ?2 AND retry_count >= ?3",
            params![&now_str, &cutoff_str, max_retries],
        )
        .map_err(StorageError::Database)?;

        // 2. Requeue remaining stale in-flight observations
        let count = conn
            .execute(
                "UPDATE observation_queue
                 SET status = 'QUEUED', updated_at = ?1
                 WHERE status = 'IN_FLIGHT' AND updated_at < ?2 AND retry_count < ?3",
                params![&now_str, &cutoff_str, max_retries],
            )
            .map_err(StorageError::Database)?;

        Ok(count)
    }

    /// Counts total records matching a specific observation status.
    pub fn count_by_status(conn: &Connection, status: ObservationStatus) -> StorageResult<i64> {
        let count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM observation_queue WHERE status = ?1",
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
    fn test_queue_lifecycle_and_deduplication() {
        let conn = setup_test_db();

        // 1. Enqueue observation
        let obs1 = ObservationQueueRepository::enqueue(
            &conn,
            "SCAN_NETWORK",
            "{\"port\": 80, \"protocol\": \"tcp\"}",
            None,
        )
        .unwrap();
        assert_eq!(obs1.status, ObservationStatus::Queued);
        assert_eq!(obs1.retry_count, 0);

        // 2. Enqueue duplicate -> should return existing without adding row
        let obs2 = ObservationQueueRepository::enqueue(
            &conn,
            "SCAN_NETWORK",
            "{\"port\": 80, \"protocol\": \"tcp\"}",
            None,
        )
        .unwrap();
        assert_eq!(obs1.id, obs2.id);
        assert_eq!(
            ObservationQueueRepository::count_by_status(&conn, ObservationStatus::Queued).unwrap(),
            1
        );

        // 3. Fetch batch
        let batch = ObservationQueueRepository::fetch_queued_batch(&conn, 10).unwrap();
        assert_eq!(batch.len(), 1);
        assert_eq!(batch[0].id, obs1.id);

        // 4. Mark in-flight
        let in_flight_count =
            ObservationQueueRepository::mark_in_flight(&conn, std::slice::from_ref(&obs1.id))
                .unwrap();
        assert_eq!(in_flight_count, 1);
        assert_eq!(
            ObservationQueueRepository::count_by_status(&conn, ObservationStatus::InFlight)
                .unwrap(),
            1
        );
        assert_eq!(
            ObservationQueueRepository::count_by_status(&conn, ObservationStatus::Queued).unwrap(),
            0
        );

        // 5. Mark acknowledged
        let ack_count =
            ObservationQueueRepository::mark_acknowledged(&conn, std::slice::from_ref(&obs1.id))
                .unwrap();
        assert_eq!(ack_count, 1);
        assert_eq!(
            ObservationQueueRepository::count_by_status(&conn, ObservationStatus::Acknowledged)
                .unwrap(),
            1
        );
    }
}

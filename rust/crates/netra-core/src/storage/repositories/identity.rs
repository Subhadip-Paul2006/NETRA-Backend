use chrono::Utc;
use rusqlite::{params, Connection, OptionalExtension};
use serde::{Deserialize, Serialize};

use crate::storage::error::{StorageError, StorageResult};

/// Database record representation of the device identity.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceIdentityRecord {
    pub device_id: String,
    pub active_key_id: String,
    pub enrollment_status: String,
    pub enrolled_at: Option<String>,
    pub gateway_url: Option<String>,
    pub created_at: String,
    pub updated_at: String,
}

pub struct DeviceIdentityRepository;

impl DeviceIdentityRepository {
    /// Retrieves the current device identity record, if initialized.
    pub fn get(conn: &Connection) -> StorageResult<Option<DeviceIdentityRecord>> {
        conn.query_row(
            "SELECT device_id, active_key_id, enrollment_status, enrolled_at, gateway_url, created_at, updated_at
             FROM _netra_device_identity LIMIT 1",
            [],
            |row| {
                Ok(DeviceIdentityRecord {
                    device_id: row.get(0)?,
                    active_key_id: row.get(1)?,
                    enrollment_status: row.get(2)?,
                    enrolled_at: row.get(3)?,
                    gateway_url: row.get(4)?,
                    created_at: row.get(5)?,
                    updated_at: row.get(6)?,
                })
            },
        )
        .optional()
        .map_err(StorageError::Database)
    }

    /// Inserts or replaces the device identity record.
    pub fn upsert(conn: &Connection, record: &DeviceIdentityRecord) -> StorageResult<()> {
        conn.execute(
            "INSERT INTO _netra_device_identity (device_id, active_key_id, enrollment_status, enrolled_at, gateway_url, created_at, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
             ON CONFLICT(device_id) DO UPDATE SET
                active_key_id = excluded.active_key_id,
                enrollment_status = excluded.enrollment_status,
                enrolled_at = excluded.enrolled_at,
                gateway_url = excluded.gateway_url,
                updated_at = excluded.updated_at",
            params![
                record.device_id,
                record.active_key_id,
                record.enrollment_status,
                record.enrolled_at,
                record.gateway_url,
                record.created_at,
                record.updated_at,
            ],
        )
        .map_err(StorageError::Database)?;

        Ok(())
    }

    /// Updates the active key identifier for the device identity.
    pub fn update_active_key(
        conn: &Connection,
        device_id: &str,
        new_key_id: &str,
    ) -> StorageResult<()> {
        let now = Utc::now().to_rfc3339();
        let rows = conn
            .execute(
                "UPDATE _netra_device_identity SET active_key_id = ?1, updated_at = ?2 WHERE device_id = ?3",
                params![new_key_id, now, device_id],
            )
            .map_err(StorageError::Database)?;

        if rows == 0 {
            return Err(StorageError::NotFound(format!(
                "Device identity with id '{}' not found",
                device_id
            )));
        }

        Ok(())
    }

    /// Updates the enrollment status and gateway information.
    pub fn update_enrollment_status(
        conn: &Connection,
        device_id: &str,
        status: &str,
        enrolled_at: Option<&str>,
        gateway_url: Option<&str>,
    ) -> StorageResult<()> {
        let now = Utc::now().to_rfc3339();
        let rows = conn
            .execute(
                "UPDATE _netra_device_identity
                 SET enrollment_status = ?1, enrolled_at = ?2, gateway_url = ?3, updated_at = ?4
                 WHERE device_id = ?5",
                params![status, enrolled_at, gateway_url, now, device_id],
            )
            .map_err(StorageError::Database)?;

        if rows == 0 {
            return Err(StorageError::NotFound(format!(
                "Device identity with id '{}' not found",
                device_id
            )));
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::migrations::MigrationEngine;

    #[test]
    fn test_device_identity_repository_crud() {
        let mut conn = Connection::open_in_memory().unwrap();
        MigrationEngine::run_pending_migrations(&mut conn).unwrap();

        assert!(DeviceIdentityRepository::get(&conn).unwrap().is_none());

        let record = DeviceIdentityRecord {
            device_id: "dev_01918a2b3c4d7e8f9a0b1c2d3e4f5a6b".to_string(),
            active_key_id: "key_01918a2b3c4d".to_string(),
            enrollment_status: "UNENROLLED".to_string(),
            enrolled_at: None,
            gateway_url: None,
            created_at: Utc::now().to_rfc3339(),
            updated_at: Utc::now().to_rfc3339(),
        };

        DeviceIdentityRepository::upsert(&conn, &record).unwrap();
        let fetched = DeviceIdentityRepository::get(&conn).unwrap().unwrap();
        assert_eq!(fetched.device_id, record.device_id);
        assert_eq!(fetched.active_key_id, "key_01918a2b3c4d");

        // Update active key
        DeviceIdentityRepository::update_active_key(&conn, &record.device_id, "key_01918a2b3c4e")
            .unwrap();
        let updated = DeviceIdentityRepository::get(&conn).unwrap().unwrap();
        assert_eq!(updated.active_key_id, "key_01918a2b3c4e");

        // Update enrollment
        DeviceIdentityRepository::update_enrollment_status(
            &conn,
            &record.device_id,
            "ENROLLED",
            Some("2026-08-26T12:00:00Z"),
            Some("wss://control.netra.local"),
        )
        .unwrap();

        let enrolled = DeviceIdentityRepository::get(&conn).unwrap().unwrap();
        assert_eq!(enrolled.enrollment_status, "ENROLLED");
        assert_eq!(
            enrolled.gateway_url.as_deref(),
            Some("wss://control.netra.local")
        );
    }
}

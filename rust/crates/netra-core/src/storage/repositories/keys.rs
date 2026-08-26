use rusqlite::{params, Connection, OptionalExtension};
use serde::{Deserialize, Serialize};

use crate::storage::error::{StorageError, StorageResult};

/// Database record representation of public key metadata.
///
/// NOTE: Raw private key seeds are strictly stored in OS KeyStore and NEVER in this record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeyMetadataRecord {
    pub key_id: String,
    pub device_id: String,
    pub public_key_base64: String,
    pub algorithm: String,
    pub status: String,
    pub created_at: String,
    pub expires_at: String,
    pub retired_at: Option<String>,
}

pub struct KeyMetadataRepository;

impl KeyMetadataRepository {
    /// Inserts a new key metadata entry.
    pub fn insert(conn: &Connection, record: &KeyMetadataRecord) -> StorageResult<()> {
        conn.execute(
            "INSERT INTO _netra_key_metadata (key_id, device_id, public_key_base64, algorithm, status, created_at, expires_at, retired_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![
                record.key_id,
                record.device_id,
                record.public_key_base64,
                record.algorithm,
                record.status,
                record.created_at,
                record.expires_at,
                record.retired_at,
            ],
        )
        .map_err(StorageError::Database)?;

        Ok(())
    }

    /// Retrieves key metadata by key identifier.
    pub fn get(conn: &Connection, key_id: &str) -> StorageResult<Option<KeyMetadataRecord>> {
        conn.query_row(
            "SELECT key_id, device_id, public_key_base64, algorithm, status, created_at, expires_at, retired_at
             FROM _netra_key_metadata WHERE key_id = ?1",
            [key_id],
            |row| {
                Ok(KeyMetadataRecord {
                    key_id: row.get(0)?,
                    device_id: row.get(1)?,
                    public_key_base64: row.get(2)?,
                    algorithm: row.get(3)?,
                    status: row.get(4)?,
                    created_at: row.get(5)?,
                    expires_at: row.get(6)?,
                    retired_at: row.get(7)?,
                })
            },
        )
        .optional()
        .map_err(StorageError::Database)
    }

    /// Lists all key metadata records for a device.
    pub fn list_by_device(
        conn: &Connection,
        device_id: &str,
    ) -> StorageResult<Vec<KeyMetadataRecord>> {
        let mut stmt = conn
            .prepare(
                "SELECT key_id, device_id, public_key_base64, algorithm, status, created_at, expires_at, retired_at
                 FROM _netra_key_metadata WHERE device_id = ?1 ORDER BY created_at ASC",
            )
            .map_err(StorageError::Database)?;

        let rows = stmt
            .query_map([device_id], |row| {
                Ok(KeyMetadataRecord {
                    key_id: row.get(0)?,
                    device_id: row.get(1)?,
                    public_key_base64: row.get(2)?,
                    algorithm: row.get(3)?,
                    status: row.get(4)?,
                    created_at: row.get(5)?,
                    expires_at: row.get(6)?,
                    retired_at: row.get(7)?,
                })
            })
            .map_err(StorageError::Database)?;

        let mut results = Vec::new();
        for r in rows {
            results.push(r.map_err(StorageError::Database)?);
        }

        Ok(results)
    }

    /// Updates status and retired_at for a specific key.
    pub fn update_status(
        conn: &Connection,
        key_id: &str,
        status: &str,
        retired_at: Option<&str>,
    ) -> StorageResult<()> {
        let rows = conn
            .execute(
                "UPDATE _netra_key_metadata SET status = ?1, retired_at = ?2 WHERE key_id = ?3",
                params![status, retired_at, key_id],
            )
            .map_err(StorageError::Database)?;

        if rows == 0 {
            return Err(StorageError::NotFound(format!(
                "Key metadata with id '{}' not found",
                key_id
            )));
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::migrations::MigrationEngine;
    use crate::storage::repositories::identity::{DeviceIdentityRecord, DeviceIdentityRepository};
    use chrono::Utc;

    #[test]
    fn test_key_metadata_repository_lifecycle() {
        let mut conn = Connection::open_in_memory().unwrap();
        MigrationEngine::run_pending_migrations(&mut conn).unwrap();

        let device = DeviceIdentityRecord {
            device_id: "dev_01918a2b3c4d7e8f9a0b1c2d3e4f5a6b".to_string(),
            active_key_id: "key_01918a2b3c4d".to_string(),
            enrollment_status: "UNENROLLED".to_string(),
            enrolled_at: None,
            gateway_url: None,
            created_at: Utc::now().to_rfc3339(),
            updated_at: Utc::now().to_rfc3339(),
        };
        DeviceIdentityRepository::upsert(&conn, &device).unwrap();

        let key1 = KeyMetadataRecord {
            key_id: "key_01918a2b3c4d".to_string(),
            device_id: device.device_id.clone(),
            public_key_base64: "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
                .to_string(),
            algorithm: "Ed25519".to_string(),
            status: "ACTIVE".to_string(),
            created_at: Utc::now().to_rfc3339(),
            expires_at: Utc::now().to_rfc3339(),
            retired_at: None,
        };

        KeyMetadataRepository::insert(&conn, &key1).unwrap();
        let fetched = KeyMetadataRepository::get(&conn, &key1.key_id)
            .unwrap()
            .unwrap();
        assert_eq!(fetched.key_id, key1.key_id);
        assert_eq!(fetched.status, "ACTIVE");

        // List by device
        let list = KeyMetadataRepository::list_by_device(&conn, &device.device_id).unwrap();
        assert_eq!(list.len(), 1);

        // Update status to RETIRED
        let now = Utc::now().to_rfc3339();
        KeyMetadataRepository::update_status(&conn, &key1.key_id, "RETIRED", Some(&now)).unwrap();
        let retired = KeyMetadataRepository::get(&conn, &key1.key_id)
            .unwrap()
            .unwrap();
        assert_eq!(retired.status, "RETIRED");
        assert_eq!(retired.retired_at.as_deref(), Some(now.as_str()));
    }
}

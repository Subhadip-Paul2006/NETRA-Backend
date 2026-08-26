use crate::storage::error::{StorageError, StorageResult};
use chrono::Utc;
use rusqlite::{params, Connection};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ConfigEntry {
    pub key: String,
    pub value_json: String,
    pub value_type: String,
    pub updated_at: String,
}

pub struct ConfigRepository;

impl ConfigRepository {
    /// Retrieves a configuration entry by key.
    pub fn get(conn: &Connection, key: &str) -> StorageResult<Option<ConfigEntry>> {
        let mut stmt = conn
            .prepare(
                "SELECT key, value_json, value_type, updated_at FROM local_config WHERE key = ?1",
            )
            .map_err(StorageError::Database)?;

        let result = stmt
            .query_row([key], |row| {
                Ok(ConfigEntry {
                    key: row.get(0)?,
                    value_json: row.get(1)?,
                    value_type: row.get(2)?,
                    updated_at: row.get(3)?,
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

    /// Deserializes a configuration value directly into a typed structure.
    pub fn get_typed<T: DeserializeOwned>(
        conn: &Connection,
        key: &str,
    ) -> StorageResult<Option<T>> {
        if let Some(entry) = Self::get(conn, key)? {
            let val: T = serde_json::from_str(&entry.value_json)
                .map_err(|e| StorageError::Serialization(e.to_string()))?;
            Ok(Some(val))
        } else {
            Ok(None)
        }
    }

    /// Sets or updates a configuration entry.
    pub fn set(
        conn: &Connection,
        key: &str,
        value_json: &str,
        value_type: &str,
    ) -> StorageResult<()> {
        let updated_at = Utc::now().to_rfc3339();
        conn.execute(
            "INSERT INTO local_config (key, value_json, value_type, updated_at)
             VALUES (?1, ?2, ?3, ?4)
             ON CONFLICT(key) DO UPDATE SET
                value_json = excluded.value_json,
                value_type = excluded.value_type,
                updated_at = excluded.updated_at",
            params![key, value_json, value_type, updated_at],
        )
        .map_err(StorageError::Database)?;

        Ok(())
    }

    /// Serializes and sets a typed configuration entry.
    pub fn set_typed<T: Serialize>(conn: &Connection, key: &str, value: &T) -> StorageResult<()> {
        let json =
            serde_json::to_string(value).map_err(|e| StorageError::Serialization(e.to_string()))?;
        Self::set(conn, key, &json, "json")
    }

    /// Deletes a configuration entry. Returns true if a record was removed.
    pub fn delete(conn: &Connection, key: &str) -> StorageResult<bool> {
        let rows = conn
            .execute("DELETE FROM local_config WHERE key = ?1", [key])
            .map_err(StorageError::Database)?;
        Ok(rows > 0)
    }

    /// Lists all configuration entries.
    pub fn list(conn: &Connection) -> StorageResult<Vec<ConfigEntry>> {
        let mut stmt = conn
            .prepare(
                "SELECT key, value_json, value_type, updated_at FROM local_config ORDER BY key ASC",
            )
            .map_err(StorageError::Database)?;

        let rows = stmt
            .query_map([], |row| {
                Ok(ConfigEntry {
                    key: row.get(0)?,
                    value_json: row.get(1)?,
                    value_type: row.get(2)?,
                    updated_at: row.get(3)?,
                })
            })
            .map_err(StorageError::Database)?;

        let mut entries = Vec::new();
        for row in rows {
            entries.push(row.map_err(StorageError::Database)?);
        }

        Ok(entries)
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
    fn test_config_crud_lifecycle() {
        let conn = setup_test_db();

        // 1. Get non-existent
        assert_eq!(ConfigRepository::get(&conn, "test.key").unwrap(), None);

        // 2. Set string config
        ConfigRepository::set(&conn, "test.key", "\"test_val\"", "string").unwrap();
        let entry = ConfigRepository::get(&conn, "test.key").unwrap().unwrap();
        assert_eq!(entry.key, "test.key");
        assert_eq!(entry.value_json, "\"test_val\"");

        // 3. Set typed struct
        #[derive(Serialize, Deserialize, PartialEq, Debug)]
        struct MySettings {
            enabled: bool,
            interval_sec: u32,
        }
        let settings = MySettings {
            enabled: true,
            interval_sec: 60,
        };
        ConfigRepository::set_typed(&conn, "app.settings", &settings).unwrap();

        let loaded: MySettings = ConfigRepository::get_typed(&conn, "app.settings")
            .unwrap()
            .unwrap();
        assert_eq!(loaded, settings);

        // 4. List
        let all = ConfigRepository::list(&conn).unwrap();
        assert_eq!(all.len(), 2);

        // 5. Delete
        let deleted = ConfigRepository::delete(&conn, "test.key").unwrap();
        assert!(deleted);
        assert_eq!(ConfigRepository::get(&conn, "test.key").unwrap(), None);
    }
}

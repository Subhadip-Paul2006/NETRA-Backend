#[cfg(feature = "insecure-dev-keystore")]
use async_trait::async_trait;
#[cfg(feature = "insecure-dev-keystore")]
use std::fs;
#[cfg(feature = "insecure-dev-keystore")]
use std::path::{Path, PathBuf};
#[cfg(feature = "insecure-dev-keystore")]
use tracing::warn;
#[cfg(feature = "insecure-dev-keystore")]
use zeroize::Zeroizing;

#[cfg(feature = "insecure-dev-keystore")]
use netra_core::error::{NetraError, Result};
#[cfg(feature = "insecure-dev-keystore")]
use netra_core::keystore::KeyStore;

/// INSECURE development and test KeyStore for headless CI test suites.
///
/// COMPILE-TIME GATED: This struct is ONLY compiled when the `insecure-dev-keystore` cargo feature
/// is explicitly enabled. It is physically absent from production release builds.
#[cfg(feature = "insecure-dev-keystore")]
pub struct InsecureDevKeystore {
    storage_dir: PathBuf,
}

#[cfg(feature = "insecure-dev-keystore")]
impl InsecureDevKeystore {
    pub fn new<P: AsRef<Path>>(storage_dir: P) -> Result<Self> {
        warn!(
            "[CRITICAL SECURITY WARNING: INSECURE DEV KEYSTORE ACTIVE - NEVER USE IN PRODUCTION]"
        );
        let dir = storage_dir.as_ref().to_path_buf();
        if !dir.exists() {
            fs::create_dir_all(&dir).map_err(|e| {
                NetraError::storage(format!("Failed to create dev keystore dir: {}", e))
            })?;
        }
        Ok(Self { storage_dir: dir })
    }

    fn key_path(&self, key_id: &str) -> PathBuf {
        self.storage_dir.join(format!("{}.devkey", key_id))
    }
}

#[cfg(feature = "insecure-dev-keystore")]
#[async_trait]
impl KeyStore for InsecureDevKeystore {
    async fn store_private_key(&self, key_id: &str, secret_bytes: &[u8]) -> Result<()> {
        let path = self.key_path(key_id);
        fs::write(&path, secret_bytes)
            .map_err(|e| NetraError::storage(format!("Failed to write dev key file: {}", e)))?;
        Ok(())
    }

    async fn retrieve_private_key(&self, key_id: &str) -> Result<Zeroizing<Vec<u8>>> {
        let path = self.key_path(key_id);
        if !path.exists() {
            return Err(NetraError::storage(format!(
                "Dev private key '{}' not found at '{}'",
                key_id,
                path.display()
            )));
        }

        let bytes = fs::read(&path)
            .map_err(|e| NetraError::storage(format!("Failed to read dev key file: {}", e)))?;

        Ok(Zeroizing::new(bytes))
    }

    async fn delete_private_key(&self, key_id: &str) -> Result<()> {
        let path = self.key_path(key_id);
        if path.exists() {
            let _ = fs::write(&path, [0u8; 64]);
            let _ = fs::remove_file(&path);
        }
        Ok(())
    }

    async fn is_available(&self) -> bool {
        true
    }
}

#[cfg(test)]
#[cfg(feature = "insecure-dev-keystore")]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[tokio::test]
    async fn test_insecure_dev_keystore_crud() {
        let temp = TempDir::new().unwrap();
        let keystore = InsecureDevKeystore::new(temp.path()).unwrap();

        assert!(keystore.is_available().await);

        let key_id = "key_dev_test";
        let secret = [99u8; 32];

        keystore.store_private_key(key_id, &secret).await.unwrap();
        let retrieved = keystore.retrieve_private_key(key_id).await.unwrap();
        assert_eq!(&*retrieved, &secret);

        keystore.delete_private_key(key_id).await.unwrap();
        assert!(keystore.retrieve_private_key(key_id).await.is_err());
    }
}

use async_trait::async_trait;
use std::fs;
use std::path::{Path, PathBuf};
#[cfg(windows)]
use std::ptr;
use tracing::debug;
use zeroize::Zeroizing;

use netra_core::error::{NetraError, Result};
use netra_core::keystore::KeyStore;

#[cfg(windows)]
use windows_sys::Win32::Foundation::LocalFree;
#[cfg(windows)]
use windows_sys::Win32::Security::Cryptography::{
    CryptProtectData, CryptUnprotectData, CRYPTPROTECT_UI_FORBIDDEN, CRYPT_INTEGER_BLOB,
};

/// OS-protected KeyStore implementation for Windows using Win32 DPAPI (Data Protection API).
///
/// Encrypts private key material using the Windows kernel LSA master key tied to the
/// executing user context or machine context (`CryptProtectData`).
pub struct WindowsDpapiKeystore {
    storage_dir: PathBuf,
}

impl WindowsDpapiKeystore {
    /// Creates a new WindowsDpapiKeystore using the specified base directory for ciphertext files.
    pub fn new<P: AsRef<Path>>(storage_dir: P) -> Result<Self> {
        let dir = storage_dir.as_ref().to_path_buf();
        if !dir.exists() {
            fs::create_dir_all(&dir).map_err(|e| {
                NetraError::storage(format!(
                    "Failed to create KeyStore directory at '{}': {}",
                    dir.display(),
                    e
                ))
            })?;
        }
        Ok(Self { storage_dir: dir })
    }

    /// Derives the local path for a key ciphertext file.
    fn key_file_path(&self, key_id: &str) -> PathBuf {
        self.storage_dir.join(format!("{}.dpapi", key_id))
    }

    #[cfg(windows)]
    fn dpapi_protect(plaintext: &[u8]) -> Result<Vec<u8>> {
        let in_blob = CRYPT_INTEGER_BLOB {
            cbData: plaintext.len() as u32,
            pbData: plaintext.as_ptr() as *mut u8,
        };
        let mut out_blob = CRYPT_INTEGER_BLOB {
            cbData: 0,
            pbData: ptr::null_mut(),
        };

        let success = unsafe {
            CryptProtectData(
                &in_blob,
                ptr::null(),
                ptr::null_mut(),
                ptr::null_mut(),
                ptr::null(),
                CRYPTPROTECT_UI_FORBIDDEN,
                &mut out_blob,
            )
        };

        if success == 0 {
            return Err(NetraError::crypto(
                "Win32 CryptProtectData failed to encrypt private key",
            ));
        }

        let encrypted_bytes = unsafe {
            std::slice::from_raw_parts(out_blob.pbData, out_blob.cbData as usize).to_vec()
        };

        // Free DPAPI-allocated buffer
        unsafe {
            LocalFree(out_blob.pbData as _);
        }

        Ok(encrypted_bytes)
    }

    #[cfg(windows)]
    fn dpapi_unprotect(ciphertext: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
        let in_blob = CRYPT_INTEGER_BLOB {
            cbData: ciphertext.len() as u32,
            pbData: ciphertext.as_ptr() as *mut u8,
        };
        let mut out_blob = CRYPT_INTEGER_BLOB {
            cbData: 0,
            pbData: ptr::null_mut(),
        };

        let success = unsafe {
            CryptUnprotectData(
                &in_blob,
                ptr::null_mut(),
                ptr::null_mut(),
                ptr::null_mut(),
                ptr::null(),
                CRYPTPROTECT_UI_FORBIDDEN,
                &mut out_blob,
            )
        };

        if success == 0 {
            return Err(NetraError::crypto(
                "Win32 CryptUnprotectData failed to decrypt private key",
            ));
        }

        let decrypted_bytes = unsafe {
            Zeroizing::new(
                std::slice::from_raw_parts(out_blob.pbData, out_blob.cbData as usize).to_vec(),
            )
        };

        // Free DPAPI-allocated buffer
        unsafe {
            LocalFree(out_blob.pbData as _);
        }

        Ok(decrypted_bytes)
    }

    #[cfg(not(windows))]
    fn dpapi_protect(_plaintext: &[u8]) -> Result<Vec<u8>> {
        Err(NetraError::platform(
            "Windows DPAPI is only available on Windows targets",
        ))
    }

    #[cfg(not(windows))]
    fn dpapi_unprotect(_ciphertext: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
        Err(NetraError::platform(
            "Windows DPAPI is only available on Windows targets",
        ))
    }
}

#[async_trait]
impl KeyStore for WindowsDpapiKeystore {
    async fn store_private_key(&self, key_id: &str, secret_bytes: &[u8]) -> Result<()> {
        let encrypted_bytes = Self::dpapi_protect(secret_bytes)?;
        let path = self.key_file_path(key_id);

        fs::write(&path, encrypted_bytes).map_err(|e| {
            NetraError::storage(format!(
                "Failed to write DPAPI key file at '{}': {}",
                path.display(),
                e
            ))
        })?;

        debug!(
            "Stored DPAPI-protected key '{}' at '{}'",
            key_id,
            path.display()
        );
        Ok(())
    }

    async fn retrieve_private_key(&self, key_id: &str) -> Result<Zeroizing<Vec<u8>>> {
        let path = self.key_file_path(key_id);
        if !path.exists() {
            return Err(NetraError::storage(format!(
                "Private key '{}' not found in KeyStore at '{}'",
                key_id,
                path.display()
            )));
        }

        let ciphertext = fs::read(&path).map_err(|e| {
            NetraError::storage(format!(
                "Failed to read DPAPI key file at '{}': {}",
                path.display(),
                e
            ))
        })?;

        Self::dpapi_unprotect(&ciphertext)
    }

    async fn delete_private_key(&self, key_id: &str) -> Result<()> {
        let path = self.key_file_path(key_id);
        if path.exists() {
            // Overwrite with zeros before deletion
            let _ = fs::write(&path, [0u8; 64]);
            fs::remove_file(&path).map_err(|e| {
                NetraError::storage(format!(
                    "Failed to delete DPAPI key file at '{}': {}",
                    path.display(),
                    e
                ))
            })?;
        }
        debug!("Deleted DPAPI key '{}'", key_id);
        Ok(())
    }

    async fn is_available(&self) -> bool {
        #[cfg(windows)]
        {
            true
        }
        #[cfg(not(windows))]
        {
            false
        }
    }
}

#[cfg(all(test, windows))]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[tokio::test]
    async fn test_windows_dpapi_keystore_lifecycle() {
        let temp_dir = TempDir::new().unwrap();
        let keystore = WindowsDpapiKeystore::new(temp_dir.path()).unwrap();

        assert!(keystore.is_available().await);

        let key_id = "key_01918a2b3c4d";
        let secret = [42u8; 32];

        // Store
        keystore.store_private_key(key_id, &secret).await.unwrap();

        // Retrieve
        let retrieved = keystore.retrieve_private_key(key_id).await.unwrap();
        assert_eq!(&*retrieved, &secret);

        // Delete
        keystore.delete_private_key(key_id).await.unwrap();
        assert!(keystore.retrieve_private_key(key_id).await.is_err());
    }
}

use async_trait::async_trait;
use zeroize::Zeroizing;

use netra_core::error::{NetraError, Result};
use netra_core::keystore::KeyStore;

/// OS-protected KeyStore implementation for macOS using Apple Keychain Services.
pub struct MacosKeychainKeystore;

impl MacosKeychainKeystore {
    pub fn new() -> Self {
        Self
    }
}

impl Default for MacosKeychainKeystore {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl KeyStore for MacosKeychainKeystore {
    async fn store_private_key(&self, _key_id: &str, _secret_bytes: &[u8]) -> Result<()> {
        Err(NetraError::crypto(
            "ERR_KEYSTORE_UNAVAILABLE: macOS Keychain is not accessible.",
        ))
    }

    async fn retrieve_private_key(&self, _key_id: &str) -> Result<Zeroizing<Vec<u8>>> {
        Err(NetraError::crypto(
            "ERR_KEYSTORE_UNAVAILABLE: macOS Keychain is not accessible.",
        ))
    }

    async fn delete_private_key(&self, _key_id: &str) -> Result<()> {
        Err(NetraError::crypto(
            "ERR_KEYSTORE_UNAVAILABLE: macOS Keychain is not accessible.",
        ))
    }

    async fn is_available(&self) -> bool {
        false
    }
}

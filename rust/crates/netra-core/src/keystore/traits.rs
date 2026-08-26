use async_trait::async_trait;
use zeroize::Zeroizing;

use crate::error::Result;

/// Asynchronous interface for OS-native secure credential and private key storage.
///
/// Private key material is stored exclusively through this interface and is never
/// committed to plaintext SQLite databases, logs, or configuration files.
#[async_trait]
pub trait KeyStore: Send + Sync {
    /// Securely encrypts and stores raw private key bytes under the specified key identifier.
    async fn store_private_key(&self, key_id: &str, secret_bytes: &[u8]) -> Result<()>;

    /// Retrieves and decrypts the private key bytes into a memory-cleared zeroizing buffer.
    async fn retrieve_private_key(&self, key_id: &str) -> Result<Zeroizing<Vec<u8>>>;

    /// Permanently deletes the private key material from OS protected storage.
    async fn delete_private_key(&self, key_id: &str) -> Result<()>;

    /// Probes whether the underlying OS secure credential subsystem is active and available.
    async fn is_available(&self) -> bool;
}

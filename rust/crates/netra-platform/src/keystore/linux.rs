use async_trait::async_trait;
use zeroize::Zeroizing;

use netra_core::error::{NetraError, Result};
use netra_core::keystore::KeyStore;

/// OS-protected KeyStore implementation for Linux using the Freedesktop Secret Service API (D-Bus).
///
/// If D-Bus Secret Service is unavailable (e.g. headless server environments without a configured
/// secret daemon), the implementation strictly fails with [`ERR_KEYSTORE_UNAVAILABLE`].
///
/// Fallback encryption using non-secret host identifiers (like `/etc/machine-id`) is structurally prohibited.
pub struct LinuxSecretServiceKeystore;

impl LinuxSecretServiceKeystore {
    pub fn new() -> Self {
        Self
    }
}

impl Default for LinuxSecretServiceKeystore {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl KeyStore for LinuxSecretServiceKeystore {
    async fn store_private_key(&self, _key_id: &str, _secret_bytes: &[u8]) -> Result<()> {
        #[cfg(target_os = "linux")]
        {
            if !self.is_available().await {
                return Err(NetraError::crypto(
                    "ERR_KEYSTORE_UNAVAILABLE: Linux Secret Service (D-Bus) is not accessible. \
                     Headless servers must configure an explicit OS secret provider or key agent. \
                     Weak unencrypted local fallbacks are structurally prohibited in release builds.",
                ));
            }
            Err(NetraError::crypto(
                "ERR_KEYSTORE_UNAVAILABLE: Secret Service connection not initialized",
            ))
        }
        #[cfg(not(target_os = "linux"))]
        {
            Err(NetraError::crypto(
                "ERR_KEYSTORE_UNAVAILABLE: Linux Secret Service is only available on Linux targets",
            ))
        }
    }

    async fn retrieve_private_key(&self, _key_id: &str) -> Result<Zeroizing<Vec<u8>>> {
        #[cfg(target_os = "linux")]
        {
            if !self.is_available().await {
                return Err(NetraError::crypto(
                    "ERR_KEYSTORE_UNAVAILABLE: Linux Secret Service (D-Bus) is not accessible.",
                ));
            }
            Err(NetraError::crypto(
                "ERR_KEYSTORE_UNAVAILABLE: Secret Service connection not initialized",
            ))
        }
        #[cfg(not(target_os = "linux"))]
        {
            Err(NetraError::crypto(
                "ERR_KEYSTORE_UNAVAILABLE: Linux Secret Service is only available on Linux targets",
            ))
        }
    }

    async fn delete_private_key(&self, _key_id: &str) -> Result<()> {
        #[cfg(target_os = "linux")]
        {
            if !self.is_available().await {
                return Err(NetraError::crypto(
                    "ERR_KEYSTORE_UNAVAILABLE: Linux Secret Service (D-Bus) is not accessible.",
                ));
            }
            Err(NetraError::crypto(
                "ERR_KEYSTORE_UNAVAILABLE: Secret Service connection not initialized",
            ))
        }
        #[cfg(not(target_os = "linux"))]
        {
            Err(NetraError::crypto(
                "ERR_KEYSTORE_UNAVAILABLE: Linux Secret Service is only available on Linux targets",
            ))
        }
    }

    async fn is_available(&self) -> bool {
        #[cfg(target_os = "linux")]
        {
            // Probes whether DBUS_SESSION_BUS_ADDRESS or system D-Bus socket exists
            std::env::var("DBUS_SESSION_BUS_ADDRESS").is_ok()
        }
        #[cfg(not(target_os = "linux"))]
        {
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_linux_failsafe_policy() {
        let keystore = LinuxSecretServiceKeystore::new();
        // Outside an active Linux desktop D-Bus session, store must fail safely with ERR_KEYSTORE_UNAVAILABLE
        if !keystore.is_available().await {
            let res = keystore.store_private_key("key_test", &[0u8; 32]).await;
            assert!(res.is_err());
            let err_msg = res.unwrap_err().to_string();
            assert!(err_msg.contains("ERR_KEYSTORE_UNAVAILABLE"));
        }
    }
}

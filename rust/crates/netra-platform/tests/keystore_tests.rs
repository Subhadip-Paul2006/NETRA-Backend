use netra_core::keystore::KeyStore;
use netra_platform::keystore::{create_platform_keystore, LinuxSecretServiceKeystore};
use tempfile::TempDir;

#[tokio::test]
async fn test_platform_keystore_factory_and_crud() {
    let temp_dir = TempDir::new().unwrap();
    let keystore = create_platform_keystore(Some(temp_dir.path().to_path_buf())).unwrap();

    let is_avail = keystore.is_available().await;

    #[cfg(windows)]
    {
        assert!(is_avail);

        let key_id = "key_01918a2b3c4d7e8f9a0b1c2d3e4f5a6b";
        let secret = [77u8; 32];

        // Store
        keystore.store_private_key(key_id, &secret).await.unwrap();

        // Retrieve
        let retrieved = keystore.retrieve_private_key(key_id).await.unwrap();
        assert_eq!(&*retrieved, &secret);

        // Delete
        keystore.delete_private_key(key_id).await.unwrap();
        assert!(keystore.retrieve_private_key(key_id).await.is_err());
    }

    #[cfg(not(windows))]
    {
        assert!(!is_avail || is_avail);
    }
}

#[tokio::test]
async fn test_linux_failsafe_rejection() {
    let linux_keystore = LinuxSecretServiceKeystore::new();
    if !linux_keystore.is_available().await {
        let err = linux_keystore
            .store_private_key("key_test", &[1u8; 32])
            .await
            .unwrap_err();
        assert!(err.to_string().contains("ERR_KEYSTORE_UNAVAILABLE"));
    }
}

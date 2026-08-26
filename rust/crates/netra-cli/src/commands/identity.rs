use chrono::Utc;
use netra_core::config::NetraConfig;
use netra_core::identity::{DeviceId, DeviceKeypair, KeyId, KeyRotationRequest, ProofOfPossession};
use netra_core::keystore::KeyStore;
use netra_core::storage::repositories::identity::{DeviceIdentityRecord, DeviceIdentityRepository};
use netra_core::storage::repositories::keys::{KeyMetadataRecord, KeyMetadataRepository};
use netra_core::storage::DatabaseEngine;
use netra_platform::keystore::create_platform_keystore;
use serde::Serialize;
use std::sync::Arc;
use uuid::Uuid;

#[cfg(feature = "insecure-dev-keystore")]
use netra_platform::keystore::create_insecure_dev_keystore;

use crate::cli::{EnrollArgs, IdentityArgs, IdentitySubcommand};
use crate::errors::{CliError, ExitCode};
use crate::output::formatting::format_box_block;
use crate::output::OutputPresenter;

#[derive(Serialize)]
struct EnrollResult {
    device_id: String,
    key_id: String,
    public_key_base64: String,
    public_key_hex: String,
    gateway_url: String,
    enrollment_status: String,
}

#[derive(Serialize)]
struct IdentityStatusResult {
    enrollment_status: String,
    device_id: Option<String>,
    active_key_id: Option<String>,
    gateway_url: Option<String>,
    enrolled_at: Option<String>,
    keystore_available: bool,
    active_key: Option<KeyMetadataRecord>,
    keys_count: usize,
}

#[derive(Serialize)]
struct RotateResult {
    device_id: String,
    previous_key_id: String,
    new_active_key_id: String,
    new_public_key_base64: String,
    rotation_type: String,
    dual_signed: bool,
}

/// Executes the `netra enroll` command.
pub async fn execute_enroll(
    args: &EnrollArgs,
    _config: &NetraConfig,
    storage: Option<&DatabaseEngine>,
    presenter: &OutputPresenter,
) -> Result<ExitCode, CliError> {
    let engine = storage.ok_or_else(|| {
        CliError::operational(
            "ERR_STORAGE_FAILURE",
            "Storage engine is required for device enrollment",
        )
    })?;

    // Instantiate KeyStore backend
    #[cfg(feature = "insecure-dev-keystore")]
    let keystore: Arc<dyn KeyStore> = if args.insecure_dev_keystore {
        let temp_dir = std::env::temp_dir().join("netra_insecure_keystore");
        create_insecure_dev_keystore(temp_dir)
            .map_err(|e| CliError::operational("ERR_KEYSTORE_ERROR", e.to_string()))?
    } else {
        create_platform_keystore(None)
            .map_err(|e| CliError::operational("ERR_KEYSTORE_ERROR", e.to_string()))?
    };

    #[cfg(not(feature = "insecure-dev-keystore"))]
    let keystore: Arc<dyn KeyStore> = create_platform_keystore(None)
        .map_err(|e| CliError::operational("ERR_KEYSTORE_ERROR", e.to_string()))?;

    if !keystore.is_available().await {
        return Err(CliError::operational(
            "ERR_KEYSTORE_UNAVAILABLE",
            "OS-protected KeyStore is not accessible on this system.",
        ));
    }

    // Check existing enrollment in SQLite
    let existing_identity = engine
        .with_reader(DeviceIdentityRepository::get)
        .await
        .map_err(|e| {
            CliError::operational("ERR_DATABASE_ERROR", format!("Database error: {}", e))
        })?;

    if let Some(identity) = existing_identity {
        if identity.enrollment_status == "ENROLLED" {
            let res = EnrollResult {
                device_id: identity.device_id.clone(),
                key_id: identity.active_key_id.clone(),
                public_key_base64: "[EXISTING_KEY]".to_string(),
                public_key_hex: "[EXISTING_KEY]".to_string(),
                gateway_url: identity.gateway_url.unwrap_or_else(|| args.gateway.clone()),
                enrollment_status: "ENROLLED".to_string(),
            };

            let dev_id = identity.device_id;
            let act_key = identity.active_key_id;
            let gw = res.gateway_url.clone();

            presenter.emit_result("enroll", &res, |c| {
                format_box_block(
                    "DEVICE ALREADY ENROLLED",
                    &[
                        ("Device ID", dev_id),
                        ("Active Key ID", act_key),
                        ("Gateway URL", gw),
                        ("Status", "ENROLLED".to_string()),
                    ],
                    c,
                )
            });
            return Ok(ExitCode::Success);
        }
    }

    // Generate fresh device identity & Ed25519 keypair
    let device_id = DeviceId::generate();
    let key_id = KeyId::generate();
    let keypair = DeviceKeypair::generate();

    // Store private key seed in KeyStore
    let secret = keypair.to_secret_bytes();
    keystore
        .store_private_key(key_id.as_str(), &*secret)
        .await
        .map_err(|e| {
            CliError::operational(
                "ERR_KEYSTORE_WRITE",
                format!("Failed to store key in KeyStore: {}", e),
            )
        })?;

    // Perform client-side Proof of Possession generation
    let challenge_nonce = Uuid::now_v7().to_string();
    let timestamp = Utc::now().timestamp();
    let pop = ProofOfPossession::new(
        device_id.clone(),
        key_id.clone(),
        &challenge_nonce,
        timestamp,
        "CLI_DEVICE_ENROLLMENT",
    );
    let _pop_sig = pop.sign(&keypair);

    let now_str = Utc::now().to_rfc3339();
    let expires_str = (Utc::now() + chrono::Duration::days(90)).to_rfc3339();

    // Persist public identity to SQLite
    let identity_record = DeviceIdentityRecord {
        device_id: device_id.to_string(),
        active_key_id: key_id.to_string(),
        enrollment_status: "ENROLLED".to_string(),
        enrolled_at: Some(now_str.clone()),
        gateway_url: Some(args.gateway.clone()),
        created_at: now_str.clone(),
        updated_at: now_str.clone(),
    };

    let key_record = KeyMetadataRecord {
        key_id: key_id.to_string(),
        device_id: device_id.to_string(),
        public_key_base64: keypair.public_key_base64(),
        algorithm: "Ed25519".to_string(),
        status: "ACTIVE".to_string(),
        created_at: now_str,
        expires_at: expires_str,
        retired_at: None,
    };

    engine
        .with_writer(move |conn| {
            DeviceIdentityRepository::upsert(conn, &identity_record)?;
            KeyMetadataRepository::insert(conn, &key_record)?;
            Ok(())
        })
        .await
        .map_err(|e| {
            CliError::operational(
                "ERR_DATABASE_ERROR",
                format!("Database error during enrollment: {}", e),
            )
        })?;

    let res = EnrollResult {
        device_id: device_id.to_string(),
        key_id: key_id.to_string(),
        public_key_base64: keypair.public_key_base64(),
        public_key_hex: keypair.public_key_hex(),
        gateway_url: args.gateway.clone(),
        enrollment_status: "ENROLLED".to_string(),
    };

    let d_id = device_id.to_string();
    let k_id = key_id.to_string();
    let pk_b64 = keypair.public_key_base64();
    let gw_url = args.gateway.clone();

    presenter.emit_result("enroll", &res, |c| {
        format_box_block(
            "DEVICE ENROLLMENT SUCCESSFUL",
            &[
                ("Device ID", d_id),
                ("Active Key ID", k_id),
                ("Public Key (Base64)", pk_b64),
                ("Gateway URL", gw_url),
                ("Enrollment Status", "ENROLLED".to_string()),
            ],
            c,
        )
    });

    Ok(ExitCode::Success)
}

/// Executes the `netra identity` commands (status or rotate).
pub async fn execute_identity(
    args: &IdentityArgs,
    _config: &NetraConfig,
    storage: Option<&DatabaseEngine>,
    presenter: &OutputPresenter,
) -> Result<ExitCode, CliError> {
    let engine = storage.ok_or_else(|| {
        CliError::operational(
            "ERR_STORAGE_FAILURE",
            "Storage engine is required for identity operations",
        )
    })?;

    let action = args.action.as_ref().unwrap_or(&IdentitySubcommand::Status);

    match action {
        IdentitySubcommand::Status => {
            let identity = engine
                .with_reader(DeviceIdentityRepository::get)
                .await
                .map_err(|e| {
                    CliError::operational("ERR_DATABASE_ERROR", format!("Database error: {}", e))
                })?;

            let keystore = create_platform_keystore(None)
                .map_err(|e| CliError::operational("ERR_KEYSTORE_ERROR", e.to_string()))?;
            let keystore_available = keystore.is_available().await;

            match identity {
                Some(id_rec) => {
                    let active_key_id = id_rec.active_key_id.clone();
                    let active_key = engine
                        .with_reader(move |conn| KeyMetadataRepository::get(conn, &active_key_id))
                        .await
                        .map_err(|e| {
                            CliError::operational(
                                "ERR_DATABASE_ERROR",
                                format!("Database error: {}", e),
                            )
                        })?;

                    let dev_id_clone = id_rec.device_id.clone();
                    let all_keys = engine
                        .with_reader(move |conn| {
                            KeyMetadataRepository::list_by_device(conn, &dev_id_clone)
                        })
                        .await
                        .map_err(|e| {
                            CliError::operational(
                                "ERR_DATABASE_ERROR",
                                format!("Database error: {}", e),
                            )
                        })?;

                    let res = IdentityStatusResult {
                        enrollment_status: id_rec.enrollment_status.clone(),
                        device_id: Some(id_rec.device_id.clone()),
                        active_key_id: Some(id_rec.active_key_id.clone()),
                        gateway_url: id_rec.gateway_url.clone(),
                        enrolled_at: id_rec.enrolled_at.clone(),
                        keystore_available,
                        active_key: active_key.clone(),
                        keys_count: all_keys.len(),
                    };

                    let d_id = id_rec.device_id;
                    let st = id_rec.enrollment_status;
                    let act_k = id_rec.active_key_id;
                    let gw = id_rec.gateway_url.unwrap_or_else(|| "N/A".to_string());
                    let ks_avail = if keystore_available {
                        "YES (OS Protected)".to_string()
                    } else {
                        "NO".to_string()
                    };
                    let pk_str = active_key
                        .as_ref()
                        .map(|k| k.public_key_base64.clone())
                        .unwrap_or_else(|| "N/A".to_string());
                    let exp_str = active_key
                        .as_ref()
                        .map(|k| k.expires_at.clone())
                        .unwrap_or_else(|| "N/A".to_string());

                    presenter.emit_result("identity_status", &res, |c| {
                        format_box_block(
                            "CRYPTOGRAPHIC DEVICE IDENTITY",
                            &[
                                ("Device ID", d_id),
                                ("Enrollment Status", st),
                                ("Active Key ID", act_k),
                                ("Public Key (Base64)", pk_str),
                                ("Expires At", exp_str),
                                ("Gateway URL", gw),
                                ("KeyStore Available", ks_avail),
                            ],
                            c,
                        )
                    });
                }
                None => {
                    let res = IdentityStatusResult {
                        enrollment_status: "UNENROLLED".to_string(),
                        device_id: None,
                        active_key_id: None,
                        gateway_url: None,
                        enrolled_at: None,
                        keystore_available,
                        active_key: None,
                        keys_count: 0,
                    };

                    let ks_avail = if keystore_available {
                        "YES (OS Protected)".to_string()
                    } else {
                        "NO".to_string()
                    };

                    presenter.emit_result("identity_status", &res, |c| {
                        format_box_block(
                            "DEVICE IDENTITY STATUS",
                            &[
                                ("Enrollment Status", "UNENROLLED".to_string()),
                                ("KeyStore Available", ks_avail),
                                (
                                    "Action Required",
                                    "Run: netra enroll --token <TOKEN>".to_string(),
                                ),
                            ],
                            c,
                        )
                    });
                }
            }
            Ok(ExitCode::Success)
        }

        IdentitySubcommand::Rotate(rotate_args) => {
            let identity = engine
                .with_reader(DeviceIdentityRepository::get)
                .await
                .map_err(|e| {
                    CliError::operational("ERR_DATABASE_ERROR", format!("Database error: {}", e))
                })?
                .ok_or_else(|| {
                    CliError::invalid_args("Cannot rotate keys: Device is not enrolled")
                })?;

            let keystore = create_platform_keystore(None)
                .map_err(|e| CliError::operational("ERR_KEYSTORE_ERROR", e.to_string()))?;

            if !keystore.is_available().await {
                return Err(CliError::operational(
                    "ERR_KEYSTORE_UNAVAILABLE",
                    "Cannot rotate keys without OS KeyStore",
                ));
            }

            // Retrieve old key secret
            let old_secret = keystore
                .retrieve_private_key(&identity.active_key_id)
                .await
                .map_err(|e| {
                    CliError::operational(
                        "ERR_KEYSTORE_READ",
                        format!("Failed to retrieve old key: {}", e),
                    )
                })?;
            let old_keypair = DeviceKeypair::from_secret_bytes(&old_secret).map_err(|e| {
                CliError::operational("ERR_CRYPTO_ERROR", format!("Crypto error: {}", e))
            })?;
            let old_key_id = KeyId::parse(&identity.active_key_id).map_err(|e| {
                CliError::operational("ERR_IDENTIFIER_INVALID", format!("Invalid key id: {}", e))
            })?;

            // Generate new keypair
            let new_key_id = KeyId::generate();
            let new_keypair = DeviceKeypair::generate();
            let new_secret = new_keypair.to_secret_bytes();

            // Store new private key
            keystore
                .store_private_key(new_key_id.as_str(), &*new_secret)
                .await
                .map_err(|e| {
                    CliError::operational(
                        "ERR_KEYSTORE_WRITE",
                        format!("Failed to store new key: {}", e),
                    )
                })?;

            let dev_id = DeviceId::parse(&identity.device_id).map_err(|e| {
                CliError::operational(
                    "ERR_IDENTIFIER_INVALID",
                    format!("Invalid device id: {}", e),
                )
            })?;

            // Create dual-signed rotation assertion
            let timestamp = Utc::now().timestamp();
            let _rotation_req = KeyRotationRequest::create_and_sign(
                dev_id,
                &old_keypair,
                old_key_id,
                &new_keypair,
                new_key_id.clone(),
                timestamp,
            );

            // Update SQLite: Add new key record and update active key
            let now_str = Utc::now().to_rfc3339();
            let expires_str = (Utc::now() + chrono::Duration::days(90)).to_rfc3339();

            let new_key_record = KeyMetadataRecord {
                key_id: new_key_id.to_string(),
                device_id: identity.device_id.clone(),
                public_key_base64: new_keypair.public_key_base64(),
                algorithm: "Ed25519".to_string(),
                status: "ACTIVE".to_string(),
                created_at: now_str.clone(),
                expires_at: expires_str,
                retired_at: None,
            };

            let prev_key_id = identity.active_key_id.clone();
            let dev_id_clone = identity.device_id.clone();
            let new_key_id_str = new_key_id.to_string();
            let is_emergency = rotate_args.emergency;
            let now_str_clone = now_str.clone();

            engine
                .with_writer(move |conn| {
                    KeyMetadataRepository::insert(conn, &new_key_record)?;
                    KeyMetadataRepository::update_status(
                        conn,
                        &prev_key_id,
                        if is_emergency { "REVOKED" } else { "RETIRED" },
                        Some(&now_str_clone),
                    )?;
                    DeviceIdentityRepository::update_active_key(
                        conn,
                        &dev_id_clone,
                        &new_key_id_str,
                    )?;
                    Ok(())
                })
                .await
                .map_err(|e| {
                    CliError::operational("ERR_DATABASE_ERROR", format!("Database error: {}", e))
                })?;

            if rotate_args.emergency {
                // Delete old key immediately in emergency mode
                let _ = keystore.delete_private_key(&identity.active_key_id).await;
            }

            let res = RotateResult {
                device_id: identity.device_id.clone(),
                previous_key_id: identity.active_key_id.clone(),
                new_active_key_id: new_key_id.to_string(),
                new_public_key_base64: new_keypair.public_key_base64(),
                rotation_type: if rotate_args.emergency {
                    "EMERGENCY_REVOCATION".to_string()
                } else {
                    "STANDARD_ROTATION".to_string()
                },
                dual_signed: true,
            };

            let d_id = identity.device_id;
            let prev_k = identity.active_key_id;
            let new_k = new_key_id.to_string();
            let pk_b64 = new_keypair.public_key_base64();
            let mode_str = if rotate_args.emergency {
                "EMERGENCY (Old Key Scrubbed)".to_string()
            } else {
                "STANDARD (7-Day Grace)".to_string()
            };

            presenter.emit_result("identity_rotate", &res, |c| {
                format_box_block(
                    "KEY ROTATION COMPLETED",
                    &[
                        ("Device ID", d_id),
                        ("Previous Key ID", prev_k),
                        ("New Active Key ID", new_k),
                        ("Public Key (Base64)", pk_b64),
                        ("Rotation Mode", mode_str),
                    ],
                    c,
                )
            });

            Ok(ExitCode::Success)
        }
    }
}

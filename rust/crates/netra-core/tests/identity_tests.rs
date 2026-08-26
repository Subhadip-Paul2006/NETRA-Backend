use netra_core::identity::{
    CanonicalRequest, DeviceId, DeviceKeypair, KeyId, KeyRotationRequest, ProofOfPossession,
};

#[test]
fn test_device_id_invariants() {
    let id1 = DeviceId::generate();
    let id2 = DeviceId::generate();

    assert_ne!(id1, id2);
    assert!(id1.as_str().starts_with("dev_"));
    assert_eq!(id1.as_str().len(), 36);

    let parsed = DeviceId::parse(id1.as_str()).unwrap();
    assert_eq!(id1, parsed);

    // Rejection cases
    assert!(DeviceId::parse("usr_01918a2b3c4d7e8f9a0b1c2d3e4f5a6b").is_err());
    assert!(DeviceId::parse("dev_invalid_non_hex_character_zzzzzz").is_err());
    assert!(DeviceId::parse("dev_123").is_err());
}

#[test]
fn test_key_id_invariants() {
    let kid1 = KeyId::generate();
    let kid2 = KeyId::generate();

    assert_ne!(kid1, kid2);
    assert!(kid1.as_str().starts_with("key_"));

    let parsed = KeyId::parse(kid1.as_str()).unwrap();
    assert_eq!(kid1, parsed);

    // Supports short fingerprints (>= 8 hex) and full UUIDv7 (32 hex)
    assert!(KeyId::parse("key_01918a2b3c4d").is_ok());
    assert!(KeyId::parse("key_01918a2b3c4d7e8f9a0b1c2d3e4f5a6b").is_ok());
    assert!(KeyId::parse("key_short").is_err()); // 's', 'h', 'o', 'r', 't' are non-hex
    assert!(KeyId::parse("dev_01918a2b3c4d").is_err());
}

#[test]
fn test_rfc_8032_dalek_compatibility() {
    // RFC 8032 Test Vector 1
    let seed_hex = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60";
    let seed_bytes = hex::decode(seed_hex).unwrap();
    let keypair = DeviceKeypair::from_secret_bytes(&seed_bytes).unwrap();

    let expected_pubkey = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a";
    assert_eq!(keypair.public_key_hex(), expected_pubkey);

    let msg = b"";
    let signature = keypair.sign(msg);
    let expected_sig = "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b";
    assert_eq!(hex::encode(signature.to_bytes()), expected_sig);
}

#[test]
fn test_proof_of_possession_full_lifecycle() {
    let dev_id = DeviceId::parse("dev_01918a2b3c4d7e8f9a0b1c2d3e4f5a6b").unwrap();
    let key_id = KeyId::parse("key_01918a2b3c4d").unwrap();
    let nonce = "01918a2b-3c4d-7e8f-9a0b-1c2d3e4f5a6b";
    let timestamp = 1776189500;
    let context = "AGENT_INITIAL_ENROLLMENT";

    let pop = ProofOfPossession::new(dev_id, key_id, nonce, timestamp, context);
    let digest_hex = hex::encode(pop.compute_digest());

    // Matches exact RFC-style test vector in API.md and implementation_plan.md
    assert_eq!(
        digest_hex,
        "607c586844d6749c4bb5d239414f3ece58e54bcd518b5a7d38d97572b568ea1c"
    );

    let keypair = DeviceKeypair::generate();
    let sig_hex = pop.sign(&keypair);
    assert_eq!(sig_hex.len(), 128);

    // Verify against correct public key
    assert!(pop.verify(keypair.verifying_key(), &sig_hex).is_ok());

    // Verify against incorrect public key fails
    let wrong_keypair = DeviceKeypair::generate();
    assert!(pop.verify(wrong_keypair.verifying_key(), &sig_hex).is_err());
}

#[test]
fn test_key_rotation_dual_signature_validation() {
    let dev_id = DeviceId::generate();
    let old_keypair = DeviceKeypair::generate();
    let old_key_id = KeyId::generate();
    let new_keypair = DeviceKeypair::generate();
    let new_key_id = KeyId::generate();
    let timestamp = 1776189500;

    let rotation_req = KeyRotationRequest::create_and_sign(
        dev_id.clone(),
        &old_keypair,
        old_key_id.clone(),
        &new_keypair,
        new_key_id.clone(),
        timestamp,
    );

    assert_eq!(rotation_req.protocol_version, 1);
    assert_eq!(rotation_req.device_id, dev_id);
    assert_eq!(rotation_req.old_key_id, old_key_id);
    assert_eq!(rotation_req.new_key_id, new_key_id);

    // Verify both signatures succeed
    assert!(rotation_req
        .verify(old_keypair.verifying_key(), new_keypair.verifying_key())
        .is_ok());

    // Verify tampering with new public key invalidates signature
    let mut tampered_req = rotation_req.clone();
    tampered_req.new_public_key_base64 = DeviceKeypair::generate().public_key_base64();
    assert!(tampered_req
        .verify(old_keypair.verifying_key(), new_keypair.verifying_key())
        .is_err());
}

#[test]
fn test_canonical_request_signing_and_tampering() {
    let keypair = DeviceKeypair::generate();
    let method = "POST";
    let path = "/api/v1/storage/check";
    let timestamp = 1776189500;
    let nonce = "01918a2b-3c4d-7e8f-9a0b-1c2d3e4f5a6b";
    let request_id = "req_01918a2b3c4d";
    let body = b"{\"deep\":true}";

    let req = CanonicalRequest::new(method, path, timestamp, nonce, request_id, body);
    let sig_hex = req.sign(&keypair);

    assert!(req.verify(keypair.verifying_key(), &sig_hex).is_ok());

    // Modifying method should fail
    let mut bad_method = req.clone();
    bad_method.method = "GET".to_string();
    assert!(bad_method
        .verify(keypair.verifying_key(), &sig_hex)
        .is_err());

    // Modifying timestamp should fail
    let mut bad_time = req.clone();
    bad_time.timestamp += 1;
    assert!(bad_time.verify(keypair.verifying_key(), &sig_hex).is_err());

    // Modifying body hash should fail
    let mut bad_body = req.clone();
    bad_body.body_hash = CanonicalRequest::compute_body_hash(b"{\"deep\":false}");
    assert!(bad_body.verify(keypair.verifying_key(), &sig_hex).is_err());
}

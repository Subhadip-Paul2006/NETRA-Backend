use ed25519_dalek::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::error::{NetraError, Result};
use crate::identity::device_id::DeviceId;
use crate::identity::keypair::{DeviceKeypair, KeyId};
use crate::identity::signer::CanonicalRequest;

/// Explicit domain separation string for device enrollment Proof of Possession challenges.
pub const PROOF_OF_POSSESSION_DOMAIN_V1: &str = "NETRA_PROOF_OF_POSSESSION_V1";

/// Structured challenge-response message for proving private key possession during enrollment.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProofOfPossession {
    pub protocol_version: u32,
    pub device_id: DeviceId,
    pub key_id: KeyId,
    pub challenge_nonce: String,
    pub server_timestamp: i64,
    pub enrollment_context: String,
}

impl ProofOfPossession {
    /// Constructs a new ProofOfPossession challenge object.
    pub fn new(
        device_id: DeviceId,
        key_id: KeyId,
        challenge_nonce: &str,
        server_timestamp: i64,
        enrollment_context: &str,
    ) -> Self {
        Self {
            protocol_version: 1,
            device_id,
            key_id,
            challenge_nonce: challenge_nonce.trim().to_string(),
            server_timestamp,
            enrollment_context: enrollment_context.trim().to_string(),
        }
    }

    /// Builds the format-strict, line-delimited canonical string.
    pub fn canonical_string(&self) -> String {
        let context_hash = CanonicalRequest::compute_body_hash(self.enrollment_context.as_bytes());
        format!(
            "{}\n{}\n{}\n{}\n{}\n{}\n{}",
            PROOF_OF_POSSESSION_DOMAIN_V1,
            self.protocol_version,
            self.device_id.as_str(),
            self.key_id.as_str(),
            self.challenge_nonce,
            self.server_timestamp,
            context_hash
        )
    }

    /// Computes the SHA-256 digest of the canonical proof string.
    pub fn compute_digest(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(self.canonical_string().as_bytes());
        let result = hasher.finalize();
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&result);
        arr
    }

    /// Signs the proof challenge using the device private key, returning a 128-char hex signature.
    pub fn sign(&self, keypair: &DeviceKeypair) -> String {
        let digest = self.compute_digest();
        let sig = keypair.sign(&digest);
        hex::encode(sig.to_bytes())
    }

    /// Verifies the signature against a verifying key.
    pub fn verify(&self, public_key: &VerifyingKey, signature_hex: &str) -> Result<()> {
        let sig_bytes = hex::decode(signature_hex)
            .map_err(|e| NetraError::crypto(format!("Invalid signature hex: {}", e)))?;

        if sig_bytes.len() != 64 {
            return Err(NetraError::crypto(format!(
                "Signature must be exactly 64 bytes, got {}",
                sig_bytes.len()
            )));
        }

        let mut sig_arr = [0u8; 64];
        sig_arr.copy_from_slice(&sig_bytes);
        let signature = Signature::from_bytes(&sig_arr);

        let digest = self.compute_digest();
        DeviceKeypair::verify_signature(public_key, &digest, &signature)
    }
}

/// Durable receipt issued by the control gateway upon successful device enrollment.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceEnrollmentReceipt {
    pub device_id: DeviceId,
    pub key_id: KeyId,
    pub enrolled_at: String,
    pub gateway_id: String,
}

/// Explicit domain separation string for key rotation assertions.
pub const KEY_ROTATION_DOMAIN_V1: &str = "NETRA_KEY_ROTATION_V1";

/// Dual-signed key rotation request transitioning from old key to new key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeyRotationRequest {
    pub protocol_version: u32,
    pub device_id: DeviceId,
    pub old_key_id: KeyId,
    pub new_key_id: KeyId,
    pub new_public_key_base64: String,
    pub timestamp: i64,
    pub signature_by_old_key: String,
    pub signature_by_new_key: String,
}

impl KeyRotationRequest {
    /// Builds the canonical rotation payload string to sign.
    pub fn canonical_rotation_string(
        protocol_version: u32,
        device_id: &DeviceId,
        old_key_id: &KeyId,
        new_key_id: &KeyId,
        new_public_key_base64: &str,
        timestamp: i64,
    ) -> String {
        format!(
            "{}\n{}\n{}\n{}\n{}\n{}\n{}",
            KEY_ROTATION_DOMAIN_V1,
            protocol_version,
            device_id.as_str(),
            old_key_id.as_str(),
            new_key_id.as_str(),
            new_public_key_base64.trim(),
            timestamp
        )
    }

    /// Constructs and dual-signs a key rotation request.
    pub fn create_and_sign(
        device_id: DeviceId,
        old_keypair: &DeviceKeypair,
        old_key_id: KeyId,
        new_keypair: &DeviceKeypair,
        new_key_id: KeyId,
        timestamp: i64,
    ) -> Self {
        let protocol_version = 1;
        let new_public_key_base64 = new_keypair.public_key_base64();
        let canonical_str = Self::canonical_rotation_string(
            protocol_version,
            &device_id,
            &old_key_id,
            &new_key_id,
            &new_public_key_base64,
            timestamp,
        );

        let mut hasher = Sha256::new();
        hasher.update(canonical_str.as_bytes());
        let digest = hasher.finalize();

        let sig_old = old_keypair.sign(&digest);
        let sig_new = new_keypair.sign(&digest);

        Self {
            protocol_version,
            device_id,
            old_key_id,
            new_key_id,
            new_public_key_base64,
            timestamp,
            signature_by_old_key: hex::encode(sig_old.to_bytes()),
            signature_by_new_key: hex::encode(sig_new.to_bytes()),
        }
    }

    /// Verifies that both old and new signatures are cryptographically valid.
    pub fn verify(
        &self,
        old_public_key: &VerifyingKey,
        new_public_key: &VerifyingKey,
    ) -> Result<()> {
        let canonical_str = Self::canonical_rotation_string(
            self.protocol_version,
            &self.device_id,
            &self.old_key_id,
            &self.new_key_id,
            &self.new_public_key_base64,
            self.timestamp,
        );

        let mut hasher = Sha256::new();
        hasher.update(canonical_str.as_bytes());
        let digest = hasher.finalize();

        // Verify old key signature
        let old_sig_bytes = hex::decode(&self.signature_by_old_key)
            .map_err(|e| NetraError::crypto(format!("Invalid old signature hex: {}", e)))?;
        if old_sig_bytes.len() != 64 {
            return Err(NetraError::crypto("Old signature must be 64 bytes"));
        }
        let mut old_sig_arr = [0u8; 64];
        old_sig_arr.copy_from_slice(&old_sig_bytes);
        DeviceKeypair::verify_signature(
            old_public_key,
            &digest,
            &Signature::from_bytes(&old_sig_arr),
        )?;

        // Verify new key signature
        let new_sig_bytes = hex::decode(&self.signature_by_new_key)
            .map_err(|e| NetraError::crypto(format!("Invalid new signature hex: {}", e)))?;
        if new_sig_bytes.len() != 64 {
            return Err(NetraError::crypto("New signature must be 64 bytes"));
        }
        let mut new_sig_arr = [0u8; 64];
        new_sig_arr.copy_from_slice(&new_sig_bytes);
        DeviceKeypair::verify_signature(
            new_public_key,
            &digest,
            &Signature::from_bytes(&new_sig_arr),
        )?;

        Ok(())
    }
}

/// Key rotation response emitted by the gateway confirming new active key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeyRotationResponse {
    pub active_key_id: KeyId,
    pub grace_expires_at: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_proof_of_possession_test_vector_match() {
        let dev_id = DeviceId::parse("dev_01918a2b3c4d7e8f9a0b1c2d3e4f5a6b").unwrap();
        let key_id = KeyId::parse("key_01918a2b3c4d").unwrap();
        let nonce = "01918a2b-3c4d-7e8f-9a0b-1c2d3e4f5a6b";
        let timestamp = 1776189500;
        let context = "AGENT_INITIAL_ENROLLMENT";

        let pop = ProofOfPossession::new(dev_id, key_id, nonce, timestamp, context);
        let digest_hex = hex::encode(pop.compute_digest());

        // Must match exact test vector in implementation_plan.md and docs/API.md
        assert_eq!(
            digest_hex,
            "607c586844d6749c4bb5d239414f3ece58e54bcd518b5a7d38d97572b568ea1c"
        );
    }

    #[test]
    fn test_proof_of_possession_sign_and_verify() {
        let keypair = DeviceKeypair::generate();
        let dev_id = DeviceId::generate();
        let key_id = KeyId::generate();

        let pop = ProofOfPossession::new(
            dev_id,
            key_id,
            "01918a2b-3c4d-7e8f-9a0b-1c2d3e4f5a6b",
            1776189500,
            "AGENT_INITIAL_ENROLLMENT",
        );

        let sig_hex = pop.sign(&keypair);
        assert!(pop.verify(keypair.verifying_key(), &sig_hex).is_ok());

        // Tampering test on challenge nonce
        let mut tampered_pop = pop.clone();
        tampered_pop.challenge_nonce = "01918a2b-3c4d-7e8f-9a0b-1c2d3e4f5a6c".to_string();
        assert!(tampered_pop
            .verify(keypair.verifying_key(), &sig_hex)
            .is_err());
    }

    #[test]
    fn test_key_rotation_dual_sign_and_verify() {
        let dev_id = DeviceId::generate();
        let old_keypair = DeviceKeypair::generate();
        let old_key_id = KeyId::generate();
        let new_keypair = DeviceKeypair::generate();
        let new_key_id = KeyId::generate();

        let rotation_req = KeyRotationRequest::create_and_sign(
            dev_id,
            &old_keypair,
            old_key_id,
            &new_keypair,
            new_key_id,
            1776189500,
        );

        assert!(rotation_req
            .verify(old_keypair.verifying_key(), new_keypair.verifying_key())
            .is_ok());

        // Tampering with timestamp
        let mut tampered = rotation_req.clone();
        tampered.timestamp += 1;
        assert!(tampered
            .verify(old_keypair.verifying_key(), new_keypair.verifying_key())
            .is_err());
    }
}

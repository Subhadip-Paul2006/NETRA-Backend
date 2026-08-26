use ed25519_dalek::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::error::{NetraError, Result};
use crate::identity::keypair::DeviceKeypair;

/// Canonical representation of an HTTP request or security frame for Ed25519 signing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CanonicalRequest {
    pub method: String,
    pub path: String,
    pub timestamp: i64,
    pub nonce: String,
    pub request_id: String,
    pub body_hash: String,
}

impl CanonicalRequest {
    /// Constructs a CanonicalRequest, automatically computing the SHA-256 body hash.
    pub fn new(
        method: &str,
        path: &str,
        timestamp: i64,
        nonce: &str,
        request_id: &str,
        body: &[u8],
    ) -> Self {
        Self {
            method: method.trim().to_ascii_uppercase(),
            path: if path.starts_with('/') {
                path.trim().to_string()
            } else {
                format!("/{}", path.trim())
            },
            timestamp,
            nonce: nonce.trim().to_string(),
            request_id: request_id.trim().to_string(),
            body_hash: Self::compute_body_hash(body),
        }
    }

    /// Computes the lowercase hex-encoded SHA-256 hash of a payload buffer.
    pub fn compute_body_hash(body: &[u8]) -> String {
        let mut hasher = Sha256::new();
        hasher.update(body);
        hex::encode(hasher.finalize())
    }

    /// Builds the deterministic, line-delimited ASCII string to sign.
    ///
    /// ```text
    /// StringToSign = METHOD + "\n" +
    ///                PATH + "\n" +
    ///                TIMESTAMP + "\n" +
    ///                NONCE + "\n" +
    ///                REQUEST_ID + "\n" +
    ///                BODY_HASH
    /// ```
    pub fn string_to_sign(&self) -> String {
        format!(
            "{}\n{}\n{}\n{}\n{}\n{}",
            self.method, self.path, self.timestamp, self.nonce, self.request_id, self.body_hash
        )
    }

    /// Signs the canonical request using the active device keypair, returning a 128-char hex signature.
    pub fn sign(&self, keypair: &DeviceKeypair) -> String {
        let string_to_sign = self.string_to_sign();
        let sig = keypair.sign(string_to_sign.as_bytes());
        hex::encode(sig.to_bytes())
    }

    /// Verifies a hex-encoded signature against a public verifying key.
    pub fn verify(&self, public_key: &VerifyingKey, signature_hex: &str) -> Result<()> {
        let sig_bytes = hex::decode(signature_hex)
            .map_err(|e| NetraError::crypto(format!("Invalid signature hex encoding: {}", e)))?;

        if sig_bytes.len() != 64 {
            return Err(NetraError::crypto(format!(
                "Signature must be exactly 64 bytes, got {}",
                sig_bytes.len()
            )));
        }

        let mut sig_arr = [0u8; 64];
        sig_arr.copy_from_slice(&sig_bytes);
        let signature = Signature::from_bytes(&sig_arr);

        let string_to_sign = self.string_to_sign();
        DeviceKeypair::verify_signature(public_key, string_to_sign.as_bytes(), &signature)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_canonical_string_construction() {
        let req = CanonicalRequest::new(
            "post",
            "api/v1/agent/enroll",
            1776189500,
            "01918a2b-3c4d-7e8f-9a0b-1c2d3e4f5a6b",
            "req_01918a2b3c4d",
            b"{\"test\":true}",
        );

        let expected_body_hash = CanonicalRequest::compute_body_hash(b"{\"test\":true}");
        let expected_str = format!(
            "POST\n/api/v1/agent/enroll\n1776189500\n01918a2b-3c4d-7e8f-9a0b-1c2d3e4f5a6b\nreq_01918a2b3c4d\n{}",
            expected_body_hash
        );

        assert_eq!(req.string_to_sign(), expected_str);
    }

    #[test]
    fn test_canonical_request_sign_and_verify() {
        let keypair = DeviceKeypair::generate();
        let req = CanonicalRequest::new(
            "GET",
            "/api/v1/status",
            1776189500,
            "01918a2b-3c4d-7e8f-9a0b-1c2d3e4f5a6b",
            "req_01918a2b3c4d",
            b"",
        );

        let sig_hex = req.sign(&keypair);
        assert_eq!(sig_hex.len(), 128); // 64 bytes = 128 hex chars
        assert!(req.verify(keypair.verifying_key(), &sig_hex).is_ok());

        // Tampering test on path
        let mut tampered_req = req.clone();
        tampered_req.path = "/api/v1/diagnostics".to_string();
        assert!(tampered_req
            .verify(keypair.verifying_key(), &sig_hex)
            .is_err());
    }
}

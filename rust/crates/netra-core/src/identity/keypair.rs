use base64::prelude::*;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand_core::OsRng;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::fmt;
use std::str::FromStr;
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::error::{NetraError, Result};

/// Strongly-typed key identifier formatted as `key_<32_hex_chars>`.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct KeyId(String);

impl KeyId {
    /// Generates a new random KeyId (UUIDv7).
    pub fn generate() -> Self {
        let raw_hex = Uuid::now_v7().simple().to_string();
        Self(format!("key_{}", raw_hex))
    }

    /// Parses and validates a raw string as a KeyId.
    pub fn parse(s: &str) -> Result<Self> {
        if !s.starts_with("key_") {
            return Err(NetraError::validation(
                "KeyId must start with 'key_' prefix",
            ));
        }

        let hex_part = &s[4..];
        if hex_part.len() < 8 || hex_part.len() > 32 {
            return Err(NetraError::validation(format!(
                "KeyId hex body must be between 8 and 32 characters, got {}",
                hex_part.len()
            )));
        }

        if !hex_part.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err(NetraError::validation(
                "KeyId hex body must contain only hexadecimal characters",
            ));
        }

        Ok(Self(s.to_ascii_lowercase()))
    }

    /// Returns the string slice representation of the KeyId.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl AsRef<str> for KeyId {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for KeyId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl fmt::Debug for KeyId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "KeyId({})", self.0)
    }
}

impl FromStr for KeyId {
    type Err = NetraError;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        Self::parse(s)
    }
}

impl Serialize for KeyId {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for KeyId {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        Self::parse(&s).map_err(serde::de::Error::custom)
    }
}

/// In-memory Ed25519 device keypair for signing operations.
///
/// Private key material is memory-cleared upon drop via `ed25519_dalek::SigningKey`.
pub struct DeviceKeypair {
    signing_key: SigningKey,
    verifying_key: VerifyingKey,
}

impl DeviceKeypair {
    /// Generates a fresh Ed25519 keypair using OS kernel entropy (OsRng).
    pub fn generate() -> Self {
        let signing_key = SigningKey::generate(&mut OsRng);
        let verifying_key = signing_key.verifying_key();
        Self {
            signing_key,
            verifying_key,
        }
    }

    /// Reconstructs a keypair from raw 32-byte private seed bytes.
    pub fn from_secret_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != 32 {
            return Err(NetraError::crypto(format!(
                "Ed25519 private seed must be exactly 32 bytes, got {}",
                bytes.len()
            )));
        }

        let mut seed = [0u8; 32];
        seed.copy_from_slice(bytes);
        let signing_key = SigningKey::from_bytes(&seed);
        let verifying_key = signing_key.verifying_key();

        Ok(Self {
            signing_key,
            verifying_key,
        })
    }

    /// Exports raw private seed bytes inside a zeroizing wrapper.
    pub fn to_secret_bytes(&self) -> Zeroizing<[u8; 32]> {
        Zeroizing::new(self.signing_key.to_bytes())
    }

    /// Returns the public verifying key reference.
    pub fn verifying_key(&self) -> &VerifyingKey {
        &self.verifying_key
    }

    /// Returns the raw 32-byte public key array.
    pub fn public_key_bytes(&self) -> [u8; 32] {
        self.verifying_key.to_bytes()
    }

    /// Returns the Base64-encoded public key string.
    pub fn public_key_base64(&self) -> String {
        BASE64_STANDARD.encode(self.public_key_bytes())
    }

    /// Returns the lowercase hex-encoded public key string.
    pub fn public_key_hex(&self) -> String {
        hex::encode(self.public_key_bytes())
    }

    /// Signs a message buffer using the private signing key.
    pub fn sign(&self, message: &[u8]) -> Signature {
        self.signing_key.sign(message)
    }

    /// Verifies a signature against a verifying key and message.
    pub fn verify_signature(
        verifying_key: &VerifyingKey,
        message: &[u8],
        signature: &Signature,
    ) -> Result<()> {
        verifying_key.verify(message, signature).map_err(|e| {
            NetraError::crypto(format!("Ed25519 signature verification failed: {}", e))
        })
    }

    /// Parses a public verifying key from a Base64 string.
    pub fn parse_public_key_base64(b64: &str) -> Result<VerifyingKey> {
        let bytes = BASE64_STANDARD
            .decode(b64)
            .map_err(|e| NetraError::crypto(format!("Invalid Base64 public key: {}", e)))?;

        if bytes.len() != 32 {
            return Err(NetraError::crypto(format!(
                "Public key must be 32 bytes, got {}",
                bytes.len()
            )));
        }

        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        VerifyingKey::from_bytes(&arr)
            .map_err(|e| NetraError::crypto(format!("Invalid Ed25519 public key bytes: {}", e)))
    }

    /// Parses a public verifying key from a Hex string.
    pub fn parse_public_key_hex(hex_str: &str) -> Result<VerifyingKey> {
        let bytes = hex::decode(hex_str)
            .map_err(|e| NetraError::crypto(format!("Invalid Hex public key: {}", e)))?;

        if bytes.len() != 32 {
            return Err(NetraError::crypto(format!(
                "Public key must be 32 bytes, got {}",
                bytes.len()
            )));
        }

        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        VerifyingKey::from_bytes(&arr)
            .map_err(|e| NetraError::crypto(format!("Invalid Ed25519 public key bytes: {}", e)))
    }
}

impl fmt::Debug for DeviceKeypair {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DeviceKeypair")
            .field("verifying_key", &self.public_key_hex())
            .field("signing_key", &"[REDACTED_PRIVATE_KEY]")
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_key_id_lifecycle() {
        let kid = KeyId::generate();
        assert!(kid.as_str().starts_with("key_"));
        assert_eq!(kid.as_str().len(), 36);
        assert!(KeyId::parse(kid.as_str()).is_ok());
    }

    #[test]
    fn test_keypair_sign_and_verify() {
        let keypair = DeviceKeypair::generate();
        let message = b"NETRA test payload for Ed25519 signing";
        let sig = keypair.sign(message);

        assert!(DeviceKeypair::verify_signature(keypair.verifying_key(), message, &sig).is_ok());

        // Tampering test
        let mut tampered_message = message.to_vec();
        tampered_message[0] ^= 0xFF;
        assert!(
            DeviceKeypair::verify_signature(keypair.verifying_key(), &tampered_message, &sig)
                .is_err()
        );
    }

    #[test]
    fn test_keypair_secret_roundtrip() {
        let keypair = DeviceKeypair::generate();
        let secret = keypair.to_secret_bytes();
        let restored = DeviceKeypair::from_secret_bytes(&*secret).unwrap();
        assert_eq!(keypair.public_key_bytes(), restored.public_key_bytes());
    }

    #[test]
    fn test_rfc_8032_test_vector_1() {
        // RFC 8032 Section 7.1 Test 1 (32-byte secret key seed 9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60)
        let seed = hex::decode("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
            .unwrap();
        let keypair = DeviceKeypair::from_secret_bytes(&seed).unwrap();

        let expected_public = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a";
        assert_eq!(keypair.public_key_hex(), expected_public);

        let message = b"";
        let sig = keypair.sign(message);
        let expected_sig = "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b";
        assert_eq!(hex::encode(sig.to_bytes()), expected_sig);
        assert!(DeviceKeypair::verify_signature(keypair.verifying_key(), message, &sig).is_ok());
    }
}

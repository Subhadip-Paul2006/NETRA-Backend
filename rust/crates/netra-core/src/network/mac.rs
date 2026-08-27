//! # MAC Address Privacy & Pseudonymization
//!
//! Provides strict SHA-256 pseudonymization for Hardware / MAC addresses.
//!
//! **PRIVACY GUARANTEE**: Raw MAC addresses must NEVER be logged, serialized into
//! observation payloads, persisted to database tables, or transmitted over network APIs.
//! All references to hardware addresses use deterministic, 64-character lowercase hexadecimal
//! SHA-256 digests.

use sha2::{Digest, Sha256};

/// Computes the deterministic SHA-256 pseudonymized hash of raw MAC address bytes.
///
/// Accepts standard 6-byte (EUI-48) or 8-byte (EUI-64) hardware addresses.
pub fn hash_mac_bytes(raw_mac_bytes: &[u8]) -> String {
    if raw_mac_bytes.is_empty() || raw_mac_bytes.iter().all(|&b| b == 0) {
        return String::new();
    }
    let mut hasher = Sha256::new();
    hasher.update(b"netra:mac:v1:");
    hasher.update(raw_mac_bytes);
    hex::encode(hasher.finalize())
}

/// Computes the deterministic SHA-256 pseudonymized hash of a MAC address string.
///
/// Normalizes strings like `00:1A:2B:3C:4D:5E`, `00-1a-2b-3c-4d-5e`, or `001a2b3c4d5e`
/// into canonical raw bytes before hashing.
pub fn hash_mac_str(raw_mac_str: &str) -> Option<String> {
    let clean = raw_mac_str.replace([':', '-', '.'], "");
    if clean.len() != 12 && clean.len() != 16 {
        return None;
    }
    let bytes = hex::decode(&clean).ok()?;
    if bytes.iter().all(|&b| b == 0) {
        return None;
    }
    let hash = hash_mac_bytes(&bytes);
    if hash.is_empty() {
        None
    } else {
        Some(hash)
    }
}

/// Validates whether a string is a valid 64-character hex SHA-256 MAC pseudonym.
pub fn is_valid_mac_hash(hash: &str) -> bool {
    hash.len() == 64 && hash.chars().all(|c| c.is_ascii_hexdigit())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mac_hashing_determinism_and_normalization() {
        let mac_colon = "00:1A:2B:3C:4D:5E";
        let mac_dash = "00-1a-2b-3c-4d-5e";
        let mac_raw = [0x00, 0x1a, 0x2b, 0x3c, 0x4d, 0x5e];

        let hash_from_bytes = hash_mac_bytes(&mac_raw);
        let hash_from_colon = hash_mac_str(mac_colon).unwrap();
        let hash_from_dash = hash_mac_str(mac_dash).unwrap();

        assert_eq!(hash_from_bytes, hash_from_colon);
        assert_eq!(hash_from_colon, hash_from_dash);
        assert_eq!(hash_from_bytes.len(), 64);
        assert!(is_valid_mac_hash(&hash_from_bytes));
    }

    #[test]
    fn test_zero_or_empty_mac_returns_empty_or_none() {
        assert_eq!(hash_mac_bytes(&[]), "");
        assert_eq!(hash_mac_bytes(&[0, 0, 0, 0, 0, 0]), "");
        assert_eq!(hash_mac_str("00:00:00:00:00:00"), None);
        assert_eq!(hash_mac_str("invalid_mac"), None);
    }
}

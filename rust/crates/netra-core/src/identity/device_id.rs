use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::fmt;
use std::str::FromStr;
use uuid::Uuid;

use crate::error::{NetraError, Result};

/// Unique, immutable, public device identifier formatted as `dev_<32_hex_chars>`.
///
/// Contains an embedded timestamp (UUIDv7) and is strictly independent of hostnames,
/// MAC addresses, or hardware serial numbers.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct DeviceId(String);

impl DeviceId {
    /// Generates a new random DeviceId with embedded UTC timestamp (UUIDv7).
    pub fn generate() -> Self {
        let raw_hex = Uuid::now_v7().simple().to_string();
        Self(format!("dev_{}", raw_hex))
    }

    /// Parses and validates a raw string as a DeviceId.
    pub fn parse(s: &str) -> Result<Self> {
        if !s.starts_with("dev_") {
            return Err(NetraError::validation(
                "DeviceId must start with 'dev_' prefix",
            ));
        }

        let hex_part = &s[4..];
        if hex_part.len() != 32 {
            return Err(NetraError::validation(format!(
                "DeviceId hex body must be exactly 32 characters, got {}",
                hex_part.len()
            )));
        }

        if !hex_part.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err(NetraError::validation(
                "DeviceId hex body must contain only hexadecimal characters",
            ));
        }

        Ok(Self(s.to_ascii_lowercase()))
    }

    /// Returns the string slice representation of the DeviceId.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl AsRef<str> for DeviceId {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for DeviceId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl fmt::Debug for DeviceId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "DeviceId({})", self.0)
    }
}

impl FromStr for DeviceId {
    type Err = NetraError;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        Self::parse(s)
    }
}

impl Serialize for DeviceId {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for DeviceId {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        Self::parse(&s).map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_device_id_generate_format() {
        let id = DeviceId::generate();
        assert!(id.as_str().starts_with("dev_"));
        assert_eq!(id.as_str().len(), 36); // "dev_" (4) + 32 hex = 36
        assert!(DeviceId::parse(id.as_str()).is_ok());
    }

    #[test]
    fn test_device_id_validation_failures() {
        assert!(DeviceId::parse("usr_01918a2b3c4d7e8f9a0b1c2d3e4f5a6b").is_err());
        assert!(DeviceId::parse("dev_tooshort").is_err());
        assert!(DeviceId::parse("dev_01918a2b3c4d7e8f9a0b1c2d3e4f5a6b_extra").is_err());
        assert!(DeviceId::parse("dev_01918a2b3c4d7e8f9a0b1c2d3e4f5a6g").is_err());
        // 'g' is non-hex
    }

    #[test]
    fn test_device_id_serde_roundtrip() {
        let id = DeviceId::generate();
        let json = serde_json::to_string(&id).unwrap();
        let deserialized: DeviceId = serde_json::from_str(&json).unwrap();
        assert_eq!(id, deserialized);
    }
}

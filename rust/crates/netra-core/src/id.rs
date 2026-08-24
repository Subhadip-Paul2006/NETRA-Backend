use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use uuid::Uuid;

use crate::error::{NetraError, Result};

/// Macro to generate strongly-typed prefixed UUIDv7 identifiers.
macro_rules! define_id {
    ($name:ident, $prefix:expr, $doc:expr) => {
        #[doc = $doc]
        #[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub struct $name(String);

        impl $name {
            /// Generates a new cryptographically unique identifier using UUIDv7 (time-sortable).
            pub fn new() -> Self {
                let u = Uuid::now_v7();
                let clean = u.simple().to_string();
                Self(format!("{}_{}", $prefix, clean))
            }

            /// Creates an identifier from an existing raw string, validating the prefix.
            pub fn parse_str(raw: &str) -> Result<Self> {
                if !raw.starts_with(concat!($prefix, "_")) {
                    return Err(NetraError::invalid_identifier(format!(
                        "Identifier '{}' must start with prefix '{}_'",
                        raw, $prefix
                    )));
                }
                if raw.len() < 10 {
                    return Err(NetraError::invalid_identifier(format!(
                        "Identifier '{}' is too short",
                        raw
                    )));
                }
                Ok(Self(raw.to_string()))
            }

            /// Returns the inner string representation.
            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl Default for $name {
            fn default() -> Self {
                Self::new()
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "{}", self.0)
            }
        }

        impl FromStr for $name {
            type Err = NetraError;

            fn from_str(s: &str) -> Result<Self> {
                Self::parse_str(s)
            }
        }

        impl Serialize for $name {
            fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
            where
                S: Serializer,
            {
                serializer.serialize_str(&self.0)
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
            where
                D: Deserializer<'de>,
            {
                let s = String::deserialize(deserializer)?;
                Self::parse_str(&s).map_err(serde::de::Error::custom)
            }
        }
    };
}

define_id!(
    DeviceId,
    "dev",
    "Globally unique identifier for an enrolled endpoint device host."
);
define_id!(
    TenantId,
    "ten",
    "Unique identifier for an isolated organization or academic tenant."
);
define_id!(
    TaskId,
    "tsk",
    "Unique identifier for an asynchronous scanning or verification task."
);
define_id!(
    FindingId,
    "fnd",
    "Unique identifier for a detected security posture finding."
);
define_id!(
    ObservationId,
    "obs",
    "Unique identifier for an individual raw telemetry observation."
);
define_id!(
    RemediationId,
    "rem",
    "Unique identifier for a controlled remediation execution record."
);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_device_id_generation_and_prefix() {
        let id = DeviceId::new();
        assert!(id.as_str().starts_with("dev_"));
        assert!(id.as_str().len() > 10);
    }

    #[test]
    fn test_tenant_id_parsing_valid() {
        let parsed = TenantId::parse_str("ten_01h8a1b2c3d4e5f6").unwrap();
        assert_eq!(parsed.as_str(), "ten_01h8a1b2c3d4e5f6");
    }

    #[test]
    fn test_invalid_prefix_fails() {
        let err = DeviceId::parse_str("ten_01h8a1b2c3d4").unwrap_err();
        assert!(err.to_string().contains("must start with prefix 'dev_'"));
    }

    #[test]
    fn test_serde_roundtrip() {
        let id = TaskId::new();
        let json = serde_json::to_string(&id).unwrap();
        let deserialized: TaskId = serde_json::from_str(&json).unwrap();
        assert_eq!(id, deserialized);
    }
}

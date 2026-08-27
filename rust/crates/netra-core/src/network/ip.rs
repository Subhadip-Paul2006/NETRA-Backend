//! # IP Address Classification & CIDR Models
//!
//! Provides deterministic categorization for IPv4 and IPv6 addresses according to IANA and RFC standards.

use serde::{Deserialize, Serialize};
use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// Classification of an IP address scope and routing category.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum IpClassification {
    /// Host loopback address (127.0.0.0/8, ::1)
    Loopback,
    /// Private RFC 1918 / RFC 4193 network (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, fc00::/7)
    Private,
    /// Link-local autoconfiguration (169.254.0.0/16, fe80::/10)
    LinkLocal,
    /// Multicast group (224.0.0.0/4, ff00::/8)
    Multicast,
    /// Broadcast address (255.255.255.255)
    Broadcast,
    /// Unspecified / Any address (0.0.0.0, ::)
    Unspecified,
    /// Carrier-Grade NAT / Shared Address Space RFC 6598 (100.64.0.0/10)
    CarrierGradeNat,
    /// Documentation / Benchmark RFC 5737 / RFC 3849 (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24, 2001:db8::/32)
    Documentation,
    /// Globally routable public IP
    PublicGlobal,
}

impl IpClassification {
    /// Classifies an IP address into its deterministic scope category.
    pub fn classify(ip: &IpAddr) -> Self {
        match ip {
            IpAddr::V4(v4) => Self::classify_v4(v4),
            IpAddr::V6(v6) => Self::classify_v6(v6),
        }
    }

    /// Classifies an IPv4 address.
    pub fn classify_v4(v4: &Ipv4Addr) -> Self {
        let octets = v4.octets();
        if v4.is_loopback() {
            Self::Loopback
        } else if v4.is_unspecified() {
            Self::Unspecified
        } else if v4.is_broadcast() {
            Self::Broadcast
        } else if v4.is_multicast() {
            Self::Multicast
        } else if v4.is_link_local() {
            Self::LinkLocal
        } else if v4.is_private() {
            Self::Private
        } else if octets[0] == 100 && (octets[1] & 0xC0) == 64 {
            // 100.64.0.0/10 (CGNAT RFC 6598)
            Self::CarrierGradeNat
        } else if (octets[0] == 192 && octets[1] == 0 && octets[2] == 2)
            || (octets[0] == 198 && octets[1] == 51 && octets[2] == 100)
            || (octets[0] == 203 && octets[1] == 0 && octets[2] == 113)
        {
            // Documentation (TEST-NET-1, TEST-NET-2, TEST-NET-3)
            Self::Documentation
        } else {
            Self::PublicGlobal
        }
    }

    /// Classifies an IPv6 address.
    pub fn classify_v6(v6: &Ipv6Addr) -> Self {
        let segments = v6.segments();
        if v6.is_loopback() {
            Self::Loopback
        } else if v6.is_unspecified() {
            Self::Unspecified
        } else if v6.is_multicast() {
            Self::Multicast
        } else if (segments[0] & 0xffc0) == 0xfe80 {
            // fe80::/10 (Link-Local)
            Self::LinkLocal
        } else if (segments[0] & 0xfe00) == 0xfc00 {
            // fc00::/7 (Unique Local Address RFC 4193)
            Self::Private
        } else if segments[0] == 0x2001 && segments[1] == 0x0db8 {
            // 2001:db8::/32 (Documentation RFC 3849)
            Self::Documentation
        } else {
            Self::PublicGlobal
        }
    }

    /// Returns whether this IP is privately routed (RFC 1918 / ULA) or link-local.
    pub fn is_local_or_private(&self) -> bool {
        matches!(
            self,
            Self::Loopback | Self::Private | Self::LinkLocal | Self::CarrierGradeNat
        )
    }

    /// Returns whether this IP is publicly routable on the global Internet.
    pub fn is_public(&self) -> bool {
        matches!(self, Self::PublicGlobal)
    }
}

impl fmt::Display for IpClassification {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Loopback => write!(f, "LOOPBACK"),
            Self::Private => write!(f, "PRIVATE"),
            Self::LinkLocal => write!(f, "LINK_LOCAL"),
            Self::Multicast => write!(f, "MULTICAST"),
            Self::Broadcast => write!(f, "BROADCAST"),
            Self::Unspecified => write!(f, "UNSPECIFIED"),
            Self::CarrierGradeNat => write!(f, "CARRIER_GRADE_NAT"),
            Self::Documentation => write!(f, "DOCUMENTATION"),
            Self::PublicGlobal => write!(f, "PUBLIC_GLOBAL"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    #[test]
    fn test_ipv4_classifications() {
        assert_eq!(
            IpClassification::classify(&IpAddr::from_str("127.0.0.1").unwrap()),
            IpClassification::Loopback
        );
        assert_eq!(
            IpClassification::classify(&IpAddr::from_str("10.0.1.5").unwrap()),
            IpClassification::Private
        );
        assert_eq!(
            IpClassification::classify(&IpAddr::from_str("172.16.50.1").unwrap()),
            IpClassification::Private
        );
        assert_eq!(
            IpClassification::classify(&IpAddr::from_str("192.168.1.1").unwrap()),
            IpClassification::Private
        );
        assert_eq!(
            IpClassification::classify(&IpAddr::from_str("169.254.10.20").unwrap()),
            IpClassification::LinkLocal
        );
        assert_eq!(
            IpClassification::classify(&IpAddr::from_str("224.0.0.1").unwrap()),
            IpClassification::Multicast
        );
        assert_eq!(
            IpClassification::classify(&IpAddr::from_str("255.255.255.255").unwrap()),
            IpClassification::Broadcast
        );
        assert_eq!(
            IpClassification::classify(&IpAddr::from_str("0.0.0.0").unwrap()),
            IpClassification::Unspecified
        );
        assert_eq!(
            IpClassification::classify(&IpAddr::from_str("100.64.0.1").unwrap()),
            IpClassification::CarrierGradeNat
        );
        assert_eq!(
            IpClassification::classify(&IpAddr::from_str("198.51.100.25").unwrap()),
            IpClassification::Documentation
        );
        assert_eq!(
            IpClassification::classify(&IpAddr::from_str("8.8.8.8").unwrap()),
            IpClassification::PublicGlobal
        );
        assert_eq!(
            IpClassification::classify(&IpAddr::from_str("1.1.1.1").unwrap()),
            IpClassification::PublicGlobal
        );
    }

    #[test]
    fn test_ipv6_classifications() {
        assert_eq!(
            IpClassification::classify(&IpAddr::from_str("::1").unwrap()),
            IpClassification::Loopback
        );
        assert_eq!(
            IpClassification::classify(&IpAddr::from_str("::").unwrap()),
            IpClassification::Unspecified
        );
        assert_eq!(
            IpClassification::classify(&IpAddr::from_str("fe80::1").unwrap()),
            IpClassification::LinkLocal
        );
        assert_eq!(
            IpClassification::classify(&IpAddr::from_str("fd00::1").unwrap()),
            IpClassification::Private
        );
        assert_eq!(
            IpClassification::classify(&IpAddr::from_str("ff02::1").unwrap()),
            IpClassification::Multicast
        );
        assert_eq!(
            IpClassification::classify(&IpAddr::from_str("2001:db8::1").unwrap()),
            IpClassification::Documentation
        );
        assert_eq!(
            IpClassification::classify(&IpAddr::from_str("2606:4700:4700::1111").unwrap()),
            IpClassification::PublicGlobal
        );
    }
}

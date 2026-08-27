//! # Network Domain Contracts & Models
//!
//! Strongly typed models for network interfaces, routing tables, default gateways,
//! DNS resolvers, passive neighbor caches, and in-memory topology snapshots.

pub mod ip;
pub mod mac;
pub mod topology;

pub use ip::IpClassification;
pub use mac::{hash_mac_bytes, hash_mac_str, is_valid_mac_hash};
pub use topology::{
    NetworkTopologySnapshot, TopologyBuilder, TopologyDnsNode, TopologyGatewayNode,
    TopologyInterfaceNode, TopologyNeighborNode, TopologySubnetRecord,
};

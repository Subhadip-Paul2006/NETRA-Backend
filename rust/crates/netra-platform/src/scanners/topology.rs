//! # In-Memory Network Topology Synthesis
//!
//! Re-exports topology synthesis components from `netra-core`.
//!
//! **NOTE**: Topology is NOT a standalone `PostureScanner` collector. It is synthesized
//! in-memory by `ScannerSupervisor` from the results of the 4 native network scanners
//! (`interfaces`, `routes`, `dns`, `neighbors`).

pub use netra_core::network::topology::{
    NetworkTopologySnapshot, TopologyBuilder, TopologyCorrelationEdge, TopologyCorrelator,
    TopologyDnsNode, TopologyEdgeKind, TopologyExtractor, TopologyGatewayNode,
    TopologyInterfaceNode, TopologyNeighborNode, TopologyObservationPayload, TopologySubnetRecord,
    NETWORK_SCANNER_IDS, TOPOLOGY_SCANNER_ID,
};

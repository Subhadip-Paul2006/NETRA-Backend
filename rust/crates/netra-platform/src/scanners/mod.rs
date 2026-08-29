//! # Host Posture Scanners
//!
//! Native operating system collectors for security posture telemetry.

pub mod dns;
pub mod firewall;
pub mod interfaces;
#[allow(dead_code, unused_imports)]
pub mod linux;
#[allow(dead_code, unused_imports)]
pub mod macos;
pub mod neighbors;
pub mod os_config;
pub mod process;
pub mod routes;
pub mod services;
pub mod socket;
pub mod topology;
pub mod users;
#[allow(dead_code, unused_imports)]
pub mod windows;

pub use dns::PlatformDnsScanner;
pub use firewall::PlatformFirewallScanner;
pub use interfaces::PlatformInterfaceScanner;
pub use neighbors::PlatformNeighborScanner;
pub use os_config::PlatformOsConfigScanner;
pub use process::PlatformProcessScanner;
pub use routes::PlatformRouteScanner;
pub use services::PlatformServiceScanner;
pub use socket::PlatformSocketScanner;
pub use topology::{
    NetworkTopologySnapshot, TopologyBuilder, TopologyCorrelationEdge, TopologyCorrelator,
    TopologyDnsNode, TopologyEdgeKind, TopologyExtractor, TopologyGatewayNode,
    TopologyInterfaceNode, TopologyNeighborNode, TopologyObservationPayload, TopologySubnetRecord,
    NETWORK_SCANNER_IDS, TOPOLOGY_SCANNER_ID,
};
pub use users::PlatformUserScanner;

use netra_core::observation::PostureScanner;
use std::sync::Arc;

/// Creates the native OS Socket Posture Scanner.
pub fn create_socket_scanner() -> Arc<dyn PostureScanner> {
    Arc::new(PlatformSocketScanner::new())
}

/// Creates the native OS Network Interface Posture Scanner.
pub fn create_interface_scanner() -> Arc<dyn PostureScanner> {
    Arc::new(PlatformInterfaceScanner::new())
}

/// Creates the native OS Routing Table Posture Scanner.
pub fn create_route_scanner() -> Arc<dyn PostureScanner> {
    Arc::new(PlatformRouteScanner::new())
}

/// Creates the native OS DNS Configuration Posture Scanner.
pub fn create_dns_scanner() -> Arc<dyn PostureScanner> {
    Arc::new(PlatformDnsScanner::new())
}

/// Creates the native OS Neighbor Discovery Posture Scanner.
pub fn create_neighbor_scanner() -> Arc<dyn PostureScanner> {
    Arc::new(PlatformNeighborScanner::new())
}

/// Creates all native OS Posture Scanners for the host.
pub fn create_all_platform_scanners(hash_binaries: bool) -> Vec<Arc<dyn PostureScanner>> {
    vec![
        Arc::new(PlatformSocketScanner::new()),
        Arc::new(PlatformProcessScanner::new(hash_binaries)),
        Arc::new(PlatformFirewallScanner::new()),
        Arc::new(PlatformUserScanner::new()),
        Arc::new(PlatformServiceScanner::new()),
        Arc::new(PlatformOsConfigScanner::new()),
        Arc::new(PlatformInterfaceScanner::new()),
        Arc::new(PlatformRouteScanner::new()),
        Arc::new(PlatformDnsScanner::new()),
        Arc::new(PlatformNeighborScanner::new()),
    ]
}

pub(crate) fn whoami_hostname() -> String {
    std::env::var("COMPUTERNAME")
        .or_else(|_| std::env::var("HOSTNAME"))
        .unwrap_or_else(|_| "localhost".to_string())
}

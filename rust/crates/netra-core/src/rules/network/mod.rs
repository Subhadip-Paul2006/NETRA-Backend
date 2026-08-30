//! # Network Posture Finding Rules (Phase 8.7)
//!
//! Modular infrastructure for evaluating network configuration and topology observations
//! to produce actionable, deterministic security posture findings.

pub mod common;
pub mod net_003;
pub mod net_004;
pub mod net_005;
pub mod net_006;
pub mod net_007;
pub mod net_008;
pub mod registry;

pub use common::{
    extract_dns_payload, extract_interface_payload, extract_neighbor_payload,
    extract_route_payload, extract_topology_payload, format_discriminator, ConfidenceAction,
    GuardrailDecision, NetworkConfidenceGuardrail,
};
pub use net_003::Net003GatewayOffSubnetRule;
pub use net_004::Net004CompetingGatewaysRule;
pub use net_005::Net005InvalidDnsResolverRule;
pub use net_006::Net006LoopbackRouteLeakRule;
pub use net_007::Net007InvalidNeighborEntryRule;
pub use net_008::Net008MultiHomedPublicPrivateRule;
pub use registry::{create_all_network_rules, NetworkRuleMetadata, NetworkRuleRegistry};

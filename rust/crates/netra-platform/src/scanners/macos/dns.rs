//! macOS stub DNS collector.

use netra_core::error::Result;
use netra_core::observation::{DnsObservationPayload, ObservationPayload};

/// macOS stub DNS collector.
///
/// Native verification has not been performed on the current development host.
/// Returns an empty DNS payload which the cross-platform scanner adapter wraps with
/// `PrivilegeStatus::Unsupported` and `ConfidenceScore::HEURISTIC`.
pub fn collect_macos_dns() -> Result<ObservationPayload> {
    Ok(ObservationPayload::Dns(DnsObservationPayload {
        dns_servers: Vec::new(),
        search_domains: Vec::new(),
        is_dynamic_dns_enabled: None,
    }))
}

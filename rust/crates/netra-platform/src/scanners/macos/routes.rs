//! macOS BSD sysctl routing table collector (Stub).

use netra_core::error::Result;
use netra_core::observation::{ObservationPayload, RouteObservationPayload};

/// Collects routes on macOS (Stub).
///
/// NOTE: macOS native kernel routing table inspection via BSD sysctl/PF_ROUTE
/// is not natively implemented or tested on the current development target.
pub fn collect_macos_routes() -> Result<ObservationPayload> {
    Ok(ObservationPayload::Routes(
        RouteObservationPayload::default(),
    ))
}

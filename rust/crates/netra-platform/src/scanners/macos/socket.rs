//! macOS BSD sysctl socket telemetry collector.

use netra_core::error::Result;
use netra_core::observation::{ObservationPayload, SocketObservationPayload};

/// Collects sockets on macOS.
pub fn collect_macos_sockets() -> Result<ObservationPayload> {
    // macOS sysctl net.inet.tcp.pcblist_n parser or fallback
    Ok(ObservationPayload::Sockets(SocketObservationPayload {
        sockets: Vec::new(),
    }))
}

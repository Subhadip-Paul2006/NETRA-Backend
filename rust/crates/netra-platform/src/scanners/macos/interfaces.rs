//! macOS network interface collector (Stub).

use netra_core::error::Result;
use netra_core::observation::{InterfaceObservationPayload, ObservationPayload};

/// Collects interfaces on macOS (Stub).
pub fn collect_macos_interfaces() -> Result<ObservationPayload> {
    Ok(ObservationPayload::Interfaces(
        InterfaceObservationPayload {
            interfaces: Vec::new(),
        },
    ))
}

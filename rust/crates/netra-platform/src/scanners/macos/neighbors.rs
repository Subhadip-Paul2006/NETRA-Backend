//! macOS explicit unsupported neighbor collector stub.
//!
//! # Platform Demarcation
//!
//! Tag: `STUB + NOT NATIVE TESTED`
//!
//! Reading macOS Layer-2 neighbor tables (ARP/NDP) without subprocess execution (`arp -a` / `ndp -a`)
//! requires low-level Darwin routing socket (`AF_ROUTE`) message parsing.
//! Since native Darwin kernel structures cannot be verified on the current Windows host environment,
//! this collector returns an explicit `PrivilegeStatus::Unsupported` without fabricating data.

use netra_core::error::Result;
use netra_core::observation::{NeighborObservationPayload, ObservationPayload};

/// macOS neighbor collector stub returning empty payload for explicit unsupported handling.
pub fn collect_macos_neighbors() -> Result<ObservationPayload> {
    Ok(ObservationPayload::Neighbors(
        NeighborObservationPayload::default(),
    ))
}

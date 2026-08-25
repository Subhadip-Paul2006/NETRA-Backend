//! Asynchronous lifecycle coordination module (re-exported from [`crate::runtime`]).

pub use crate::runtime::component::{ArcComponent, ComponentHealth, ComponentLifecycle};
pub use crate::runtime::coordinator::RuntimeCoordinator;
pub use crate::runtime::state::RuntimeState;

use async_trait::async_trait;

use crate::error::Result;
use crate::id::DeviceId;
use crate::observation::models::{Observation, ObservationType};

/// Asynchronous cross-platform contract for host security posture observation collectors.
#[async_trait]
pub trait PostureScanner: Send + Sync {
    /// Unique identifier of the scanner routine (e.g. `scanner.sockets.v1`).
    fn scanner_id(&self) -> &'static str;

    /// Primary observation domain of this scanner.
    fn domain(&self) -> ObservationType;

    /// Executes the posture observation and returns a normalized [`Observation`].
    async fn scan(&self, device_id: &DeviceId) -> Result<Observation>;
}

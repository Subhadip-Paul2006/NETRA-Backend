//! # Posture Finding Rules & Rule Engine
//!
//! Deterministic security posture evaluation rules and deduplication pipeline.

pub mod baseline;
pub mod engine;
pub mod traits;

pub use baseline::*;
pub use engine::RuleEngine;
pub use traits::{FindingRule, RawFinding};

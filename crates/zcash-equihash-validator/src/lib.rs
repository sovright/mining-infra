//! Equihash solution validation for Zcash Stratum V2
//!
//! This crate provides:
//! - Equihash (200,9) solution verification
//! - Share difficulty validation
//! - Adaptive variable difficulty (vardiff) algorithm

pub mod difficulty;
pub mod error;
pub mod validator;
pub mod vardiff;

pub use difficulty::{Target, compact_to_target, difficulty_to_target, target_to_difficulty};
pub use error::ValidationError;
pub use validator::EquihashValidator;
pub use vardiff::{VardiffConfig, VardiffController, VardiffStats};

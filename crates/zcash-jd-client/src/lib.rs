//! Job Declaration Client for Zcash Stratum V2
//!
//! This crate provides the JD Client that:
//! - Connects to a local Zebra node via Template Provider
//! - Builds custom block templates
//! - Declares jobs to a pool's JD Server
//! - Submits found blocks to both Zebra and the pool

pub mod block_submitter;
pub mod client;
pub mod config;
pub mod declared_job;
pub mod error;
pub mod full_template;
pub mod listener;
pub mod policy;
pub mod relay;
pub mod share_path;
pub mod template_builder;

pub use block_submitter::BlockSubmitter;
pub use client::JdClient;
pub use config::{JdClientConfig, TxSelectionStrategy};
pub use declared_job::{CurrentDeclaredJob, DeclaredJobState};
pub use error::JdClientError;
pub use full_template::FullTemplateBuilder;
pub use listener::{RelayShare, run_listener};
pub use share_path::ShareOutcome;
pub use template_builder::TemplateBuilder;

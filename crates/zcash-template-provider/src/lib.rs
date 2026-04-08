//! Zcash Template Provider for Stratum V2
//!
//! This crate provides a Template Provider that interfaces with Zebra nodes
//! and produces SV2-compatible block templates for Equihash mining.

pub mod commitments;
pub mod error;
pub mod header;
pub mod nonce;
pub mod rpc;
pub mod template;
pub mod types;

pub use commitments::calculate_block_commitments_hash;
pub use error::Error;
pub use rpc::RpcProvider;
pub use header::{assemble_header, parse_target};
pub use nonce::{NoncePartitioner, NonceRange};
pub use template::{TemplateProvider, TemplateProviderConfig};

#[cfg(any(test, feature = "test-support"))]
pub mod testutil;

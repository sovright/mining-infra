//! Test fixtures for E2E testing

pub mod blocks;

#[allow(unused_imports)]
pub use blocks::{
    create_large_block,
    create_minimal_block,
    create_synthetic_block,
    create_testnet_block,
    TestBlock,
};

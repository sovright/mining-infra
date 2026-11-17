//! Receive blocks from Zakura native P2P peers for the Sovright relay.
//!
//! Everything sits behind the `zakura-native` feature.

#[cfg(feature = "zakura-native")]
pub mod native;

#[cfg(all(feature = "zakura-native", feature = "test-support"))]
pub mod test_support;

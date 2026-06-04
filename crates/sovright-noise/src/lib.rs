//! Noise Protocol encryption for Sovright mining infrastructure
//!
//! Implements the Noise NK handshake pattern as specified by SV2.
//! - Server has static keypair (known to clients)
//! - Client uses ephemeral keys
//!
//! ## Usage
//!
//! ```ignore
//! // Server side
//! let keypair = Keypair::generate();
//! let responder = NoiseResponder::new(&keypair);
//! let stream = responder.accept(tcp_stream).await?;
//!
//! // Client side
//! let initiator = NoiseInitiator::new(server_public_key);
//! let stream = initiator.connect(tcp_stream).await?;
//! ```

pub mod keys;
pub mod handshake;
pub mod transport;

pub use keys::{Keypair, PublicKey};
pub use handshake::{NoiseInitiator, NoiseResponder};
pub use transport::NoiseStream;

/// Noise protocol pattern used (NK = known server key)
pub const NOISE_PATTERN: &str = "Noise_NK_25519_ChaChaPoly_BLAKE2s";

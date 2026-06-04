//! UDP transport layer for compact block relay
//!
//! Implements chunked transmission with FEC for low-latency block propagation.

mod chunk;
mod chunker;
mod config;
mod error;
mod pow;
mod session;

pub use chunk::{
    CHUNK_MAGIC, Chunk, ChunkHeader, HEADER_SIZE_V1, HEADER_SIZE_V2, MAX_PAYLOAD_SIZE,
    MAX_TOTAL_CHUNKS, MessageType,
};
pub use chunker::BlockChunker;
pub use config::{ClientConfig, RelayConfig};
pub use error::TransportError;
pub use pow::{
    EQUIHASH_K, EQUIHASH_N, EQUIHASH_SOLUTION_SIZE, EquihashPowValidator, PowResult, PowValidator,
    RejectAllValidator, StubPowValidator, ZCASH_FULL_HEADER_SIZE, ZCASH_HEADER_SIZE,
};
pub use session::{BlockAssembly, RelaySession};

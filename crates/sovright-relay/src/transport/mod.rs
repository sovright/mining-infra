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
    CHUNK_MAGIC, Chunk, ChunkHeader, HEADER_SIZE, HEADER_SIZE_V1, HEADER_SIZE_V2, HEADER_SIZE_V3,
    MAX_PAYLOAD_SIZE, MAX_PAYLOAD_SIZE_V3, MAX_TOTAL_CHUNKS, MessageType, header_size_for_version,
};
pub use chunker::BlockChunker;
pub use config::{AuthKey, ClientConfig, RelayConfig};
pub use error::TransportError;
pub use pow::{
    EQUIHASH_K, EQUIHASH_N, EQUIHASH_SOLUTION_SIZE, EquihashPowValidator, PowResult, PowValidator,
    RejectAllValidator, StubPowValidator, ZCASH_FULL_HEADER_SIZE, ZCASH_HEADER_SIZE,
};
pub use session::{BlockAssembly, RelaySession};

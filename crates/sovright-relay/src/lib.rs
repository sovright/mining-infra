//! sovright-relay: Low-latency block relay network for Zcash
//!
//! This crate implements compact block relay (BIP 152 adapted for Zcash)
//! for bandwidth-efficient block propagation.

pub mod builder;
pub mod compact_block;
pub mod error;
pub mod fec;
pub mod mempool;
pub mod messages;
pub mod reconstructor;
pub mod relay;
pub mod transport;
pub mod types;

pub use builder::CompactBlockBuilder;
pub use compact_block::{CompactBlock, PrefilledTx};
pub use error::CompactBlockError;
pub use fec::FecError;
pub use mempool::{MempoolError, MempoolProvider, TestMempool};
pub use messages::{BlockTxn, GetBlockTxn, SendCmpct};
pub use reconstructor::{CompactBlockReconstructor, ReconstructionResult};
pub use transport::{BlockAssembly, BlockChunker, Chunk, ChunkHeader, ClientConfig, EquihashPowValidator, MessageType, PowResult, PowValidator, RejectAllValidator, RelayConfig, RelaySession, StubPowValidator, TransportError, CHUNK_MAGIC, EQUIHASH_K, EQUIHASH_N, EQUIHASH_SOLUTION_SIZE, MAX_PAYLOAD_SIZE, ZCASH_FULL_HEADER_SIZE, ZCASH_HEADER_SIZE};
pub use relay::{BlockReceiver, BlockSender, MetricsSnapshot, RelayClient, RelayMetrics, RelayNode};
pub use types::{AuthDigest, BlockHash, ShortId, TxId, WtxId};

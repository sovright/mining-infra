//! sovright-relay: Low-latency block relay network for Zcash
//!
//! This crate implements compact block relay (BIP 152 adapted for Zcash)
//! for bandwidth-efficient block propagation.

pub mod builder;
pub mod compact_block;
pub mod error;
pub mod fec;
pub mod hash;
pub mod mempool;
pub mod messages;
pub mod reconstructor;
pub mod relay;
pub mod segmented_block;
pub mod transport;
pub mod tx_feed;
pub mod types;

pub use builder::CompactBlockBuilder;
pub use compact_block::{CompactBlock, PrefilledTx};
pub use error::CompactBlockError;
pub use fec::FecError;
pub use hash::{consensus_block_hash, consensus_block_hash_display, zcash_block_hash};
pub use mempool::{
    MempoolError, MempoolProvider, TestMempool, TxCache, TxCacheConfig, TxCacheInsertOutcome,
    TxCacheSnapshot,
};
pub use messages::{BlockTxn, GetBlockTxn, SendCmpct};
pub use reconstructor::{CompactBlockReconstructor, ReconstructionResult};
pub use relay::{
    ArrivalSink, BlockReceiver, BlockSender, MetricsSnapshot, RelayClient, RelayMetrics, RelayNode,
    RelayPayload, render_prometheus_text,
};
pub use segmented_block::{
    RawBlockSegment, SegmentedBlockError, reassemble_raw_block, segment_object_hash,
    split_raw_block,
};
pub use transport::{
    BlockAssembly, BlockChunker, CHUNK_MAGIC, Chunk, ChunkHeader, ClientConfig, EQUIHASH_K,
    EQUIHASH_N, EQUIHASH_SOLUTION_SIZE, EquihashPowValidator, MAX_PAYLOAD_SIZE, MessageType,
    PowResult, PowValidator, RejectAllValidator, RelayConfig, RelaySession, StubPowValidator,
    TransportError, ZCASH_FULL_HEADER_SIZE, ZCASH_HEADER_SIZE,
};
pub use tx_feed::{TxFeedError, TxFeedRecord};
pub use types::{AuthDigest, BlockHash, ShortId, TxId, WtxId};

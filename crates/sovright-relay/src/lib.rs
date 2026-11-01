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
pub mod merkle;
pub mod messages;
pub mod reconstructor;
pub mod relay;
pub mod segmented_block;
#[cfg(any(test, feature = "test-support"))]
pub mod test_support;
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
pub use merkle::{
    BlockBodyError, MAX_BLOCK_BYTES, ParsedBlockBody, TX_READER_BRANCH_HINT, header_merkle_root,
    merkle_root, parse_block_body, transactions_match_merkle_root, txid_from_tx_bytes,
    validate_block_body, validate_block_transactions,
};
pub use messages::{BlockTxn, GetBlockTxn, SendCmpct};
pub use reconstructor::{CompactBlockReconstructor, ReconstructionResult};
pub use relay::{
    ArrivalSink, BOUND_SEND_BURST_DELAY, BOUND_SEND_BURST_PACKETS, BlockReceiver, BlockSender,
    BoundArrivals, BoundBlock, BoundForwardConfig, BoundHandoffs, BoundIngress, BoundNodeUsage,
    BoundProbe, BoundProgress, BoundRawConfig, BoundUsed, MetricsSnapshot, RelayClient,
    RelayMetrics, RelayNode, RelayPayload, SendReport, body_frames, bound_raw_refused, is_bound,
    render_prometheus_text, sealed_body, sealed_frame,
};
pub use segmented_block::{
    RawBlockSegment, SegmentedBlockError, compact_v3_object_hash, reassemble_raw_block,
    segment_object_hash, skeleton_object_hash, split_raw_block,
};
pub use transport::{
    AuthKey, BlockAssembly, BlockChunker, CHUNK_MAGIC, Chunk, ChunkHeader, ClientConfig,
    EQUIHASH_K, EQUIHASH_N, EQUIHASH_SOLUTION_SIZE, EquihashPowValidator, KeyRole,
    MAX_PAYLOAD_SIZE, MessageType, PowResult, PowValidator, RejectAllValidator, RelayConfig,
    RelaySession, StubPowValidator, TargetCheck, TransportError, ZCASH_FULL_HEADER_SIZE,
    ZCASH_HEADER_SIZE, header_meets_stated_target,
};
pub use tx_feed::{TxFeedError, TxFeedRecord};
pub use types::{AuthDigest, BlockHash, ShortId, TxId, WtxId};

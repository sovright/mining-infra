use std::sync::Arc;
use std::time::Duration;

use sovright_relay::{
    BlockChunker, BlockSender, ClientConfig, CompactBlock, MAX_PAYLOAD_SIZE, RawBlockSegment,
    RelayClient, TransportError, split_raw_block,
};
use tokio::sync::RwLock;
use tokio::time::sleep;
use tracing::{info, warn};

use crate::block::{
    compact_block_from_raw_block, compact_block_from_raw_block_with_tx_cache,
    skeleton_compact_block_from_raw_block,
};
use crate::config::Config;
use crate::error::{IngressError, Result};
use crate::tx_cache::TxCache;

const RELAY_LEN_PREFIX_BYTES: usize = 4;

/// Upper bound on the serialized compact-skeleton size worth sending as a
/// redundant, heavier-parity early copy ahead of the full compact block. The
/// skeleton is a strict duplicate of the reconstruction-critical data, so for a
/// large object the extra copy is pure overhead -- above this the full compact
/// block (the push fallback) is left to carry it alone. Typical Zcash compact
/// blocks are ~1.5-2.5 KB (the Equihash header dominates); this admits normal
/// blocks and skips oversized / cold-cache (large-prefill) ones.
const SKELETON_MAX_WIRE_BYTES: usize = 8 * 1024;

/// Bounded, time-windowed LRU of recently-forwarded block hashes. Used by
/// `RelayBridge::forward_block` to implement first-seen-wins dedup so the
/// same block being delivered by multiple P2P peers (the steady-state case)
/// is only encoded and broadcast once into the relay mesh.
#[derive(Debug)]
struct RecentForwardedHashes {
    capacity: usize,
    window: Duration,
    entries: std::collections::VecDeque<([u8; 32], std::time::Instant)>,
}

impl RecentForwardedHashes {
    fn new(capacity: usize, window: Duration) -> Self {
        Self {
            capacity,
            window,
            entries: std::collections::VecDeque::with_capacity(capacity.max(1)),
        }
    }

    fn contains(&mut self, hash: &[u8; 32], now: std::time::Instant) -> bool {
        self.evict_expired(now);
        self.entries.iter().any(|(h, _)| h == hash)
    }

    fn record(&mut self, hash: [u8; 32], now: std::time::Instant) {
        self.evict_expired(now);
        if self.capacity == 0 {
            return;
        }
        if self.entries.len() == self.capacity {
            self.entries.pop_front();
        }
        self.entries.push_back((hash, now));
    }

    fn evict_expired(&mut self, now: std::time::Instant) {
        while let Some((_, ts)) = self.entries.front() {
            if now.duration_since(*ts) > self.window {
                self.entries.pop_front();
            } else {
                break;
            }
        }
    }
}

#[derive(Clone)]
pub struct RelayBridge {
    sender: BlockSender,
    data_shards: usize,
    parity_shards: usize,
    /// FEC chunker cached at construction: building the RS(224,32) codec is
    /// ~100ms of matrix math, far too expensive for the per-block hot path.
    chunker: Arc<BlockChunker>,
    compact_from_tx_cache: bool,
    /// Send a compact skeleton first (and redundantly) ahead of the full
    /// compact block. Only acts when `compact_from_tx_cache` is also on and a
    /// tx cache is supplied to `forward_block`.
    skeleton_first: bool,
    raw_fallback_with_tx_cache: bool,
    raw_segment_send_rounds: usize,
    raw_segment_round_delay: Duration,
    /// Shared dedup ring for first-seen-wins forward suppression. Cloned
    /// bridges share the same state via `Arc`.
    recent_forwarded: Arc<std::sync::Mutex<RecentForwardedHashes>>,
}

impl RelayBridge {
    pub async fn from_config(config: &Config) -> Result<Option<Self>> {
        let Some(auth_key) = config.relay_auth_key else {
            return Ok(None);
        };
        if config.relay_peers.is_empty() {
            return Ok(None);
        }

        let mut client = Self::new_client_for_config(config, auth_key)?;
        client
            .bind()
            .await
            .map_err(|e| IngressError::Relay(e.to_string()))?;
        let sender = client.sender();
        let client = Arc::new(RwLock::new(client));
        tokio::spawn(async move {
            let mut client = client.write().await;
            if let Err(error) = client.run().await {
                warn!(%error, "Sovright relay client exited");
            }
        });
        info!(
            peers = config.relay_peers.len(),
            data_shards = config.relay_data_shards,
            parity_shards = config.relay_parity_shards,
            raw_segment_send_rounds = config.relay_raw_segment_send_rounds,
            raw_segment_round_delay_millis = config.relay_raw_segment_round_delay_millis,
            "Relay bridge enabled"
        );
        Ok(Some(Self {
            sender,
            data_shards: config.relay_data_shards,
            parity_shards: config.relay_parity_shards,
            chunker: Arc::new(
                BlockChunker::new(config.relay_data_shards, config.relay_parity_shards)
                    .map_err(|e| IngressError::Relay(e.to_string()))?,
            ),
            compact_from_tx_cache: config.relay_compact_from_tx_cache,
            skeleton_first: config.relay_skeleton_first,
            raw_fallback_with_tx_cache: config.relay_raw_fallback_with_tx_cache,
            raw_segment_send_rounds: config.relay_raw_segment_send_rounds,
            raw_segment_round_delay: Duration::from_millis(
                config.relay_raw_segment_round_delay_millis,
            ),
            recent_forwarded: Arc::new(std::sync::Mutex::new(RecentForwardedHashes::new(
                config.relay_forward_dedup_capacity,
                config.relay_forward_dedup_window,
            ))),
        }))
    }

    #[cfg(test)]
    fn new_for_config(config: &Config) -> Result<Self> {
        let auth_key = config
            .relay_auth_key
            .ok_or_else(|| IngressError::Relay("missing relay auth key".to_string()))?;
        let client = Self::new_client_for_config(config, auth_key)?;
        let sender = client.sender();
        Ok(Self {
            sender,
            data_shards: config.relay_data_shards,
            parity_shards: config.relay_parity_shards,
            chunker: Arc::new(
                BlockChunker::new(config.relay_data_shards, config.relay_parity_shards)
                    .map_err(|e| IngressError::Relay(e.to_string()))?,
            ),
            compact_from_tx_cache: config.relay_compact_from_tx_cache,
            skeleton_first: config.relay_skeleton_first,
            raw_fallback_with_tx_cache: config.relay_raw_fallback_with_tx_cache,
            raw_segment_send_rounds: config.relay_raw_segment_send_rounds,
            raw_segment_round_delay: Duration::from_millis(
                config.relay_raw_segment_round_delay_millis,
            ),
            recent_forwarded: Arc::new(std::sync::Mutex::new(RecentForwardedHashes::new(
                config.relay_forward_dedup_capacity,
                config.relay_forward_dedup_window,
            ))),
        })
    }

    fn new_client_for_config(config: &Config, auth_key: [u8; 32]) -> Result<RelayClient> {
        let client_config = ClientConfig::new(config.relay_peers.clone(), auth_key)
            .with_bind_addr(config.relay_bind_addr)
            .with_fec(config.relay_data_shards, config.relay_parity_shards)
            .with_adaptive_fec(config.relay_adaptive_fec)
            .with_send_pacing(
                config.relay_send_burst_packets,
                Duration::from_micros(config.relay_send_burst_delay_micros),
            )
            .with_auth_required(true);
        RelayClient::new(client_config).map_err(|e| IngressError::Relay(e.to_string()))
    }

    pub async fn forward_block(
        &self,
        block_payload: &[u8],
        tx_cache: Option<&TxCache>,
    ) -> Result<ForwardedBlock> {
        let compact = if self.compact_from_tx_cache {
            if let Some(tx_cache) = tx_cache {
                compact_block_from_raw_block_with_tx_cache(block_payload, tx_cache)?
            } else {
                compact_block_from_raw_block(block_payload)?
            }
        } else {
            compact_block_from_raw_block(block_payload)?
        };
        let tx_count = compact.tx_count();
        // Wire size of the compact object as serialized for the relay. The
        // event's bytes field reports what is actually sent per mode (0 for
        // deduplicated), NOT the full block size -- downstream consumers
        // compare it against p2p_block_received bytes to measure savings.
        let compact_wire_bytes = BlockChunker::serialize_compact_block(&compact).len();

        // First-seen-wins dedup. Under steady state multiple Zcash P2P peers
        // deliver the same block within the same few hundred milliseconds.
        // Without this check each delivery re-encodes and re-broadcasts the
        // block into the relay mesh, multiplying mesh traffic for no benefit.
        // The decision is recorded on successful broadcast so a half-failed
        // forward can be retried by the next delivery.
        let header_hash = *compact.header_hash().as_bytes();
        {
            let now = std::time::Instant::now();
            let mut ring = self
                .recent_forwarded
                .lock()
                .expect("recent_forwarded mutex poisoned");
            if ring.contains(&header_hash, now) {
                return Ok(ForwardedBlock {
                    tx_count,
                    bytes: 0,
                    relay_objects: 0,
                    mode: ForwardMode::Deduplicated,
                });
            }
        }
        if let Err(error) = self.preflight_chunks(&compact) {
            let text = error.to_string();
            if text.contains("all-prefilled compact block too large") {
                let segments =
                    self.raw_block_segments(*compact.header_hash().as_bytes(), block_payload)?;
                let raw_wire_bytes = self.raw_segments_wire_bytes(&segments);
                let relay_objects = self.send_raw_block_segments(&segments).await?;
                self.record_forwarded(header_hash);
                return Ok(ForwardedBlock {
                    tx_count,
                    bytes: raw_wire_bytes,
                    relay_objects,
                    mode: ForwardMode::RawBlockSegments,
                });
            }
            return Err(self.with_segment_plan(error, &compact, block_payload));
        }
        // Skeleton fast path: emit the reconstruction-critical skeleton first
        // (and with heavier FEC parity) so a receiver that already holds the
        // block's transactions reconstructs and submits before the FEC'd compact
        // bodies arrive. The full compact block below is the push fallback, so it
        // is ALWAYS sent afterward -- the skeleton never suppresses it. Only
        // meaningful with tx-cache compaction (short_id compact blocks).
        if self.skeleton_first
            && self.compact_from_tx_cache
            && let Some(tx_cache) = tx_cache
        {
            match skeleton_compact_block_from_raw_block(block_payload, tx_cache) {
                Ok(skeleton) => {
                    // Small-block guard: the skeleton is only worth an extra
                    // redundant, heavier-parity early copy when (a) it carries
                    // short_ids a receiver can resolve from its own mempool --
                    // an all-prefilled skeleton reconstructs from nothing, so
                    // it would only ever duplicate the full block -- and (b) it
                    // is small enough that the duplicate send is cheap. Oversized
                    // / cold-cache (large-prefill) blocks are left to the full
                    // compact block alone.
                    let skeleton_bytes = BlockChunker::serialize_compact_block(&skeleton).len();
                    if !skeleton.short_ids.is_empty() && skeleton_bytes <= SKELETON_MAX_WIRE_BYTES {
                        self.sender
                            .send_skeleton(skeleton)
                            .await
                            .map_err(map_transport_error)?;
                    }
                }
                Err(error) => {
                    warn!(%error, "Failed to build compact skeleton; sending full compact block only");
                }
            }
        }
        self.sender
            .send(compact.clone())
            .await
            .map_err(map_transport_error)?;
        if self.raw_fallback_with_tx_cache
            && self.compact_from_tx_cache
            && !compact.short_ids.is_empty()
        {
            let segments =
                self.raw_block_segments(*compact.header_hash().as_bytes(), block_payload)?;
            let raw_wire_bytes = self.raw_segments_wire_bytes(&segments);
            let raw_segment_relay_objects = self.send_raw_block_segments(&segments).await?;
            self.record_forwarded(header_hash);
            return Ok(ForwardedBlock {
                tx_count,
                bytes: compact_wire_bytes + raw_wire_bytes,
                relay_objects: raw_segment_relay_objects + 1,
                mode: ForwardMode::CompactBlockWithRawFallback,
            });
        }
        self.record_forwarded(header_hash);
        Ok(ForwardedBlock {
            tx_count,
            bytes: compact_wire_bytes,
            relay_objects: 1,
            mode: ForwardMode::CompactBlock,
        })
    }

    /// Record a successfully-forwarded block hash in the dedup ring.
    fn record_forwarded(&self, header_hash: [u8; 32]) {
        let now = std::time::Instant::now();
        if let Ok(mut ring) = self.recent_forwarded.lock() {
            ring.record(header_hash, now);
        }
    }

    fn with_segment_plan(
        &self,
        error: IngressError,
        compact: &CompactBlock,
        block_payload: &[u8],
    ) -> IngressError {
        let text = error.to_string();
        if !text.contains("all-prefilled compact block too large") {
            return error;
        }
        match self.plan_raw_block_segments(*compact.header_hash().as_bytes(), block_payload) {
            Ok(plan) => IngressError::Relay(format!(
                "{text}; segmented raw block plan: segments={} object_bytes={} max_segment_frame_bytes={}",
                plan.segment_count, plan.object_bytes, plan.max_segment_frame_bytes
            )),
            Err(plan_error) => IngressError::Relay(format!(
                "{text}; segmented raw block plan unavailable: {plan_error}"
            )),
        }
    }

    fn preflight_chunks(&self, compact: &CompactBlock) -> Result<()> {
        let block_hash = compact.header_hash();
        let serialized_len = BlockChunker::serialize_compact_block(compact).len();
        let max_data_bytes = self.data_shards.saturating_mul(MAX_PAYLOAD_SIZE);
        if serialized_len > max_data_bytes {
            return Err(IngressError::Relay(format!(
                "all-prefilled compact block too large for current relay frame budget: \
                 serialized_bytes={serialized_len} max_data_bytes={max_data_bytes} \
                 data_shards={} parity_shards={} max_payload={MAX_PAYLOAD_SIZE}; \
                 production full-block relay needs compact reconstruction or segmented object framing",
                self.data_shards, self.parity_shards
            )));
        }
        self.chunker
            .compact_block_to_chunks(compact, block_hash.as_bytes())
            .map(|_| ())
            .map_err(|e| IngressError::Relay(e.to_string()))
    }

    fn plan_raw_block_segments(
        &self,
        block_hash: [u8; 32],
        block_payload: &[u8],
    ) -> Result<RawBlockSegmentPlan> {
        let max_segment_frame_bytes = self.raw_segment_frame_budget();
        let segments = split_raw_block(block_hash, block_payload, max_segment_frame_bytes)
            .map_err(|e| IngressError::Relay(e.to_string()))?;
        Ok(RawBlockSegmentPlan {
            segment_count: segments.len(),
            object_bytes: block_payload.len(),
            max_segment_frame_bytes,
        })
    }

    fn raw_block_segments(
        &self,
        block_hash: [u8; 32],
        block_payload: &[u8],
    ) -> Result<Vec<sovright_relay::RawBlockSegment>> {
        let max_segment_frame_bytes = self.raw_segment_frame_budget();
        split_raw_block(block_hash, block_payload, max_segment_frame_bytes)
            .map_err(|e| IngressError::Relay(e.to_string()))
    }

    fn raw_segment_frame_budget(&self) -> usize {
        self.data_shards
            .saturating_mul(MAX_PAYLOAD_SIZE)
            .saturating_sub(RELAY_LEN_PREFIX_BYTES)
    }

    fn raw_segments_wire_bytes(&self, segments: &[RawBlockSegment]) -> usize {
        segments.iter().map(|s| s.encoded_len()).sum::<usize>() * self.raw_segment_send_rounds
    }

    async fn send_raw_block_segments(&self, segments: &[RawBlockSegment]) -> Result<usize> {
        let mut relay_objects = 0;
        for round in 0..self.raw_segment_send_rounds {
            for segment in segments {
                self.sender
                    .send_raw_block_segment(segment.clone())
                    .await
                    .map_err(map_transport_error)?;
                relay_objects += 1;
            }
            if round + 1 < self.raw_segment_send_rounds && !self.raw_segment_round_delay.is_zero() {
                sleep(self.raw_segment_round_delay).await;
            }
        }
        Ok(relay_objects)
    }
}

pub struct ForwardedBlock {
    pub tx_count: usize,
    pub bytes: usize,
    pub relay_objects: usize,
    pub mode: ForwardMode,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ForwardMode {
    CompactBlock,
    CompactBlockWithRawFallback,
    RawBlockSegments,
    /// First-seen-wins dedup: this block hash was already forwarded within
    /// the dedup window, so the bridge skipped encoding and broadcast.
    /// `ForwardedBlock.relay_objects` is 0 in this case.
    Deduplicated,
}

impl ForwardMode {
    pub fn as_str(self) -> &'static str {
        match self {
            ForwardMode::CompactBlock => "compact_block",
            ForwardMode::CompactBlockWithRawFallback => "compact_block_with_raw_fallback",
            ForwardMode::RawBlockSegments => "raw_block_segments",
            ForwardMode::Deduplicated => "deduplicated",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct RawBlockSegmentPlan {
    segment_count: usize,
    object_bytes: usize,
    max_segment_frame_bytes: usize,
}

fn map_transport_error(error: TransportError) -> IngressError {
    IngressError::Relay(error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tx_cache::{TxCacheConfig, TxInventoryKey};
    use sovright_relay::{
        PrefilledTx, RawBlockSegment, RelayPayload, ZCASH_FULL_HEADER_SIZE, reassemble_raw_block,
    };
    use std::path::PathBuf;
    use std::time::Duration;

    fn bridge_with_default_fec() -> RelayBridge {
        let config = ClientConfig::new(vec!["127.0.0.1:1".parse().unwrap()], [0x42; 32])
            .with_auth_required(true);
        let client = RelayClient::new(config).unwrap();
        RelayBridge {
            sender: client.sender(),
            data_shards: 10,
            parity_shards: 3,
            chunker: Arc::new(BlockChunker::new(10, 3).unwrap()),
            compact_from_tx_cache: false,
            skeleton_first: false,
            raw_fallback_with_tx_cache: false,
            raw_segment_send_rounds: 1,
            raw_segment_round_delay: Duration::ZERO,
            recent_forwarded: Arc::new(std::sync::Mutex::new(RecentForwardedHashes::new(
                64,
                Duration::from_secs(30),
            ))),
        }
    }

    fn minimal_v1_tx(tag: u8) -> Vec<u8> {
        let mut tx = Vec::new();
        tx.extend_from_slice(&1u32.to_le_bytes());
        crate::wire::encode_compact_size(0, &mut tx);
        crate::wire::encode_compact_size(0, &mut tx);
        tx.extend_from_slice(&(tag as u32).to_le_bytes());
        tx
    }

    fn two_tx_raw_block() -> (Vec<u8>, Vec<u8>, Vec<u8>) {
        let header = vec![0xab; ZCASH_FULL_HEADER_SIZE];
        let tx0 = minimal_v1_tx(0x11);
        let tx1 = minimal_v1_tx(0x22);
        let mut block = header;
        crate::wire::encode_compact_size(2, &mut block);
        block.extend_from_slice(&tx0);
        block.extend_from_slice(&tx1);
        (block, tx0, tx1)
    }

    fn large_raw_block() -> Vec<u8> {
        let mut block = vec![0xab; ZCASH_FULL_HEADER_SIZE];
        crate::wire::encode_compact_size(2_000, &mut block);
        for _ in 0..2_000 {
            block.extend_from_slice(&1u32.to_le_bytes());
            crate::wire::encode_compact_size(0, &mut block);
            crate::wire::encode_compact_size(0, &mut block);
            block.extend_from_slice(&0u32.to_le_bytes());
        }
        block
    }

    #[tokio::test]
    async fn forward_block_reuses_cached_fec_codec() {
        // Building the production RS(224,32) codec is ~100ms of matrix
        // construction. Rebuilding it inside every forward put a flat ~150ms
        // on the relay's critical path per block (measured in production
        // 2026-07-01), spending the relay's entire inter-region head start.
        // Forwarding several distinct blocks must therefore be decisively
        // cheaper than rebuilding the codec once per block.
        let client = RelayClient::new(
            ClientConfig::new(vec!["127.0.0.1:1".parse().unwrap()], [0x42; 32])
                .with_auth_required(true),
        )
        .unwrap();
        let bridge = RelayBridge {
            sender: client.sender(),
            data_shards: 224,
            parity_shards: 32,
            chunker: Arc::new(BlockChunker::new(224, 32).unwrap()),
            compact_from_tx_cache: false,
            skeleton_first: false,
            raw_fallback_with_tx_cache: false,
            raw_segment_send_rounds: 1,
            raw_segment_round_delay: Duration::ZERO,
            recent_forwarded: Arc::new(std::sync::Mutex::new(RecentForwardedHashes::new(
                64,
                Duration::from_secs(30),
            ))),
        };

        let t = std::time::Instant::now();
        let _codec = BlockChunker::new(224, 32).unwrap();
        let codec_build = t.elapsed();

        let mut blocks = Vec::new();
        for tag in 0u8..6 {
            let mut block = vec![0xab; ZCASH_FULL_HEADER_SIZE];
            block[0] = tag; // distinct hash per block so dedup never triggers
            crate::wire::encode_compact_size(1, &mut block);
            block.extend_from_slice(&minimal_v1_tx(tag));
            blocks.push(block);
        }

        // Warm-up forward absorbs any one-time lazy initialization.
        bridge.forward_block(&blocks[0], None).await.unwrap();

        let t = std::time::Instant::now();
        for block in &blocks[1..] {
            let forwarded = bridge.forward_block(block, None).await.unwrap();
            assert_eq!(forwarded.mode, ForwardMode::CompactBlock);
        }
        let five_forwards = t.elapsed();

        assert!(
            five_forwards < codec_build.max(Duration::from_millis(5)) * 3,
            "5 forwards took {five_forwards:?} vs codec build {codec_build:?}; \
             the FEC codec is being rebuilt per forwarded block"
        );
    }

    #[tokio::test]
    async fn forwarded_bytes_report_wire_bytes_per_mode() {
        // The bytes field previously logged block_payload.len() for every
        // mode, so downstream wire-vs-full comparisons (dashboard bytes card,
        // 24h fullness panel) compared full-to-full by construction. It must
        // report what was actually handed to the relay per mode.
        let (raw_block, tx0, tx1) = two_tx_raw_block();
        let cache = TxCache::new(TxCacheConfig {
            max_entries: 8,
            max_bytes: 4096,
            max_tx_bytes: 512,
        });
        cache.insert(TxInventoryKey::wtx([0x31; 32], [0x41; 32]).to_wtxid(), tx0);
        cache.insert(TxInventoryKey::wtx([0x32; 32], [0x42; 32]).to_wtxid(), tx1);

        let client = RelayClient::new(
            ClientConfig::new(vec!["127.0.0.1:1".parse().unwrap()], [0x42; 32])
                .with_auth_required(true),
        )
        .unwrap();
        let bridge = RelayBridge {
            sender: client.sender(),
            data_shards: 10,
            parity_shards: 3,
            chunker: Arc::new(BlockChunker::new(10, 3).unwrap()),
            compact_from_tx_cache: true,
            skeleton_first: false,
            raw_fallback_with_tx_cache: false,
            raw_segment_send_rounds: 1,
            raw_segment_round_delay: Duration::ZERO,
            recent_forwarded: Arc::new(std::sync::Mutex::new(RecentForwardedHashes::new(
                64,
                Duration::from_secs(30),
            ))),
        };

        let forwarded = bridge
            .forward_block(&raw_block, Some(&cache))
            .await
            .unwrap();
        assert_eq!(forwarded.mode, ForwardMode::CompactBlock);
        let compact =
            crate::block::compact_block_from_raw_block_with_tx_cache(&raw_block, &cache).unwrap();
        let compact_wire = BlockChunker::serialize_compact_block(&compact).len();
        assert_eq!(forwarded.bytes, compact_wire);

        // Dedup suppresses the send entirely: nothing goes on the wire.
        let forwarded = bridge
            .forward_block(&raw_block, Some(&cache))
            .await
            .unwrap();
        assert_eq!(forwarded.mode, ForwardMode::Deduplicated);
        assert_eq!(forwarded.bytes, 0);
    }

    #[tokio::test]
    async fn forwarded_bytes_count_raw_fallback_segments_and_rounds() {
        let (raw_block, tx0, tx1) = two_tx_raw_block();
        let cache = TxCache::new(TxCacheConfig {
            max_entries: 8,
            max_bytes: 4096,
            max_tx_bytes: 512,
        });
        cache.insert(TxInventoryKey::wtx([0x33; 32], [0x43; 32]).to_wtxid(), tx0);
        cache.insert(TxInventoryKey::wtx([0x34; 32], [0x44; 32]).to_wtxid(), tx1);

        let client = RelayClient::new(
            ClientConfig::new(vec!["127.0.0.1:1".parse().unwrap()], [0x42; 32])
                .with_auth_required(true),
        )
        .unwrap();
        let bridge = RelayBridge {
            sender: client.sender(),
            data_shards: 10,
            parity_shards: 3,
            chunker: Arc::new(BlockChunker::new(10, 3).unwrap()),
            compact_from_tx_cache: true,
            skeleton_first: false,
            raw_fallback_with_tx_cache: true,
            raw_segment_send_rounds: 2,
            raw_segment_round_delay: Duration::ZERO,
            recent_forwarded: Arc::new(std::sync::Mutex::new(RecentForwardedHashes::new(
                64,
                Duration::from_secs(30),
            ))),
        };

        let forwarded = bridge
            .forward_block(&raw_block, Some(&cache))
            .await
            .unwrap();
        assert_eq!(forwarded.mode, ForwardMode::CompactBlockWithRawFallback);
        let compact =
            crate::block::compact_block_from_raw_block_with_tx_cache(&raw_block, &cache).unwrap();
        let compact_wire = BlockChunker::serialize_compact_block(&compact).len();
        let segments = bridge
            .plan_raw_block_segments(*compact.header_hash().as_bytes(), &raw_block)
            .map(|plan| {
                split_raw_block(
                    *compact.header_hash().as_bytes(),
                    &raw_block,
                    plan.max_segment_frame_bytes,
                )
                .unwrap()
            })
            .unwrap();
        let raw_wire: usize = segments.iter().map(|s| s.encoded_len()).sum();
        assert_eq!(forwarded.bytes, compact_wire + raw_wire * 2);
    }

    #[test]
    fn preflight_reports_all_prefilled_frame_budget_for_large_blocks() {
        let compact = CompactBlock::new(
            vec![0xab; ZCASH_FULL_HEADER_SIZE],
            0,
            Vec::new(),
            vec![PrefilledTx {
                index: 0,
                tx_data: vec![0xcd; 20_000],
            }],
        );

        let err = bridge_with_default_fec()
            .preflight_chunks(&compact)
            .unwrap_err();

        assert!(
            err.to_string()
                .contains("all-prefilled compact block too large"),
            "{err}"
        );
        assert!(err.to_string().contains("data_shards=10"), "{err}");
    }

    #[test]
    fn raw_block_segment_plan_uses_current_fec_budget() {
        let bridge = bridge_with_default_fec();
        let raw_block = vec![0xab; 25_000];
        let block_hash = [0x42; 32];

        let plan = bridge
            .plan_raw_block_segments(block_hash, &raw_block)
            .unwrap();
        let segments =
            split_raw_block(block_hash, &raw_block, plan.max_segment_frame_bytes).unwrap();
        let reassembled = reassemble_raw_block(&segments).unwrap();

        assert_eq!(plan.object_bytes, raw_block.len());
        assert!(plan.segment_count > 1);
        assert!(
            segments
                .iter()
                .all(|segment: &RawBlockSegment| segment.encoded_len()
                    <= plan.max_segment_frame_bytes)
        );
        let chunker = BlockChunker::new(bridge.data_shards, bridge.parity_shards).unwrap();
        for segment in &segments {
            chunker.raw_block_segment_to_chunks(segment).unwrap();
        }
        assert_eq!(reassembled, raw_block);
    }

    #[tokio::test]
    async fn forwards_raw_block_segments_when_compact_exceeds_current_fec_budget() {
        let mut client = RelayClient::new(
            ClientConfig::new(vec!["127.0.0.1:1".parse().unwrap()], [0x42; 32])
                .with_auth_required(true),
        )
        .unwrap();
        let sender = client.sender();
        let (_receiver, mut outgoing) = client.take_receiver().unwrap();
        let bridge = RelayBridge {
            sender,
            data_shards: 10,
            parity_shards: 3,
            chunker: Arc::new(BlockChunker::new(10, 3).unwrap()),
            compact_from_tx_cache: false,
            skeleton_first: false,
            raw_fallback_with_tx_cache: false,
            raw_segment_send_rounds: 1,
            raw_segment_round_delay: Duration::ZERO,
            recent_forwarded: Arc::new(std::sync::Mutex::new(RecentForwardedHashes::new(
                64,
                Duration::from_secs(30),
            ))),
        };
        let raw_block = large_raw_block();

        let forwarded = bridge.forward_block(&raw_block, None).await.unwrap();

        assert_eq!(forwarded.mode, ForwardMode::RawBlockSegments);
        assert!(forwarded.relay_objects > 1);

        let mut segments = Vec::new();
        for _ in 0..forwarded.relay_objects {
            let payload = outgoing.recv().await.expect("segment queued");
            match payload {
                RelayPayload::RawBlockSegment(segment) => segments.push(segment),
                other => panic!("expected raw block segment, got {other:?}"),
            }
        }

        let reassembled = reassemble_raw_block(&segments).unwrap();
        assert_eq!(reassembled, raw_block);
    }

    #[tokio::test]
    async fn configured_raw_segment_send_rounds_retransmit_each_segment() {
        let mut client = RelayClient::new(
            ClientConfig::new(vec!["127.0.0.1:1".parse().unwrap()], [0x42; 32])
                .with_auth_required(true),
        )
        .unwrap();
        let sender = client.sender();
        let (_receiver, mut outgoing) = client.take_receiver().unwrap();
        let bridge = RelayBridge {
            sender,
            data_shards: 10,
            parity_shards: 3,
            chunker: Arc::new(BlockChunker::new(10, 3).unwrap()),
            compact_from_tx_cache: false,
            skeleton_first: false,
            raw_fallback_with_tx_cache: false,
            raw_segment_send_rounds: 3,
            raw_segment_round_delay: Duration::ZERO,
            recent_forwarded: Arc::new(std::sync::Mutex::new(RecentForwardedHashes::new(
                64,
                Duration::from_secs(30),
            ))),
        };
        let raw_block = large_raw_block();

        let forwarded = bridge.forward_block(&raw_block, None).await.unwrap();

        assert_eq!(forwarded.mode, ForwardMode::RawBlockSegments);
        assert_eq!(forwarded.relay_objects % 3, 0);
        let segments_per_round = forwarded.relay_objects / 3;
        assert!(segments_per_round > 1);

        let mut segments = Vec::new();
        for _ in 0..forwarded.relay_objects {
            let payload = outgoing.recv().await.expect("segment queued");
            match payload {
                RelayPayload::RawBlockSegment(segment) => segments.push(segment),
                other => panic!("expected raw block segment, got {other:?}"),
            }
        }

        for round in segments.chunks_exact(segments_per_round) {
            assert_eq!(reassemble_raw_block(round).unwrap(), raw_block);
        }
    }

    #[tokio::test]
    async fn tx_cache_compact_forwarding_can_send_raw_fallback_segments() {
        let mut client = RelayClient::new(
            ClientConfig::new(vec!["127.0.0.1:1".parse().unwrap()], [0x42; 32])
                .with_auth_required(true),
        )
        .unwrap();
        let sender = client.sender();
        let (_receiver, mut outgoing) = client.take_receiver().unwrap();
        let bridge = RelayBridge {
            sender,
            data_shards: 10,
            parity_shards: 3,
            chunker: Arc::new(BlockChunker::new(10, 3).unwrap()),
            compact_from_tx_cache: true,
            skeleton_first: false,
            raw_fallback_with_tx_cache: true,
            raw_segment_send_rounds: 1,
            raw_segment_round_delay: Duration::ZERO,
            recent_forwarded: Arc::new(std::sync::Mutex::new(RecentForwardedHashes::new(
                64,
                Duration::from_secs(30),
            ))),
        };
        let (raw_block, _tx0, tx1) = two_tx_raw_block();
        let tx_cache = TxCache::new(TxCacheConfig {
            max_entries: 8,
            max_bytes: 4_096,
            max_tx_bytes: 2_048,
        });
        tx_cache.insert(TxInventoryKey::wtx([0x41; 32], [0x42; 32]).to_wtxid(), tx1);

        let forwarded = bridge
            .forward_block(&raw_block, Some(&tx_cache))
            .await
            .unwrap();

        assert_eq!(forwarded.mode, ForwardMode::CompactBlockWithRawFallback);
        assert!(forwarded.relay_objects > 1);

        let first = outgoing.recv().await.expect("compact block queued");
        match first {
            RelayPayload::CompactBlock(compact) => {
                assert_eq!(compact.tx_count(), 2);
                assert_eq!(compact.short_ids.len(), 1);
            }
            other => panic!("compact block should be sent first, got {other:?}"),
        }

        let mut segments = Vec::new();
        for _ in 1..forwarded.relay_objects {
            let payload = outgoing.recv().await.expect("raw fallback segment queued");
            match payload {
                RelayPayload::RawBlockSegment(segment) => segments.push(segment),
                other => panic!("expected raw fallback segment, got {other:?}"),
            }
        }
        assert_eq!(reassemble_raw_block(&segments).unwrap(), raw_block);
    }

    #[tokio::test]
    async fn forward_block_flag_off_emits_no_skeleton() {
        // With skeleton_first off, forward_block sends exactly the compact block
        // and nothing else -- byte-for-byte the current behavior.
        let mut client = RelayClient::new(
            ClientConfig::new(vec!["127.0.0.1:1".parse().unwrap()], [0x42; 32])
                .with_auth_required(true),
        )
        .unwrap();
        let sender = client.sender();
        let (_receiver, mut outgoing) = client.take_receiver().unwrap();
        let bridge = RelayBridge {
            sender,
            data_shards: 10,
            parity_shards: 3,
            chunker: Arc::new(BlockChunker::new(10, 3).unwrap()),
            compact_from_tx_cache: true,
            skeleton_first: false,
            raw_fallback_with_tx_cache: false,
            raw_segment_send_rounds: 1,
            raw_segment_round_delay: Duration::ZERO,
            recent_forwarded: Arc::new(std::sync::Mutex::new(RecentForwardedHashes::new(
                64,
                Duration::from_secs(30),
            ))),
        };
        let (raw_block, _tx0, tx1) = two_tx_raw_block();
        let tx_cache = TxCache::new(TxCacheConfig {
            max_entries: 8,
            max_bytes: 4_096,
            max_tx_bytes: 2_048,
        });
        tx_cache.insert(TxInventoryKey::wtx([0x41; 32], [0x42; 32]).to_wtxid(), tx1);

        let forwarded = bridge
            .forward_block(&raw_block, Some(&tx_cache))
            .await
            .unwrap();
        assert_eq!(forwarded.mode, ForwardMode::CompactBlock);

        // Exactly one payload, and it is the compact block (no skeleton).
        match outgoing.recv().await.expect("compact block queued") {
            RelayPayload::CompactBlock(_) => {}
            other => panic!("expected only a compact block, got {other:?}"),
        }
        assert!(
            outgoing.try_recv().is_err(),
            "no second payload should be sent when skeleton_first is off"
        );
    }

    #[tokio::test]
    async fn forward_block_skeleton_first_sends_skeleton_then_compact() {
        // With skeleton_first on and tx-cache compaction, forward_block emits the
        // CompactSkeleton FIRST, then the full CompactBlock push fallback.
        let mut client = RelayClient::new(
            ClientConfig::new(vec!["127.0.0.1:1".parse().unwrap()], [0x42; 32])
                .with_auth_required(true),
        )
        .unwrap();
        let sender = client.sender();
        let (_receiver, mut outgoing) = client.take_receiver().unwrap();
        let bridge = RelayBridge {
            sender,
            data_shards: 10,
            parity_shards: 3,
            chunker: Arc::new(BlockChunker::new(10, 3).unwrap()),
            compact_from_tx_cache: true,
            skeleton_first: true,
            raw_fallback_with_tx_cache: false,
            raw_segment_send_rounds: 1,
            raw_segment_round_delay: Duration::ZERO,
            recent_forwarded: Arc::new(std::sync::Mutex::new(RecentForwardedHashes::new(
                64,
                Duration::from_secs(30),
            ))),
        };
        let (raw_block, _tx0, tx1) = two_tx_raw_block();
        let tx_cache = TxCache::new(TxCacheConfig {
            max_entries: 8,
            max_bytes: 4_096,
            max_tx_bytes: 2_048,
        });
        tx_cache.insert(TxInventoryKey::wtx([0x41; 32], [0x42; 32]).to_wtxid(), tx1);

        let forwarded = bridge
            .forward_block(&raw_block, Some(&tx_cache))
            .await
            .unwrap();
        assert_eq!(forwarded.mode, ForwardMode::CompactBlock);

        // Skeleton first ...
        let skeleton = match outgoing.recv().await.expect("skeleton queued") {
            RelayPayload::CompactSkeleton(skeleton) => skeleton,
            other => panic!("expected skeleton first, got {other:?}"),
        };
        assert_eq!(skeleton.short_ids.len(), 1, "tx1 resolved to a short_id");
        assert_eq!(skeleton.prefilled_txs.len(), 1, "only coinbase prefilled");

        // ... then the full compact block push fallback.
        match outgoing.recv().await.expect("compact block queued") {
            RelayPayload::CompactBlock(compact) => {
                assert_eq!(compact.header, skeleton.header);
            }
            other => panic!("expected compact block second, got {other:?}"),
        }
        assert!(outgoing.try_recv().is_err(), "exactly two payloads");
    }

    #[tokio::test]
    async fn forward_block_skeleton_guard_skips_all_prefilled() {
        // Small-block guard: a block whose txs are NOT in the cache is
        // all-prefilled (no short_ids), so its skeleton could only duplicate the
        // full block -- the guard must suppress it and send ONLY the compact
        // block, even with skeleton_first on.
        let mut client = RelayClient::new(
            ClientConfig::new(vec!["127.0.0.1:1".parse().unwrap()], [0x42; 32])
                .with_auth_required(true),
        )
        .unwrap();
        let sender = client.sender();
        let (_receiver, mut outgoing) = client.take_receiver().unwrap();
        let bridge = RelayBridge {
            sender,
            data_shards: 10,
            parity_shards: 3,
            chunker: Arc::new(BlockChunker::new(10, 3).unwrap()),
            compact_from_tx_cache: true,
            skeleton_first: true,
            raw_fallback_with_tx_cache: false,
            raw_segment_send_rounds: 1,
            raw_segment_round_delay: Duration::ZERO,
            recent_forwarded: Arc::new(std::sync::Mutex::new(RecentForwardedHashes::new(
                64,
                Duration::from_secs(30),
            ))),
        };
        let (raw_block, _tx0, _tx1) = two_tx_raw_block();
        // Empty cache => tx1 cannot resolve to a short_id => all-prefilled.
        let tx_cache = TxCache::new(TxCacheConfig {
            max_entries: 8,
            max_bytes: 4_096,
            max_tx_bytes: 2_048,
        });

        let forwarded = bridge
            .forward_block(&raw_block, Some(&tx_cache))
            .await
            .unwrap();
        assert_eq!(forwarded.mode, ForwardMode::CompactBlock);

        // Exactly one payload -- the compact block -- and it is NOT a skeleton.
        match outgoing.recv().await.expect("compact block queued") {
            RelayPayload::CompactBlock(compact) => {
                assert!(compact.short_ids.is_empty(), "all txs prefilled");
            }
            other => panic!("expected compact block, got {other:?}"),
        }
        assert!(
            outgoing.try_recv().is_err(),
            "guard must suppress the skeleton for an all-prefilled block"
        );
    }

    fn test_config() -> Config {
        Config {
            seeds: Vec::new(),
            peers: vec!["127.0.0.1:8233".parse().unwrap()],
            max_peers: 1,
            connect_timeout: Duration::from_secs(1),
            peer_runtime: Duration::from_secs(0),
            crawler_enabled: false,
            crawler_max_known_peers: 1,
            crawler_max_addr_per_message: 1,
            crawler_drain_interval: Duration::from_secs(1),
            rotation_enabled: false,
            rotation_cooldown: Duration::from_secs(1),
            rotation_failure_cooldown: Duration::from_secs(1),
            accept_nonstandard_ports: false,
            peer_scoring_enabled: false,
            peer_score_block_inv: 5,
            peer_score_block_received: 25,
            peer_score_relay_forwarded: 10,
            peer_score_error: -50,
            tx_cache_enabled: false,
            tx_cache_max_entries: 200_000,
            tx_cache_max_bytes: 536_870_912,
            tx_cache_max_tx_bytes: 2_097_152,
            tx_feed_addr: None,
            tx_request_limit_per_inv: 256,
            event_log: Some(PathBuf::from("/tmp/test.jsonl")),
            relay_peers: vec!["127.0.0.1:1".parse().unwrap()],
            relay_bind_addr: "127.0.0.1:0".parse().unwrap(),
            relay_auth_key: Some([0x42; 32]),
            relay_data_shards: 96,
            relay_parity_shards: 32,
            relay_adaptive_fec: false,
            relay_send_burst_packets: 0,
            relay_send_burst_delay_micros: 0,
            relay_compact_from_tx_cache: false,
            relay_skeleton_first: false,
            relay_raw_fallback_with_tx_cache: false,
            relay_raw_segment_send_rounds: 1,
            relay_raw_segment_round_delay_millis: 0,
            relay_forward_dedup_window: Duration::from_secs(30),
            relay_forward_dedup_capacity: 64,
        }
    }

    #[test]
    fn bridge_uses_configured_relay_fec_profile() {
        let bridge = RelayBridge::new_for_config(&test_config()).unwrap();

        assert_eq!(bridge.data_shards, 96);
        assert_eq!(bridge.parity_shards, 32);
    }

    #[test]
    fn bridge_keeps_tx_cache_compaction_disabled_by_default() {
        let bridge = RelayBridge::new_for_config(&test_config()).unwrap();

        assert!(!bridge.compact_from_tx_cache);
    }

    #[test]
    fn bridge_keeps_raw_fallback_disabled_by_default() {
        let bridge = RelayBridge::new_for_config(&test_config()).unwrap();

        assert!(!bridge.raw_fallback_with_tx_cache);
    }

    #[test]
    fn bridge_uses_configured_raw_segment_retransmission_profile() {
        let mut config = test_config();
        config.relay_raw_segment_send_rounds = 3;
        config.relay_raw_segment_round_delay_millis = 25;

        let bridge = RelayBridge::new_for_config(&config).unwrap();

        assert_eq!(bridge.raw_segment_send_rounds, 3);
        assert_eq!(bridge.raw_segment_round_delay, Duration::from_millis(25));
    }

    // ----------------------------------------------------------------
    // Dedup ring tests (the RecentForwardedHashes helper)
    // ----------------------------------------------------------------

    #[test]
    fn recent_forwarded_initially_empty() {
        let mut r = RecentForwardedHashes::new(4, Duration::from_secs(30));
        let now = std::time::Instant::now();
        assert!(!r.contains(&[1u8; 32], now));
    }

    #[test]
    fn recent_forwarded_records_and_finds() {
        let mut r = RecentForwardedHashes::new(4, Duration::from_secs(30));
        let now = std::time::Instant::now();
        r.record([7u8; 32], now);
        assert!(r.contains(&[7u8; 32], now));
        assert!(!r.contains(&[1u8; 32], now));
    }

    #[test]
    fn recent_forwarded_evicts_expired() {
        let mut r = RecentForwardedHashes::new(4, Duration::from_secs(30));
        let t0 = std::time::Instant::now();
        r.record([7u8; 32], t0);
        assert!(!r.contains(&[7u8; 32], t0 + Duration::from_secs(31)));
    }

    #[test]
    fn recent_forwarded_capacity_evicts_oldest() {
        let mut r = RecentForwardedHashes::new(2, Duration::from_secs(30));
        let t0 = std::time::Instant::now();
        r.record([1u8; 32], t0);
        r.record([2u8; 32], t0);
        r.record([3u8; 32], t0);
        // Oldest entry [1; 32] should be evicted.
        assert!(!r.contains(&[1u8; 32], t0));
        assert!(r.contains(&[2u8; 32], t0));
        assert!(r.contains(&[3u8; 32], t0));
    }

    #[test]
    fn recent_forwarded_zero_capacity_is_no_op() {
        let mut r = RecentForwardedHashes::new(0, Duration::from_secs(30));
        let t0 = std::time::Instant::now();
        r.record([7u8; 32], t0);
        // Zero-capacity ring never retains, never reports a hit.
        assert!(!r.contains(&[7u8; 32], t0));
    }
}

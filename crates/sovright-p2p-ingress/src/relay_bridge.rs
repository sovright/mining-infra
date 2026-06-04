use std::sync::Arc;
use std::time::Duration;

use sovright_relay::{
    BlockChunker, BlockSender, ClientConfig, CompactBlock, MAX_PAYLOAD_SIZE, RawBlockSegment,
    RelayClient, TransportError, split_raw_block,
};
use tokio::sync::RwLock;
use tokio::time::sleep;
use tracing::{info, warn};

use crate::block::{compact_block_from_raw_block, compact_block_from_raw_block_with_tx_cache};
use crate::config::Config;
use crate::error::{IngressError, Result};
use crate::tx_cache::TxCache;

const RELAY_LEN_PREFIX_BYTES: usize = 4;

#[derive(Clone)]
pub struct RelayBridge {
    sender: BlockSender,
    data_shards: usize,
    parity_shards: usize,
    compact_from_tx_cache: bool,
    raw_fallback_with_tx_cache: bool,
    raw_segment_send_rounds: usize,
    raw_segment_round_delay: Duration,
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
            compact_from_tx_cache: config.relay_compact_from_tx_cache,
            raw_fallback_with_tx_cache: config.relay_raw_fallback_with_tx_cache,
            raw_segment_send_rounds: config.relay_raw_segment_send_rounds,
            raw_segment_round_delay: Duration::from_millis(
                config.relay_raw_segment_round_delay_millis,
            ),
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
            compact_from_tx_cache: config.relay_compact_from_tx_cache,
            raw_fallback_with_tx_cache: config.relay_raw_fallback_with_tx_cache,
            raw_segment_send_rounds: config.relay_raw_segment_send_rounds,
            raw_segment_round_delay: Duration::from_millis(
                config.relay_raw_segment_round_delay_millis,
            ),
        })
    }

    fn new_client_for_config(config: &Config, auth_key: [u8; 32]) -> Result<RelayClient> {
        let client_config = ClientConfig::new(config.relay_peers.clone(), auth_key)
            .with_bind_addr(config.relay_bind_addr)
            .with_fec(config.relay_data_shards, config.relay_parity_shards)
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
        if let Err(error) = self.preflight_chunks(&compact) {
            let text = error.to_string();
            if text.contains("all-prefilled compact block too large") {
                let segments =
                    self.raw_block_segments(*compact.header_hash().as_bytes(), block_payload)?;
                let relay_objects = self.send_raw_block_segments(&segments).await?;
                return Ok(ForwardedBlock {
                    tx_count,
                    bytes: block_payload.len(),
                    relay_objects,
                    mode: ForwardMode::RawBlockSegments,
                });
            }
            return Err(self.with_segment_plan(error, &compact, block_payload));
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
            let raw_segment_relay_objects = self.send_raw_block_segments(&segments).await?;
            return Ok(ForwardedBlock {
                tx_count,
                bytes: block_payload.len(),
                relay_objects: raw_segment_relay_objects + 1,
                mode: ForwardMode::CompactBlockWithRawFallback,
            });
        }
        Ok(ForwardedBlock {
            tx_count,
            bytes: block_payload.len(),
            relay_objects: 1,
            mode: ForwardMode::CompactBlock,
        })
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
        let chunker = BlockChunker::new(self.data_shards, self.parity_shards)
            .map_err(|e| IngressError::Relay(e.to_string()))?;
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
        chunker
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
}

impl ForwardMode {
    pub fn as_str(self) -> &'static str {
        match self {
            ForwardMode::CompactBlock => "compact_block",
            ForwardMode::CompactBlockWithRawFallback => "compact_block_with_raw_fallback",
            ForwardMode::RawBlockSegments => "raw_block_segments",
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
            compact_from_tx_cache: false,
            raw_fallback_with_tx_cache: false,
            raw_segment_send_rounds: 1,
            raw_segment_round_delay: Duration::ZERO,
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
            compact_from_tx_cache: false,
            raw_fallback_with_tx_cache: false,
            raw_segment_send_rounds: 1,
            raw_segment_round_delay: Duration::ZERO,
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
                RelayPayload::CompactBlock(_) => panic!("expected raw block segment"),
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
            compact_from_tx_cache: false,
            raw_fallback_with_tx_cache: false,
            raw_segment_send_rounds: 3,
            raw_segment_round_delay: Duration::ZERO,
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
                RelayPayload::CompactBlock(_) => panic!("expected raw block segment"),
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
            compact_from_tx_cache: true,
            raw_fallback_with_tx_cache: true,
            raw_segment_send_rounds: 1,
            raw_segment_round_delay: Duration::ZERO,
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
            RelayPayload::RawBlockSegment(_) => panic!("compact block should be sent first"),
        }

        let mut segments = Vec::new();
        for _ in 1..forwarded.relay_objects {
            let payload = outgoing.recv().await.expect("raw fallback segment queued");
            match payload {
                RelayPayload::RawBlockSegment(segment) => segments.push(segment),
                RelayPayload::CompactBlock(_) => panic!("expected raw fallback segment"),
            }
        }
        assert_eq!(reassemble_raw_block(&segments).unwrap(), raw_block);
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
            relay_send_burst_packets: 0,
            relay_send_burst_delay_micros: 0,
            relay_compact_from_tx_cache: false,
            relay_raw_fallback_with_tx_cache: false,
            relay_raw_segment_send_rounds: 1,
            relay_raw_segment_round_delay_millis: 0,
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
}

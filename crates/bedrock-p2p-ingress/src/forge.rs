use std::sync::Arc;

use bedrock_forge::{
    BlockChunker, BlockSender, ClientConfig, CompactBlock, MAX_PAYLOAD_SIZE, RelayClient,
    TransportError, split_raw_block,
};
use tokio::sync::RwLock;
use tracing::{info, warn};

use crate::block::compact_block_from_raw_block;
use crate::config::Config;
use crate::error::{IngressError, Result};

#[derive(Clone)]
pub struct ForgeBridge {
    sender: BlockSender,
    data_shards: usize,
    parity_shards: usize,
}

impl ForgeBridge {
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
            .map_err(|e| IngressError::Forge(e.to_string()))?;
        let sender = client.sender();
        let client = Arc::new(RwLock::new(client));
        tokio::spawn(async move {
            let mut client = client.write().await;
            if let Err(error) = client.run().await {
                warn!(%error, "FORGE relay client exited");
            }
        });
        info!(
            peers = config.relay_peers.len(),
            data_shards = config.relay_data_shards,
            parity_shards = config.relay_parity_shards,
            "FORGE bridge enabled"
        );
        Ok(Some(Self {
            sender,
            data_shards: config.relay_data_shards,
            parity_shards: config.relay_parity_shards,
        }))
    }

    #[cfg(test)]
    fn new_for_config(config: &Config) -> Result<Self> {
        let auth_key = config
            .relay_auth_key
            .ok_or_else(|| IngressError::Forge("missing relay auth key".to_string()))?;
        let client = Self::new_client_for_config(config, auth_key)?;
        let sender = client.sender();
        Ok(Self {
            sender,
            data_shards: config.relay_data_shards,
            parity_shards: config.relay_parity_shards,
        })
    }

    fn new_client_for_config(config: &Config, auth_key: [u8; 32]) -> Result<RelayClient> {
        let client_config = ClientConfig::new(config.relay_peers.clone(), auth_key)
            .with_bind_addr(config.relay_bind_addr)
            .with_fec(config.relay_data_shards, config.relay_parity_shards)
            .with_auth_required(true);
        RelayClient::new(client_config).map_err(|e| IngressError::Forge(e.to_string()))
    }

    pub async fn forward_block(&self, block_payload: &[u8]) -> Result<ForwardedBlock> {
        let compact = compact_block_from_raw_block(block_payload)?;
        let tx_count = compact.prefilled_txs.len();
        if let Err(error) = self.preflight_chunks(&compact) {
            return Err(self.with_segment_plan(error, &compact, block_payload));
        }
        self.sender
            .send(compact)
            .await
            .map_err(map_transport_error)?;
        Ok(ForwardedBlock {
            tx_count,
            bytes: block_payload.len(),
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
            Ok(plan) => IngressError::Forge(format!(
                "{text}; segmented raw block plan: segments={} object_bytes={} max_segment_frame_bytes={}",
                plan.segment_count, plan.object_bytes, plan.max_segment_frame_bytes
            )),
            Err(plan_error) => IngressError::Forge(format!(
                "{text}; segmented raw block plan unavailable: {plan_error}"
            )),
        }
    }

    fn preflight_chunks(&self, compact: &CompactBlock) -> Result<()> {
        let block_hash = compact.header_hash();
        let chunker = BlockChunker::new(self.data_shards, self.parity_shards)
            .map_err(|e| IngressError::Forge(e.to_string()))?;
        let serialized_len = BlockChunker::serialize_compact_block(compact).len();
        let max_data_bytes = self.data_shards.saturating_mul(MAX_PAYLOAD_SIZE);
        if serialized_len > max_data_bytes {
            return Err(IngressError::Forge(format!(
                "all-prefilled compact block too large for current FORGE frame budget: \
                 serialized_bytes={serialized_len} max_data_bytes={max_data_bytes} \
                 data_shards={} parity_shards={} max_payload={MAX_PAYLOAD_SIZE}; \
                 production full-block relay needs compact reconstruction or segmented object framing",
                self.data_shards, self.parity_shards
            )));
        }
        chunker
            .compact_block_to_chunks(compact, block_hash.as_bytes())
            .map(|_| ())
            .map_err(|e| IngressError::Forge(e.to_string()))
    }

    fn plan_raw_block_segments(
        &self,
        block_hash: [u8; 32],
        block_payload: &[u8],
    ) -> Result<RawBlockSegmentPlan> {
        let max_segment_frame_bytes = self.data_shards.saturating_mul(MAX_PAYLOAD_SIZE);
        let segments = split_raw_block(block_hash, block_payload, max_segment_frame_bytes)
            .map_err(|e| IngressError::Forge(e.to_string()))?;
        Ok(RawBlockSegmentPlan {
            segment_count: segments.len(),
            object_bytes: block_payload.len(),
            max_segment_frame_bytes,
        })
    }
}

pub struct ForwardedBlock {
    pub tx_count: usize,
    pub bytes: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct RawBlockSegmentPlan {
    segment_count: usize,
    object_bytes: usize,
    max_segment_frame_bytes: usize,
}

fn map_transport_error(error: TransportError) -> IngressError {
    IngressError::Forge(error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use bedrock_forge::{
        PrefilledTx, RawBlockSegment, ZCASH_FULL_HEADER_SIZE, reassemble_raw_block,
    };
    use std::path::PathBuf;
    use std::time::Duration;

    fn bridge_with_default_fec() -> ForgeBridge {
        let config = ClientConfig::new(vec!["127.0.0.1:1".parse().unwrap()], [0x42; 32])
            .with_auth_required(true);
        let client = RelayClient::new(config).unwrap();
        ForgeBridge {
            sender: client.sender(),
            data_shards: 10,
            parity_shards: 3,
        }
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
        assert_eq!(reassembled, raw_block);
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
            event_log: Some(PathBuf::from("/tmp/test.jsonl")),
            relay_peers: vec!["127.0.0.1:1".parse().unwrap()],
            relay_bind_addr: "127.0.0.1:0".parse().unwrap(),
            relay_auth_key: Some([0x42; 32]),
            relay_data_shards: 96,
            relay_parity_shards: 32,
        }
    }

    #[test]
    fn bridge_uses_configured_relay_fec_profile() {
        let bridge = ForgeBridge::new_for_config(&test_config()).unwrap();

        assert_eq!(bridge.data_shards, 96);
        assert_eq!(bridge.parity_shards, 32);
    }
}

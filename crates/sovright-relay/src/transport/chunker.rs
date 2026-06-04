//! Block chunker for converting compact blocks to/from FEC chunks

use crate::compact_block::CompactBlock;
use crate::fec::{FecDecoder, FecEncoder, FecError};
use crate::transport::{MAX_PAYLOAD_SIZE, MAX_TOTAL_CHUNKS};

/// Maximum header size (Zcash headers are ~2189 bytes, allow some margin)
const MAX_HEADER_SIZE: usize = 3_000;
/// Maximum number of short IDs in a compact block
const MAX_SHORT_IDS: usize = 50_000;
/// Maximum number of prefilled transactions
const MAX_PREFILLED_TXS: usize = 10_000;
/// Maximum total transaction count in a compact block
const MAX_TX_COUNT: usize = 100_000;
/// Maximum size of a single transaction
const MAX_TX_DATA_SIZE: usize = 2_000_000; // 2MB

use super::chunk::{Chunk, ChunkHeader};

/// Converts compact blocks to FEC-encoded chunks for transmission
pub struct BlockChunker {
    encoder: FecEncoder,
    decoder: FecDecoder,
    data_shards: usize,
    parity_shards: usize,
    max_payload: usize,
}

impl BlockChunker {
    /// Create a new block chunker
    ///
    /// Default: 10 data shards, 3 parity shards (30% overhead, can lose up to 3 chunks)
    pub fn new(data_shards: usize, parity_shards: usize) -> Result<Self, FecError> {
        Self::new_with_max_payload(data_shards, parity_shards, MAX_PAYLOAD_SIZE)
    }

    /// Create a new block chunker with explicit payload size limit
    pub fn new_with_max_payload(
        data_shards: usize,
        parity_shards: usize,
        max_payload: usize,
    ) -> Result<Self, FecError> {
        let encoder = FecEncoder::new(data_shards, parity_shards)?;
        let decoder = FecDecoder::new(data_shards, parity_shards)?;
        let capped = std::cmp::min(max_payload, MAX_PAYLOAD_SIZE);

        Ok(Self {
            encoder,
            decoder,
            data_shards,
            parity_shards,
            max_payload: capped,
        })
    }

    /// Default configuration (10 data, 3 parity)
    pub fn default_config() -> Result<Self, FecError> {
        Self::new(10, 3)
    }

    /// Serialize compact block to bytes
    ///
    /// Format: content_len (4) + content
    /// where content = header_len (4) + header + nonce (8) + short_ids + prefilled
    ///
    /// The content_len prefix makes the format self-describing so that
    /// FEC padding bytes (from shard size rounding) can be stripped on decode
    /// without needing the exact original data length out-of-band.
    pub fn serialize_compact_block(compact: &CompactBlock) -> Vec<u8> {
        let mut content = Vec::new();

        // Header length + header
        let header_len = compact.header.len() as u32;
        content.extend_from_slice(&header_len.to_le_bytes());
        content.extend_from_slice(&compact.header);

        // Nonce
        content.extend_from_slice(&compact.nonce.to_le_bytes());

        // Short IDs count + data
        let short_id_count = compact.short_ids.len() as u32;
        content.extend_from_slice(&short_id_count.to_le_bytes());
        for short_id in &compact.short_ids {
            content.extend_from_slice(short_id.as_bytes());
        }

        // Prefilled count + data
        let prefilled_count = compact.prefilled_txs.len() as u32;
        content.extend_from_slice(&prefilled_count.to_le_bytes());
        for prefilled in &compact.prefilled_txs {
            content.extend_from_slice(&prefilled.index.to_le_bytes());
            let tx_len = prefilled.tx_data.len() as u32;
            content.extend_from_slice(&tx_len.to_le_bytes());
            content.extend_from_slice(&prefilled.tx_data);
        }

        // Prepend content length so decoder can strip FEC padding
        let mut data = Vec::with_capacity(4 + content.len());
        data.extend_from_slice(&(content.len() as u32).to_le_bytes());
        data.extend_from_slice(&content);
        data
    }

    /// Deserialize compact block from bytes
    ///
    /// Reads the content_len prefix to determine the actual payload boundary,
    /// stripping any FEC padding that may follow.
    fn deserialize_compact_block(data: &[u8]) -> std::io::Result<CompactBlock> {
        use crate::compact_block::PrefilledTx;
        use crate::types::ShortId;
        use std::io::{self, Cursor, Read};

        if data.len() < 4 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "data too short for content length prefix",
            ));
        }

        // Read content length prefix (strips FEC padding)
        let content_len = u32::from_le_bytes([data[0], data[1], data[2], data[3]]) as usize;
        if content_len + 4 > data.len() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "content length {} exceeds available data ({})",
                    content_len,
                    data.len() - 4
                ),
            ));
        }
        // Parse only the content portion, ignoring any trailing FEC padding
        let content = &data[4..4 + content_len];

        let mut cursor = Cursor::new(content);
        let mut buf4 = [0u8; 4];
        let mut buf8 = [0u8; 8];
        let mut buf6 = [0u8; 6];
        let mut buf2 = [0u8; 2];

        // Header
        cursor.read_exact(&mut buf4)?;
        let header_len = u32::from_le_bytes(buf4) as usize;
        if header_len == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "header length must be > 0",
            ));
        }
        if header_len > MAX_HEADER_SIZE {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("header too large: {} bytes", header_len),
            ));
        }
        let mut header = vec![0u8; header_len];
        cursor.read_exact(&mut header)?;
        if header.len() < 140 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "header too short for Zcash",
            ));
        }

        // Nonce
        cursor.read_exact(&mut buf8)?;
        let nonce = u64::from_le_bytes(buf8);

        // Short IDs
        cursor.read_exact(&mut buf4)?;
        let short_id_count = u32::from_le_bytes(buf4) as usize;
        if short_id_count > MAX_SHORT_IDS {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("too many short IDs: {}", short_id_count),
            ));
        }
        let mut short_ids = Vec::with_capacity(short_id_count);
        for _ in 0..short_id_count {
            cursor.read_exact(&mut buf6)?;
            short_ids.push(ShortId::from_bytes(buf6));
        }

        // Prefilled
        cursor.read_exact(&mut buf4)?;
        let prefilled_count = u32::from_le_bytes(buf4) as usize;
        if prefilled_count > MAX_PREFILLED_TXS {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("too many prefilled transactions: {}", prefilled_count),
            ));
        }
        let mut prefilled_txs = Vec::with_capacity(prefilled_count);
        for _ in 0..prefilled_count {
            cursor.read_exact(&mut buf2)?;
            let index = u16::from_le_bytes(buf2);
            cursor.read_exact(&mut buf4)?;
            let tx_len = u32::from_le_bytes(buf4);
            if tx_len as usize > MAX_TX_DATA_SIZE {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("transaction data too large: {} bytes", tx_len),
                ));
            }
            let mut tx_data = vec![0u8; tx_len as usize];
            cursor.read_exact(&mut tx_data)?;
            prefilled_txs.push(PrefilledTx { index, tx_data });
        }

        let total_txs = short_ids.len() + prefilled_txs.len();
        if total_txs > MAX_TX_COUNT {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("too many total transactions: {}", total_txs),
            ));
        }

        if cursor.position() as usize != content.len() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "trailing bytes after compact block payload",
            ));
        }

        Ok(CompactBlock::new(header, nonce, short_ids, prefilled_txs))
    }

    /// Convert a compact block into FEC-encoded chunks
    pub fn compact_block_to_chunks(
        &self,
        compact: &CompactBlock,
        block_hash: &[u8; 32],
    ) -> Result<Vec<Chunk>, FecError> {
        let data = Self::serialize_compact_block(compact);
        let shards = self.encoder.encode(&data)?;

        if shards.len() > MAX_TOTAL_CHUNKS as usize {
            return Err(FecError::EncodingFailed(
                "too many shards for protocol limit".into(),
            ));
        }

        let total_chunks = shards.len() as u16;

        let chunks: Vec<Chunk> = shards
            .into_iter()
            .enumerate()
            .map(|(i, shard)| {
                if shard.len() > self.max_payload {
                    return Err(FecError::EncodingFailed(
                        format!(
                            "shard too large for payload: {} > {}",
                            shard.len(),
                            self.max_payload
                        ),
                    ));
                }
                let header = ChunkHeader::new_block(
                    block_hash,
                    i as u16,
                    total_chunks,
                    shard.len() as u16,
                );
                Ok(Chunk::new(header, shard))
            })
            .collect::<Result<Vec<_>, _>>()?;

        Ok(chunks)
    }

    /// Reconstruct a compact block from received chunks
    ///
    /// `chunks` should be indexed by chunk_id, with None for missing chunks
    pub fn chunks_to_compact_block(
        &self,
        chunks: Vec<Option<Vec<u8>>>,
        original_len: usize,
    ) -> Result<CompactBlock, FecError> {
        let data = self.decoder.decode(chunks, original_len)?;
        Self::deserialize_compact_block(&data)
            .map_err(|e| FecError::DecodingFailed(format!("deserialization failed: {}", e)))
    }

    /// Decode raw serialized data from shards (caller handles parsing)
    pub fn decode_data(
        &self,
        chunks: Vec<Option<Vec<u8>>>,
        original_len: usize,
    ) -> Result<Vec<u8>, FecError> {
        self.decoder.decode(chunks, original_len)
    }

    /// Get total shard count
    pub fn total_shards(&self) -> usize {
        self.data_shards + self.parity_shards
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::compact_block::PrefilledTx;
    use crate::types::{AuthDigest, ShortId, TxId, WtxId};

    fn make_test_compact_block() -> CompactBlock {
        let header = vec![0xab; 2189];
        let nonce = 12345u64;

        let wtxid = WtxId::new(
            TxId::from_bytes([0xaa; 32]),
            AuthDigest::from_bytes([0xbb; 32]),
        );
        let header_hash = [0u8; 32];
        let short_id = ShortId::compute(&wtxid, &header_hash, nonce);

        let prefilled = PrefilledTx {
            index: 0,
            tx_data: vec![1, 2, 3, 4, 5],
        };

        CompactBlock::new(header, nonce, vec![short_id], vec![prefilled])
    }

    #[test]
    fn chunker_roundtrip() {
        let chunker = BlockChunker::default_config().unwrap();
        let compact = make_test_compact_block();
        let block_hash = [0xcd; 32];

        // Serialize to chunks
        let chunks = chunker.compact_block_to_chunks(&compact, &block_hash).unwrap();
        assert_eq!(chunks.len(), 13); // 10 data + 3 parity

        // Get original data length from serialization
        let original_data = BlockChunker::serialize_compact_block(&compact);
        let original_len = original_data.len();

        // Extract payloads
        let shard_opts: Vec<Option<Vec<u8>>> = chunks
            .into_iter()
            .map(|c| Some(c.payload))
            .collect();

        // Reconstruct
        let recovered = chunker.chunks_to_compact_block(shard_opts, original_len).unwrap();

        assert_eq!(recovered.header, compact.header);
        assert_eq!(recovered.nonce, compact.nonce);
        assert_eq!(recovered.short_ids.len(), compact.short_ids.len());
        assert_eq!(recovered.prefilled_txs.len(), compact.prefilled_txs.len());
    }

    /// Wrap content bytes with the content_len prefix for deserialization tests
    fn wrap_with_len(content: &[u8]) -> Vec<u8> {
        let mut data = Vec::with_capacity(4 + content.len());
        data.extend_from_slice(&(content.len() as u32).to_le_bytes());
        data.extend_from_slice(content);
        data
    }

    #[test]
    fn deserialize_rejects_empty_header() {
        let mut content = Vec::new();
        content.extend_from_slice(&0u32.to_le_bytes()); // header len = 0
        content.extend_from_slice(&0u64.to_le_bytes()); // nonce
        content.extend_from_slice(&0u32.to_le_bytes()); // short ids
        content.extend_from_slice(&0u32.to_le_bytes()); // prefilled

        let result = BlockChunker::deserialize_compact_block(&wrap_with_len(&content));
        assert!(result.is_err());
    }

    #[test]
    fn deserialize_rejects_too_large_header() {
        let mut content = Vec::new();
        content.extend_from_slice(&(MAX_HEADER_SIZE as u32 + 1).to_le_bytes());
        content.resize(content.len() + MAX_HEADER_SIZE + 1, 0u8);
        content.extend_from_slice(&0u64.to_le_bytes()); // nonce
        content.extend_from_slice(&0u32.to_le_bytes()); // short ids
        content.extend_from_slice(&0u32.to_le_bytes()); // prefilled

        let result = BlockChunker::deserialize_compact_block(&wrap_with_len(&content));
        assert!(result.is_err());
    }

    #[test]
    fn deserialize_rejects_too_many_txs() {
        let header = vec![0u8; 2189];
        let mut content = Vec::new();
        content.extend_from_slice(&(header.len() as u32).to_le_bytes());
        content.extend_from_slice(&header);
        content.extend_from_slice(&0u64.to_le_bytes()); // nonce

        let short_id_count = (MAX_TX_COUNT + 1) as u32;
        content.extend_from_slice(&short_id_count.to_le_bytes());
        for _ in 0..short_id_count {
            content.extend_from_slice(&[0u8; 6]);
        }
        content.extend_from_slice(&0u32.to_le_bytes()); // prefilled

        let result = BlockChunker::deserialize_compact_block(&wrap_with_len(&content));
        assert!(result.is_err());
    }

    #[test]
    fn deserialize_rejects_short_header() {
        let header = vec![0u8; 100];
        let mut content = Vec::new();
        content.extend_from_slice(&(header.len() as u32).to_le_bytes());
        content.extend_from_slice(&header);
        content.extend_from_slice(&0u64.to_le_bytes()); // nonce
        content.extend_from_slice(&0u32.to_le_bytes()); // short ids
        content.extend_from_slice(&0u32.to_le_bytes()); // prefilled

        let result = BlockChunker::deserialize_compact_block(&wrap_with_len(&content));
        assert!(result.is_err());
    }

    #[test]
    fn deserialize_rejects_trailing_bytes() {
        let header = vec![0u8; 2189];
        let mut content = Vec::new();
        content.extend_from_slice(&(header.len() as u32).to_le_bytes());
        content.extend_from_slice(&header);
        content.extend_from_slice(&0u64.to_le_bytes()); // nonce
        content.extend_from_slice(&0u32.to_le_bytes()); // short ids
        content.extend_from_slice(&0u32.to_le_bytes()); // prefilled
        content.extend_from_slice(&[0u8; 4]); // trailing garbage

        let result = BlockChunker::deserialize_compact_block(&wrap_with_len(&content));
        assert!(result.is_err());
    }

    #[test]
    fn deserialize_strips_fec_padding() {
        // Regression: estimate_original_len returned shard_size * data_shards
        // which includes FEC padding. The content_len prefix lets the
        // deserializer ignore padding bytes beyond the actual content.
        let compact = make_test_compact_block();
        let serialized = BlockChunker::serialize_compact_block(&compact);

        // Add padding bytes (simulating FEC shard rounding)
        let mut padded = serialized.clone();
        padded.extend_from_slice(&[0u8; 7]); // 7 bytes of FEC padding

        let recovered = BlockChunker::deserialize_compact_block(&padded).unwrap();
        assert_eq!(recovered.header, compact.header);
        assert_eq!(recovered.nonce, compact.nonce);
    }

    #[test]
    fn chunker_recovers_with_lost_chunks() {
        let chunker = BlockChunker::default_config().unwrap();
        let compact = make_test_compact_block();
        let block_hash = [0xcd; 32];

        let chunks = chunker.compact_block_to_chunks(&compact, &block_hash).unwrap();

        let original_data = BlockChunker::serialize_compact_block(&compact);
        let original_len = original_data.len();

        // Lose 3 chunks (max recoverable)
        let mut shard_opts: Vec<Option<Vec<u8>>> = chunks
            .into_iter()
            .map(|c| Some(c.payload))
            .collect();
        shard_opts[1] = None;
        shard_opts[5] = None;
        shard_opts[9] = None;

        let recovered = chunker.chunks_to_compact_block(shard_opts, original_len).unwrap();
        assert_eq!(recovered.nonce, compact.nonce);
    }

    #[test]
    fn chunker_enforces_max_payload() {
        let compact = make_test_compact_block();
        let block_hash = [0xcd; 32];
        let data = BlockChunker::serialize_compact_block(&compact);
        // Make shard size large by using 1 data shard
        let chunker = BlockChunker::new_with_max_payload(1, 1, 100).unwrap();

        let result = chunker.compact_block_to_chunks(&compact, &block_hash);
        assert!(result.is_err());

        // Sanity: with enough data shards, it should succeed under default limit
        let min_shards = data.len().div_ceil(MAX_PAYLOAD_SIZE);
        let chunker_ok = BlockChunker::new(min_shards, 1).unwrap();
        let ok = chunker_ok.compact_block_to_chunks(&compact, &block_hash);
        assert!(ok.is_ok(), "expected default max payload to allow shard size under limit");
    }
}

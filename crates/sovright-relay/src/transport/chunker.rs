//! Block chunker for converting compact blocks to/from FEC chunks

use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use crate::compact_block::CompactBlock;
use crate::fec::{FecDecoder, FecEncoder, FecError, adaptive_shards, adaptive_shards_skeleton};
use crate::segmented_block::{RawBlockSegment, segment_object_hash};
use crate::transport::{MAX_PAYLOAD_SIZE, MAX_PAYLOAD_SIZE_V3, MAX_TOTAL_CHUNKS};

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

use super::chunk::{Chunk, ChunkHeader, MessageType};

/// A cached Reed-Solomon codec (encoder + decoder) for one shard shape.
///
/// Building a Reed-Solomon matrix is expensive (~100ms for the 224/32 profile),
/// far too costly to redo per block on the hot path. The chunker caches one of
/// these per `(data_shards, parity_shards)` shape it encounters.
struct FecCodec {
    encoder: FecEncoder,
    decoder: FecDecoder,
}

impl FecCodec {
    fn new(data_shards: usize, parity_shards: usize) -> Result<Self, FecError> {
        Ok(Self {
            encoder: FecEncoder::new(data_shards, parity_shards)?,
            decoder: FecDecoder::new(data_shards, parity_shards)?,
        })
    }
}

/// Shared, lazily-populated cache of Reed-Solomon codecs keyed by shard shape.
type CodecCache = Arc<Mutex<HashMap<(usize, usize), Arc<FecCodec>>>>;

/// Converts compact blocks to FEC-encoded chunks for transmission
pub struct BlockChunker {
    encoder: FecEncoder,
    decoder: FecDecoder,
    data_shards: usize,
    parity_shards: usize,
    max_payload: usize,
    /// Lazily-built cache of Reed-Solomon codecs keyed by shard shape, used by
    /// the adaptive (v3) encode path and per-block (v3) decode path so a given
    /// shape's RS matrix is built at most once and shared thereafter. Wrapped
    /// in `Arc` so chunkers behind an `Arc` share the same cache.
    codec_cache: CodecCache,
    /// Number of codecs actually built through the cache (test/observability
    /// hook proving the cache prevents per-block rebuilds).
    codec_builds: Arc<AtomicUsize>,
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
            codec_cache: Arc::new(Mutex::new(HashMap::new())),
            codec_builds: Arc::new(AtomicUsize::new(0)),
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

    fn wrap_len_prefixed(content: &[u8]) -> Vec<u8> {
        let mut data = Vec::with_capacity(4 + content.len());
        data.extend_from_slice(&(content.len() as u32).to_le_bytes());
        data.extend_from_slice(content);
        data
    }

    fn read_len_prefixed(data: &[u8]) -> std::io::Result<&[u8]> {
        use std::io;

        if data.len() < 4 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "data too short for content length prefix",
            ));
        }

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

        Ok(&data[4..4 + content_len])
    }

    /// Deserialize compact block from bytes
    ///
    /// Reads the content_len prefix to determine the actual payload boundary,
    /// stripping any FEC padding that may follow.
    fn deserialize_compact_block(data: &[u8]) -> std::io::Result<CompactBlock> {
        use crate::compact_block::PrefilledTx;
        use crate::types::ShortId;
        use std::io::{self, Cursor, Read};

        // Parse only the content portion, ignoring any trailing FEC padding
        let content = Self::read_len_prefixed(data)?;

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

    fn data_to_chunks(
        &self,
        msg_type: MessageType,
        object_hash: &[u8; 32],
        data: &[u8],
    ) -> Result<Vec<Chunk>, FecError> {
        let shards = self.encoder.encode(data)?;

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
                    return Err(FecError::EncodingFailed(format!(
                        "shard too large for payload: {} > {}",
                        shard.len(),
                        self.max_payload
                    )));
                }
                let header = match msg_type {
                    MessageType::Block => ChunkHeader::new_block(
                        object_hash,
                        i as u16,
                        total_chunks,
                        shard.len() as u16,
                    ),
                    MessageType::RawBlockSegment => ChunkHeader::new_raw_block_segment(
                        object_hash,
                        i as u16,
                        total_chunks,
                        shard.len() as u16,
                    ),
                    MessageType::CompactSkeleton => ChunkHeader::new_compact_skeleton(
                        object_hash,
                        i as u16,
                        total_chunks,
                        shard.len() as u16,
                    ),
                    MessageType::Keepalive | MessageType::Auth => {
                        return Err(FecError::EncodingFailed(
                            "unsupported chunk data message type".into(),
                        ));
                    }
                };
                Ok(Chunk::new(header, shard))
            })
            .collect::<Result<Vec<_>, _>>()?;

        Ok(chunks)
    }

    /// Get (or lazily build and cache) the Reed-Solomon codec for a shard shape.
    ///
    /// The codec is built outside the lock; if a concurrent caller wins the
    /// insert we discard ours. `codec_builds` counts only stored codecs, so a
    /// given shape is counted exactly once.
    fn codec_for(
        &self,
        data_shards: usize,
        parity_shards: usize,
    ) -> Result<Arc<FecCodec>, FecError> {
        let key = (data_shards, parity_shards);
        {
            let cache = self.codec_cache.lock().expect("codec cache poisoned");
            if let Some(codec) = cache.get(&key) {
                return Ok(Arc::clone(codec));
            }
        }
        let built = Arc::new(FecCodec::new(data_shards, parity_shards)?);
        let mut cache = self.codec_cache.lock().expect("codec cache poisoned");
        use std::collections::hash_map::Entry;
        match cache.entry(key) {
            Entry::Occupied(entry) => Ok(Arc::clone(entry.get())),
            Entry::Vacant(entry) => {
                self.codec_builds.fetch_add(1, Ordering::Relaxed);
                Ok(Arc::clone(entry.insert(built)))
            }
        }
    }

    /// Encode `data` into shards for a given shape, reusing the fixed
    /// construction-time codec when the shape matches (avoids a rebuild) and the
    /// shared cache otherwise.
    fn encode_with_shape(
        &self,
        data: &[u8],
        data_shards: usize,
        parity_shards: usize,
    ) -> Result<Vec<Vec<u8>>, FecError> {
        if data_shards == self.data_shards && parity_shards == self.parity_shards {
            return self.encoder.encode(data);
        }
        let codec = self.codec_for(data_shards, parity_shards)?;
        codec.encoder.encode(data)
    }

    /// Decode shards for a given shape, reusing the fixed construction-time codec
    /// when the shape matches (critical: this avoids the ~100ms RS rebuild on
    /// the hot path for the common fixed/v2 profile) and the shared cache
    /// otherwise.
    fn decode_with_shape(
        &self,
        chunks: Vec<Option<Vec<u8>>>,
        original_len: usize,
        data_shards: usize,
        parity_shards: usize,
    ) -> Result<Vec<u8>, FecError> {
        if data_shards == self.data_shards && parity_shards == self.parity_shards {
            return self.decoder.decode(chunks, original_len);
        }
        let codec = self.codec_for(data_shards, parity_shards)?;
        codec.decoder.decode(chunks, original_len)
    }

    /// Split `total` into `(data_shards, parity_shards)` for decode, validating
    /// that at least one parity shard is present and `data_shards <= total`.
    fn split_shape(data_shards: usize, total: usize) -> Result<(usize, usize), FecError> {
        if data_shards == 0 {
            return Err(FecError::InvalidConfiguration(
                "data_shards must be > 0".into(),
            ));
        }
        let parity = total.checked_sub(data_shards).ok_or_else(|| {
            FecError::InvalidConfiguration(format!(
                "data_shards {} exceeds total chunks {}",
                data_shards, total
            ))
        })?;
        if parity == 0 {
            return Err(FecError::InvalidConfiguration(
                "at least one parity shard is required".into(),
            ));
        }
        Ok((data_shards, parity))
    }

    /// Adaptively FEC-encode `data`, emitting version-3 chunks sized to the
    /// block, or falling back to the fixed scheme (version-2-destined intermediate
    /// headers) for blocks too large to fit the 8-bit shard space.
    ///
    /// The returned headers are intermediate (unauthenticated); the send path
    /// recomputes the HMAC. Version-3 headers carry the per-block `data_shards`.
    fn data_to_chunks_adaptive(
        &self,
        msg_type: MessageType,
        object_hash: &[u8; 32],
        data: &[u8],
    ) -> Result<Vec<Chunk>, FecError> {
        self.data_to_chunks_adaptive_inner(
            msg_type,
            object_hash,
            data,
            adaptive_shards(data.len(), MAX_PAYLOAD_SIZE_V3),
        )
    }

    /// Adaptively FEC-encode `data` for a compact *skeleton*, applying the
    /// heavier skeleton parity floor (see [`adaptive_shards_skeleton`]) so a
    /// single lost packet still reconstructs. Falls back to the fixed scheme for
    /// blocks too large for the adaptive shard space.
    fn data_to_chunks_adaptive_skeleton(
        &self,
        object_hash: &[u8; 32],
        data: &[u8],
    ) -> Result<Vec<Chunk>, FecError> {
        self.data_to_chunks_adaptive_inner(
            MessageType::CompactSkeleton,
            object_hash,
            data,
            adaptive_shards_skeleton(data.len(), MAX_PAYLOAD_SIZE_V3),
        )
    }

    fn data_to_chunks_adaptive_inner(
        &self,
        msg_type: MessageType,
        object_hash: &[u8; 32],
        data: &[u8],
        shards: Option<(usize, usize)>,
    ) -> Result<Vec<Chunk>, FecError> {
        let Some((data_shards, parity_shards)) = shards else {
            // Too large for adaptive sizing: keep the current behavior and emit
            // fixed-profile (version-2) chunks.
            return self.data_to_chunks(msg_type, object_hash, data);
        };

        let shards = self.encode_with_shape(data, data_shards, parity_shards)?;
        // adaptive_shards guarantees data + parity <= MAX_TOTAL_CHUNKS.
        debug_assert!(shards.len() <= MAX_TOTAL_CHUNKS as usize);
        let total_chunks = shards.len() as u16;
        let ds = data_shards as u16;

        shards
            .into_iter()
            .enumerate()
            .map(|(i, shard)| {
                if shard.len() > MAX_PAYLOAD_SIZE_V3 {
                    return Err(FecError::EncodingFailed(format!(
                        "v3 shard too large for payload: {} > {}",
                        shard.len(),
                        MAX_PAYLOAD_SIZE_V3
                    )));
                }
                let header = match msg_type {
                    MessageType::Block => ChunkHeader::new_block_v3(
                        object_hash,
                        i as u16,
                        total_chunks,
                        shard.len() as u16,
                        ds,
                    ),
                    MessageType::RawBlockSegment => ChunkHeader::new_raw_block_segment_v3(
                        object_hash,
                        i as u16,
                        total_chunks,
                        shard.len() as u16,
                        ds,
                    ),
                    MessageType::CompactSkeleton => ChunkHeader::new_compact_skeleton_v3(
                        object_hash,
                        i as u16,
                        total_chunks,
                        shard.len() as u16,
                        ds,
                    ),
                    MessageType::Keepalive | MessageType::Auth => {
                        return Err(FecError::EncodingFailed(
                            "unsupported chunk data message type".into(),
                        ));
                    }
                };
                Ok(Chunk::new(header, shard))
            })
            .collect::<Result<Vec<_>, _>>()
    }

    /// Convert a compact block into FEC-encoded chunks
    pub fn compact_block_to_chunks(
        &self,
        compact: &CompactBlock,
        block_hash: &[u8; 32],
    ) -> Result<Vec<Chunk>, FecError> {
        let data = Self::serialize_compact_block(compact);
        self.data_to_chunks(MessageType::Block, block_hash, &data)
    }

    /// Convert a compact block into adaptively-sized (version-3) FEC chunks,
    /// falling back to the fixed profile for oversized blocks.
    pub fn compact_block_to_chunks_adaptive(
        &self,
        compact: &CompactBlock,
        block_hash: &[u8; 32],
    ) -> Result<Vec<Chunk>, FecError> {
        let data = Self::serialize_compact_block(compact);
        self.data_to_chunks_adaptive(MessageType::Block, block_hash, &data)
    }

    /// Convert a compact skeleton into adaptively-sized (version-3) FEC chunks
    /// under [`MessageType::CompactSkeleton`], applying the heavier skeleton
    /// parity floor. Falls back to the fixed profile for oversized skeletons.
    ///
    /// `object_hash` is the skeleton's relay routing id (distinct from the full
    /// block's id so the two do not collide in the mesh); the payload is a
    /// serialized `CompactBlock` decoded exactly like a normal compact block.
    pub fn compact_block_to_chunks_skeleton(
        &self,
        compact: &CompactBlock,
        object_hash: &[u8; 32],
    ) -> Result<Vec<Chunk>, FecError> {
        let data = Self::serialize_compact_block(compact);
        self.data_to_chunks_adaptive_skeleton(object_hash, &data)
    }

    /// Convert a raw block segment into adaptively-sized (version-3) FEC chunks,
    /// falling back to the fixed profile for oversized segments.
    pub fn raw_block_segment_to_chunks_adaptive(
        &self,
        segment: &RawBlockSegment,
    ) -> Result<Vec<Chunk>, FecError> {
        let object_hash = segment_object_hash(segment.block_hash, segment.segment_index);
        let data = Self::wrap_len_prefixed(&segment.encode());
        self.data_to_chunks_adaptive(MessageType::RawBlockSegment, &object_hash, &data)
    }

    /// Convert a raw block segment into FEC-encoded chunks.
    pub fn raw_block_segment_to_chunks(
        &self,
        segment: &RawBlockSegment,
    ) -> Result<Vec<Chunk>, FecError> {
        let object_hash = segment_object_hash(segment.block_hash, segment.segment_index);
        let data = Self::wrap_len_prefixed(&segment.encode());
        self.data_to_chunks(MessageType::RawBlockSegment, &object_hash, &data)
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

    /// Reconstruct a raw block segment from received chunks.
    pub fn chunks_to_raw_block_segment(
        &self,
        chunks: Vec<Option<Vec<u8>>>,
        original_len: usize,
    ) -> Result<RawBlockSegment, FecError> {
        let data = self.decoder.decode(chunks, original_len)?;
        let frame = Self::read_len_prefixed(&data)
            .map_err(|e| FecError::DecodingFailed(format!("segment frame failed: {}", e)))?;
        RawBlockSegment::decode(frame)
            .map_err(|e| FecError::DecodingFailed(format!("segment decode failed: {}", e)))
    }

    /// Decode raw serialized data from shards (caller handles parsing)
    pub fn decode_data(
        &self,
        chunks: Vec<Option<Vec<u8>>>,
        original_len: usize,
    ) -> Result<Vec<u8>, FecError> {
        self.decoder.decode(chunks, original_len)
    }

    /// Reconstruct a compact block using an explicit per-block `data_shards`
    /// count (from a version-3 chunk header). The parity count is inferred as
    /// `chunks.len() - data_shards`. Pass the receiver's fixed `data_shards`
    /// for version-2 chunks.
    pub fn chunks_to_compact_block_with_shards(
        &self,
        chunks: Vec<Option<Vec<u8>>>,
        original_len: usize,
        data_shards: usize,
    ) -> Result<CompactBlock, FecError> {
        let (data_shards, parity_shards) = Self::split_shape(data_shards, chunks.len())?;
        let data = self.decode_with_shape(chunks, original_len, data_shards, parity_shards)?;
        Self::deserialize_compact_block(&data)
            .map_err(|e| FecError::DecodingFailed(format!("deserialization failed: {}", e)))
    }

    /// Reconstruct a raw block segment using an explicit per-block `data_shards`
    /// count (from a version-3 chunk header).
    pub fn chunks_to_raw_block_segment_with_shards(
        &self,
        chunks: Vec<Option<Vec<u8>>>,
        original_len: usize,
        data_shards: usize,
    ) -> Result<RawBlockSegment, FecError> {
        let (data_shards, parity_shards) = Self::split_shape(data_shards, chunks.len())?;
        let data = self.decode_with_shape(chunks, original_len, data_shards, parity_shards)?;
        let frame = Self::read_len_prefixed(&data)
            .map_err(|e| FecError::DecodingFailed(format!("segment frame failed: {}", e)))?;
        RawBlockSegment::decode(frame)
            .map_err(|e| FecError::DecodingFailed(format!("segment decode failed: {}", e)))
    }

    /// Decode raw serialized data using an explicit per-block `data_shards`
    /// count (from a version-3 chunk header); caller handles parsing.
    pub fn decode_data_with_shards(
        &self,
        chunks: Vec<Option<Vec<u8>>>,
        original_len: usize,
        data_shards: usize,
    ) -> Result<Vec<u8>, FecError> {
        let (data_shards, parity_shards) = Self::split_shape(data_shards, chunks.len())?;
        self.decode_with_shape(chunks, original_len, data_shards, parity_shards)
    }

    /// Number of Reed-Solomon codecs built through the shard-shape cache.
    ///
    /// Test/observability hook: proves repeated blocks of the same adaptive
    /// shape reuse a single cached codec instead of rebuilding per block.
    pub fn codec_build_count(&self) -> usize {
        self.codec_builds.load(Ordering::Relaxed)
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
        let chunks = chunker
            .compact_block_to_chunks(&compact, &block_hash)
            .unwrap();
        assert_eq!(chunks.len(), 13); // 10 data + 3 parity

        // Get original data length from serialization
        let original_data = BlockChunker::serialize_compact_block(&compact);
        let original_len = original_data.len();

        // Extract payloads
        let shard_opts: Vec<Option<Vec<u8>>> =
            chunks.into_iter().map(|c| Some(c.payload)).collect();

        // Reconstruct
        let recovered = chunker
            .chunks_to_compact_block(shard_opts, original_len)
            .unwrap();

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

        let chunks = chunker
            .compact_block_to_chunks(&compact, &block_hash)
            .unwrap();

        let original_data = BlockChunker::serialize_compact_block(&compact);
        let original_len = original_data.len();

        // Lose 3 chunks (max recoverable)
        let mut shard_opts: Vec<Option<Vec<u8>>> =
            chunks.into_iter().map(|c| Some(c.payload)).collect();
        shard_opts[1] = None;
        shard_opts[5] = None;
        shard_opts[9] = None;

        let recovered = chunker
            .chunks_to_compact_block(shard_opts, original_len)
            .unwrap();
        assert_eq!(recovered.nonce, compact.nonce);
    }

    /// Full adaptive path: encode a small compact block, round-trip every chunk
    /// through the wire form, then reassemble with the per-block data_shards and
    /// decode back to the original. The block must collapse to a handful of v3
    /// chunks (vs the fixed 13/256).
    #[test]
    fn adaptive_roundtrip_small_block_is_few_v3_chunks() {
        let chunker = BlockChunker::new(10, 3).unwrap();
        let compact = make_test_compact_block();
        let block_hash = [0xcd; 32];

        let chunks = chunker
            .compact_block_to_chunks_adaptive(&compact, &block_hash)
            .unwrap();
        // ~2.2 KB compact block => 2 data + 1 parity = 3 chunks.
        assert_eq!(chunks.len(), 3, "small block should collapse to 3 chunks");
        assert!(chunks.iter().all(|c| c.header.version == 3));
        assert!(chunks.iter().all(|c| c.header.data_shards == 2));

        let data_shards = chunks[0].header.data_shards as usize;
        let total = chunks.len();

        // Round-trip each chunk through to_bytes/from_bytes (the wire).
        let mut shard_opts: Vec<Option<Vec<u8>>> = vec![None; total];
        for chunk in &chunks {
            let wire = chunk.to_bytes();
            let parsed = Chunk::from_bytes(&wire).unwrap();
            assert_eq!(parsed.header.data_shards as usize, data_shards);
            shard_opts[parsed.header.chunk_id as usize] = Some(parsed.payload);
        }

        let shard_size = shard_opts.iter().flatten().next().unwrap().len();
        let original_len = shard_size * data_shards;
        let recovered = chunker
            .chunks_to_compact_block_with_shards(shard_opts, original_len, data_shards)
            .unwrap();
        assert_eq!(recovered.header, compact.header);
        assert_eq!(recovered.nonce, compact.nonce);
        assert_eq!(recovered.short_ids.len(), compact.short_ids.len());
        assert_eq!(recovered.prefilled_txs.len(), compact.prefilled_txs.len());
    }

    /// Adaptive path recovers from a dropped chunk via the parity shard.
    #[test]
    fn adaptive_recovers_with_one_dropped_chunk() {
        let chunker = BlockChunker::new(10, 3).unwrap();
        let compact = make_test_compact_block();
        let block_hash = [0x01; 32];

        let chunks = chunker
            .compact_block_to_chunks_adaptive(&compact, &block_hash)
            .unwrap();
        let data_shards = chunks[0].header.data_shards as usize;
        let total = chunks.len();
        assert_eq!(total, 3);

        let shard_size = chunks[0].payload.len();
        let mut shard_opts: Vec<Option<Vec<u8>>> = vec![None; total];
        for chunk in &chunks {
            shard_opts[chunk.header.chunk_id as usize] = Some(chunk.payload.clone());
        }
        // Drop one data shard; the single parity shard recovers it.
        shard_opts[0] = None;

        let original_len = shard_size * data_shards;
        let recovered = chunker
            .chunks_to_compact_block_with_shards(shard_opts, original_len, data_shards)
            .unwrap();
        assert_eq!(recovered.nonce, compact.nonce);
    }

    /// A v2 (fixed) block and a v3 (adaptive) block both decode on the same
    /// chunker via the per-shard decode entry, each yielding the original.
    #[test]
    fn interop_v2_and_v3_both_decode() {
        let chunker = BlockChunker::new(10, 3).unwrap();
        let compact = make_test_compact_block();
        let block_hash = [0x02; 32];

        // v2 fixed path: 13 chunks, intermediate headers carry data_shards == 0.
        let v2 = chunker
            .compact_block_to_chunks(&compact, &block_hash)
            .unwrap();
        assert_eq!(v2.len(), 13);
        assert!(v2.iter().all(|c| c.header.data_shards == 0));
        let v2_shard = v2[0].payload.len();
        let v2_shards: Vec<Option<Vec<u8>>> = v2.into_iter().map(|c| Some(c.payload)).collect();
        // A v3-capable receiver decodes a v2 block using its fixed data_shards.
        let recovered_v2 = chunker
            .chunks_to_compact_block_with_shards(v2_shards, v2_shard * 10, 10)
            .unwrap();
        assert_eq!(recovered_v2.nonce, compact.nonce);

        // v3 adaptive path decoded via the header's data_shards.
        let v3 = chunker
            .compact_block_to_chunks_adaptive(&compact, &block_hash)
            .unwrap();
        let ds = v3[0].header.data_shards as usize;
        let v3_shard = v3[0].payload.len();
        let v3_shards: Vec<Option<Vec<u8>>> = v3.into_iter().map(|c| Some(c.payload)).collect();
        let recovered_v3 = chunker
            .chunks_to_compact_block_with_shards(v3_shards, v3_shard * ds, ds)
            .unwrap();
        assert_eq!(recovered_v3.nonce, compact.nonce);
    }

    /// Two blocks of the same adaptive shape reuse one cached codec (no rebuild).
    #[test]
    fn adaptive_reuses_cached_codec_for_same_shape() {
        // Fixed profile (10,3); small blocks adaptively become (2,1), a distinct
        // shape that therefore goes through the shared codec cache.
        let chunker = BlockChunker::new(10, 3).unwrap();
        assert_eq!(chunker.codec_build_count(), 0);

        let mut block_a = make_test_compact_block();
        block_a.nonce = 1;
        let mut block_b = make_test_compact_block();
        block_b.nonce = 2;

        let ca = chunker
            .compact_block_to_chunks_adaptive(&block_a, &[1u8; 32])
            .unwrap();
        assert_eq!(ca[0].header.data_shards, 2);
        assert_eq!(
            chunker.codec_build_count(),
            1,
            "first adaptive block of shape (2,1) builds one codec"
        );

        let cb = chunker
            .compact_block_to_chunks_adaptive(&block_b, &[2u8; 32])
            .unwrap();
        assert_eq!(cb[0].header.data_shards, 2);
        assert_eq!(
            chunker.codec_build_count(),
            1,
            "second block of the same shape must reuse the cached codec"
        );
    }

    /// Oversized data (needing > 256 total adaptive shards) falls back to the
    /// fixed profile and emits v2 (data_shards == 0) intermediate chunks. The
    /// fixed profile here has enough data shards to encode the payload that the
    /// adaptive scheme rejects.
    #[test]
    fn adaptive_falls_back_to_fixed_for_oversized_block() {
        // Adaptive rejects any block > ~227 * MAX_PAYLOAD_SIZE_V3 (would exceed
        // 256 total shards). Use a 240/16 fixed profile that can still encode it.
        let chunker = BlockChunker::new(240, 16).unwrap();
        let big = vec![0x7a; 255_000];
        assert_eq!(
            adaptive_shards(big.len(), MAX_PAYLOAD_SIZE_V3),
            None,
            "test payload must overflow the adaptive shard space"
        );
        let object_hash = [0x03; 32];
        let chunks = chunker
            .data_to_chunks_adaptive(MessageType::Block, &object_hash, &big)
            .unwrap();
        // Fixed 240/16 profile => 256 chunks, all v2-destined (data_shards == 0).
        assert_eq!(chunks.len(), 256);
        assert!(chunks.iter().all(|c| c.header.data_shards == 0));
        assert!(chunks.iter().all(|c| c.header.version == 1));
    }

    /// The skeleton encode path emits CompactSkeleton v3 chunks with the heavier
    /// skeleton parity floor. The ~2.2 KB test block needs 2 data shards; the
    /// skeleton floor forces 2 parity (4 chunks total) where the normal adaptive
    /// profile would ship only 1 parity (3 chunks). That extra parity lets the
    /// skeleton survive TWO lost packets, which the normal profile could not.
    #[test]
    fn skeleton_chunks_use_compact_skeleton_type_and_higher_parity() {
        let chunker = BlockChunker::new(10, 3).unwrap();
        let compact = make_test_compact_block();
        let object_hash = [0x5c; 32];

        // The normal adaptive profile for this block: 2 data + 1 parity.
        let normal = chunker
            .compact_block_to_chunks_adaptive(&compact, &object_hash)
            .unwrap();
        assert_eq!(normal.len(), 3, "normal adaptive: 2 data + 1 parity");

        let chunks = chunker
            .compact_block_to_chunks_skeleton(&compact, &object_hash)
            .unwrap();
        // Skeleton floor: 2 data + max(2, ceil(2/4)) = 2 parity = 4 chunks.
        assert_eq!(chunks.len(), 4, "skeleton: 2 data + 2 parity");
        assert!(chunks.iter().all(|c| c.header.version == 3));
        assert!(
            chunks
                .iter()
                .all(|c| c.header.msg_type == MessageType::CompactSkeleton)
        );
        assert!(chunks.iter().all(|c| c.header.data_shards == 2));

        let data_shards = chunks[0].header.data_shards as usize;
        let total = chunks.len();

        // Lose BOTH data packets (chunks 0 and 1). RS(2,2) rebuilds them from the
        // two surviving parity packets -- two-packet resilience the normal
        // 2-data/1-parity profile could never provide.
        let shard_size = chunks[0].payload.len();
        let mut shard_opts: Vec<Option<Vec<u8>>> = vec![None; total];
        for chunk in &chunks {
            let wire = chunk.to_bytes();
            let parsed = Chunk::from_bytes(&wire).unwrap();
            if parsed.header.chunk_id >= 2 {
                shard_opts[parsed.header.chunk_id as usize] = Some(parsed.payload);
            }
        }

        let original_len = shard_size * data_shards;
        let recovered = chunker
            .chunks_to_compact_block_with_shards(shard_opts, original_len, data_shards)
            .unwrap();
        assert_eq!(recovered.header, compact.header);
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
        assert!(
            ok.is_ok(),
            "expected default max payload to allow shard size under limit"
        );
    }
}

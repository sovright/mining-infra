//! Relay session management

use std::collections::HashMap;
use std::net::SocketAddr;
use std::time::{Duration, Instant};

use super::MessageType;
use hmac::{Hmac, Mac};

/// Result of one assembly-cleanup pass, feeding the delivery/miss instrument.
/// A "miss" is a block whose chunk assembly timed out before enough chunks
/// arrived to reconstruct -- the delivery failure that drives the propagation
/// tail (reconstruction itself is fast once chunks are present).
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct AssemblyCleanupStats {
    /// Assemblies dropped after timing out without reconstructing.
    pub expired_incomplete: u64,
    /// Of those, ones that had received >= 90% of `data_shards` -- a marginal
    /// miss a parity bump or retransmit would likely have saved, as opposed to
    /// a wholesale delivery failure (few chunks ever arrived).
    pub expired_incomplete_near: u64,
}
use sha2::Sha256;
use std::collections::VecDeque;
use subtle::ConstantTimeEq;

type HmacSha256 = Hmac<Sha256>;
const MAX_PENDING_BLOCKS: usize = 64;
const MAX_RECENT_CHUNKS: usize = 4096;
const RECENT_CHUNK_TTL: Duration = Duration::from_secs(120);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct ChunkKey {
    block_hash: [u8; 32],
    chunk_id: u16,
}

/// Block assembly state
#[derive(Debug)]
pub struct BlockAssembly {
    /// Block hash (from chunk headers)
    pub block_hash: [u8; 32],
    /// Relay message type for this assembly
    pub msg_type: MessageType,
    /// Total expected chunks
    pub total_chunks: usize,
    /// Per-block FEC data-shard count from the chunk header.
    ///
    /// Zero means "not carried on the wire" (a version-1/2 chunk); the receiver
    /// falls back to its fixed configured `data_shards`. Nonzero is the
    /// adaptive (version-3) per-block count captured from the first chunk.
    pub data_shards: u16,
    /// Received chunk payloads (indexed by chunk_id)
    pub chunks: Vec<Option<Vec<u8>>>,
    /// When we started receiving this block
    pub started_at: Instant,
    /// Original serialized data length (from first chunk metadata, if available)
    pub original_len: Option<usize>,
    /// Whether PoW has been validated
    pub pow_validated: bool,
    /// Tracks which chunks have already been forwarded downstream
    pub forwarded: Vec<bool>,
}

impl BlockAssembly {
    /// Create a new block assembly
    pub fn new(block_hash: [u8; 32], total_chunks: usize) -> Self {
        Self::new_for_message(block_hash, total_chunks, MessageType::Block)
    }

    /// Create a new block assembly for a specific relay message type.
    pub fn new_for_message(
        block_hash: [u8; 32],
        total_chunks: usize,
        msg_type: MessageType,
    ) -> Self {
        Self {
            block_hash,
            msg_type,
            total_chunks,
            data_shards: 0,
            chunks: vec![None; total_chunks],
            started_at: Instant::now(),
            original_len: None,
            pow_validated: false,
            forwarded: vec![false; total_chunks],
        }
    }

    /// Effective data-shard count for reconstruction.
    ///
    /// Returns the per-block adaptive value captured from a version-3 chunk
    /// header, or `fixed` (the receiver's configured `data_shards`) for a
    /// version-1/2 assembly that carries no per-block shard count.
    pub fn effective_data_shards(&self, fixed: usize) -> usize {
        if self.data_shards > 0 {
            self.data_shards as usize
        } else {
            fixed
        }
    }

    /// Add a chunk to the assembly
    pub fn add_chunk(&mut self, chunk_id: usize, payload: Vec<u8>) -> bool {
        if chunk_id < self.total_chunks {
            self.chunks[chunk_id] = Some(payload);
            true
        } else {
            false
        }
    }

    /// Count received chunks
    pub fn received_count(&self) -> usize {
        self.chunks.iter().filter(|c| c.is_some()).count()
    }

    /// Check if we have enough chunks to reconstruct
    pub fn can_reconstruct(&self, data_shards: usize) -> bool {
        self.received_count() >= data_shards
    }

    /// Check if assembly is complete (all chunks received)
    pub fn is_complete(&self) -> bool {
        self.received_count() == self.total_chunks
    }

    /// Check if assembly has timed out
    pub fn is_expired(&self, timeout: Duration) -> bool {
        self.started_at.elapsed() > timeout
    }
}

/// Authenticated relay session
pub struct RelaySession {
    /// Peer address
    pub peer_addr: SocketAddr,
    /// Pre-shared authentication key
    auth_key: [u8; 32],
    /// Last activity time
    pub last_seen: Instant,
    /// Pending block assemblies (keyed by block hash prefix)
    pub pending_blocks: HashMap<[u8; 32], BlockAssembly>,
    /// Recently seen chunks for replay detection
    recent_chunks: HashMap<ChunkKey, Instant>,
    recent_order: VecDeque<(ChunkKey, Instant)>,
}

impl RelaySession {
    /// Create a new session
    pub fn new(peer_addr: SocketAddr, auth_key: [u8; 32]) -> Self {
        Self {
            peer_addr,
            auth_key,
            last_seen: Instant::now(),
            pending_blocks: HashMap::new(),
            recent_chunks: HashMap::new(),
            recent_order: VecDeque::new(),
        }
    }

    /// Update last seen time
    pub fn touch(&mut self) {
        self.last_seen = Instant::now();
    }

    /// Check if session has timed out
    pub fn is_expired(&self, timeout: Duration) -> bool {
        self.last_seen.elapsed() > timeout
    }

    /// Compute HMAC for a version-2 chunk.
    ///
    /// Covers block_hash, chunk_id, total_chunks, payload_len, and payload.
    /// Byte-for-byte stable across releases -- do not change the fold order.
    pub fn compute_hmac(
        &self,
        block_hash: &[u8; 32],
        chunk_id: u16,
        total_chunks: u16,
        payload_len: u16,
        payload: &[u8],
    ) -> [u8; 32] {
        let mut mac = HmacSha256::new_from_slice(&self.auth_key)
            .expect("32-byte key should always be valid for HMAC-SHA256");
        mac.update(block_hash);
        mac.update(&chunk_id.to_be_bytes());
        mac.update(&total_chunks.to_be_bytes());
        mac.update(&payload_len.to_be_bytes());
        mac.update(payload);
        let result = mac.finalize();
        let mut output = [0u8; 32];
        output.copy_from_slice(&result.into_bytes());
        output
    }

    /// Compute HMAC for a version-3 (adaptive) chunk.
    ///
    /// Identical to [`RelaySession::compute_hmac`] but additionally authenticates
    /// the per-block `data_shards` count, folded in after `payload_len` and
    /// before the payload. A v3 chunk whose `data_shards` is tampered with will
    /// therefore fail verification.
    pub fn compute_hmac_v3(
        &self,
        block_hash: &[u8; 32],
        chunk_id: u16,
        total_chunks: u16,
        payload_len: u16,
        data_shards: u16,
        payload: &[u8],
    ) -> [u8; 32] {
        let mut mac = HmacSha256::new_from_slice(&self.auth_key)
            .expect("32-byte key should always be valid for HMAC-SHA256");
        mac.update(block_hash);
        mac.update(&chunk_id.to_be_bytes());
        mac.update(&total_chunks.to_be_bytes());
        mac.update(&payload_len.to_be_bytes());
        mac.update(&data_shards.to_be_bytes());
        mac.update(payload);
        let result = mac.finalize();
        let mut output = [0u8; 32];
        output.copy_from_slice(&result.into_bytes());
        output
    }

    /// Verify HMAC for a version-2 chunk
    pub fn verify_hmac(
        &self,
        block_hash: &[u8; 32],
        chunk_id: u16,
        total_chunks: u16,
        payload_len: u16,
        payload: &[u8],
        provided: &[u8; 32],
    ) -> bool {
        let expected = self.compute_hmac(block_hash, chunk_id, total_chunks, payload_len, payload);
        // Use constant-time comparison to prevent timing attacks
        expected.ct_eq(provided).into()
    }

    /// Verify HMAC for a version-3 (adaptive) chunk, authenticating `data_shards`.
    #[allow(clippy::too_many_arguments)]
    pub fn verify_hmac_v3(
        &self,
        block_hash: &[u8; 32],
        chunk_id: u16,
        total_chunks: u16,
        payload_len: u16,
        data_shards: u16,
        payload: &[u8],
        provided: &[u8; 32],
    ) -> bool {
        let expected = self.compute_hmac_v3(
            block_hash,
            chunk_id,
            total_chunks,
            payload_len,
            data_shards,
            payload,
        );
        expected.ct_eq(provided).into()
    }

    /// Track a chunk to prevent replay; returns false if seen recently
    pub fn mark_chunk_seen(&mut self, block_hash: [u8; 32], chunk_id: u16) -> bool {
        let key = ChunkKey {
            block_hash,
            chunk_id,
        };
        let now = Instant::now();

        if let Some(seen_at) = self.recent_chunks.get(&key)
            && now.duration_since(*seen_at) <= RECENT_CHUNK_TTL
        {
            return false;
        }

        self.recent_chunks.insert(key, now);
        self.recent_order.push_back((key, now));

        while self.recent_chunks.len() > MAX_RECENT_CHUNKS {
            if let Some((old_key, old_time)) = self.recent_order.pop_front() {
                // Only remove from map if the timestamp matches (entry wasn't updated)
                if self.recent_chunks.get(&old_key) == Some(&old_time) {
                    self.recent_chunks.remove(&old_key);
                }
                // Continue evicting until we're under the limit
            } else {
                break;
            }
        }

        true
    }

    /// Get or create a block assembly
    pub fn get_or_create_assembly(
        &mut self,
        block_hash: [u8; 32],
        total_chunks: usize,
    ) -> Option<&mut BlockAssembly> {
        self.get_or_create_assembly_for_message(block_hash, total_chunks, MessageType::Block)
    }

    /// Get or create an assembly for a specific relay message type.
    pub fn get_or_create_assembly_for_message(
        &mut self,
        block_hash: [u8; 32],
        total_chunks: usize,
        msg_type: MessageType,
    ) -> Option<&mut BlockAssembly> {
        use std::collections::hash_map::Entry;

        let at_capacity = self.pending_blocks.len() >= MAX_PENDING_BLOCKS;
        match self.pending_blocks.entry(block_hash) {
            Entry::Occupied(entry) => {
                let assembly = entry.into_mut();
                if assembly.total_chunks != total_chunks || assembly.msg_type != msg_type {
                    return None;
                }
                Some(assembly)
            }
            Entry::Vacant(entry) => {
                if at_capacity {
                    return None;
                }
                Some(entry.insert(BlockAssembly::new_for_message(
                    block_hash,
                    total_chunks,
                    msg_type,
                )))
            }
        }
    }

    /// Remove completed or expired assemblies, counting timed-out incomplete
    /// ones (delivery misses) and how many were near the reconstruction
    /// threshold. `data_shards` is the reconstruction threshold.
    pub fn cleanup_assemblies(
        &mut self,
        assembly_timeout: Duration,
        data_shards: usize,
    ) -> AssemblyCleanupStats {
        let mut stats = AssemblyCleanupStats::default();
        let near_threshold = data_shards.saturating_mul(9) / 10;
        self.pending_blocks.retain(|_, assembly| {
            let expired = assembly.is_expired(assembly_timeout);
            let complete = assembly.is_complete();
            if expired && !complete && !assembly.pow_validated {
                stats.expired_incomplete += 1;
                if assembly.received_count() >= near_threshold {
                    stats.expired_incomplete_near += 1;
                }
            }
            !expired && !complete
        });
        stats
    }

    /// Cleanup old replay entries
    pub fn cleanup_recent(&mut self) {
        let now = Instant::now();
        self.recent_chunks
            .retain(|_, t| now.duration_since(*t) <= RECENT_CHUNK_TTL);
        self.recent_order
            .retain(|(k, t)| self.recent_chunks.get(k) == Some(t));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn block_assembly_tracks_chunks() {
        let mut assembly = BlockAssembly::new([0xab; 32], 13);

        assert_eq!(assembly.received_count(), 0);
        assert!(!assembly.can_reconstruct(10));

        // Add 10 chunks
        for i in 0..10 {
            assembly.add_chunk(i, vec![i as u8; 100]);
        }

        assert_eq!(assembly.received_count(), 10);
        assert!(assembly.can_reconstruct(10));
        assert!(!assembly.is_complete());

        // Add remaining 3
        for i in 10..13 {
            assembly.add_chunk(i, vec![i as u8; 100]);
        }

        assert!(assembly.is_complete());
    }

    #[test]
    fn cleanup_counts_timed_out_incomplete_assemblies() {
        let addr = "127.0.0.1:8333".parse().unwrap();
        let mut session = RelaySession::new(addr, [0x42; 32]);
        let old = Instant::now() - Duration::from_secs(60);
        // data_shards = 10 -> near threshold = 9.

        // A: near-complete (9 chunks), expired -> miss AND near.
        let mut a = BlockAssembly::new([0xa1; 32], 12);
        for i in 0..9 {
            a.add_chunk(i, vec![0u8; 4]);
        }
        a.started_at = old;
        session.pending_blocks.insert([0xa1; 32], a);

        // B: wholesale miss (2 chunks), expired -> miss, NOT near.
        let mut b = BlockAssembly::new([0xb2; 32], 12);
        for i in 0..2 {
            b.add_chunk(i, vec![0u8; 4]);
        }
        b.started_at = old;
        session.pending_blocks.insert([0xb2; 32], b);

        // C: expired but already reconstructed -> NOT a miss.
        let mut c = BlockAssembly::new([0xc3; 32], 12);
        c.add_chunk(0, vec![0u8; 4]);
        c.pow_validated = true;
        c.started_at = old;
        session.pending_blocks.insert([0xc3; 32], c);

        // D: fresh incomplete -> retained, not a miss.
        let mut d = BlockAssembly::new([0xd4; 32], 12);
        d.add_chunk(0, vec![0u8; 4]);
        session.pending_blocks.insert([0xd4; 32], d);

        let stats = session.cleanup_assemblies(Duration::from_secs(10), 10);
        assert_eq!(stats.expired_incomplete, 2); // A + B
        assert_eq!(stats.expired_incomplete_near, 1); // A only (9 >= 9)
        assert!(session.pending_blocks.contains_key(&[0xd4; 32])); // fresh kept
        assert!(!session.pending_blocks.contains_key(&[0xa1; 32])); // expired dropped
    }

    #[test]
    fn session_hmac_verification() {
        let addr = "127.0.0.1:8333".parse().unwrap();
        let key = [0x42; 32];
        let session = RelaySession::new(addr, key);

        let block_hash = [0xab; 32];
        let chunk_id = 5u16;
        let total_chunks = 10u16;
        let payload = [0x01, 0x02, 0x03];
        let payload_len = payload.len() as u16;

        let hmac = session.compute_hmac(&block_hash, chunk_id, total_chunks, payload_len, &payload);
        assert!(session.verify_hmac(
            &block_hash,
            chunk_id,
            total_chunks,
            payload_len,
            &payload,
            &hmac
        ));

        // Wrong chunk_id should fail
        assert!(!session.verify_hmac(&block_hash, 6, total_chunks, payload_len, &payload, &hmac));
    }

    #[test]
    fn session_hmac_detects_payload_tampering() {
        let addr = "127.0.0.1:8333".parse().unwrap();
        let key = [0x24; 32];
        let session = RelaySession::new(addr, key);

        let block_hash = [0x11; 32];
        let chunk_id = 1u16;
        let total_chunks = 3u16;
        let payload = [0xaa, 0xbb, 0xcc];
        let payload_len = payload.len() as u16;

        let hmac = session.compute_hmac(&block_hash, chunk_id, total_chunks, payload_len, &payload);
        let tampered = [0xaa, 0xbb, 0xcd];

        assert!(!session.verify_hmac(
            &block_hash,
            chunk_id,
            total_chunks,
            payload_len,
            &tampered,
            &hmac
        ));
    }

    #[test]
    fn session_hmac_v3_authenticates_data_shards() {
        let addr = "127.0.0.1:8333".parse().unwrap();
        let session = RelaySession::new(addr, [0x42; 32]);

        let block_hash = [0xab; 32];
        let payload = [0x01, 0x02, 0x03];
        let hmac = session.compute_hmac_v3(&block_hash, 5, 10, 3, 7, &payload);

        // Correct data_shards verifies.
        assert!(session.verify_hmac_v3(&block_hash, 5, 10, 3, 7, &payload, &hmac));
        // Flipping data_shards fails verification.
        assert!(!session.verify_hmac_v3(&block_hash, 5, 10, 3, 8, &payload, &hmac));
    }

    #[test]
    fn session_hmac_v3_differs_from_v2() {
        let addr = "127.0.0.1:8333".parse().unwrap();
        let session = RelaySession::new(addr, [0x24; 32]);

        let block_hash = [0x11; 32];
        let payload = [0xaa, 0xbb, 0xcc];
        let v2 = session.compute_hmac(&block_hash, 1, 3, 3, &payload);
        let v3 = session.compute_hmac_v3(&block_hash, 1, 3, 3, 2, &payload);
        assert_ne!(v2, v3, "folding data_shards must change the HMAC");
    }

    #[test]
    fn effective_data_shards_prefers_per_block_value() {
        let mut assembly = BlockAssembly::new([0u8; 32], 3);
        // v2/v1 assembly (data_shards == 0) falls back to the fixed config.
        assert_eq!(assembly.effective_data_shards(224), 224);
        // v3 assembly uses the captured per-block value.
        assembly.data_shards = 2;
        assert_eq!(assembly.effective_data_shards(224), 2);
    }

    #[test]
    fn session_limits_pending_blocks() {
        let addr = "127.0.0.1:8333".parse().unwrap();
        let key = [0x11; 32];
        let mut session = RelaySession::new(addr, key);

        for i in 0..MAX_PENDING_BLOCKS {
            let mut hash = [0u8; 32];
            hash[0] = i as u8;
            assert!(session.get_or_create_assembly(hash, 1).is_some());
        }

        let mut overflow_hash = [0u8; 32];
        overflow_hash[0] = 0xff;
        assert!(session.get_or_create_assembly(overflow_hash, 1).is_none());
    }

    #[test]
    fn session_rejects_assembly_message_type_mismatch() {
        let addr = "127.0.0.1:8333".parse().unwrap();
        let key = [0x33; 32];
        let mut session = RelaySession::new(addr, key);
        let hash = [0x66; 32];

        assert!(
            session
                .get_or_create_assembly_for_message(hash, 13, MessageType::RawBlockSegment)
                .is_some()
        );
        assert!(
            session
                .get_or_create_assembly_for_message(hash, 13, MessageType::Block)
                .is_none()
        );
    }

    #[test]
    fn session_rejects_recent_replay() {
        let addr = "127.0.0.1:8333".parse().unwrap();
        let key = [0x22; 32];
        let mut session = RelaySession::new(addr, key);

        let hash = [0x55; 32];
        assert!(session.mark_chunk_seen(hash, 1));
        assert!(!session.mark_chunk_seen(hash, 1));
    }
}

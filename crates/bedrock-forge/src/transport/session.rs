//! Relay session management

use std::collections::HashMap;
use std::net::SocketAddr;
use std::time::{Duration, Instant};

use hmac::{Hmac, Mac};
use sha2::Sha256;
use subtle::ConstantTimeEq;
use std::collections::VecDeque;

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
    /// Total expected chunks
    pub total_chunks: usize,
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
        Self {
            block_hash,
            total_chunks,
            chunks: vec![None; total_chunks],
            started_at: Instant::now(),
            original_len: None,
            pow_validated: false,
            forwarded: vec![false; total_chunks],
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

    /// Compute HMAC for a chunk
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

    /// Verify HMAC for a chunk
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

    /// Track a chunk to prevent replay; returns false if seen recently
    pub fn mark_chunk_seen(&mut self, block_hash: [u8; 32], chunk_id: u16) -> bool {
        let key = ChunkKey { block_hash, chunk_id };
        let now = Instant::now();

        if let Some(seen_at) = self.recent_chunks.get(&key) {
            if now.duration_since(*seen_at) <= RECENT_CHUNK_TTL {
                return false;
            }
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
        use std::collections::hash_map::Entry;

        let at_capacity = self.pending_blocks.len() >= MAX_PENDING_BLOCKS;
        match self.pending_blocks.entry(block_hash) {
            Entry::Occupied(entry) => Some(entry.into_mut()),
            Entry::Vacant(entry) => {
                if at_capacity {
                    return None;
                }
                Some(entry.insert(BlockAssembly::new(block_hash, total_chunks)))
            }
        }
    }

    /// Remove completed or expired assemblies
    pub fn cleanup_assemblies(&mut self, assembly_timeout: Duration) {
        self.pending_blocks
            .retain(|_, assembly| !assembly.is_expired(assembly_timeout) && !assembly.is_complete());
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
        assert!(!session.verify_hmac(
            &block_hash,
            6,
            total_chunks,
            payload_len,
            &payload,
            &hmac
        ));
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
    fn session_rejects_recent_replay() {
        let addr = "127.0.0.1:8333".parse().unwrap();
        let key = [0x22; 32];
        let mut session = RelaySession::new(addr, key);

        let hash = [0x55; 32];
        assert!(session.mark_chunk_seen(hash, 1));
        assert!(!session.mark_chunk_seen(hash, 1));
    }
}

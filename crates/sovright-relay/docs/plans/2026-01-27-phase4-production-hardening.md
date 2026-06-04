# Phase 4: Production Hardening Implementation Plan

> Note: This document was written before the rename from fiber-zcash to bedrock-forge. Some internal references may still use the old name.

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Harden bedrock-forge relay for production use with HMAC authentication, logging, and metrics.

**Architecture:** Add HMAC authentication to chunk protocol (using existing session.rs methods), replace eprintln with tracing, add basic counters for operational visibility.

**Tech Stack:** Rust, tracing crate for structured logging, existing HMAC implementation

---

## Phase 4 Overview

Phase 4 delivers:
1. HMAC authentication in chunk protocol
2. Auth handshake message handling
3. Structured logging with tracing
4. Basic relay metrics (counters)
5. Production-ready error handling

---

## Task 1: Add tracing Dependency

**Files:**
- Modify: `Cargo.toml`

**Step 1: Add tracing dependency**

Add to `Cargo.toml` dependencies:

```toml
tracing = "0.1"
```

**Step 2: Verify compilation**

Run: `cargo check`
Expected: Compiles successfully

**Step 3: Commit**

```bash
git add Cargo.toml
git commit -m "$(cat <<'EOF'
chore: add tracing dependency for structured logging

Co-Authored-By: Claude Opus 4.5 <noreply@anthropic.com>
EOF
)"
```

---

## Task 2: Add HMAC Field to Chunk Header

**Files:**
- Modify: `src/transport/chunk.rs`

**Step 1: Extend ChunkHeader with HMAC field**

Update the ChunkHeader struct to include an optional HMAC field. The `reserved` field (4 bytes) is not enough for a 32-byte HMAC, so we need to extend the header.

Change HEADER_SIZE from 32 to 64 bytes:

```rust
/// Chunk header size in bytes (extended for HMAC)
pub const HEADER_SIZE: usize = 64;
```

Update ChunkHeader struct:

```rust
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChunkHeader {
    /// Protocol magic (CHUNK_MAGIC)
    pub magic: u32,
    /// Protocol version (2 for HMAC-enabled)
    pub version: u8,
    /// Message type
    pub msg_type: MessageType,
    /// Block hash (first 20 bytes for identification)
    pub block_hash: [u8; 20],
    /// Chunk index (0..total_chunks)
    pub chunk_id: u16,
    /// Total chunks for this block
    pub total_chunks: u16,
    /// Payload length
    pub payload_len: u16,
    /// HMAC-SHA256 of (block_hash || chunk_id) with auth key
    pub hmac: [u8; 32],
}
```

**Step 2: Update to_bytes**

```rust
    pub fn to_bytes(&self) -> [u8; HEADER_SIZE] {
        let mut buf = [0u8; HEADER_SIZE];
        buf[0..4].copy_from_slice(&self.magic.to_be_bytes());
        buf[4] = self.version;
        buf[5] = self.msg_type as u8;
        buf[6..26].copy_from_slice(&self.block_hash);
        buf[26..28].copy_from_slice(&self.chunk_id.to_be_bytes());
        buf[28..30].copy_from_slice(&self.total_chunks.to_be_bytes());
        buf[30..32].copy_from_slice(&self.payload_len.to_be_bytes());
        buf[32..64].copy_from_slice(&self.hmac);
        buf
    }
```

**Step 3: Update from_bytes to accept version 1 and 2**

```rust
    pub fn from_bytes(buf: &[u8]) -> io::Result<Self> {
        if buf.len() < 32 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "buffer too small for chunk header",
            ));
        }

        let magic = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]);
        if magic != CHUNK_MAGIC {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("invalid magic: expected {:08x}, got {:08x}", CHUNK_MAGIC, magic),
            ));
        }

        let version = buf[4];
        if version != 1 && version != 2 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("unsupported protocol version: {}", version),
            ));
        }

        let msg_type = MessageType::try_from(buf[5])?;

        let mut block_hash = [0u8; 20];
        block_hash.copy_from_slice(&buf[6..26]);

        let chunk_id = u16::from_be_bytes([buf[26], buf[27]]);
        let total_chunks = u16::from_be_bytes([buf[28], buf[29]]);
        let payload_len = u16::from_be_bytes([buf[30], buf[31]]);

        // HMAC is only present in version 2
        let hmac = if version == 2 && buf.len() >= HEADER_SIZE {
            let mut h = [0u8; 32];
            h.copy_from_slice(&buf[32..64]);
            h
        } else {
            [0u8; 32]
        };

        Ok(Self {
            magic,
            version,
            msg_type,
            block_hash,
            chunk_id,
            total_chunks,
            payload_len,
            hmac,
        })
    }
```

**Step 4: Update new_block to support HMAC**

```rust
    /// Create a new chunk header for block data (version 1, no HMAC)
    pub fn new_block(
        block_hash: &[u8; 32],
        chunk_id: u16,
        total_chunks: u16,
        payload_len: u16,
    ) -> Self {
        let mut hash_prefix = [0u8; 20];
        hash_prefix.copy_from_slice(&block_hash[..20]);

        Self {
            magic: CHUNK_MAGIC,
            version: 1,
            msg_type: MessageType::Block,
            block_hash: hash_prefix,
            chunk_id,
            total_chunks,
            payload_len,
            hmac: [0u8; 32],
        }
    }

    /// Create a new chunk header with HMAC (version 2)
    pub fn new_block_authenticated(
        block_hash: &[u8; 32],
        chunk_id: u16,
        total_chunks: u16,
        payload_len: u16,
        hmac: [u8; 32],
    ) -> Self {
        let mut hash_prefix = [0u8; 20];
        hash_prefix.copy_from_slice(&block_hash[..20]);

        Self {
            magic: CHUNK_MAGIC,
            version: 2,
            msg_type: MessageType::Block,
            block_hash: hash_prefix,
            chunk_id,
            total_chunks,
            payload_len,
            hmac,
        }
    }
```

**Step 5: Update Chunk::from_bytes for dynamic header size**

```rust
    pub fn from_bytes(buf: &[u8]) -> io::Result<Self> {
        // First parse minimal header to get version
        if buf.len() < 32 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "buffer too small for chunk header",
            ));
        }

        let version = buf[4];
        let header_size = if version == 2 { 64 } else { 32 };

        if buf.len() < header_size {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "buffer too small for chunk header",
            ));
        }

        let header = ChunkHeader::from_bytes(buf)?;

        if buf.len() < header_size + header.payload_len as usize {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "buffer too small for payload",
            ));
        }

        let payload = buf[header_size..header_size + header.payload_len as usize].to_vec();

        Ok(Self { header, payload })
    }
```

**Step 6: Run tests**

Run: `cargo test chunk`
Expected: All tests pass (may need to update tests for new header size)

**Step 7: Commit**

```bash
git add src/transport/chunk.rs
git commit -m "$(cat <<'EOF'
feat: add HMAC field to chunk header

Extend chunk protocol for authentication:
- Add 32-byte HMAC field to ChunkHeader
- Version 1: legacy (no HMAC), version 2: authenticated
- new_block_authenticated() constructor for HMAC chunks
- Backwards compatible parsing

Co-Authored-By: Claude Opus 4.5 <noreply@anthropic.com>
EOF
)"
```

---

## Task 3: Implement HMAC Verification in RelayNode

**Files:**
- Modify: `src/relay/node.rs`

**Step 1: Add tracing import**

```rust
use tracing::{debug, info, warn, error};
```

**Step 2: Update handle_packet for HMAC verification**

Replace the authentication TODO with actual HMAC verification:

```rust
    async fn handle_packet(&self, data: &[u8], src_addr: SocketAddr) -> Result<(), TransportError> {
        let chunk = Chunk::from_bytes(data)?;

        // Validate chunk counts
        if chunk.header.total_chunks == 0 || chunk.header.total_chunks > 1000 {
            return Err(TransportError::InvalidChunk(
                format!("invalid total_chunks: {}", chunk.header.total_chunks),
            ));
        }

        let block_hash = chunk.header.block_hash;
        let chunk_id = chunk.header.chunk_id as usize;
        let total_chunks = chunk.header.total_chunks as usize;

        if chunk_id >= total_chunks {
            return Err(TransportError::InvalidChunk(
                format!("chunk_id {} >= total_chunks {}", chunk_id, total_chunks),
            ));
        }

        let should_forward = {
            let mut sessions = self.sessions.write().await;

            // Check if session exists
            if let Some(session) = sessions.get_mut(&src_addr) {
                // Existing session - verify HMAC if version 2
                if chunk.header.version == 2 {
                    if !session.verify_hmac(&block_hash, chunk.header.chunk_id, &chunk.header.hmac) {
                        warn!(peer = %src_addr, "HMAC verification failed");
                        return Err(TransportError::AuthenticationFailed);
                    }
                }

                session.touch();
                self.process_chunk_for_session(session, &chunk, block_hash, chunk_id, total_chunks)
            } else {
                // New session - need to authenticate
                if self.config.authorized_keys.is_empty() {
                    // No auth required
                    debug!(peer = %src_addr, "Creating unauthenticated session");
                    sessions.insert(src_addr, RelaySession::new(src_addr, [0u8; 32]));
                    let session = sessions.get_mut(&src_addr).unwrap();
                    self.process_chunk_for_session(session, &chunk, block_hash, chunk_id, total_chunks)
                } else if chunk.header.version == 2 {
                    // Try to authenticate with any authorized key
                    let mut authenticated = false;
                    let mut matching_key = [0u8; 32];

                    for key in &self.config.authorized_keys {
                        let temp_session = RelaySession::new(src_addr, *key);
                        if temp_session.verify_hmac(&block_hash, chunk.header.chunk_id, &chunk.header.hmac) {
                            authenticated = true;
                            matching_key = *key;
                            break;
                        }
                    }

                    if authenticated {
                        info!(peer = %src_addr, "Authenticated new session");
                        sessions.insert(src_addr, RelaySession::new(src_addr, matching_key));
                        let session = sessions.get_mut(&src_addr).unwrap();
                        self.process_chunk_for_session(session, &chunk, block_hash, chunk_id, total_chunks)
                    } else {
                        warn!(peer = %src_addr, "Authentication failed - no matching key");
                        return Err(TransportError::AuthenticationFailed);
                    }
                } else {
                    // Auth required but client sent version 1
                    warn!(peer = %src_addr, "Authentication required but received unauthenticated chunk");
                    return Err(TransportError::AuthenticationFailed);
                }
            }
        };

        if should_forward {
            let sessions = self.sessions.read().await;
            if let Some(session) = sessions.get(&src_addr) {
                if let Some(assembly) = session.pending_blocks.get(&block_hash) {
                    let chunks_to_forward: Vec<_> = assembly.chunks.clone();
                    drop(sessions);
                    self.forward_to_peers(src_addr, &block_hash, &chunks_to_forward).await?;
                }
            }
        }

        Ok(())
    }

    /// Process a chunk for an existing session
    fn process_chunk_for_session(
        &self,
        session: &mut RelaySession,
        chunk: &Chunk,
        block_hash: [u8; 20],
        chunk_id: usize,
        total_chunks: usize,
    ) -> bool {
        let assembly = session.get_or_create_assembly(block_hash, total_chunks);
        let is_new = assembly.chunks.get(chunk_id).map_or(true, |c| c.is_none());
        assembly.add_chunk(chunk_id, chunk.payload.clone());

        if is_new && !assembly.pow_validated {
            if let Some(valid) = self.check_and_validate_header(assembly) {
                assembly.pow_validated = valid;
                valid
            } else {
                false
            }
        } else {
            assembly.pow_validated
        }
    }
```

**Step 3: Replace eprintln with tracing**

Update the run() method:

```rust
                Ok(Ok((len, src_addr))) => {
                    if let Err(e) = self.handle_packet(&buf[..len], src_addr).await {
                        debug!(peer = %src_addr, error = ?e, "Error handling packet");
                    }
                }
```

**Step 4: Run tests**

Run: `cargo test relay_node`
Expected: All tests pass

**Step 5: Commit**

```bash
git add src/relay/node.rs
git commit -m "$(cat <<'EOF'
feat: implement HMAC verification in RelayNode

Production-ready authentication:
- Verify HMAC for version 2 chunks
- Try all authorized_keys for new sessions
- Replace eprintln with tracing macros
- Extract process_chunk_for_session helper

Co-Authored-By: Claude Opus 4.5 <noreply@anthropic.com>
EOF
)"
```

---

## Task 4: Add HMAC to RelayClient Outgoing Chunks

**Files:**
- Modify: `src/relay/client.rs`

**Step 1: Add tracing import**

```rust
use tracing::{debug, warn};
```

**Step 2: Update send_block_internal to use authenticated chunks**

```rust
    async fn send_block_internal(
        &self,
        socket: &UdpSocket,
        block: &CompactBlock,
    ) -> Result<(), TransportError> {
        let block_hash = self.compute_block_hash(block);

        // Convert to chunks (unauthenticated first)
        let chunks = self.chunker.compact_block_to_chunks(block, &block_hash)?;

        // Create a temporary session for HMAC computation
        let session = crate::transport::RelaySession::new(
            "0.0.0.0:0".parse().unwrap(),
            self.config.auth_key,
        );

        // Send to all relay nodes
        for relay_addr in &self.config.relay_addrs {
            for chunk in &chunks {
                // Compute HMAC and create authenticated chunk
                let hmac = session.compute_hmac(&chunk.header.block_hash, chunk.header.chunk_id);
                let auth_header = ChunkHeader::new_block_authenticated(
                    &block_hash,
                    chunk.header.chunk_id,
                    chunk.header.total_chunks,
                    chunk.header.payload_len,
                    hmac,
                );
                let auth_chunk = Chunk::new(auth_header, chunk.payload.clone());

                let data = auth_chunk.to_bytes();
                socket.send_to(&data, relay_addr).await?;
            }
        }

        debug!(block_hash = ?&block_hash[..8], chunks = chunks.len(), "Sent authenticated block");
        Ok(())
    }
```

**Step 3: Replace eprintln with tracing**

In run() method:

```rust
                Some(block) = outgoing_rx.recv() => {
                    if let Err(e) = self.send_block_internal(&socket, &block).await {
                        warn!(error = ?e, "Error sending block");
                    }
                }
```

And in handle_incoming_chunk:

```rust
                if let Err(_) = tx.send(block).await {
                    warn!("Failed to deliver reconstructed block (receiver dropped)");
                }
```

**Step 4: Add imports**

```rust
use crate::transport::{
    BlockAssembly, BlockChunker, Chunk, ChunkHeader, ClientConfig, TransportError,
};
```

**Step 5: Run tests**

Run: `cargo test client`
Expected: All tests pass

**Step 6: Commit**

```bash
git add src/relay/client.rs
git commit -m "$(cat <<'EOF'
feat: add HMAC authentication to RelayClient

Authenticated block transmission:
- Compute HMAC for each chunk using auth_key
- Send version 2 authenticated chunks
- Replace eprintln with tracing

Co-Authored-By: Claude Opus 4.5 <noreply@anthropic.com>
EOF
)"
```

---

## Task 5: Add Relay Metrics

**Files:**
- Create: `src/relay/metrics.rs`
- Modify: `src/relay/mod.rs`
- Modify: `src/relay/node.rs`

**Step 1: Create metrics module**

Create `src/relay/metrics.rs`:

```rust
//! Relay metrics for operational monitoring

use std::sync::atomic::{AtomicU64, Ordering};

/// Relay node metrics
#[derive(Debug, Default)]
pub struct RelayMetrics {
    /// Total packets received
    pub packets_received: AtomicU64,
    /// Total packets forwarded
    pub packets_forwarded: AtomicU64,
    /// Authentication failures
    pub auth_failures: AtomicU64,
    /// Invalid chunks rejected
    pub invalid_chunks: AtomicU64,
    /// Blocks fully assembled
    pub blocks_assembled: AtomicU64,
    /// Sessions created
    pub sessions_created: AtomicU64,
    /// Sessions expired
    pub sessions_expired: AtomicU64,
}

impl RelayMetrics {
    /// Create new metrics
    pub fn new() -> Self {
        Self::default()
    }

    /// Increment packets received
    pub fn inc_packets_received(&self) {
        self.packets_received.fetch_add(1, Ordering::Relaxed);
    }

    /// Increment packets forwarded
    pub fn inc_packets_forwarded(&self) {
        self.packets_forwarded.fetch_add(1, Ordering::Relaxed);
    }

    /// Increment auth failures
    pub fn inc_auth_failures(&self) {
        self.auth_failures.fetch_add(1, Ordering::Relaxed);
    }

    /// Increment invalid chunks
    pub fn inc_invalid_chunks(&self) {
        self.invalid_chunks.fetch_add(1, Ordering::Relaxed);
    }

    /// Increment blocks assembled
    pub fn inc_blocks_assembled(&self) {
        self.blocks_assembled.fetch_add(1, Ordering::Relaxed);
    }

    /// Increment sessions created
    pub fn inc_sessions_created(&self) {
        self.sessions_created.fetch_add(1, Ordering::Relaxed);
    }

    /// Add to sessions expired count
    pub fn add_sessions_expired(&self, count: u64) {
        self.sessions_expired.fetch_add(count, Ordering::Relaxed);
    }

    /// Get snapshot of current metrics
    pub fn snapshot(&self) -> MetricsSnapshot {
        MetricsSnapshot {
            packets_received: self.packets_received.load(Ordering::Relaxed),
            packets_forwarded: self.packets_forwarded.load(Ordering::Relaxed),
            auth_failures: self.auth_failures.load(Ordering::Relaxed),
            invalid_chunks: self.invalid_chunks.load(Ordering::Relaxed),
            blocks_assembled: self.blocks_assembled.load(Ordering::Relaxed),
            sessions_created: self.sessions_created.load(Ordering::Relaxed),
            sessions_expired: self.sessions_expired.load(Ordering::Relaxed),
        }
    }
}

/// Snapshot of metrics at a point in time
#[derive(Debug, Clone)]
pub struct MetricsSnapshot {
    pub packets_received: u64,
    pub packets_forwarded: u64,
    pub auth_failures: u64,
    pub invalid_chunks: u64,
    pub blocks_assembled: u64,
    pub sessions_created: u64,
    pub sessions_expired: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn metrics_increment() {
        let metrics = RelayMetrics::new();

        metrics.inc_packets_received();
        metrics.inc_packets_received();
        metrics.inc_auth_failures();

        let snapshot = metrics.snapshot();
        assert_eq!(snapshot.packets_received, 2);
        assert_eq!(snapshot.auth_failures, 1);
        assert_eq!(snapshot.packets_forwarded, 0);
    }
}
```

**Step 2: Update relay/mod.rs**

```rust
mod client;
mod metrics;
mod node;

pub use client::{BlockReceiver, BlockSender, RelayClient};
pub use metrics::{MetricsSnapshot, RelayMetrics};
pub use node::RelayNode;
```

**Step 3: Add metrics to RelayNode**

In `src/relay/node.rs`, add metrics field and update methods:

Add to struct:
```rust
    /// Metrics
    metrics: Arc<RelayMetrics>,
```

Update constructor:
```rust
        Ok(Self {
            config,
            socket: None,
            sessions: Arc::new(RwLock::new(HashMap::new())),
            chunker,
            validator,
            running: Arc::new(AtomicBool::new(false)),
            metrics: Arc::new(RelayMetrics::new()),
        })
```

Add getter:
```rust
    /// Get metrics reference
    pub fn metrics(&self) -> &RelayMetrics {
        &self.metrics
    }
```

Update handle_packet to increment counters:
- After receiving: `self.metrics.inc_packets_received();`
- On auth failure: `self.metrics.inc_auth_failures();`
- On invalid chunk: `self.metrics.inc_invalid_chunks();`
- On session creation: `self.metrics.inc_sessions_created();`

Update forward_to_peers:
- After each send: `self.metrics.inc_packets_forwarded();`

Update cleanup_expired_sessions:
```rust
    async fn cleanup_expired_sessions(&self) {
        let mut sessions = self.sessions.write().await;
        let timeout = self.config.session_timeout;
        let before = sessions.len();
        sessions.retain(|_, session| !session.is_expired(timeout));
        let expired = before - sessions.len();
        if expired > 0 {
            self.metrics.add_sessions_expired(expired as u64);
        }
    }
```

**Step 4: Run tests**

Run: `cargo test`
Expected: All tests pass

**Step 5: Commit**

```bash
git add src/relay/metrics.rs src/relay/mod.rs src/relay/node.rs
git commit -m "$(cat <<'EOF'
feat: add relay metrics for operational monitoring

RelayMetrics counters:
- packets_received, packets_forwarded
- auth_failures, invalid_chunks
- blocks_assembled, sessions_created/expired
- Thread-safe with atomic counters

Co-Authored-By: Claude Opus 4.5 <noreply@anthropic.com>
EOF
)"
```

---

## Task 6: Update lib.rs Exports

**Files:**
- Modify: `src/lib.rs`

**Step 1: Add new exports**

Add to lib.rs exports:
```rust
pub use relay::{MetricsSnapshot, RelayMetrics};
```

**Step 2: Run tests**

Run: `cargo test`
Expected: All tests pass

**Step 3: Commit**

```bash
git add src/lib.rs
git commit -m "$(cat <<'EOF'
chore: export RelayMetrics from lib.rs

Co-Authored-By: Claude Opus 4.5 <noreply@anthropic.com>
EOF
)"
```

---

## Task 7: Integration Test with Authentication

**Files:**
- Modify: `tests/relay_integration.rs`

**Step 1: Add authenticated relay test**

```rust
/// Test authenticated relay with HMAC verification.
///
/// This test verifies that authentication works:
/// - Node configured with authorized_keys
/// - Client sends authenticated (version 2) chunks
/// - Node accepts and processes the chunks
#[tokio::test]
async fn authenticated_relay() {
    let auth_key = [0x42; 32];

    // Start relay node with auth required
    let node_config = RelayConfig::new("127.0.0.1:0".parse().unwrap())
        .with_authorized_keys(vec![auth_key]);
    let mut node = RelayNode::new(node_config).unwrap();
    node.bind().await.unwrap();

    let node_addr = node.local_addr().unwrap();
    let node = Arc::new(node);
    let node_clone = Arc::clone(&node);

    let node_handle = tokio::spawn(async move {
        node_clone.run().await
    });

    tokio::time::sleep(Duration::from_millis(50)).await;

    // Create client with matching auth key
    let client_config = ClientConfig::new(vec![node_addr], auth_key);
    let mut client = RelayClient::new(client_config).unwrap();
    client.bind().await.unwrap();
    let sender = client.sender();

    let _client_handle = tokio::spawn(async move {
        client.run().await
    });

    tokio::time::sleep(Duration::from_millis(50)).await;

    // Send a block
    let block = make_test_block();
    sender.send(block).await.unwrap();

    tokio::time::sleep(Duration::from_millis(200)).await;

    // Verify metrics show successful processing
    let metrics = node.metrics().snapshot();
    assert!(metrics.packets_received > 0, "Expected packets received");
    assert_eq!(metrics.auth_failures, 0, "Expected no auth failures");

    // Cleanup
    node.stop();
    let _ = node_handle.await;
}
```

**Step 2: Run tests**

Run: `cargo test --test relay_integration`
Expected: All tests pass

**Step 3: Commit**

```bash
git add tests/relay_integration.rs
git commit -m "$(cat <<'EOF'
test: add authenticated relay integration test

Tests HMAC authentication flow:
- Node with authorized_keys
- Client with matching auth_key
- Verify packets accepted without auth failures

Co-Authored-By: Claude Opus 4.5 <noreply@anthropic.com>
EOF
)"
```

---

## Phase 4 Summary

After completing all 7 tasks, you will have:

1. **HMAC Authentication** (`src/transport/chunk.rs`, `src/relay/node.rs`):
   - Version 2 chunk protocol with 32-byte HMAC
   - Server-side HMAC verification
   - Client-side HMAC signing

2. **Structured Logging** (all relay modules):
   - tracing macros replace eprintln
   - Debug/info/warn/error levels

3. **Metrics** (`src/relay/metrics.rs`):
   - Atomic counters for operational visibility
   - packets_received, packets_forwarded
   - auth_failures, invalid_chunks
   - sessions_created, sessions_expired

4. **Tests**:
   - Authenticated relay integration test
   - Metrics verification

**Next Steps (not in this plan)**:
- Real Equihash PoW validation
- Performance benchmarking
- Prometheus/metrics export endpoint

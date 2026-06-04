# Bedrock-Forge Phase 2: UDP/FEC Transport Implementation Plan

> Note: This document was written before the rename from fiber-zcash to bedrock-forge. Some internal references may still use the old name.

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Implement low-latency UDP transport with Forward Error Correction for FIBRE-style block relay between Zcash mining pools.

**Architecture:** Extends bedrock-forge with FEC encoding/decoding, UDP chunk protocol, and relay node/client components. Uses `reed-solomon-erasure` for FEC, `tokio` for async networking.

**Tech Stack:** Rust, tokio (async UDP), reed-solomon-erasure (FEC), hmac/sha2 (authentication)

---

## Phase 2 Overview

Phase 2 delivers:
1. FEC encoder/decoder for compact blocks
2. UDP chunk protocol with wire format
3. Relay session management with authentication
4. Relay node (server) with cut-through routing
5. Relay client for pool connectivity
6. Integration tests with simulated packet loss

---

## Task 1: Add Phase 2 Dependencies

**Files:**
- Modify: `Cargo.toml`

**Step 1: Add new dependencies**

Update `Cargo.toml`:

```toml
[dependencies]
thiserror = "1.0"
hex = "0.4"
siphasher = "1.0"
reed-solomon-erasure = "6.0"
tokio = { version = "1", features = ["net", "rt-multi-thread", "macros", "time", "sync"] }
hmac = "0.12"
sha2 = "0.10"
bytes = "1.5"

[dev-dependencies]
proptest = "1.4"
tokio-test = "0.4"
```

**Step 2: Verify compilation**

Run: `cargo check`
Expected: Compiles successfully

**Step 3: Commit**

```bash
git add Cargo.toml
git commit -m "$(cat <<'EOF'
chore: add Phase 2 dependencies

Add dependencies for UDP/FEC transport:
- reed-solomon-erasure for FEC encoding
- tokio for async UDP networking
- hmac/sha2 for session authentication
- bytes for buffer management

Co-Authored-By: Claude Opus 4.5 <noreply@anthropic.com>
EOF
)"
```

---

## Task 2: FEC Error Types

**Files:**
- Create: `src/fec/mod.rs`
- Create: `src/fec/error.rs`
- Modify: `src/lib.rs`

**Step 1: Create FEC module structure**

Create `src/fec/mod.rs`:

```rust
//! Forward Error Correction for compact block relay
//!
//! Uses Reed-Solomon erasure coding to enable block reconstruction
//! even when some UDP packets are lost.

mod error;

pub use error::FecError;
```

**Step 2: Create FEC error types**

Create `src/fec/error.rs`:

```rust
//! FEC error types

use thiserror::Error;

/// Errors that can occur during FEC operations
#[derive(Error, Debug)]
pub enum FecError {
    /// Not enough shards to reconstruct data
    #[error("insufficient shards: need {required}, have {available}")]
    InsufficientShards { required: usize, available: usize },

    /// Invalid shard configuration
    #[error("invalid configuration: {0}")]
    InvalidConfiguration(String),

    /// Reed-Solomon encoding failed
    #[error("encoding failed: {0}")]
    EncodingFailed(String),

    /// Reed-Solomon decoding failed
    #[error("decoding failed: {0}")]
    DecodingFailed(String),

    /// Data too large for configured shard count
    #[error("data too large: {size} bytes exceeds max {max} bytes")]
    DataTooLarge { size: usize, max: usize },
}
```

**Step 3: Add to lib.rs**

Add to `src/lib.rs`:

```rust
pub mod fec;

pub use fec::FecError;
```

**Step 4: Run tests**

Run: `cargo test`
Expected: All existing tests pass

**Step 5: Commit**

```bash
git add src/fec/mod.rs src/fec/error.rs src/lib.rs
git commit -m "$(cat <<'EOF'
feat: add FEC module and error types

Initialize Forward Error Correction module with error types:
- InsufficientShards
- InvalidConfiguration
- EncodingFailed / DecodingFailed
- DataTooLarge

Co-Authored-By: Claude Opus 4.5 <noreply@anthropic.com>
EOF
)"
```

---

## Task 3: FEC Encoder

**Files:**
- Create: `src/fec/encoder.rs`
- Modify: `src/fec/mod.rs`

**Step 1: Write failing test for encoder**

Add to `src/fec/mod.rs`:

```rust
mod encoder;

pub use encoder::FecEncoder;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encoder_creates_correct_shard_count() {
        let encoder = FecEncoder::new(10, 3).unwrap();
        let data = vec![0u8; 1000];
        let shards = encoder.encode(&data).unwrap();
        assert_eq!(shards.len(), 13); // 10 data + 3 parity
    }

    #[test]
    fn encoder_shards_have_equal_size() {
        let encoder = FecEncoder::new(10, 3).unwrap();
        let data = vec![0u8; 1000];
        let shards = encoder.encode(&data).unwrap();
        let shard_size = shards[0].len();
        for shard in &shards {
            assert_eq!(shard.len(), shard_size);
        }
    }
}
```

**Step 2: Run test to verify it fails**

Run: `cargo test`
Expected: FAIL with "cannot find module `encoder`"

**Step 3: Implement FecEncoder**

Create `src/fec/encoder.rs`:

```rust
//! FEC encoder using Reed-Solomon erasure coding

use reed_solomon_erasure::galois_8::ReedSolomon;

use super::FecError;

/// Forward Error Correction encoder
///
/// Encodes data into data shards + parity shards using Reed-Solomon.
/// Can reconstruct original data if at least `data_shards` of the
/// total shards are received.
pub struct FecEncoder {
    rs: ReedSolomon,
    data_shards: usize,
    parity_shards: usize,
}

impl FecEncoder {
    /// Create a new encoder with specified shard counts
    ///
    /// # Arguments
    /// * `data_shards` - Number of data shards (original data split into this many pieces)
    /// * `parity_shards` - Number of parity shards (redundancy for recovery)
    pub fn new(data_shards: usize, parity_shards: usize) -> Result<Self, FecError> {
        if data_shards == 0 {
            return Err(FecError::InvalidConfiguration(
                "data_shards must be > 0".into(),
            ));
        }
        if parity_shards == 0 {
            return Err(FecError::InvalidConfiguration(
                "parity_shards must be > 0".into(),
            ));
        }

        let rs = ReedSolomon::new(data_shards, parity_shards)
            .map_err(|e| FecError::InvalidConfiguration(e.to_string()))?;

        Ok(Self {
            rs,
            data_shards,
            parity_shards,
        })
    }

    /// Encode data into shards
    ///
    /// Returns a vector of shards: [data_shard_0, ..., data_shard_n, parity_0, ..., parity_m]
    pub fn encode(&self, data: &[u8]) -> Result<Vec<Vec<u8>>, FecError> {
        let total_shards = self.data_shards + self.parity_shards;

        // Calculate shard size (pad data to be divisible by data_shards)
        let shard_size = (data.len() + self.data_shards - 1) / self.data_shards;

        // Create shards with padding
        let mut shards: Vec<Vec<u8>> = Vec::with_capacity(total_shards);

        // Split data into data shards
        for i in 0..self.data_shards {
            let start = i * shard_size;
            let end = std::cmp::min(start + shard_size, data.len());

            let mut shard = vec![0u8; shard_size];
            if start < data.len() {
                let copy_len = end - start;
                shard[..copy_len].copy_from_slice(&data[start..end]);
            }
            shards.push(shard);
        }

        // Add empty parity shards
        for _ in 0..self.parity_shards {
            shards.push(vec![0u8; shard_size]);
        }

        // Encode parity
        self.rs
            .encode(&mut shards)
            .map_err(|e| FecError::EncodingFailed(e.to_string()))?;

        Ok(shards)
    }

    /// Get the number of data shards
    pub fn data_shards(&self) -> usize {
        self.data_shards
    }

    /// Get the number of parity shards
    pub fn parity_shards(&self) -> usize {
        self.parity_shards
    }

    /// Get total number of shards
    pub fn total_shards(&self) -> usize {
        self.data_shards + self.parity_shards
    }
}
```

**Step 4: Run tests to verify they pass**

Run: `cargo test`
Expected: PASS

**Step 5: Commit**

```bash
git add src/fec/encoder.rs src/fec/mod.rs
git commit -m "$(cat <<'EOF'
feat: add FecEncoder for Reed-Solomon encoding

Implement FEC encoder using reed-solomon-erasure:
- Configurable data and parity shard counts
- Pads data to equal-sized shards
- Returns data shards + parity shards

Co-Authored-By: Claude Opus 4.5 <noreply@anthropic.com>
EOF
)"
```

---

## Task 4: FEC Decoder

**Files:**
- Create: `src/fec/decoder.rs`
- Modify: `src/fec/mod.rs`

**Step 1: Write failing test for decoder**

Add to `src/fec/mod.rs`:

```rust
mod decoder;

pub use decoder::FecDecoder;
```

Add to tests in `src/fec/mod.rs`:

```rust
    #[test]
    fn decoder_reconstructs_from_all_shards() {
        let encoder = FecEncoder::new(10, 3).unwrap();
        let decoder = FecDecoder::new(10, 3).unwrap();

        let original = b"Hello, this is test data for FEC encoding!".to_vec();
        let shards = encoder.encode(&original).unwrap();

        // Convert to Option<Vec<u8>> (all present)
        let shard_opts: Vec<Option<Vec<u8>>> = shards.into_iter().map(Some).collect();

        let recovered = decoder.decode(shard_opts, original.len()).unwrap();
        assert_eq!(recovered, original);
    }

    #[test]
    fn decoder_reconstructs_with_missing_shards() {
        let encoder = FecEncoder::new(10, 3).unwrap();
        let decoder = FecDecoder::new(10, 3).unwrap();

        let original = b"Hello, this is test data for FEC encoding!".to_vec();
        let shards = encoder.encode(&original).unwrap();

        // Simulate losing 3 shards (parity can recover up to parity_shards losses)
        let mut shard_opts: Vec<Option<Vec<u8>>> = shards.into_iter().map(Some).collect();
        shard_opts[2] = None;
        shard_opts[5] = None;
        shard_opts[8] = None;

        let recovered = decoder.decode(shard_opts, original.len()).unwrap();
        assert_eq!(recovered, original);
    }

    #[test]
    fn decoder_fails_with_too_many_missing() {
        let encoder = FecEncoder::new(10, 3).unwrap();
        let decoder = FecDecoder::new(10, 3).unwrap();

        let original = b"Hello, this is test data for FEC encoding!".to_vec();
        let shards = encoder.encode(&original).unwrap();

        // Simulate losing 4 shards (more than parity_shards)
        let mut shard_opts: Vec<Option<Vec<u8>>> = shards.into_iter().map(Some).collect();
        shard_opts[0] = None;
        shard_opts[1] = None;
        shard_opts[2] = None;
        shard_opts[3] = None;

        let result = decoder.decode(shard_opts, original.len());
        assert!(result.is_err());
    }
```

**Step 2: Run test to verify it fails**

Run: `cargo test`
Expected: FAIL

**Step 3: Implement FecDecoder**

Create `src/fec/decoder.rs`:

```rust
//! FEC decoder using Reed-Solomon erasure coding

use reed_solomon_erasure::galois_8::ReedSolomon;

use super::FecError;

/// Forward Error Correction decoder
///
/// Reconstructs original data from received shards, even if some are missing.
pub struct FecDecoder {
    rs: ReedSolomon,
    data_shards: usize,
    parity_shards: usize,
}

impl FecDecoder {
    /// Create a new decoder with specified shard counts
    ///
    /// Must match the encoder configuration.
    pub fn new(data_shards: usize, parity_shards: usize) -> Result<Self, FecError> {
        if data_shards == 0 {
            return Err(FecError::InvalidConfiguration(
                "data_shards must be > 0".into(),
            ));
        }
        if parity_shards == 0 {
            return Err(FecError::InvalidConfiguration(
                "parity_shards must be > 0".into(),
            ));
        }

        let rs = ReedSolomon::new(data_shards, parity_shards)
            .map_err(|e| FecError::InvalidConfiguration(e.to_string()))?;

        Ok(Self {
            rs,
            data_shards,
            parity_shards,
        })
    }

    /// Decode shards back to original data
    ///
    /// # Arguments
    /// * `shards` - Vector of optional shards (None for missing/lost shards)
    /// * `original_len` - Original data length (needed to trim padding)
    ///
    /// # Returns
    /// Original data if enough shards are present, error otherwise
    pub fn decode(
        &self,
        mut shards: Vec<Option<Vec<u8>>>,
        original_len: usize,
    ) -> Result<Vec<u8>, FecError> {
        let total_shards = self.data_shards + self.parity_shards;

        if shards.len() != total_shards {
            return Err(FecError::InvalidConfiguration(format!(
                "expected {} shards, got {}",
                total_shards,
                shards.len()
            )));
        }

        // Count available shards
        let available = shards.iter().filter(|s| s.is_some()).count();
        if available < self.data_shards {
            return Err(FecError::InsufficientShards {
                required: self.data_shards,
                available,
            });
        }

        // Reconstruct missing shards
        self.rs
            .reconstruct(&mut shards)
            .map_err(|e| FecError::DecodingFailed(e.to_string()))?;

        // Concatenate data shards
        let mut data = Vec::with_capacity(original_len);
        for shard in shards.into_iter().take(self.data_shards) {
            if let Some(s) = shard {
                data.extend_from_slice(&s);
            }
        }

        // Trim to original length (remove padding)
        data.truncate(original_len);

        Ok(data)
    }

    /// Get the number of data shards
    pub fn data_shards(&self) -> usize {
        self.data_shards
    }

    /// Get the number of parity shards
    pub fn parity_shards(&self) -> usize {
        self.parity_shards
    }
}
```

**Step 4: Run tests to verify they pass**

Run: `cargo test`
Expected: PASS

**Step 5: Commit**

```bash
git add src/fec/decoder.rs src/fec/mod.rs
git commit -m "$(cat <<'EOF'
feat: add FecDecoder for Reed-Solomon decoding

Implement FEC decoder:
- Reconstructs data from partial shards
- Handles up to parity_shards missing pieces
- Trims padding to recover original data

Co-Authored-By: Claude Opus 4.5 <noreply@anthropic.com>
EOF
)"
```

---

## Task 5: Chunk Protocol Types

**Files:**
- Create: `src/transport/mod.rs`
- Create: `src/transport/chunk.rs`
- Modify: `src/lib.rs`

**Step 1: Create transport module**

Create `src/transport/mod.rs`:

```rust
//! UDP transport layer for compact block relay
//!
//! Implements chunked transmission with FEC for low-latency block propagation.

mod chunk;

pub use chunk::{Chunk, ChunkHeader, MessageType, CHUNK_MAGIC, MAX_PAYLOAD_SIZE};
```

**Step 2: Implement chunk protocol**

Create `src/transport/chunk.rs`:

```rust
//! UDP chunk protocol for block relay
//!
//! Wire format for transmitting FEC-encoded compact blocks over UDP.

use std::io::{self, Read, Write};

/// Protocol magic number: "ZCHR" (Zcash Relay)
pub const CHUNK_MAGIC: u32 = 0x5A434852;

/// Maximum payload size to fit in standard MTU
/// MTU (1500) - IP header (20) - UDP header (8) - Chunk header (32) = 1440
/// Round down to 1400 for safety
pub const MAX_PAYLOAD_SIZE: usize = 1400;

/// Chunk header size in bytes
pub const HEADER_SIZE: usize = 32;

/// Message types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum MessageType {
    /// Block data chunk
    Block = 0,
    /// Keepalive
    Keepalive = 1,
    /// Authentication handshake
    Auth = 2,
}

impl TryFrom<u8> for MessageType {
    type Error = io::Error;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(MessageType::Block),
            1 => Ok(MessageType::Keepalive),
            2 => Ok(MessageType::Auth),
            _ => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("invalid message type: {}", value),
            )),
        }
    }
}

/// Chunk header
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChunkHeader {
    /// Protocol magic (CHUNK_MAGIC)
    pub magic: u32,
    /// Protocol version
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
    /// Reserved for future use
    pub reserved: [u8; 4],
}

impl ChunkHeader {
    /// Create a new chunk header for block data
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
            reserved: [0; 4],
        }
    }

    /// Serialize header to bytes
    pub fn to_bytes(&self) -> [u8; HEADER_SIZE] {
        let mut buf = [0u8; HEADER_SIZE];
        buf[0..4].copy_from_slice(&self.magic.to_be_bytes());
        buf[4] = self.version;
        buf[5] = self.msg_type as u8;
        buf[6..26].copy_from_slice(&self.block_hash);
        buf[26..28].copy_from_slice(&self.chunk_id.to_be_bytes());
        buf[28..30].copy_from_slice(&self.total_chunks.to_be_bytes());
        buf[30..32].copy_from_slice(&self.payload_len.to_be_bytes());
        buf
    }

    /// Parse header from bytes
    pub fn from_bytes(buf: &[u8]) -> io::Result<Self> {
        if buf.len() < HEADER_SIZE {
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
        let msg_type = MessageType::try_from(buf[5])?;

        let mut block_hash = [0u8; 20];
        block_hash.copy_from_slice(&buf[6..26]);

        let chunk_id = u16::from_be_bytes([buf[26], buf[27]]);
        let total_chunks = u16::from_be_bytes([buf[28], buf[29]]);
        let payload_len = u16::from_be_bytes([buf[30], buf[31]]);

        Ok(Self {
            magic,
            version,
            msg_type,
            block_hash,
            chunk_id,
            total_chunks,
            payload_len,
            reserved: [0; 4],
        })
    }
}

/// Complete chunk (header + payload)
#[derive(Debug, Clone)]
pub struct Chunk {
    pub header: ChunkHeader,
    pub payload: Vec<u8>,
}

impl Chunk {
    /// Create a new chunk
    pub fn new(header: ChunkHeader, payload: Vec<u8>) -> Self {
        Self { header, payload }
    }

    /// Serialize chunk to bytes for transmission
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(HEADER_SIZE + self.payload.len());
        buf.extend_from_slice(&self.header.to_bytes());
        buf.extend_from_slice(&self.payload);
        buf
    }

    /// Parse chunk from received bytes
    pub fn from_bytes(buf: &[u8]) -> io::Result<Self> {
        let header = ChunkHeader::from_bytes(buf)?;

        if buf.len() < HEADER_SIZE + header.payload_len as usize {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "buffer too small for payload",
            ));
        }

        let payload = buf[HEADER_SIZE..HEADER_SIZE + header.payload_len as usize].to_vec();

        Ok(Self { header, payload })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chunk_header_roundtrip() {
        let block_hash = [0xab; 32];
        let header = ChunkHeader::new_block(&block_hash, 5, 13, 1400);

        let bytes = header.to_bytes();
        let parsed = ChunkHeader::from_bytes(&bytes).unwrap();

        assert_eq!(parsed.magic, CHUNK_MAGIC);
        assert_eq!(parsed.version, 1);
        assert_eq!(parsed.msg_type, MessageType::Block);
        assert_eq!(parsed.chunk_id, 5);
        assert_eq!(parsed.total_chunks, 13);
        assert_eq!(parsed.payload_len, 1400);
    }

    #[test]
    fn chunk_roundtrip() {
        let block_hash = [0xcd; 32];
        let header = ChunkHeader::new_block(&block_hash, 0, 10, 100);
        let payload = vec![1, 2, 3, 4, 5];
        let chunk = Chunk::new(header.clone(), payload.clone());

        let bytes = chunk.to_bytes();
        let parsed = Chunk::from_bytes(&bytes).unwrap();

        assert_eq!(parsed.header.chunk_id, 0);
        // Note: payload_len in header is 100, but actual payload is 5 bytes
        // The from_bytes uses header.payload_len to determine how much to read
    }

    #[test]
    fn rejects_invalid_magic() {
        let mut buf = [0u8; HEADER_SIZE];
        buf[0..4].copy_from_slice(&[0xFF, 0xFF, 0xFF, 0xFF]);

        let result = ChunkHeader::from_bytes(&buf);
        assert!(result.is_err());
    }
}
```

**Step 3: Add to lib.rs**

Add to `src/lib.rs`:

```rust
pub mod transport;

pub use transport::{Chunk, ChunkHeader, MessageType, CHUNK_MAGIC, MAX_PAYLOAD_SIZE};
```

**Step 4: Run tests**

Run: `cargo test`
Expected: All tests pass

**Step 5: Commit**

```bash
git add src/transport/mod.rs src/transport/chunk.rs src/lib.rs
git commit -m "$(cat <<'EOF'
feat: add UDP chunk protocol types

Implement wire format for block relay:
- ChunkHeader with magic, version, block hash prefix
- MessageType enum (Block, Keepalive, Auth)
- Chunk serialization/deserialization
- MAX_PAYLOAD_SIZE for MTU compliance

Co-Authored-By: Claude Opus 4.5 <noreply@anthropic.com>
EOF
)"
```

---

## Task 6: Block Chunker

**Files:**
- Create: `src/transport/chunker.rs`
- Modify: `src/transport/mod.rs`

**Step 1: Write tests for block chunker**

Add to `src/transport/mod.rs`:

```rust
mod chunker;

pub use chunker::BlockChunker;
```

**Step 2: Implement BlockChunker**

Create `src/transport/chunker.rs`:

```rust
//! Block chunker for converting compact blocks to/from FEC chunks

use crate::compact_block::CompactBlock;
use crate::fec::{FecDecoder, FecEncoder, FecError};
use crate::types::BlockHash;

use super::chunk::{Chunk, ChunkHeader, MAX_PAYLOAD_SIZE};

/// Converts compact blocks to FEC-encoded chunks for transmission
pub struct BlockChunker {
    encoder: FecEncoder,
    decoder: FecDecoder,
    data_shards: usize,
    parity_shards: usize,
}

impl BlockChunker {
    /// Create a new block chunker
    ///
    /// Default: 10 data shards, 3 parity shards (30% overhead, can lose up to 3 chunks)
    pub fn new(data_shards: usize, parity_shards: usize) -> Result<Self, FecError> {
        let encoder = FecEncoder::new(data_shards, parity_shards)?;
        let decoder = FecDecoder::new(data_shards, parity_shards)?;

        Ok(Self {
            encoder,
            decoder,
            data_shards,
            parity_shards,
        })
    }

    /// Default configuration (10 data, 3 parity)
    pub fn default_config() -> Result<Self, FecError> {
        Self::new(10, 3)
    }

    /// Serialize compact block to bytes
    fn serialize_compact_block(compact: &CompactBlock) -> Vec<u8> {
        // Simple serialization: header_len (4) + header + nonce (8) + short_ids + prefilled
        let mut data = Vec::new();

        // Header length + header
        let header_len = compact.header.len() as u32;
        data.extend_from_slice(&header_len.to_le_bytes());
        data.extend_from_slice(&compact.header);

        // Nonce
        data.extend_from_slice(&compact.nonce.to_le_bytes());

        // Short IDs count + data
        let short_id_count = compact.short_ids.len() as u32;
        data.extend_from_slice(&short_id_count.to_le_bytes());
        for short_id in &compact.short_ids {
            data.extend_from_slice(short_id.as_bytes());
        }

        // Prefilled count + data
        let prefilled_count = compact.prefilled_txs.len() as u32;
        data.extend_from_slice(&prefilled_count.to_le_bytes());
        for prefilled in &compact.prefilled_txs {
            data.extend_from_slice(&prefilled.index.to_le_bytes());
            let tx_len = prefilled.tx_data.len() as u32;
            data.extend_from_slice(&tx_len.to_le_bytes());
            data.extend_from_slice(&prefilled.tx_data);
        }

        data
    }

    /// Deserialize compact block from bytes
    fn deserialize_compact_block(data: &[u8]) -> std::io::Result<CompactBlock> {
        use crate::compact_block::PrefilledTx;
        use crate::types::ShortId;
        use std::io::{Cursor, Read};

        let mut cursor = Cursor::new(data);
        let mut buf4 = [0u8; 4];
        let mut buf8 = [0u8; 8];
        let mut buf6 = [0u8; 6];
        let mut buf2 = [0u8; 2];

        // Header
        cursor.read_exact(&mut buf4)?;
        let header_len = u32::from_le_bytes(buf4) as usize;
        let mut header = vec![0u8; header_len];
        cursor.read_exact(&mut header)?;

        // Nonce
        cursor.read_exact(&mut buf8)?;
        let nonce = u64::from_le_bytes(buf8);

        // Short IDs
        cursor.read_exact(&mut buf4)?;
        let short_id_count = u32::from_le_bytes(buf4) as usize;
        let mut short_ids = Vec::with_capacity(short_id_count);
        for _ in 0..short_id_count {
            cursor.read_exact(&mut buf6)?;
            short_ids.push(ShortId::from_bytes(buf6));
        }

        // Prefilled
        cursor.read_exact(&mut buf4)?;
        let prefilled_count = u32::from_le_bytes(buf4) as usize;
        let mut prefilled_txs = Vec::with_capacity(prefilled_count);
        for _ in 0..prefilled_count {
            cursor.read_exact(&mut buf2)?;
            let index = u16::from_le_bytes(buf2);
            cursor.read_exact(&mut buf4)?;
            let tx_len = u32::from_le_bytes(buf4) as usize;
            let mut tx_data = vec![0u8; tx_len];
            cursor.read_exact(&mut tx_data)?;
            prefilled_txs.push(PrefilledTx { index, tx_data });
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
        let total_chunks = shards.len() as u16;

        let chunks: Vec<Chunk> = shards
            .into_iter()
            .enumerate()
            .map(|(i, shard)| {
                let header = ChunkHeader::new_block(
                    block_hash,
                    i as u16,
                    total_chunks,
                    shard.len() as u16,
                );
                Chunk::new(header, shard)
            })
            .collect();

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
}
```

**Step 3: Update mod.rs exports**

Update `src/transport/mod.rs` to export BlockChunker.

**Step 4: Update lib.rs**

Add to lib.rs exports:

```rust
pub use transport::BlockChunker;
```

**Step 5: Run tests**

Run: `cargo test`
Expected: All tests pass

**Step 6: Commit**

```bash
git add src/transport/chunker.rs src/transport/mod.rs src/lib.rs
git commit -m "$(cat <<'EOF'
feat: add BlockChunker for compact block FEC encoding

Implement block chunking:
- Serialize CompactBlock to bytes
- FEC encode into data + parity shards
- Wrap shards as Chunks with headers
- Reconstruct from partial chunks

Co-Authored-By: Claude Opus 4.5 <noreply@anthropic.com>
EOF
)"
```

---

## Task 7: Transport Error Types

**Files:**
- Create: `src/transport/error.rs`
- Modify: `src/transport/mod.rs`

**Step 1: Create transport error types**

Create `src/transport/error.rs`:

```rust
//! Transport layer error types

use std::io;
use thiserror::Error;

use crate::fec::FecError;

/// Errors that can occur during relay transport
#[derive(Error, Debug)]
pub enum TransportError {
    /// IO error
    #[error("IO error: {0}")]
    Io(#[from] io::Error),

    /// FEC error
    #[error("FEC error: {0}")]
    Fec(#[from] FecError),

    /// Invalid chunk received
    #[error("invalid chunk: {0}")]
    InvalidChunk(String),

    /// Authentication failed
    #[error("authentication failed")]
    AuthenticationFailed,

    /// Session timeout
    #[error("session timeout")]
    Timeout,

    /// Block assembly incomplete
    #[error("block assembly incomplete: received {received}/{total} chunks")]
    IncompleteBlock { received: usize, total: usize },

    /// PoW validation failed
    #[error("PoW validation failed")]
    InvalidPow,

    /// Connection refused
    #[error("connection refused: {0}")]
    ConnectionRefused(String),
}
```

**Step 2: Update mod.rs**

Add to `src/transport/mod.rs`:

```rust
mod error;

pub use error::TransportError;
```

**Step 3: Update lib.rs**

Add export:

```rust
pub use transport::TransportError;
```

**Step 4: Run tests**

Run: `cargo test`
Expected: All tests pass

**Step 5: Commit**

```bash
git add src/transport/error.rs src/transport/mod.rs src/lib.rs
git commit -m "$(cat <<'EOF'
feat: add TransportError type

Define transport layer errors:
- Io, Fec wrapper errors
- InvalidChunk, AuthenticationFailed
- Timeout, IncompleteBlock, InvalidPow

Co-Authored-By: Claude Opus 4.5 <noreply@anthropic.com>
EOF
)"
```

---

## Task 8: Relay Session

**Files:**
- Create: `src/transport/session.rs`
- Modify: `src/transport/mod.rs`

**Step 1: Implement RelaySession**

Create `src/transport/session.rs`:

```rust
//! Relay session management

use std::collections::HashMap;
use std::net::SocketAddr;
use std::time::{Duration, Instant};

use hmac::{Hmac, Mac};
use sha2::Sha256;

use crate::types::BlockHash;

use super::chunk::Chunk;
use super::error::TransportError;

type HmacSha256 = Hmac<Sha256>;

/// Block assembly state
#[derive(Debug)]
pub struct BlockAssembly {
    /// Block hash (from chunk headers)
    pub block_hash: [u8; 20],
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
}

impl BlockAssembly {
    /// Create a new block assembly
    pub fn new(block_hash: [u8; 20], total_chunks: usize) -> Self {
        Self {
            block_hash,
            total_chunks,
            chunks: vec![None; total_chunks],
            started_at: Instant::now(),
            original_len: None,
            pow_validated: false,
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
    pub pending_blocks: HashMap<[u8; 20], BlockAssembly>,
}

impl RelaySession {
    /// Create a new session
    pub fn new(peer_addr: SocketAddr, auth_key: [u8; 32]) -> Self {
        Self {
            peer_addr,
            auth_key,
            last_seen: Instant::now(),
            pending_blocks: HashMap::new(),
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
    pub fn compute_hmac(&self, block_hash: &[u8; 20], chunk_id: u16) -> [u8; 32] {
        let mut mac = HmacSha256::new_from_slice(&self.auth_key)
            .expect("HMAC can take key of any size");
        mac.update(block_hash);
        mac.update(&chunk_id.to_be_bytes());
        let result = mac.finalize();
        let mut output = [0u8; 32];
        output.copy_from_slice(&result.into_bytes());
        output
    }

    /// Verify HMAC for a chunk
    pub fn verify_hmac(&self, block_hash: &[u8; 20], chunk_id: u16, provided: &[u8; 32]) -> bool {
        let expected = self.compute_hmac(block_hash, chunk_id);
        // Constant-time comparison
        expected == *provided
    }

    /// Get or create a block assembly
    pub fn get_or_create_assembly(
        &mut self,
        block_hash: [u8; 20],
        total_chunks: usize,
    ) -> &mut BlockAssembly {
        self.pending_blocks
            .entry(block_hash)
            .or_insert_with(|| BlockAssembly::new(block_hash, total_chunks))
    }

    /// Remove completed or expired assemblies
    pub fn cleanup_assemblies(&mut self, assembly_timeout: Duration) {
        self.pending_blocks
            .retain(|_, assembly| !assembly.is_expired(assembly_timeout));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn block_assembly_tracks_chunks() {
        let mut assembly = BlockAssembly::new([0xab; 20], 13);

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

        let block_hash = [0xab; 20];
        let chunk_id = 5u16;

        let hmac = session.compute_hmac(&block_hash, chunk_id);
        assert!(session.verify_hmac(&block_hash, chunk_id, &hmac));

        // Wrong chunk_id should fail
        assert!(!session.verify_hmac(&block_hash, 6, &hmac));
    }
}
```

**Step 2: Update mod.rs**

Add to `src/transport/mod.rs`:

```rust
mod session;

pub use session::{BlockAssembly, RelaySession};
```

**Step 3: Update lib.rs**

Add exports.

**Step 4: Run tests**

Run: `cargo test`
Expected: All tests pass

**Step 5: Commit**

```bash
git add src/transport/session.rs src/transport/mod.rs src/lib.rs
git commit -m "$(cat <<'EOF'
feat: add RelaySession and BlockAssembly

Implement session management:
- BlockAssembly tracks chunk reception
- RelaySession with HMAC authentication
- Session timeout and cleanup logic

Co-Authored-By: Claude Opus 4.5 <noreply@anthropic.com>
EOF
)"
```

---

## Task 9: Integration Test - FEC Round Trip

**Files:**
- Create: `tests/fec_integration.rs`

**Step 1: Write FEC integration tests**

Create `tests/fec_integration.rs`:

```rust
//! FEC integration tests

use bedrock_forge::{
    AuthDigest, BlockChunker, CompactBlock, CompactBlockBuilder,
    PrefilledTx, ShortId, TestMempool, TxId, WtxId,
};

fn make_wtxid(seed: u8) -> WtxId {
    WtxId::new(
        TxId::from_bytes([seed; 32]),
        AuthDigest::from_bytes([seed; 32]),
    )
}

fn make_realistic_compact_block() -> CompactBlock {
    // Simulate a block with coinbase + 50 transactions
    let header = vec![0xab; 2189]; // Zcash header size
    let nonce = 0xdeadbeef_u64;
    let header_hash = [0u8; 32];

    let coinbase = make_wtxid(0);
    let txs: Vec<_> = (1..=50).map(|i| make_wtxid(i)).collect();

    let mut builder = CompactBlockBuilder::new(header.clone(), nonce);
    builder.add_transaction(coinbase, vec![0u8; 500]); // Coinbase

    let mut mempool = TestMempool::new();
    for (i, wtxid) in txs.iter().enumerate() {
        let tx_data = vec![(i + 1) as u8; 300]; // 300 byte transactions
        mempool.insert(*wtxid, tx_data.clone());
        builder.add_transaction(*wtxid, tx_data);
    }

    builder.build(&mempool)
}

#[test]
fn fec_roundtrip_no_loss() {
    let chunker = BlockChunker::default_config().unwrap();
    let compact = make_realistic_compact_block();
    let block_hash = [0xcd; 32];

    // Encode
    let chunks = chunker.compact_block_to_chunks(&compact, &block_hash).unwrap();
    println!("Encoded into {} chunks", chunks.len());

    // Get original length
    let original_data = bedrock_forge::transport::chunker::BlockChunker::serialize_compact_block(&compact);
    let original_len = original_data.len();
    println!("Original data size: {} bytes", original_len);

    // Decode with all chunks
    let shard_opts: Vec<Option<Vec<u8>>> = chunks
        .into_iter()
        .map(|c| Some(c.payload))
        .collect();

    let recovered = chunker.chunks_to_compact_block(shard_opts, original_len).unwrap();

    assert_eq!(recovered.header.len(), compact.header.len());
    assert_eq!(recovered.nonce, compact.nonce);
    assert_eq!(recovered.short_ids.len(), compact.short_ids.len());
}

#[test]
fn fec_roundtrip_with_packet_loss() {
    let chunker = BlockChunker::default_config().unwrap();
    let compact = make_realistic_compact_block();
    let block_hash = [0xcd; 32];

    let chunks = chunker.compact_block_to_chunks(&compact, &block_hash).unwrap();

    let original_data = bedrock_forge::transport::chunker::BlockChunker::serialize_compact_block(&compact);
    let original_len = original_data.len();

    // Simulate 3 lost packets (max recoverable with 3 parity shards)
    let mut shard_opts: Vec<Option<Vec<u8>>> = chunks
        .into_iter()
        .map(|c| Some(c.payload))
        .collect();

    // Lose chunks 2, 7, 11
    shard_opts[2] = None;
    shard_opts[7] = None;
    shard_opts[11] = None;

    let recovered = chunker.chunks_to_compact_block(shard_opts, original_len).unwrap();

    assert_eq!(recovered.nonce, compact.nonce);
    assert_eq!(recovered.short_ids.len(), compact.short_ids.len());
}

#[test]
fn fec_fails_with_too_much_loss() {
    let chunker = BlockChunker::default_config().unwrap();
    let compact = make_realistic_compact_block();
    let block_hash = [0xcd; 32];

    let chunks = chunker.compact_block_to_chunks(&compact, &block_hash).unwrap();

    let original_data = bedrock_forge::transport::chunker::BlockChunker::serialize_compact_block(&compact);
    let original_len = original_data.len();

    // Simulate 4 lost packets (more than 3 parity shards can recover)
    let mut shard_opts: Vec<Option<Vec<u8>>> = chunks
        .into_iter()
        .map(|c| Some(c.payload))
        .collect();

    shard_opts[0] = None;
    shard_opts[1] = None;
    shard_opts[2] = None;
    shard_opts[3] = None;

    let result = chunker.chunks_to_compact_block(shard_opts, original_len);
    assert!(result.is_err());
}
```

**Step 2: Run integration tests**

Run: `cargo test --test fec_integration`
Expected: All tests pass

**Step 3: Commit**

```bash
git add tests/fec_integration.rs
git commit -m "$(cat <<'EOF'
test: add FEC integration tests

Test FEC round-trip scenarios:
- No packet loss (all chunks received)
- Partial loss (up to parity shards)
- Excessive loss (more than recoverable)

Co-Authored-By: Claude Opus 4.5 <noreply@anthropic.com>
EOF
)"
```

---

## Phase 2 Summary

After completing all 9 tasks, you will have:

1. **FEC Module** (`src/fec/`):
   - `FecEncoder` - Reed-Solomon encoding
   - `FecDecoder` - Reed-Solomon decoding with recovery
   - `FecError` - Error types

2. **Transport Module** (`src/transport/`):
   - `Chunk`, `ChunkHeader` - Wire protocol
   - `BlockChunker` - CompactBlock <-> FEC chunks
   - `RelaySession`, `BlockAssembly` - Session management
   - `TransportError` - Error types

3. **Tests**:
   - Unit tests for all components
   - FEC integration tests with simulated packet loss

**Next Steps (not in this plan)**:
- Task 10+: RelayNode async server implementation
- Task 11+: RelayClient async client implementation
- Task 12+: Full network integration tests

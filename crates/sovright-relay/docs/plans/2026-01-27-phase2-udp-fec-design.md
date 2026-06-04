# Phase 2: UDP/FEC Transport Design

> Note: This document was written before the rename from fiber-zcash to bedrock-forge. Some internal references may still use the old name.

## Overview

Phase 2 adds low-latency UDP transport with Forward Error Correction (FEC) to the bedrock-forge relay network. This enables FIBRE-style block propagation for Zcash mining pool infrastructure.

## Design Decisions

| Decision | Choice | Rationale |
|----------|--------|-----------|
| Approach | Full FIBRE port | FEC is the core innovation; without it UDP has no advantage |
| Use case | Mining pool infrastructure | Classic FIBRE use case, defines trust model |
| Topology | Hybrid | Public relay nodes + direct pool peering |
| FEC library | `reed-solomon-erasure` | Pure Rust, battle-tested, no C dependencies |
| Chunk size | ~1400 bytes | Fits standard MTU, avoids IP fragmentation |
| Cut-through | PoW validation first | Verify header before forwarding (Level 0 trust) |
| Connections | Persistent + authenticated | Low latency + access control for pool infra |

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    bedrock-forge crate                        │
├─────────────────────────────────────────────────────────────┤
│  Phase 1 (done)        │  Phase 2 (new)                     │
│  ─────────────────     │  ─────────────────                 │
│  • CompactBlock        │  • UdpTransport                    │
│  • Builder             │  • FecEncoder / FecDecoder         │
│  • Reconstructor       │  • ChunkProtocol                   │
│  • Messages            │  • RelaySession                    │
│                        │  • RelayNode (server)              │
│                        │  • RelayClient (pool connector)    │
└─────────────────────────────────────────────────────────────┘
```

## Components

### 1. FEC Encoder/Decoder (`src/fec.rs`)

Uses `reed-solomon-erasure` to encode compact blocks into data + parity chunks.

```rust
pub struct FecEncoder {
    data_shards: usize,    // e.g., 10
    parity_shards: usize,  // e.g., 3 (30% overhead)
}

impl FecEncoder {
    /// Encode data into shards (data + parity)
    pub fn encode(&self, data: &[u8]) -> Result<Vec<Vec<u8>>, FecError>;
}

pub struct FecDecoder {
    data_shards: usize,
    parity_shards: usize,
}

impl FecDecoder {
    /// Decode shards back to original data (can recover from missing shards)
    pub fn decode(&self, shards: Vec<Option<Vec<u8>>>) -> Result<Vec<u8>, FecError>;
}
```

### 2. Chunk Protocol (`src/chunk.rs`)

Wire format for UDP packets:

```
┌─────────────────────────────────────────────────────────────┐
│ Chunk Header (32 bytes)                                     │
├─────────────────────────────────────────────────────────────┤
│ magic: u32          │ Protocol identifier (0x5A434852)      │
│ version: u8         │ Protocol version                      │
│ msg_type: u8        │ 0=block, 1=keepalive, 2=auth          │
│ block_hash: [u8;20] │ First 20 bytes of block hash          │
│ chunk_id: u16       │ Which chunk (0..total_chunks)         │
│ total_chunks: u16   │ Total chunks for this block           │
│ chunk_len: u16      │ Payload length                        │
├─────────────────────────────────────────────────────────────┤
│ Payload (~1368 bytes max)                                   │
│ • For chunk 0: block header (2189 bytes, spans chunks 0-1)  │
│ • For other chunks: FEC-encoded compact block data          │
└─────────────────────────────────────────────────────────────┘
```

### 3. Relay Session (`src/session.rs`)

Manages authenticated persistent connection between a client and relay.

```rust
pub struct RelaySession {
    peer_addr: SocketAddr,
    auth_key: [u8; 32],        // Pre-shared key
    last_seen: Instant,
    pending_blocks: HashMap<BlockHash, BlockAssembly>,
}

pub struct BlockAssembly {
    header: Option<Vec<u8>>,
    chunks: Vec<Option<Vec<u8>>>,
    received_at: Instant,
    pow_validated: bool,
}
```

### 4. Relay Node (`src/relay_node.rs`)

Server component that:
- Listens for UDP packets from authenticated pools
- Validates PoW on block headers before forwarding
- Implements cut-through routing (forward chunks as they arrive, after PoW check)
- Manages multiple concurrent block assemblies

```rust
pub struct RelayNode {
    socket: UdpSocket,
    sessions: HashMap<SocketAddr, RelaySession>,
    authorized_keys: HashSet<[u8; 32]>,
}

impl RelayNode {
    pub async fn run(&mut self) -> Result<(), RelayError>;
}
```

### 5. Relay Client (`src/relay_client.rs`)

Client component for pools to:
- Connect to relay nodes
- Send newly mined blocks
- Receive blocks from other pools

```rust
pub struct RelayClient {
    socket: UdpSocket,
    relay_addrs: Vec<SocketAddr>,
    auth_key: [u8; 32],
}

impl RelayClient {
    pub async fn send_block(&self, compact: &CompactBlock) -> Result<(), RelayError>;
    pub async fn recv_block(&mut self) -> Result<CompactBlock, RelayError>;
}
```

## Data Flow

### Sending a Block

```
Pool mines block
       │
       ▼
CompactBlockBuilder.build()  ─────────────────────►  CompactBlock
       │
       ▼
FecEncoder.encode()  ─────────────────────────────►  [chunk0, chunk1, ..., chunkN, parity0, ...]
       │
       ▼
ChunkProtocol.wrap()  ────────────────────────────►  [UDP packets with headers]
       │
       ▼
RelayClient.send_block()  ────────────────────────►  UDP to relay node(s)
```

### Receiving a Block (Relay Node)

```
UDP packet arrives
       │
       ▼
ChunkProtocol.unwrap()  ──────────────────────────►  chunk_id, payload
       │
       ▼
BlockAssembly.add_chunk()
       │
       ▼
Header complete? ───► validate_equihash_pow()
       │                      │
       │                      ▼ (valid)
       │              Forward to other sessions (cut-through)
       │
       ▼
All chunks received? ───► FecDecoder.decode() ───► CompactBlock
```

## Authentication

Simple pre-shared key authentication:

1. Relay operator generates keys for authorized pools
2. Pool includes HMAC-SHA256(key, block_hash || chunk_id) in chunk header
3. Relay validates HMAC before processing

Future: Could upgrade to proper handshake with session keys.

## Error Handling

```rust
pub enum RelayError {
    Io(std::io::Error),
    Fec(FecError),
    InvalidChunk { reason: String },
    AuthenticationFailed,
    PowValidationFailed,
    Timeout,
}
```

## Configuration

```rust
pub struct RelayConfig {
    pub listen_addr: SocketAddr,
    pub data_shards: usize,      // default: 10
    pub parity_shards: usize,    // default: 3
    pub chunk_size: usize,       // default: 1400
    pub session_timeout: Duration,
    pub authorized_keys: Vec<[u8; 32]>,
}
```

## New Dependencies

```toml
[dependencies]
reed-solomon-erasure = "6.0"
tokio = { version = "1", features = ["net", "rt-multi-thread", "macros"] }
hmac = "0.12"
sha2 = "0.10"
```

## Testing Strategy

1. **Unit tests**: FEC encode/decode round-trip, chunk protocol serialization
2. **Integration tests**: Full send/receive cycle with simulated packet loss
3. **Benchmark**: Measure latency vs TCP baseline

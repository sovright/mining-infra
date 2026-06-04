# Mining Software Integration Guide

This guide is for developers integrating Zcash Stratum V2 support into mining software.

## Protocol Overview

Zcash Stratum V2 uses binary-encoded messages over TCP with optional Noise encryption.

### Message Frame Format

```
+----------------+----------------+------------------+
|  Message Type  |  Payload Len   |     Payload      |
|    (1 byte)    |   (2 bytes)    |   (variable)     |
+----------------+----------------+------------------+
```

All multi-byte integers are **little-endian**.

## Connection Establishment

### Step 1: TCP Connection

```rust
let stream = TcpStream::connect("pool.example.com:3333").await?;
```

### Step 2: Noise Handshake (Optional but Recommended)

If the pool supports Noise encryption:

```rust
use sovright_noise::{NoiseInitiator, PublicKey};

let server_pubkey = PublicKey::from_hex("pool_public_key_hex")?;
let initiator = NoiseInitiator::new(server_pubkey);
let encrypted_stream = initiator.connect(stream).await?;
```

**Noise Pattern**: `Noise_NK_25519_ChaChaPoly_BLAKE2s`

Handshake flow:
```
Client                              Server
  |                                    |
  |------- e, es (48 bytes) --------->|
  |<------ e, ee (48 bytes) ----------|
  |                                    |
  |  [All further messages encrypted]  |
```

### Step 3: Setup Connection

Send `SetupConnection` (0x00):

```rust
struct SetupConnection {
    protocol: u16,           // 0 = Mining Protocol
    min_version: u16,        // 2
    max_version: u16,        // 2
    flags: u32,              // 0 (no optional features)
    endpoint_host: String,   // Pool hostname (for SNI)
    endpoint_port: u16,      // Pool port
    vendor: String,          // "MyMiner/1.0"
    hardware_version: String,// "GPU-RTX3090"
    firmware: String,        // ""
    device_id: String,       // Unique device identifier
}
```

**Encoding**:
```
+----------+----------+----------+----------+
| protocol | min_ver  | max_ver  |  flags   |
|  2 bytes |  2 bytes |  2 bytes | 4 bytes  |
+----------+----------+----------+----------+
|  host_len |    endpoint_host (UTF-8)      |
|  1 byte   |    variable                   |
+-----------+-------------------------------+
|  port     | vendor_len | vendor (UTF-8)   |
|  2 bytes  |  1 byte    | variable         |
+-----------+------------+------------------+
... (remaining strings)
```

Receive `SetupConnection.Success` (0x01):
```rust
struct SetupConnectionSuccess {
    used_version: u16,       // Negotiated version
    flags: u32,              // Accepted flags
}
```

### Step 4: Open Mining Channel

Send `OpenStandardMiningChannel` (0x10):

```rust
struct OpenStandardMiningChannel {
    request_id: u32,
    user_identity: String,   // "wallet.worker"
    nominal_hashrate: f32,   // Expected hashrate (H/s)
    max_extranonce_size: u16,// Max NONCE_1 size we support
}
```

Receive `OpenStandardMiningChannel.Success` (0x11):

```rust
struct OpenStandardMiningChannelSuccess {
    request_id: u32,
    channel_id: u32,         // Use this in all future messages
    extranonce_prefix: Vec<u8>, // NONCE_1 (typically 4 bytes)
    group_channel_id: u32,
}
```

## Receiving Jobs

### NewMiningJob (0x1E)

```rust
struct NewMiningJob {
    channel_id: u32,
    job_id: u32,
    future_job: bool,         // If true, don't mine yet
    version: u32,
    prev_hash: [u8; 32],      // Previous block hash
    merkle_root: [u8; 32],    // Merkle root of transactions
    block_commitments: [u8; 32], // NU5+ hashBlockCommitments
    nbits: u32,               // Compact difficulty target
    ntime: u32,               // Block timestamp
}
```

### SetTarget (0x21)

Updates share difficulty:

```rust
struct SetTarget {
    channel_id: u32,
    max_target: [u8; 32],     // Maximum hash value for valid share
}
```

Convert target to difficulty:
```rust
fn target_to_difficulty(target: &[u8; 32]) -> f64 {
    // Zcash uses big-endian for difficulty comparison
    let target_u256 = U256::from_be_bytes(*target);
    let max_target = U256::from(0xFFFF) << 208; // Equihash base
    (max_target / target_u256).as_f64()
}
```

### NewPrevHash (0x20)

Indicates a new block; invalidates all previous jobs:

```rust
struct NewPrevHash {
    channel_id: u32,
    prev_hash: [u8; 32],
    min_ntime: u32,
    nbits: u32,
}
```

## Mining Loop

### Constructing the Block Header

Zcash block header is 140 bytes:

```rust
fn build_header(job: &NewMiningJob, nonce: &[u8; 32]) -> [u8; 140] {
    let mut header = [0u8; 140];

    // Version (4 bytes, little-endian)
    header[0..4].copy_from_slice(&job.version.to_le_bytes());

    // Previous block hash (32 bytes)
    header[4..36].copy_from_slice(&job.prev_hash);

    // Merkle root (32 bytes)
    header[36..68].copy_from_slice(&job.merkle_root);

    // Block commitments - hashBlockCommitments for NU5+ (32 bytes)
    header[68..100].copy_from_slice(&job.block_commitments);

    // Time (4 bytes, little-endian)
    header[100..104].copy_from_slice(&job.ntime.to_le_bytes());

    // nBits (4 bytes, little-endian)
    header[104..108].copy_from_slice(&job.nbits.to_le_bytes());

    // Nonce (32 bytes)
    header[108..140].copy_from_slice(nonce);

    header
}
```

### Nonce Space

```
Nonce (32 bytes):
+------------------+--------------------------------+
|     NONCE_1      |            NONCE_2             |
|  (from pool)     |      (miner iterates)          |
|    4 bytes       |           28 bytes             |
+------------------+--------------------------------+
```

```rust
fn build_nonce(extranonce_prefix: &[u8], nonce2: u64) -> [u8; 32] {
    let mut nonce = [0u8; 32];

    // Copy pool's extranonce (NONCE_1)
    nonce[..extranonce_prefix.len()].copy_from_slice(extranonce_prefix);

    // Fill NONCE_2 (remaining bytes)
    let nonce2_start = extranonce_prefix.len();
    nonce[nonce2_start..nonce2_start + 8].copy_from_slice(&nonce2.to_le_bytes());

    nonce
}
```

### Equihash (200,9) Solving

```rust
// Pseudocode for Equihash solving
fn mine(header: &[u8; 140], target: &[u8; 32]) -> Option<(Nonce, Solution)> {
    for nonce2 in 0..u64::MAX {
        let nonce = build_nonce(&extranonce_prefix, nonce2);
        let header_with_nonce = build_header(job, &nonce);

        // Try to find Equihash solution
        if let Some(solution) = solve_equihash_200_9(&header_with_nonce) {
            // Check if meets target
            let hash = blake2b_256(&header_with_nonce, &solution);
            if hash <= target {
                return Some((nonce, solution));
            }
        }
    }
    None
}
```

Equihash (200,9) parameters:
- **n** = 200 (bit width)
- **k** = 9 (number of steps)
- **Solution size** = 1344 bytes (2^9 * 21 bits, packed)

## Submitting Shares

### SubmitSharesStandard (0x1C)

```rust
struct SubmitSharesStandard {
    channel_id: u32,
    sequence_number: u32,     // Incrementing counter
    job_id: u32,              // From NewMiningJob
    nonce: [u8; 32],          // Full 32-byte nonce
    ntime: u32,               // Block time (can roll within limits)
    solution: Vec<u8>,        // 1344-byte Equihash solution
}
```

**Binary encoding**:
```
+------------+------------+------------+
| channel_id |  seq_num   |   job_id   |
|  4 bytes   |  4 bytes   |  4 bytes   |
+------------+------------+------------+
|           nonce (32 bytes)           |
+--------------------------------------+
|   ntime    | solution_len | solution |
|  4 bytes   |   2 bytes    | 1344 B   |
+------------+--------------+----------+
```

### SubmitShares.Success (0x1D)

```rust
struct SubmitSharesSuccess {
    channel_id: u32,
    last_sequence_number: u32,  // Confirms receipt up to this seq
    new_submits_accepted: u32,  // Number of shares accepted
    new_shares_sum: u64,        // Sum of difficulty of accepted shares
}
```

### SubmitShares.Error (0x1E)

```rust
struct SubmitSharesError {
    channel_id: u32,
    sequence_number: u32,       // Which submission failed
    error_code: u32,            // See error codes below
}
```

**Error Codes**:
| Code | Meaning |
|------|---------|
| 0x01 | Invalid channel |
| 0x02 | Stale share (job expired) |
| 0x03 | Difficulty too low |
| 0x04 | Invalid solution |
| 0x05 | Duplicate share |

## Complete Message Type Reference

### Client -> Server

| Type | Name | Description |
|------|------|-------------|
| 0x00 | SetupConnection | Initial connection setup |
| 0x10 | OpenStandardMiningChannel | Open mining channel |
| 0x1C | SubmitSharesStandard | Submit found shares |

### Server -> Client

| Type | Name | Description |
|------|------|-------------|
| 0x01 | SetupConnection.Success | Connection accepted |
| 0x02 | SetupConnection.Error | Connection rejected |
| 0x11 | OpenStandardMiningChannel.Success | Channel opened |
| 0x12 | OpenStandardMiningChannel.Error | Channel rejected |
| 0x1D | SubmitShares.Success | Shares accepted |
| 0x1E | SubmitShares.Error | Shares rejected |
| 0x1F | NewMiningJob | New work to mine |
| 0x20 | NewPrevHash | New block, invalidate old work |
| 0x21 | SetTarget | Update share difficulty |

## Implementation Checklist

### Minimum Viable Implementation

- [ ] TCP connection handling
- [ ] Message framing (type + length + payload)
- [ ] SetupConnection / SetupConnection.Success
- [ ] OpenStandardMiningChannel / Success
- [ ] NewMiningJob parsing
- [ ] SetTarget parsing
- [ ] Header construction (140 bytes)
- [ ] Nonce space iteration
- [ ] Equihash (200,9) solver
- [ ] SubmitSharesStandard encoding
- [ ] Share acceptance/rejection handling

### Recommended Additions

- [ ] Noise Protocol encryption
- [ ] Automatic reconnection
- [ ] NewPrevHash handling (drop stale work)
- [ ] Vardiff tracking
- [ ] Share statistics logging
- [ ] Multiple pool failover

### Advanced Features

- [ ] Job Declaration Protocol support
- [ ] Full-Template mode
- [ ] Aggregated share submission
- [ ] Channel multiplexing

## Reference Implementation

See the example miner in the repository:

```bash
cargo run --example simple_miner -- \
  --pool pool.example.com:3333 \
  --worker wallet.worker1
```

Source: `crates/zcash-mining-protocol/examples/simple_miner.rs`

## Testing

### Mock Pool Server

```bash
# Run the test pool server
cargo run --example mock_pool

# Connect your implementation
./your_miner --pool 127.0.0.1:3333
```

### Protocol Validation

Use `wireshark` with the SV2 dissector or our debug tool:

```bash
# Capture and decode SV2 traffic
cargo run --example sv2_decoder < captured_traffic.bin
```

## Common Mistakes

1. **Wrong endianness**: All integers are little-endian
2. **Wrong nonce format**: Pool's NONCE_1 goes at the START of the 32-byte nonce
3. **Wrong solution format**: Equihash solutions are bit-packed, not byte-aligned
4. **Ignoring SetTarget**: Must respect difficulty updates
5. **Not handling NewPrevHash**: Results in many stale shares

## Performance Considerations

- **Batch submissions**: Submit multiple shares in one message when possible
- **Async I/O**: Use non-blocking sockets to not stall mining
- **Pre-compute**: Cache constant header bytes between jobs
- **Memory pools**: Avoid allocations in hot path

## Support

For implementation questions:
- GitHub Issues: https://github.com/iqlusioninc/stratum-zcash/issues
- Protocol spec: [Stratum V2 Specification](https://stratumprotocol.org/)

# Migration from Stratum V1 to Stratum V2

This guide helps pool operators and mining software developers migrate from Zcash's existing Stratum V1 protocol (ZIP 301) to Stratum V2.

## Current Zcash Mining Landscape

### Existing Stratum V1 Implementations

Based on research, the current Zcash mining ecosystem uses:

**Mining Software:**
- [lolMiner](https://github.com/Lolliedieb/lolMiner-releases) - GPU miner with Equihash support
- [miniZ](https://miniz.ch/) - Optimized Equihash miner
- [GMiner](https://gminer.info/) - Multi-algorithm GPU miner
- Legacy: EWBF, nheqminer, Genoil ZECMiner

**Major Pools:**
- [Flypool](https://zcash.flypool.org/start) - Europe, Asia, US servers
- [F2Pool](https://f2pool.io/mining/guides/how-to-mine-zcash/) - Global, PPS payout
- [2miners](https://2miners.com/) - PPLNS/solo options
- [ViaBTC](https://www.viabtc.com/) - PPS+ payout

**ASIC Miners:**
- Bitmain Antminer Z15 Pro (840 KSol/s)
- Innosilicon A9++ (140 KSol/s)

## Protocol Comparison

### ZIP 301 (Stratum V1) vs Stratum V2

| Feature | Stratum V1 (ZIP 301) | Stratum V2 |
|---------|---------------------|------------|
| **Encoding** | JSON-RPC 1.0 | Binary (compact) |
| **Encryption** | None | Noise Protocol |
| **Message termination** | ASCII LF | Length-prefixed |
| **Nonce handling** | NONCE_1 + NONCE_2 (text) | NONCE_1 + NONCE_2 (binary) |
| **Difficulty** | 256-bit target | 256-bit target |
| **Job Declaration** | Not supported | Full support |
| **Transaction selection** | Pool only | Miner optional |

### Message Mapping

| V1 Method | V2 Message |
|-----------|------------|
| `mining.subscribe` | SetupConnection + OpenMiningChannel |
| `mining.authorize` | Included in OpenMiningChannel |
| `mining.notify` | NewMiningJob |
| `mining.set_target` | SetTarget |
| `mining.submit` | SubmitSharesStandard |
| `client.reconnect` | Reconnect |

## V1 Protocol Details (ZIP 301)

### Current Message Format

```json
{"id": 1, "method": "mining.subscribe", "params": ["user-agent/1.0", null, "pool.example.com", 3333]}
{"id": 2, "method": "mining.authorize", "params": ["wallet.worker", "password"]}
{"id": null, "method": "mining.notify", "params": ["job_id", "version", "prev_hash", "merkle_root", "reserved", "time", "bits", true]}
{"id": 4, "method": "mining.submit", "params": ["wallet.worker", "job_id", "time", "nonce_2", "solution"]}
```

### V1 Nonce Handling

ZIP 301 specifies:
- `NONCE_1`: Server-assigned prefix (< 32 bytes)
- `NONCE_2`: Miner iterates (32 - len(NONCE_1) bytes)
- Combined as little-endian 32-byte nonce

```
// V1 nonce construction
nonce = NONCE_1 || NONCE_2  // concatenation
// Incrementing: miner adds (1 << (len(NONCE_1) * 8)) to preserve NONCE_1
```

### V1 Solution Format

Equihash solution with compactSize prefix:
```
// 1344 bytes for Equihash 200,9
solution_with_size = compactSize(1344) || solution_bytes
```

## V2 Protocol Details

### Binary Message Format

```
+----------------+----------------+------------------+
|  Message Type  |  Payload Len   |     Payload      |
|    (1 byte)    |   (2 bytes LE) |   (variable)     |
+----------------+----------------+------------------+
```

### V2 Nonce Handling

Same conceptual split, but binary encoded:
```rust
// V2 nonce construction
let mut nonce = [0u8; 32];
nonce[..extranonce.len()].copy_from_slice(&extranonce);
nonce[extranonce.len()..].copy_from_slice(&nonce2_bytes);
```

### V2 Solution Format

Raw 1344 bytes, no compactSize prefix:
```rust
struct SubmitSharesStandard {
    channel_id: u32,
    sequence_number: u32,
    job_id: u32,
    nonce: [u8; 32],
    ntime: u32,
    solution: [u8; 1344],  // Raw solution, no length prefix
}
```

## Migration Steps

### For Pool Operators

#### Phase 1: Dual-Stack Support

Run both V1 and V2 endpoints:

```
Pool Server
├── Port 3333: Stratum V1 (existing)
└── Port 3335: Stratum V2 (new)
```

Share validation and payout tracking remain unified.

#### Phase 2: V2 Feature Enablement

1. Enable Noise encryption on V2 endpoint
2. Enable Job Declaration support
3. Optionally enable Full-Template mode

#### Phase 3: V1 Deprecation

After sufficient V2 adoption:
1. Announce V1 deprecation timeline
2. Redirect V1 connections to V2 (with proxy if needed)
3. Retire V1 endpoint

### For Mining Software Developers

#### Step 1: Add Binary Codec

Replace JSON-RPC parsing with binary message handling:

```rust
// V1: JSON parsing
let msg: Value = serde_json::from_str(&line)?;

// V2: Binary parsing
let msg_type = reader.read_u8()?;
let payload_len = reader.read_u16::<LittleEndian>()?;
let payload = reader.read_exact(payload_len)?;
```

#### Step 2: Implement New Handshake

```rust
// V1
mining.subscribe() -> session_id, nonce_1
mining.authorize() -> success

// V2
SetupConnection -> SetupConnection.Success
OpenStandardMiningChannel -> OpenStandardMiningChannel.Success (includes extranonce)
```

#### Step 3: Handle Binary Jobs

```rust
// V1: Parse JSON fields
let job_id = params[0].as_str()?;
let prev_hash = hex::decode(params[2].as_str()?)?;

// V2: Parse binary struct
let job = NewMiningJob {
    channel_id: reader.read_u32::<LittleEndian>()?,
    job_id: reader.read_u32::<LittleEndian>()?,
    prev_hash: reader.read_exact(32)?,
    // ...
};
```

#### Step 4: Update Solution Submission

```rust
// V1: JSON with hex-encoded solution
{"method": "mining.submit", "params": ["worker", "job_id", "time", "nonce2_hex", "solution_hex"]}

// V2: Binary submission
writer.write_u8(0x1C)?;  // SubmitSharesStandard
writer.write_u16::<LittleEndian>(payload.len())?;
writer.write_all(&channel_id.to_le_bytes())?;
writer.write_all(&nonce)?;
writer.write_all(&solution)?;  // Raw bytes, no hex
```

#### Step 5: Add Noise Support (Optional but Recommended)

```rust
use sovright_noise::{NoiseInitiator, PublicKey};

// Before: plain TCP
let stream = TcpStream::connect(pool_addr)?;

// After: Noise-encrypted
let server_key = PublicKey::from_hex(pool_pubkey)?;
let initiator = NoiseInitiator::new(server_key);
let stream = initiator.connect(TcpStream::connect(pool_addr)?)?;
```

## Configuration Migration

### lolMiner Example

**V1 Configuration:**
```bash
lolMiner --algo EQUI200_9 \
  --pool stratum+tcp://zec.f2pool.com:3357 \
  --user wallet.worker \
  --pass x
```

**V2 Configuration:**
```bash
lolMiner --algo EQUI200_9 \
  --pool stratum2+tcp://pool.example.com:3335 \
  --user wallet.worker \
  --sv2-pubkey a1b2c3d4...
```

### miniZ Example

**V1:**
```bash
miniZ --url wallet.worker@pool:3357 --par 200,9
```

**V2:**
```bash
miniZ --url-sv2 wallet.worker@pool:3335 --par 200,9 --sv2-key <pubkey>
```

## Compatibility Considerations

### ASIC Miners

Most Zcash ASICs (Antminer Z15, Innosilicon A9) have firmware-level Stratum V1 support. Options:

1. **Firmware update**: Manufacturers release SV2 firmware
2. **Translation proxy**: Run proxy that accepts V1 from ASIC, speaks V2 to pool
3. **Hybrid mode**: Pool supports both V1 and V2

### Translation Proxy

For miners that can't upgrade:

```
ASIC (V1) ──▶ Translation Proxy ──▶ Pool (V2)
```

```rust
// Proxy pseudocode
fn handle_v1_submit(v1_msg: V1Submit) -> V2Submit {
    V2Submit {
        channel_id: channel_map[&v1_msg.worker],
        job_id: job_map[&v1_msg.job_id],
        nonce: decode_nonce(&v1_msg.nonce2),
        solution: hex::decode(&v1_msg.solution)?,
    }
}
```

## Feature Comparison Matrix

| Feature | V1 Support | V2 Support | Migration Effort |
|---------|------------|------------|------------------|
| Basic mining | Yes | Yes | Low |
| Encryption | No | Yes (Noise) | Medium |
| Vardiff | Yes | Yes | Low |
| Session resumption | Yes | Yes | Low |
| Job Declaration | No | Yes | N/A (new feature) |
| Full-Template | No | Yes | N/A (new feature) |
| Binary encoding | No | Yes | Medium |

## Testing Your Migration

### Compatibility Test

```bash
# Start test pool with both endpoints
cargo run --example dual_stack_pool

# Test V1 connection
nheqminer -l 127.0.0.1:3333 -u test.worker

# Test V2 connection
cargo run --example sv2_test_miner -- --pool 127.0.0.1:3335
```

### Performance Benchmark

Compare bandwidth and latency:

```bash
# V1 bandwidth (JSON)
tcpdump -i eth0 port 3333 -w v1.pcap
# Analyze: typically 200-500 bytes per job notification

# V2 bandwidth (binary)
tcpdump -i eth0 port 3335 -w v2.pcap
# Analyze: typically 100-200 bytes per job notification
```

## Timeline Recommendations

| Phase | Duration | Goals |
|-------|----------|-------|
| Development | 2-3 months | Implement V2 support |
| Testing | 1-2 months | Compatibility testing |
| Soft launch | 1-2 months | V2 endpoint available, V1 default |
| Promotion | 3-6 months | Encourage V2 adoption |
| Deprecation | 6+ months | V1 sunset announcement |

## Resources

- [ZIP 301: Zcash Stratum Protocol](https://zips.z.cash/zip-0301) - Current V1 specification
- [Stratum V2 Specification](https://stratumprotocol.org/) - V2 protocol reference
- [lolMiner Releases](https://github.com/Lolliedieb/lolMiner-releases) - Example mining software
- [F2Pool Mining Guide](https://f2pool.io/mining/guides/how-to-mine-zcash/) - Pool configuration example

## Support

For migration assistance:
- GitHub Issues: https://github.com/iqlusioninc/stratum-zcash/issues
- Zcash Forum: https://forum.zcashcommunity.com/

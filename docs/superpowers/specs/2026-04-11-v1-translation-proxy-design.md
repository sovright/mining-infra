# Stratum V1 Translation Proxy Design

## Overview

A new crate (`crates/bedrock-v1-proxy/`) that translates between Stratum V1 (JSON-RPC / ZIP 301) and Bedrock's Stratum V2 binary protocol. This enables existing Zcash ASICs (Antminer Z15, Innosilicon A9++, etc.) to mine against the Bedrock pool without firmware changes.

## Design Decisions

| Decision | Choice | Rationale |
|----------|--------|-----------|
| Location | New crate in bedrock workspace | Reuses `zcash-mining-protocol` V2 codec directly |
| Deployment | Pool-side or miner-side | Same binary works in either position |
| Validation | Dumb translator (no Equihash check) | Pool validates; keeps proxy simple and low-memory |
| V1 dialect | Broad compatibility | Accept both `set_target` and `set_difficulty`, lenient hex parsing |
| Multiplexing | One V2 connection per V1 miner | Pool assigns channel on TCP connect; no channel mux protocol exists yet |
| Architecture | Actor-per-miner with dedicated V2 connections | Clean ownership, no shared mutable state, matches pool's 1-connection-per-session model |

## Architecture

```
ASIC1 ──V1 JSON-RPC──► [MinerSession task] ──V2 binary──► Pool (conn 1)
ASIC2 ──V1 JSON-RPC──► [MinerSession task] ──V2 binary──► Pool (conn 2)
ASIC3 ──V1 JSON-RPC──► [MinerSession task] ──V2 binary──► Pool (conn 3)
```

Each V1 ASIC gets its own V2 TCP connection to the pool. The pool server assigns a channel and nonce_1 immediately on TCP connect (no SetupConnection/OpenChannel handshake exists in the current protocol). This 1:1 mapping matches the pool's session model directly.

- **MinerSession**: One Tokio task per V1 ASIC connection. Owns both the V1 downstream and V2 upstream connections. Handles the V1 JSON-RPC lifecycle, translates messages, maintains per-miner state.
- **translate**: Pure functions for V1/V2 field conversion (hex/bytes, endianness, nonce mapping).

Future optimization: if the pool adds SetupConnection/OpenChannel support, the proxy can be updated to multiplex channels on a shared V2 connection.

## Crate Structure

```
crates/bedrock-v1-proxy/
├── Cargo.toml
├── src/
│   ├── main.rs         # CLI entrypoint, config loading, startup
│   ├── config.rs       # ProxyConfig (listen addr, upstream addr, timeouts)
│   ├── v1/
│   │   ├── mod.rs
│   │   ├── codec.rs    # JSON-RPC line codec (newline-delimited JSON)
│   │   └── messages.rs # V1 message types (Subscribe, Authorize, Notify, Submit, etc.)
│   ├── session.rs      # MinerSession actor (owns both V1 downstream and V2 upstream)
│   └── translate.rs    # V1<->V2 field conversion
```

### Dependencies

From workspace: `zcash-mining-protocol` (V2 codec and message types).

External: `tokio` (async runtime), `serde`/`serde_json` (V1 JSON), `tracing` (logging), `clap` (CLI).

## MinerSession Actor

One per V1 ASIC connection. Owns both the V1 downstream (ASIC) and V2 upstream (pool) connections.

### State Machine

```
Connected -> Subscribed (V2 upstream opened) -> Authorized -> Mining
                                                               ^ (receives jobs, submits shares)
```

### State

```rust
struct MinerSession {
    v1_stream: Framed<TcpStream, LinesCodec>,   // V1 ASIC connection
    v2_stream: Framed<TcpStream, V2Codec>,       // V2 pool connection (1:1)
    worker_name: Option<String>,
    channel_id: u32,                              // assigned by pool on V2 connect
    nonce_1: Vec<u8>,                             // assigned by pool on V2 connect
    job_map: HashMap<String, u32>,                // V1 job_id (string) -> V2 job_id (u32)
    current_target: [u8; 32],
    next_sequence: u32,                           // V2 share sequence counter
    pending_shares: HashMap<u32, serde_json::Value>, // V2 sequence -> V1 request id
}
```

### Lifecycle

On `mining.subscribe`, the session opens a new V2 TCP connection to the pool. The pool assigns `channel_id` and `nonce_1` immediately. The session then runs a select loop reading from both the V1 stream and V2 stream concurrently.

### V1 Method Handling

**`mining.subscribe`**: Open V2 TCP connection to pool. Pool assigns channel_id + nonce_1 on connect. Respond with `[["mining.notify", "session_id"], "nonce_1_hex"]`.

**`mining.authorize`**: Store worker name. Respond `true`. (No real auth -- pool handles identity via channel.)

**`mining.extranonce.subscribe`**: Respond `true`. If the V2 upstream reconnects and gets a new nonce_1, send `mining.set_extranonce` to the ASIC with the updated nonce_1 hex and size.

**`mining.submit`**: Parse hex `nonce_2` and `solution`, hex `ntime` to u32. Solution may be 1344 bytes (raw) or 1347 bytes (with compactSize prefix `fd 40 05`); strip the prefix if present. Translate to `SubmitEquihashShare`, send on V2 stream, store V1 request id keyed by V2 sequence number.

**V2 `NewEquihashJob` -> V1 `mining.notify`**: Convert fields: job_id u32 to string, **version u32 to hex** (second param per ZIP 301), reverse hashes to big-endian hex, encode time/bits as hex strings.

**V2 `SetTarget` -> V1 `mining.set_target` / `mining.set_difficulty`**: Send both forms to the ASIC. `set_target` uses big-endian hex. `set_difficulty` uses a float computed from target.

**V2 `SubmitSharesResponse`**: Match sequence number to pending V1 request id. Respond `true`/`false` with error string if rejected.

### V2 Upstream Reconnection

If the V2 connection drops, the session reconnects with exponential backoff (1s, 2s, 4s... capped at 60s). On reconnect, the pool assigns a new channel_id and nonce_1. The session sends `mining.set_extranonce` to the ASIC with the new nonce_1 and clears the job_map. The V1 connection stays alive throughout.

### V1 Dialect Tolerance

- Accept hex with or without `0x` prefix
- Case-insensitive hex parsing
- Accept both `mining.set_target` and `mining.set_difficulty` subscriptions
- Handle `mining.extranonce.subscribe` (respond true, send updates on reconnect)
- Respond to unknown methods with JSON-RPC error (not disconnect)
- Don't disconnect on malformed JSON -- send error, keep connection alive

## Translation Layer

Pure functions in `translate.rs`. No state.

### Hex/Bytes

- `hex_to_bytes(s: &str) -> Result<Vec<u8>>` -- strips optional `0x`, case-insensitive
- `bytes_to_hex(b: &[u8]) -> String` -- lowercase, no prefix

### Endianness

- `reverse_hash(h: &[u8; 32]) -> [u8; 32]` -- V1 uses big-endian hex for hashes, V2 uses little-endian bytes. Applied to `prev_hash`, `merkle_root`, `block_commitments`, `target`.

### Job Translation (V2 -> V1)

`NewEquihashJob` -> `mining.notify` params (ZIP 301 order):
- `job_id`: u32 -> decimal string
- `version`: u32 -> hex string (second param per ZIP 301)
- `prev_hash`: reverse bytes -> hex
- `merkle_root`: reverse bytes -> hex
- `block_commitments`: reverse bytes -> hex (the "reserved" field in V1)
- `time`: u32 -> hex string
- `bits`: u32 -> hex string
- `clean_jobs`: bool

### Share Translation (V1 -> V2)

`mining.submit` params -> `SubmitEquihashShare`:
- `nonce_2`: hex string -> bytes (direct decode, no byte reversal -- nonce bytes are position-dependent, not integer-endian)
- `solution`: hex string -> bytes. Accept both 1344 bytes (raw Equihash solution) and 1347 bytes (with compactSize prefix `fd 40 05`). If 1347 bytes and starts with `fd 40 05`, strip the 3-byte prefix.
- `ntime`: hex string -> u32

### Difficulty Conversion

- `target_to_difficulty(target: &[u8; 32]) -> f64` -- for `mining.set_difficulty`
- `difficulty_to_target(diff: f64) -> [u8; 32]` -- if needed

## Configuration

```toml
# bedrock-v1-proxy.toml

[proxy]
listen = "0.0.0.0:3334"
upstream = "127.0.0.1:3333"

[proxy.timeouts]
upstream_connect = 10
upstream_reconnect_max = 60
miner_idle = 600

[metrics]
enabled = true
listen = "0.0.0.0:9334"

[logging]
level = "info"
```

CLI args override config file: `bedrock-v1-proxy --listen 0.0.0.0:3334 --upstream 127.0.0.1:3333`

No TLS/Noise on the V1 side (protocol doesn't support it). V2 upstream uses plaintext initially; Noise support is a later enhancement.

## Error Handling

**Stale job submission**: Proxy checks `job_map`. Unknown job_id gets an immediate `{"result": false, "error": "Stale job"}` without forwarding to pool.

**V2 upstream disconnect**: Per-session exponential backoff reconnection (1s to 60s cap). On reconnect, pool assigns new channel_id + nonce_1. Session sends `mining.set_extranonce` to ASIC and clears job_map. V1 connection stays alive; shares submitted during reconnection get error response.

**Malformed V1 JSON**: JSON-RPC error response, keep connection alive. ASICs sometimes send garbage on startup.

**ASIC disconnect**: Close V2 upstream connection, clean up MinerSession. Log with worker_name.

**Graceful shutdown**: SIGTERM/SIGINT -> stop accepting new V1 connections, drain in-flight shares (5s timeout), close V2 upstream, exit.

## Test Miner V1 Mode

Add `--v1` flag to existing `zcash-test-miner` crate. When set, the test miner connects using V1 JSON-RPC instead of V2 binary.

**Changes:**
- New `v1_client` module alongside existing V2 connection code
- Reuses the same Equihash solver logic
- Sends `mining.subscribe` + `mining.authorize`, receives `mining.notify`, submits via `mining.submit`
- Handles both `mining.set_target` and `mining.set_difficulty`

**End-to-end test path:**
```
zcash-test-miner --v1 --pool 127.0.0.1:3334
    -> bedrock-v1-proxy (3334 -> 3333)
        -> zcash-pool-server (3333)
```

This validates the full translation path with real Equihash solutions.

## Protocol Reference

### V1 Message Format (JSON-RPC over TCP, newline-delimited)

```
mining.subscribe:    {"id":1,"method":"mining.subscribe","params":["agent/ver",null,"host",port]}
  response:          {"id":1,"result":[["mining.notify","session"],"nonce1_hex"],"error":null}

mining.authorize:    {"id":2,"method":"mining.authorize","params":["wallet.worker","pass"]}
  response:          {"id":2,"result":true,"error":null}

mining.notify:       {"id":null,"method":"mining.notify","params":["job_id","version_hex","prev_hash_hex","merkle_root_hex","reserved_hex","time_hex","bits_hex",clean_jobs]}

mining.set_target:   {"id":null,"method":"mining.set_target","params":["target_hex"]}

mining.set_difficulty: {"id":null,"method":"mining.set_difficulty","params":[difficulty_float]}

mining.submit:       {"id":N,"method":"mining.submit","params":["wallet.worker","job_id","ntime_hex","nonce2_hex","solution_hex"]}
  response:          {"id":N,"result":true,"error":null}  or  {"id":N,"result":false,"error":"reason"}
```

### V2 Message Format (Binary, 6-byte header)

```
Header: extension_type(u16 LE) | msg_type(u8) | payload_len(u24 LE)

0x20 NewEquihashJob:      channel_id(u32) job_id(u32) future_job(u8) version(u32) prev_hash(32B) merkle_root(32B) block_commitments(32B) nonce_1_len(u8) nonce_1(var) nonce_2_len(u8) time(u32) bits(u32) target(32B) clean_jobs(u8)
0x21 SubmitEquihashShare: channel_id(u32) sequence(u32) job_id(u32) nonce_2_len(u8) nonce_2(var) time(u32) solution(1344B)
0x22 SubmitSharesResponse: channel_id(u32) sequence(u32) result(u8) [reason(u8) [reason_text(var)]]
0x23 SetTarget:           channel_id(u32) target(32B)
```

### Nonce Mapping

Both V1 and V2 use a 32-byte nonce split into pool-assigned prefix (nonce_1) and miner-iterated suffix (nonce_2). The proxy passes nonce_1 through directly (bytes <-> hex). No proxy-level nonce management.

Nonce bytes are position-dependent (not an integer), so no endianness reversal is applied. `nonce_2` hex from V1 is decoded to bytes directly and sent as-is in V2.

### Hash Endianness

V1 hashes are big-endian hex strings. V2 hashes are little-endian bytes. The proxy reverses byte order when translating `prev_hash`, `merkle_root`, `block_commitments`, and `target`.

### Solution Encoding

V1 solutions are hex-encoded. Some ASIC firmware includes a compactSize length prefix (3 bytes: `fd 40 05` for 1344), others send raw 1344 bytes. The proxy accepts both: if the decoded bytes are 1347 and start with `fd 40 05`, strip the prefix before forwarding to V2.

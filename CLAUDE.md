# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Stratum V2 for Zcash - a decentralized mining pool protocol implementation that enables miners to control transaction selection in blocks. Adapted from Bitcoin's SV2 to handle Zcash's Equihash (200,9) consensus with its 1,344-byte solutions and 32-byte nonces.

## Build Commands

```bash
cargo build --release           # Build all crates
cargo build -p zcash-pool-server  # Build specific crate
cargo check                      # Fast type checking
cargo test                       # Run all tests
cargo test --test codec_tests    # Run specific test file
cargo test -p zcash-mining-protocol  # Test specific crate
cargo clippy                     # Lint checks
```

## Running Examples

```bash
# Fetch template from Zebra node (requires Zebra on port 8232)
cargo run --example fetch_template -p zcash-template-provider

# Validate Equihash share
cargo run --example validate_share -p zcash-equihash-validator

# Run pool server (requires Zebra node)
cargo run --example run_pool -p zcash-pool-server
```

## Architecture

### Crate Dependency Graph

```
zcash-pool-server (main orchestrator)
├── zcash-template-provider     # Fetches templates from Zebra RPC
├── zcash-mining-protocol       # Binary message types (NewEquihashJob, SubmitEquihashShare)
├── zcash-equihash-validator    # Share validation + vardiff algorithm
├── zcash-pool-common           # Shared types (PayoutTracker)
├── zcash-jd-server             # Job Declaration Server (miner-controlled templates)
├── sovright-noise              # Noise_NK encryption
├── sovright-telemetry          # Prometheus metrics, tracing
├── sovright-relay              # Compact block relay
└── sovright-relay-sidecar      # Relay sidecar binary (relay-sidecar)

zcash-jd-client (standalone binary)
├── zcash-template-provider
├── zcash-mining-protocol
└── local Zebra node
```

### Data Flow

1. **TemplateProvider** polls Zebra's `getblocktemplate` RPC
2. **JobDistributor** creates `NewEquihashJob` messages from templates
3. Miners receive jobs, compute Equihash solutions, submit shares
4. **ShareProcessor** validates solutions using **EquihashValidator**
5. **VardiffController** adjusts per-miner difficulty targeting ~5 shares/min
6. **PayoutTracker** records PPS contributions
7. Found blocks announced to the **relay network** (`RelayHandle`) then submitted to Zebra

### Key Zcash-Specific Details

- **32-byte nonce** split: `NONCE_1` (pool prefix) + `NONCE_2` (miner suffix)
- **1,344-byte solutions** (512 indices × 21 bits, packed)
- **140-byte Equihash input header** (not 80 bytes like Bitcoin)
- **hashBlockCommitments** field required for NU5+ blocks
- Equihash validation requires ~144 MB memory per thread

### Job Declaration Modes

- **Coinbase-Only**: Miner customizes coinbase output, pool provides transactions
- **Full-Template**: Miner selects all transactions (maximum decentralization)

## Key Files

| Path | Purpose |
|------|---------|
| `crates/zcash-pool-server/src/server.rs` | Main PoolServer orchestration |
| `crates/zcash-pool-server/src/session.rs` | Per-miner connection handling |
| `crates/zcash-mining-protocol/src/messages.rs` | Binary protocol messages |
| `crates/zcash-equihash-validator/src/lib.rs` | Solution validation |
| `crates/zcash-equihash-validator/src/vardiff.rs` | Adaptive difficulty |
| `crates/zcash-template-provider/src/provider.rs` | Zebra RPC integration |
| `crates/zcash-jd-server/src/server.rs` | Job Declaration Server |
| `crates/zcash-pool-server/src/relay.rs` | Relay integration (`RelayHandle`, `relay` feature) |

## Configuration

Pool server config fields:
- `listen_addr`: TCP bind address (default 0.0.0.0:3333)
- `zebra_url`: Zebra RPC endpoint (default http://127.0.0.1:8232)
- `nonce_1_len`: Pool nonce prefix length (typically 4-8 bytes)
- `initial_difficulty`: Starting share difficulty
- `target_shares_per_minute`: Vardiff target (default 5.0)
- `jd_listen_addr`: Optional Job Declaration port (3334)
- `relay_*`: Optional relay settings (`relay_enabled`, `relay_peers`, `relay_bind_addr`, `relay_auth_key`, `relay_data_shards`, `relay_parity_shards`)
- `noise_*`: Optional Noise encryption keypair

## External Dependencies

- **Zebra node**: Required for `getblocktemplate` RPC (port 8232 mainnet)
- **equihash** crate: Core Equihash algorithm implementation

## Documentation

- `docs/stratum-v2-planning.md` - Technical design and rationale
- `docs/plans/` - Implementation phase plans (1-6)
- `docs/integration/` - Operator and miner guides

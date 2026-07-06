# zcash-pool-server

Stratum V2 pool server for Zcash Equihash mining.

## Overview

This crate provides a basic pool server that:

- Accepts miner connections over TCP (port 3333)
- Distributes Equihash mining jobs from Zebra templates
- Validates submitted shares using Equihash (200,9)
- Tracks contributions for PPS payout
- Supports per-miner adaptive difficulty (vardiff)

## Architecture

```
                               +------------------+
                               |     Template     |
                               |     Provider     |
                               +--------+---------+
                                        |
                                        v
+----------------+            +------------------+            +------------------+
|    Listener    |----------->|      Session     |<---------->|       Job        |
|   (TCP:3333)   |            |      Manager     |            |   Distributor    |
+----------------+            +--------+---------+            +------------------+
                                       |
                                       v
                              +------------------+
                              |      Share       |
                              |    Processor     |
                              +------------------+
```

## Usage

```rust
use zcash_pool_server::{PoolConfig, PoolServer};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = PoolConfig {
        listen_addr: "0.0.0.0:3333".parse()?,
        zebra_url: "http://127.0.0.1:8232".to_string(),
        ..Default::default()
    };

    let server = PoolServer::new(config)?;
    server.run().await?;
    Ok(())
}
```

## Configuration

| Option | Default | Description |
|--------|---------|-------------|
| `listen_addr` | `0.0.0.0:3333` | TCP address for miner connections |
| `zebra_url` | `http://127.0.0.1:8232` | Zebra RPC endpoint |
| `nonce_1_len` | 4 | Pool nonce prefix length (bytes) |
| `initial_difficulty` | 1.0 | Starting share difficulty |
| `target_shares_per_minute` | 5.0 | Vardiff target rate |
| `payout_state_path` | `payout-state.json` | Durable PPS payout state file |
| `validation_threads` | 4 | Threads for Equihash validation |
| `max_connections` | 10000 | Maximum concurrent miners |

## Requirements

- Running Zebra node with RPC enabled
- Rust 1.75+

## Phase 3 Limitations

This is an MVP implementation. Not yet included:

- Block submission to Zebra
- Persistent payout tracking (database)
- SetTarget message encoding
- Full SV2 handshake
- TLS/Noise encryption

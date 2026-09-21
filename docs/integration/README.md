# Zcash Stratum V2 Integration Guide

> **Mode availability:** Full-Template JD is unavailable pending consensus-version payout authorization and commitment validation. FullTemplate guides describe a planned protocol; enabling the server flag is rejected. See [mode status](./full-template-mode.md).

This documentation covers how to integrate Zcash Stratum V2 into your mining infrastructure.

## What is Stratum V2?

Stratum V2 is the next-generation mining protocol that replaces Stratum V1 with significant improvements:

| Feature | Stratum V1 | Stratum V2 |
|---------|-----------|------------|
| Encryption | None (plaintext) | Noise Protocol (ChaCha20-Poly1305) |
| Data format | JSON | Binary (compact, efficient) |
| Job Declaration | Pool-only | Miner can declare custom jobs |
| Transaction Selection | Pool-only | Miner can select transactions |
| Bandwidth | High | ~50% reduction |
| Man-in-middle attacks | Vulnerable | Protected |

## Architecture Overview

```
                                    ┌─────────────────────────────────────┐
                                    │         Zebra Node (RPC)            │
                                    │       http://127.0.0.1:8232         │
                                    └──────────────┬──────────────────────┘
                                                   │
                    ┌──────────────────────────────┼──────────────────────────────┐
                    │                              │                              │
                    ▼                              ▼                              ▼
        ┌───────────────────┐         ┌───────────────────┐         ┌───────────────────┐
        │  Template Provider│         │    Pool Server    │         │    JD Client      │
        │  (fetches blocks) │         │   (port 3333)     │         │ (decentralized)   │
        └─────────┬─────────┘         └─────────┬─────────┘         └─────────┬─────────┘
                  │                             │                             │
                  │                             │                             │
                  ▼                             ▼                             ▼
        ┌───────────────────┐         ┌───────────────────┐         ┌───────────────────┐
        │   Mining Jobs     │◀────────│   JD Server       │◀────────│  Custom Templates │
        │  (Equihash 200,9) │         │   (port 3334)     │         │ (tx selection)    │
        └───────────────────┘         └───────────────────┘         └───────────────────┘
                                               │
                                               ▼
                                      ┌───────────────────┐
                                      │     Miners        │
                                      │  (ASIC/GPU/CPU)   │
                                      └───────────────────┘
```

## Documentation Index

### For Pool Operators

- **[Pool Operator Guide](./pool-operator-guide.md)** - Setting up and running a Stratum V2 pool
- **[JD Server Configuration](./jd-server-config.md)** - Configuring Job Declaration for your pool
- **[Security Configuration](./security-guide.md)** - Noise encryption and security hardening

### For Miners

- **[Miner Quick Start](./miner-quickstart.md)** - Connect to a Stratum V2 pool in 5 minutes
- **[Mining Software Integration](./mining-software-integration.md)** - Integrating SV2 into mining software
- **[Protocol Reference](./protocol-reference.md)** - Complete message format documentation

### For Decentralized Mining

- **[JD Client Guide](./jd-client-guide.md)** - Run your own template construction
- **[Full-Template Mode](./full-template-mode.md)** - Transaction selection and censorship resistance
- **[Solo Mining Setup](./solo-mining.md)** - Mining directly to Zebra

### Migration

- **[Stratum V1 Migration](./migration-from-v1.md)** - Upgrading from Stratum V1

## Quick Start

### Pool Operators

```bash
# Build the pool server
cargo build --release -p zcash-pool-server

# Generate Noise keypair
cargo run --release -p zcash-pool-server --example generate_keys

# Run the pool (requires Zebra node)
cargo run --release -p zcash-pool-server --example run_pool -- \
  --zebra-url http://127.0.0.1:8232 \
  --listen 0.0.0.0:3333 \
  --noise-key <private_key_hex>
```

### Miners

```bash
# Connect mining software to pool
# Your mining software needs SV2 support for Zcash Equihash (200,9)

# Example connection string:
stratum+tcp://pool.example.com:3333
# With Noise encryption:
stratum+noise://pool.example.com:3333?pubkey=<pool_public_key>
```

### Decentralized Mining (JD Client)

```bash
# Build the JD Client
cargo build --release -p zcash-jd-client

# Run with your own Zebra node
cargo run --release -p zcash-jd-client -- \
  --zebra-url http://127.0.0.1:8232 \
  --pool-jd-addr pool.example.com:3334 \
  --user-id my-miner \
  --full-template \
  --tx-selection all
```

## Key Concepts

### Mining Modes

| Mode | Description | Use Case |
|------|-------------|----------|
| **Standard Pool Mining** | Pool provides jobs, miner submits shares | Most miners |
| **Coinbase-Only (JD)** | Miner customizes coinbase, pool provides txs | Payout customization |
| **Full-Template (JD)** | Miner selects transactions | Censorship resistance |

### Nonce Structure

Zcash Equihash uses a 32-byte nonce split between pool and miner:

```
|<---- NONCE_1 (pool) ---->|<---- NONCE_2 (miner) ---->|
|        4 bytes           |         28 bytes          |
```

- **NONCE_1**: Assigned by pool, unique per miner session
- **NONCE_2**: Miner iterates through this space

### Difficulty

Share difficulty is adaptive (vardiff) targeting ~5 shares/minute per miner:

- `initial_difficulty`: Starting difficulty (typically 1.0)
- `min_difficulty`: Floor (0.001)
- `max_difficulty`: Ceiling (network difficulty)

## Network Requirements

| Component | Port | Protocol | Direction |
|-----------|------|----------|-----------|
| Pool Server | 3333 | TCP (SV2) | Inbound from miners |
| JD Server | 3334 | TCP (SV2) | Inbound from JD clients |
| Zebra RPC | 8232 | HTTP | Outbound to node |

## Support

- GitHub Issues: https://github.com/iqlusioninc/stratum-zcash/issues
- Zcash Forum: https://forum.zcashcommunity.com/

## License

MIT OR Apache-2.0

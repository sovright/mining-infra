<p align="center">
  <img src="../../assets/brand/sovright-relay-sidecar-logo.svg" alt="Sovright Relay Sidecar" width="180">
</p>

# Sovright Relay Sidecar

> Formerly `fiber-sidecar`.

A standalone sidecar binary that enables Stratum V1 mining pools to use sovright-relay for low-latency block relay.

## Overview

The relay sidecar:
- Polls Zebra for new block templates
- Builds compact blocks when templates change
- Announces compact blocks to the Sovright relay network
- Optionally receives relay-reconstructed compact blocks in dry-run mode
- Submits eligible relay-received blocks to Zebra only when explicitly enabled

This allows any V1 pool (NOMP, etc.) to benefit from compact block relay without modification.

## Usage

### Command Line

```bash
sovright-relay-sidecar \
    --zebra-url http://127.0.0.1:8232 \
    --relay-peer relay.example.com:8333 \
    --auth-key 0123456789abcdef... \
    --poll-interval-ms 100
```

### Configuration File

```bash
sovright-relay-sidecar --config config.toml
```

See `config.example.toml` for all options.

### Relay Receive Safety

Relay receive is disabled by default. To observe relay-received blocks without
submitting them, enable dry-run receive:

```bash
sovright-relay-sidecar \
    --zebra-url http://127.0.0.1:8232 \
    --relay-peer relay.example.com:8333 \
    --auth-key 0123456789abcdef... \
    --receive-relay-blocks \
    --disable-template-announcements
```

`--enable-submitblock` requires `--receive-relay-blocks` and should remain off
until mainnet cutover signoff. The sidecar only submits compact blocks that
contain all transactions as contiguous prefilled transactions; header-only or
short-ID-only compact blocks are rejected as non-submit candidates.
`--disable-template-announcements` is useful while the local Zebra node is not
at tip because it prevents stale template broadcasts while keeping relay receive
telemetry alive.

Relay FEC settings must match the relay nodes and any P2P ingress bridge in the
same canary path. The defaults are `data_shards = 10` and `parity_shards = 3`;
larger canary profiles can be set in `config.example.toml` or with
`--data-shards` and `--parity-shards`.

## Architecture

```
STRATUM V1 POOL (unmodified)
        │
        ▼ getblocktemplate/submitblock
    ZEBRA NODE ◄──────────────────────┐
        │                             │
        │ poll templates              │ guarded submitblock, disabled by default
        ▼                             │
   RELAY SIDECAR ─────────────────────┘
        │
        ▼ UDP/FEC
   SOVRIGHT RELAY NETWORK
```

## Requirements

- Zebra node with JSON-RPC enabled
- Network connectivity to Sovright relay nodes

## Building

```bash
cargo build --release -p sovright-relay-sidecar
```

Binary will be at `target/release/sovright-relay-sidecar`.

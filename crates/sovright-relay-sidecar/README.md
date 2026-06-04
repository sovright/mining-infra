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

This allows any V1 pool (NOMP, etc.) to benefit from compact block relay without modification.

## Usage

### Command Line

```bash
relay-sidecar \
    --zebra-url http://127.0.0.1:8232 \
    --relay-peer relay.example.com:8333 \
    --auth-key 0123456789abcdef... \
    --poll-interval-ms 100
```

### Configuration File

```bash
relay-sidecar --config config.toml
```

See `config.example.toml` for all options.

## Architecture

```
STRATUM V1 POOL (unmodified)
        │
        ▼ getblocktemplate/submitblock
    ZEBRA NODE ◄──────────────────────┐
        │                             │
        │ poll templates              │ (future: submitblock)
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

Binary will be at `target/release/relay-sidecar`.

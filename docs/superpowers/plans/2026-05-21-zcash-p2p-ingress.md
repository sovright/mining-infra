# Zcash P2P Ingress Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build and deploy an MVP Zcash P2P ingress daemon for Bedrock.

**Architecture:** Add a separate `bedrock-p2p-ingress` crate that owns Zcash P2P peer connections and event logging. It will optionally bridge received block headers into the existing FORGE relay client.

**Tech Stack:** Rust, Tokio TCP, Bedrock FORGE relay client, Zcash ZIP 204 message framing, systemd deployment.

---

### Task 1: P2P Wire Layer

**Files:**
- Create: `crates/bedrock-p2p-ingress/Cargo.toml`
- Create: `crates/bedrock-p2p-ingress/src/error.rs`
- Create: `crates/bedrock-p2p-ingress/src/wire.rs`

- [x] Implement message framing with mainnet magic `24 e9 27 64`, 12-byte command, 4-byte payload length, 4-byte checksum, and payload.
- [x] Implement compact-size encoding/decoding.
- [x] Implement inventory vector parsing for block inventory.
- [x] Add unit tests for framing, checksum rejection, compact size, and inventory parsing.

### Task 2: Peer Session

**Files:**
- Create: `crates/bedrock-p2p-ingress/src/peer.rs`
- Create: `crates/bedrock-p2p-ingress/src/event.rs`
- Create: `crates/bedrock-p2p-ingress/src/config.rs`
- Create: `crates/bedrock-p2p-ingress/src/hash.rs`

- [x] Resolve DNS seeds and connect outbound to peers.
- [x] Send `version`, answer remote `version` with `verack`, and wait for `verack`.
- [x] Answer `ping` with `pong`.
- [x] On block `inv`, log `p2p_block_inv` and request unseen blocks with `getdata`.
- [x] On `block`, compute display hash from the Zcash serialized header and log `p2p_block_received`.

### Task 3: FORGE Bridge

**Files:**
- Create: `crates/bedrock-p2p-ingress/src/forge.rs`
- Create: `crates/bedrock-p2p-ingress/src/main.rs`

- [x] Create an optional FORGE relay bridge when relay peers and auth key are configured.
- [x] Forward header-only compact blocks as experimental relay ingress signals.
- [x] Leave bridge disabled by default.

### Task 4: Verification And Deploy

**Files:**
- Create: `crates/bedrock-p2p-ingress/README.md`
- Create: `/private/tmp/bedrock-mainnet-deployment/infra/systemd/bedrock-p2p-ingress.service`
- Create: `/private/tmp/bedrock-mainnet-deployment/runbooks/zcash-p2p-ingress.md`

- [x] Run `cargo fmt`.
- [x] Run crate tests.
- [x] Install binary and systemd unit on the ops host when gcloud auth is available.
- [x] Verify JSONL events are written.

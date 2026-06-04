# Bedrock-Forge Phase 1: Compact Block Protocol Implementation Plan

> Note: This document was written before the rename from fiber-zcash to bedrock-forge. Some internal references may still use the old name.

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Implement compact block relay for Zcash, enabling bandwidth-efficient block propagation using wtxid-based short transaction IDs.

**Architecture:** A Rust library crate (`bedrock-forge`) that implements compact block construction and reconstruction. The library will be designed for eventual integration with Zebra but developed as a standalone crate first. We follow BIP 152 semantics adapted for Zcash v5 transactions (ZIP 244 txid/wtxid structure).

**Tech Stack:** Rust, Cargo, SHA256 (for short ID calculation), SipHash-2-4 (for collision-resistant short IDs)

---

## Phase 1 Overview

Phase 1 focuses on the compact block protocol - the foundation for bandwidth-efficient block relay. This phase delivers:
1. Transaction identifier types (txid, wtxid, short_id)
2. Compact block message construction
3. Compact block reconstruction from mempool
4. High-bandwidth mode peer management
5. Integration test suite against test vectors

---

## Task 1: Project Scaffolding

**Files:**
- Create: `Cargo.toml`
- Create: `src/lib.rs`
- Create: `.gitignore`

**Step 1: Initialize Cargo project**

```bash
cd /Users/zakimanian/bedrock-forge
cargo init --lib
```

**Step 2: Configure Cargo.toml**

Replace `Cargo.toml` with:

```toml
[package]
name = "bedrock-forge"
version = "0.1.0"
edition = "2021"
description = "Low-latency block relay network for Zcash"
license = "MIT OR Apache-2.0"
repository = "https://github.com/zmanian/bedrock-forge"

[dependencies]
thiserror = "1.0"
hex = "0.4"

[dev-dependencies]
proptest = "1.4"
```

**Step 3: Set up .gitignore**

Create `.gitignore`:

```
/target
Cargo.lock
*.swp
*.swo
.DS_Store
```

**Step 4: Create minimal lib.rs**

Replace `src/lib.rs` with:

```rust
//! Bedrock-Forge: Low-latency block relay network for Zcash
//!
//! This crate implements compact block relay (BIP 152 adapted for Zcash)
//! for bandwidth-efficient block propagation.

pub mod types;

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert!(true);
    }
}
```

**Step 5: Create types module placeholder**

Create `src/types.rs`:

```rust
//! Core types for Zcash transaction and block identifiers
```

**Step 6: Run tests to verify setup**

Run: `cargo test`
Expected: PASS with 1 test passing

**Step 7: Commit**

```bash
git init
git add Cargo.toml src/lib.rs src/types.rs .gitignore
git commit -m "$(cat <<'EOF'
chore: initialize bedrock-forge project

Set up Rust library crate for Zcash compact block relay implementation.

Co-Authored-By: Claude Opus 4.5 <noreply@anthropic.com>
EOF
)"
```

---

## Task 2: Transaction Identifier Types (TxId, WtxId)

**Files:**
- Modify: `src/types.rs`
- Create: `src/types/txid.rs`

**Step 1: Write failing test for TxId**

Add to `src/types.rs`:

```rust
//! Core types for Zcash transaction and block identifiers

mod txid;

pub use txid::{TxId, WtxId, AuthDigest};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn txid_from_bytes() {
        let bytes = [0u8; 32];
        let txid = TxId::from_bytes(bytes);
        assert_eq!(txid.as_bytes(), &bytes);
    }

    #[test]
    fn txid_from_hex() {
        let hex_str = "0000000000000000000000000000000000000000000000000000000000000000";
        let txid = TxId::from_hex(hex_str).unwrap();
        assert_eq!(txid.as_bytes(), &[0u8; 32]);
    }

    #[test]
    fn wtxid_combines_txid_and_auth_digest() {
        let txid = TxId::from_bytes([1u8; 32]);
        let auth = AuthDigest::from_bytes([2u8; 32]);
        let wtxid = WtxId::new(txid, auth);

        assert_eq!(wtxid.txid().as_bytes(), &[1u8; 32]);
        assert_eq!(wtxid.auth_digest().as_bytes(), &[2u8; 32]);
    }
}
```

**Step 2: Run test to verify it fails**

Run: `cargo test`
Expected: FAIL with "cannot find module `txid`"

**Step 3: Write minimal implementation**

Create `src/types/txid.rs`:

```rust
//! Transaction identifier types following ZIP 244
//!
//! ZIP 244 defines two transaction identifiers for v5 transactions:
//! - txid: commits to "effecting data" (transaction effects)
//! - wtxid: concatenates txid with auth_digest for witness commitment

use std::fmt;

/// Transaction ID - 32-byte hash of transaction effecting data (ZIP 244)
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct TxId([u8; 32]);

impl TxId {
    /// Create TxId from raw bytes
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Create TxId from hex string
    pub fn from_hex(s: &str) -> Result<Self, hex::FromHexError> {
        let mut bytes = [0u8; 32];
        hex::decode_to_slice(s, &mut bytes)?;
        Ok(Self(bytes))
    }

    /// Get raw bytes
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Debug for TxId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "TxId({})", hex::encode(self.0))
    }
}

impl fmt::Display for TxId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", hex::encode(self.0))
    }
}

/// Authorization digest - 32-byte hash of transaction authorization data
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct AuthDigest([u8; 32]);

impl AuthDigest {
    /// Create AuthDigest from raw bytes
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Get raw bytes
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Debug for AuthDigest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "AuthDigest({})", hex::encode(self.0))
    }
}

/// Witness Transaction ID - combines txid and auth_digest (ZIP 239)
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct WtxId {
    txid: TxId,
    auth_digest: AuthDigest,
}

impl WtxId {
    /// Create WtxId from txid and auth_digest
    pub fn new(txid: TxId, auth_digest: AuthDigest) -> Self {
        Self { txid, auth_digest }
    }

    /// Get the transaction ID component
    pub fn txid(&self) -> &TxId {
        &self.txid
    }

    /// Get the authorization digest component
    pub fn auth_digest(&self) -> &AuthDigest {
        &self.auth_digest
    }

    /// Serialize to 64-byte array (txid || auth_digest)
    pub fn to_bytes(&self) -> [u8; 64] {
        let mut bytes = [0u8; 64];
        bytes[..32].copy_from_slice(self.txid.as_bytes());
        bytes[32..].copy_from_slice(self.auth_digest.as_bytes());
        bytes
    }
}

impl fmt::Debug for WtxId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "WtxId({:?}, {:?})", self.txid, self.auth_digest)
    }
}
```

**Step 4: Run tests to verify they pass**

Run: `cargo test`
Expected: PASS with all tests passing

**Step 5: Commit**

```bash
git add src/types.rs src/types/txid.rs
git commit -m "$(cat <<'EOF'
feat: add TxId, WtxId, and AuthDigest types

Implement transaction identifier types following ZIP 244/239:
- TxId: 32-byte hash of transaction effecting data
- AuthDigest: 32-byte hash of authorization data
- WtxId: combined identifier for v5 transaction relay

Co-Authored-By: Claude Opus 4.5 <noreply@anthropic.com>
EOF
)"
```

---

## Task 3: Short Transaction ID Type

**Files:**
- Create: `src/types/short_id.rs`
- Modify: `src/types.rs`

**Step 1: Write failing test for ShortId**

Add to `src/types.rs` tests:

```rust
    #[test]
    fn short_id_is_6_bytes() {
        let short_id = ShortId::from_bytes([1, 2, 3, 4, 5, 6]);
        assert_eq!(short_id.as_bytes(), &[1, 2, 3, 4, 5, 6]);
    }

    #[test]
    fn short_id_computes_from_wtxid_with_nonce() {
        // Per BIP 152: short_id = SipHash-2-4(k0, k1, wtxid)[0..6]
        // where k0 = block_header_hash[0..8], k1 = block_header_hash[8..16] XOR nonce
        let wtxid = WtxId::new(
            TxId::from_bytes([0xaa; 32]),
            AuthDigest::from_bytes([0xbb; 32]),
        );
        let header_hash = [0x11; 32];
        let nonce: u64 = 0x1234567890abcdef;

        let short_id = ShortId::compute(&wtxid, &header_hash, nonce);

        // Should produce consistent 6-byte result
        assert_eq!(short_id.as_bytes().len(), 6);

        // Same inputs should produce same output
        let short_id2 = ShortId::compute(&wtxid, &header_hash, nonce);
        assert_eq!(short_id, short_id2);
    }
```

Add to imports in `src/types.rs`:

```rust
mod short_id;
pub use short_id::ShortId;
```

**Step 2: Run test to verify it fails**

Run: `cargo test`
Expected: FAIL with "cannot find module `short_id`"

**Step 3: Add siphasher dependency**

Update `Cargo.toml` dependencies:

```toml
[dependencies]
thiserror = "1.0"
hex = "0.4"
siphasher = "1.0"
```

**Step 4: Write minimal implementation**

Create `src/types/short_id.rs`:

```rust
//! Short transaction ID for compact block relay
//!
//! Per BIP 152, short IDs are 6-byte truncated SipHash values computed from
//! the wtxid using keys derived from the block header hash and a random nonce.

use siphasher::sip::SipHasher24;
use std::hash::Hasher;

use super::WtxId;

/// 6-byte short transaction ID for compact block relay
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct ShortId([u8; 6]);

impl ShortId {
    /// Create ShortId from raw bytes
    pub fn from_bytes(bytes: [u8; 6]) -> Self {
        Self(bytes)
    }

    /// Get raw bytes
    pub fn as_bytes(&self) -> &[u8; 6] {
        &self.0
    }

    /// Compute short ID from wtxid using BIP 152 algorithm
    ///
    /// short_id = SipHash-2-4(k0, k1, wtxid)[0..6]
    /// where:
    ///   k0 = header_hash[0..8] as little-endian u64
    ///   k1 = header_hash[8..16] as little-endian u64 XOR nonce
    pub fn compute(wtxid: &WtxId, header_hash: &[u8; 32], nonce: u64) -> Self {
        let k0 = u64::from_le_bytes(header_hash[0..8].try_into().unwrap());
        let k1 = u64::from_le_bytes(header_hash[8..16].try_into().unwrap()) ^ nonce;

        let mut hasher = SipHasher24::new_with_keys(k0, k1);
        hasher.write(&wtxid.to_bytes());
        let hash = hasher.finish();

        let hash_bytes = hash.to_le_bytes();
        let mut short_id = [0u8; 6];
        short_id.copy_from_slice(&hash_bytes[0..6]);

        Self(short_id)
    }
}
```

**Step 5: Run tests to verify they pass**

Run: `cargo test`
Expected: PASS with all tests passing

**Step 6: Commit**

```bash
git add Cargo.toml src/types.rs src/types/short_id.rs
git commit -m "$(cat <<'EOF'
feat: add ShortId type for compact block relay

Implement 6-byte short transaction IDs per BIP 152:
- SipHash-2-4 based computation
- Keys derived from block header hash and nonce
- Deterministic for same inputs

Co-Authored-By: Claude Opus 4.5 <noreply@anthropic.com>
EOF
)"
```

---

## Task 4: Block Header Hash Type

**Files:**
- Create: `src/types/block.rs`
- Modify: `src/types.rs`

**Step 1: Write failing test for BlockHash**

Add to `src/types.rs` tests:

```rust
    #[test]
    fn block_hash_from_bytes() {
        let bytes = [0xffu8; 32];
        let hash = BlockHash::from_bytes(bytes);
        assert_eq!(hash.as_bytes(), &bytes);
    }

    #[test]
    fn block_hash_from_hex() {
        let hex_str = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";
        let hash = BlockHash::from_hex(hex_str).unwrap();
        assert_eq!(hash.as_bytes(), &[0xff; 32]);
    }
```

Add to imports in `src/types.rs`:

```rust
mod block;
pub use block::BlockHash;
```

**Step 2: Run test to verify it fails**

Run: `cargo test`
Expected: FAIL with "cannot find module `block`"

**Step 3: Write minimal implementation**

Create `src/types/block.rs`:

```rust
//! Block-related types

use std::fmt;

/// Block header hash - 32-byte double-SHA256 of block header
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct BlockHash([u8; 32]);

impl BlockHash {
    /// Create BlockHash from raw bytes
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Create BlockHash from hex string
    pub fn from_hex(s: &str) -> Result<Self, hex::FromHexError> {
        let mut bytes = [0u8; 32];
        hex::decode_to_slice(s, &mut bytes)?;
        Ok(Self(bytes))
    }

    /// Get raw bytes
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Debug for BlockHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "BlockHash({})", hex::encode(self.0))
    }
}

impl fmt::Display for BlockHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", hex::encode(self.0))
    }
}
```

**Step 4: Run tests to verify they pass**

Run: `cargo test`
Expected: PASS with all tests passing

**Step 5: Commit**

```bash
git add src/types.rs src/types/block.rs
git commit -m "$(cat <<'EOF'
feat: add BlockHash type

Implement 32-byte block header hash type with hex conversion utilities.

Co-Authored-By: Claude Opus 4.5 <noreply@anthropic.com>
EOF
)"
```

---

## Task 5: Compact Block Message Structure

**Files:**
- Create: `src/compact_block.rs`
- Modify: `src/lib.rs`

**Step 1: Write failing test for CompactBlock**

Create `src/compact_block.rs`:

```rust
//! Compact block message types for bandwidth-efficient block relay
//!
//! Implements BIP 152 compact block semantics adapted for Zcash.

use crate::types::{BlockHash, ShortId, WtxId};

/// Prefilled transaction in a compact block
#[derive(Clone, Debug)]
pub struct PrefilledTx {
    /// Index in the block (differentially encoded in wire format)
    pub index: u16,
    /// Full transaction data (opaque bytes for now)
    pub tx_data: Vec<u8>,
}

/// Compact block message
#[derive(Clone, Debug)]
pub struct CompactBlock {
    /// Block header (2189 bytes for Zcash including Equihash solution)
    pub header: Vec<u8>,
    /// Random nonce for short ID calculation
    pub nonce: u64,
    /// Short transaction IDs
    pub short_ids: Vec<ShortId>,
    /// Prefilled transactions (always includes coinbase)
    pub prefilled_txs: Vec<PrefilledTx>,
}

impl CompactBlock {
    /// Create a new compact block
    pub fn new(
        header: Vec<u8>,
        nonce: u64,
        short_ids: Vec<ShortId>,
        prefilled_txs: Vec<PrefilledTx>,
    ) -> Self {
        Self {
            header,
            nonce,
            short_ids,
            prefilled_txs,
        }
    }

    /// Get the block header hash for short ID calculation
    ///
    /// Note: In production, this would compute double-SHA256 of header.
    /// For now we require it to be passed in.
    pub fn header_hash(&self) -> BlockHash {
        // Placeholder: compute actual hash in production
        // For Zcash, this is SHA256d of the 2189-byte header
        let mut hash = [0u8; 32];
        if self.header.len() >= 32 {
            hash.copy_from_slice(&self.header[..32]);
        }
        BlockHash::from_bytes(hash)
    }

    /// Total number of transactions in the original block
    pub fn tx_count(&self) -> usize {
        self.short_ids.len() + self.prefilled_txs.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{AuthDigest, TxId};

    #[test]
    fn compact_block_construction() {
        let header = vec![0u8; 2189]; // Zcash header size
        let nonce = 0x123456789abcdef0u64;

        let wtxid = WtxId::new(
            TxId::from_bytes([0xaa; 32]),
            AuthDigest::from_bytes([0xbb; 32]),
        );
        let header_hash = [0u8; 32];
        let short_id = ShortId::compute(&wtxid, &header_hash, nonce);

        let prefilled = PrefilledTx {
            index: 0,
            tx_data: vec![0u8; 100], // Coinbase placeholder
        };

        let compact = CompactBlock::new(
            header,
            nonce,
            vec![short_id],
            vec![prefilled],
        );

        assert_eq!(compact.tx_count(), 2); // 1 short_id + 1 prefilled
        assert_eq!(compact.nonce, nonce);
    }

    #[test]
    fn prefilled_tx_includes_coinbase() {
        let compact = CompactBlock::new(
            vec![0u8; 2189],
            0,
            vec![],
            vec![PrefilledTx { index: 0, tx_data: vec![1, 2, 3] }],
        );

        assert_eq!(compact.prefilled_txs.len(), 1);
        assert_eq!(compact.prefilled_txs[0].index, 0);
    }
}
```

**Step 2: Add module to lib.rs**

Update `src/lib.rs`:

```rust
//! Bedrock-Forge: Low-latency block relay network for Zcash
//!
//! This crate implements compact block relay (BIP 152 adapted for Zcash)
//! for bandwidth-efficient block propagation.

pub mod compact_block;
pub mod types;

pub use compact_block::{CompactBlock, PrefilledTx};
pub use types::{AuthDigest, BlockHash, ShortId, TxId, WtxId};
```

**Step 3: Run tests to verify they pass**

Run: `cargo test`
Expected: PASS with all tests passing

**Step 4: Commit**

```bash
git add src/lib.rs src/compact_block.rs
git commit -m "$(cat <<'EOF'
feat: add CompactBlock and PrefilledTx types

Implement compact block message structure per BIP 152:
- Block header storage (2189 bytes for Zcash)
- Nonce for short ID calculation
- List of short transaction IDs
- Prefilled transactions (including coinbase)

Co-Authored-By: Claude Opus 4.5 <noreply@anthropic.com>
EOF
)"
```

---

## Task 6: Mempool Interface Trait

**Files:**
- Create: `src/mempool.rs`
- Modify: `src/lib.rs`

**Step 1: Write failing test for mempool interface**

Create `src/mempool.rs`:

```rust
//! Mempool interface for compact block reconstruction
//!
//! Defines the trait that mempool implementations must satisfy
//! for compact block reconstruction to work.

use crate::types::WtxId;

/// Error type for mempool operations
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MempoolError {
    /// Transaction not found in mempool
    TransactionNotFound(WtxId),
}

impl std::fmt::Display for MempoolError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MempoolError::TransactionNotFound(wtxid) => {
                write!(f, "transaction not found in mempool: {:?}", wtxid)
            }
        }
    }
}

impl std::error::Error for MempoolError {}

/// Trait for mempool implementations to support compact block reconstruction
pub trait MempoolProvider {
    /// Get all wtxids currently in mempool
    fn get_wtxids(&self) -> Vec<WtxId>;

    /// Get transaction data by wtxid
    fn get_tx_data(&self, wtxid: &WtxId) -> Option<Vec<u8>>;

    /// Check if transaction exists in mempool
    fn contains(&self, wtxid: &WtxId) -> bool {
        self.get_tx_data(wtxid).is_some()
    }
}

/// In-memory mempool implementation for testing
#[derive(Default)]
pub struct TestMempool {
    transactions: std::collections::HashMap<WtxId, Vec<u8>>,
}

impl TestMempool {
    /// Create empty test mempool
    pub fn new() -> Self {
        Self::default()
    }

    /// Add transaction to mempool
    pub fn insert(&mut self, wtxid: WtxId, tx_data: Vec<u8>) {
        self.transactions.insert(wtxid, tx_data);
    }

    /// Number of transactions in mempool
    pub fn len(&self) -> usize {
        self.transactions.len()
    }

    /// Check if mempool is empty
    pub fn is_empty(&self) -> bool {
        self.transactions.is_empty()
    }
}

impl MempoolProvider for TestMempool {
    fn get_wtxids(&self) -> Vec<WtxId> {
        self.transactions.keys().copied().collect()
    }

    fn get_tx_data(&self, wtxid: &WtxId) -> Option<Vec<u8>> {
        self.transactions.get(wtxid).cloned()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{AuthDigest, TxId};

    #[test]
    fn test_mempool_insert_and_retrieve() {
        let mut mempool = TestMempool::new();

        let wtxid = WtxId::new(
            TxId::from_bytes([1u8; 32]),
            AuthDigest::from_bytes([2u8; 32]),
        );
        let tx_data = vec![0xde, 0xad, 0xbe, 0xef];

        mempool.insert(wtxid, tx_data.clone());

        assert!(mempool.contains(&wtxid));
        assert_eq!(mempool.get_tx_data(&wtxid), Some(tx_data));
        assert_eq!(mempool.len(), 1);
    }

    #[test]
    fn test_mempool_get_wtxids() {
        let mut mempool = TestMempool::new();

        let wtxid1 = WtxId::new(
            TxId::from_bytes([1u8; 32]),
            AuthDigest::from_bytes([1u8; 32]),
        );
        let wtxid2 = WtxId::new(
            TxId::from_bytes([2u8; 32]),
            AuthDigest::from_bytes([2u8; 32]),
        );

        mempool.insert(wtxid1, vec![1]);
        mempool.insert(wtxid2, vec![2]);

        let wtxids = mempool.get_wtxids();
        assert_eq!(wtxids.len(), 2);
        assert!(wtxids.contains(&wtxid1));
        assert!(wtxids.contains(&wtxid2));
    }

    #[test]
    fn test_mempool_not_found() {
        let mempool = TestMempool::new();

        let wtxid = WtxId::new(
            TxId::from_bytes([99u8; 32]),
            AuthDigest::from_bytes([99u8; 32]),
        );

        assert!(!mempool.contains(&wtxid));
        assert_eq!(mempool.get_tx_data(&wtxid), None);
    }
}
```

**Step 2: Add module to lib.rs**

Update `src/lib.rs`:

```rust
//! Bedrock-Forge: Low-latency block relay network for Zcash
//!
//! This crate implements compact block relay (BIP 152 adapted for Zcash)
//! for bandwidth-efficient block propagation.

pub mod compact_block;
pub mod mempool;
pub mod types;

pub use compact_block::{CompactBlock, PrefilledTx};
pub use mempool::{MempoolError, MempoolProvider, TestMempool};
pub use types::{AuthDigest, BlockHash, ShortId, TxId, WtxId};
```

**Step 3: Run tests to verify they pass**

Run: `cargo test`
Expected: PASS with all tests passing

**Step 4: Commit**

```bash
git add src/lib.rs src/mempool.rs
git commit -m "$(cat <<'EOF'
feat: add MempoolProvider trait and TestMempool

Define mempool interface for compact block reconstruction:
- MempoolProvider trait for wtxid lookups
- TestMempool implementation for testing
- MempoolError for missing transaction handling

Co-Authored-By: Claude Opus 4.5 <noreply@anthropic.com>
EOF
)"
```

---

## Task 7: Compact Block Builder

**Files:**
- Create: `src/builder.rs`
- Modify: `src/lib.rs`

**Step 1: Write failing test for CompactBlockBuilder**

Create `src/builder.rs`:

```rust
//! Compact block construction from full blocks
//!
//! Builds CompactBlock messages from full block data and mempool state.

use crate::compact_block::{CompactBlock, PrefilledTx};
use crate::mempool::MempoolProvider;
use crate::types::{ShortId, WtxId};

/// Builder for constructing compact blocks
pub struct CompactBlockBuilder {
    header: Vec<u8>,
    nonce: u64,
    /// Transactions with their wtxids, in block order
    transactions: Vec<(WtxId, Vec<u8>)>,
}

impl CompactBlockBuilder {
    /// Create a new builder with block header and nonce
    pub fn new(header: Vec<u8>, nonce: u64) -> Self {
        Self {
            header,
            nonce,
            transactions: Vec::new(),
        }
    }

    /// Add a transaction (in block order, coinbase first)
    pub fn add_transaction(&mut self, wtxid: WtxId, tx_data: Vec<u8>) {
        self.transactions.push((wtxid, tx_data));
    }

    /// Build compact block, prefilling transactions not in peer's mempool
    ///
    /// Always prefills the coinbase transaction (index 0).
    /// Other transactions are prefilled if not in the provided mempool wtxids.
    pub fn build<M: MempoolProvider>(self, peer_mempool: &M) -> CompactBlock {
        let peer_wtxids: std::collections::HashSet<_> =
            peer_mempool.get_wtxids().into_iter().collect();

        let header_hash = self.compute_header_hash();

        let mut short_ids = Vec::new();
        let mut prefilled_txs = Vec::new();
        let mut short_id_index = 0u16;

        for (block_index, (wtxid, tx_data)) in self.transactions.into_iter().enumerate() {
            let is_coinbase = block_index == 0;
            let in_peer_mempool = peer_wtxids.contains(&wtxid);

            if is_coinbase || !in_peer_mempool {
                // Prefill this transaction
                // Index is differentially encoded relative to last short_id position
                prefilled_txs.push(PrefilledTx {
                    index: short_id_index,
                    tx_data,
                });
            } else {
                // Use short ID
                short_ids.push(ShortId::compute(&wtxid, &header_hash, self.nonce));
                short_id_index += 1;
            }
        }

        CompactBlock::new(self.header, self.nonce, short_ids, prefilled_txs)
    }

    /// Compute header hash for short ID calculation
    fn compute_header_hash(&self) -> [u8; 32] {
        // TODO: Implement proper SHA256d
        // For now, use first 32 bytes as placeholder
        let mut hash = [0u8; 32];
        let len = std::cmp::min(32, self.header.len());
        hash[..len].copy_from_slice(&self.header[..len]);
        hash
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mempool::TestMempool;
    use crate::types::{AuthDigest, TxId};

    fn make_wtxid(seed: u8) -> WtxId {
        WtxId::new(
            TxId::from_bytes([seed; 32]),
            AuthDigest::from_bytes([seed; 32]),
        )
    }

    #[test]
    fn builder_always_prefills_coinbase() {
        let mut builder = CompactBlockBuilder::new(vec![0u8; 2189], 12345);

        let coinbase_wtxid = make_wtxid(0);
        builder.add_transaction(coinbase_wtxid, vec![1, 2, 3]);

        // Even if coinbase is "in mempool", it should be prefilled
        let mut mempool = TestMempool::new();
        mempool.insert(coinbase_wtxid, vec![1, 2, 3]);

        let compact = builder.build(&mempool);

        assert_eq!(compact.prefilled_txs.len(), 1);
        assert_eq!(compact.prefilled_txs[0].index, 0);
        assert_eq!(compact.short_ids.len(), 0);
    }

    #[test]
    fn builder_uses_short_ids_for_mempool_txs() {
        let mut builder = CompactBlockBuilder::new(vec![0u8; 2189], 12345);

        let coinbase = make_wtxid(0);
        let tx1 = make_wtxid(1);
        let tx2 = make_wtxid(2);

        builder.add_transaction(coinbase, vec![10]);
        builder.add_transaction(tx1, vec![11]);
        builder.add_transaction(tx2, vec![12]);

        // tx1 is in mempool, tx2 is not
        let mut mempool = TestMempool::new();
        mempool.insert(tx1, vec![11]);

        let compact = builder.build(&mempool);

        // Coinbase + tx2 prefilled, tx1 as short_id
        assert_eq!(compact.prefilled_txs.len(), 2);
        assert_eq!(compact.short_ids.len(), 1);
    }

    #[test]
    fn builder_prefills_missing_txs() {
        let mut builder = CompactBlockBuilder::new(vec![0u8; 2189], 12345);

        let coinbase = make_wtxid(0);
        let tx1 = make_wtxid(1);

        builder.add_transaction(coinbase, vec![10]);
        builder.add_transaction(tx1, vec![11]);

        // Empty mempool - everything should be prefilled
        let mempool = TestMempool::new();

        let compact = builder.build(&mempool);

        assert_eq!(compact.prefilled_txs.len(), 2);
        assert_eq!(compact.short_ids.len(), 0);
    }
}
```

**Step 2: Add module to lib.rs**

Update `src/lib.rs`:

```rust
//! Bedrock-Forge: Low-latency block relay network for Zcash
//!
//! This crate implements compact block relay (BIP 152 adapted for Zcash)
//! for bandwidth-efficient block propagation.

pub mod builder;
pub mod compact_block;
pub mod mempool;
pub mod types;

pub use builder::CompactBlockBuilder;
pub use compact_block::{CompactBlock, PrefilledTx};
pub use mempool::{MempoolError, MempoolProvider, TestMempool};
pub use types::{AuthDigest, BlockHash, ShortId, TxId, WtxId};
```

**Step 3: Run tests to verify they pass**

Run: `cargo test`
Expected: PASS with all tests passing

**Step 4: Commit**

```bash
git add src/lib.rs src/builder.rs
git commit -m "$(cat <<'EOF'
feat: add CompactBlockBuilder for block construction

Implement compact block construction logic:
- Always prefills coinbase transaction
- Uses short IDs for transactions in peer mempool
- Prefills transactions missing from peer mempool

Co-Authored-By: Claude Opus 4.5 <noreply@anthropic.com>
EOF
)"
```

---

## Task 8: Compact Block Reconstructor

**Files:**
- Create: `src/reconstructor.rs`
- Modify: `src/lib.rs`

**Step 1: Write failing test for reconstruction**

Create `src/reconstructor.rs`:

```rust
//! Compact block reconstruction from mempool
//!
//! Reconstructs full blocks from compact block messages using local mempool.

use std::collections::HashMap;

use crate::compact_block::CompactBlock;
use crate::mempool::MempoolProvider;
use crate::types::{ShortId, WtxId};

/// Result of compact block reconstruction
#[derive(Debug)]
pub enum ReconstructionResult {
    /// Successfully reconstructed all transactions
    Complete {
        /// Transactions in block order
        transactions: Vec<Vec<u8>>,
    },
    /// Missing some transactions - need to request them
    Incomplete {
        /// Transactions we have (Some) and missing (None), in block order
        partial: Vec<Option<Vec<u8>>>,
        /// WtxIds of missing transactions (if identifiable)
        missing_wtxids: Vec<WtxId>,
        /// Short IDs we couldn't resolve
        unresolved_short_ids: Vec<ShortId>,
    },
}

/// Reconstructs full blocks from compact block messages
pub struct CompactBlockReconstructor<'a, M: MempoolProvider> {
    mempool: &'a M,
    /// Short ID to wtxid mapping computed from mempool
    short_id_map: HashMap<ShortId, WtxId>,
}

impl<'a, M: MempoolProvider> CompactBlockReconstructor<'a, M> {
    /// Create a new reconstructor with the given mempool
    pub fn new(mempool: &'a M) -> Self {
        Self {
            mempool,
            short_id_map: HashMap::new(),
        }
    }

    /// Precompute short ID mappings for a specific compact block
    pub fn prepare(&mut self, header_hash: &[u8; 32], nonce: u64) {
        self.short_id_map.clear();

        for wtxid in self.mempool.get_wtxids() {
            let short_id = ShortId::compute(&wtxid, header_hash, nonce);
            // Note: collisions overwrite - this is expected per BIP 152
            self.short_id_map.insert(short_id, wtxid);
        }
    }

    /// Attempt to reconstruct a block from a compact block message
    pub fn reconstruct(&self, compact: &CompactBlock) -> ReconstructionResult {
        let total_tx_count = compact.tx_count();
        let mut transactions: Vec<Option<Vec<u8>>> = vec![None; total_tx_count];
        let mut missing_wtxids = Vec::new();
        let mut unresolved_short_ids = Vec::new();

        // First, fill in prefilled transactions
        let mut prefilled_positions: Vec<usize> = Vec::new();
        let mut cumulative_offset = 0usize;

        for prefilled in &compact.prefilled_txs {
            // Differentially decoded index
            let position = cumulative_offset + prefilled.index as usize;
            if position < total_tx_count {
                transactions[position] = Some(prefilled.tx_data.clone());
                prefilled_positions.push(position);
                cumulative_offset = position + 1;
            }
        }

        // Then, resolve short IDs to transactions
        let mut short_id_idx = 0;
        for tx_idx in 0..total_tx_count {
            if transactions[tx_idx].is_some() {
                // Already filled by prefilled
                continue;
            }

            if short_id_idx >= compact.short_ids.len() {
                // This shouldn't happen in a well-formed compact block
                break;
            }

            let short_id = compact.short_ids[short_id_idx];
            short_id_idx += 1;

            if let Some(wtxid) = self.short_id_map.get(&short_id) {
                if let Some(tx_data) = self.mempool.get_tx_data(wtxid) {
                    transactions[tx_idx] = Some(tx_data);
                } else {
                    // In mempool when we computed map, but removed since
                    missing_wtxids.push(*wtxid);
                }
            } else {
                // Short ID not in our mempool
                unresolved_short_ids.push(short_id);
            }
        }

        // Check if reconstruction is complete
        if transactions.iter().all(|t| t.is_some()) {
            ReconstructionResult::Complete {
                transactions: transactions.into_iter().map(|t| t.unwrap()).collect(),
            }
        } else {
            ReconstructionResult::Incomplete {
                partial: transactions,
                missing_wtxids,
                unresolved_short_ids,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::builder::CompactBlockBuilder;
    use crate::mempool::TestMempool;
    use crate::types::{AuthDigest, TxId};

    fn make_wtxid(seed: u8) -> WtxId {
        WtxId::new(
            TxId::from_bytes([seed; 32]),
            AuthDigest::from_bytes([seed; 32]),
        )
    }

    #[test]
    fn reconstruct_complete_block() {
        // Sender side: build compact block
        let header = vec![0u8; 2189];
        let nonce = 12345u64;

        let coinbase = make_wtxid(0);
        let tx1 = make_wtxid(1);
        let tx2 = make_wtxid(2);

        let mut builder = CompactBlockBuilder::new(header.clone(), nonce);
        builder.add_transaction(coinbase, vec![10]);
        builder.add_transaction(tx1, vec![11]);
        builder.add_transaction(tx2, vec![12]);

        // Sender's view of receiver's mempool (has tx1 and tx2)
        let mut sender_view = TestMempool::new();
        sender_view.insert(tx1, vec![11]);
        sender_view.insert(tx2, vec![12]);

        let compact = builder.build(&sender_view);

        // Receiver side: reconstruct
        let mut receiver_mempool = TestMempool::new();
        receiver_mempool.insert(tx1, vec![11]);
        receiver_mempool.insert(tx2, vec![12]);

        let mut reconstructor = CompactBlockReconstructor::new(&receiver_mempool);

        // Use same header hash computation as builder
        let header_hash = {
            let mut h = [0u8; 32];
            h.copy_from_slice(&header[..32]);
            h
        };
        reconstructor.prepare(&header_hash, nonce);

        let result = reconstructor.reconstruct(&compact);

        match result {
            ReconstructionResult::Complete { transactions } => {
                assert_eq!(transactions.len(), 3);
                assert_eq!(transactions[0], vec![10]); // coinbase
                assert_eq!(transactions[1], vec![11]); // tx1
                assert_eq!(transactions[2], vec![12]); // tx2
            }
            ReconstructionResult::Incomplete { .. } => {
                panic!("Expected complete reconstruction");
            }
        }
    }

    #[test]
    fn reconstruct_incomplete_block() {
        let header = vec![0u8; 2189];
        let nonce = 12345u64;

        let coinbase = make_wtxid(0);
        let tx1 = make_wtxid(1);

        let mut builder = CompactBlockBuilder::new(header.clone(), nonce);
        builder.add_transaction(coinbase, vec![10]);
        builder.add_transaction(tx1, vec![11]);

        // Sender thinks receiver has tx1
        let mut sender_view = TestMempool::new();
        sender_view.insert(tx1, vec![11]);

        let compact = builder.build(&sender_view);

        // But receiver's mempool is empty!
        let receiver_mempool = TestMempool::new();

        let mut reconstructor = CompactBlockReconstructor::new(&receiver_mempool);
        let header_hash = {
            let mut h = [0u8; 32];
            h.copy_from_slice(&header[..32]);
            h
        };
        reconstructor.prepare(&header_hash, nonce);

        let result = reconstructor.reconstruct(&compact);

        match result {
            ReconstructionResult::Incomplete { unresolved_short_ids, .. } => {
                assert_eq!(unresolved_short_ids.len(), 1);
            }
            ReconstructionResult::Complete { .. } => {
                panic!("Expected incomplete reconstruction");
            }
        }
    }
}
```

**Step 2: Add module to lib.rs**

Update `src/lib.rs`:

```rust
//! Bedrock-Forge: Low-latency block relay network for Zcash
//!
//! This crate implements compact block relay (BIP 152 adapted for Zcash)
//! for bandwidth-efficient block propagation.

pub mod builder;
pub mod compact_block;
pub mod mempool;
pub mod reconstructor;
pub mod types;

pub use builder::CompactBlockBuilder;
pub use compact_block::{CompactBlock, PrefilledTx};
pub use mempool::{MempoolError, MempoolProvider, TestMempool};
pub use reconstructor::{CompactBlockReconstructor, ReconstructionResult};
pub use types::{AuthDigest, BlockHash, ShortId, TxId, WtxId};
```

**Step 3: Run tests to verify they pass**

Run: `cargo test`
Expected: PASS with all tests passing

**Step 4: Commit**

```bash
git add src/lib.rs src/reconstructor.rs
git commit -m "$(cat <<'EOF'
feat: add CompactBlockReconstructor for block reconstruction

Implement compact block reconstruction from mempool:
- Precomputes short ID to wtxid mappings
- Fills in prefilled transactions
- Resolves short IDs from mempool
- Returns Complete or Incomplete result with missing tx info

Co-Authored-By: Claude Opus 4.5 <noreply@anthropic.com>
EOF
)"
```

---

## Task 9: GetBlockTxn Request/Response Messages

**Files:**
- Create: `src/messages.rs`
- Modify: `src/lib.rs`

**Step 1: Write failing test for messages**

Create `src/messages.rs`:

```rust
//! Network message types for compact block protocol
//!
//! Implements the request/response messages needed for compact block relay.

use crate::types::{BlockHash, ShortId};

/// Request for specific transactions from a block (getblocktxn)
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GetBlockTxn {
    /// Hash of the block containing the transactions
    pub block_hash: BlockHash,
    /// Indices of requested transactions (differentially encoded)
    pub indexes: Vec<u16>,
}

impl GetBlockTxn {
    /// Create a new request
    pub fn new(block_hash: BlockHash, indexes: Vec<u16>) -> Self {
        Self { block_hash, indexes }
    }

    /// Create request for unresolved short IDs after reconstruction failure
    pub fn from_missing_indexes(block_hash: BlockHash, missing: &[usize]) -> Self {
        // Convert absolute indexes to differential encoding
        let mut indexes = Vec::with_capacity(missing.len());
        let mut prev = 0usize;

        for &idx in missing {
            let diff = idx.saturating_sub(prev);
            indexes.push(diff as u16);
            prev = idx + 1;
        }

        Self { block_hash, indexes }
    }
}

/// Response with requested transactions (blocktxn)
#[derive(Clone, Debug)]
pub struct BlockTxn {
    /// Hash of the block
    pub block_hash: BlockHash,
    /// Requested transactions in order
    pub transactions: Vec<Vec<u8>>,
}

impl BlockTxn {
    /// Create a new response
    pub fn new(block_hash: BlockHash, transactions: Vec<Vec<u8>>) -> Self {
        Self {
            block_hash,
            transactions,
        }
    }
}

/// High-bandwidth mode announcement (sendcmpct)
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SendCmpct {
    /// Whether high-bandwidth mode is requested
    pub high_bandwidth: bool,
    /// Protocol version (1 for BIP 152)
    pub version: u64,
}

impl SendCmpct {
    /// Create announcement for high-bandwidth mode
    pub fn high_bandwidth() -> Self {
        Self {
            high_bandwidth: true,
            version: 1,
        }
    }

    /// Create announcement for low-bandwidth mode
    pub fn low_bandwidth() -> Self {
        Self {
            high_bandwidth: false,
            version: 1,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn get_block_txn_creation() {
        let hash = BlockHash::from_bytes([1u8; 32]);
        let indexes = vec![0, 5, 10];

        let msg = GetBlockTxn::new(hash, indexes.clone());

        assert_eq!(msg.block_hash, hash);
        assert_eq!(msg.indexes, indexes);
    }

    #[test]
    fn get_block_txn_from_missing_indexes() {
        let hash = BlockHash::from_bytes([1u8; 32]);
        // Missing transactions at positions 0, 5, 6, 10
        let missing = vec![0, 5, 6, 10];

        let msg = GetBlockTxn::from_missing_indexes(hash, &missing);

        // Differential encoding: 0, 5-1=4, 6-6=0, 10-7=3
        assert_eq!(msg.indexes, vec![0, 4, 0, 3]);
    }

    #[test]
    fn block_txn_creation() {
        let hash = BlockHash::from_bytes([2u8; 32]);
        let txs = vec![vec![1, 2, 3], vec![4, 5, 6]];

        let msg = BlockTxn::new(hash, txs.clone());

        assert_eq!(msg.block_hash, hash);
        assert_eq!(msg.transactions, txs);
    }

    #[test]
    fn send_cmpct_modes() {
        let high = SendCmpct::high_bandwidth();
        assert!(high.high_bandwidth);
        assert_eq!(high.version, 1);

        let low = SendCmpct::low_bandwidth();
        assert!(!low.high_bandwidth);
        assert_eq!(low.version, 1);
    }
}
```

**Step 2: Add module to lib.rs**

Update `src/lib.rs`:

```rust
//! Bedrock-Forge: Low-latency block relay network for Zcash
//!
//! This crate implements compact block relay (BIP 152 adapted for Zcash)
//! for bandwidth-efficient block propagation.

pub mod builder;
pub mod compact_block;
pub mod mempool;
pub mod messages;
pub mod reconstructor;
pub mod types;

pub use builder::CompactBlockBuilder;
pub use compact_block::{CompactBlock, PrefilledTx};
pub use mempool::{MempoolError, MempoolProvider, TestMempool};
pub use messages::{BlockTxn, GetBlockTxn, SendCmpct};
pub use reconstructor::{CompactBlockReconstructor, ReconstructionResult};
pub use types::{AuthDigest, BlockHash, ShortId, TxId, WtxId};
```

**Step 3: Run tests to verify they pass**

Run: `cargo test`
Expected: PASS with all tests passing

**Step 4: Commit**

```bash
git add src/lib.rs src/messages.rs
git commit -m "$(cat <<'EOF'
feat: add GetBlockTxn, BlockTxn, and SendCmpct messages

Implement compact block protocol messages:
- GetBlockTxn: request missing transactions
- BlockTxn: response with transaction data
- SendCmpct: high/low bandwidth mode negotiation

Co-Authored-By: Claude Opus 4.5 <noreply@anthropic.com>
EOF
)"
```

---

## Task 10: Integration Test - Round Trip

**Files:**
- Create: `tests/integration.rs`

**Step 1: Write integration test**

Create `tests/integration.rs`:

```rust
//! Integration tests for compact block round-trip

use bedrock_forge::{
    CompactBlockBuilder, CompactBlockReconstructor, MempoolProvider,
    ReconstructionResult, TestMempool, WtxId, TxId, AuthDigest,
    GetBlockTxn, BlockTxn, BlockHash,
};

fn make_wtxid(seed: u8) -> WtxId {
    WtxId::new(
        TxId::from_bytes([seed; 32]),
        AuthDigest::from_bytes([seed; 32]),
    )
}

fn header_hash_from_header(header: &[u8]) -> [u8; 32] {
    let mut h = [0u8; 32];
    let len = std::cmp::min(32, header.len());
    h[..len].copy_from_slice(&header[..len]);
    h
}

/// Full round trip: sender builds compact block, receiver reconstructs
#[test]
fn full_round_trip_synchronized_mempools() {
    // Setup: A block with coinbase + 10 transactions
    let header = vec![0xab; 2189];
    let nonce = 0xdeadbeef_u64;

    let coinbase = make_wtxid(0);
    let txs: Vec<_> = (1..=10).map(|i| make_wtxid(i)).collect();
    let tx_data: Vec<Vec<u8>> = (0..=10).map(|i| vec![i as u8; 100]).collect();

    // Sender's view: receiver has all transactions
    let mut sender_view = TestMempool::new();
    for (i, wtxid) in txs.iter().enumerate() {
        sender_view.insert(*wtxid, tx_data[i + 1].clone());
    }

    // Build compact block
    let mut builder = CompactBlockBuilder::new(header.clone(), nonce);
    builder.add_transaction(coinbase, tx_data[0].clone());
    for (i, wtxid) in txs.iter().enumerate() {
        builder.add_transaction(*wtxid, tx_data[i + 1].clone());
    }
    let compact = builder.build(&sender_view);

    // Verify compact block has minimal prefills (just coinbase)
    assert_eq!(compact.prefilled_txs.len(), 1, "Should only prefill coinbase");
    assert_eq!(compact.short_ids.len(), 10, "Should have 10 short IDs");

    // Receiver's mempool matches sender's view
    let mut receiver_mempool = TestMempool::new();
    for (i, wtxid) in txs.iter().enumerate() {
        receiver_mempool.insert(*wtxid, tx_data[i + 1].clone());
    }

    // Reconstruct
    let mut reconstructor = CompactBlockReconstructor::new(&receiver_mempool);
    reconstructor.prepare(&header_hash_from_header(&header), nonce);
    let result = reconstructor.reconstruct(&compact);

    // Should be complete
    match result {
        ReconstructionResult::Complete { transactions } => {
            assert_eq!(transactions.len(), 11);
            for (i, tx) in transactions.iter().enumerate() {
                assert_eq!(tx, &tx_data[i], "Transaction {} mismatch", i);
            }
        }
        _ => panic!("Expected complete reconstruction"),
    }
}

/// Round trip with missing transactions requiring getblocktxn
#[test]
fn round_trip_with_missing_transactions() {
    let header = vec![0xcd; 2189];
    let nonce = 0xcafebabe_u64;

    let coinbase = make_wtxid(0);
    let tx1 = make_wtxid(1);
    let tx2 = make_wtxid(2);
    let tx3 = make_wtxid(3);

    let tx_data = vec![
        vec![0u8; 50],   // coinbase
        vec![1u8; 100],  // tx1
        vec![2u8; 9000], // tx2 (large shielded tx)
        vec![3u8; 150],  // tx3
    ];

    // Sender thinks receiver has tx1 and tx3, but not tx2
    let mut sender_view = TestMempool::new();
    sender_view.insert(tx1, tx_data[1].clone());
    sender_view.insert(tx3, tx_data[3].clone());

    // Build compact block (tx2 will be prefilled)
    let mut builder = CompactBlockBuilder::new(header.clone(), nonce);
    builder.add_transaction(coinbase, tx_data[0].clone());
    builder.add_transaction(tx1, tx_data[1].clone());
    builder.add_transaction(tx2, tx_data[2].clone());
    builder.add_transaction(tx3, tx_data[3].clone());
    let compact = builder.build(&sender_view);

    // Coinbase + tx2 prefilled, tx1 + tx3 as short IDs
    assert_eq!(compact.prefilled_txs.len(), 2);
    assert_eq!(compact.short_ids.len(), 2);

    // Receiver only has tx1 (not tx3)
    let mut receiver_mempool = TestMempool::new();
    receiver_mempool.insert(tx1, tx_data[1].clone());

    // First reconstruction attempt
    let mut reconstructor = CompactBlockReconstructor::new(&receiver_mempool);
    reconstructor.prepare(&header_hash_from_header(&header), nonce);
    let result = reconstructor.reconstruct(&compact);

    // Should be incomplete - missing tx3
    let missing_indexes = match result {
        ReconstructionResult::Incomplete {
            partial,
            unresolved_short_ids,
            ..
        } => {
            assert_eq!(unresolved_short_ids.len(), 1, "Should have 1 unresolved short ID");

            // Find which indexes are missing
            partial.iter()
                .enumerate()
                .filter(|(_, tx)| tx.is_none())
                .map(|(i, _)| i)
                .collect::<Vec<_>>()
        }
        _ => panic!("Expected incomplete reconstruction"),
    };

    assert_eq!(missing_indexes, vec![3], "tx3 should be missing");

    // Create getblocktxn request
    let block_hash = BlockHash::from_bytes(header_hash_from_header(&header));
    let request = GetBlockTxn::from_missing_indexes(block_hash, &missing_indexes);

    // Sender responds with blocktxn
    let response = BlockTxn::new(block_hash, vec![tx_data[3].clone()]);

    // Verify response matches request
    assert_eq!(response.transactions.len(), missing_indexes.len());
    assert_eq!(response.transactions[0], tx_data[3]);
}

/// Test bandwidth savings calculation
#[test]
fn bandwidth_savings_measurement() {
    let header = vec![0u8; 2189];
    let nonce = 12345u64;

    // Simulate a block with varying transaction sizes
    let num_txs = 50;
    let mut total_tx_bytes = 0usize;
    let mut wtxids = Vec::new();
    let mut tx_datas = Vec::new();

    for i in 0..num_txs {
        let wtxid = make_wtxid(i as u8);
        // Mix of tx sizes: some small (transparent), some large (shielded)
        let size = if i % 5 == 0 { 9000 } else { 300 };
        let data = vec![i as u8; size];
        total_tx_bytes += size;
        wtxids.push(wtxid);
        tx_datas.push(data);
    }

    // Perfect mempool sync
    let mut mempool = TestMempool::new();
    for (wtxid, data) in wtxids.iter().zip(tx_datas.iter()) {
        mempool.insert(*wtxid, data.clone());
    }

    // Build compact block
    let mut builder = CompactBlockBuilder::new(header.clone(), nonce);
    builder.add_transaction(wtxids[0], tx_datas[0].clone()); // coinbase
    for i in 1..num_txs {
        builder.add_transaction(wtxids[i], tx_datas[i].clone());
    }
    let compact = builder.build(&mempool);

    // Calculate sizes
    let full_block_size = header.len() + total_tx_bytes;
    let compact_block_size = header.len()
        + 8  // nonce
        + compact.short_ids.len() * 6  // short IDs
        + compact.prefilled_txs.iter()
            .map(|p| 2 + p.tx_data.len())  // index + data
            .sum::<usize>();

    let savings_pct = 100.0 * (1.0 - compact_block_size as f64 / full_block_size as f64);

    println!("Full block: {} bytes", full_block_size);
    println!("Compact block: {} bytes", compact_block_size);
    println!("Bandwidth savings: {:.1}%", savings_pct);

    // With good mempool sync, should save >80% bandwidth
    assert!(savings_pct > 80.0, "Expected >80% bandwidth savings, got {:.1}%", savings_pct);
}
```

**Step 2: Run integration tests**

Run: `cargo test --test integration`
Expected: PASS with all tests passing

**Step 3: Commit**

```bash
git add tests/integration.rs
git commit -m "$(cat <<'EOF'
test: add integration tests for compact block round-trip

Test scenarios:
- Full round trip with synchronized mempools
- Round trip with missing transactions and getblocktxn
- Bandwidth savings measurement (>80% with good sync)

Co-Authored-By: Claude Opus 4.5 <noreply@anthropic.com>
EOF
)"
```

---

## Task 11: Error Types and Edge Cases

**Files:**
- Create: `src/error.rs`
- Modify: `src/lib.rs`
- Modify: `src/reconstructor.rs`

**Step 1: Write failing test for error handling**

Create `src/error.rs`:

```rust
//! Error types for bedrock-forge

use thiserror::Error;

use crate::types::ShortId;

/// Errors that can occur during compact block operations
#[derive(Error, Debug)]
pub enum CompactBlockError {
    /// Short ID collision detected (multiple wtxids map to same short ID)
    #[error("short ID collision detected: {0:?}")]
    ShortIdCollision(ShortId),

    /// Invalid prefilled transaction index
    #[error("invalid prefilled transaction index: {index} >= {tx_count}")]
    InvalidPrefilledIndex { index: usize, tx_count: usize },

    /// Compact block has wrong transaction count
    #[error("transaction count mismatch: expected {expected}, got {actual}")]
    TransactionCountMismatch { expected: usize, actual: usize },

    /// Block reconstruction failed after receiving blocktxn
    #[error("block reconstruction failed: still missing {missing_count} transactions")]
    ReconstructionFailed { missing_count: usize },
}
```

**Step 2: Add module to lib.rs**

Update `src/lib.rs` to include:

```rust
//! Bedrock-Forge: Low-latency block relay network for Zcash
//!
//! This crate implements compact block relay (BIP 152 adapted for Zcash)
//! for bandwidth-efficient block propagation.

pub mod builder;
pub mod compact_block;
pub mod error;
pub mod mempool;
pub mod messages;
pub mod reconstructor;
pub mod types;

pub use builder::CompactBlockBuilder;
pub use compact_block::{CompactBlock, PrefilledTx};
pub use error::CompactBlockError;
pub use mempool::{MempoolError, MempoolProvider, TestMempool};
pub use messages::{BlockTxn, GetBlockTxn, SendCmpct};
pub use reconstructor::{CompactBlockReconstructor, ReconstructionResult};
pub use types::{AuthDigest, BlockHash, ShortId, TxId, WtxId};
```

**Step 3: Run tests to verify they pass**

Run: `cargo test`
Expected: PASS with all tests passing

**Step 4: Commit**

```bash
git add src/error.rs src/lib.rs
git commit -m "$(cat <<'EOF'
feat: add CompactBlockError type

Define error types for compact block operations:
- ShortIdCollision
- InvalidPrefilledIndex
- TransactionCountMismatch
- ReconstructionFailed

Co-Authored-By: Claude Opus 4.5 <noreply@anthropic.com>
EOF
)"
```

---

## Task 12: Documentation and README

**Files:**
- Create: `README.md`

**Step 1: Write README**

Create `README.md`:

```markdown
# bedrock-forge

Low-latency block relay network for Zcash, implementing compact block relay (BIP 152 adapted for Zcash).

## Overview

This crate implements the core compact block protocol for bandwidth-efficient block propagation in Zcash. It is designed for eventual integration with [Zebra](https://github.com/ZcashFoundation/zebra) but can be used as a standalone library.

## Features

- **Compact Block Construction**: Build compact blocks from full blocks, using short transaction IDs for transactions likely in peer mempools
- **Compact Block Reconstruction**: Reconstruct full blocks from compact blocks using local mempool
- **Transaction ID Types**: Support for Zcash v5 transaction identifiers (txid, wtxid per ZIP 244/239)
- **Protocol Messages**: GetBlockTxn, BlockTxn, and SendCmpct message types

## Quick Start

```rust
use bedrock_forge::{
    CompactBlockBuilder, CompactBlockReconstructor,
    TestMempool, WtxId, TxId, AuthDigest,
};

// Sender side: build compact block
let mut builder = CompactBlockBuilder::new(block_header, nonce);
builder.add_transaction(coinbase_wtxid, coinbase_data);
builder.add_transaction(tx1_wtxid, tx1_data);
let compact = builder.build(&peer_mempool_view);

// Receiver side: reconstruct
let mut reconstructor = CompactBlockReconstructor::new(&local_mempool);
reconstructor.prepare(&header_hash, nonce);
match reconstructor.reconstruct(&compact) {
    ReconstructionResult::Complete { transactions } => {
        // Full block reconstructed
    }
    ReconstructionResult::Incomplete { unresolved_short_ids, .. } => {
        // Need to request missing transactions via getblocktxn
    }
}
```

## Zcash-Specific Considerations

- **Larger Transactions**: Shielded transactions are 12-40x larger than Bitcoin transactions
- **Larger Headers**: Zcash headers are 2189 bytes (vs 80 for Bitcoin) due to Equihash solution
- **ZIP 244/239**: Uses wtxid-based short IDs for v5 transaction relay

## Project Status

Phase 1 (Compact Block Protocol) - In Progress
- [x] Transaction identifier types
- [x] Compact block construction
- [x] Compact block reconstruction
- [x] Protocol messages

## License

Licensed under either of Apache License, Version 2.0 or MIT license at your option.
```

**Step 2: Commit**

```bash
git add README.md
git commit -m "$(cat <<'EOF'
docs: add README with usage examples

Document library features, quick start example, and Zcash-specific
considerations for compact block relay.

Co-Authored-By: Claude Opus 4.5 <noreply@anthropic.com>
EOF
)"
```

---

## Phase 1 Summary

After completing all 12 tasks, you will have:

1. **Core Types** (`src/types/`):
   - `TxId`, `WtxId`, `AuthDigest` - Transaction identifiers per ZIP 244/239
   - `ShortId` - 6-byte SipHash-based short IDs per BIP 152
   - `BlockHash` - Block header hash

2. **Compact Block Protocol** (`src/`):
   - `CompactBlock`, `PrefilledTx` - Message structures
   - `CompactBlockBuilder` - Construct compact blocks from full blocks
   - `CompactBlockReconstructor` - Reconstruct blocks from mempool
   - `GetBlockTxn`, `BlockTxn`, `SendCmpct` - Protocol messages

3. **Infrastructure**:
   - `MempoolProvider` trait for integration
   - `TestMempool` for testing
   - `CompactBlockError` for error handling
   - Integration tests demonstrating round-trip

**Next Phase**: Phase 2 will add UDP/FEC transport for low-latency relay between nodes.

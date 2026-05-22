<p align="center">
  <img src="../../assets/brand/forge-logo.svg" alt="FORGE" width="180">
</p>

# bedrock-forge

> Formerly `fiber-zcash`.

Low-latency block relay network for Zcash, implementing compact block relay (BIP 152 adapted for Zcash).

## Overview

This crate implements the core compact block protocol for bandwidth-efficient block propagation in Zcash. It is designed for eventual integration with [Zebra](https://github.com/ZcashFoundation/zebra) but can be used as a standalone library.

## Features

- **Compact Block Construction**: Build compact blocks from full blocks, using short transaction IDs for transactions likely in peer mempools
- **Compact Block Reconstruction**: Reconstruct full blocks from compact blocks using local mempool
- **Transaction ID Types**: Support for Zcash v5 transaction identifiers (txid, wtxid per ZIP 244/239)
- **Protocol Messages**: GetBlockTxn, BlockTxn, and SendCmpct message types

## Binaries

- `bedrock-forge-relay`: authenticated UDP relay daemon for the FORGE relay network.
- `bedrock-forge-probe`: synthetic authenticated compact-block sender for private relay smoke tests.

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

# Building a FIBRE-like low-latency relay network for Zcash

> Note: This document was written before the rename from fiber-zcash to sovright-relay. Some internal references may still use the old name.

A dedicated block relay network for Zcash is technically feasible and would address a significant infrastructure gap. Unlike Bitcoin, which has mature relay infrastructure through FIBRE, Falcon, and bloXroute, **Zcash currently operates without any dedicated relay network optimization**—a surprising omission given that shielded transactions are 10-40x larger than Bitcoin's transparent transactions and impose expensive proof verification costs. The core technical challenge lies in adapting compact block relay for Zcash's cryptographic transaction structure while preserving the privacy guarantees that make the protocol valuable.

## How Bitcoin's FIBRE achieves sub-second block propagation

Bitcoin's Fast Internet Bitcoin Relay Engine, developed by Matt Corallo in 2016, achieves block propagation times approaching the theoretical speed-of-light limit through three key innovations working in concert. The first is **compact block relay** (BIP 152), which exploits mempool synchronization between peers—since nodes typically share 95%+ of unconfirmed transactions, a block can be represented by its header plus **6-byte short transaction IDs** rather than full transaction data. This reduces a typical 1MB block to approximately 15KB when mempools are well-synchronized.

The second innovation is **UDP-based forward error correction**. TCP performs poorly for low-latency relay because packet loss (averaging ~1% over long-haul internet links) triggers retransmission delays. With a 1% loss rate, transmitting even a compressed 15KB block has only a 90% probability of arriving without requiring retransmission. FIBRE sends redundant FEC-encoded data proactively over UDP, allowing receivers to reconstruct complete blocks even when packets are lost. The third component is **cut-through routing**: FIBRE relay servers forward individual packets immediately upon receipt rather than waiting for complete block reconstruction, effectively eliminating hop latency between geographically distributed relay nodes.

The trust model underlying FIBRE is elegant: relay nodes verify only that a block header contains valid proof-of-work before propagation, deferring full transaction validation. This is economically safe because creating a header with valid PoW is expensive—an attacker broadcasting invalid blocks forfeits the block reward they could earn mining honestly. Critical guidance from BIP 152 notes that nodes "SHOULD NOT ban a peer for announcing a new block with a CMPCTBLOCK message that is invalid, but has a valid header."

## Zcash's unique constraints multiply complexity

Zcash transactions present fundamentally different propagation characteristics than Bitcoin's. A fully shielded **Sapling transaction** with 2 inputs and 2 outputs requires approximately **2,756 bytes**—each containing Groth16 proofs (192 bytes), encrypted note ciphertexts (~580 bytes), nullifiers (32 bytes), and value commitments. **Orchard transactions** are substantially larger at approximately **9,160 bytes** because Halo 2 proofs use polynomial commitment schemes rather than pairing-based proofs. Transparent Zcash transactions remain similar to Bitcoin (~250 bytes), but the shielded transaction overhead represents a **12-40x increase** over transparent equivalents.

Verification costs compound the size penalty. Groth16 proof verification takes **7-10ms per proof** in zcashd, though optimized implementations achieve ~1.2ms. Halo 2 (Orchard) verification has comparable individual costs but benefits from batching—Zebra implements batch verification providing roughly **3x speedup** for chain synchronization. This compares unfavorably to Bitcoin's ECDSA/Schnorr signature verification at 0.1-0.5ms per signature, though batching substantially closes the gap.

The Zcash block header itself presents an obstacle: at **2,189 bytes** versus Bitcoin's 80 bytes, it includes the 1,344-byte Equihash solution—a consequence of the memory-hard proof-of-work algorithm. Combined with Zcash's **75-second block time** (post-Blossom upgrade), a relay network would need to optimize for larger headers and faster block arrival frequency than Bitcoin's 10-minute cadence.

## Current Zcash infrastructure lacks relay optimization

The Zcash ecosystem operates without any dedicated block relay infrastructure. Network monitoring research (the Map-Z study from 2019) found block propagation follows standard Bitcoin-style three-way message exchange with no compact block optimization. The reference client establishes 8 outgoing connections by default with an estimated **300-350 simultaneously connected nodes** on the network.

**zebrad**, the Rust-based full node implementation actively replacing the deprecated zcashd, offers architectural advantages for relay integration. Its modular design separates concerns cleanly: zebra-network handles async P2P with isolated peer connections, zebra-consensus manages block/transaction verification with batch processing, and the Tower services pattern enables concurrent verification pipelines. The documentation explicitly notes that "the zebra-network crate can also be used to implement anonymous transaction relay, network crawlers, or other functionality, without requiring a full node"—suggesting the architecture was designed with relay extensibility in mind.

**lightwalletd** provides bandwidth-efficient block streaming to light wallets via gRPC but serves as read-only infrastructure rather than relay optimization. The ongoing zcashd deprecation (82% complete as of late 2025) creates a natural integration window for relay network design with zebrad as the primary node implementation.

Mining pool concentration shapes trust model considerations. The top 3-4 pools typically control over **60% of hashrate**, with ASIC mining (Bitmain Antminer Z15 series) dominating the **13-15 PH/s** network. This centralization is higher than Bitcoin's and affects pre-validation relay economics—a smaller pool coalition could theoretically coordinate invalid block propagation attacks, though the economic disincentives remain substantial.

## Compact block relay can work for shielded transactions

The critical question for Zcash compact block relay is whether shielded transactions can be deduplicated despite their encrypted contents. The answer is **yes, with important caveats**. Although shielded transaction contents are encrypted, the txid is computed over the canonical serialization of the entire transaction structure—including encrypted components. Two nodes observing the same shielded transaction will compute identical txids regardless of their inability to decrypt contents.

ZIP 244 defines Zcash v5 transaction identifiers: the **txid** commits to "effecting data" (transaction effects excluding witness data), while the **wtxid** concatenates txid with auth_digest to commit to a specific transaction instance. ZIP 239 introduced MSG_WTX for v5 transaction relay, directly analogous to Bitcoin's BIP 339. This provides the identifier structure needed for compact block construction—short IDs can be derived from wtxids just as in Bitcoin.

However, compact blocks cannot reduce shielded transaction size beyond identifier matching. Unlike transparent transactions where script and signature structures are well-understood and partially predictable, shielded transactions contain:
- **zk-SNARK proofs**: Incompressible, 192 bytes (Sapling) to 7KB+ (Orchard)
- **Encrypted note ciphertexts**: Cannot be compressed or content-addressed (~580 bytes each)
- **Value commitments and nullifiers**: Cryptographically unpredictable

This means the "missing transaction penalty" for shielded transactions is severe. When a receiver lacks a shielded transaction in mempool and must request it, the bandwidth cost is **9KB** (Orchard) versus **250 bytes** for a typical Bitcoin transaction—a 36x penalty. Mempool synchronization becomes correspondingly more critical for Zcash compact block efficiency.

## Set reconciliation faces asymmetric costs

Erlay (BIP 330) uses minisketch—a PinSketch BCH-based secure sketch implementation—for bandwidth-efficient transaction announcement reconciliation. The technique encodes transaction sets into sketches proportional to symmetric difference size rather than total set size, achieving **40% bandwidth savings** versus flooding. Sketch operations (XOR combination, difference decoding) work on fixed-length identifiers and complete in sub-millisecond time for differences under 100 elements.

Zcash wtxids are compatible with minisketch: they're fixed-length (64 bytes for v5+) and can be truncated to 32-bit short IDs with per-link salting for collision resistance. The XOR and algebraic operations required for sketch encoding work identically regardless of what the identifiers represent. Standard Erlay implementation could therefore apply to Zcash transaction reconciliation without cryptographic modifications.

The asymmetric challenge is **collision cost**. When a 32-bit collision occurs requiring transaction request (rare but expected under adversarial conditions), the cost difference is enormous: Bitcoin requests ~250 bytes, Zcash potentially requests ~9KB. This suggests Zcash implementations should consider:
- Larger short IDs (48-64 bits) to reduce collision probability
- Tiered reconciliation: flooding for recent shielded transactions, reconciliation for older transactions or transparent transactions
- More aggressive proactive transaction push to trusted peers

## Pre-validation relay requires careful trust calibration

FIBRE's pre-validation relay model—propagating blocks after header PoW verification but before full transaction validation—translates directly to Zcash with one important consideration: proof verification is expensive but batchable. A tiered validation approach could define:

| Level | Checks performed | Relay speed | Trust required |
|-------|-----------------|-------------|----------------|
| 0 | Header + Equihash PoW only | Fastest (~3-5ms) | High (pool-to-pool) |
| 1 | + Transaction structure parsing | Fast | Medium |
| 2 | + Batched proof verification | Moderate | Low |
| 3 | Full validation including nullifier checks | Slowest | None |

Level 0 is appropriate for trusted connections between major mining pools—the economic analysis parallels Bitcoin exactly. An attacker creating valid Equihash headers for invalid blocks forfeits ~1.25 ZEC (post-halving block reward) per attempt. Level 2 adds substantial latency (batch verification across all proofs in a block) but provides cryptographic validity guarantees beyond PoW.

**Nullifier validation** presents a unique Zcash consideration. Each spent note reveals a unique nullifier that must not duplicate any nullifier in chain history. This consensus-critical check requires state access (querying the nullifier set), which cannot be deferred to the same extent as proof verification. A relay network would need either:
- Pre-fetched nullifier set synchronization between relay nodes
- Parallel nullifier checking during block propagation (exploiting the time window between packet arrival and full block reconstruction)
- Acceptance of nullifier checking as a post-relay validation step (appropriate for Level 0-1 trust)

## Integration architecture builds on zebrad's modularity

The recommended integration approach leverages zebrad's clean architectural separation. The core requirements are:

**Mempool synchronization interface**: Expose mempool wtxid sets for compact block reconstruction. Zebra's internal request/response pattern already separates protocol concerns from state management, suggesting a natural extension point for relay-specific mempool queries.

**Block submission bypass**: A `submit_unvalidated_block` pathway that accepts blocks verified only to Level 0-1, queuing them for full validation while immediately preparing relay to connected peers. This parallels FIBRE's approach of treating relay network blocks as "unverified tips" that must be validated before mining upon.

**Batch verification pipeline hooks**: Zebra already implements batch verification via Tower services. Relay integration requires exposing this pipeline for pre-computation—when a relay node receives early packets of a block via cut-through routing, it could begin batching proofs from available transactions before full block reconstruction completes.

Mining pool integration requires minimal additional work beyond standard getblocktemplate/submitblock RPCs already implemented in Zebra. Pools would run relay-enabled zebrad instances connecting to the relay network, receiving compact blocks with sub-second latency and submitting newly mined blocks for rapid propagation.

The relationship to lightwalletd is indirect: relay networks serve consensus-layer participants (pools, full nodes), while lightwalletd serves wallet-layer clients. However, relay-accelerated block propagation would reduce the delay between block mining and lightwalletd serving compact blocks to light wallets—an indirect benefit for user experience.

## Dandelion++ considerations for privacy-preserving relay

Unlike Bitcoin, Zcash's cryptographic privacy (zk-SNARKs for transaction contents) provides transaction-level unlinkability independent of network-layer propagation patterns. However, network-layer deanonymization remains relevant: an adversary observing transaction propagation timing can potentially link IP addresses to transaction broadcasts, even if transaction contents are encrypted.

Monero's Dandelion++ protocol—deployed since 2020—addresses this through two-phase propagation: a "stem" phase where transactions hop through random single peers, followed by "fluff" phase standard flooding. The stem phase adds ~30 seconds aggregation window but provides formal anonymity guarantees against adversaries observing network traffic.

For a Zcash relay network, the design choice involves a tradeoff: relay networks inherently concentrate propagation through known nodes, potentially creating deanonymization vectors. Mitigations include:
- Encrypting transaction content during relay (bloXroute's approach provides "provable neutrality")
- Allowing nodes to submit transactions through Tor/I2P before relay network propagation
- Implementing Dandelion-style stem phase for transaction origination before relay network handoff

The bloXroute model—where relay content is encrypted and the network can be audited by the peer-to-peer layer—offers a template for privacy-preserving relay. Relay operators cannot discriminate based on transaction content (they can't see it), and standard P2P propagation provides a fallback ensuring relay network participation is economically motivated rather than privacy-compromising.

## Development effort and critical path

Building a Zcash FIBRE equivalent requires work across four major phases:

**Phase 1: Compact block protocol** (estimated 3-6 months). Implement BIP 152-equivalent for Zcash including wtxid-based short IDs, high-bandwidth mode for trusted peers, and mempool txid set exposure. This requires protocol specification (potentially as ZIP 204, currently reserved but undrafted), zebrad implementation, and interoperability testing. The primary reference is Bitcoin Core's compact block implementation, adapted for Zcash transaction identifier structure.

**Phase 2: UDP/FEC transport** (estimated 2-4 months). Port FIBRE's FEC encoding for Zcash compact blocks, accounting for larger transaction sizes. Implement trusted peer management, cut-through routing between relay nodes, and connection pooling. This is largely transport-layer work independent of Zcash-specific consensus.

**Phase 3: Pre-validation relay modes** (estimated 2-3 months). Implement tiered validation levels, deferred proof verification with batch processing, and nullifier pre-fetch or parallel checking. Requires careful security analysis of each trust level and coordination with Zebra's existing batch verification infrastructure.

**Phase 4: Set reconciliation** (estimated 2-3 months). Integrate minisketch library for transaction announcement reconciliation, adapt parameters for Zcash transaction size characteristics, and implement hybrid flooding/reconciliation strategy for shielded transactions.

The critical technical challenges are:
1. **Missing transaction penalty**: The 36x bandwidth cost differential for shielded transaction requests makes mempool synchronization paramount—any compact block implementation must prioritize aggressive mempool sync
2. **Proof verification latency**: Even batched verification adds meaningful delay; determining which validation level is appropriate for each relay connection requires operational experience
3. **Mining centralization**: The trust model assumes rational economic actors; higher mining concentration increases theoretical coordination attack surface (though remains economically irrational)

## Conclusion

A Zcash FIBRE-equivalent is technically achievable using the same architectural principles: compact block relay for bandwidth efficiency, UDP/FEC for latency robustness, and hashpower-based trust for pre-validation propagation. The key adaptations required are accounting for shielded transaction size (making mempool synchronization more critical), integrating with Zebra's batch verification infrastructure for proof validation, and carefully calibrating trust levels given Zcash's more concentrated mining landscape.

The absence of existing relay infrastructure represents both a gap and an opportunity. Zebra's modular Rust architecture provides a clean integration foundation, and the ongoing zcashd deprecation creates a natural window for protocol evolution. The reserved but undrafted ZIP 204 (Zcash P2P Network Protocol) could incorporate relay network specification alongside compact block relay, providing the formal protocol documentation Zcash currently lacks.

Development effort is estimated at **9-16 months** for a full-featured implementation across all four phases, assuming a small team (2-3 developers) with Rust expertise and familiarity with cryptocurrency networking. The highest-impact initial deliverable would be Phase 1 compact block support alone—this addresses the most significant current gap (no block compression) and provides immediate latency and bandwidth improvements even without dedicated relay infrastructure.

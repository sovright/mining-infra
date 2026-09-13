//! A genuine solved block must clear the target its own `nBits` encodes.
//!
//! `verify_share` compares the hash it computes against the target it is
//! given, and returns that hash. Three sites judge it against a block target
//! rather than a pool-chosen share target: `zcash-jd-server`'s
//! `handle_push_solution` builds the header from the job and takes its target
//! from the **declared job's** bits (`server.rs:655`,
//! `compact_to_target(job.bits)`), while `zcash-pool-server` (`is_block`, which
//! gates `submit_block`) and `zcash-jd-client` (`meets_block_target`, which
//! gates block assembly) compare the returned hash against their block target.
//! For any of that to mean anything, the hash has to be the one Zcash consensus
//! uses: the double-SHA256 of the full 1487-byte serialized header.
//!
//! The other target tests in this crate use all-`0xff` ("easy") and all-`0x00`
//! ("impossible") targets. The first accepts every digest and the second
//! rejects every non-zero one, so neither can tell one hash function from
//! another. These tests use a real block, the target its own header states,
//! and its known block hash.

use zcash_equihash_validator::{EquihashValidator, ValidationError, compact_to_target};
use zcash_pool_common::block_hash::BITS_OFFSET;
use zcash_pool_common::fixtures::{
    MAINNET_BLOCK_3470793_HASH_DISPLAY, mainnet_header_and_solution,
};

/// The target this header itself states, via its `nBits`.
fn stated_target(header: &[u8]) -> [u8; 32] {
    let bits = u32::from_le_bytes(
        header[BITS_OFFSET..BITS_OFFSET + 4]
            .try_into()
            .expect("4 bytes at the nBits offset"),
    );
    compact_to_target(bits).to_le_bytes()
}

/// The consensus hash of block 3470793 in internal byte order, the reversal of
/// the display-order value the fixture publishes.
fn consensus_hash_internal() -> [u8; 32] {
    let mut hash: [u8; 32] = hex::decode(MAINNET_BLOCK_3470793_HASH_DISPLAY)
        .expect("hash hex")
        .try_into()
        .expect("32 bytes");
    hash.reverse();
    hash
}

/// `value - 1` for a little-endian 256-bit integer.
fn minus_one(mut value: [u8; 32]) -> [u8; 32] {
    for byte in value.iter_mut() {
        if *byte == 0 {
            *byte = 0xff;
        } else {
            *byte -= 1;
            return value;
        }
    }
    panic!("minus_one called on zero");
}

/// THE regression. Block 3470793 is on mainnet, so by definition its proof of
/// work meets the target its own `nBits` encodes. A pool that cannot recognise
/// that has no way to know it found a block.
#[test]
fn a_real_mainnet_block_meets_its_own_stated_target() {
    let (header, solution) = mainnet_header_and_solution();
    let target = stated_target(&header);

    let validator = EquihashValidator::new();
    let result = validator.verify_share(&header, &solution, &target);

    assert!(
        result.is_ok(),
        "mainnet block 3470793 is a solved block, so verify_share must accept \
         it against the target its own nBits encodes; got {:?}",
        result.err()
    );
}

/// Pins the digest itself, so a refactor cannot quietly swap the hash function
/// back. The double-SHA256 of this header is the block id Zebra reports and
/// every explorer displays; the BLAKE2b `"ZcashBlockHash"` digest over the same
/// bytes is the relay's internal object id (see `sovright_relay::hash`) and is
/// a different value entirely.
#[test]
fn the_returned_hash_is_the_consensus_block_hash() {
    let (header, solution) = mainnet_header_and_solution();
    let target = stated_target(&header);

    let validator = EquihashValidator::new();
    let hash = validator
        .verify_share(&header, &solution, &target)
        .expect("mainnet block 3470793 meets its own stated target");

    // Display order is the byte reversal of the internal order.
    let mut display = hash;
    display.reverse();
    assert_eq!(
        hex::encode(display),
        MAINNET_BLOCK_3470793_HASH_DISPLAY,
        "verify_share must return the consensus block hash for block 3470793"
    );
}

/// Pins the hash `verify_share` compares against the target internally, which
/// decides share acceptance and jd-server's `handle_push_solution`. The previous
/// test pins the hash it returns, which `is_block` and `meets_block_target`
/// use. The rule is `hash <= target`, so a target equal to the block's
/// consensus hash is met and a target one below it is not. Between them the two
/// assertions leave only one value the compared hash can be.
#[test]
fn the_target_boundary_sits_exactly_at_the_consensus_block_hash() {
    let (header, solution) = mainnet_header_and_solution();
    let at = consensus_hash_internal();
    let below = minus_one(at);

    let validator = EquihashValidator::new();
    assert!(
        validator.verify_share(&header, &solution, &at).is_ok(),
        "a target equal to the consensus hash must be met"
    );
    assert!(
        matches!(
            validator.verify_share(&header, &solution, &below),
            Err(ValidationError::TargetNotMet)
        ),
        "a target one below the consensus hash must not be met"
    );
}

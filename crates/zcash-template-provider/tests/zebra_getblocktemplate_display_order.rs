//! Zebra's `getblocktemplate` encodes its hash fields in display order.
//!
//! The fixture is the JSON body of Zebra v6.2.0's own insta snapshot
//! `zebra-rpc/src/methods/tests/snapshots/get_block_template_basic@mainnet_10.snap`,
//! with the insta front matter stripped; the v6.3.0 file is byte-identical. Zebra
//! generated it over a mock chain state, so it pins Zebra's RPC *encoding* contract,
//! not real chain data.
//!
//! In that contract the five hash fields -- `previousblockhash` and the four
//! `defaultroots` -- are `BytesInDisplayOrder<true>` types: their hex is the internal
//! bytes reversed. `target` is an `ExpandedDifficulty`, serialised as a big-endian
//! integer. Every expectation below is a literal in internal byte order, decoded with
//! `hex::decode` rather than `Hash256::from_hex*`, so no expectation can share a bug
//! with the parser it checks.

use zcash_template_provider::types::{GetBlockTemplateResponse, Hash256};
use zcash_template_provider::{assemble_header, calculate_block_commitments_hash, parse_target};

const SNAPSHOT: &str = include_str!("fixtures/zebra-6.2.0-getblocktemplate-mainnet_10.json");

// The snapshot's hash fields in internal byte order: each is its display-order hex,
// reversed.
const PREVIOUS_BLOCK_HASH: &str =
    "f87b08af88515d9e6df0e2d75e67197ada8449cfff659b6d1523d70000000000";
const MERKLE_ROOT: &str = "8a3e898f9107c5686398af44e4227a546b8278950701ef1f4352ba6a7dc8d40d";
const CHAIN_HISTORY_ROOT: &str = "b5e0475805444c7faa715e13423ade144f20f3a35a9a10db5f1abd6ea60f4794";
const AUTH_DATA_ROOT: &str = "5d642f0e3da60b2a79a5826dc55fe57684dc51f46b720fb1628204fa7784b5c1";
const BLOCK_COMMITMENTS_HASH: &str =
    "cdccae3a6ab973239d896f1f241433aabfd8ea5485b7c4d5d0e34208f5f2e09f";

fn template() -> GetBlockTemplateResponse {
    serde_json::from_str(SNAPSHOT).expect("Zebra v6.2.0 snapshot deserialises")
}

/// A literal 32-byte value.
fn bytes(hex_str: &str) -> [u8; 32] {
    hex::decode(hex_str)
        .expect("literal hex")
        .try_into()
        .expect("32 bytes")
}

/// Guards against the fixture silently being some other template.
#[test]
fn fixture_is_zebras_mainnet_template() {
    let template = template();
    assert_eq!(template.height, 1_687_105);
    assert_eq!(template.bits, "1f055554");
    assert_eq!(
        template.target,
        "0005555400000000000000000000000000000000000000000000000000000000"
    );
}

/// `target` is the big-endian expansion of nBits 0x1f055554, i.e. 0x055554 * 256^28.
/// Parsed, that is bytes 54 55 05 at little-endian indices 28, 29 and 30.
#[test]
fn target_parses_to_little_endian_bytes() {
    let mut expected = [0u8; 32];
    expected[28] = 0x54;
    expected[29] = 0x55;
    expected[30] = 0x05;
    assert_eq!(parse_target(&template().target).unwrap().0, expected);
}

#[test]
fn merkle_root_lands_in_internal_order() {
    let header = assemble_header(&template()).unwrap();
    assert_eq!(header.merkle_root.0, bytes(MERKLE_ROOT));
}

/// `assemble_header` recomputes hashBlockCommitments from `chainhistoryroot` and
/// `authdataroot`. Read in internal order, they reproduce the `blockcommitmentshash`
/// Zebra sent.
#[test]
fn block_commitments_hash_is_recomputed_from_internal_order_roots() {
    let header = assemble_header(&template()).unwrap();
    assert_eq!(
        header.hash_block_commitments.0,
        bytes(BLOCK_COMMITMENTS_HASH)
    );
}

/// The oracle for the test above, independent of the parser. ZIP-244's
/// hashBlockCommitments over the internal-order roots is the internal-order commitments
/// hash; over the roots as sent, unreversed, it is an unrelated value. That is what makes
/// display order the only consistent reading of this snapshot, rather than an assumption.
#[test]
fn only_internal_order_roots_reproduce_zebras_commitments_hash() {
    let internal = calculate_block_commitments_hash(
        &Hash256(bytes(CHAIN_HISTORY_ROOT)),
        &Hash256(bytes(AUTH_DATA_ROOT)),
    );
    assert_eq!(internal.0, bytes(BLOCK_COMMITMENTS_HASH));

    let template = template();
    let unreversed = calculate_block_commitments_hash(
        &Hash256(bytes(&template.default_roots.chain_history_root)),
        &Hash256(bytes(&template.default_roots.auth_data_root)),
    );
    assert_ne!(unreversed.0, bytes(BLOCK_COMMITMENTS_HASH));
    assert_ne!(
        unreversed.0,
        bytes(&template.default_roots.block_commitments_hash)
    );
}

/// Over-correction guard: `previousblockhash` was already parsed in display order and
/// must not move.
#[test]
fn previous_block_hash_is_unchanged() {
    let header = assemble_header(&template()).unwrap();
    assert_eq!(header.prev_hash.0, bytes(PREVIOUS_BLOCK_HASH));
}

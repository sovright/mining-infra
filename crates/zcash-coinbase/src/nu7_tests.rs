//! v5/v6 coinbase handling, checked against real coinbases and zcash_primitives.
//!
//! Before these tests the parser read every version in v4 field order, txids
//! were SHA256d, and the auth digest assumed coinbases have no shielded data.
//! All three are wrong for v5/v6.

use std::io::Cursor;

use sha2::{Digest, Sha256};
use zcash_pool_common::fixtures::{mainnet_serialized_header, mainnet_transactions};
use zcash_primitives::transaction::Transaction;
use zcash_protocol::consensus::BranchId;

use crate::builder::build_coinbase;
use crate::digest::{self, DigestError};
use crate::fixtures::{
    NU7_BRANCH_ID, TESTNET_4465026_COINBASE_AUTHDIGEST_DISPLAY,
    TESTNET_4465026_COINBASE_TXID_DISPLAY, internal_from_display, testnet_nu7_coinbase,
    v5_coinbase,
};
use crate::tx_parse::{ParseError, ParsedTx, parse_transaction, push_compact_size};

fn mainnet_v6_coinbase() -> Vec<u8> {
    mainnet_transactions().remove(0)
}

fn read(raw: &[u8]) -> Transaction {
    let mut cursor = Cursor::new(raw);
    let tx = Transaction::read(&mut cursor, BranchId::Nu7).expect("zcash_primitives reads it");
    assert_eq!(cursor.position() as usize, raw.len(), "whole tx consumed");
    tx
}

/// Every transparent field must match what zcash_primitives reads from the
/// same bytes, compared on serialized form so no script types are needed.
fn assert_matches_reference(parsed: &ParsedTx, raw: &[u8]) {
    let tx = read(raw);
    assert_eq!(parsed.lock_time, tx.lock_time());
    assert_eq!(parsed.expiry_height, Some(u32::from(tx.expiry_height())));
    assert_eq!(
        parsed.consensus_branch_id,
        Some(u32::from(tx.consensus_branch_id()))
    );
    let bundle = tx
        .transparent_bundle()
        .expect("coinbase has a transparent bundle");

    assert_eq!(parsed.inputs.len(), bundle.vin.len());
    for (ours, theirs) in parsed.inputs.iter().zip(&bundle.vin) {
        let mut a = Vec::new();
        a.extend_from_slice(&ours.prevout_hash);
        a.extend_from_slice(&ours.prevout_index.to_le_bytes());
        push_compact_size(&mut a, ours.script_sig.len() as u64);
        a.extend_from_slice(&ours.script_sig);
        a.extend_from_slice(&ours.sequence.to_le_bytes());
        let mut b = Vec::new();
        theirs.write(&mut b).unwrap();
        assert_eq!(a, b, "input");
    }

    assert_eq!(parsed.outputs.len(), bundle.vout.len());
    for (ours, theirs) in parsed.outputs.iter().zip(&bundle.vout) {
        let mut a = Vec::new();
        a.extend_from_slice(&ours.value.to_le_bytes());
        push_compact_size(&mut a, ours.script_pubkey.len() as u64);
        a.extend_from_slice(&ours.script_pubkey);
        let mut b = Vec::new();
        theirs.write(&mut b).unwrap();
        assert_eq!(a, b, "output");
    }
}

#[test]
fn parses_a_mainnet_v6_coinbase_in_v5_field_order() {
    let raw = mainnet_v6_coinbase();
    let parsed = parse_transaction(&raw).expect("v6 coinbase parses");
    assert_eq!(parsed.version, 6);
    assert!(parsed.is_overwinter_plus);
    assert_eq!(parsed.version_group_id, Some(0xD884_B698));
    assert_eq!(parsed.inputs[0].prevout_hash, [0u8; 32]);
    assert_eq!(parsed.inputs[0].prevout_index, 0xFFFF_FFFF);
    assert_matches_reference(&parsed, &raw);
}

#[test]
fn parses_a_shielded_nu7_coinbase() {
    let raw = testnet_nu7_coinbase();
    let parsed = parse_transaction(&raw).expect("NU7 coinbase parses");
    assert_eq!(parsed.version, 6);
    assert_eq!(parsed.consensus_branch_id, Some(NU7_BRANCH_ID));
    assert!(
        parsed.trailing_data_offset.is_some(),
        "shielded bundles follow"
    );
    assert_matches_reference(&parsed, &raw);
}

#[test]
fn parses_a_v5_coinbase_in_v5_field_order() {
    let raw = v5_coinbase(
        u32::from(BranchId::Nu6_1),
        &[0x03, 0x01, 0x02, 0x03],
        &[0x51],
    );
    let parsed = parse_transaction(&raw).expect("v5 coinbase parses");
    assert_eq!(parsed.version, 5);
    assert_eq!(parsed.version_group_id, Some(0x26A7_270A));
    assert_matches_reference(&parsed, &raw);
}

#[test]
fn rejects_v5_and_v6_without_the_overwinter_flag() {
    for version in [5u32, 6] {
        let mut raw = mainnet_v6_coinbase();
        raw[..4].copy_from_slice(&version.to_le_bytes());
        assert!(
            matches!(
                parse_transaction(&raw),
                Err(ParseError::MissingOverwinterFlag(v)) if v == version
            ),
            "v{version}"
        );
    }
}

#[test]
fn spans_reassemble_the_transaction() {
    for raw in [
        mainnet_v6_coinbase(),
        testnet_nu7_coinbase(),
        crate::tx_parse::minimal_v4_coinbase(),
    ] {
        let parsed = parse_transaction(&raw).unwrap();
        let (s0, s1) = parsed.input0_script_span.expect("one input");
        let (o0, o1) = parsed.outputs_span;
        assert!(s0 < s1 && s1 <= o0 && o0 < o1 && o1 <= raw.len());
        let mut script = Vec::new();
        push_compact_size(&mut script, parsed.inputs[0].script_sig.len() as u64);
        script.extend_from_slice(&parsed.inputs[0].script_sig);
        assert_eq!(&raw[s0..s1], &script[..]);
    }
}

#[test]
fn txid_of_a_shielded_nu7_coinbase_matches_both_nodes() {
    let raw = testnet_nu7_coinbase();
    assert_eq!(
        digest::txid(&raw).unwrap(),
        internal_from_display(TESTNET_4465026_COINBASE_TXID_DISPLAY)
    );
}

#[test]
fn auth_digest_of_a_shielded_nu7_coinbase_matches_both_nodes() {
    let raw = testnet_nu7_coinbase();
    assert_eq!(
        digest::auth_digest(&raw).unwrap(),
        internal_from_display(TESTNET_4465026_COINBASE_AUTHDIGEST_DISPLAY)
    );
}

#[test]
fn txids_of_a_mixed_v4_v6_mainnet_block_make_its_merkle_root() {
    let txids: Vec<[u8; 32]> = mainnet_transactions()
        .iter()
        .map(|tx| digest::txid(tx).unwrap())
        .collect();
    let header = mainnet_serialized_header();
    assert_eq!(sha256d_merkle_root(&txids), header[36..68]);
}

#[test]
fn auth_digest_refuses_pre_v5_transactions() {
    let raw = crate::tx_parse::minimal_v4_coinbase();
    assert!(matches!(
        digest::auth_digest(&raw),
        Err(DigestError::NoAuthDigest { version: 4 })
    ));
}

#[test]
fn txid_rejects_trailing_bytes() {
    let mut raw = testnet_nu7_coinbase();
    raw.push(0);
    assert!(matches!(
        digest::txid(&raw),
        Err(DigestError::TrailingBytes { bytes: 1 })
    ));
}

#[test]
fn coinbase_only_auth_root_requires_the_template_branch() {
    let raw = testnet_nu7_coinbase();
    let root = digest::coinbase_only_auth_data_root(&raw, NU7_BRANCH_ID).unwrap();
    // One leaf: the root is the leaf.
    assert_eq!(
        root,
        internal_from_display(TESTNET_4465026_COINBASE_AUTHDIGEST_DISPLAY)
    );
    let nu6_3 = u32::from(BranchId::Nu6_3);
    assert!(matches!(
        digest::coinbase_only_auth_data_root(&raw, nu6_3),
        Err(DigestError::BranchMismatch { coinbase, template })
            if coinbase == NU7_BRANCH_ID && template == nu6_3
    ));
}

#[test]
fn tagging_a_v6_coinbase_changes_only_the_script_sig() {
    for raw in [mainnet_v6_coinbase(), testnet_nu7_coinbase()] {
        let before = parse_transaction(&raw).unwrap();
        let built = build_coinbase(&raw, b"/Sovright/").expect("tag injected");
        let after = parse_transaction(&built.tx_bytes).expect("still parses");

        let script = &after.inputs[0].script_sig;
        assert!(script.ends_with(b"/Sovright/"));
        let height_push = 1 + before.inputs[0].script_sig[0] as usize;
        assert_eq!(
            script[..height_push],
            before.inputs[0].script_sig[..height_push]
        );

        // Everything outside input 0's scriptSig is byte-identical.
        let (s0, s1) = before.input0_script_span.unwrap();
        let (t0, t1) = after.input0_script_span.unwrap();
        assert_eq!(s0, t0);
        assert_eq!(raw[..s0], built.tx_bytes[..t0]);
        assert_eq!(raw[s1..], built.tx_bytes[t1..]);

        // zcash_primitives accepts the result, and the txid is its txid.
        let tx = read(&built.tx_bytes);
        assert_eq!(built.txid, *tx.txid().as_ref());
        assert_matches_reference(&after, &built.tx_bytes);
    }
}

fn sha256d(data: &[u8]) -> [u8; 32] {
    Sha256::digest(Sha256::digest(data)).into()
}

fn sha256d_merkle_root(leaves: &[[u8; 32]]) -> [u8; 32] {
    let mut layer = leaves.to_vec();
    while layer.len() > 1 {
        layer = layer
            .chunks(2)
            .map(|pair| {
                let right = pair.get(1).unwrap_or(&pair[0]);
                sha256d(&[pair[0], *right].concat())
            })
            .collect();
    }
    layer[0]
}

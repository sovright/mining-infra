//! The independent vectors, generated from the design note by a Python script that does
//! not read this crate. A mismatch here is a finding to report, and the vectors are not to
//! be changed to make it pass.

mod common;

use std::time::Instant;

use chunk_proof::assembler::Arrival;
use chunk_proof::datagram::Verifier;
use chunk_proof::object::{MSG_BLOCK, ObjectError, Profile, Shape, decode, encode};
use chunk_proof::tree::{Node, climb, depth, empty_leaf, levels, proof, root, tagged};
use common::{KEY, assembler_on, datagram, roomy, verifier};
use reed_solomon_erasure::galois_8::ReedSolomon;
use serde_json::Value;
use sha2::{Digest, Sha256};

const VECTORS: &str = include_str!("vectors/chunk.json");
const LEAF_TAG: &str = "sovright/v2/chunk-leaf";

fn vectors() -> Value {
    serde_json::from_str(VECTORS).unwrap()
}

fn unhex(text: &str) -> Vec<u8> {
    (0..text.len() / 2)
        .map(|at| u8::from_str_radix(&text[2 * at..2 * at + 2], 16).unwrap())
        .collect()
}

fn hex(value: &Value) -> Vec<u8> {
    unhex(value.as_str().unwrap())
}

fn hex32(value: &Value) -> Node {
    hex(value).try_into().unwrap()
}

fn number(value: &Value) -> usize {
    value.as_u64().unwrap() as usize
}

fn name(case: &Value) -> &str {
    case["ad"].as_str().unwrap()
}

fn nodes(value: &Value) -> Vec<Node> {
    value.as_array().unwrap().iter().map(hex32).collect()
}

fn byte_lists(value: &Value) -> Vec<Vec<u8>> {
    value.as_array().unwrap().iter().map(hex).collect()
}

fn shape_of(case: &Value) -> Shape {
    Shape {
        msg_type: number(&case["msg_type"]) as u8,
        n: number(&case["n"]) as u16,
        k: number(&case["k"]) as u16,
        s: number(&case["s"]) as u16,
    }
}

/// Every way to pick `k` of `n`, in order.
fn subsets(items: &[usize], k: usize) -> Vec<Vec<usize>> {
    if k == 0 {
        return vec![Vec::new()];
    }
    let mut out = Vec::new();
    for (at, item) in items.iter().enumerate() {
        for mut rest in subsets(&items[at + 1..], k - 1) {
            rest.insert(0, *item);
            out.push(rest);
        }
    }
    out
}

fn picked(shards: &[Vec<u8>], subset: &[usize]) -> Vec<Option<Vec<u8>>> {
    (0..shards.len())
        .map(|at| subset.contains(&at).then(|| shards[at].clone()))
        .collect()
}

/// The script's content, so a large object need not be in the file.
fn stream(label: &str, len: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(len + 32);
    let mut counter = 0u32;
    while out.len() < len {
        let mut hash = Sha256::new();
        hash.update(label.as_bytes());
        hash.update(counter.to_be_bytes());
        out.extend_from_slice(&hash.finalize());
        counter += 1;
    }
    out.truncate(len);
    out
}

#[test]
fn trees_match() {
    let vectors = vectors();
    assert_eq!(empty_leaf(), hex32(&vectors["hash"]["chunk-empty"]));
    let cases = vectors["agac"].as_array().unwrap();
    assert_eq!(cases.len(), 13);
    for case in cases {
        let n = number(&case["n"]);
        let leaves: Vec<Node> = (0..n as u16)
            .map(|at| tagged(LEAF_TAG, &[&at.to_be_bytes(), &(n as u16).to_be_bytes()]))
            .collect();
        let want = hex32(&case["kok"]);
        assert_eq!(root(&leaves), want, "n {n}");
        let levels = levels(leaves.clone());
        for (at, proof_nodes) in case["kanitlar"].as_object().unwrap() {
            let at: usize = at.parse().unwrap();
            let expected = nodes(proof_nodes);
            assert_eq!(proof(&levels, at), expected, "n {n}, {at}");
            assert_eq!(expected.len(), depth(n));
            assert_eq!(climb(leaves[at], at, &expected), want);
        }
    }
}

#[test]
fn bad_proofs_do_not_reach_the_root() {
    let vectors = vectors();
    let cases = vectors["kanit_olumsuz"].as_array().unwrap();
    assert_eq!(cases.len(), 7);
    for case in cases {
        let (at, n) = (number(&case["i"]), number(&case["n"]));
        let siblings = nodes(&case["kanit"]);
        let passes = at < n
            && siblings.len() == depth(n)
            && climb(hex32(&case["yaprak"]), at, &siblings) == hex32(&case["kok"]);
        assert!(!passes, "{}", name(case));
    }
}

#[test]
fn parity_matches() {
    let vectors = vectors();
    for case in vectors["rs"].as_array().unwrap() {
        let (k, p) = (number(&case["k"]), number(&case["p"]));
        let data = byte_lists(&case["data"]);
        let mut parity = vec![vec![0u8; data[0].len()]; p];
        ReedSolomon::new(k, p)
            .unwrap()
            .encode_sep(&data, &mut parity)
            .unwrap();
        assert_eq!(parity, byte_lists(&case["parity"]), "({k}, {p})");
    }
}

/// The same object from the same content, and the same content back from every subset.
#[test]
fn every_object_encodes_the_same_and_decodes_from_every_subset() {
    let vectors = vectors();
    let cases = vectors["nesne"].as_array().unwrap();
    assert_eq!(cases.len(), 51);
    let mut decodes = 0;
    for case in cases {
        let shape = shape_of(case);
        let content = hex(&case["icerik"]);
        let encoded = encode(shape.msg_type, shape.n, shape.k, &content).unwrap();
        let id = hex32(&case["object_id"]);
        let shards = byte_lists(&case["shardlar"]);
        assert_eq!(encoded.object_id, id);
        assert_eq!(encoded.shape, shape);
        assert_eq!(encoded.shards, shards);
        let proofs: Vec<Vec<Node>> = case["kanitlar"]
            .as_array()
            .unwrap()
            .iter()
            .map(nodes)
            .collect();
        assert_eq!(encoded.proofs, proofs);

        let indices: Vec<usize> = (0..shards.len()).collect();
        for subset in subsets(&indices, usize::from(shape.k)) {
            let got = decode(
                &shape,
                &id,
                picked(&shards, &subset),
                common::max_content(0),
            );
            assert_eq!(got.as_ref(), Ok(&content), "{subset:?}");
            decodes += 1;
        }
    }
    assert_eq!(decodes, 3771, "the count the script reports");
}

#[test]
fn every_bad_object_stops_at_the_expected_rule_from_every_subset() {
    let vectors = vectors();
    let cases = vectors["nesne_olumsuz"].as_array().unwrap();
    assert_eq!(cases.len(), 7);
    for case in cases {
        let (shape, id) = (shape_of(case), hex32(&case["object_id"]));
        let shards = byte_lists(&case["shardlar"]);
        let max = if name(case) == "L tur sinirini asiyor" {
            20
        } else {
            common::max_content(0)
        };
        let seen: Vec<String> = match case.get("gorulen") {
            Some(seen) => seen
                .as_array()
                .unwrap()
                .iter()
                .map(|rule| rule.as_str().unwrap().to_owned())
                .collect(),
            None => vec![case["beklenen_kural"].as_str().unwrap().to_owned()],
        };
        let indices: Vec<usize> = (0..shards.len()).collect();
        for subset in subsets(&indices, usize::from(shape.k)) {
            let error = decode(&shape, &id, picked(&shards, &subset), max)
                .expect_err(&format!("{} {subset:?}", name(case)));
            assert!(
                seen.iter().any(|rule| rule == error.rule()),
                "{} {subset:?}: {}",
                name(case),
                error.rule()
            );
        }
    }
}

/// `L + 4` overflows 32 bits on some of these. On the others `L` is zero and `s` is as small
/// as it can be, so the shape agrees and only `L >= 1` stops them.
#[test]
fn lengths_at_the_edges_stop_at_the_structure_rule() {
    let vectors = vectors();
    let cases = vectors["L_sinirlari"].as_array().unwrap();
    assert_eq!(cases.len(), 5);
    for case in cases {
        let (shape, id) = (shape_of(case), hex32(&case["object_id"]));
        let shards = byte_lists(&case["shardlar"]);
        let subset: Vec<usize> = (0..usize::from(shape.k)).collect();
        let got = decode(&shape, &id, picked(&shards, &subset), usize::MAX);
        assert_eq!(got.err(), Some(ObjectError::Structure), "{}", name(case));
        assert_eq!(ObjectError::Structure.rule(), case["beklenen_kural"]);
    }
}

#[test]
fn datagrams_match_byte_for_byte_and_every_flipped_byte_is_refused() {
    let vectors = vectors();
    let case = &vectors["datagram"];
    assert_eq!(hex32(&case["anahtar"]), KEY);
    let encoded = encode(3, 6, 4, &stream("datagram", 21)).unwrap();
    assert_eq!(encoded.object_id, hex32(&case["object_id"]));
    let verifier = verifier();
    let expected = byte_lists(&case["datagramlar"]);
    for (at, want) in expected.iter().enumerate() {
        assert_eq!(datagram(&encoded, at), *want, "{at}");
        assert!(verifier.verify(want).is_ok());
    }

    let good = &expected[1];
    let mut counts = std::collections::BTreeMap::new();
    for at in 0..good.len() {
        let mut flipped = good.clone();
        flipped[at] ^= 1;
        let error = verifier.verify(&flipped).expect_err("a flipped byte");
        *counts.entry(error.rule().to_owned()).or_insert(0u64) += 1;
    }
    let want: std::collections::BTreeMap<String, u64> = case["bayt_cevirme_sonuclari"]
        .as_object()
        .unwrap()
        .iter()
        .map(|(rule, count)| (rule.clone(), count.as_u64().unwrap()))
        .collect();
    assert_eq!(counts, want);

    // A relay's new MAC changes bytes 47 to 78 and nothing else.
    let relayed = hex(&case["yeniden_mac"]);
    assert!(
        Verifier::new([0x43; 32], Profile::EveryShape)
            .verify(&relayed)
            .is_ok()
    );
    assert_eq!(relayed[..47], good[..47]);
    assert_eq!(relayed[79..], good[79..]);
    assert_eq!(
        verifier.verify(&relayed).err().map(|error| error.rule()),
        Some("A3")
    );
}

/// Headers changed by someone holding the key, so the MAC does not stop these.
#[test]
fn every_changed_header_stops_at_the_expected_rule() {
    let vectors = vectors();
    let cases = vectors["datagram_olumsuz"].as_array().unwrap();
    assert_eq!(cases.len(), 20);
    let verifier = verifier();
    for case in cases {
        let error = verifier
            .verify(&hex(&case["datagram"]))
            .expect_err(name(case));
        assert_eq!(error.rule(), case["beklenen_kural"], "{}", name(case));
    }
}

/// One proof sees only the padding in its own siblings, so some chunks pass under the
/// other root. Any `k` of those decode, and only the canonical rebuild stops the object.
#[test]
fn other_padding_passes_one_chunk_at_a_time_and_stops_at_the_rebuild() {
    let vectors = vectors();
    let cases = vectors["dolgu"].as_array().unwrap();
    assert_eq!(cases.len(), 4);
    let verifier = verifier();
    let mut objects = 0;
    for case in cases {
        let id = hex32(&case["object_id"]);
        assert_ne!(id, hex32(&case["kanonik_object_id"]), "{}", name(case));

        for frame in case["duran_A4a"].as_object().unwrap().values() {
            let error = verifier.verify(&hex(frame)).expect_err(name(case));
            assert_eq!(error.rule(), "A4a", "{}", name(case));
        }
        let passing: Vec<(usize, Vec<u8>)> = case["gecen"]
            .as_object()
            .unwrap()
            .iter()
            .map(|(at, frame)| (at.parse().unwrap(), hex(frame)))
            .collect();
        for (_, frame) in &passing {
            assert_eq!(verifier.verify(frame).unwrap().object_id(), id);
        }

        let indices: Vec<usize> = (0..passing.len()).collect();
        for subset in subsets(&indices, number(&case["k"])) {
            let mut assembler = assembler_on(&roomy());
            let mut last = None;
            for at in subset {
                last = Some(assembler.receive(&passing[at].1, Instant::now()));
            }
            assert!(
                matches!(last, Some(Arrival::Rejected(ObjectError::Root))),
                "{}: {last:?}",
                name(case)
            );
            objects += 1;
        }
    }
    assert!(objects > 10, "the subsets were tried: {objects}");
}

/// A consistent tree whose leaves disagree on the shape. Every chunk passes alone, and the
/// first one's shape stands, whichever came first.
#[test]
fn a_tree_of_mixed_shapes_cannot_share_an_assembly() {
    let vectors = vectors();
    let cases = vectors["karisik_sekil"].as_array().unwrap();
    assert_eq!(cases.len(), 3);
    let verifier = verifier();
    for case in cases {
        let frames = case["datagramlar"].as_object().unwrap();
        for frame in frames.values() {
            assert!(verifier.verify(&hex(frame)).is_ok(), "{}", name(case));
        }
        let odd = number(&case["uyumsuz_indeks"]).to_string();
        let (odd, even) = (hex(&frames[&odd]), hex(&frames["0"]));
        for (first, second) in [(&even, &odd), (&odd, &even)] {
            let mut assembler = assembler_on(&roomy());
            let now = Instant::now();
            let opened = assembler.receive(first, now);
            let state = assembler.state();
            let arrival = assembler.receive(second, now);
            assert!(
                matches!(arrival, Arrival::OtherShape),
                "{}: {opened:?}, {arrival:?}",
                name(case)
            );
            assert_eq!(assembler.state(), state);
        }
    }
}

/// Proofs consistent with their root, shards that are no codeword. Every `k` of them is
/// tried through the assembler and stops where the script says.
#[test]
fn an_inconsistent_code_is_refused_from_every_subset() {
    let vectors = vectors();
    let cases = vectors["tutarsiz_alt_kumeler"].as_array().unwrap();
    assert_eq!(cases.len(), 4);
    let verifier = verifier();
    let mut objects = 0;
    for case in cases {
        let frames = byte_lists(&case["datagramlar"]);
        for frame in &frames {
            assert!(verifier.verify(frame).is_ok(), "{}", name(case));
        }
        for (subset, rule) in case["alt_kumeler"].as_object().unwrap() {
            let mut assembler = assembler_on(&roomy());
            let mut last = None;
            for at in subset.split(',') {
                let at: usize = at.parse().unwrap();
                last = Some(assembler.receive(&frames[at], Instant::now()));
            }
            match last {
                Some(Arrival::Rejected(error)) => {
                    assert_eq!(error.rule(), rule, "{} {subset}", name(case));
                }
                other => panic!("{} {subset}: {other:?}", name(case)),
            }
            objects += 1;
        }
    }
    assert!(objects >= 300, "the subsets were tried: {objects}");
}

#[test]
fn large_objects_get_the_same_id_and_come_back_from_the_last_k_shards() {
    let vectors = vectors();
    let cases = vectors["buyuk_nesne"].as_array().unwrap();
    assert_eq!(cases.len(), 2);
    for case in cases {
        let label = case["etiket"].as_str().unwrap();
        let (n, k) = (number(&case["n"]), number(&case["k"]));
        let content = stream(label, number(&case["L"]));
        let msg_type = number(&case["msg_type"]) as u8;
        let encoded = encode(msg_type, n as u16, k as u16, &content).unwrap();
        assert_eq!(encoded.object_id, hex32(&case["object_id"]), "{label}");
        assert_eq!(usize::from(encoded.shape.s), number(&case["s"]));

        let last: Vec<usize> = (n - k..n).collect();
        let got = decode(
            &encoded.shape,
            &encoded.object_id,
            picked(&encoded.shards, &last),
            1 << 20,
        );
        assert_eq!(got.as_ref(), Ok(&content), "{label}");
        assert!(msg_type == MSG_BLOCK || msg_type == 3);
    }
}

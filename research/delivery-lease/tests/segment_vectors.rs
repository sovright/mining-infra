//! The independent V9 and V10 vectors, generated from the design note by a Python script
//! that does not read this crate. A mismatch here is a finding to report, and the
//! vectors are not to be changed to make it pass.

use delivery_lease::segment_frame::{
    FrameRules, body_id, empty_leaf, segment_leaf, segment_node, verify,
};
use serde_json::Value;

const VECTORS: &str = include_str!("vectors/cerceve.json");

fn hash_header(header: &[u8]) -> [u8; 32] {
    let hash = blake2b_simd::Params::new()
        .hash_length(32)
        .personal(b"ZcashBlockHash\0\0")
        .hash(header);
    hash.as_bytes().try_into().unwrap()
}

fn vectors() -> Value {
    serde_json::from_str(VECTORS).unwrap()
}

fn rules(vectors: &Value) -> FrameRules {
    let rules = &vectors["kurallar"];
    FrameRules::new(
        rules["segment_size"].as_u64().unwrap() as u32,
        rules["max_raw_len"].as_u64().unwrap(),
        rules["header_len"].as_u64().unwrap() as usize,
        hash_header,
    )
    .unwrap()
}

fn unhex(text: &str) -> Vec<u8> {
    (0..text.len() / 2)
        .map(|i| u8::from_str_radix(&text[2 * i..2 * i + 2], 16).unwrap())
        .collect()
}

fn hex32(value: &Value) -> [u8; 32] {
    unhex(value.as_str().unwrap()).try_into().unwrap()
}

#[test]
fn the_frame_bound_matches() {
    let vectors = vectors();
    assert_eq!(
        rules(&vectors).max_frame_len() as u64,
        vectors["kurallar"]["max_frame_len"].as_u64().unwrap()
    );
}

#[test]
fn every_valid_frame_passes_with_the_expected_identity() {
    let vectors = vectors();
    let rules = rules(&vectors);
    let mut frames = 0;
    for case in vectors["gecerli"].as_array().unwrap() {
        for (index, frame) in case["cerceveler"].as_object().unwrap() {
            let segment = verify(&unhex(frame.as_str().unwrap()), &rules)
                .unwrap_or_else(|error| panic!("{}, {index}: {error:?}", case["ad"]));
            assert_eq!(
                segment.key().body_id,
                hex32(&case["body_id"]),
                "{}",
                case["ad"]
            );
            assert_eq!(segment.key().block_hash, hex32(&case["block_hash"]));
            assert_eq!(segment.index(), index.parse::<u16>().unwrap());
            assert_eq!(u64::from(segment.count()), case["count"].as_u64().unwrap());
            assert_eq!(segment.raw_len(), case["raw_len"].as_u64().unwrap());
            frames += 1;
        }
    }
    assert!(frames >= 14, "the vectors were read: {frames}");
}

#[test]
fn every_invalid_frame_stops_at_the_expected_rule() {
    let vectors = vectors();
    let rules = rules(&vectors);
    let cases = vectors["olumsuz"].as_array().unwrap();
    assert!(cases.len() >= 20);
    for case in cases {
        let frame = match case["cerceve"].as_str() {
            Some(frame) => unhex(frame),
            None => vec![0; case["uzunluk"].as_u64().unwrap() as usize],
        };
        let error = verify(&frame, &rules).expect_err(case["ad"].as_str().unwrap());
        assert_eq!(
            error.rule(),
            case["beklenen_kural"].as_str().unwrap(),
            "{}",
            case["ad"]
        );
    }
}

/// Frames of a tree over the same bytes with non-empty padding. Earlier ones can pass
/// under a root of their own. The last segment never does, so no such set completes.
#[test]
fn a_tree_with_other_padding_never_gets_its_last_segment_through() {
    let vectors = vectors();
    let rules = rules(&vectors);
    let cases = vectors["kanonik_olmayan_dolgu"].as_array().unwrap();
    assert!(cases.len() >= 3);
    for case in cases {
        let name = case["ad"].as_str().unwrap();
        let forged_id = hex32(&case["kanonik_olmayan_body_id"]);
        assert_ne!(forged_id, hex32(&case["kanonik_body_id"]), "{name}");

        for (index, frame) in case["gecen"].as_object().unwrap() {
            let segment = verify(&unhex(frame.as_str().unwrap()), &rules)
                .unwrap_or_else(|error| panic!("{name}, {index}: {error:?}"));
            assert_eq!(segment.key().body_id, forged_id, "{name}, {index}");
        }

        let stopped = case["duran_F5a"].as_object().unwrap();
        for (index, frame) in stopped {
            let error = verify(&unhex(frame.as_str().unwrap()), &rules)
                .expect_err(&format!("{name}, {index}"));
            assert_eq!(error.rule(), "F5a", "{name}, {index}");
        }
        let last = case["count"].as_u64().unwrap() - 1;
        assert!(stopped.contains_key(&last.to_string()), "{name}");
    }
}

#[test]
fn the_hash_samples_match() {
    let vectors = vectors();
    let samples = &vectors["kimlikler"]["hash_ornekleri"];
    assert_eq!(empty_leaf(), hex32(&samples["segment_empty"]));
    assert_eq!(segment_leaf(1, 3, b"abc"), hex32(&samples["segment_leaf"]));
    assert_eq!(
        segment_node(&[0; 32], &[1; 32]),
        hex32(&samples["segment_node"])
    );
    assert_eq!(
        body_id(&[7; 32], 5, 1, &[9; 32]),
        hex32(&samples["body_id"])
    );
    assert_eq!(hash_header(b""), hex32(&samples["block_hash_bos"]));
}

#[test]
fn identities_separate_what_they_should() {
    let vectors = vectors();
    let rules = rules(&vectors);
    let identities = &vectors["kimlikler"];
    let honest = &identities["durust"];
    let (block_hash, root) = (hex32(&honest["block_hash"]), hex32(&honest["segment_root"]));
    let (raw_len, count) = (
        honest["raw_len"].as_u64().unwrap(),
        honest["count"].as_u64().unwrap() as u16,
    );
    let honest_id = body_id(&block_hash, raw_len, count, &root);
    assert_eq!(honest_id, hex32(&honest["body_id"]));

    let lies = &identities["metadata_yalanlari"];
    assert_eq!(
        body_id(&block_hash, raw_len + 1, count, &root),
        hex32(&lies["raw_len"])
    );
    assert_eq!(
        body_id(&block_hash, raw_len, count + 1, &root),
        hex32(&lies["count"])
    );
    assert_eq!(
        body_id(&[0; 32], raw_len, count, &root),
        hex32(&lies["block_hash"])
    );
    assert_ne!(honest_id, hex32(&identities["ayni_baslik_baska_govde"]));

    // A consistent body of the same header is valid, under an identity of its own.
    let own = &identities["kendi_koku_ile_tutarli"];
    let frame = unhex(own["cerceve_0"].as_str().unwrap());
    let segment = verify(&frame, &rules).unwrap();
    assert_eq!(segment.key().body_id, hex32(&own["body_id"]));
    assert_eq!(segment.key().block_hash, block_hash);
    assert_ne!(segment.key().body_id, honest_id);
}

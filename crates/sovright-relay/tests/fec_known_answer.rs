//! Known-answer tests for the FEC codec.
//!
//! The parity bytes are part of the wire format: every relay node must
//! produce the same shards for the same input. These hashes were recorded
//! with the unpatched crates.io `reed-solomon-erasure` 6.0.0 and pin the
//! output across changes to that dependency.

use sha2::{Digest, Sha256};
use sovright_relay::fec::{FecDecoder, FecEncoder};

fn sample(len: usize) -> Vec<u8> {
    (0..len).map(|i| (i.wrapping_mul(31) + 7) as u8).collect()
}

fn shards_digest(shards: &[Vec<u8>]) -> String {
    let mut h = Sha256::new();
    for s in shards {
        h.update((s.len() as u32).to_le_bytes());
        h.update(s);
    }
    hex::encode(h.finalize())
}

/// (data_shards, parity_shards, input_len, sha256 of all shards)
const VECTORS: &[(usize, usize, usize, &str)] = &[
    (
        1,
        1,
        1,
        "1fdc3a37fe2d195ca8f665812279fd191d435b2716febf9ecfd8416c0ce4f40f",
    ),
    (
        2,
        1,
        1500,
        "0faf7069a1f11e01a79c81014035d5aa3c0bd8482aba5599dc6e564eb4e5a5e0",
    ),
    (
        10,
        3,
        3001,
        "d61207d332e8e3341dcb31e94348ecea7af15463b7cbf2c04e4066e08e6375b4",
    ),
    (
        17,
        5,
        20000,
        "677bcc4888f751390fdb10f3716453244a94b6840fd8a4c33e842934cf0b243d",
    ),
    (
        32,
        8,
        65536,
        "834250d0a5eb41a2f9f882c330b6c7e6e403e8ae3c995138570650fe8119d00a",
    ),
];

#[test]
fn encoded_shards_match_recorded_bytes() {
    let mut changed = Vec::new();
    for &(d, p, len, want) in VECTORS {
        let shards = FecEncoder::new(d, p).unwrap().encode(&sample(len)).unwrap();
        let got = shards_digest(&shards);
        if got != want {
            changed.push(format!("({d}, {p}, {len}, \"{got}\"),"));
        }
    }
    assert!(
        changed.is_empty(),
        "shard bytes changed:\n{}",
        changed.join("\n")
    );
}

/// Every 4-shard erasure pattern of a 10+4 code: 1001 decodes on one
/// decoder. That is more distinct patterns than the library's 254-entry
/// decode-matrix cache, so it runs the cache's insert, hit and eviction
/// paths. A second pass decodes the same patterns again from the cache.
#[test]
fn every_erasure_pattern_recovers_through_the_decode_cache() {
    let (d, p) = (10, 4);
    let data = sample(4321);
    let shards = FecEncoder::new(d, p).unwrap().encode(&data).unwrap();
    let decoder = FecDecoder::new(d, p).unwrap();
    let n = d + p;

    let mut patterns = 0;
    for _pass in 0..2 {
        for a in 0..n {
            for b in a + 1..n {
                for c in b + 1..n {
                    for e in c + 1..n {
                        let mut input: Vec<Option<Vec<u8>>> =
                            shards.iter().cloned().map(Some).collect();
                        for &i in &[a, b, c, e] {
                            input[i] = None;
                        }
                        let out = decoder.decode(input, data.len()).unwrap();
                        assert_eq!(out, data, "pattern {a},{b},{c},{e}");
                        patterns += 1;
                    }
                }
            }
        }
    }
    assert_eq!(patterns, 2 * 1001);
}

#[test]
fn too_many_erasures_is_an_error() {
    let (d, p) = (10, 4);
    let data = sample(4321);
    let shards = FecEncoder::new(d, p).unwrap().encode(&data).unwrap();
    let mut input: Vec<Option<Vec<u8>>> = shards.into_iter().map(Some).collect();
    for slot in input.iter_mut().take(p + 1) {
        *slot = None;
    }
    assert!(
        FecDecoder::new(d, p)
            .unwrap()
            .decode(input, data.len())
            .is_err()
    );
}

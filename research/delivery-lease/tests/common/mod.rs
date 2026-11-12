//! A small honest sender for tests. It builds frames with the crate's own hash functions,
//! so it shows bookkeeping and not agreement with the design: that is what the
//! independent vectors in `tests/vectors` are for.
#![allow(dead_code)]

use delivery_lease::segment_frame::{
    FrameRules, SetKey, body_id, empty_leaf, segment_leaf, segment_node,
};
use sha2::{Digest, Sha256};

pub const SEGMENT: usize = 100;
const HEADER: usize = 16;

fn hash_header(header: &[u8]) -> [u8; 32] {
    Sha256::digest(header).into()
}

/// Small test values. The header hash is a stand-in here, and real values are in the
/// vector test.
pub fn rules() -> FrameRules {
    FrameRules::new(SEGMENT as u32, 64 * SEGMENT as u64, HEADER, hash_header).unwrap()
}

pub struct Body {
    pub key: SetKey,
    pub raw: Vec<u8>,
    pub root: [u8; 32],
    pub frames: Vec<Vec<u8>>,
}

pub fn levels(mut level: Vec<[u8; 32]>) -> Vec<Vec<[u8; 32]>> {
    level.resize(level.len().next_power_of_two(), empty_leaf());
    let mut levels = vec![level];
    while levels.last().unwrap().len() > 1 {
        let next = levels
            .last()
            .unwrap()
            .chunks(2)
            .map(|pair| segment_node(&pair[0], &pair[1]))
            .collect();
        levels.push(next);
    }
    levels
}

pub fn frame(
    index: u16,
    count: u16,
    raw_len: u64,
    block_hash: &[u8; 32],
    root: &[u8; 32],
    proof: &[[u8; 32]],
    payload: &[u8],
) -> Vec<u8> {
    let mut frame = Vec::new();
    frame.extend_from_slice(&0x4652_5347u32.to_be_bytes());
    frame.extend_from_slice(&[2, 0]);
    frame.extend_from_slice(&index.to_be_bytes());
    frame.extend_from_slice(&count.to_be_bytes());
    frame.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    frame.extend_from_slice(&raw_len.to_be_bytes());
    frame.extend_from_slice(block_hash);
    frame.extend_from_slice(root);
    for node in proof {
        frame.extend_from_slice(node);
    }
    frame.extend_from_slice(payload);
    frame
}

pub fn proof(levels: &[Vec<[u8; 32]>], index: usize) -> Vec<[u8; 32]> {
    (0..levels.len() - 1)
        .map(|level| levels[level][(index >> level) ^ 1])
        .collect()
}

/// `raw` split into honest frames. Its first bytes are the header.
pub fn body_of(raw: Vec<u8>) -> Body {
    padded_body(raw, &[])
}

/// As [`body_of`], with `padding` in place of the first empty leaves. Each frame is
/// consistent with its own root, so anything other than empty leaves makes a
/// non-canonical tree over the same bytes.
pub fn padded_body(raw: Vec<u8>, padding: &[[u8; 32]]) -> Body {
    let block_hash = hash_header(&raw[..HEADER]);
    let payloads: Vec<&[u8]> = raw.chunks(SEGMENT).collect();
    let count = payloads.len() as u16;
    let mut leaves: Vec<_> = payloads
        .iter()
        .enumerate()
        .map(|(i, payload)| segment_leaf(i as u16, count, payload))
        .collect();
    leaves.extend_from_slice(padding);
    let levels = levels(leaves);
    let root = levels.last().unwrap()[0];
    let raw_len = raw.len() as u64;
    let frames = payloads
        .iter()
        .enumerate()
        .map(|(i, payload)| {
            frame(
                i as u16,
                count,
                raw_len,
                &block_hash,
                &root,
                &proof(&levels, i),
                payload,
            )
        })
        .collect();
    let key = SetKey {
        block_hash,
        body_id: body_id(&block_hash, raw_len, count, &root),
    };
    Body {
        key,
        raw,
        root,
        frames,
    }
}

/// A body of `block`'s header, told apart by `fill`.
pub fn sized(block: u8, fill: u8, raw_len: usize) -> Body {
    let mut raw = vec![block; HEADER];
    raw.resize(raw_len, fill);
    body_of(raw)
}

pub fn body(block: u8, fill: u8) -> Body {
    sized(block, fill, 2 * SEGMENT)
}

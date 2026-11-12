//! Bodies in the design's real format: the full header, `zcash_block_hash`, and frames
//! carried in the fixed `13 / 10`. `SEG` is still the design's placeholder, and nothing
//! here is a real block or has been near a node.
#![allow(dead_code)]

use chunk_proof::object::{Encoded, MSG_RAW_SEGMENT, encode};
use delivery_lease::ObjectId;
use delivery_lease::segment_frame::{
    FrameRules, SetKey, body_id, check, empty_leaf, segment_leaf, segment_node,
};

pub const SEG: usize = 9584;
pub const HEADER: usize = 1487;
const MAX_BODY: u64 = 2_000_000;

fn zcash_block_hash(header: &[u8]) -> [u8; 32] {
    let hash = blake2b_simd::Params::new()
        .hash_length(32)
        .personal(b"ZcashBlockHash\0\0")
        .hash(header);
    hash.as_bytes().try_into().unwrap()
}

pub fn rules() -> FrameRules {
    FrameRules::new(SEG as u32, MAX_BODY, HEADER, zcash_block_hash).unwrap()
}

pub struct Body {
    pub raw: Vec<u8>,
    pub key: SetKey,
    pub root: [u8; 32],
    pub levels: Vec<Vec<[u8; 32]>>,
    pub frames: Vec<Vec<u8>>,
    pub objects: Vec<Encoded>,
    pub segments: Vec<ObjectId>,
}

fn levels_of(mut level: Vec<[u8; 32]>) -> Vec<Vec<[u8; 32]>> {
    level.resize(level.len().next_power_of_two(), empty_leaf());
    let mut levels = vec![level];
    while levels[levels.len() - 1].len() > 1 {
        let next = levels[levels.len() - 1]
            .chunks(2)
            .map(|pair| segment_node(&pair[0], &pair[1]))
            .collect();
        levels.push(next);
    }
    levels
}

fn frame_of(
    index: usize,
    count: usize,
    raw_len: usize,
    block_hash: &[u8; 32],
    root: &[u8; 32],
    levels: &[Vec<[u8; 32]>],
    payload: &[u8],
) -> Vec<u8> {
    let mut frame = Vec::with_capacity(86 + 32 * levels.len() + payload.len());
    frame.extend_from_slice(&0x4652_5347u32.to_be_bytes());
    frame.extend_from_slice(&[2, 0]);
    frame.extend_from_slice(&(index as u16).to_be_bytes());
    frame.extend_from_slice(&(count as u16).to_be_bytes());
    frame.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    frame.extend_from_slice(&(raw_len as u64).to_be_bytes());
    frame.extend_from_slice(block_hash);
    frame.extend_from_slice(root);
    for level in 0..levels.len() - 1 {
        frame.extend_from_slice(&levels[level][(index >> level) ^ 1]);
    }
    frame.extend_from_slice(payload);
    frame
}

pub fn carried(frame: &[u8]) -> Encoded {
    encode(MSG_RAW_SEGMENT, 13, 10, frame).expect("the fixed shape")
}

/// A body with a header made of `header` and the rest told apart by `fill`.
pub fn body(header: u8, fill: u8, raw_len: usize) -> Body {
    let mut raw = vec![header; HEADER];
    raw.extend((0..raw_len - HEADER).map(|at| fill.wrapping_add((at % 251) as u8)));
    let block_hash = zcash_block_hash(&raw[..HEADER]);
    let payloads: Vec<&[u8]> = raw.chunks(SEG).collect();
    let count = payloads.len();
    let levels = levels_of(
        payloads
            .iter()
            .enumerate()
            .map(|(at, payload)| segment_leaf(at as u16, count as u16, payload))
            .collect(),
    );
    let root = levels[levels.len() - 1][0];
    let frames: Vec<Vec<u8>> = payloads
        .iter()
        .enumerate()
        .map(|(at, payload)| frame_of(at, count, raw.len(), &block_hash, &root, &levels, payload))
        .collect();
    let objects = frames.iter().map(|frame| carried(frame)).collect();
    let segments = frames
        .iter()
        .map(|frame| check(frame, &rules()).unwrap().ledger_key())
        .collect();
    let key = SetKey {
        block_hash,
        body_id: body_id(&block_hash, raw.len() as u64, count as u16, &root),
    };
    Body {
        key,
        root,
        levels,
        frames,
        objects,
        segments,
        raw,
    }
}

/// The honest body's metadata, root and proof, around another body's payload.
pub fn forged_frame(honest: &Body, other: &Body, index: usize) -> Vec<u8> {
    let payload = &other.raw[index * SEG..((index + 1) * SEG).min(other.raw.len())];
    frame_of(
        index,
        honest.frames.len(),
        honest.raw.len(),
        &honest.key.block_hash,
        &honest.root,
        &honest.levels,
        payload,
    )
}

//! Real frames for the segment prototype, written out from the design note.

use chunk_proof::object::{Encoded, MSG_RAW_SEGMENT, encode};
use delivery_lease::segment_frame::{FrameRules, body_id, empty_leaf, segment_leaf, segment_node};
use sha2::{Digest, Sha256};

pub const SEGMENT: usize = 100;
pub const HEADER: usize = 16;

fn hash_header(header: &[u8]) -> [u8; 32] {
    Sha256::digest(header).into()
}

pub fn frame_rules() -> FrameRules {
    FrameRules::new(SEGMENT as u32, 64 * SEGMENT as u64, HEADER, hash_header).unwrap()
}

/// The frames of a body of two whole segments.
pub fn frames_of(raw: &[u8]) -> Vec<Vec<u8>> {
    assert_eq!(raw.len(), 2 * SEGMENT);
    let block_hash = hash_header(&raw[..HEADER]);
    let payloads: Vec<&[u8]> = raw.chunks(SEGMENT).collect();
    let leaves: Vec<[u8; 32]> = payloads
        .iter()
        .enumerate()
        .map(|(at, payload)| segment_leaf(at as u16, 2, payload))
        .collect();
    assert_ne!(leaves[0], empty_leaf());
    let root = segment_node(&leaves[0], &leaves[1]);
    assert_ne!(body_id(&block_hash, raw.len() as u64, 2, &root), root);
    payloads
        .iter()
        .enumerate()
        .map(|(at, payload)| {
            let mut frame = Vec::new();
            frame.extend_from_slice(&0x4652_5347u32.to_be_bytes());
            frame.extend_from_slice(&[2, 0]);
            frame.extend_from_slice(&(at as u16).to_be_bytes());
            frame.extend_from_slice(&2u16.to_be_bytes());
            frame.extend_from_slice(&(payload.len() as u32).to_be_bytes());
            frame.extend_from_slice(&(raw.len() as u64).to_be_bytes());
            frame.extend_from_slice(&block_hash);
            frame.extend_from_slice(&root);
            frame.extend_from_slice(&leaves[1 - at]);
            frame.extend_from_slice(payload);
            frame
        })
        .collect()
}

pub fn body(fill: u8) -> Vec<u8> {
    let mut raw = vec![1; HEADER];
    raw.resize(2 * SEGMENT, fill);
    raw
}

pub fn carried(frame: &[u8]) -> Encoded {
    encode(MSG_RAW_SEGMENT, 6, 4, frame).expect("a valid shape")
}

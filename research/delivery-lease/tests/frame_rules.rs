//! What the constructor refuses, how far the padding rule reaches, and frames of no fixed
//! shape under valid rules. A panic fails these, and the seeds are fixed.

mod common;

use common::{SEGMENT, body, frame, padded_body, rules};
use delivery_lease::segment_frame::{
    FrameError, FrameRules, InvalidRules, empty_leaf, segment_leaf, segment_node, verify,
};
use sha2::{Digest, Sha256};

fn hash_header(header: &[u8]) -> [u8; 32] {
    Sha256::digest(header).into()
}

fn refused(segment_size: u32, max_raw_len: u64, header_len: usize) -> Option<&'static str> {
    FrameRules::new(segment_size, max_raw_len, header_len, hash_header)
        .err()
        .map(|InvalidRules(field)| field)
}

/// A small generator, so a failure repeats.
struct Random(u64);

impl Random {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }

    fn below(&mut self, limit: usize) -> usize {
        (self.next() % limit as u64) as usize
    }

    fn bytes(&mut self, len: usize) -> Vec<u8> {
        (0..len).map(|_| self.next() as u8).collect()
    }

    fn node(&mut self) -> [u8; 32] {
        self.bytes(32).try_into().unwrap()
    }
}

// The constructor.

#[test]
fn settings_that_cannot_work_are_refused() {
    assert_eq!(refused(0, 1000, 16), Some("segment_size"));
    assert_eq!(refused(0, 0, 0), Some("segment_size"));

    assert_eq!(refused(100, 1000, 0), Some("header_len"));
    assert_eq!(refused(100, 1000, 101), Some("header_len"));
    assert_eq!(refused(100, 1000, usize::MAX), Some("header_len"));

    assert_eq!(refused(100, 0, 16), Some("max_raw_len"));
    assert_eq!(refused(100, 15, 16), Some("max_raw_len"));

    assert_eq!(refused(1, 65_536, 1), Some("segment_count"));
    assert_eq!(refused(100, 6_553_501, 16), Some("segment_count"));
    assert_eq!(refused(1, u64::MAX, 1), Some("segment_count"));
    assert_eq!(refused(u32::MAX, u64::MAX, 1), Some("segment_count"));
}

#[test]
fn the_edges_that_can_work_are_kept() {
    assert_eq!(refused(100, 16, 16), None, "a body of just a header");
    assert_eq!(refused(100, 1000, 100), None, "a header filling a segment");
    assert_eq!(refused(1, 65_535, 1), None);
    assert_eq!(refused(100, 6_553_500, 16), None, "the last count there is");

    let widest = u64::from(u16::MAX) * u64::from(u32::MAX);
    let rules = FrameRules::new(u32::MAX, widest, 1, hash_header).unwrap();
    assert_eq!(rules.max_frame_len(), 86 + 32 * 16 + u32::MAX as usize);
}

// The padding rule.

fn tampered_leaf() -> [u8; 32] {
    segment_leaf(u16::MAX, u16::MAX, b"not padding")
}

fn raw_of(count: usize) -> Vec<u8> {
    let mut raw = vec![1; 16];
    raw.resize(count * SEGMENT - 7, 2);
    raw
}

/// The claim the design leans on, tried on every shape up to 33 segments: any change to
/// any padding leaf stops the last segment, under its own consistent root.
#[test]
fn every_padding_leaf_is_covered_by_the_last_segment() {
    let rules = rules();
    let mut shapes = 0;
    for count in 1..=33usize {
        let canonical = padded_body(raw_of(count), &[]);
        assert!(verify(canonical.frames.last().unwrap(), &rules).is_ok());

        for changed in count..count.next_power_of_two() {
            let mut padding = vec![empty_leaf(); changed - count];
            padding.push(tampered_leaf());
            let forged = padded_body(raw_of(count), &padding);

            assert_ne!(forged.root, canonical.root);
            assert_eq!(
                verify(forged.frames.last().unwrap(), &rules).err(),
                Some(FrameError::Padding),
                "count {count}, padding leaf {changed}"
            );
            shapes += 1;
        }
    }
    assert!(shapes > 150, "the shapes were tried: {shapes}");
}

/// The same with whole subtrees: a node the padding could not have made, at any level.
#[test]
fn a_padding_sibling_of_any_height_is_checked() {
    let rules = rules();
    for count in [3usize, 5, 9, 17, 33] {
        let honest = padded_body(raw_of(count), &[]);
        let (index, depth) = (
            count - 1,
            count.next_power_of_two().trailing_zeros() as usize,
        );
        let payload_at = 86 + 32 * depth;
        for level in 0..depth {
            if (index >> level) & 1 == 1 {
                continue;
            }
            let mut forged = honest.frames[index].clone();
            forged[86 + 32 * level] ^= 1;
            assert_eq!(
                verify(&forged, &rules).err(),
                Some(FrameError::Padding),
                "count {count}, level {level}"
            );
        }
        assert_eq!(honest.frames[index].len(), payload_at + SEGMENT - 7);
    }
}

/// What one frame cannot show, kept visible. A sibling that mixes real leaves and
/// padding cannot be opened, so an earlier segment passes under a root of its own.
#[test]
fn known_gap_an_earlier_segment_passes_under_a_non_canonical_root() {
    let rules = rules();
    let canonical = padded_body(raw_of(3), &[]);
    let forged = padded_body(raw_of(3), &[tampered_leaf()]);

    for index in 0..2 {
        let segment = verify(&forged.frames[index], &rules).unwrap();
        assert_eq!(segment.key(), forged.key);
        assert_ne!(segment.key(), canonical.key);
    }
    assert_eq!(
        verify(&forged.frames[2], &rules).err(),
        Some(FrameError::Padding)
    );
}

/// A wrong sibling inside the real part of the tree is the proof's business, and a
/// sibling that is real on one side of the tree is not taken for padding.
#[test]
fn only_siblings_wholly_in_padding_are_held_to_the_empty_subtree() {
    let rules = rules();
    let honest = padded_body(raw_of(3), &[]);

    // Segment 0's sibling at level 1 mixes segment 2 with padding.
    let mut mixed = honest.frames[0].clone();
    mixed[86 + 32] ^= 1;
    assert_eq!(verify(&mixed, &rules).err(), Some(FrameError::Proof));

    // Segment 1's sibling at level 0 is segment 0.
    let mut real = honest.frames[1].clone();
    real[86] ^= 1;
    assert_eq!(verify(&real, &rules).err(), Some(FrameError::Proof));
}

/// The deepest proof there is, with no tree behind it. Segment 65534 of 65535: its first
/// sibling is padding, and the rest are left siblings that real segments would fill.
#[test]
fn the_deepest_proof_works_at_every_level() {
    let rules = FrameRules::new(1, 65_535, 1, hash_header).unwrap();
    let mut random = Random(0x1357);
    let (index, count) = (65_534u16, 65_535u16);

    let mut siblings = vec![empty_leaf()];
    siblings.extend((1..16).map(|_| random.node()));
    let mut root = segment_leaf(index, count, b"x");
    root = segment_node(&root, &siblings[0]);
    for sibling in &siblings[1..] {
        root = segment_node(sibling, &root);
    }

    let raw_len = u64::from(count);
    let good = frame(index, count, raw_len, &[7; 32], &root, &siblings, b"x");
    assert!(verify(&good, &rules).is_ok());

    siblings[0] = random.node();
    let bad = frame(index, count, raw_len, &[7; 32], &root, &siblings, b"x");
    assert_eq!(verify(&bad, &rules).err(), Some(FrameError::Padding));
}

// Frames of no fixed shape, under rules at the edges.

fn edge_rules() -> Vec<FrameRules> {
    vec![
        rules(),
        FrameRules::new(1, 1, 1, hash_header).unwrap(),
        FrameRules::new(1, 65_535, 1, hash_header).unwrap(),
        FrameRules::new(7, 7, 7, hash_header).unwrap(),
        FrameRules::new(64, 65_535 * 64, 32, hash_header).unwrap(),
        FrameRules::new(
            u32::MAX,
            u64::from(u16::MAX) * u64::from(u32::MAX),
            1,
            hash_header,
        )
        .unwrap(),
    ]
}

const FIELDS: [u64; 8] = [
    0,
    1,
    2,
    u16::MAX as u64 - 1,
    u16::MAX as u64,
    u32::MAX as u64,
    u32::MAX as u64 + 1,
    u64::MAX,
];

fn header(index: u16, count: u16, length: u32, raw_len: u64) -> Vec<u8> {
    frame(index, count, 0, &[1; 32], &[2; 32], &[], &[])
        .into_iter()
        .take(86)
        .enumerate()
        .map(|(at, byte)| match at {
            10..=13 => length.to_be_bytes()[at - 10],
            14..=21 => raw_len.to_be_bytes()[at - 14],
            _ => byte,
        })
        .collect()
}

#[test]
fn random_bytes_of_any_length_are_answered() {
    let mut random = Random(0x2468);
    for rules in edge_rules() {
        for _ in 0..2_000 {
            let len = random.below(rules.max_frame_len().min(4096) + 8);
            assert!(verify(&random.bytes(len), &rules).is_err());
        }
    }
}

/// A valid format with the fields at their edges, so the arithmetic after F1 runs on the
/// values it would overflow on. Lengths are made to agree often enough to get past F2.
#[test]
fn extreme_fields_are_answered() {
    let mut random = Random(0x3579);
    for rules in edge_rules() {
        for &index in &FIELDS {
            for &count in &FIELDS {
                for &length in &FIELDS {
                    for &raw_len in &FIELDS {
                        let (index, count) = (index as u16, count as u16);
                        let mut frame = header(index, count, length as u32, raw_len);
                        let depth = usize::from(count).next_power_of_two().trailing_zeros();
                        let tail = 32 * depth as usize + (length as usize).min(64);
                        frame.extend_from_slice(&random.bytes(tail));
                        let _ = verify(&frame, &rules);
                    }
                }
            }
        }
    }
}

/// Everything a sender controls, one honest frame at a time: every truncation, and every
/// byte changed. Nothing but the honest frame itself may pass as that frame's identity.
#[test]
fn honest_frames_damaged_anywhere_are_answered() {
    let rules = rules();
    let honest = body(1, 10);
    let mut random = Random(0x4680);
    for frame in &honest.frames {
        let segment = verify(frame, &rules).unwrap();
        for len in 0..frame.len() {
            assert!(verify(&frame[..len], &rules).is_err());
        }
        for at in 0..frame.len() {
            let mut damaged = frame.clone();
            damaged[at] ^= 1 + random.below(255) as u8;
            if let Ok(passed) = verify(&damaged, &rules) {
                assert_ne!(passed.key(), segment.key(), "byte {at} changed nothing");
            }
        }
    }
}

/// Honest frames pass under every shape, so the tests above are not passing because
/// nothing does.
#[test]
fn honest_frames_of_every_shape_pass() {
    let rules = rules();
    for count in 1..=33usize {
        let honest = padded_body(raw_of(count), &[]);
        for (index, frame) in honest.frames.iter().enumerate() {
            let segment = verify(frame, &rules).unwrap();
            assert_eq!(usize::from(segment.index()), index);
            assert_eq!(segment.key(), honest.key);
        }
    }
}

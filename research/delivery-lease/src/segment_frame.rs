//! The raw segment frame of the #130 PR B design note (Ek A, section 3), for research.
//! It carries no wire format into any product path.
//!
//! [`check`] reads a borrowed frame and allocates nothing, so a bad frame costs at most
//! the hashing of one bounded frame, and a good one can wait for a reservation before
//! anything is copied. [`verify`] is that and the copy, for callers with no ledger. This
//! is about these functions and not a whole path: the frame is the caller's allocation.
//!
//! What a pass means: this payload, at this index, belongs to the tree under
//! `segment_root`, and `body_id` commits to that root and the metadata. It does not mean
//! the body is the block. A sender can build a tree of its own over any bytes and any
//! real header, and that passes here as a different `body_id`. Telling such a body from
//! the real one is for strict validation and the node. Segment 0 alone ties `block_hash`
//! to a header, so a set is only anchored once segment 0 is in it.
//!
//! How far a pass goes on the padding of a tree that is not full:
//!
//! - One frame shows only the siblings that lie wholly in padding. A sibling that mixes
//!   real leaves and padding cannot be opened from here, so a non-canonical root can pass.
//! - The last segment's right siblings cover every padding leaf, and all of them lie
//!   wholly in padding. If that frame passes, the root is canonical.
//! - A complete set contains that frame, so its root is canonical and its `body_id` is
//!   the only one those bytes have. Recomputing the root at assembly would add nothing.
//! - A partial set shows nothing. Earlier segments of a non-canonical root sit in a set
//!   of their own, which can never complete and holds capacity until it is dropped.

use sha2::{Digest, Sha256};

const MAGIC: u32 = 0x4652_5347;
const VERSION: u8 = 2;
const FIXED_LEN: usize = 86;
const NODE_LEN: usize = 32;
/// `count` is a `u16`, so no proof has more siblings than this.
const MAX_DEPTH: usize = 16;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct SetKey {
    pub block_hash: [u8; 32],
    pub body_id: [u8; 32],
}

/// The values the design leaves open. `segment_size` is one constant per format in the
/// design, and `hash_header` is passed in so this crate needs no relay dependency.
///
/// The fields are private so that [`FrameRules::new`] is the only way to get one, and
/// [`verify`] can rely on what it checked.
#[derive(Clone, Copy, Debug)]
pub struct FrameRules {
    segment_size: u32,
    max_raw_len: u64,
    header_len: usize,
    hash_header: fn(&[u8]) -> [u8; 32],
    max_frame_len: usize,
    empty_subtrees: [[u8; 32]; MAX_DEPTH],
}

/// A setting that cannot work, named. Settings are not network input, but one bad value
/// would otherwise turn every frame into a panic or a refusal.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InvalidRules(pub &'static str);

impl FrameRules {
    pub fn new(
        segment_size: u32,
        max_raw_len: u64,
        header_len: usize,
        hash_header: fn(&[u8]) -> [u8; 32],
    ) -> Result<Self, InvalidRules> {
        if segment_size == 0 {
            return Err(InvalidRules("segment_size"));
        }
        // The header is read from segment 0, so it has to fit in one.
        let header = u32::try_from(header_len)
            .ok()
            .filter(|header| (1..=segment_size).contains(header))
            .ok_or(InvalidRules("header_len"))?;
        if max_raw_len < u64::from(header) || usize::try_from(max_raw_len).is_err() {
            return Err(InvalidRules("max_raw_len"));
        }
        let count = max_raw_len.div_ceil(u64::from(segment_size));
        if count > u64::from(u16::MAX) {
            return Err(InvalidRules("segment_count"));
        }
        let max_frame_len = usize::try_from(segment_size)
            .ok()
            .and_then(|size| size.checked_add(FIXED_LEN + NODE_LEN * ceil_log2(count)))
            .ok_or(InvalidRules("max_frame_len"))?;

        let mut empty_subtrees = [empty_leaf(); MAX_DEPTH];
        for level in 1..MAX_DEPTH {
            let below = empty_subtrees[level - 1];
            empty_subtrees[level] = segment_node(&below, &below);
        }
        Ok(Self {
            segment_size,
            max_raw_len,
            header_len,
            hash_header,
            max_frame_len,
            empty_subtrees,
        })
    }

    pub fn max_frame_len(&self) -> usize {
        self.max_frame_len
    }
}

/// Every frame of one body, for a sender. `None` if the body does not fit `rules`.
pub fn build(raw: &[u8], rules: &FrameRules) -> Option<Vec<Vec<u8>>> {
    let raw_len = u64::try_from(raw.len()).ok()?;
    if raw.len() < rules.header_len || raw_len > rules.max_raw_len {
        return None;
    }
    let block_hash = (rules.hash_header)(&raw[..rules.header_len]);
    let payloads: Vec<&[u8]> = raw
        .chunks(usize::try_from(rules.segment_size).ok()?)
        .collect();
    let count = u16::try_from(payloads.len()).ok()?;

    let mut level: Vec<[u8; 32]> = payloads
        .iter()
        .zip(0u16..)
        .map(|(payload, index)| segment_leaf(index, count, payload))
        .collect();
    level.resize(level.len().next_power_of_two(), empty_leaf());
    let mut levels = vec![level];
    while levels[levels.len() - 1].len() > 1 {
        let next = levels[levels.len() - 1]
            .chunks(2)
            .map(|pair| segment_node(&pair[0], &pair[1]))
            .collect();
        levels.push(next);
    }
    let root = levels[levels.len() - 1][0];

    let mut frames = Vec::with_capacity(payloads.len());
    for (index, payload) in payloads.iter().enumerate() {
        let mut frame = Vec::with_capacity(FIXED_LEN + NODE_LEN * levels.len() + payload.len());
        frame.extend_from_slice(&MAGIC.to_be_bytes());
        frame.extend_from_slice(&[VERSION, 0]);
        frame.extend_from_slice(&u16::try_from(index).ok()?.to_be_bytes());
        frame.extend_from_slice(&count.to_be_bytes());
        frame.extend_from_slice(&u32::try_from(payload.len()).ok()?.to_be_bytes());
        frame.extend_from_slice(&raw_len.to_be_bytes());
        frame.extend_from_slice(&block_hash);
        frame.extend_from_slice(&root);
        for (depth, level) in levels[..levels.len() - 1].iter().enumerate() {
            frame.extend_from_slice(&level[(index >> depth) ^ 1]);
        }
        frame.extend_from_slice(payload);
        frames.push(frame);
    }
    Some(frames)
}

/// The first rule a frame broke, in the design's order. F6 computes and cannot fail.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FrameError {
    /// F0
    TooLong,
    /// F1
    Format,
    /// F2
    Length,
    /// F3
    Shape,
    /// F4
    SegmentLength,
    /// F5a
    Padding,
    /// F5
    Proof,
    /// F7
    Header,
}

impl FrameError {
    pub fn rule(self) -> &'static str {
        match self {
            Self::TooLong => "F0",
            Self::Format => "F1",
            Self::Length => "F2",
            Self::Shape => "F3",
            Self::SegmentLength => "F4",
            Self::Padding => "F5a",
            Self::Proof => "F5",
            Self::Header => "F7",
        }
    }
}

fn format_tag(tag: &str) -> [u8; 64] {
    // Tags are short ASCII, and this keeps a failed frame free of allocation.
    let mut out = [0u8; 64];
    out[..12].copy_from_slice(b"sovright/v2/");
    out[12..12 + tag.len()].copy_from_slice(tag.as_bytes());
    out
}

fn finish_tagged(tag: &str, parts: &[&[u8]]) -> [u8; 32] {
    let full = format_tag(tag);
    let len = 12 + tag.len();
    let mut hash = Sha256::new();
    hash.update([len as u8]);
    hash.update(&full[..len]);
    for part in parts {
        hash.update(part);
    }
    hash.finalize().into()
}

pub fn empty_leaf() -> [u8; 32] {
    finish_tagged("segment-empty", &[])
}

pub fn segment_leaf(index: u16, count: u16, payload: &[u8]) -> [u8; 32] {
    finish_tagged(
        "segment-leaf",
        &[
            &index.to_be_bytes(),
            &count.to_be_bytes(),
            &(payload.len() as u32).to_be_bytes(),
            payload,
        ],
    )
}

pub fn segment_node(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    finish_tagged("segment-node", &[left, right])
}

pub fn body_id(block_hash: &[u8; 32], raw_len: u64, count: u16, root: &[u8; 32]) -> [u8; 32] {
    finish_tagged(
        "body-id",
        &[
            block_hash,
            &raw_len.to_be_bytes(),
            &count.to_be_bytes(),
            root,
        ],
    )
}

fn ceil_log2(value: u64) -> usize {
    value.next_power_of_two().trailing_zeros() as usize
}

fn array<const N: usize>(bytes: &[u8]) -> [u8; N] {
    let mut out = [0u8; N];
    out.copy_from_slice(bytes);
    out
}

fn segment_key(key: &SetKey, index: u16) -> [u8; 32] {
    finish_tagged("segment-key", &[&key.body_id, &index.to_be_bytes()])
}

/// A frame that passed every rule, with its payload still in the caller's buffer.
#[derive(Debug)]
pub struct CheckedFrame<'a> {
    key: SetKey,
    index: u16,
    count: u16,
    raw_len: u64,
    payload: &'a [u8],
}

impl CheckedFrame<'_> {
    pub fn key(&self) -> SetKey {
        self.key
    }

    pub fn count(&self) -> u16 {
        self.count
    }

    pub fn payload_len(&self) -> usize {
        self.payload.len()
    }

    /// See [`VerifiedSegment::ledger_key`].
    pub fn ledger_key(&self) -> [u8; 32] {
        segment_key(&self.key, self.index)
    }

    /// The one copy of the payload. A caller with a ledger makes it under a reservation.
    pub fn into_segment(self) -> VerifiedSegment {
        VerifiedSegment {
            key: self.key,
            index: self.index,
            count: self.count,
            raw_len: self.raw_len,
            payload: self.payload.to_vec(),
        }
    }
}

/// A segment that passed [`check`] and was copied. Its fields are private and nothing else builds one,
/// so holding this is the evidence that the rules ran.
///
/// ```compile_fail
/// use delivery_lease::segment_frame::{SetKey, VerifiedSegment};
/// let key = SetKey { block_hash: [0; 32], body_id: [0; 32] };
/// let forged = VerifiedSegment { key, index: 0, count: 1, raw_len: 1, payload: vec![0] };
/// ```
#[derive(Debug)]
pub struct VerifiedSegment {
    key: SetKey,
    index: u16,
    count: u16,
    raw_len: u64,
    payload: Vec<u8>,
}

impl VerifiedSegment {
    pub fn key(&self) -> SetKey {
        self.key
    }

    pub fn index(&self) -> u16 {
        self.index
    }

    pub fn count(&self) -> u16 {
        self.count
    }

    pub fn raw_len(&self) -> u64 {
        self.raw_len
    }

    pub fn payload(&self) -> &[u8] {
        &self.payload
    }

    /// This segment's name in the delivery ledger. A research label: the design's own
    /// object id belongs to the chunk layer, which is not built here.
    pub fn ledger_key(&self) -> [u8; 32] {
        segment_key(&self.key, self.index)
    }

    pub(super) fn into_payload(self) -> Vec<u8> {
        self.payload
    }
}

/// Every rule in order. Nothing is allocated.
pub fn check<'a>(frame: &'a [u8], rules: &FrameRules) -> Result<CheckedFrame<'a>, FrameError> {
    if frame.len() > rules.max_frame_len {
        return Err(FrameError::TooLong);
    }
    if frame.len() < FIXED_LEN {
        return Err(FrameError::Length);
    }
    if u32::from_be_bytes(array(&frame[..4])) != MAGIC || frame[4] != VERSION || frame[5] != 0 {
        return Err(FrameError::Format);
    }
    let index = u16::from_be_bytes(array(&frame[6..8]));
    let count = u16::from_be_bytes(array(&frame[8..10]));
    let length = u32::from_be_bytes(array(&frame[10..14])) as usize;
    let raw_len = u64::from_be_bytes(array(&frame[14..22]));
    let block_hash: [u8; 32] = array(&frame[22..54]);
    let root: [u8; 32] = array(&frame[54..86]);

    let depth = if count == 0 {
        0
    } else {
        ceil_log2(u64::from(count))
    };
    let payload_at = FIXED_LEN + NODE_LEN * depth;
    if payload_at.checked_add(length) != Some(frame.len()) {
        return Err(FrameError::Length);
    }

    let size = u64::from(rules.segment_size);
    if count == 0
        || index >= count
        || raw_len == 0
        || raw_len > rules.max_raw_len
        || u64::from(count) != raw_len.div_ceil(size)
    {
        return Err(FrameError::Shape);
    }

    let expected = if index + 1 < count {
        size
    } else {
        raw_len - u64::from(count - 1) * size
    };
    if length as u64 != expected {
        return Err(FrameError::SegmentLength);
    }

    let (siblings, _) = frame[FIXED_LEN..payload_at].as_chunks::<NODE_LEN>();
    for (level, sibling) in siblings.iter().enumerate() {
        let first_leaf = ((usize::from(index) >> level) ^ 1) << level;
        if first_leaf >= usize::from(count) && *sibling != rules.empty_subtrees[level] {
            return Err(FrameError::Padding);
        }
    }

    let payload = &frame[payload_at..];
    let mut node = segment_leaf(index, count, payload);
    for (level, sibling) in siblings.iter().enumerate() {
        node = if (index >> level) & 1 == 0 {
            segment_node(&node, sibling)
        } else {
            segment_node(sibling, &node)
        };
    }
    if node != root {
        return Err(FrameError::Proof);
    }

    if index == 0 {
        let header = payload.get(..rules.header_len).ok_or(FrameError::Header)?;
        if (rules.hash_header)(header) != block_hash {
            return Err(FrameError::Header);
        }
    }

    Ok(CheckedFrame {
        key: SetKey {
            block_hash,
            body_id: body_id(&block_hash, raw_len, count, &root),
        },
        index,
        count,
        raw_len,
        payload,
    })
}

/// [`check`] and the copy.
pub fn verify(frame: &[u8], rules: &FrameRules) -> Result<VerifiedSegment, FrameError> {
    check(frame, rules).map(CheckedFrame::into_segment)
}

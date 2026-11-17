//! The canonical object of Ek A 2.1 and its decode, D1 to D4. Pure: no state, no budget.
//!
//! D5, the type's strict parser, is the caller's. Passing here is transport canonicality
//! and nothing about whether the content parses.

use reed_solomon_erasure::galois_8::ReedSolomon;

use super::tree::{Node, chunk_leaf, levels, proof, root};

pub const FORMAT: u8 = 1;
pub const MSG_BLOCK: u8 = 0;
pub const MSG_RAW_SEGMENT: u8 = 3;
pub const MSG_SKELETON: u8 = 4;
/// `n` is at most this, a limit of the code and not a choice.
pub const MAX_SHARDS: u16 = 256;

const LENGTH_LEN: usize = 4;

/// Which shapes a receiver takes, the A2 rule that Ek A leaves open. A research choice,
/// and no protocol decision.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Profile {
    /// The fixed `13 / 10` and the formulas in `fec/mod.rs` today: `max(1, ceil(k / 8))`
    /// parity, and `max(2, ceil(k / 4))` for a skeleton.
    Research,
    /// The one shape a bound sender uses for a segment, `13 / 10`. What a datagram declares
    /// here stays near what it costs to send, and a frame has one encoding and so one id.
    BoundSegment,
    /// Whatever the format can express, for vectors and for adversarial tests. Nothing
    /// bounds the cost of this one but the budget.
    EveryShape,
}

impl Profile {
    pub fn allows(self, shape: &Shape) -> bool {
        let fixed = shape.n == 13 && shape.k == 10;
        let parity = match shape.msg_type {
            MSG_SKELETON => shape.k.div_ceil(4).max(2),
            _ => shape.k.div_ceil(8).max(1),
        };
        match self {
            Self::Research => fixed || shape.n == shape.k + parity,
            Self::BoundSegment => fixed && shape.msg_type == MSG_RAW_SEGMENT,
            Self::EveryShape => true,
        }
    }
}

/// Everything a leaf commits to apart from its index and bytes, so two chunks of one
/// object agree on all of it. `format` is a single value here.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Shape {
    pub msg_type: u8,
    pub n: u16,
    pub k: u16,
    pub s: u16,
}

impl Shape {
    /// A2's shape rule. Which `(k, n - k)` profiles are allowed is still open in the design.
    pub fn is_valid(&self) -> bool {
        matches!(self.msg_type, MSG_BLOCK | MSG_RAW_SEGMENT | MSG_SKELETON)
            && self.k >= 1
            && self.k < self.n
            && self.n <= MAX_SHARDS
            && self.s >= 1
    }

    fn sizes(&self) -> (usize, usize, usize) {
        let (n, k) = (usize::from(self.n), usize::from(self.k));
        (n, k, usize::from(self.s))
    }
}

/// What one open object can hold: `k` shards and its slot list. Held from the first chunk,
/// so an object that was let in can always finish.
pub fn held_bytes(shape: &Shape) -> usize {
    let (n, k, s) = shape.sizes();
    k * s + n * size_of::<Option<Vec<u8>>>()
}

/// The shortest content this shape can carry by D2: anything shorter would fit in a smaller
/// `s`, and no canonical sender does that.
pub fn least_content(shape: &Shape) -> usize {
    let (_, k, s) = shape.sizes();
    (k * (s - 1) + 1).saturating_sub(LENGTH_LEN).max(1)
}

/// What the budget charges for one [`decode`], on top of the held shards. Each term is
/// read from this file and from `reed-solomon-erasure 6.0.0` and `lru 0.7.8` as pinned,
/// and a new version of either can make it wrong. It is an estimate with its reasons
/// written down and measurements behind it in `tests/memory.rs`, not a proven bound.
///
/// - `buffers`: the concatenated data, the content copy, recovered shards, parity.
/// - `tree`: the leaves and the working level of [`root`].
/// - `matrices`: the code's build peaks at `max(nk + 4k², 2nk + 2k²)`, and a decode at
///   `nk + 4k²`, both under `3(nk + k²)`.
/// - `lists`: `k` and `n - k` list heads here, and the library's slice and index lists.
/// - `CODEC_FIXED`: the library's cache table for 254 entries, and one entry.
pub fn work_bytes(shape: &Shape) -> usize {
    const CODEC_FIXED: usize = 16 * 1024;
    const LIST_ENTRY: usize = size_of::<Vec<u8>>();
    let (n, k, s) = shape.sizes();
    let parity = n - k;
    let buffers = (2 * k + k.min(parity) + parity) * s;
    let lists = 4 * n * LIST_ENTRY;
    let tree = 2 * n.next_power_of_two() * size_of::<Node>();
    let matrices = 3 * (n * k + k * k);
    buffers + lists + tree + matrices + CODEC_FIXED
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ObjectError {
    /// D1
    Decode,
    /// D2, the structural part. A canonical sender does not do this.
    Structure,
    /// D2, `max(msg_type)`. This depends on the binary, so an honest object can hit it.
    ContentLimit,
    /// D3
    Padding,
    /// D4
    Root,
}

impl ObjectError {
    pub fn rule(self) -> &'static str {
        match self {
            Self::Decode => "D1",
            Self::Structure => "D2T",
            Self::ContentLimit => "D2I",
            Self::Padding => "D3",
            Self::Root => "D4",
        }
    }
}

/// A sender's view of an object.
#[derive(Clone, Debug)]
pub struct Encoded {
    pub shape: Shape,
    pub object_id: Node,
    pub shards: Vec<Vec<u8>>,
    pub proofs: Vec<Vec<Node>>,
}

/// `None` if the object has no valid shape. This is the sender's side, for tests.
pub fn encode(msg_type: u8, n: u16, k: u16, content: &[u8]) -> Option<Encoded> {
    let length = u32::try_from(content.len()).ok()?;
    let framed = content.len().checked_add(LENGTH_LEN)?;
    let s = u16::try_from(framed.div_ceil(usize::from(k.max(1)))).ok()?;
    let shape = Shape { msg_type, n, k, s };
    if !shape.is_valid() {
        return None;
    }
    let (n, k, s) = shape.sizes();

    let mut data = Vec::with_capacity(k * s);
    data.extend_from_slice(&length.to_le_bytes());
    data.extend_from_slice(content);
    data.resize(k * s, 0);
    let mut shards: Vec<Vec<u8>> = data.chunks(s).map(<[u8]>::to_vec).collect();
    let mut parity = vec![vec![0u8; s]; n - k];
    ReedSolomon::new(k, n - k)
        .ok()?
        .encode_sep(&shards, &mut parity)
        .ok()?;
    shards.append(&mut parity);

    let levels = levels(leaves_of(&shape, &shards));
    let object_id = levels[levels.len() - 1][0];
    let proofs = (0..n).map(|index| proof(&levels, index)).collect();
    Some(Encoded {
        shape,
        object_id,
        shards,
        proofs,
    })
}

fn leaves_of<T: AsRef<[u8]>>(shape: &Shape, shards: &[T]) -> Vec<Node> {
    shards
        .iter()
        .enumerate()
        .map(|(index, shard)| {
            chunk_leaf(
                FORMAT,
                shape.msg_type,
                shape.n,
                shape.k,
                index as u16,
                shard.as_ref(),
            )
        })
        .collect()
}

/// D1 to D4 over at least `k` shards of `shape`, each of `shape.s` bytes, in an `n` long
/// list. The codec is built here and dropped here: the library keeps a cache of decode
/// matrices in each one, and a codec kept per shape would hold that cache for good.
pub fn decode(
    shape: &Shape,
    object_id: &Node,
    mut shards: Vec<Option<Vec<u8>>>,
    max_content: usize,
) -> Result<Vec<u8>, ObjectError> {
    let (n, k, s) = shape.sizes();
    let codec = ReedSolomon::new(k, n - k).map_err(|_| ObjectError::Decode)?;
    codec
        .reconstruct_data(&mut shards)
        .map_err(|_| ObjectError::Decode)?;
    shards.truncate(k);
    let mut data_shards = Vec::with_capacity(k);
    data_shards.extend(shards.into_iter().flatten());
    if data_shards.len() != k {
        return Err(ObjectError::Decode);
    }

    let data = data_shards.concat();
    let (length, rest) = data
        .split_first_chunk::<LENGTH_LEN>()
        .ok_or(ObjectError::Structure)?;
    let length = u32::from_le_bytes(*length) as usize;
    if length == 0 || length > rest.len() || (length + LENGTH_LEN).div_ceil(k) != s {
        return Err(ObjectError::Structure);
    }
    if length > max_content {
        return Err(ObjectError::ContentLimit);
    }
    let (content, padding) = rest.split_at(length);
    if padding.iter().any(|byte| *byte != 0) {
        return Err(ObjectError::Padding);
    }

    let mut parity = vec![vec![0u8; s]; n - k];
    codec
        .encode_sep(&data_shards, &mut parity)
        .map_err(|_| ObjectError::Decode)?;
    let mut leaves = Vec::with_capacity(n);
    let shards_in_order = data_shards.iter().chain(&parity);
    for (index, shard) in shards_in_order.enumerate() {
        leaves.push(chunk_leaf(
            FORMAT,
            shape.msg_type,
            shape.n,
            shape.k,
            index as u16,
            shard,
        ));
    }
    if root(&leaves) != *object_id {
        return Err(ObjectError::Root);
    }
    Ok(content.to_vec())
}

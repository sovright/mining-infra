//! The candidate chunk layout of Ek A 1.4 and the arrival rules A1 to A4, in the order the
//! design fixes: the header, the exact size, the MAC, then the proof.
//!
//! [`Verifier::verify`] borrows the datagram and allocates nothing, so a bad chunk costs
//! one MAC and one proof at most and leaves no trace.

use std::fmt;

use hmac::{Hmac, Mac};
use sha2::Sha256;

use super::object::{FORMAT, Profile, Shape};
use super::tree::{MAX_DEPTH, Node, chunk_leaf, climb, depth, empty_subtrees, padding_holds};

const MAGIC: u32 = 0x5A43_4852;
const VERSION: u8 = 4;
const MAC_TAG: &[u8] = b"sovright/v2/chunk-mac";
const MAC_AT: usize = 47;
const MAC_LEN: usize = 32;
const NODE_LEN: usize = 32;
pub const HEADER_LEN: usize = 79;
pub const MAX_DATAGRAM: usize = 1200;

/// The first rule a datagram broke.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ChunkError {
    /// A1
    Size,
    /// A2
    Header,
    /// A2's shape rule, which is a receiver's profile and not the format.
    Profile,
    /// A3
    Mac,
    /// A4a
    Padding,
    /// A4
    Proof,
}

impl ChunkError {
    pub fn rule(self) -> &'static str {
        match self {
            Self::Size => "A1",
            Self::Header => "A2",
            Self::Profile => "A2p",
            Self::Mac => "A3",
            Self::Padding => "A4a",
            Self::Proof => "A4",
        }
    }
}

fn be16(bytes: &[u8]) -> u16 {
    u16::from_be_bytes([bytes[0], bytes[1]])
}

fn mac_over(key: &[u8; 32], head: &[u8], tail: &[u8]) -> Hmac<Sha256> {
    let mut mac = Hmac::<Sha256>::new_from_slice(key).expect("a key of any length is accepted");
    mac.update(&[MAC_TAG.len() as u8]);
    mac.update(MAC_TAG);
    mac.update(head);
    mac.update(tail);
    mac
}

/// A chunk that passed A1 to A4, with its shard still in the caller's buffer. Its fields
/// are private and nothing else builds one, so holding this is the evidence the rules ran.
#[derive(Clone, Copy, Debug)]
pub struct VerifiedChunk<'a> {
    object_id: Node,
    shape: Shape,
    index: u16,
    shard: &'a [u8],
}

impl VerifiedChunk<'_> {
    pub fn object_id(&self) -> Node {
        self.object_id
    }

    pub fn shape(&self) -> Shape {
        self.shape
    }

    pub fn index(&self) -> u16 {
        self.index
    }

    pub fn shard(&self) -> &[u8] {
        self.shard
    }
}

/// One session's key, what it accepts, and the padding table.
pub struct Verifier {
    key: [u8; 32],
    profile: Profile,
    empties: [Node; MAX_DEPTH],
}

impl fmt::Debug for Verifier {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("Verifier { .. }")
    }
}

impl Verifier {
    pub fn new(key: [u8; 32], profile: Profile) -> Self {
        Self {
            key,
            profile,
            empties: empty_subtrees(),
        }
    }

    pub fn verify<'a>(&self, datagram: &'a [u8]) -> Result<VerifiedChunk<'a>, ChunkError> {
        if !(HEADER_LEN..=MAX_DATAGRAM).contains(&datagram.len()) {
            return Err(ChunkError::Size);
        }
        let magic = u32::from_be_bytes([datagram[0], datagram[1], datagram[2], datagram[3]]);
        if magic != MAGIC || datagram[4] != VERSION || datagram[6] != FORMAT {
            return Err(ChunkError::Header);
        }
        let shape = Shape {
            msg_type: datagram[5],
            n: be16(&datagram[41..43]),
            k: be16(&datagram[43..45]),
            s: be16(&datagram[45..47]),
        };
        let index = be16(&datagram[39..41]);
        if !shape.is_valid() || index >= shape.n {
            return Err(ChunkError::Header);
        }
        if !self.profile.allows(&shape) {
            return Err(ChunkError::Profile);
        }

        let proof_len = NODE_LEN * depth(usize::from(shape.n));
        let shard_at = HEADER_LEN + proof_len;
        if datagram.len() != shard_at + usize::from(shape.s) {
            return Err(ChunkError::Size);
        }

        let tail = &datagram[MAC_AT + MAC_LEN..];
        mac_over(&self.key, &datagram[..MAC_AT], tail)
            .verify_slice(&datagram[MAC_AT..MAC_AT + MAC_LEN])
            .map_err(|_| ChunkError::Mac)?;

        let (siblings, _) = datagram[HEADER_LEN..shard_at].as_chunks::<NODE_LEN>();
        let at = usize::from(index);
        if !padding_holds(at, usize::from(shape.n), siblings, &self.empties) {
            return Err(ChunkError::Padding);
        }
        let shard = &datagram[shard_at..];
        let leaf = chunk_leaf(FORMAT, shape.msg_type, shape.n, shape.k, index, shard);
        let mut object_id = [0u8; NODE_LEN];
        object_id.copy_from_slice(&datagram[7..39]);
        if climb(leaf, at, siblings) != object_id {
            return Err(ChunkError::Proof);
        }
        Ok(VerifiedChunk {
            object_id,
            shape,
            index,
            shard,
        })
    }
}

/// Whether a datagram claims this format, by its first bytes. Nothing is checked.
pub fn claims_this_format(datagram: &[u8]) -> bool {
    let magic = MAGIC.to_be_bytes();
    datagram.len() > magic.len()
        && datagram[..magic.len()] == magic
        && datagram[magic.len()] == VERSION
}

/// A sender's datagram.
pub fn seal(
    key: &[u8; 32],
    shape: &Shape,
    object_id: &Node,
    index: u16,
    proof: &[Node],
    shard: &[u8],
) -> Vec<u8> {
    let mut head = Vec::with_capacity(MAC_AT);
    head.extend_from_slice(&MAGIC.to_be_bytes());
    head.extend_from_slice(&[VERSION, shape.msg_type, FORMAT]);
    head.extend_from_slice(object_id);
    for field in [index, shape.n, shape.k, shape.s] {
        head.extend_from_slice(&field.to_be_bytes());
    }
    let mut tail = Vec::with_capacity(NODE_LEN * proof.len() + shard.len());
    for node in proof {
        tail.extend_from_slice(node);
    }
    tail.extend_from_slice(shard);

    let mac = mac_over(key, &head, &tail).finalize().into_bytes();
    let mut datagram = head;
    datagram.extend_from_slice(&mac);
    datagram.append(&mut tail);
    datagram
}

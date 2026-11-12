//! The chunk tree of Ek A 1.2 and 1.3: `n` leaves padded with `EMPTY` to a power of two.

use sha2::{Digest, Sha256};

pub type Node = [u8; 32];

/// `n` is at most 256.
pub const MAX_DEPTH: usize = 8;

const LEAF_TAG: &str = "sovright/v2/chunk-leaf";
const NODE_TAG: &str = "sovright/v2/chunk-node";
const EMPTY_TAG: &str = "sovright/v2/chunk-empty";

pub fn tagged(tag: &str, parts: &[&[u8]]) -> Node {
    let mut hash = Sha256::new();
    hash.update([tag.len() as u8]);
    hash.update(tag.as_bytes());
    for part in parts {
        hash.update(part);
    }
    hash.finalize().into()
}

pub fn empty_leaf() -> Node {
    tagged(EMPTY_TAG, &[])
}

pub fn node(left: &Node, right: &Node) -> Node {
    tagged(NODE_TAG, &[left, right])
}

/// The caller keeps `shard` to a `u16` length: the wire says so, and so does the encoder.
pub fn chunk_leaf(format: u8, msg_type: u8, n: u16, k: u16, index: u16, shard: &[u8]) -> Node {
    tagged(
        LEAF_TAG,
        &[
            &[format, msg_type],
            &n.to_be_bytes(),
            &k.to_be_bytes(),
            &index.to_be_bytes(),
            &(shard.len() as u16).to_be_bytes(),
            shard,
        ],
    )
}

pub fn depth(n: usize) -> usize {
    n.next_power_of_two().trailing_zeros() as usize
}

/// `E_0` to `E_7`: the empty subtree of each height.
pub fn empty_subtrees() -> [Node; MAX_DEPTH] {
    let mut subtrees = [empty_leaf(); MAX_DEPTH];
    for level in 1..MAX_DEPTH {
        let below = subtrees[level - 1];
        subtrees[level] = node(&below, &below);
    }
    subtrees
}

/// The canonical root. The padding is whatever this writes, so a root that passes here
/// says nothing can differ from the canonical tree over these leaves.
pub fn root(leaves: &[Node]) -> Node {
    let width = leaves.len().next_power_of_two();
    let mut level = Vec::with_capacity(width);
    level.extend_from_slice(leaves);
    level.resize(width, empty_leaf());
    while level.len() > 1 {
        for at in 0..level.len() / 2 {
            level[at] = node(&level[2 * at], &level[2 * at + 1]);
        }
        level.truncate(level.len() / 2);
    }
    level[0]
}

/// Every level of the canonical tree, for a sender.
pub fn levels(mut level: Vec<Node>) -> Vec<Vec<Node>> {
    level.resize(level.len().next_power_of_two(), empty_leaf());
    let mut levels = vec![level];
    while levels[levels.len() - 1].len() > 1 {
        let next = levels[levels.len() - 1]
            .chunks(2)
            .map(|pair| node(&pair[0], &pair[1]))
            .collect();
        levels.push(next);
    }
    levels
}

pub fn proof(levels: &[Vec<Node>], index: usize) -> Vec<Node> {
    (0..levels.len() - 1)
        .map(|level| levels[level][(index >> level) ^ 1])
        .collect()
}

/// A4a. One proof can open only the siblings that lie wholly in padding. A sibling that
/// mixes real leaves and padding stays closed, so passing here does not make a root
/// canonical. D4 does that, for all `n` leaves.
pub fn padding_holds(
    index: usize,
    n: usize,
    siblings: &[Node],
    empties: &[Node; MAX_DEPTH],
) -> bool {
    siblings.iter().enumerate().all(|(level, sibling)| {
        let first_leaf = ((index >> level) ^ 1) << level;
        first_leaf < n || *sibling == empties[level]
    })
}

/// A4. The root this leaf and these siblings add up to.
pub fn climb(leaf: Node, index: usize, siblings: &[Node]) -> Node {
    let mut at = leaf;
    for (level, sibling) in siblings.iter().enumerate() {
        at = if (index >> level) & 1 == 0 {
            node(&at, sibling)
        } else {
            node(sibling, &at)
        };
    }
    at
}

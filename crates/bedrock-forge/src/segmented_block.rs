//! Segmented raw block framing.
//!
//! This is the object-framing layer needed before worst-case mainnet blocks can
//! move through FORGE without depending on a single FEC frame budget.

use std::error::Error;
use std::fmt;

use sha2::{Digest, Sha256};

const SEGMENT_MAGIC: u32 = 0x4652_5347; // "FRSG"
const SEGMENT_VERSION: u8 = 1;

/// One segment of a raw serialized block.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RawBlockSegment {
    pub block_hash: [u8; 32],
    pub segment_index: u16,
    pub segment_count: u16,
    pub raw_block_len: u64,
    pub raw_block_digest: [u8; 32],
    pub payload_digest: [u8; 32],
    pub payload: Vec<u8>,
}

impl RawBlockSegment {
    /// Encoded segment header length.
    pub const HEADER_LEN: usize = 4 + 1 + 1 + 2 + 2 + 4 + 8 + 32 + 32 + 32;

    /// Return the encoded frame length.
    pub fn encoded_len(&self) -> usize {
        Self::HEADER_LEN + self.payload.len()
    }

    /// Encode the segment into a self-contained frame.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.encoded_len());
        out.extend_from_slice(&SEGMENT_MAGIC.to_be_bytes());
        out.push(SEGMENT_VERSION);
        out.push(0);
        out.extend_from_slice(&self.segment_index.to_be_bytes());
        out.extend_from_slice(&self.segment_count.to_be_bytes());
        out.extend_from_slice(&(self.payload.len() as u32).to_be_bytes());
        out.extend_from_slice(&self.raw_block_len.to_be_bytes());
        out.extend_from_slice(&self.block_hash);
        out.extend_from_slice(&self.raw_block_digest);
        out.extend_from_slice(&self.payload_digest);
        out.extend_from_slice(&self.payload);
        out
    }

    /// Decode and validate a segment frame.
    pub fn decode(frame: &[u8]) -> Result<Self, SegmentedBlockError> {
        if frame.len() < Self::HEADER_LEN {
            return Err(SegmentedBlockError::FrameTooShort);
        }

        let magic = u32::from_be_bytes(frame[0..4].try_into().unwrap());
        if magic != SEGMENT_MAGIC {
            return Err(SegmentedBlockError::InvalidMagic);
        }
        let version = frame[4];
        if version != SEGMENT_VERSION {
            return Err(SegmentedBlockError::UnsupportedVersion { version });
        }

        let segment_index = u16::from_be_bytes(frame[6..8].try_into().unwrap());
        let segment_count = u16::from_be_bytes(frame[8..10].try_into().unwrap());
        let payload_len = u32::from_be_bytes(frame[10..14].try_into().unwrap()) as usize;
        let raw_block_len = u64::from_be_bytes(frame[14..22].try_into().unwrap());
        let mut block_hash = [0u8; 32];
        block_hash.copy_from_slice(&frame[22..54]);
        let mut raw_block_digest = [0u8; 32];
        raw_block_digest.copy_from_slice(&frame[54..86]);
        let mut payload_digest = [0u8; 32];
        payload_digest.copy_from_slice(&frame[86..118]);

        if frame.len() != Self::HEADER_LEN + payload_len {
            return Err(SegmentedBlockError::LengthMismatch);
        }
        if segment_count == 0 || segment_index >= segment_count {
            return Err(SegmentedBlockError::InvalidSegmentIndex {
                segment_index,
                segment_count,
            });
        }

        let payload = frame[Self::HEADER_LEN..].to_vec();
        if sha256(&payload) != payload_digest {
            return Err(SegmentedBlockError::DigestMismatch);
        }

        Ok(Self {
            block_hash,
            segment_index,
            segment_count,
            raw_block_len,
            raw_block_digest,
            payload_digest,
            payload,
        })
    }
}

/// Segment/reassembly errors.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SegmentedBlockError {
    SegmentPayloadTooSmall,
    TooManySegments {
        segment_count: usize,
    },
    FrameTooShort,
    InvalidMagic,
    UnsupportedVersion {
        version: u8,
    },
    LengthMismatch,
    InvalidSegmentIndex {
        segment_index: u16,
        segment_count: u16,
    },
    DuplicateSegment {
        segment_index: u16,
    },
    MissingSegment {
        segment_index: u16,
    },
    InconsistentMetadata,
    DigestMismatch,
}

impl fmt::Display for SegmentedBlockError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SegmentedBlockError::SegmentPayloadTooSmall => {
                write!(f, "segment frame budget leaves no payload room")
            }
            SegmentedBlockError::TooManySegments { segment_count } => {
                write!(f, "raw block requires too many segments: {segment_count}")
            }
            SegmentedBlockError::FrameTooShort => write!(f, "segment frame too short"),
            SegmentedBlockError::InvalidMagic => write!(f, "invalid segment magic"),
            SegmentedBlockError::UnsupportedVersion { version } => {
                write!(f, "unsupported segment version: {version}")
            }
            SegmentedBlockError::LengthMismatch => {
                write!(f, "segment payload length does not match frame length")
            }
            SegmentedBlockError::InvalidSegmentIndex {
                segment_index,
                segment_count,
            } => write!(
                f,
                "segment index {segment_index} is outside segment count {segment_count}"
            ),
            SegmentedBlockError::DuplicateSegment { segment_index } => {
                write!(f, "duplicate segment index {segment_index}")
            }
            SegmentedBlockError::MissingSegment { segment_index } => {
                write!(f, "missing segment index {segment_index}")
            }
            SegmentedBlockError::InconsistentMetadata => {
                write!(f, "segments do not describe the same raw block")
            }
            SegmentedBlockError::DigestMismatch => write!(f, "segment digest mismatch"),
        }
    }
}

impl Error for SegmentedBlockError {}

/// Split a raw serialized block into independently encoded segment payloads.
pub fn split_raw_block(
    block_hash: [u8; 32],
    raw_block: &[u8],
    max_frame_len: usize,
) -> Result<Vec<RawBlockSegment>, SegmentedBlockError> {
    let payload_budget = max_frame_len
        .checked_sub(RawBlockSegment::HEADER_LEN)
        .filter(|budget| *budget > 0)
        .ok_or(SegmentedBlockError::SegmentPayloadTooSmall)?;

    let segment_count = raw_block.len().div_ceil(payload_budget).max(1);
    if segment_count > u16::MAX as usize {
        return Err(SegmentedBlockError::TooManySegments { segment_count });
    }

    let raw_block_digest = sha256(raw_block);
    let raw_block_len = raw_block.len() as u64;
    let segment_count = segment_count as u16;

    let mut segments = Vec::with_capacity(segment_count as usize);
    for segment_index in 0..segment_count {
        let start = segment_index as usize * payload_budget;
        let end = std::cmp::min(start + payload_budget, raw_block.len());
        let payload = raw_block[start..end].to_vec();
        let payload_digest = sha256(&payload);
        segments.push(RawBlockSegment {
            block_hash,
            segment_index,
            segment_count,
            raw_block_len,
            raw_block_digest,
            payload_digest,
            payload,
        });
    }

    Ok(segments)
}

/// Reassemble raw block bytes from a complete segment set.
pub fn reassemble_raw_block(segments: &[RawBlockSegment]) -> Result<Vec<u8>, SegmentedBlockError> {
    let first = segments
        .first()
        .ok_or(SegmentedBlockError::MissingSegment { segment_index: 0 })?;
    let segment_count = first.segment_count as usize;
    if segment_count == 0 {
        return Err(SegmentedBlockError::InvalidSegmentIndex {
            segment_index: 0,
            segment_count: 0,
        });
    }

    let mut slots: Vec<Option<&RawBlockSegment>> = vec![None; segment_count];
    for segment in segments {
        if segment.block_hash != first.block_hash
            || segment.segment_count != first.segment_count
            || segment.raw_block_len != first.raw_block_len
            || segment.raw_block_digest != first.raw_block_digest
        {
            return Err(SegmentedBlockError::InconsistentMetadata);
        }
        if segment.segment_index as usize >= segment_count {
            return Err(SegmentedBlockError::InvalidSegmentIndex {
                segment_index: segment.segment_index,
                segment_count: segment.segment_count,
            });
        }
        if sha256(&segment.payload) != segment.payload_digest {
            return Err(SegmentedBlockError::DigestMismatch);
        }

        let slot = &mut slots[segment.segment_index as usize];
        if slot.is_some() {
            return Err(SegmentedBlockError::DuplicateSegment {
                segment_index: segment.segment_index,
            });
        }
        *slot = Some(segment);
    }

    let mut raw_block = Vec::with_capacity(first.raw_block_len as usize);
    for (index, slot) in slots.into_iter().enumerate() {
        let segment = slot.ok_or(SegmentedBlockError::MissingSegment {
            segment_index: index as u16,
        })?;
        raw_block.extend_from_slice(&segment.payload);
    }

    if raw_block.len() != first.raw_block_len as usize {
        return Err(SegmentedBlockError::LengthMismatch);
    }
    if sha256(&raw_block) != first.raw_block_digest {
        return Err(SegmentedBlockError::DigestMismatch);
    }

    Ok(raw_block)
}

/// Derive the relay object identifier for one raw block segment.
///
/// Relay chunk headers have one 32-byte object key. Segmented raw blocks need a
/// distinct key per segment while preserving the parent block hash inside the
/// segment frame.
pub fn segment_object_hash(block_hash: [u8; 32], segment_index: u16) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"FORGE raw block segment v1");
    hasher.update(block_hash);
    hasher.update(segment_index.to_be_bytes());
    let digest = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
}

fn sha256(data: &[u8]) -> [u8; 32] {
    let digest = Sha256::digest(data);
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
}

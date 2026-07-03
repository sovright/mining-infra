//! UDP chunk protocol for block relay
//!
//! Wire format for transmitting FEC-encoded compact blocks over UDP.

use std::io;

/// Protocol magic number: "ZCHR" (Zcash Relay)
pub const CHUNK_MAGIC: u32 = 0x5A434852;

/// Chunk header size in bytes (version 2 with HMAC)
pub const HEADER_SIZE: usize = 76;

/// Version 1 header size (no HMAC)
pub const HEADER_SIZE_V1: usize = 44;

/// Version 2 header size (with HMAC)
pub const HEADER_SIZE_V2: usize = 76;

/// Version 3 header size (with HMAC and per-block `data_shards`).
///
/// v3 inserts a `u16` data-shard count between `payload_len` and the HMAC so
/// receivers can decode adaptively-sized FEC blocks without an out-of-band
/// shard profile. Two extra bytes over v2 -> 78.
pub const HEADER_SIZE_V3: usize = 78;

/// Conservative UDP datagram budget for authenticated relay packets.
pub const MAX_AUTHENTICATED_DATAGRAM_SIZE: usize = 1200;

/// Maximum FEC payload bytes per relay chunk.
///
/// Production relays require authenticated version-2 chunks, so the full UDP
/// datagram is `HEADER_SIZE_V2 + payload`. Keeping the datagram at 1200 bytes
/// avoids fragmentation on tunneled/cloud paths while leaving room for IP/UDP
/// headers.
pub const MAX_PAYLOAD_SIZE: usize = MAX_AUTHENTICATED_DATAGRAM_SIZE - HEADER_SIZE_V2;

/// Maximum FEC payload bytes per version-3 (adaptive) relay chunk.
///
/// v3 chunks carry a two-byte-larger header, so the per-chunk payload budget
/// shrinks by two bytes relative to [`MAX_PAYLOAD_SIZE`]. Adaptive origins size
/// shards against this value so the full v3 datagram stays within
/// [`MAX_AUTHENTICATED_DATAGRAM_SIZE`].
pub const MAX_PAYLOAD_SIZE_V3: usize = MAX_AUTHENTICATED_DATAGRAM_SIZE - HEADER_SIZE_V3;

/// Maximum allowed chunks per block
pub const MAX_TOTAL_CHUNKS: u16 = 256;

/// Header size for a given protocol version.
///
/// Unknown versions fall back to the version-1 size; callers validate the
/// version separately (see [`ChunkHeader::from_bytes`]).
pub const fn header_size_for_version(version: u8) -> usize {
    match version {
        2 => HEADER_SIZE_V2,
        3 => HEADER_SIZE_V3,
        _ => HEADER_SIZE_V1,
    }
}

/// Message types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[repr(u8)]
pub enum MessageType {
    /// Block data chunk
    Block = 0,
    /// Keepalive
    Keepalive = 1,
    /// Authentication handshake
    Auth = 2,
    /// Segmented raw block object chunk
    RawBlockSegment = 3,
    /// Compact-skeleton fast-path object chunk.
    ///
    /// Wire-identical to a [`MessageType::Block`] chunk (it carries a serialized
    /// `CompactBlock`); only the type byte differs so a receiver routes it to
    /// the skeleton fast path instead of the normal compact-block path. A
    /// skeleton is the reconstruction-critical header + nonce + all-non-coinbase
    /// short_ids (coinbase prefilled), sent first and redundantly ahead of the
    /// full compact block.
    CompactSkeleton = 4,
}

impl TryFrom<u8> for MessageType {
    type Error = io::Error;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(MessageType::Block),
            1 => Ok(MessageType::Keepalive),
            2 => Ok(MessageType::Auth),
            3 => Ok(MessageType::RawBlockSegment),
            4 => Ok(MessageType::CompactSkeleton),
            _ => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("invalid message type: {}", value),
            )),
        }
    }
}

/// Chunk header
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub struct ChunkHeader {
    /// Protocol magic (CHUNK_MAGIC)
    pub magic: u32,
    /// Protocol version
    pub version: u8,
    /// Message type
    pub msg_type: MessageType,
    /// Block hash (full 32 bytes)
    pub block_hash: [u8; 32],
    /// Chunk index (0..total_chunks)
    pub chunk_id: u16,
    /// Total chunks for this block
    pub total_chunks: u16,
    /// Payload length
    pub payload_len: u16,
    /// Per-block FEC data-shard count.
    ///
    /// Zero for version 1/2 chunks ("not present" -- the receiver uses its
    /// fixed configured profile). Nonzero for version 3 (adaptive) chunks,
    /// where it carries the origin's per-block data-shard count and the parity
    /// count is `total_chunks - data_shards`.
    pub data_shards: u16,
    /// HMAC-SHA256 for authentication (version 2 and 3)
    pub hmac: [u8; 32],
}

impl ChunkHeader {
    /// Create a new chunk header for block data
    pub fn new_block(
        block_hash: &[u8; 32],
        chunk_id: u16,
        total_chunks: u16,
        payload_len: u16,
    ) -> Self {
        Self::new(
            MessageType::Block,
            block_hash,
            chunk_id,
            total_chunks,
            payload_len,
        )
    }

    /// Create a new chunk header for raw block segment data
    pub fn new_raw_block_segment(
        object_hash: &[u8; 32],
        chunk_id: u16,
        total_chunks: u16,
        payload_len: u16,
    ) -> Self {
        Self::new(
            MessageType::RawBlockSegment,
            object_hash,
            chunk_id,
            total_chunks,
            payload_len,
        )
    }

    fn new(
        msg_type: MessageType,
        block_hash: &[u8; 32],
        chunk_id: u16,
        total_chunks: u16,
        payload_len: u16,
    ) -> Self {
        Self {
            magic: CHUNK_MAGIC,
            version: 1,
            msg_type,
            block_hash: *block_hash,
            chunk_id,
            total_chunks,
            payload_len,
            data_shards: 0,
            hmac: [0u8; 32],
        }
    }

    /// Create a new authenticated chunk header (version 2 with HMAC)
    pub fn new_block_authenticated(
        block_hash: &[u8; 32],
        chunk_id: u16,
        total_chunks: u16,
        payload_len: u16,
        hmac: [u8; 32],
    ) -> Self {
        Self::new_authenticated(
            MessageType::Block,
            block_hash,
            chunk_id,
            total_chunks,
            payload_len,
            hmac,
        )
    }

    /// Create a new authenticated raw block segment chunk header
    pub fn new_raw_block_segment_authenticated(
        object_hash: &[u8; 32],
        chunk_id: u16,
        total_chunks: u16,
        payload_len: u16,
        hmac: [u8; 32],
    ) -> Self {
        Self::new_authenticated(
            MessageType::RawBlockSegment,
            object_hash,
            chunk_id,
            total_chunks,
            payload_len,
            hmac,
        )
    }

    fn new_authenticated(
        msg_type: MessageType,
        block_hash: &[u8; 32],
        chunk_id: u16,
        total_chunks: u16,
        payload_len: u16,
        hmac: [u8; 32],
    ) -> Self {
        Self {
            magic: CHUNK_MAGIC,
            version: 2,
            msg_type,
            block_hash: *block_hash,
            chunk_id,
            total_chunks,
            payload_len,
            data_shards: 0,
            hmac,
        }
    }

    /// Create a new authenticated keepalive header.
    pub fn new_keepalive_authenticated(hmac: [u8; 32]) -> Self {
        Self {
            magic: CHUNK_MAGIC,
            version: 2,
            msg_type: MessageType::Keepalive,
            block_hash: [0u8; 32],
            chunk_id: 0,
            total_chunks: 0,
            payload_len: 0,
            data_shards: 0,
            hmac,
        }
    }

    /// Create a version-3 (adaptive) block data header without authentication.
    ///
    /// Intermediate header emitted by the chunker; the send path recomputes the
    /// HMAC and produces the authenticated form via
    /// [`ChunkHeader::new_block_authenticated_v3`].
    pub fn new_block_v3(
        block_hash: &[u8; 32],
        chunk_id: u16,
        total_chunks: u16,
        payload_len: u16,
        data_shards: u16,
    ) -> Self {
        Self::new_v3(
            MessageType::Block,
            block_hash,
            chunk_id,
            total_chunks,
            payload_len,
            data_shards,
            [0u8; 32],
        )
    }

    /// Create a version-3 (adaptive) raw block segment header without authentication.
    pub fn new_raw_block_segment_v3(
        object_hash: &[u8; 32],
        chunk_id: u16,
        total_chunks: u16,
        payload_len: u16,
        data_shards: u16,
    ) -> Self {
        Self::new_v3(
            MessageType::RawBlockSegment,
            object_hash,
            chunk_id,
            total_chunks,
            payload_len,
            data_shards,
            [0u8; 32],
        )
    }

    /// Create an authenticated version-3 (adaptive) block data header.
    pub fn new_block_authenticated_v3(
        block_hash: &[u8; 32],
        chunk_id: u16,
        total_chunks: u16,
        payload_len: u16,
        data_shards: u16,
        hmac: [u8; 32],
    ) -> Self {
        Self::new_v3(
            MessageType::Block,
            block_hash,
            chunk_id,
            total_chunks,
            payload_len,
            data_shards,
            hmac,
        )
    }

    /// Create an authenticated version-3 (adaptive) raw block segment header.
    pub fn new_raw_block_segment_authenticated_v3(
        object_hash: &[u8; 32],
        chunk_id: u16,
        total_chunks: u16,
        payload_len: u16,
        data_shards: u16,
        hmac: [u8; 32],
    ) -> Self {
        Self::new_v3(
            MessageType::RawBlockSegment,
            object_hash,
            chunk_id,
            total_chunks,
            payload_len,
            data_shards,
            hmac,
        )
    }

    /// Create a new compact-skeleton chunk header (version 1, unauthenticated).
    pub fn new_compact_skeleton(
        block_hash: &[u8; 32],
        chunk_id: u16,
        total_chunks: u16,
        payload_len: u16,
    ) -> Self {
        Self::new(
            MessageType::CompactSkeleton,
            block_hash,
            chunk_id,
            total_chunks,
            payload_len,
        )
    }

    /// Create a new authenticated compact-skeleton chunk header (version 2).
    pub fn new_compact_skeleton_authenticated(
        block_hash: &[u8; 32],
        chunk_id: u16,
        total_chunks: u16,
        payload_len: u16,
        hmac: [u8; 32],
    ) -> Self {
        Self::new_authenticated(
            MessageType::CompactSkeleton,
            block_hash,
            chunk_id,
            total_chunks,
            payload_len,
            hmac,
        )
    }

    /// Create a version-3 (adaptive) compact-skeleton header without authentication.
    pub fn new_compact_skeleton_v3(
        block_hash: &[u8; 32],
        chunk_id: u16,
        total_chunks: u16,
        payload_len: u16,
        data_shards: u16,
    ) -> Self {
        Self::new_v3(
            MessageType::CompactSkeleton,
            block_hash,
            chunk_id,
            total_chunks,
            payload_len,
            data_shards,
            [0u8; 32],
        )
    }

    /// Create an authenticated version-3 (adaptive) compact-skeleton header.
    pub fn new_compact_skeleton_authenticated_v3(
        block_hash: &[u8; 32],
        chunk_id: u16,
        total_chunks: u16,
        payload_len: u16,
        data_shards: u16,
        hmac: [u8; 32],
    ) -> Self {
        Self::new_v3(
            MessageType::CompactSkeleton,
            block_hash,
            chunk_id,
            total_chunks,
            payload_len,
            data_shards,
            hmac,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn new_v3(
        msg_type: MessageType,
        block_hash: &[u8; 32],
        chunk_id: u16,
        total_chunks: u16,
        payload_len: u16,
        data_shards: u16,
        hmac: [u8; 32],
    ) -> Self {
        Self {
            magic: CHUNK_MAGIC,
            version: 3,
            msg_type,
            block_hash: *block_hash,
            chunk_id,
            total_chunks,
            payload_len,
            data_shards,
            hmac,
        }
    }

    /// Serialized size of this header on the wire (branches on version).
    pub fn header_size(&self) -> usize {
        header_size_for_version(self.version)
    }

    /// Serialize header to bytes.
    ///
    /// Returns a fixed [`HEADER_SIZE_V3`]-byte buffer; callers slice it to
    /// [`ChunkHeader::header_size`] for the wire. The version-1/2 byte layout is
    /// unchanged from prior releases (magic, version, type, hash, ids, len,
    /// then a 32-byte HMAC at `[44..76]`); trailing bytes are zero. Version 3
    /// inserts `data_shards` at `[44..46]` and moves the HMAC to `[46..78]`.
    pub fn to_bytes(&self) -> [u8; HEADER_SIZE_V3] {
        let mut buf = [0u8; HEADER_SIZE_V3];
        buf[0..4].copy_from_slice(&self.magic.to_be_bytes());
        buf[4] = self.version;
        buf[5] = self.msg_type as u8;
        buf[6..38].copy_from_slice(&self.block_hash);
        buf[38..40].copy_from_slice(&self.chunk_id.to_be_bytes());
        buf[40..42].copy_from_slice(&self.total_chunks.to_be_bytes());
        buf[42..44].copy_from_slice(&self.payload_len.to_be_bytes());
        if self.version == 3 {
            buf[44..46].copy_from_slice(&self.data_shards.to_be_bytes());
            buf[46..78].copy_from_slice(&self.hmac);
        } else {
            // Version 1/2 layout preserved byte-for-byte: HMAC at [44..76].
            buf[44..76].copy_from_slice(&self.hmac);
        }
        buf
    }

    /// Parse header from bytes
    pub fn from_bytes(buf: &[u8]) -> io::Result<Self> {
        if buf.len() < HEADER_SIZE_V1 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "buffer too small for chunk header",
            ));
        }

        let magic = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]);
        if magic != CHUNK_MAGIC {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "invalid magic: expected {:08x}, got {:08x}",
                    CHUNK_MAGIC, magic
                ),
            ));
        }

        let version = buf[4];
        if version != 1 && version != 2 && version != 3 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("unsupported protocol version: {}", version),
            ));
        }

        // Version 3 needs the full extended header to read data_shards + HMAC.
        if version == 3 && buf.len() < HEADER_SIZE_V3 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "buffer too small for version 3 chunk header",
            ));
        }

        let msg_type = MessageType::try_from(buf[5])?;

        let mut block_hash = [0u8; 32];
        block_hash.copy_from_slice(&buf[6..38]);

        let chunk_id = u16::from_be_bytes([buf[38], buf[39]]);
        let total_chunks = u16::from_be_bytes([buf[40], buf[41]]);
        if total_chunks > MAX_TOTAL_CHUNKS {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "total_chunks {} exceeds max {}",
                    total_chunks, MAX_TOTAL_CHUNKS
                ),
            ));
        }
        let payload_len = u16::from_be_bytes([buf[42], buf[43]]);
        // v3 chunks carry a two-byte-larger header, shrinking the payload budget.
        let max_payload = if version == 3 {
            MAX_PAYLOAD_SIZE_V3
        } else {
            MAX_PAYLOAD_SIZE
        };
        if payload_len as usize > max_payload {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("payload_len {} exceeds max {}", payload_len, max_payload),
            ));
        }
        if matches!(
            msg_type,
            MessageType::Block | MessageType::RawBlockSegment | MessageType::CompactSkeleton
        ) && payload_len == 0
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "payload_len must be > 0 for data messages",
            ));
        }

        // data_shards is only present (and only meaningful) in version 3.
        let data_shards = if version == 3 {
            let ds = u16::from_be_bytes([buf[44], buf[45]]);
            // Reject malformed/hostile adaptive headers: a v3 block always has
            // at least one data shard and at least one parity shard, so
            // 1 <= data_shards < total_chunks must hold. This also guards the
            // decode path against a zero divisor / zero-parity codec.
            if ds == 0 || ds >= total_chunks {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!(
                        "invalid v3 data_shards {} for total_chunks {}",
                        ds, total_chunks
                    ),
                ));
            }
            ds
        } else {
            0
        };

        // HMAC present in version 2 ([44..76]) and version 3 ([46..78]).
        let hmac = if version == 2 && buf.len() >= HEADER_SIZE_V2 {
            let mut h = [0u8; 32];
            h.copy_from_slice(&buf[44..76]);
            h
        } else if version == 3 {
            let mut h = [0u8; 32];
            h.copy_from_slice(&buf[46..78]);
            h
        } else {
            [0u8; 32]
        };

        Ok(Self {
            magic,
            version,
            msg_type,
            block_hash,
            chunk_id,
            total_chunks,
            payload_len,
            data_shards,
            hmac,
        })
    }
}

/// Complete chunk (header + payload)
#[derive(Debug, Clone)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub struct Chunk {
    pub header: ChunkHeader,
    pub payload: Vec<u8>,
}

impl Chunk {
    /// Create a new chunk
    pub fn new(header: ChunkHeader, payload: Vec<u8>) -> Self {
        Self { header, payload }
    }

    /// Serialize chunk to bytes for transmission
    pub fn to_bytes(&self) -> Vec<u8> {
        let header_bytes = self.header.to_bytes();
        let header_size = header_size_for_version(self.header.version);

        let mut buf = Vec::with_capacity(header_size + self.payload.len());
        buf.extend_from_slice(&header_bytes[..header_size]);
        buf.extend_from_slice(&self.payload);
        buf
    }

    /// Parse chunk from received bytes
    pub fn from_bytes(buf: &[u8]) -> io::Result<Self> {
        if buf.len() < HEADER_SIZE_V1 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "buffer too small for chunk header",
            ));
        }

        // Check version to determine header size
        let version = buf[4];
        let header_size = header_size_for_version(version);

        if buf.len() < header_size {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("buffer too small for version {} header", version),
            ));
        }

        let header = ChunkHeader::from_bytes(buf)?;

        if buf.len() < header_size + header.payload_len as usize {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "buffer too small for payload",
            ));
        }
        if buf.len() != header_size + header.payload_len as usize {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "buffer has trailing bytes beyond payload",
            ));
        }

        let payload = buf[header_size..header_size + header.payload_len as usize].to_vec();

        Ok(Self { header, payload })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chunk_header_roundtrip() {
        let block_hash = [0xab; 32];
        let header = ChunkHeader::new_block(&block_hash, 5, 13, MAX_PAYLOAD_SIZE as u16);

        let bytes = header.to_bytes();
        let parsed = ChunkHeader::from_bytes(&bytes).unwrap();

        assert_eq!(parsed.magic, CHUNK_MAGIC);
        assert_eq!(parsed.version, 1);
        assert_eq!(parsed.msg_type, MessageType::Block);
        assert_eq!(parsed.chunk_id, 5);
        assert_eq!(parsed.total_chunks, 13);
        assert_eq!(parsed.payload_len, MAX_PAYLOAD_SIZE as u16);
    }

    #[test]
    fn chunk_roundtrip() {
        let block_hash = [0xcd; 32];
        let header = ChunkHeader::new_block(&block_hash, 0, 10, 5);
        let payload = vec![1, 2, 3, 4, 5];
        let chunk = Chunk::new(header, payload.clone());

        let bytes = chunk.to_bytes();
        let parsed = Chunk::from_bytes(&bytes).unwrap();

        assert_eq!(parsed.header.chunk_id, 0);
        assert_eq!(parsed.payload, payload);
    }

    #[test]
    fn rejects_invalid_magic() {
        let mut buf = [0u8; HEADER_SIZE];
        buf[0..4].copy_from_slice(&[0xFF, 0xFF, 0xFF, 0xFF]);

        let result = ChunkHeader::from_bytes(&buf);
        assert!(result.is_err());
    }

    #[test]
    fn rejects_invalid_version() {
        let block_hash = [0xab; 32];
        let header = ChunkHeader::new_block(&block_hash, 0, 10, 100);
        let mut bytes = header.to_bytes();
        bytes[4] = 99; // Invalid version

        let result = ChunkHeader::from_bytes(&bytes);
        assert!(result.is_err());
    }

    #[test]
    fn rejects_payload_len_over_max() {
        let block_hash = [0xab; 32];
        let header = ChunkHeader::new_block(
            &block_hash,
            0,
            10,
            (MAX_PAYLOAD_SIZE as u16).saturating_add(1),
        );
        let bytes = header.to_bytes();

        let result = ChunkHeader::from_bytes(&bytes);
        assert!(result.is_err());
    }

    #[test]
    fn rejects_total_chunks_over_max() {
        let block_hash = [0xab; 32];
        let header = ChunkHeader::new_block(&block_hash, 0, MAX_TOTAL_CHUNKS.saturating_add(1), 10);
        let bytes = header.to_bytes();

        let result = ChunkHeader::from_bytes(&bytes);
        assert!(result.is_err());
    }

    #[test]
    fn rejects_zero_payload_for_block() {
        let block_hash = [0xab; 32];
        let header = ChunkHeader::new_block(&block_hash, 0, 1, 0);
        let bytes = header.to_bytes();

        let result = ChunkHeader::from_bytes(&bytes);
        assert!(result.is_err());
    }

    #[test]
    fn authenticated_chunk_roundtrip() {
        let block_hash = [0xcd; 32];
        let hmac = [0xef; 32];
        let header = ChunkHeader::new_block_authenticated(&block_hash, 3, 10, 5, hmac);
        let payload = vec![1, 2, 3, 4, 5];
        let chunk = Chunk::new(header, payload.clone());

        assert_eq!(chunk.header.version, 2);

        let bytes = chunk.to_bytes();
        assert_eq!(bytes.len(), HEADER_SIZE_V2 + 5); // v2 header + payload

        let parsed = Chunk::from_bytes(&bytes).unwrap();
        assert_eq!(parsed.header.version, 2);
        assert_eq!(parsed.header.hmac, hmac);
        assert_eq!(parsed.payload, payload);
    }

    #[test]
    fn authenticated_max_payload_fits_datagram_budget() {
        let block_hash = [0xcd; 32];
        let hmac = [0xef; 32];
        let header =
            ChunkHeader::new_block_authenticated(&block_hash, 0, 1, MAX_PAYLOAD_SIZE as u16, hmac);
        let chunk = Chunk::new(header, vec![0xab; MAX_PAYLOAD_SIZE]);

        assert!(chunk.to_bytes().len() <= MAX_AUTHENTICATED_DATAGRAM_SIZE);
    }

    /// The version-2 wire encoding must remain byte-for-byte identical to prior
    /// releases so a v2 origin and a v3-capable receiver interoperate. This
    /// pins the exact 76-byte layout as a golden.
    #[test]
    fn v2_header_to_bytes_matches_hardcoded_golden() {
        let block_hash = [0xab; 32];
        let hmac = [0xcd; 32];
        let header = ChunkHeader::new_block_authenticated(&block_hash, 5, 13, 100, hmac);

        let mut golden = Vec::with_capacity(HEADER_SIZE_V2);
        golden.extend_from_slice(&[0x5A, 0x43, 0x48, 0x52]); // magic "ZCHR"
        golden.push(2); // version
        golden.push(0); // msg_type = Block
        golden.extend_from_slice(&[0xab; 32]); // block_hash
        golden.extend_from_slice(&[0x00, 0x05]); // chunk_id = 5
        golden.extend_from_slice(&[0x00, 0x0D]); // total_chunks = 13
        golden.extend_from_slice(&[0x00, 0x64]); // payload_len = 100
        golden.extend_from_slice(&[0xcd; 32]); // hmac
        assert_eq!(golden.len(), HEADER_SIZE_V2);

        let bytes = header.to_bytes();
        assert_eq!(&bytes[..HEADER_SIZE_V2], golden.as_slice());

        // And the full chunk wire form is header(76) + payload with no v3 bytes.
        let chunk = Chunk::new(header, vec![0x11; 100]);
        let wire = chunk.to_bytes();
        assert_eq!(wire.len(), HEADER_SIZE_V2 + 100);
        assert_eq!(&wire[..HEADER_SIZE_V2], golden.as_slice());
    }

    #[test]
    fn v3_header_roundtrip_carries_data_shards() {
        let block_hash = [0x11; 32];
        let hmac = [0x22; 32];
        let header = ChunkHeader::new_block_authenticated_v3(&block_hash, 1, 3, 812, 2, hmac);
        assert_eq!(header.version, 3);
        assert_eq!(header.header_size(), HEADER_SIZE_V3);

        let bytes = header.to_bytes();
        // data_shards lives at [44..46], hmac at [46..78].
        assert_eq!(&bytes[44..46], &2u16.to_be_bytes());
        assert_eq!(&bytes[46..78], &hmac);

        let parsed = ChunkHeader::from_bytes(&bytes).unwrap();
        assert_eq!(parsed.version, 3);
        assert_eq!(parsed.data_shards, 2);
        assert_eq!(parsed.total_chunks, 3);
        assert_eq!(parsed.payload_len, 812);
        assert_eq!(parsed.hmac, hmac);
        assert_eq!(parsed.block_hash, block_hash);
    }

    #[test]
    fn v3_chunk_roundtrip_over_wire() {
        let block_hash = [0x33; 32];
        let hmac = [0x44; 32];
        let header = ChunkHeader::new_raw_block_segment_authenticated_v3(&block_hash, 0, 2, 5, 1, hmac);
        let payload = vec![9, 8, 7, 6, 5];
        let chunk = Chunk::new(header, payload.clone());

        let wire = chunk.to_bytes();
        assert_eq!(wire.len(), HEADER_SIZE_V3 + 5);

        let parsed = Chunk::from_bytes(&wire).unwrap();
        assert_eq!(parsed.header.version, 3);
        assert_eq!(parsed.header.data_shards, 1);
        assert_eq!(parsed.header.msg_type, MessageType::RawBlockSegment);
        assert_eq!(parsed.payload, payload);
    }

    #[test]
    fn v3_max_payload_fits_datagram_budget() {
        let header =
            ChunkHeader::new_block_authenticated_v3(&[0u8; 32], 0, 2, MAX_PAYLOAD_SIZE_V3 as u16, 1, [0u8; 32]);
        let chunk = Chunk::new(header, vec![0xab; MAX_PAYLOAD_SIZE_V3]);
        assert_eq!(chunk.to_bytes().len(), MAX_AUTHENTICATED_DATAGRAM_SIZE);
        assert!(chunk.to_bytes().len() <= MAX_AUTHENTICATED_DATAGRAM_SIZE);
    }

    #[test]
    fn v3_rejects_zero_data_shards() {
        // Hand-craft a v3 header with data_shards == 0.
        let header = ChunkHeader::new_block_authenticated_v3(&[0u8; 32], 0, 3, 10, 2, [0u8; 32]);
        let mut bytes = header.to_bytes();
        bytes[44..46].copy_from_slice(&0u16.to_be_bytes());
        assert!(ChunkHeader::from_bytes(&bytes).is_err());
    }

    #[test]
    fn v3_rejects_data_shards_ge_total_chunks() {
        let header = ChunkHeader::new_block_authenticated_v3(&[0u8; 32], 0, 3, 10, 2, [0u8; 32]);
        let mut bytes = header.to_bytes();
        // data_shards = total_chunks (3) => no parity => invalid.
        bytes[44..46].copy_from_slice(&3u16.to_be_bytes());
        assert!(ChunkHeader::from_bytes(&bytes).is_err());
        // data_shards > total_chunks => invalid.
        bytes[44..46].copy_from_slice(&9u16.to_be_bytes());
        assert!(ChunkHeader::from_bytes(&bytes).is_err());
    }

    #[test]
    fn compact_skeleton_message_type_survives_to_from_bytes() {
        // A CompactSkeleton chunk is wire-identical to a Block chunk save for
        // the type byte (5 = CompactSkeleton), which must survive the round trip.
        let block_hash = [0x5c; 32];
        let hmac = [0x6d; 32];
        let header = ChunkHeader::new_compact_skeleton_authenticated(&block_hash, 2, 5, 7, hmac);
        assert_eq!(header.version, 2);
        assert_eq!(header.msg_type, MessageType::CompactSkeleton);

        let bytes = header.to_bytes();
        // Type byte lives at offset 5 and must encode CompactSkeleton == 4.
        assert_eq!(bytes[5], MessageType::CompactSkeleton as u8);
        assert_eq!(bytes[5], 4);

        let parsed = ChunkHeader::from_bytes(&bytes).unwrap();
        assert_eq!(parsed.msg_type, MessageType::CompactSkeleton);

        let payload = vec![1, 2, 3, 4, 5, 6, 7];
        let chunk = Chunk::new(header, payload.clone());
        let wire = chunk.to_bytes();
        let parsed = Chunk::from_bytes(&wire).unwrap();
        assert_eq!(parsed.header.msg_type, MessageType::CompactSkeleton);
        assert_eq!(parsed.payload, payload);
    }

    #[test]
    fn compact_skeleton_v3_roundtrip_carries_data_shards() {
        let block_hash = [0x77; 32];
        let hmac = [0x88; 32];
        let header =
            ChunkHeader::new_compact_skeleton_authenticated_v3(&block_hash, 0, 3, 9, 1, hmac);
        assert_eq!(header.version, 3);
        let bytes = header.to_bytes();
        let parsed = ChunkHeader::from_bytes(&bytes).unwrap();
        assert_eq!(parsed.msg_type, MessageType::CompactSkeleton);
        assert_eq!(parsed.data_shards, 1);
        assert_eq!(parsed.total_chunks, 3);
    }

    #[test]
    fn v3_rejects_truncated_buffer() {
        let header = ChunkHeader::new_block_authenticated_v3(&[0u8; 32], 0, 2, 5, 1, [0u8; 32]);
        let bytes = header.to_bytes();
        // 77 bytes: one short of the v3 header.
        assert!(ChunkHeader::from_bytes(&bytes[..HEADER_SIZE_V3 - 1]).is_err());
    }
}

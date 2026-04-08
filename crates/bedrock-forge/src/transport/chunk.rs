//! UDP chunk protocol for block relay
//!
//! Wire format for transmitting FEC-encoded compact blocks over UDP.

use std::io;

/// Protocol magic number: "ZCHR" (Zcash Relay)
pub const CHUNK_MAGIC: u32 = 0x5A434852;

/// Maximum payload size to fit in standard MTU
/// MTU (1500) - IP header (20) - UDP header (8) - Chunk header (44) = 1428
/// Round down to 1396 for safety
pub const MAX_PAYLOAD_SIZE: usize = 1396;

/// Chunk header size in bytes (version 2 with HMAC)
pub const HEADER_SIZE: usize = 76;

/// Version 1 header size (no HMAC)
pub const HEADER_SIZE_V1: usize = 44;

/// Version 2 header size (with HMAC)
pub const HEADER_SIZE_V2: usize = 76;

/// Maximum allowed chunks per block
pub const MAX_TOTAL_CHUNKS: u16 = 256;

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
}

impl TryFrom<u8> for MessageType {
    type Error = io::Error;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(MessageType::Block),
            1 => Ok(MessageType::Keepalive),
            2 => Ok(MessageType::Auth),
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
    /// HMAC-SHA256 for authentication (version 2 only)
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
        Self {
            magic: CHUNK_MAGIC,
            version: 1,
            msg_type: MessageType::Block,
            block_hash: *block_hash,
            chunk_id,
            total_chunks,
            payload_len,
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
        Self {
            magic: CHUNK_MAGIC,
            version: 2,
            msg_type: MessageType::Block,
            block_hash: *block_hash,
            chunk_id,
            total_chunks,
            payload_len,
            hmac,
        }
    }

    /// Serialize header to bytes
    pub fn to_bytes(&self) -> [u8; HEADER_SIZE] {
        let mut buf = [0u8; HEADER_SIZE];
        buf[0..4].copy_from_slice(&self.magic.to_be_bytes());
        buf[4] = self.version;
        buf[5] = self.msg_type as u8;
        buf[6..38].copy_from_slice(&self.block_hash);
        buf[38..40].copy_from_slice(&self.chunk_id.to_be_bytes());
        buf[40..42].copy_from_slice(&self.total_chunks.to_be_bytes());
        buf[42..44].copy_from_slice(&self.payload_len.to_be_bytes());
        buf[44..76].copy_from_slice(&self.hmac);
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
                format!("invalid magic: expected {:08x}, got {:08x}", CHUNK_MAGIC, magic),
            ));
        }

        let version = buf[4];
        if version != 1 && version != 2 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("unsupported protocol version: {}", version),
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
                format!("total_chunks {} exceeds max {}", total_chunks, MAX_TOTAL_CHUNKS),
            ));
        }
        let payload_len = u16::from_be_bytes([buf[42], buf[43]]);
        if payload_len as usize > MAX_PAYLOAD_SIZE {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "payload_len {} exceeds max {}",
                    payload_len, MAX_PAYLOAD_SIZE
                ),
            ));
        }
        if msg_type == MessageType::Block && payload_len == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "payload_len must be > 0 for block messages",
            ));
        }

        // HMAC only present in version 2 with sufficient buffer
        let hmac = if version == 2 && buf.len() >= HEADER_SIZE_V2 {
            let mut h = [0u8; 32];
            h.copy_from_slice(&buf[44..76]);
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
        let header_size = if self.header.version == 2 {
            HEADER_SIZE_V2
        } else {
            HEADER_SIZE_V1
        };

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
        let header_size = if version == 2 {
            HEADER_SIZE_V2
        } else {
            HEADER_SIZE_V1
        };

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
        let header = ChunkHeader::new_block(
            &block_hash,
            0,
            MAX_TOTAL_CHUNKS.saturating_add(1),
            10,
        );
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
}

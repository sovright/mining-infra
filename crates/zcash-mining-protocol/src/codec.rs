//! Binary codec for Zcash Mining Protocol messages
//!
//! Wire format follows SRI conventions:
//! - Little-endian integers
//! - Variable-length fields prefixed with length byte
//! - Fixed arrays without length prefix

use crate::error::{ProtocolError, Result};
use crate::messages::{
    NewEquihashJob, RejectReason, SetTarget, ShareResult, SubmitEquihashShare,
    SubmitSharesResponse, message_types,
};
use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use std::io::{Cursor, Read, Write};

/// Maximum payload size for a single message frame (1 MB).
pub const MAX_FRAME_PAYLOAD: u32 = 1_048_576;

/// Message frame header
#[derive(Debug, Clone)]
pub struct MessageFrame {
    /// Extension type (0 for mining protocol)
    pub extension_type: u16,
    /// Message type identifier
    pub msg_type: u8,
    /// Payload length
    pub length: u32,
}

impl MessageFrame {
    /// Header size in bytes
    pub const HEADER_SIZE: usize = 6;

    /// Encode frame header
    pub fn encode(&self) -> [u8; 6] {
        let mut buf = [0u8; 6];
        buf[0..2].copy_from_slice(&self.extension_type.to_le_bytes());
        buf[2] = self.msg_type;
        // Length is 3 bytes (24-bit)
        buf[3..6].copy_from_slice(&self.length.to_le_bytes()[0..3]);
        buf
    }

    /// Decode frame header
    pub fn decode(data: &[u8]) -> Result<Self> {
        if data.len() < Self::HEADER_SIZE {
            return Err(ProtocolError::MessageTooShort {
                expected: Self::HEADER_SIZE,
                actual: data.len(),
            });
        }
        let extension_type = u16::from_le_bytes([data[0], data[1]]);
        let msg_type = data[2];
        let mut len_bytes = [0u8; 4];
        len_bytes[0..3].copy_from_slice(&data[3..6]);
        let length = u32::from_le_bytes(len_bytes);

        if length > MAX_FRAME_PAYLOAD {
            return Err(ProtocolError::EncodingError(format!(
                "frame payload {} exceeds maximum of {} bytes",
                length, MAX_FRAME_PAYLOAD
            )));
        }

        Ok(Self {
            extension_type,
            msg_type,
            length,
        })
    }
}

/// Encode a NewEquihashJob message
pub fn encode_new_equihash_job(job: &NewEquihashJob) -> Result<Vec<u8>> {
    let mut payload = Vec::new();

    payload.write_u32::<LittleEndian>(job.channel_id).unwrap();
    payload.write_u32::<LittleEndian>(job.job_id).unwrap();
    payload
        .write_u8(if job.future_job { 1 } else { 0 })
        .unwrap();
    payload.write_u32::<LittleEndian>(job.version).unwrap();
    payload.write_all(&job.prev_hash).unwrap();
    payload.write_all(&job.merkle_root).unwrap();
    payload.write_all(&job.block_commitments).unwrap();
    // Variable-length nonce_1
    payload.write_u8(job.nonce_1.len() as u8).unwrap();
    payload.write_all(&job.nonce_1).unwrap();
    payload.write_u8(job.nonce_2_len).unwrap();
    payload.write_u32::<LittleEndian>(job.time).unwrap();
    payload.write_u32::<LittleEndian>(job.bits).unwrap();
    payload.write_all(&job.target).unwrap();
    payload
        .write_u8(if job.clean_jobs { 1 } else { 0 })
        .unwrap();

    let frame = MessageFrame {
        extension_type: 0,
        msg_type: message_types::NEW_EQUIHASH_JOB,
        length: payload.len() as u32,
    };

    let mut result = frame.encode().to_vec();
    result.extend(payload);
    Ok(result)
}

/// Decode a NewEquihashJob message
pub fn decode_new_equihash_job(data: &[u8]) -> Result<NewEquihashJob> {
    let frame = MessageFrame::decode(data)?;
    if frame.msg_type != message_types::NEW_EQUIHASH_JOB {
        return Err(ProtocolError::InvalidMessageType(frame.msg_type));
    }

    let total_len = MessageFrame::HEADER_SIZE + frame.length as usize;
    if data.len() < total_len {
        return Err(ProtocolError::MessageTooShort {
            expected: total_len,
            actual: data.len(),
        });
    }
    if data.len() > total_len {
        return Err(ProtocolError::EncodingError(
            "trailing bytes in message".into(),
        ));
    }

    let payload = &data[MessageFrame::HEADER_SIZE..total_len];
    let mut cursor = Cursor::new(payload);

    let channel_id = cursor
        .read_u32::<LittleEndian>()
        .map_err(|e| ProtocolError::EncodingError(e.to_string()))?;
    let job_id = cursor
        .read_u32::<LittleEndian>()
        .map_err(|e| ProtocolError::EncodingError(e.to_string()))?;
    let future_job = cursor
        .read_u8()
        .map_err(|e| ProtocolError::EncodingError(e.to_string()))?
        != 0;
    let version = cursor
        .read_u32::<LittleEndian>()
        .map_err(|e| ProtocolError::EncodingError(e.to_string()))?;

    let mut prev_hash = [0u8; 32];
    cursor
        .read_exact(&mut prev_hash)
        .map_err(|e| ProtocolError::EncodingError(e.to_string()))?;

    let mut merkle_root = [0u8; 32];
    cursor
        .read_exact(&mut merkle_root)
        .map_err(|e| ProtocolError::EncodingError(e.to_string()))?;

    let mut block_commitments = [0u8; 32];
    cursor
        .read_exact(&mut block_commitments)
        .map_err(|e| ProtocolError::EncodingError(e.to_string()))?;

    let nonce_1_len = cursor
        .read_u8()
        .map_err(|e| ProtocolError::EncodingError(e.to_string()))? as usize;
    // Validate nonce_1_len (Zcash nonce is 32 bytes total)
    if nonce_1_len > 32 {
        return Err(ProtocolError::EncodingError(format!(
            "nonce_1_len {} exceeds maximum of 32",
            nonce_1_len
        )));
    }
    let mut nonce_1 = vec![0u8; nonce_1_len];
    cursor
        .read_exact(&mut nonce_1)
        .map_err(|e| ProtocolError::EncodingError(e.to_string()))?;

    let nonce_2_len = cursor
        .read_u8()
        .map_err(|e| ProtocolError::EncodingError(e.to_string()))?;
    // Validate nonce_2_len and that nonce_1 + nonce_2 == 32 bytes
    if nonce_2_len as usize > 32 {
        return Err(ProtocolError::EncodingError(format!(
            "nonce_2_len {} exceeds maximum of 32",
            nonce_2_len
        )));
    }
    if nonce_1_len + nonce_2_len as usize != 32 {
        return Err(ProtocolError::EncodingError(format!(
            "nonce_1_len ({}) + nonce_2_len ({}) must equal 32",
            nonce_1_len, nonce_2_len
        )));
    }

    let time = cursor
        .read_u32::<LittleEndian>()
        .map_err(|e| ProtocolError::EncodingError(e.to_string()))?;
    let bits = cursor
        .read_u32::<LittleEndian>()
        .map_err(|e| ProtocolError::EncodingError(e.to_string()))?;

    let mut target = [0u8; 32];
    cursor
        .read_exact(&mut target)
        .map_err(|e| ProtocolError::EncodingError(e.to_string()))?;

    let clean_jobs = cursor
        .read_u8()
        .map_err(|e| ProtocolError::EncodingError(e.to_string()))?
        != 0;

    Ok(NewEquihashJob {
        channel_id,
        job_id,
        future_job,
        version,
        prev_hash,
        merkle_root,
        block_commitments,
        nonce_1,
        nonce_2_len,
        time,
        bits,
        target,
        clean_jobs,
    })
}

/// Encode a SubmitEquihashShare message
pub fn encode_submit_share(share: &SubmitEquihashShare) -> Result<Vec<u8>> {
    let mut payload = Vec::new();

    payload.write_u32::<LittleEndian>(share.channel_id).unwrap();
    payload
        .write_u32::<LittleEndian>(share.sequence_number)
        .unwrap();
    payload.write_u32::<LittleEndian>(share.job_id).unwrap();
    // Variable-length nonce_2
    payload.write_u8(share.nonce_2.len() as u8).unwrap();
    payload.write_all(&share.nonce_2).unwrap();
    payload.write_u32::<LittleEndian>(share.time).unwrap();
    payload.write_all(&share.solution).unwrap();

    let frame = MessageFrame {
        extension_type: 0,
        msg_type: message_types::SUBMIT_EQUIHASH_SHARE,
        length: payload.len() as u32,
    };

    let mut result = frame.encode().to_vec();
    result.extend(payload);
    Ok(result)
}

/// Decode a SubmitEquihashShare message
pub fn decode_submit_share(data: &[u8]) -> Result<SubmitEquihashShare> {
    let frame = MessageFrame::decode(data)?;
    if frame.msg_type != message_types::SUBMIT_EQUIHASH_SHARE {
        return Err(ProtocolError::InvalidMessageType(frame.msg_type));
    }

    let total_len = MessageFrame::HEADER_SIZE + frame.length as usize;
    if data.len() < total_len {
        return Err(ProtocolError::MessageTooShort {
            expected: total_len,
            actual: data.len(),
        });
    }
    if data.len() > total_len {
        return Err(ProtocolError::EncodingError(
            "trailing bytes in message".into(),
        ));
    }

    let payload = &data[MessageFrame::HEADER_SIZE..total_len];
    let mut cursor = Cursor::new(payload);

    let channel_id = cursor
        .read_u32::<LittleEndian>()
        .map_err(|e| ProtocolError::EncodingError(e.to_string()))?;
    let sequence_number = cursor
        .read_u32::<LittleEndian>()
        .map_err(|e| ProtocolError::EncodingError(e.to_string()))?;
    let job_id = cursor
        .read_u32::<LittleEndian>()
        .map_err(|e| ProtocolError::EncodingError(e.to_string()))?;

    let nonce_2_len = cursor
        .read_u8()
        .map_err(|e| ProtocolError::EncodingError(e.to_string()))? as usize;
    // Validate nonce_2_len (Zcash nonce is 32 bytes total)
    if nonce_2_len > 32 {
        return Err(ProtocolError::EncodingError(format!(
            "nonce_2_len {} exceeds maximum of 32",
            nonce_2_len
        )));
    }
    let mut nonce_2 = vec![0u8; nonce_2_len];
    cursor
        .read_exact(&mut nonce_2)
        .map_err(|e| ProtocolError::EncodingError(e.to_string()))?;

    let time = cursor
        .read_u32::<LittleEndian>()
        .map_err(|e| ProtocolError::EncodingError(e.to_string()))?;

    let mut solution = [0u8; 1344];
    cursor
        .read_exact(&mut solution)
        .map_err(|e| ProtocolError::EncodingError(e.to_string()))?;

    Ok(SubmitEquihashShare {
        channel_id,
        sequence_number,
        job_id,
        nonce_2,
        time,
        solution,
    })
}

/// Generic encode trait
pub trait Encodable {
    fn encode(&self) -> Result<Vec<u8>>;
}

/// Generic decode trait
pub trait Decodable: Sized {
    fn decode(data: &[u8]) -> Result<Self>;
}

impl Encodable for NewEquihashJob {
    fn encode(&self) -> Result<Vec<u8>> {
        encode_new_equihash_job(self)
    }
}

impl Decodable for NewEquihashJob {
    fn decode(data: &[u8]) -> Result<Self> {
        decode_new_equihash_job(data)
    }
}

impl Encodable for SubmitEquihashShare {
    fn encode(&self) -> Result<Vec<u8>> {
        encode_submit_share(self)
    }
}

impl Decodable for SubmitEquihashShare {
    fn decode(data: &[u8]) -> Result<Self> {
        decode_submit_share(data)
    }
}

/// Share result encoding constants
mod share_result_codes {
    pub const ACCEPTED: u8 = 0x00;
    pub const REJECTED: u8 = 0x01;
}

/// Reject reason encoding constants
mod reject_reason_codes {
    pub const STALE_JOB: u8 = 0x00;
    pub const DUPLICATE: u8 = 0x01;
    pub const INVALID_SOLUTION: u8 = 0x02;
    pub const LOW_DIFFICULTY: u8 = 0x03;
    pub const OTHER: u8 = 0xFF;
}

/// Encode a SubmitSharesResponse message
pub fn encode_submit_shares_response(resp: &SubmitSharesResponse) -> Result<Vec<u8>> {
    let mut payload = Vec::new();

    payload.write_u32::<LittleEndian>(resp.channel_id).unwrap();
    payload
        .write_u32::<LittleEndian>(resp.sequence_number)
        .unwrap();

    match &resp.result {
        ShareResult::Accepted => {
            payload.write_u8(share_result_codes::ACCEPTED).unwrap();
        }
        ShareResult::Rejected(reason) => {
            payload.write_u8(share_result_codes::REJECTED).unwrap();
            match reason {
                RejectReason::StaleJob => {
                    payload.write_u8(reject_reason_codes::STALE_JOB).unwrap();
                }
                RejectReason::Duplicate => {
                    payload.write_u8(reject_reason_codes::DUPLICATE).unwrap();
                }
                RejectReason::InvalidSolution => {
                    payload
                        .write_u8(reject_reason_codes::INVALID_SOLUTION)
                        .unwrap();
                }
                RejectReason::LowDifficulty => {
                    payload
                        .write_u8(reject_reason_codes::LOW_DIFFICULTY)
                        .unwrap();
                }
                RejectReason::Other(msg) => {
                    payload.write_u8(reject_reason_codes::OTHER).unwrap();
                    let msg_bytes = msg.as_bytes();
                    let len = msg_bytes.len().min(255);
                    payload.write_u8(len as u8).unwrap();
                    payload.write_all(&msg_bytes[..len]).unwrap();
                }
            }
        }
    }

    let frame = MessageFrame {
        extension_type: 0,
        msg_type: message_types::SUBMIT_SHARES_RESPONSE,
        length: payload.len() as u32,
    };

    let mut result = frame.encode().to_vec();
    result.extend(payload);
    Ok(result)
}

/// Decode a SubmitSharesResponse message
pub fn decode_submit_shares_response(data: &[u8]) -> Result<SubmitSharesResponse> {
    let frame = MessageFrame::decode(data)?;
    if frame.msg_type != message_types::SUBMIT_SHARES_RESPONSE {
        return Err(ProtocolError::InvalidMessageType(frame.msg_type));
    }

    let total_len = MessageFrame::HEADER_SIZE + frame.length as usize;
    if data.len() < total_len {
        return Err(ProtocolError::MessageTooShort {
            expected: total_len,
            actual: data.len(),
        });
    }
    if data.len() > total_len {
        return Err(ProtocolError::EncodingError(
            "trailing bytes in message".into(),
        ));
    }

    let payload = &data[MessageFrame::HEADER_SIZE..total_len];
    let mut cursor = Cursor::new(payload);

    let channel_id = cursor
        .read_u32::<LittleEndian>()
        .map_err(|e| ProtocolError::EncodingError(e.to_string()))?;
    let sequence_number = cursor
        .read_u32::<LittleEndian>()
        .map_err(|e| ProtocolError::EncodingError(e.to_string()))?;
    let result_code = cursor
        .read_u8()
        .map_err(|e| ProtocolError::EncodingError(e.to_string()))?;

    let result = match result_code {
        share_result_codes::ACCEPTED => ShareResult::Accepted,
        share_result_codes::REJECTED => {
            let reason_code = cursor
                .read_u8()
                .map_err(|e| ProtocolError::EncodingError(e.to_string()))?;
            let reason = match reason_code {
                reject_reason_codes::STALE_JOB => RejectReason::StaleJob,
                reject_reason_codes::DUPLICATE => RejectReason::Duplicate,
                reject_reason_codes::INVALID_SOLUTION => RejectReason::InvalidSolution,
                reject_reason_codes::LOW_DIFFICULTY => RejectReason::LowDifficulty,
                reject_reason_codes::OTHER => {
                    let msg_len = cursor
                        .read_u8()
                        .map_err(|e| ProtocolError::EncodingError(e.to_string()))?
                        as usize;
                    let mut msg_bytes = vec![0u8; msg_len];
                    cursor
                        .read_exact(&mut msg_bytes)
                        .map_err(|e| ProtocolError::EncodingError(e.to_string()))?;
                    let msg = String::from_utf8(msg_bytes).map_err(|e| {
                        ProtocolError::EncodingError(format!(
                            "invalid UTF-8 in reject reason: {}",
                            e
                        ))
                    })?;
                    RejectReason::Other(msg)
                }
                _ => {
                    return Err(ProtocolError::EncodingError(format!(
                        "unknown reject reason code: {}",
                        reason_code
                    )));
                }
            };
            ShareResult::Rejected(reason)
        }
        _ => {
            return Err(ProtocolError::EncodingError(format!(
                "unknown share result code: {}",
                result_code
            )));
        }
    };

    Ok(SubmitSharesResponse {
        channel_id,
        sequence_number,
        result,
    })
}

/// Encode a SetTarget message
pub fn encode_set_target(msg: &SetTarget) -> Result<Vec<u8>> {
    let mut payload = Vec::new();

    payload.write_u32::<LittleEndian>(msg.channel_id).unwrap();
    payload.write_all(&msg.target).unwrap();

    let frame = MessageFrame {
        extension_type: 0,
        msg_type: message_types::SET_TARGET,
        length: payload.len() as u32,
    };

    let mut result = frame.encode().to_vec();
    result.extend(payload);
    Ok(result)
}

/// Decode a SetTarget message
pub fn decode_set_target(data: &[u8]) -> Result<SetTarget> {
    let frame = MessageFrame::decode(data)?;
    if frame.msg_type != message_types::SET_TARGET {
        return Err(ProtocolError::InvalidMessageType(frame.msg_type));
    }

    let total_len = MessageFrame::HEADER_SIZE + frame.length as usize;
    if data.len() < total_len {
        return Err(ProtocolError::MessageTooShort {
            expected: total_len,
            actual: data.len(),
        });
    }
    if data.len() > total_len {
        return Err(ProtocolError::EncodingError(
            "trailing bytes in message".into(),
        ));
    }

    let payload = &data[MessageFrame::HEADER_SIZE..total_len];
    let mut cursor = Cursor::new(payload);

    let channel_id = cursor
        .read_u32::<LittleEndian>()
        .map_err(|e| ProtocolError::EncodingError(e.to_string()))?;

    let mut target = [0u8; 32];
    cursor
        .read_exact(&mut target)
        .map_err(|e| ProtocolError::EncodingError(e.to_string()))?;

    Ok(SetTarget { channel_id, target })
}

impl Encodable for SubmitSharesResponse {
    fn encode(&self) -> Result<Vec<u8>> {
        encode_submit_shares_response(self)
    }
}

impl Decodable for SubmitSharesResponse {
    fn decode(data: &[u8]) -> Result<Self> {
        decode_submit_shares_response(data)
    }
}

impl Encodable for SetTarget {
    fn encode(&self) -> Result<Vec<u8>> {
        encode_set_target(self)
    }
}

impl Decodable for SetTarget {
    fn decode(data: &[u8]) -> Result<Self> {
        decode_set_target(data)
    }
}

/// Convenience functions for generic encode/decode
pub fn encode_message<T: Encodable>(msg: &T) -> Result<Vec<u8>> {
    msg.encode()
}

pub fn decode_message<T: Decodable>(data: &[u8]) -> Result<T> {
    T::decode(data)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_frame_roundtrip() {
        let frame = MessageFrame {
            extension_type: 0x1234,
            msg_type: 0x20,
            length: 100,
        };

        let encoded = frame.encode();
        let decoded = MessageFrame::decode(&encoded).unwrap();

        assert_eq!(frame.extension_type, decoded.extension_type);
        assert_eq!(frame.msg_type, decoded.msg_type);
        assert_eq!(frame.length, decoded.length);
    }

    #[test]
    fn test_frame_rejects_oversized_payload() {
        let frame = MessageFrame {
            extension_type: 0,
            msg_type: 0x20,
            length: MAX_FRAME_PAYLOAD + 1,
        };
        let encoded = frame.encode();
        let result = MessageFrame::decode(&encoded);
        assert!(result.is_err());
    }

    #[test]
    fn test_submit_shares_response_accepted_roundtrip() {
        let resp = SubmitSharesResponse {
            channel_id: 42,
            sequence_number: 100,
            result: ShareResult::Accepted,
        };

        let encoded = encode_submit_shares_response(&resp).unwrap();
        let decoded = decode_submit_shares_response(&encoded).unwrap();

        assert_eq!(resp, decoded);
    }

    #[test]
    fn test_submit_shares_response_rejected_stale_roundtrip() {
        let resp = SubmitSharesResponse {
            channel_id: 1,
            sequence_number: 5,
            result: ShareResult::Rejected(RejectReason::StaleJob),
        };

        let encoded = encode_submit_shares_response(&resp).unwrap();
        let decoded = decode_submit_shares_response(&encoded).unwrap();

        assert_eq!(resp, decoded);
    }

    #[test]
    fn test_submit_shares_response_rejected_other_roundtrip() {
        let resp = SubmitSharesResponse {
            channel_id: 3,
            sequence_number: 77,
            result: ShareResult::Rejected(RejectReason::Other("custom error".to_string())),
        };

        let encoded = encode_submit_shares_response(&resp).unwrap();
        let decoded = decode_submit_shares_response(&encoded).unwrap();

        assert_eq!(resp, decoded);
    }

    #[test]
    fn test_submit_shares_response_all_reject_reasons() {
        let reasons = vec![
            RejectReason::StaleJob,
            RejectReason::Duplicate,
            RejectReason::InvalidSolution,
            RejectReason::LowDifficulty,
        ];

        for reason in reasons {
            let resp = SubmitSharesResponse {
                channel_id: 1,
                sequence_number: 1,
                result: ShareResult::Rejected(reason.clone()),
            };

            let encoded = encode_submit_shares_response(&resp).unwrap();
            let decoded = decode_submit_shares_response(&encoded).unwrap();
            assert_eq!(resp, decoded);
        }
    }

    #[test]
    fn test_set_target_roundtrip() {
        let msg = SetTarget {
            channel_id: 99,
            target: [0xab; 32],
        };

        let encoded = encode_set_target(&msg).unwrap();
        let decoded = decode_set_target(&encoded).unwrap();

        assert_eq!(msg, decoded);
    }

    #[test]
    fn test_set_target_trait_roundtrip() {
        let msg = SetTarget {
            channel_id: 7,
            target: [0x01; 32],
        };

        let encoded = msg.encode().unwrap();
        let decoded = SetTarget::decode(&encoded).unwrap();

        assert_eq!(msg, decoded);
    }
}

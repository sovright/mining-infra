//! Zcash transaction parsing for coinbase transactions.
//!
//! Reads the transparent part of v4, v5 (ZIP 225) and v6 (ZIP 230) transactions
//! and records where input 0's scriptSig and the output list sit in the raw
//! bytes, so callers can splice them without reserializing the rest.
//!
//! The two layouts differ in field order:
//!
//! - v4: header, version group, inputs, outputs, lock_time, expiry, shielded data.
//! - v5/v6: header, version group, consensus branch, lock_time, expiry, inputs,
//!   outputs, shielded data.
//!
//! This is not a validator. Shielded data is not parsed; use
//! [`crate::digest`] (zcash_primitives) for txids and auth digests.

use byteorder::{LittleEndian, ReadBytesExt};
use std::io::Cursor;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum ParseError {
    #[error("transaction too short: need {need} bytes, have {have}")]
    TooShort { need: usize, have: usize },
    #[error("unsupported transaction version: {0}")]
    UnsupportedVersion(u32),
    #[error("invalid compact size at offset {0}")]
    InvalidCompactSize(usize),
    #[error("v{0} transaction without the overwinter flag")]
    MissingOverwinterFlag(u32),
}

#[derive(Debug, Clone)]
pub struct TxIn {
    pub prevout_hash: [u8; 32],
    pub prevout_index: u32,
    pub script_sig: Vec<u8>,
    pub sequence: u32,
}

#[derive(Debug, Clone)]
pub struct TxOut {
    pub value: u64,
    pub script_pubkey: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct ParsedTx {
    pub version: u32,
    pub is_overwinter_plus: bool,
    pub version_group_id: Option<u32>,
    pub inputs: Vec<TxIn>,
    pub outputs: Vec<TxOut>,
    pub lock_time: u32,
    pub expiry_height: Option<u32>,
    pub raw: Vec<u8>,
    /// Byte offset of whatever follows the transparent fields: v4 shielded data
    /// after the expiry height, or v5/v6 shielded bundles after the outputs.
    pub trailing_data_offset: Option<usize>,
    /// The consensus branch ID that v5 and later transactions carry.
    pub consensus_branch_id: Option<u32>,
    /// `[start, end)` of input 0's scriptSig, including its CompactSize length.
    pub input0_script_span: Option<(usize, usize)>,
    /// `[start, end)` of the outputs, from the output count to the last output.
    pub outputs_span: (usize, usize),
}

/// Read a Bitcoin-style compact size integer from `data` at `*cursor`.
/// Advances `*cursor` past the value on success.
pub fn read_compact_size(data: &[u8], cursor: &mut usize) -> Result<u64, ParseError> {
    let pos = *cursor;
    if pos >= data.len() {
        return Err(ParseError::InvalidCompactSize(pos));
    }

    let first = data[pos];
    *cursor += 1;

    match first {
        0..=0xfc => Ok(first as u64),
        0xfd => {
            if *cursor + 2 > data.len() {
                return Err(ParseError::InvalidCompactSize(pos));
            }
            let mut rdr = Cursor::new(&data[*cursor..*cursor + 2]);
            let val = rdr.read_u16::<LittleEndian>().unwrap() as u64;
            *cursor += 2;
            Ok(val)
        }
        0xfe => {
            if *cursor + 4 > data.len() {
                return Err(ParseError::InvalidCompactSize(pos));
            }
            let mut rdr = Cursor::new(&data[*cursor..*cursor + 4]);
            let val = rdr.read_u32::<LittleEndian>().unwrap() as u64;
            *cursor += 4;
            Ok(val)
        }
        0xff => {
            if *cursor + 8 > data.len() {
                return Err(ParseError::InvalidCompactSize(pos));
            }
            let mut rdr = Cursor::new(&data[*cursor..*cursor + 8]);
            let val = rdr.read_u64::<LittleEndian>().unwrap();
            *cursor += 8;
            Ok(val)
        }
    }
}

/// Serialize a compact size integer into `buf`.
pub fn push_compact_size(buf: &mut Vec<u8>, n: u64) {
    if n < 0xfd {
        buf.push(n as u8);
    } else if n <= 0xffff {
        buf.push(0xfd);
        buf.extend_from_slice(&(n as u16).to_le_bytes());
    } else if n <= 0xffff_ffff {
        buf.push(0xfe);
        buf.extend_from_slice(&(n as u32).to_le_bytes());
    } else {
        buf.push(0xff);
        buf.extend_from_slice(&n.to_le_bytes());
    }
}

/// Read exactly `n` bytes from `data` starting at `*cursor`.
fn read_bytes(data: &[u8], cursor: &mut usize, n: usize) -> Result<Vec<u8>, ParseError> {
    // `n` can come from a peer-supplied CompactSize, so the end must not wrap.
    let end = match cursor.checked_add(n) {
        Some(end) if end <= data.len() => end,
        _ => {
            return Err(ParseError::TooShort {
                need: cursor.saturating_add(n),
                have: data.len(),
            });
        }
    };
    let result = data[*cursor..end].to_vec();
    *cursor = end;
    Ok(result)
}

/// Read a little-endian u32 from `data` at `*cursor`.
fn read_u32_le(data: &[u8], cursor: &mut usize) -> Result<u32, ParseError> {
    let bytes = read_bytes(data, cursor, 4)?;
    let mut rdr = Cursor::new(bytes);
    Ok(rdr.read_u32::<LittleEndian>().unwrap())
}

/// Read a little-endian u64 from `data` at `*cursor`.
fn read_u64_le(data: &[u8], cursor: &mut usize) -> Result<u64, ParseError> {
    let bytes = read_bytes(data, cursor, 8)?;
    let mut rdr = Cursor::new(bytes);
    Ok(rdr.read_u64::<LittleEndian>().unwrap())
}

/// Parse the transparent part of a v4, v5 or v6 transaction.
pub fn parse_transaction(data: &[u8]) -> Result<ParsedTx, ParseError> {
    if data.len() < 4 {
        return Err(ParseError::TooShort {
            need: 4,
            have: data.len(),
        });
    }

    let mut cursor = 0;

    // Version: lower 31 bits = version, top bit = overwinter flag
    let header = read_u32_le(data, &mut cursor)?;
    let is_overwinter_plus = (header >> 31) == 1;
    let version = header & 0x7fff_ffff;

    let v5_layout = match version {
        4 => false,
        5 | 6 if is_overwinter_plus => true,
        5 | 6 => return Err(ParseError::MissingOverwinterFlag(version)),
        _ => return Err(ParseError::UnsupportedVersion(version)),
    };

    // Version group ID (overwinter+)
    let version_group_id = if is_overwinter_plus {
        Some(read_u32_le(data, &mut cursor)?)
    } else {
        None
    };

    let mut consensus_branch_id = None;
    let mut lock_time = 0;
    let mut expiry_height = None;
    if v5_layout {
        consensus_branch_id = Some(read_u32_le(data, &mut cursor)?);
        lock_time = read_u32_le(data, &mut cursor)?;
        expiry_height = Some(read_u32_le(data, &mut cursor)?);
    }

    // Inputs
    let input_count = read_compact_size(data, &mut cursor)? as usize;
    // Each input is at least 41 bytes; never trust the count for allocation.
    let mut inputs = Vec::with_capacity(input_count.min(data.len() / 41));
    let mut input0_script_span = None;
    for i in 0..input_count {
        let hash_bytes = read_bytes(data, &mut cursor, 32)?;
        let mut prevout_hash = [0u8; 32];
        prevout_hash.copy_from_slice(&hash_bytes);

        let prevout_index = read_u32_le(data, &mut cursor)?;

        let script_start = cursor;
        let script_len = read_compact_size(data, &mut cursor)? as usize;
        let script_sig = read_bytes(data, &mut cursor, script_len)?;
        if i == 0 {
            input0_script_span = Some((script_start, cursor));
        }

        let sequence = read_u32_le(data, &mut cursor)?;

        inputs.push(TxIn {
            prevout_hash,
            prevout_index,
            script_sig,
            sequence,
        });
    }

    // Outputs
    let outputs_start = cursor;
    let output_count = read_compact_size(data, &mut cursor)? as usize;
    // Each output is at least 9 bytes.
    let mut outputs = Vec::with_capacity(output_count.min(data.len() / 9));
    for _ in 0..output_count {
        let value = read_u64_le(data, &mut cursor)?;

        let script_len = read_compact_size(data, &mut cursor)? as usize;
        let script_pubkey = read_bytes(data, &mut cursor, script_len)?;

        outputs.push(TxOut {
            value,
            script_pubkey,
        });
    }
    let outputs_span = (outputs_start, cursor);

    if !v5_layout {
        lock_time = read_u32_le(data, &mut cursor)?;
        if is_overwinter_plus {
            expiry_height = Some(read_u32_le(data, &mut cursor)?);
        }
    }

    let trailing_data_offset = if cursor < data.len() {
        Some(cursor)
    } else {
        None
    };

    Ok(ParsedTx {
        version,
        is_overwinter_plus,
        version_group_id,
        inputs,
        outputs,
        lock_time,
        expiry_height,
        raw: data.to_vec(),
        trailing_data_offset,
        consensus_branch_id,
        input0_script_span,
        outputs_span,
    })
}

/// Build a minimal v4 coinbase transaction for testing.
#[cfg(test)]
pub fn minimal_v4_coinbase() -> Vec<u8> {
    let mut tx = Vec::new();

    // Version 4 with overwinter flag set (0x80000004)
    tx.extend_from_slice(&0x8000_0004u32.to_le_bytes());
    // Version group ID (Sapling: 0x892F2085)
    tx.extend_from_slice(&0x892F_2085u32.to_le_bytes());

    // 1 input (coinbase)
    push_compact_size(&mut tx, 1);
    // Prevout hash: all zeros (coinbase)
    tx.extend_from_slice(&[0u8; 32]);
    // Prevout index: 0xFFFFFFFF (coinbase)
    tx.extend_from_slice(&0xFFFF_FFFFu32.to_le_bytes());
    // Script sig: block height encoding (e.g. height 1)
    let script_sig = vec![0x01, 0x01]; // minimal coinbase script
    push_compact_size(&mut tx, script_sig.len() as u64);
    tx.extend_from_slice(&script_sig);
    // Sequence
    tx.extend_from_slice(&0xFFFF_FFFFu32.to_le_bytes());

    // 2 outputs
    push_compact_size(&mut tx, 2);

    // Output 0: miner reward
    tx.extend_from_slice(&250_000_000u64.to_le_bytes());
    let script0 = vec![0x76, 0xa9, 0x14]; // OP_DUP OP_HASH160 PUSH20 (truncated for test)
    push_compact_size(&mut tx, script0.len() as u64);
    tx.extend_from_slice(&script0);

    // Output 1: dev fund
    tx.extend_from_slice(&62_500_000u64.to_le_bytes());
    let script1 = vec![0xa9, 0x14]; // OP_HASH160 PUSH20 (truncated for test)
    push_compact_size(&mut tx, script1.len() as u64);
    tx.extend_from_slice(&script1);

    // Lock time
    tx.extend_from_slice(&0u32.to_le_bytes());
    // Expiry height
    tx.extend_from_slice(&0u32.to_le_bytes());

    tx
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_v4_coinbase_extracts_outputs() {
        let raw = minimal_v4_coinbase();
        let parsed = parse_transaction(&raw).expect("should parse");

        assert_eq!(parsed.version, 4);
        assert!(parsed.is_overwinter_plus);
        assert_eq!(parsed.version_group_id, Some(0x892F_2085));

        // One coinbase input
        assert_eq!(parsed.inputs.len(), 1);
        assert_eq!(parsed.inputs[0].prevout_hash, [0u8; 32]);
        assert_eq!(parsed.inputs[0].prevout_index, 0xFFFF_FFFF);

        // Two outputs
        assert_eq!(parsed.outputs.len(), 2);
        assert_eq!(parsed.outputs[0].value, 250_000_000);
        assert_eq!(parsed.outputs[1].value, 62_500_000);

        assert_eq!(parsed.lock_time, 0);
        assert_eq!(parsed.expiry_height, Some(0));
    }

    #[test]
    fn push_compact_size_roundtrips() {
        let test_values: Vec<u64> = vec![
            0,
            1,
            0xfc,
            0xfd,
            0xffff,
            0x10000,
            0xffff_ffff,
            0x1_0000_0000,
        ];

        for val in test_values {
            let mut buf = Vec::new();
            push_compact_size(&mut buf, val);
            let mut cursor = 0;
            let decoded = read_compact_size(&buf, &mut cursor).expect("should decode");
            assert_eq!(decoded, val, "roundtrip failed for {val}");
            assert_eq!(cursor, buf.len(), "cursor should be at end for {val}");
        }
    }
}

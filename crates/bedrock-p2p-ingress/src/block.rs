use bedrock_forge::{CompactBlock, PrefilledTx, ZCASH_FULL_HEADER_SIZE};

use crate::error::{IngressError, Result};
use crate::wire::{decode_compact_size, read_u32_le};

const OVERWINTERED_FLAG: u32 = 1 << 31;
const OVERWINTER_VERSION_GROUP_ID: u32 = 0x03C4_8270;
const SAPLING_VERSION_GROUP_ID: u32 = 0x892F_2085;
const TX_V5_VERSION_GROUP_ID: u32 = 0x26A7_270A;
const BCTV14_JOINSPLIT_SIZE: usize =
    8 + 8 + 32 + (32 * 2) + (32 * 2) + 32 + 32 + (32 * 2) + (601 * 2) + 296;
const GROTH16_JOINSPLIT_SIZE: usize =
    8 + 8 + 32 + (32 * 2) + (32 * 2) + 32 + 32 + (32 * 2) + (601 * 2) + 192;
const SAPLING_V4_SPEND_SIZE: usize = 32 + 32 + 32 + 32 + 192 + 64;
const SAPLING_V5_SPEND_PREFIX_SIZE: usize = 32 + 32 + 32;
const SAPLING_OUTPUT_PREFIX_SIZE: usize = 32 + 32 + 32 + 580 + 80;
const SAPLING_OUTPUT_SIZE: usize = SAPLING_OUTPUT_PREFIX_SIZE + 192;
const ORCHARD_ACTION_SIZE: usize = 5 * 32 + 580 + 80;
const REDDSA_SIGNATURE_SIZE: usize = 64;

pub(crate) fn compact_block_from_raw_block(block_payload: &[u8]) -> Result<CompactBlock> {
    let header = block_payload
        .get(..ZCASH_FULL_HEADER_SIZE)
        .ok_or_else(|| IngressError::Wire("block payload shorter than Zcash header".to_string()))?
        .to_vec();

    let mut cursor = ZCASH_FULL_HEADER_SIZE;
    let tx_count = decode_compact_size(block_payload, &mut cursor)?;
    if tx_count == 0 {
        return Err(IngressError::Wire(
            "block payload has no transactions".to_string(),
        ));
    }
    if tx_count > u16::MAX as u64 + 1 {
        return Err(IngressError::Wire(format!(
            "too many transactions for FORGE prefilled indices: {tx_count}"
        )));
    }

    let mut prefilled_txs = Vec::with_capacity(tx_count as usize);
    for index in 0..tx_count {
        let start = cursor;
        skip_transaction(block_payload, &mut cursor)?;
        let tx_data = block_payload
            .get(start..cursor)
            .ok_or_else(|| IngressError::Wire("transaction cursor escaped block".to_string()))?
            .to_vec();
        prefilled_txs.push(PrefilledTx {
            index: index as u16,
            tx_data,
        });
    }

    if cursor != block_payload.len() {
        return Err(IngressError::Wire(format!(
            "trailing bytes after block transactions: {}",
            block_payload.len() - cursor
        )));
    }

    Ok(CompactBlock::new(header, 0, Vec::new(), prefilled_txs))
}

fn skip_transaction(payload: &[u8], cursor: &mut usize) -> Result<()> {
    let header = read_u32_le(payload, cursor)?;
    let version = header & !OVERWINTERED_FLAG;
    let overwintered = header & OVERWINTERED_FLAG != 0;

    match (version, overwintered) {
        (1, false) => {
            skip_transparent_inputs(payload, cursor)?;
            skip_transparent_outputs(payload, cursor)?;
            skip_bytes(payload, cursor, 4, "lock_time")?;
        }
        (2, false) => {
            skip_transparent_inputs(payload, cursor)?;
            skip_transparent_outputs(payload, cursor)?;
            skip_bytes(payload, cursor, 4, "lock_time")?;
            skip_joinsplit_data(payload, cursor, BCTV14_JOINSPLIT_SIZE)?;
        }
        (3, true) => {
            expect_u32(
                payload,
                cursor,
                OVERWINTER_VERSION_GROUP_ID,
                "Overwinter version group",
            )?;
            skip_transparent_inputs(payload, cursor)?;
            skip_transparent_outputs(payload, cursor)?;
            skip_bytes(payload, cursor, 4, "lock_time")?;
            skip_bytes(payload, cursor, 4, "expiry_height")?;
            skip_joinsplit_data(payload, cursor, BCTV14_JOINSPLIT_SIZE)?;
        }
        (4, true) => {
            expect_u32(
                payload,
                cursor,
                SAPLING_VERSION_GROUP_ID,
                "Sapling version group",
            )?;
            skip_transparent_inputs(payload, cursor)?;
            skip_transparent_outputs(payload, cursor)?;
            skip_bytes(payload, cursor, 4, "lock_time")?;
            skip_bytes(payload, cursor, 4, "expiry_height")?;
            skip_v4_sapling_and_sprout(payload, cursor)?;
        }
        (5, true) => {
            expect_u32(payload, cursor, TX_V5_VERSION_GROUP_ID, "v5 version group")?;
            skip_bytes(payload, cursor, 4, "consensus_branch_id")?;
            skip_bytes(payload, cursor, 4, "lock_time")?;
            skip_bytes(payload, cursor, 4, "expiry_height")?;
            skip_transparent_inputs(payload, cursor)?;
            skip_transparent_outputs(payload, cursor)?;
            skip_v5_sapling(payload, cursor)?;
            skip_orchard(payload, cursor)?;
        }
        _ => {
            return Err(IngressError::Wire(format!(
                "unsupported transaction header version={version} overwintered={overwintered}"
            )));
        }
    }

    Ok(())
}

fn skip_transparent_inputs(payload: &[u8], cursor: &mut usize) -> Result<()> {
    let count = decode_compact_size(payload, cursor)?;
    for _ in 0..count {
        skip_bytes(payload, cursor, 32 + 4, "transparent input outpoint")?;
        let script_len = decode_compact_size(payload, cursor)?;
        skip_counted_bytes(payload, cursor, script_len, "transparent input script")?;
        skip_bytes(payload, cursor, 4, "transparent input sequence")?;
    }
    Ok(())
}

fn skip_transparent_outputs(payload: &[u8], cursor: &mut usize) -> Result<()> {
    let count = decode_compact_size(payload, cursor)?;
    for _ in 0..count {
        skip_bytes(payload, cursor, 8, "transparent output value")?;
        let script_len = decode_compact_size(payload, cursor)?;
        skip_counted_bytes(payload, cursor, script_len, "transparent output script")?;
    }
    Ok(())
}

fn skip_v4_sapling_and_sprout(payload: &[u8], cursor: &mut usize) -> Result<()> {
    skip_bytes(payload, cursor, 8, "sapling value balance")?;
    let spend_count = decode_compact_size(payload, cursor)?;
    skip_fixed_items(
        payload,
        cursor,
        spend_count,
        SAPLING_V4_SPEND_SIZE,
        "v4 sapling spend",
    )?;
    let output_count = decode_compact_size(payload, cursor)?;
    skip_fixed_items(
        payload,
        cursor,
        output_count,
        SAPLING_OUTPUT_SIZE,
        "v4 sapling output",
    )?;
    skip_joinsplit_data(payload, cursor, GROTH16_JOINSPLIT_SIZE)?;
    if spend_count > 0 || output_count > 0 {
        skip_bytes(
            payload,
            cursor,
            REDDSA_SIGNATURE_SIZE,
            "sapling binding signature",
        )?;
    }
    Ok(())
}

fn skip_v5_sapling(payload: &[u8], cursor: &mut usize) -> Result<()> {
    let spend_count = decode_compact_size(payload, cursor)?;
    skip_fixed_items(
        payload,
        cursor,
        spend_count,
        SAPLING_V5_SPEND_PREFIX_SIZE,
        "v5 sapling spend prefix",
    )?;
    let output_count = decode_compact_size(payload, cursor)?;
    skip_fixed_items(
        payload,
        cursor,
        output_count,
        SAPLING_OUTPUT_PREFIX_SIZE,
        "v5 sapling output prefix",
    )?;
    if spend_count == 0 && output_count == 0 {
        return Ok(());
    }

    skip_bytes(payload, cursor, 8, "sapling value balance")?;
    if spend_count > 0 {
        skip_bytes(payload, cursor, 32, "sapling shared anchor")?;
    }
    skip_fixed_items(payload, cursor, spend_count, 192, "v5 sapling spend proof")?;
    skip_fixed_items(
        payload,
        cursor,
        spend_count,
        REDDSA_SIGNATURE_SIZE,
        "v5 sapling spend auth signature",
    )?;
    skip_fixed_items(
        payload,
        cursor,
        output_count,
        192,
        "v5 sapling output proof",
    )?;
    skip_bytes(
        payload,
        cursor,
        REDDSA_SIGNATURE_SIZE,
        "sapling binding signature",
    )
}

fn skip_orchard(payload: &[u8], cursor: &mut usize) -> Result<()> {
    let action_count = decode_compact_size(payload, cursor)?;
    skip_fixed_items(
        payload,
        cursor,
        action_count,
        ORCHARD_ACTION_SIZE,
        "orchard action",
    )?;
    if action_count == 0 {
        return Ok(());
    }

    skip_bytes(payload, cursor, 1, "orchard flags")?;
    skip_bytes(payload, cursor, 8, "orchard value balance")?;
    skip_bytes(payload, cursor, 32, "orchard anchor")?;
    let proof_len = decode_compact_size(payload, cursor)?;
    skip_counted_bytes(payload, cursor, proof_len, "orchard proof")?;
    skip_fixed_items(
        payload,
        cursor,
        action_count,
        REDDSA_SIGNATURE_SIZE,
        "orchard spend auth signature",
    )?;
    skip_bytes(
        payload,
        cursor,
        REDDSA_SIGNATURE_SIZE,
        "orchard binding signature",
    )
}

fn skip_joinsplit_data(payload: &[u8], cursor: &mut usize, item_size: usize) -> Result<()> {
    let count = decode_compact_size(payload, cursor)?;
    skip_fixed_items(payload, cursor, count, item_size, "joinsplit")?;
    if count > 0 {
        skip_bytes(payload, cursor, 32, "joinsplit pubkey")?;
        skip_bytes(payload, cursor, 64, "joinsplit signature")?;
    }
    Ok(())
}

fn expect_u32(payload: &[u8], cursor: &mut usize, expected: u32, label: &str) -> Result<()> {
    let actual = read_u32_le(payload, cursor)?;
    if actual != expected {
        return Err(IngressError::Wire(format!(
            "{label} mismatch: expected {expected:#x}, got {actual:#x}"
        )));
    }
    Ok(())
}

fn skip_fixed_items(
    payload: &[u8],
    cursor: &mut usize,
    count: u64,
    item_size: usize,
    label: &str,
) -> Result<()> {
    let count = usize::try_from(count)
        .map_err(|_| IngressError::Wire(format!("{label} count too large")))?;
    let bytes = count
        .checked_mul(item_size)
        .ok_or_else(|| IngressError::Wire(format!("{label} byte count overflow")))?;
    skip_bytes(payload, cursor, bytes, label)
}

fn skip_counted_bytes(payload: &[u8], cursor: &mut usize, len: u64, label: &str) -> Result<()> {
    let len = usize::try_from(len)
        .map_err(|_| IngressError::Wire(format!("{label} length too large")))?;
    skip_bytes(payload, cursor, len, label)
}

fn skip_bytes(payload: &[u8], cursor: &mut usize, len: usize, label: &str) -> Result<()> {
    let end = cursor
        .checked_add(len)
        .ok_or_else(|| IngressError::Wire(format!("{label} cursor overflow")))?;
    if payload.get(*cursor..end).is_none() {
        return Err(IngressError::Wire(format!(
            "unexpected end of payload while reading {label}"
        )));
    }
    *cursor = end;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const NU5_CONSENSUS_BRANCH_ID: u32 = 0xC2D6_D0B4;

    fn push_repeated(bytes: &mut Vec<u8>, len: usize, value: u8) {
        bytes.extend(std::iter::repeat_n(value, len));
    }

    fn minimal_v5_tx(script_tag: u8) -> Vec<u8> {
        let mut tx = Vec::new();
        tx.extend_from_slice(&(OVERWINTERED_FLAG | 5).to_le_bytes());
        tx.extend_from_slice(&TX_V5_VERSION_GROUP_ID.to_le_bytes());
        tx.extend_from_slice(&NU5_CONSENSUS_BRANCH_ID.to_le_bytes());
        tx.extend_from_slice(&0u32.to_le_bytes());
        tx.extend_from_slice(&0u32.to_le_bytes());

        crate::wire::encode_compact_size(1, &mut tx);
        tx.extend_from_slice(&[0u8; 32]);
        tx.extend_from_slice(&0xffff_ffffu32.to_le_bytes());
        crate::wire::encode_compact_size(2, &mut tx);
        tx.extend_from_slice(&[script_tag, script_tag.wrapping_add(1)]);
        tx.extend_from_slice(&0xffff_ffffu32.to_le_bytes());

        crate::wire::encode_compact_size(1, &mut tx);
        tx.extend_from_slice(&0u64.to_le_bytes());
        crate::wire::encode_compact_size(1, &mut tx);
        tx.push(script_tag.wrapping_add(2));

        crate::wire::encode_compact_size(0, &mut tx);
        crate::wire::encode_compact_size(0, &mut tx);
        crate::wire::encode_compact_size(0, &mut tx);
        tx
    }

    fn shielded_v5_tx(tag: u8) -> Vec<u8> {
        let mut tx = Vec::new();
        tx.extend_from_slice(&(OVERWINTERED_FLAG | 5).to_le_bytes());
        tx.extend_from_slice(&TX_V5_VERSION_GROUP_ID.to_le_bytes());
        tx.extend_from_slice(&NU5_CONSENSUS_BRANCH_ID.to_le_bytes());
        tx.extend_from_slice(&0u32.to_le_bytes());
        tx.extend_from_slice(&0u32.to_le_bytes());

        crate::wire::encode_compact_size(0, &mut tx);
        crate::wire::encode_compact_size(0, &mut tx);

        crate::wire::encode_compact_size(1, &mut tx);
        push_repeated(&mut tx, SAPLING_V5_SPEND_PREFIX_SIZE, tag);
        crate::wire::encode_compact_size(1, &mut tx);
        push_repeated(&mut tx, SAPLING_OUTPUT_PREFIX_SIZE, tag.wrapping_add(1));
        tx.extend_from_slice(&0i64.to_le_bytes());
        push_repeated(&mut tx, 32, tag.wrapping_add(2));
        push_repeated(&mut tx, 192, tag.wrapping_add(3));
        push_repeated(&mut tx, REDDSA_SIGNATURE_SIZE, tag.wrapping_add(4));
        push_repeated(&mut tx, 192, tag.wrapping_add(5));
        push_repeated(&mut tx, REDDSA_SIGNATURE_SIZE, tag.wrapping_add(6));

        crate::wire::encode_compact_size(1, &mut tx);
        push_repeated(&mut tx, ORCHARD_ACTION_SIZE, tag.wrapping_add(7));
        tx.push(1);
        tx.extend_from_slice(&0i64.to_le_bytes());
        push_repeated(&mut tx, 32, tag.wrapping_add(8));
        crate::wire::encode_compact_size(3, &mut tx);
        push_repeated(&mut tx, 3, tag.wrapping_add(9));
        push_repeated(&mut tx, REDDSA_SIGNATURE_SIZE, tag.wrapping_add(10));
        push_repeated(&mut tx, REDDSA_SIGNATURE_SIZE, tag.wrapping_add(11));
        tx
    }

    fn shielded_v4_tx(tag: u8) -> Vec<u8> {
        let mut tx = Vec::new();
        tx.extend_from_slice(&(OVERWINTERED_FLAG | 4).to_le_bytes());
        tx.extend_from_slice(&SAPLING_VERSION_GROUP_ID.to_le_bytes());

        crate::wire::encode_compact_size(0, &mut tx);
        crate::wire::encode_compact_size(0, &mut tx);
        tx.extend_from_slice(&0u32.to_le_bytes());
        tx.extend_from_slice(&0u32.to_le_bytes());
        tx.extend_from_slice(&0i64.to_le_bytes());

        crate::wire::encode_compact_size(1, &mut tx);
        push_repeated(&mut tx, SAPLING_V4_SPEND_SIZE, tag);
        crate::wire::encode_compact_size(1, &mut tx);
        push_repeated(&mut tx, SAPLING_OUTPUT_SIZE, tag.wrapping_add(1));
        crate::wire::encode_compact_size(0, &mut tx);
        push_repeated(&mut tx, REDDSA_SIGNATURE_SIZE, tag.wrapping_add(2));
        tx
    }

    #[test]
    fn raw_p2p_block_becomes_all_prefilled_compact_block() {
        let header = vec![0xab; ZCASH_FULL_HEADER_SIZE];
        let tx0 = minimal_v5_tx(0x11);
        let tx1 = minimal_v5_tx(0x22);

        let mut block = header.clone();
        crate::wire::encode_compact_size(2, &mut block);
        block.extend_from_slice(&tx0);
        block.extend_from_slice(&tx1);

        let compact = compact_block_from_raw_block(&block).unwrap();

        assert_eq!(compact.header, header);
        assert!(compact.short_ids.is_empty());
        assert_eq!(compact.prefilled_txs.len(), 2);
        assert_eq!(compact.prefilled_txs[0].index, 0);
        assert_eq!(compact.prefilled_txs[0].tx_data, tx0);
        assert_eq!(compact.prefilled_txs[1].index, 1);
        assert_eq!(compact.prefilled_txs[1].tx_data, tx1);

        let mut reconstructed = compact.header.clone();
        crate::wire::encode_compact_size(compact.prefilled_txs.len() as u64, &mut reconstructed);
        for tx in compact.prefilled_txs {
            reconstructed.extend_from_slice(&tx.tx_data);
        }
        assert_eq!(reconstructed, block);
    }

    #[test]
    fn raw_p2p_block_parser_handles_v4_and_v5_shielded_boundaries() {
        let header = vec![0xcd; ZCASH_FULL_HEADER_SIZE];
        let tx0 = shielded_v4_tx(0x44);
        let tx1 = shielded_v5_tx(0x55);

        let mut block = header;
        crate::wire::encode_compact_size(2, &mut block);
        block.extend_from_slice(&tx0);
        block.extend_from_slice(&tx1);

        let compact = compact_block_from_raw_block(&block).unwrap();

        assert_eq!(compact.prefilled_txs.len(), 2);
        assert_eq!(compact.prefilled_txs[0].tx_data, tx0);
        assert_eq!(compact.prefilled_txs[1].tx_data, tx1);
    }

    #[test]
    fn raw_p2p_block_parser_rejects_trailing_bytes() {
        let header = vec![0xab; ZCASH_FULL_HEADER_SIZE];
        let tx = minimal_v5_tx(0x33);

        let mut block = header;
        crate::wire::encode_compact_size(1, &mut block);
        block.extend_from_slice(&tx);
        block.push(0);

        let err = compact_block_from_raw_block(&block).unwrap_err();
        assert!(err.to_string().contains("trailing bytes"));
    }
}

use sovright_relay::{CompactBlock, PrefilledTx, ShortId, WtxId, ZCASH_FULL_HEADER_SIZE};

use crate::error::{IngressError, Result};
use crate::tx_cache::TxCache;
use crate::wire::{decode_compact_size, read_u32_le};
use crate::wtxid::{SOVRIGHT_P2P_CONSENSUS_BRANCH_ID, wtxid_from_tx_bytes};

const OVERWINTERED_FLAG: u32 = 1 << 31;
const OVERWINTER_VERSION_GROUP_ID: u32 = 0x03C4_8270;
const SAPLING_VERSION_GROUP_ID: u32 = 0x892F_2085;
const TX_V5_VERSION_GROUP_ID: u32 = 0x26A7_270A;
// Transaction v6, introduced by NU6.3/Ironwood (ZIP 229). Verified against
// mainnet: transactions at height 3,428,4xx carry version=6, overwintered=true,
// version_group_id=0xD884B698, consensus_branch_id=0x37A5165B. NOTE this is NOT
// the 0xFFFFFFFF that zcash_primitives <=0.28 uses for its Nu7/ZFuture "V6";
// the on-chain constant only appears from zcash_protocol 0.10.
const TX_V6_VERSION_GROUP_ID: u32 = 0xD884_B698;
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
    compact_block_from_raw_block_with_resolver(block_payload, |_| None)
}

pub(crate) fn compact_block_from_raw_block_with_tx_cache(
    block_payload: &[u8],
    tx_cache: &TxCache,
) -> Result<CompactBlock> {
    compact_block_from_raw_block_with_resolver(block_payload, |tx_payload| {
        tx_cache.wtxid_for_payload(tx_payload)
    })
}

/// Build the compact *skeleton* for a raw block: the coinbase prefilled, and a
/// short_id for every non-coinbase transaction the origin can resolve to a
/// wtxid, so each receiver resolves those short_ids against its OWN mempool.
///
/// The origin can only compute a short_id for a transaction whose wtxid it
/// already knows: its tx cache is a reverse payload->wtxid index, not a Zcash
/// transaction hasher, so it cannot derive a wtxid for a transaction it never
/// saw on the P2P network. Non-coinbase transactions the cache cannot resolve
/// are therefore prefilled -- unavoidable, and still correct (the receiver
/// reconstructs those verbatim). In the steady state, where the origin cache
/// holds every non-coinbase transaction, the skeleton collapses to
/// header + coinbase + all-short_ids: a single UDP packet.
///
/// Unlike the normal compact builder, the skeleton also resolves cache-MISS
/// transactions by hashing their raw bytes: for each non-coinbase tx not found
/// in the cache, it computes the wtxid directly with `wtxid_from_tx_bytes`
/// (v5/ZIP-244 only) and emits a short_id, falling back to a prefill only when
/// that too fails (pre-v5, or unparseable). This is what makes the skeleton
/// genuinely smaller than the cache alone allows -- the origin no longer has to
/// have seen a transaction on the P2P network to short_id it, matching the
/// sidecar mempool's own v5-only wtxid construction so the short_ids resolve on
/// the receivers.
///
/// This is, by construction, the maximally short-id'd tx-cache compaction. It
/// is named and documented separately because it is the *fast-path* object: it
/// is sent first and with heavier FEC parity, ahead of the full compact block.
pub(crate) fn skeleton_compact_block_from_raw_block(
    block_payload: &[u8],
    tx_cache: &TxCache,
) -> Result<CompactBlock> {
    compact_block_from_raw_block_with_resolver(block_payload, |tx_payload| {
        tx_cache
            .wtxid_for_payload(tx_payload)
            .or_else(|| wtxid_from_tx_bytes(tx_payload, SOVRIGHT_P2P_CONSENSUS_BRANCH_ID))
    })
}

fn compact_block_from_raw_block_with_resolver<F>(
    block_payload: &[u8],
    mut resolve_wtxid: F,
) -> Result<CompactBlock>
where
    F: FnMut(&[u8]) -> Option<WtxId>,
{
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
            "too many transactions for relay prefilled indices: {tx_count}"
        )));
    }

    let header_hash = sovright_relay::zcash_block_hash(&header);
    let nonce = 0;
    let mut short_ids = Vec::new();
    let mut prefilled_txs = Vec::with_capacity(tx_count as usize);
    let mut last_prefilled_index: i64 = -1;
    for index in 0..tx_count {
        let start = cursor;
        skip_transaction(block_payload, &mut cursor)?;
        let tx_data = block_payload
            .get(start..cursor)
            .ok_or_else(|| IngressError::Wire("transaction cursor escaped block".to_string()))?;
        if index > 0
            && let Some(wtxid) = resolve_wtxid(tx_data)
        {
            short_ids.push(ShortId::compute(&wtxid, &header_hash, nonce));
            continue;
        }
        let diff = index as i64 - last_prefilled_index - 1;
        prefilled_txs.push(PrefilledTx {
            index: diff as u16,
            tx_data: tx_data.to_vec(),
        });
        last_prefilled_index = index as i64;
    }

    if cursor != block_payload.len() {
        return Err(IngressError::Wire(format!(
            "trailing bytes after block transactions: {}",
            block_payload.len() - cursor
        )));
    }

    Ok(CompactBlock::new(header, nonce, short_ids, prefilled_txs))
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
        (6, true) => {
            // ZIP 229. Identical to v5 through the Sapling bundle, then TWO
            // Orchard-format bundles: the Orchard slot followed by the Ironwood
            // slot. Both use the same wire layout -- per zcash_primitives 0.29
            // `read_bundle`, the bundle version changes only how the flags BYTE
            // is interpreted (bit 2 cross-address), not any field's size -- so
            // skip_orchard is length-correct for both. Omitting the second
            // bundle would leave it unconsumed and mis-offset every following
            // transaction in the block.
            expect_u32(payload, cursor, TX_V6_VERSION_GROUP_ID, "v6 version group")?;
            skip_bytes(payload, cursor, 4, "consensus_branch_id")?;
            skip_bytes(payload, cursor, 4, "lock_time")?;
            skip_bytes(payload, cursor, 4, "expiry_height")?;
            skip_transparent_inputs(payload, cursor)?;
            skip_transparent_outputs(payload, cursor)?;
            skip_v5_sapling(payload, cursor)?;
            skip_orchard(payload, cursor)?;
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
    use crate::tx_cache::{TxCache, TxCacheConfig, TxInventoryKey};
    use sovright_relay::{CompactBlockReconstructor, ReconstructionResult, ShortId};

    const NU5_CONSENSUS_BRANCH_ID: u32 = 0xC2D6_D0B4;
    const NU63_CONSENSUS_BRANCH_ID: u32 = 0x37A5_165B;

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

    /// v6 (ZIP 229, NU6.3/Ironwood). Identical to v5 through the Sapling bundle,
    /// then TWO Orchard-format bundles: the Orchard slot and the Ironwood slot.
    /// `ironwood_actions` > 0 exercises the second bundle, which a parser that
    /// stops after the first would silently mis-offset.
    fn minimal_v6_tx(script_tag: u8, ironwood_actions: u64) -> Vec<u8> {
        let mut tx = Vec::new();
        tx.extend_from_slice(&(OVERWINTERED_FLAG | 6).to_le_bytes());
        tx.extend_from_slice(&TX_V6_VERSION_GROUP_ID.to_le_bytes());
        tx.extend_from_slice(&NU63_CONSENSUS_BRANCH_ID.to_le_bytes());
        tx.extend_from_slice(&0u32.to_le_bytes()); // lock_time
        tx.extend_from_slice(&0u32.to_le_bytes()); // expiry_height

        // transparent inputs
        crate::wire::encode_compact_size(1, &mut tx);
        tx.extend_from_slice(&[0u8; 32]);
        tx.extend_from_slice(&0xffff_ffffu32.to_le_bytes());
        crate::wire::encode_compact_size(2, &mut tx);
        tx.extend_from_slice(&[script_tag, script_tag.wrapping_add(1)]);
        tx.extend_from_slice(&0xffff_ffffu32.to_le_bytes());
        // transparent outputs
        crate::wire::encode_compact_size(1, &mut tx);
        tx.extend_from_slice(&0u64.to_le_bytes());
        crate::wire::encode_compact_size(1, &mut tx);
        tx.push(script_tag.wrapping_add(2));

        crate::wire::encode_compact_size(0, &mut tx); // sapling spends
        crate::wire::encode_compact_size(0, &mut tx); // sapling outputs
        crate::wire::encode_compact_size(0, &mut tx); // orchard slot: 0 actions
        push_orchard_bundle(&mut tx, ironwood_actions); // ironwood slot
        tx
    }

    /// Minimal Orchard-format bundle body; `actions == 0` is just the count.
    fn push_orchard_bundle(tx: &mut Vec<u8>, actions: u64) {
        crate::wire::encode_compact_size(actions, tx);
        if actions == 0 {
            return;
        }
        for _ in 0..actions {
            tx.extend_from_slice(&[7u8; ORCHARD_ACTION_SIZE]);
        }
        tx.push(0); // flags
        tx.extend_from_slice(&0u64.to_le_bytes()); // value balance
        tx.extend_from_slice(&[0u8; 32]); // anchor
        crate::wire::encode_compact_size(2, tx); // proof
        tx.extend_from_slice(&[1u8, 2u8]);
        for _ in 0..actions {
            tx.extend_from_slice(&[3u8; REDDSA_SIGNATURE_SIZE]);
        }
        tx.extend_from_slice(&[4u8; REDDSA_SIGNATURE_SIZE]); // binding sig
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
        assert_eq!(compact.prefilled_txs[1].index, 0);
        assert_eq!(compact.prefilled_txs[1].tx_data, tx1);

        let mut reconstructed = compact.header.clone();
        crate::wire::encode_compact_size(compact.prefilled_txs.len() as u64, &mut reconstructed);
        for tx in compact.prefilled_txs {
            reconstructed.extend_from_slice(&tx.tx_data);
        }
        assert_eq!(reconstructed, block);
    }

    #[test]
    fn cached_non_coinbase_transactions_become_short_ids() {
        let tx0 = minimal_v5_tx(0x11);
        let tx1 = minimal_v5_tx(0x22);
        let tx2 = minimal_v5_tx(0x33);
        // Reconstruction verifies the header's merkle commitment, so this
        // header has to commit to these three transactions; filler bytes would
        // be rejected before the short-id resolution under test ever runs.
        let header = {
            let mut h = vec![0xab; ZCASH_FULL_HEADER_SIZE];
            let txids: Vec<[u8; 32]> = [&tx0, &tx1, &tx2]
                .iter()
                .map(|t| sovright_relay::txid_from_tx_bytes(t))
                .collect();
            h[36..68].copy_from_slice(&sovright_relay::merkle_root(&txids).unwrap());
            h
        };

        let mut block = header.clone();
        crate::wire::encode_compact_size(3, &mut block);
        block.extend_from_slice(&tx0);
        block.extend_from_slice(&tx1);
        block.extend_from_slice(&tx2);

        let cache = TxCache::new(TxCacheConfig {
            max_entries: 8,
            max_bytes: 4_096,
            max_tx_bytes: 2_048,
        });
        let cached_key = TxInventoryKey::wtx([0x41; 32], [0x42; 32]);
        cache.insert(cached_key.to_wtxid(), tx1.clone());

        let compact = compact_block_from_raw_block_with_tx_cache(&block, &cache).unwrap();

        let header_hash = sovright_relay::zcash_block_hash(&header);
        let expected_short_id = ShortId::compute(&cached_key.to_wtxid(), &header_hash, 0);
        assert_eq!(compact.header, header);
        assert_eq!(compact.short_ids, vec![expected_short_id]);
        assert_eq!(compact.prefilled_txs.len(), 2);
        assert_eq!(compact.prefilled_txs[0].index, 0);
        assert_eq!(compact.prefilled_txs[0].tx_data, tx0);
        assert_eq!(compact.prefilled_txs[1].index, 1);
        assert_eq!(compact.prefilled_txs[1].tx_data, tx2);

        let mut reconstructor = CompactBlockReconstructor::new(&cache);
        reconstructor.prepare(&header_hash, compact.nonce);
        match reconstructor.reconstruct(&compact) {
            ReconstructionResult::Complete { transactions } => {
                assert_eq!(transactions, vec![tx0, tx1, tx2]);
            }
            ReconstructionResult::Incomplete { .. } => {
                panic!("expected cached compact block to reconstruct");
            }
            ReconstructionResult::Invalid { reason } => {
                panic!("unexpected invalid compact block: {reason}");
            }
        }
    }

    #[test]
    fn skeleton_prefills_only_coinbase_and_short_ids_all_resolvable_txs() {
        // With the origin cache holding every non-coinbase transaction, the
        // skeleton prefills ONLY the coinbase (index 0) and emits a short_id for
        // each other transaction, computed exactly as ShortId::compute expects.
        let header = vec![0xab; ZCASH_FULL_HEADER_SIZE];
        let coinbase = minimal_v5_tx(0x11);
        let tx1 = minimal_v5_tx(0x22);
        let tx2 = minimal_v5_tx(0x33);

        let mut block = header.clone();
        crate::wire::encode_compact_size(3, &mut block);
        block.extend_from_slice(&coinbase);
        block.extend_from_slice(&tx1);
        block.extend_from_slice(&tx2);

        let cache = TxCache::new(TxCacheConfig {
            max_entries: 8,
            max_bytes: 8_192,
            max_tx_bytes: 2_048,
        });
        let tx1_key = TxInventoryKey::wtx([0x51; 32], [0x52; 32]);
        let tx2_key = TxInventoryKey::wtx([0x53; 32], [0x54; 32]);
        cache.insert(tx1_key.to_wtxid(), tx1.clone());
        cache.insert(tx2_key.to_wtxid(), tx2.clone());

        let skeleton = skeleton_compact_block_from_raw_block(&block, &cache).unwrap();

        let header_hash = sovright_relay::zcash_block_hash(&header);
        assert_eq!(skeleton.header, header);
        // Only the coinbase is prefilled.
        assert_eq!(skeleton.prefilled_txs.len(), 1);
        assert_eq!(skeleton.prefilled_txs[0].index, 0);
        assert_eq!(skeleton.prefilled_txs[0].tx_data, coinbase);
        // Every non-coinbase tx is a short_id matching ShortId::compute.
        assert_eq!(
            skeleton.short_ids,
            vec![
                ShortId::compute(&tx1_key.to_wtxid(), &header_hash, skeleton.nonce),
                ShortId::compute(&tx2_key.to_wtxid(), &header_hash, skeleton.nonce),
            ]
        );
    }

    #[test]
    fn skeleton_prefills_txs_the_origin_cannot_resolve() {
        // A non-coinbase tx that is neither cached NOR resolvable from its raw
        // bytes -- here a pre-v5 (v4) tx, which has no ZIP-244 auth digest --
        // still cannot be short_id'd and is prefilled verbatim (unavoidable and
        // still correct). The cached tx becomes a short_id; the coinbase and the
        // pre-v5 tx are prefilled.
        //
        // (A cache-MISS *v5* tx, by contrast, is now short_id'd from its bytes;
        // see `skeleton_short_ids_cache_miss_v5_txs_from_bytes`.)
        let header = vec![0xcd; ZCASH_FULL_HEADER_SIZE];
        let coinbase = minimal_v5_tx(0x11);
        let cached = minimal_v5_tx(0x22);
        let unresolvable = shielded_v4_tx(0x33);

        let mut block = header;
        crate::wire::encode_compact_size(3, &mut block);
        block.extend_from_slice(&coinbase);
        block.extend_from_slice(&cached);
        block.extend_from_slice(&unresolvable);

        let cache = TxCache::new(TxCacheConfig {
            max_entries: 8,
            max_bytes: 8_192,
            max_tx_bytes: 2_048,
        });
        cache.insert(
            TxInventoryKey::wtx([0x61; 32], [0x62; 32]).to_wtxid(),
            cached,
        );

        let skeleton = skeleton_compact_block_from_raw_block(&block, &cache).unwrap();

        assert_eq!(skeleton.short_ids.len(), 1);
        // coinbase (index 0) + the pre-v5 tx are prefilled.
        assert_eq!(skeleton.prefilled_txs.len(), 2);
        assert_eq!(skeleton.prefilled_txs[0].tx_data, coinbase);
        assert_eq!(skeleton.prefilled_txs[1].tx_data, unresolvable);
    }

    // NU6.3/Ironwood (2026-07-28, height 3,428,143) introduced transaction v6
    // (ZIP 229, version group id 0xD884B698). The parser only knew v3/v4/v5, so
    // every block containing a v6 transaction failed to forward: 93 of 97 blocks
    // in the first half hour after peers resumed relaying to us.
    #[test]
    fn parses_v6_transaction_with_empty_ironwood_bundle() {
        let tx = minimal_v6_tx(0x11, 0);
        let mut cursor = 0usize;
        skip_transaction(&tx, &mut cursor).expect("v6 must parse");
        assert_eq!(cursor, tx.len(), "parser must consume exactly the whole tx");
    }

    #[test]
    fn parses_v6_transaction_with_populated_ironwood_bundle() {
        // The case that matters: a parser that stopped after the Orchard slot
        // would leave the Ironwood bundle unconsumed and mis-offset every
        // following transaction in the block.
        let tx = minimal_v6_tx(0x22, 2);
        let mut cursor = 0usize;
        skip_transaction(&tx, &mut cursor).expect("v6 with ironwood actions must parse");
        assert_eq!(cursor, tx.len());
    }

    /// Real mainnet Ironwood transaction, captured from block 3428505
    /// (txid 1ff3e45d12e8df4e...). Synthetic fixtures only prove the
    /// parser is self-consistent; this proves it agrees with what Zcash actually
    /// serialises. If a future change breaks v6 offsets, this fails.
    const REAL_MAINNET_V6_TX_HEX: &str = "0600008098b684d85b16a5370000000099503400010000000000000000000000000000000000\
         000000000000000000000000000000ffffffff090399503404f09fa693ffffffff0240597307\
         000000001976a91425db9091e9786867e536f70089a5102523ab1d6a88ac20bcbe0000000000\
         17a914c20cd5bdf7964ca61764db66bc2531b1792a084d8700000000";

    #[test]
    fn parses_a_real_mainnet_ironwood_v6_transaction() {
        let tx = hex_to_bytes(REAL_MAINNET_V6_TX_HEX);
        let header = u32::from_le_bytes(tx[0..4].try_into().unwrap());
        assert_eq!(header & 0x7FFF_FFFF, 6, "fixture must be a v6 tx");
        assert_eq!(
            u32::from_le_bytes(tx[4..8].try_into().unwrap()),
            TX_V6_VERSION_GROUP_ID,
            "fixture must carry the on-chain v6 version group id"
        );

        let mut cursor = 0usize;
        skip_transaction(&tx, &mut cursor).expect("real mainnet v6 tx must parse");
        assert_eq!(
            cursor,
            tx.len(),
            "parser must consume exactly the real transaction, no more, no less"
        );
    }

    fn hex_to_bytes(s: &str) -> Vec<u8> {
        let clean: String = s.chars().filter(|c| c.is_ascii_hexdigit()).collect();
        (0..clean.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&clean[i..i + 2], 16).unwrap())
            .collect()
    }

    #[test]
    fn v6_rejects_wrong_version_group_id() {
        let mut tx = minimal_v6_tx(0x33, 0);
        // corrupt the version group id; must fail loudly rather than mis-parse
        tx[4..8].copy_from_slice(&TX_V5_VERSION_GROUP_ID.to_le_bytes());
        let mut cursor = 0usize;
        assert!(skip_transaction(&tx, &mut cursor).is_err());
    }

    #[test]
    fn skeleton_short_ids_cache_miss_v5_txs_from_bytes() {
        // The whole point of this change: with an EMPTY origin cache, a
        // non-coinbase v5 transaction is still short_id'd -- the skeleton hashes
        // its raw bytes to the same wtxid the sidecar would. The coinbase stays
        // prefilled, and the normal (non-skeleton) builder is UNCHANGED: it has
        // no from-bytes fallback and prefills the same tx.
        let header = vec![0xab; ZCASH_FULL_HEADER_SIZE];
        let coinbase = minimal_v5_tx(0x11);
        let tx1 = minimal_v5_tx(0x22);

        let mut block = header.clone();
        crate::wire::encode_compact_size(2, &mut block);
        block.extend_from_slice(&coinbase);
        block.extend_from_slice(&tx1);

        let cache = TxCache::new(TxCacheConfig {
            max_entries: 8,
            max_bytes: 8_192,
            max_tx_bytes: 4_096,
        });

        let skeleton = skeleton_compact_block_from_raw_block(&block, &cache).unwrap();
        let header_hash = sovright_relay::zcash_block_hash(&header);

        // Coinbase prefilled; tx1 became a short_id computed from its own bytes.
        assert_eq!(skeleton.prefilled_txs.len(), 1);
        assert_eq!(skeleton.prefilled_txs[0].index, 0);
        assert_eq!(skeleton.prefilled_txs[0].tx_data, coinbase);
        let expected_wtxid =
            crate::wtxid::wtxid_from_tx_bytes(&tx1, crate::wtxid::SOVRIGHT_P2P_CONSENSUS_BRANCH_ID)
                .expect("minimal v5 tx must resolve from bytes");
        assert_eq!(
            skeleton.short_ids,
            vec![ShortId::compute(
                &expected_wtxid,
                &header_hash,
                skeleton.nonce
            )]
        );

        // Normal builder, same empty cache: tx1 is prefilled, no short_ids.
        let normal = compact_block_from_raw_block_with_tx_cache(&block, &cache).unwrap();
        assert!(normal.short_ids.is_empty());
        assert_eq!(normal.prefilled_txs.len(), 2);
        assert_eq!(normal.prefilled_txs[1].tx_data, tx1);
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

#[cfg(test)]
mod real_block_round_trip {
    use super::*;
    use crate::tx_cache::TxCacheConfig;
    use sovright_relay::{CompactBlockReconstructor, ReconstructionResult};

    /// Mainnet block 3470793: header on line 1, then its 7 transactions in
    /// block order. Five are v6 (ZIP-229, NU6.3) and two are v4.
    const FIXTURE: &str =
        include_str!("../../sovright-relay/tests/fixtures/mainnet_block_3470793.txt");

    fn fixture() -> (Vec<u8>, Vec<Vec<u8>>) {
        let mut lines = FIXTURE.lines().filter(|l| !l.trim().is_empty());
        let header = hex::decode(lines.next().unwrap().trim()).unwrap();
        let txs = lines.map(|l| hex::decode(l.trim()).unwrap()).collect();
        (header, txs)
    }

    fn raw_block(header: &[u8], txs: &[Vec<u8>]) -> Vec<u8> {
        let mut block = header.to_vec();
        crate::wire::encode_compact_size(txs.len() as u64, &mut block);
        for tx in txs {
            block.extend_from_slice(tx);
        }
        block
    }

    /// End-to-end on real mainnet bytes: build the compact block the ingress
    /// would send, reconstruct it exactly as a relay does, and require the
    /// result to be the block we started from.
    ///
    /// Every previous round-trip test used synthetic transactions, which parse
    /// as neither v5 nor v6 -- so nothing exercised a real NU6.3 block through
    /// this path, and the merkle check that now guards it had nothing real to
    /// judge.
    #[test]
    fn real_mainnet_block_round_trips_through_compact_reconstruction() {
        let (header, txs) = fixture();
        let block = raw_block(&header, &txs);

        // Receiver holds every non-coinbase transaction it can key by wtxid --
        // the best case for reconstruction. v4 transactions have no auth digest
        // so they stay prefilled, exactly as in production.
        let cache = TxCache::new(TxCacheConfig {
            max_entries: 64,
            max_bytes: 1 << 20,
            max_tx_bytes: 1 << 16,
        });
        for tx in txs.iter().skip(1) {
            if let Some(wtxid) = wtxid_from_tx_bytes(tx, SOVRIGHT_P2P_CONSENSUS_BRANCH_ID) {
                cache.insert(wtxid, tx.clone());
            }
        }

        let compact = compact_block_from_raw_block_with_tx_cache(&block, &cache).unwrap();
        assert_eq!(compact.tx_count(), txs.len());

        let header_hash = sovright_relay::zcash_block_hash(&header);
        let mut reconstructor = CompactBlockReconstructor::new(&cache);
        reconstructor.prepare(&header_hash, compact.nonce);

        match reconstructor.reconstruct(&compact) {
            ReconstructionResult::Complete { transactions } => {
                assert_eq!(transactions, txs, "reconstructed a different block");
            }
            ReconstructionResult::Invalid { reason } => {
                panic!("real block failed reconstruction: {reason}");
            }
            ReconstructionResult::Incomplete {
                missing_wtxids,
                unresolved_short_ids,
                ..
            } => {
                panic!(
                    "real block incomplete: {} missing wtxids, {} unresolved short ids",
                    missing_wtxids.len(),
                    unresolved_short_ids.len()
                );
            }
        }
    }

    /// Same real block through the SKELETON path -- the fast-path object that
    /// is actually failing in production (skeleton_incomplete/submit errors on
    /// every relay). The origin short_ids v5/v6 by hashing bytes; the receiver
    /// must resolve those against its own mempool.
    #[test]
    fn real_mainnet_block_round_trips_through_the_skeleton_path() {
        let (header, txs) = fixture();
        let block = raw_block(&header, &txs);

        // Origin cache is EMPTY: the skeleton is meant to short_id v5/v6 by
        // hashing raw bytes even for transactions it never saw on the P2P.
        let origin = TxCache::new(TxCacheConfig {
            max_entries: 64,
            max_bytes: 1 << 20,
            max_tx_bytes: 1 << 16,
        });
        let skeleton = skeleton_compact_block_from_raw_block(&block, &origin).unwrap();

        // Receiver holds every transaction the origin could short_id.
        let receiver = TxCache::new(TxCacheConfig {
            max_entries: 64,
            max_bytes: 1 << 20,
            max_tx_bytes: 1 << 16,
        });
        for tx in txs.iter().skip(1) {
            if let Some(wtxid) = wtxid_from_tx_bytes(tx, SOVRIGHT_P2P_CONSENSUS_BRANCH_ID) {
                receiver.insert(wtxid, tx.clone());
            }
        }

        let header_hash = sovright_relay::zcash_block_hash(&header);
        let mut reconstructor = CompactBlockReconstructor::new(&receiver);
        reconstructor.prepare(&header_hash, skeleton.nonce);

        match reconstructor.reconstruct(&skeleton) {
            ReconstructionResult::Complete { transactions } => {
                assert_eq!(
                    transactions, txs,
                    "skeleton reconstructed a different block"
                );
            }
            ReconstructionResult::Invalid { reason } => {
                panic!("real block failed skeleton reconstruction: {reason}");
            }
            ReconstructionResult::Incomplete {
                missing_wtxids,
                unresolved_short_ids,
                ..
            } => {
                panic!(
                    "skeleton incomplete: {} missing wtxids, {} unresolved short ids, {} short_ids sent, {} prefilled",
                    missing_wtxids.len(),
                    unresolved_short_ids.len(),
                    skeleton.short_ids.len(),
                    skeleton.prefilled_txs.len(),
                );
            }
        }
    }
}

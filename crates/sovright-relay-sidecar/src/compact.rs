//! Build CompactBlock from Zebra block templates

use crate::rpc::BlockTemplate;
use sovright_relay::{
    AuthDigest, CompactBlock, PrefilledTx, ShortId, TxId, WtxId, zcash_block_hash,
};
use tracing::warn;

/// Equihash solution size for Zcash (n=200, k=9)
const EQUIHASH_SOLUTION_SIZE: usize = 1344;

/// Build a CompactBlock from a BlockTemplate
pub fn build_compact_block(
    template: &BlockTemplate,
    nonce: u64,
) -> Result<CompactBlock, CompactBlockError> {
    // Build the block header
    let header_bytes = build_header(template)?;

    // Compute header hash for short IDs
    let header_hash = compute_header_hash(&header_bytes);

    // Prefill coinbase
    let coinbase_data = template
        .coinbase_txn
        .as_ref()
        .map(|c| hex::decode(&c.data))
        .transpose()
        .map_err(|_| CompactBlockError::InvalidHex("coinbase".into()))?
        .unwrap_or_default();

    let prefilled = vec![PrefilledTx {
        index: 0,
        tx_data: coinbase_data,
    }];

    // Build short IDs for transactions
    let short_ids: Vec<ShortId> = template
        .transactions
        .iter()
        .filter_map(|tx| {
            match hex::decode(&tx.hash) {
                Ok(hash_bytes) if hash_bytes.len() == 32 => {
                    let mut txid_bytes = [0u8; 32];
                    txid_bytes.copy_from_slice(&hash_bytes);
                    // Zebra returns little-endian hash, reverse for txid
                    txid_bytes.reverse();
                    let txid = TxId::from_bytes(txid_bytes);
                    // Zcash v4 transactions don't have auth digest
                    let wtxid = WtxId::new(txid, AuthDigest::from_bytes([0u8; 32]));
                    Some(ShortId::compute(&wtxid, &header_hash, nonce))
                }
                _ => {
                    warn!(tx_hash = %tx.hash, "Failed to decode transaction hash, skipping");
                    None
                }
            }
        })
        .collect();

    Ok(CompactBlock::new(header_bytes, nonce, short_ids, prefilled))
}

/// Build the full block header from template
fn build_header(template: &BlockTemplate) -> Result<Vec<u8>, CompactBlockError> {
    let mut header = Vec::with_capacity(140 + 3 + EQUIHASH_SOLUTION_SIZE);

    // Version (4 bytes, little-endian)
    header.extend_from_slice(&template.version.to_le_bytes());

    // Previous block hash (32 bytes)
    let prev_hash = hex::decode(&template.previous_block_hash)
        .map_err(|_| CompactBlockError::InvalidHex("previous_block_hash".into()))?;
    if prev_hash.len() != 32 {
        return Err(CompactBlockError::InvalidLength(
            "previous_block_hash".into(),
        ));
    }
    header.extend_from_slice(&prev_hash);

    // Merkle root (32 bytes)
    let merkle_root = template
        .default_roots
        .as_ref()
        .map(|r| hex::decode(&r.merkle_root))
        .transpose()
        .map_err(|_| CompactBlockError::InvalidHex("merkle_root".into()))?
        .unwrap_or_else(|| vec![0u8; 32]);
    if merkle_root.len() != 32 {
        return Err(CompactBlockError::InvalidLength("merkle_root".into()));
    }
    header.extend_from_slice(&merkle_root);

    // Reserved field / final sapling root (32 bytes) - use chain history root or zeros
    let reserved = template
        .default_roots
        .as_ref()
        .and_then(|r| r.chain_history_root.as_ref())
        .map(hex::decode)
        .transpose()
        .map_err(|_| CompactBlockError::InvalidHex("chain_history_root".into()))?
        .unwrap_or_else(|| vec![0u8; 32]);
    if reserved.len() != 32 {
        return Err(CompactBlockError::InvalidLength("reserved".into()));
    }
    header.extend_from_slice(&reserved);

    // Time (4 bytes, little-endian)
    if template.cur_time > u32::MAX as u64 {
        return Err(CompactBlockError::InvalidLength(format!(
            "timestamp {} exceeds u32::MAX",
            template.cur_time
        )));
    }
    header.extend_from_slice(&(template.cur_time as u32).to_le_bytes());

    // Bits (4 bytes)
    let bits =
        hex::decode(&template.bits).map_err(|_| CompactBlockError::InvalidHex("bits".into()))?;
    if bits.len() != 4 {
        return Err(CompactBlockError::InvalidLength("bits".into()));
    }
    header.extend_from_slice(&bits);

    // Nonce (32 bytes) - placeholder for mining
    header.extend_from_slice(&[0u8; 32]);

    // Equihash solution - compactSize + placeholder
    header.push(0xfd); // compactSize prefix for 1344
    header.extend_from_slice(&(EQUIHASH_SOLUTION_SIZE as u16).to_le_bytes());
    header.extend(std::iter::repeat_n(0u8, EQUIHASH_SOLUTION_SIZE));

    Ok(header)
}

/// Compute the Zcash header hash.
fn compute_header_hash(header: &[u8]) -> [u8; 32] {
    zcash_block_hash(header)
}

#[derive(Debug)]
pub enum CompactBlockError {
    InvalidHex(String),
    InvalidLength(String),
}

impl std::fmt::Display for CompactBlockError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CompactBlockError::InvalidHex(field) => write!(f, "invalid hex in field: {}", field),
            CompactBlockError::InvalidLength(field) => {
                write!(f, "invalid length for field: {}", field)
            }
        }
    }
}

impl std::error::Error for CompactBlockError {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mempool_sync::wtxid_from_display_hex;
    use crate::rpc::{CoinbaseTxn, DefaultRoots};
    use sovright_relay::{CompactBlockReconstructor, ReconstructionResult, TestMempool, merkle};

    #[test]
    fn build_compact_from_template() {
        let template = BlockTemplate {
            version: 4,
            previous_block_hash: "00".repeat(32),
            cur_time: 1700000000,
            bits: "1f07ffff".to_string(),
            height: 100,
            transactions: vec![],
            coinbase_txn: Some(CoinbaseTxn {
                data: "01000000010000".to_string(),
            }),
            default_roots: Some(DefaultRoots {
                merkle_root: "ab".repeat(32),
                block_commitments_hash: None,
                chain_history_root: None,
                auth_data_root: None,
            }),
        };

        let compact = build_compact_block(&template, 0).unwrap();

        // Header should be 140 + 3 + 1344 = 1487 bytes
        assert_eq!(compact.header.len(), 1487);
        assert_eq!(compact.prefilled_txs.len(), 1);
        assert_eq!(compact.short_ids.len(), 0);
    }

    #[test]
    fn build_compact_with_transactions() {
        let template = BlockTemplate {
            version: 4,
            previous_block_hash: "00".repeat(32),
            cur_time: 1700000000,
            bits: "1f07ffff".to_string(),
            height: 100,
            transactions: vec![crate::rpc::TemplateTransaction {
                data: "deadbeef".to_string(),
                hash: "aa".repeat(32),
                fee: 1000,
            }],
            coinbase_txn: Some(CoinbaseTxn {
                data: "01000000010000".to_string(),
            }),
            default_roots: Some(DefaultRoots {
                merkle_root: "ab".repeat(32),
                block_commitments_hash: None,
                chain_history_root: None,
                auth_data_root: None,
            }),
        };

        let compact = build_compact_block(&template, 12345).unwrap();

        assert_eq!(compact.prefilled_txs.len(), 1); // coinbase
        assert_eq!(compact.short_ids.len(), 1); // 1 transaction
    }

    // #105: a template compact block's header and short IDs, checked against the
    // real chain and against what a receiver expects. Templates are built from
    // JSON shaped like Zebra's `getblocktemplate` result, the way the sidecar
    // receives them.

    /// Block 3470793 in the display order Zebra reports (the values
    /// `zcash-pool-server/tests/block_submission_path.rs` uses).
    const MAINNET_PREVIOUS_BLOCK_HASH_DISPLAY: &str =
        "00000000001380045e6c366dfe888cd5085a20660e4524f59dd813c4f05a5707";
    const MAINNET_MERKLE_ROOT_DISPLAY: &str =
        "d4b0800733ccdbb9655face8d28622530f3ec855e32c7eb1633854190a09ade8";
    const MAINNET_BLOCK_COMMITMENTS_HASH_DISPLAY: &str =
        "9bca25817433262c45ea7c8deec73181b136819a1d05eaf2db2a2b502ea4e7b4";

    /// Zebra v6.2.0's `get_block_template_basic@mainnet_10` snapshot, display order.
    const SNAPSHOT_PREVIOUS_BLOCK_HASH: &str =
        "0000000000d723156d9b65ffcf4984da7a19675ed7e2f06d9e5d5188af087bf8";
    const SNAPSHOT_MERKLE_ROOT: &str =
        "0dd4c87d6aba52431fef01079578826b547a22e444af986368c507918f893e8a";
    const SNAPSHOT_CHAIN_HISTORY_ROOT: &str =
        "94470fa66ebd1a5fdb109a5aa3f3204f14de3a42135e71aa7f4c44055847e0b5";
    const SNAPSHOT_AUTH_DATA_ROOT: &str =
        "c1b58477fa048262b10f726bf451dc8476e55fc56d82a5792a0ba63d0e2f645d";
    const SNAPSHOT_BLOCK_COMMITMENTS_HASH: &str =
        "9fe0f2f50842e3d0d5c4b78554ead8bfaa3314241f6f899d2373b96a3aaecccd";
    /// The snapshot's coinbase: a v5 transaction, 203 bytes.
    const SNAPSHOT_COINBASE_HEX: &str = "050000800a27a726b4d0d6c20000000041be1900010000000000000000000000000000000000\
         000000000000000000000000000000ffffffff090341be1904f09fa693ffffffff0480b2e60e\
         0000000017a9147e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e87286bee000000000017a9\
         14d45cb1adffb5215a42720532a076f02c7c778c908738c94d010000000017a91469a9f95a98\
         fe581b6eb52841ef4806dc4402eb908740787d010000000017a914931fec54c1fea86e574462\
         cc32013f5400b8912987000000";

    /// A real mainnet v6 (NU6.3) transaction from block 3431330, 208 bytes, with
    /// the txid and auth digest Zebra reports for it (display order). The same
    /// ground truth `sovright-p2p-ingress/src/wtxid.rs` pins.
    const V6_TX_HEX: &str = "0600008098b684d85b16a53700000000ca5b340001fc596961b6fdf9874d076f9e9562d32e65\
         bff1eca23c270b8e8d666a73d1b9d6000000006b483045022100bd13949d7d911d23123b7615\
         91dfcf814288bf59aeb88bb2786200290d7689c102200315c504b3b28bbd04614e4ba8832fbd\
         f49fc77c954570b4687668a6bf0b9ab8012103f28a3742b9927bae40d1d6fbef8c6f1b4ce535\
         9cf25a04bee069616cbaf6ab8dffffffff01905f0100000000001976a91497dc3652e93ca575\
         80f9792849749f4ee6c359f388ac00000000";
    const V6_TXID_DISPLAY: &str =
        "362f368f5361f4e9212d1f6e6c6f71fb261446c3c0ac30b873c6cf7bc5d73b0e";
    const V6_AUTHDIGEST_DISPLAY: &str =
        "7cd2d582308fbfa9db33d59179cdec4b120c05d09b6a2790d6d80302ed50a14f";

    /// 32 bytes exactly as written, with no reversal.
    fn bytes32(hex_str: &str) -> [u8; 32] {
        let mut bytes = [0u8; 32];
        hex::decode_to_slice(hex_str, &mut bytes).expect("32-byte hex");
        bytes
    }

    /// The snapshot as a `getblocktemplate` result, reduced to the fields the
    /// sidecar reads. Tests adjust it before parsing.
    fn snapshot_template_json() -> serde_json::Value {
        serde_json::json!({
            "version": 4,
            "previousblockhash": SNAPSHOT_PREVIOUS_BLOCK_HASH,
            "curtime": 1_654_008_617u64,
            "bits": "1f055554",
            "height": 1_687_105u64,
            "transactions": [],
            "coinbasetxn": { "data": SNAPSHOT_COINBASE_HEX },
            "defaultroots": {
                "merkleroot": SNAPSHOT_MERKLE_ROOT,
                "chainhistoryroot": SNAPSHOT_CHAIN_HISTORY_ROOT,
                "authdataroot": SNAPSHOT_AUTH_DATA_ROOT,
                "blockcommitmentshash": SNAPSHOT_BLOCK_COMMITMENTS_HASH
            }
        })
    }

    fn parse_template(json: serde_json::Value) -> BlockTemplate {
        serde_json::from_value(json).expect("template JSON parses")
    }

    /// Block 3470793 as the template Zebra would send for it. Up to the nonce, the
    /// header `build_header` writes must be the real header, byte for byte. Every
    /// mismatching region is reported at once.
    #[test]
    fn template_header_matches_the_real_mainnet_header() {
        let template = parse_template(serde_json::json!({
            "version": 4,
            "previousblockhash": MAINNET_PREVIOUS_BLOCK_HASH_DISPLAY,
            "curtime": 1_788_462_019u64,
            "bits": "1c00a48e",
            "height": 3_470_793u64,
            "transactions": [],
            "defaultroots": {
                "merkleroot": MAINNET_MERKLE_ROOT_DISPLAY,
                "blockcommitmentshash": MAINNET_BLOCK_COMMITMENTS_HASH_DISPLAY
            }
        }));
        let header = build_header(&template).expect("header builds");
        let (real, _solution) = zcash_pool_common::fixtures::mainnet_header_and_solution();

        let regions = [
            ("version", 0..4),
            ("previous block hash", 4..36),
            ("merkle root", 36..68),
            ("hashBlockCommitments", 68..100),
            ("time", 100..104),
            ("nBits", 104..108),
        ];
        let wrong: Vec<String> = regions
            .into_iter()
            .filter(|(_, range)| header[range.clone()] != real[range.clone()])
            .map(|(name, range)| {
                format!(
                    "{name}: wrote {}, block has {}",
                    hex::encode(&header[range.clone()]),
                    hex::encode(&real[range])
                )
            })
            .collect();
        assert!(
            wrong.is_empty(),
            "header differs from block 3470793:\n{}",
            wrong.join("\n")
        );
    }

    /// Zebra v6.2.0's own snapshot, all four roots present. The field after the
    /// merkle root must hold the snapshot's commitments hash in internal order, not
    /// the chain history root in either order.
    #[test]
    fn commitments_field_is_the_blockcommitmentshash() {
        let header =
            build_header(&parse_template(snapshot_template_json())).expect("header builds");
        let field: [u8; 32] = header[68..100].try_into().unwrap();

        assert_eq!(
            hex::encode(field),
            "cdccae3a6ab973239d896f1f241433aabfd8ea5485b7c4d5d0e34208f5f2e09f",
            "hashBlockCommitments must be the snapshot's blockcommitmentshash, reversed"
        );
        let history = bytes32(SNAPSHOT_CHAIN_HISTORY_ROOT);
        let mut history_reversed = history;
        history_reversed.reverse();
        assert_ne!(field, history, "must not be the chain history root");
        assert_ne!(
            field, history_reversed,
            "must not be the reversed chain history root"
        );
    }

    /// A synthetic two-transaction block whose header commits to exactly its own
    /// transactions. Slot 0 is the snapshot's v5 coinbase, prefilled. Slot 1 is a
    /// real mainnet v6 transaction the receiver resolves from its mempool by short
    /// ID. The block exists nowhere: this checks that announcer and receiver agree
    /// on the v6 transaction's wtxid, not that any block would be accepted.
    #[test]
    fn template_short_id_resolves_from_the_receivers_mempool() {
        let coinbase = hex::decode(SNAPSHOT_COINBASE_HEX).unwrap();
        let v6_tx = hex::decode(V6_TX_HEX).unwrap();

        // The block's merkle root, computed outside the code under test as
        // double-SHA256(coinbase txid || v6 txid), internal order.
        let coinbase_txid =
            bytes32("8a3e898f9107c5686398af44e4227a546b8278950701ef1f4352ba6a7dc8d40d");
        let v6_txid = bytes32("0e3bd7c57bcfc673b830acc0c3461426fb716f6c6e1f2d21e9f461538f362f36");
        let root = bytes32("b8ac84ddfdd10b83cabe3506e1cd617a0190fa5ae177d8fc8c65f91f74c7447d");
        // The receiver's own txid and merkle code agree with those values, so a
        // regression there cannot pass or fail this test in disguise.
        assert_eq!(merkle::txid_from_tx_bytes(&coinbase), coinbase_txid);
        assert_eq!(merkle::txid_from_tx_bytes(&v6_tx), v6_txid);
        assert_eq!(merkle::merkle_root(&[coinbase_txid, v6_txid]), Some(root));

        // The receiver holds the v6 transaction under the wtxid mempool sync builds
        // from Zebra's report of it.
        let v6_wtxid = WtxId::new(
            TxId::from_bytes(v6_txid),
            AuthDigest::from_bytes(bytes32(
                "4fa150ed0203d8d690276a9bd0050c124beccd7991d533dba9bf8f3082d5d27c",
            )),
        );
        assert_eq!(
            wtxid_from_display_hex(V6_TXID_DISPLAY, V6_AUTHDIGEST_DISPLAY),
            Some(v6_wtxid)
        );
        let mut mempool = TestMempool::new();
        mempool.insert(v6_wtxid, v6_tx.clone());

        let mut json = snapshot_template_json();
        json["defaultroots"]["merkleroot"] =
            serde_json::json!("7d44c7741ff9658cfcd877e15afa90017a61cde10635beca830bd1fddd84acb8");
        json["transactions"] = serde_json::json!([{
            "data": V6_TX_HEX,
            "hash": V6_TXID_DISPLAY,
            "authdigest": V6_AUTHDIGEST_DISPLAY,
            "fee": 0
        }]);
        let compact = build_compact_block(&parse_template(json), 0).expect("compact block builds");

        let mut reconstructor = CompactBlockReconstructor::new(&mempool);
        reconstructor.prepare(&zcash_block_hash(&compact.header), compact.nonce);
        match reconstructor.reconstruct(&compact) {
            ReconstructionResult::Complete { transactions } => {
                assert_eq!(transactions, vec![coinbase, v6_tx]);
            }
            ReconstructionResult::Incomplete {
                unresolved_short_ids,
                missing_wtxids,
                ..
            } => panic!(
                "Incomplete: {} unresolved short ID(s), {} missing wtxid(s)",
                unresolved_short_ids.len(),
                missing_wtxids.len()
            ),
            ReconstructionResult::Invalid { reason } => panic!("Invalid: {reason}"),
        }
    }

    /// A template transaction without `authdigest` keeps the wtxid this code has
    /// always built for it: its txid with an all-zero auth digest.
    #[test]
    fn absent_authdigest_keeps_the_zero_digest_wtxid() {
        let mut json = snapshot_template_json();
        json["transactions"] = serde_json::json!([{ "data": V6_TX_HEX, "hash": V6_TXID_DISPLAY }]);
        let compact = build_compact_block(&parse_template(json), 7).expect("compact block builds");

        let zero_digest_wtxid = WtxId::new(
            TxId::from_bytes(bytes32(
                "0e3bd7c57bcfc673b830acc0c3461426fb716f6c6e1f2d21e9f461538f362f36",
            )),
            AuthDigest::from_bytes([0u8; 32]),
        );
        let expected = ShortId::compute(&zero_digest_wtxid, &zcash_block_hash(&compact.header), 7);
        assert_eq!(compact.short_ids, vec![expected]);
    }

    /// An `authdigest` that is present but malformed is an error, reported with the
    /// variants the header fields use. Falling back to a zero digest would hide the
    /// mismatch the field exists to fix.
    #[test]
    fn malformed_authdigest_is_an_error() {
        for (authdigest, length_error) in [("zz".repeat(32), false), ("00".repeat(31), true)] {
            let mut json = snapshot_template_json();
            json["transactions"] = serde_json::json!([{
                "data": V6_TX_HEX,
                "hash": V6_TXID_DISPLAY,
                "authdigest": authdigest
            }]);
            match build_compact_block(&parse_template(json), 0) {
                Err(CompactBlockError::InvalidHex(field)) if !length_error => {
                    assert_eq!(field, "authdigest")
                }
                Err(CompactBlockError::InvalidLength(field)) if length_error => {
                    assert_eq!(field, "authdigest")
                }
                Err(other) => panic!("{authdigest}: unexpected error: {other}"),
                Ok(_) => panic!("{authdigest}: a malformed authdigest built a compact block"),
            }
        }
    }

    /// With a chain history root but no commitments hash, the field is left zero,
    /// as it is when the roots are missing altogether. A deliberate change: the old
    /// code wrote the history root there, unreversed. In the NU5+ header this code
    /// builds, the field is hashBlockCommitments, of which the history root is only
    /// an input.
    #[test]
    fn absent_commitments_hash_leaves_the_field_zero() {
        let mut json = snapshot_template_json();
        json["defaultroots"]
            .as_object_mut()
            .unwrap()
            .remove("blockcommitmentshash");
        let header = build_header(&parse_template(json)).expect("header builds");
        assert_eq!(hex::encode(&header[68..100]), "00".repeat(32));
    }
}

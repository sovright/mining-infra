//! Merkle-root verification for reconstructed blocks.
//!
//! BIP 152 reconstruction fills transaction slots from a local mempool by
//! 6-byte short id. A short id is not a commitment: it can collide, and the
//! mempool copy of a transaction can differ from the one the miner actually
//! included. Filling every slot therefore proves only that reconstruction ran
//! out of holes, NOT that the assembled block is the block the header commits
//! to. Without the check in this module the sidecar submitted whatever it
//! assembled and let Zebra be the validator -- which it was, rejecting the
//! block and burning the fast path's entire latency advantage.
//!
//! The header's merkle root IS that commitment, so verifying it turns a remote
//! `submitblock` rejection into a local, immediate, correctly-attributed
//! failure that falls back to `getblocktxn` or the raw block.
//!
//! TXID, NOT WTXID (load-bearing): the merkle tree commits to *txids*. For v5
//! (ZIP-244) and v6 (ZIP-229, NU6.3/Ironwood) the txid is a personalized
//! BLAKE2b digest over effecting data, which is NOT the double-SHA256 of the
//! wire bytes; for v4 and earlier it is exactly that double-SHA256. Both rules
//! are exercised against a real mainnet block in the tests below -- block
//! 3470793 carries five v6 and two v4 transactions, so a regression in either
//! branch fails.
//!
//! BYTE ORDER (load-bearing): leaves, internal nodes, and the header field are
//! all internal (wire) order. Zebra's RPC and explorers display the byte
//! reversal of each. Nothing here reverses anything; the fixture test pins it.

use std::collections::HashSet;
use std::io::Cursor;
use std::ops::Range;

use crate::ZCASH_FULL_HEADER_SIZE;
use sha2::{Digest, Sha256};
use zcash_encoding::CompactSize;
use zcash_primitives::transaction::{Transaction, TxVersion};
use zcash_protocol::consensus::BranchId;

/// Byte range of the merkle root inside a serialized Zcash block header.
///
/// Header layout: version(4) prev(32) merkle(32) commitments(32) time(4)
/// bits(4) nonce(32) then the Equihash solution. Verified against mainnet
/// block 3470793 in the tests.
pub(crate) const MERKLE_ROOT_RANGE: std::ops::Range<usize> = 36..68;

/// Branch id handed to `zcash_primitives::transaction::Transaction::read`, and
/// the only definition of it in the workspace: `sovright-p2p-ingress` re-exports
/// this rather than declaring its own.
///
/// For v5/v6 -- the only versions whose txid is not a plain double-SHA256 --
/// `Transaction::read` takes the consensus branch id from the transaction bytes
/// themselves, so this argument never influences a txid or auth digest we
/// compute. For v4 the reader stores it but hashes the bytes, and it does not
/// check `valid_in_branch` on read, so pre-NU7 v4 transactions still parse.
/// `reader_hint_does_not_change_txids` pins the txids and the v4 parse; the
/// ingress wtxid tests pin the auth digests. It is threaded only to satisfy the
/// reader API: any value works for v5/v6 and the v4 read path today, and Nu7 is
/// chosen to track the newest known branch, not because NU7 is active.
pub const TX_READER_BRANCH_HINT: BranchId = BranchId::Nu7;

fn sha256d(bytes: &[u8]) -> [u8; 32] {
    let first = Sha256::digest(bytes);
    let second = Sha256::digest(first);
    let mut out = [0u8; 32];
    out.copy_from_slice(&second);
    out
}

/// The txid a block's merkle tree commits to, in internal (wire) byte order.
///
/// v5/v6 carry a ZIP-244 txid; everything else -- including a transaction that
/// fails to parse -- falls back to double-SHA256 of the wire bytes, which is
/// the correct rule for v4 and earlier. A malformed v5/v6 transaction therefore
/// yields a txid that will not match the header, so the block fails the merkle
/// check rather than being submitted on a silent parse failure. Never panics.
pub fn txid_from_tx_bytes(tx_bytes: &[u8]) -> [u8; 32] {
    let mut cursor = Cursor::new(tx_bytes);
    if let Ok(tx) = Transaction::read(&mut cursor, TX_READER_BRANCH_HINT) {
        // A well-formed transaction consumes its whole slice; a leftover tail
        // means we mis-parsed, so fall through rather than trust the txid.
        let consumed_all = cursor.position() as usize == tx_bytes.len();
        if consumed_all && matches!(tx.version(), TxVersion::V5 | TxVersion::V6) {
            return *tx.txid().as_ref();
        }
    }
    sha256d(tx_bytes)
}

/// Merkle root over `txids` (wire order), using the Bitcoin/Zcash tree: pair
/// adjacent nodes, duplicating the last one when a level has an odd count.
///
/// Returns `None` for an empty list -- a block always has a coinbase, so an
/// empty transaction list is a caller bug, not a valid root.
pub fn merkle_root(txids: &[[u8; 32]]) -> Option<[u8; 32]> {
    if txids.is_empty() {
        return None;
    }
    let mut level: Vec<[u8; 32]> = txids.to_vec();
    while level.len() > 1 {
        if level.len() % 2 == 1 {
            let last = level[level.len() - 1];
            level.push(last);
        }
        let mut next = Vec::with_capacity(level.len() / 2);
        for pair in level.as_chunks::<2>().0 {
            let mut buf = [0u8; 64];
            buf[..32].copy_from_slice(&pair[0]);
            buf[32..].copy_from_slice(&pair[1]);
            next.push(sha256d(&buf));
        }
        level = next;
    }
    Some(level[0])
}

/// The merkle root committed to by a serialized block header, in wire order.
///
/// Returns `None` if the header is too short to contain the field.
pub fn header_merkle_root(header: &[u8]) -> Option<[u8; 32]> {
    let bytes = header.get(MERKLE_ROOT_RANGE)?;
    let mut out = [0u8; 32];
    out.copy_from_slice(bytes);
    Some(out)
}

/// Whether `transactions` (in block order, wire bytes) are exactly the
/// transactions `header` commits to.
///
/// Fails closed: a header too short to carry a merkle root, an empty transaction
/// list, or a repeated txid is a mismatch rather than a pass.
pub fn transactions_match_merkle_root(header: &[u8], transactions: &[Vec<u8>]) -> bool {
    let Some(expected) = header_merkle_root(header) else {
        return false;
    };
    let txids: Vec<[u8; 32]> = transactions
        .iter()
        .map(|tx| txid_from_tx_bytes(tx))
        .collect();
    if first_repeated_txid(&txids).is_some() {
        return false;
    }
    match merkle_root(&txids) {
        Some(actual) => actual == expected,
        None => false,
    }
}

/// Largest serialized block, in bytes (Zebra's `MAX_BLOCK_BYTES`). This bounds
/// the input, not the time spent parsing it.
pub const MAX_BLOCK_BYTES: usize = 2_000_000;

/// Why a block body failed [`validate_block_body`] or
/// [`validate_block_transactions`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum BlockBodyError {
    #[error("block is {bytes} bytes, over the limit")]
    TooLarge { bytes: usize },
    #[error("block header has the wrong length")]
    InvalidHeaderLength,
    /// The header misses the target it states. Only ingress's peer path reports
    /// this, before any parsing; the validators here never do.
    #[error("block header misses the target it states")]
    HeaderTarget,
    #[error("invalid transaction count")]
    InvalidCount,
    #[error("block has no transactions")]
    EmptyTransactions,
    #[error("transaction {index} does not parse")]
    Transaction { index: usize },
    #[error("transaction slice {index} is not exactly one transaction")]
    TransactionBoundary { index: usize },
    #[error("{bytes} bytes follow the last transaction")]
    TrailingBytes { bytes: usize },
    #[error("transaction {index} repeats an earlier txid")]
    DuplicateTxid { index: usize },
    #[error("merkle root mismatch")]
    MerkleMismatch,
}

impl BlockBodyError {
    /// One error of each kind, in metric order. Fields are placeholders.
    pub const ALL: [Self; 10] = [
        Self::TooLarge { bytes: 0 },
        Self::InvalidHeaderLength,
        Self::HeaderTarget,
        Self::InvalidCount,
        Self::EmptyTransactions,
        Self::Transaction { index: 0 },
        Self::TransactionBoundary { index: 0 },
        Self::TrailingBytes { bytes: 0 },
        Self::DuplicateTxid { index: 0 },
        Self::MerkleMismatch,
    ];

    /// This error's metric label.
    pub fn label(&self) -> &'static str {
        match self {
            Self::TooLarge { .. } => "too_large",
            Self::InvalidHeaderLength => "invalid_header_length",
            Self::HeaderTarget => "header_target",
            Self::InvalidCount => "invalid_count",
            Self::EmptyTransactions => "empty_transactions",
            Self::Transaction { .. } => "transaction",
            Self::TransactionBoundary { .. } => "transaction_boundary",
            Self::TrailingBytes { .. } => "trailing_bytes",
            Self::DuplicateTxid { .. } => "duplicate_txid",
            Self::MerkleMismatch => "merkle_mismatch",
        }
    }

    /// Position of this error's kind in [`Self::ALL`].
    pub fn kind_index(&self) -> usize {
        Self::ALL
            .iter()
            .position(|kind| kind.label() == self.label())
            .expect("ALL holds every kind")
    }
}

/// A block [`parse_block_body`] accepted, holding the bytes it checked.
///
/// Everything is read from those bytes, so the boundaries cannot be applied to
/// another block, and a slice from here is a transaction the reader validated
/// rather than another parser's reading of it. It owns them, not borrows, so the
/// result can come back from a blocking task.
///
/// The fields are private, so that pairing cannot be built by hand:
///
/// ```compile_fail,E0451
/// let parsed = sovright_relay::ParsedBlockBody {
///     raw: Vec::new(),
///     boundaries: Vec::new(),
/// };
/// ```
#[derive(Debug)]
pub struct ParsedBlockBody {
    raw: Vec<u8>,
    boundaries: Vec<Range<usize>>,
    coinbase: Transaction,
}

impl ParsedBlockBody {
    /// The serialized block.
    pub fn raw_block(&self) -> &[u8] {
        &self.raw
    }

    /// The serialized block header.
    pub fn header(&self) -> &[u8] {
        &self.raw[..ZCASH_FULL_HEADER_SIZE]
    }

    /// Each transaction's bytes, in block order.
    pub fn transactions(&self) -> impl ExactSizeIterator<Item = &[u8]> {
        self.boundaries
            .iter()
            .map(|boundary| &self.raw[boundary.clone()])
    }

    /// The first transaction as the reader read it, so nothing has to read it
    /// again.
    pub fn coinbase(&self) -> &Transaction {
        &self.coinbase
    }
}

/// Strictly parse a serialized block and check its body against its header.
///
/// Unlike [`transactions_match_merkle_root`], a transaction that does not parse
/// is refused rather than hashed: a block is only valid here if the reader
/// consumes it exactly. This does not check proofs, signatures or which
/// transaction versions an upgrade allows; those stay with the node.
pub fn parse_block_body(raw_block: Vec<u8>) -> Result<ParsedBlockBody, BlockBodyError> {
    let (boundaries, coinbase) = read_checked(&raw_block)?;
    Ok(ParsedBlockBody {
        raw: raw_block,
        boundaries,
        coinbase,
    })
}

/// [`parse_block_body`] for a caller that needs only the transaction count and
/// keeps its own bytes.
pub fn validate_block_body(raw_block: &[u8]) -> Result<usize, BlockBodyError> {
    read_checked(raw_block).map(|(boundaries, _)| boundaries.len())
}

fn read_checked(raw_block: &[u8]) -> Result<(Vec<Range<usize>>, Transaction), BlockBodyError> {
    if raw_block.len() > MAX_BLOCK_BYTES {
        return Err(BlockBodyError::TooLarge {
            bytes: raw_block.len(),
        });
    }
    let (header, body) = raw_block
        .split_at_checked(ZCASH_FULL_HEADER_SIZE)
        .ok_or(BlockBodyError::InvalidHeaderLength)?;
    let mut cursor = Cursor::new(body);
    let count = CompactSize::read(&mut cursor).map_err(|_| BlockBodyError::InvalidCount)?;
    if count == 0 {
        return Err(BlockBodyError::EmptyTransactions);
    }
    // The declared count is not trusted for allocation; reading stops at the
    // first transaction the bytes cannot supply.
    let mut boundaries = Vec::new();
    let mut txids = Vec::new();
    let mut coinbase = None;
    for index in 0..count as usize {
        let start = ZCASH_FULL_HEADER_SIZE + cursor.position() as usize;
        let Ok(tx) = Transaction::read(&mut cursor, TX_READER_BRANCH_HINT) else {
            // `Transaction` means nothing is known against the body, which is what
            // the emergency bypass relies on, so a repeat already read comes first.
            return Err(match first_repeated_txid(&txids) {
                Some(index) => BlockBodyError::DuplicateTxid { index },
                None => BlockBodyError::Transaction { index },
            });
        };
        boundaries.push(start..ZCASH_FULL_HEADER_SIZE + cursor.position() as usize);
        txids.push(*tx.txid().as_ref());
        coinbase.get_or_insert(tx);
    }
    // Before the trailing check, so `TrailingBytes` means the header's transactions
    // were all read and only the extra bytes are unexplained. A body that does not
    // match its header is reported as that, whatever follows it.
    check_txids(header, &txids)?;
    let trailing = body.len() - cursor.position() as usize;
    if trailing != 0 {
        return Err(BlockBodyError::TrailingBytes { bytes: trailing });
    }
    let coinbase = coinbase.ok_or(BlockBodyError::EmptyTransactions)?;
    Ok((boundaries, coinbase))
}

/// The rules of [`validate_block_body`] for transactions that already have their
/// own boundaries: each slice must be exactly one transaction. Concatenating the
/// slices and validating the result would not show that, because shifted
/// boundaries can join into a valid block.
pub fn validate_block_transactions<'a>(
    header: &[u8],
    transactions: impl ExactSizeIterator<Item = &'a [u8]>,
) -> Result<usize, BlockBodyError> {
    if header.len() != ZCASH_FULL_HEADER_SIZE {
        return Err(BlockBodyError::InvalidHeaderLength);
    }
    if transactions.len() == 0 {
        return Err(BlockBodyError::EmptyTransactions);
    }
    // What the block serializes to, so the count is included. `bytes` is within
    // the limit before each addition, so the sum cannot overflow.
    let mut bytes = header.len() + CompactSize::serialized_size(transactions.len());
    let mut txids = Vec::with_capacity(transactions.len());
    for (index, slice) in transactions.enumerate() {
        bytes += slice.len();
        if bytes > MAX_BLOCK_BYTES {
            return Err(BlockBodyError::TooLarge { bytes });
        }
        let mut cursor = Cursor::new(slice);
        let tx = Transaction::read(&mut cursor, TX_READER_BRANCH_HINT)
            .map_err(|_| BlockBodyError::Transaction { index })?;
        if cursor.position() as usize != slice.len() {
            return Err(BlockBodyError::TransactionBoundary { index });
        }
        txids.push(*tx.txid().as_ref());
    }
    check_txids(header, &txids)?;
    Ok(txids.len())
}

fn check_txids(header: &[u8], txids: &[[u8; 32]]) -> Result<(), BlockBodyError> {
    if let Some(index) = first_repeated_txid(txids) {
        return Err(BlockBodyError::DuplicateTxid { index });
    }
    let root = merkle_root(txids);
    if root.is_none() || root != header_merkle_root(header) {
        return Err(BlockBodyError::MerkleMismatch);
    }
    Ok(())
}

/// The index of the first txid that repeats an earlier one, at any position.
///
/// The tree pairs an odd last node with itself, so repeating the tail of a block
/// keeps the root. Equal roots therefore do not show that a list is the one the
/// header commits to; a repeated txid must be refused separately.
///
/// The rule is wider than the shapes that keep the root. It refuses any repeat,
/// adjacent or not, and it compares txids, so two encodings of one transaction
/// count as a repeat even when their authorizing data differs. This is a relay
/// rule; whether it matches consensus on every block is still open in #130.
fn first_repeated_txid(txids: &[[u8; 32]]) -> Option<usize> {
    let mut seen = HashSet::with_capacity(txids.len());
    txids.iter().position(|txid| !seen.insert(txid))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Mainnet block 3470793: header + all 7 transactions, in block order,
    /// fetched from Zebra (`getblock <hash> 0` / `getrawtransaction`). Five are
    /// v6 (ZIP-229, version group 0x98b684d8) and two are v4, so this fixture
    /// exercises BOTH txid rules. Synthetic bytes cannot: they parse as neither.
    ///
    /// The bytes live in `zcash-pool-common` behind its `test-support` feature,
    /// where every crate that needs them can reach them through the dependency
    /// graph instead of by relative path.
    fn fixture() -> (Vec<u8>, Vec<Vec<u8>>) {
        (
            zcash_pool_common::fixtures::mainnet_serialized_header(),
            zcash_pool_common::fixtures::mainnet_transactions(),
        )
    }

    /// The load-bearing test: a real block's real transactions reproduce the
    /// real header's merkle root. This pins the tree shape (7 leaves, so the
    /// odd-node duplication runs), both txid rules, and the wire byte order at
    /// once. If any one of them regresses, this fails.
    #[test]
    fn real_mainnet_block_transactions_match_its_header() {
        let (header, txs) = fixture();
        assert_eq!(txs.len(), 7, "fixture should carry all 7 transactions");
        assert!(transactions_match_merkle_root(&header, &txs));
    }

    #[test]
    fn header_merkle_root_reads_the_committed_field() {
        let (header, _) = fixture();
        // Zebra reports this block's merkleroot as the byte reversal of the
        // header field; the wire-order value is what we must compare against.
        let expected =
            hex::decode("e8ad090a19543863b17e2ce355c83e0f532286d2e8ac5f65b9dbcc330780b0d4")
                .unwrap();
        assert_eq!(header_merkle_root(&header).unwrap().to_vec(), expected);
    }

    /// v6 (NU6.3) txids are ZIP-244 digests, NOT double-SHA256. This is the
    /// branch a pre-NU5 implementation gets wrong, and it is the majority of
    /// this block.
    #[test]
    fn v6_txid_is_zip244_not_sha256d() {
        let (_, txs) = fixture();
        let coinbase = &txs[0];
        assert_eq!(
            &coinbase[..4],
            &[0x06, 0x00, 0x00, 0x80],
            "fixture tx 0 is v6"
        );
        let txid = txid_from_tx_bytes(coinbase);
        assert_ne!(txid, sha256d(coinbase), "v6 txid must not be sha256d");
        // Zebra's display-order txid, reversed to wire order.
        let mut expected =
            hex::decode("6a4fe7ad651836a7777f451da8250ffc4cf1a123d1ecb5925dfb6c55c216eb52")
                .unwrap();
        expected.reverse();
        assert_eq!(txid.to_vec(), expected);
    }

    /// v4 txids ARE double-SHA256. The fallback is not a guess; it is the rule
    /// for every pre-v5 transaction, and this block contains two of them.
    #[test]
    fn v4_txid_is_sha256d() {
        let (_, txs) = fixture();
        let v4 = &txs[3];
        assert_eq!(&v4[..4], &[0x04, 0x00, 0x00, 0x80], "fixture tx 3 is v4");
        assert_eq!(txid_from_tx_bytes(v4), sha256d(v4));
    }

    /// The pinned zcash crates must be the releases that schedule NU7 on
    /// mainnet (ZIP 259, Zebra 7.0.0), with the branch id the hint names. The
    /// `-pre.0` prereleases left the mainnet height unset.
    #[test]
    fn pinned_protocol_crate_schedules_nu7_on_mainnet() {
        use zcash_protocol::consensus::{
            BlockHeight, MAIN_NETWORK, NetworkUpgrade, Parameters, TEST_NETWORK,
        };
        assert_eq!(
            MAIN_NETWORK.activation_height(NetworkUpgrade::Nu7),
            Some(BlockHeight::from_u32(3_543_405))
        );
        assert_eq!(
            TEST_NETWORK.activation_height(NetworkUpgrade::Nu7),
            Some(BlockHeight::from_u32(4_465_026))
        );
        assert_eq!(u32::from(TX_READER_BRANCH_HINT), 0x7719_0ad9);
    }

    /// The branch hint handed to `Transaction::read` must not move any txid, so
    /// that pointing it at a new network upgrade is safe. Checks the reader
    /// directly rather than through `txid_from_tx_bytes`: that helper falls
    /// back to sha256d on a parse failure, which would hide a v4 transaction
    /// the reader stopped accepting.
    #[test]
    fn reader_hint_does_not_change_txids() {
        let (_, txs) = fixture();
        for (index, tx) in txs.iter().enumerate() {
            let txids: Vec<[u8; 32]> = [BranchId::Nu6_3, BranchId::Nu7]
                .into_iter()
                .map(|hint| {
                    let mut cursor = Cursor::new(tx.as_slice());
                    let parsed = Transaction::read(&mut cursor, hint)
                        .unwrap_or_else(|e| panic!("tx {index} must parse under {hint:?}: {e}"));
                    assert_eq!(
                        cursor.position() as usize,
                        tx.len(),
                        "tx {index} must be read whole under {hint:?}"
                    );
                    *parsed.txid().as_ref()
                })
                .collect();
            assert_eq!(txids[0], txids[1], "tx {index}: txid depends on the hint");
            assert_eq!(
                txids[1],
                txid_from_tx_bytes(tx),
                "tx {index}: reader and txid_from_tx_bytes disagree"
            );
        }
    }

    /// The whole point: a single substituted transaction -- what a short-id
    /// collision or a stale mempool copy produces -- must not pass.
    #[test]
    fn one_substituted_transaction_fails_the_root() {
        let (header, mut txs) = fixture();
        txs[2] = vec![0xde, 0xad, 0xbe, 0xef];
        assert!(!transactions_match_merkle_root(&header, &txs));
    }

    /// Ordering is part of the commitment, not an incidental detail.
    #[test]
    fn reordered_transactions_fail_the_root() {
        let (header, mut txs) = fixture();
        txs.swap(1, 2);
        assert!(!transactions_match_merkle_root(&header, &txs));
    }

    #[test]
    fn single_transaction_root_is_that_txid() {
        let tx = vec![0x04, 0x00, 0x00, 0x80, 0x01, 0x02];
        let txid = txid_from_tx_bytes(&tx);
        assert_eq!(merkle_root(&[txid]).unwrap(), txid);
    }

    /// sovright/mining-infra#103, cross-checked without zcash-template-provider. The
    /// coinbase in Zebra v6.2.0's own `getblocktemplate` snapshot
    /// (`get_block_template_basic@mainnet_10.snap`) is a v5 transaction. Its ZIP-244 txid,
    /// computed here with zcash_primitives, is the byte reversal of the `merkleroot` Zebra
    /// sent -- so that field is display order. Constants copied from the snapshot.
    #[test]
    fn zebra_template_merkle_root_is_the_display_order_zip244_txid() {
        const COINBASE_HEX: [&str; 7] = [
            "050000800a27a726b4d0d6c20000000041be1900010000000000000000000000",
            "000000000000000000000000000000000000000000ffffffff090341be1904f0",
            "9fa693ffffffff0480b2e60e0000000017a9147e7e7e7e7e7e7e7e7e7e7e7e7e",
            "7e7e7e7e7e7e7e87286bee000000000017a914d45cb1adffb5215a42720532a0",
            "76f02c7c778c908738c94d010000000017a91469a9f95a98fe581b6eb52841ef",
            "4806dc4402eb908740787d010000000017a914931fec54c1fea86e574462cc32",
            "013f5400b8912987000000",
        ];
        const MERKLE_ROOT_DISPLAY: &str =
            "0dd4c87d6aba52431fef01079578826b547a22e444af986368c507918f893e8a";

        let tx = hex::decode(COINBASE_HEX.concat()).expect("coinbase hex");
        let txid = txid_from_tx_bytes(&tx);
        assert_eq!(
            merkle_root(&[txid]).unwrap(),
            txid,
            "a one-tx root is the txid"
        );

        let mut display = txid;
        display.reverse();
        assert_eq!(hex::encode(display), MERKLE_ROOT_DISPLAY);

        // Negative control: the double-SHA256 of the same bytes, the txid rule for v4 and
        // earlier, is a different value. A v5 coinbase's txid is not recoverable that way.
        let mut double_sha = sha256d(&tx);
        double_sha.reverse();
        assert_eq!(
            hex::encode(double_sha),
            "f96ec1f0b0b8732dc3fc81bc629bfe6ef437d704f03ef884359ddcb7044f0613"
        );
        assert_ne!(hex::encode(double_sha), MERKLE_ROOT_DISPLAY);
    }

    #[test]
    fn odd_level_duplicates_the_last_node() {
        let a = [1u8; 32];
        let b = [2u8; 32];
        let c = [3u8; 32];
        let mut ab = [0u8; 64];
        ab[..32].copy_from_slice(&a);
        ab[32..].copy_from_slice(&b);
        let mut cc = [0u8; 64];
        cc[..32].copy_from_slice(&c);
        cc[32..].copy_from_slice(&c);
        let mut top = [0u8; 64];
        top[..32].copy_from_slice(&sha256d(&ab));
        top[32..].copy_from_slice(&sha256d(&cc));
        assert_eq!(merkle_root(&[a, b, c]).unwrap(), sha256d(&top));
    }

    #[test]
    fn empty_transaction_list_is_not_a_valid_root() {
        assert!(merkle_root(&[]).is_none());
    }

    /// Fails closed rather than passing a block it cannot check.
    #[test]
    fn short_header_is_a_mismatch_not_a_pass() {
        let (_, txs) = fixture();
        assert!(!transactions_match_merkle_root(&[0u8; 40], &txs));
    }

    #[test]
    fn empty_transactions_are_a_mismatch_not_a_pass() {
        let (header, _) = fixture();
        assert!(!transactions_match_merkle_root(&header, &[]));
    }

    /// A truncated v6 transaction must not be quietly accepted via the
    /// double-SHA256 fallback path as though it were a legacy transaction.
    #[test]
    fn malformed_v6_falls_back_and_fails_the_root() {
        let (header, mut txs) = fixture();
        txs[0].truncate(50);
        assert!(!transactions_match_merkle_root(&header, &txs));
    }
}

/// A 32-byte hash in DISPLAY (reversed) hex, matching Zebra's RPC and block
/// explorers -- so a logged value can be pasted straight into `getblock` /
/// `getrawtransaction` when joining a diagnostic against the real chain.
pub fn display_hex(hash: &[u8; 32]) -> String {
    let mut reversed = *hash;
    reversed.reverse();
    hex::encode(reversed)
}

/// Which slots a reconstruction filled from the local mempool, as
/// `index:txid_display` pairs joined by commas.
///
/// Prefilled slots are deliberately omitted: their bytes arrive inside the
/// compact block itself, so they are whatever the sender sent and cannot be the
/// source of a merkle mismatch. Only mempool-resolved slots can substitute the
/// wrong transaction, so those are the only ones worth carrying into a log line
/// that has to be joined against the real block.
pub fn mempool_slot_digest(transactions: &[Vec<u8>], prefilled_positions: &[usize]) -> String {
    let mut parts = Vec::new();
    for (index, tx) in transactions.iter().enumerate() {
        if prefilled_positions.contains(&index) {
            continue;
        }
        parts.push(format!("{index}:{}", display_hex(&txid_from_tx_bytes(tx))));
    }
    parts.join(",")
}

#[cfg(test)]
mod diagnostic_tests {
    use super::*;

    #[test]
    fn display_hex_reverses_wire_order() {
        let mut wire = [0u8; 32];
        wire[0] = 0xaa;
        wire[31] = 0xbb;
        let shown = display_hex(&wire);
        assert!(shown.starts_with("bb"));
        assert!(shown.ends_with("aa"));
    }

    /// The digest must skip prefilled slots -- they cannot be wrong -- and
    /// report the surviving ones under their real block index, not a
    /// renumbering, or the join against the real block lines up the wrong rows.
    #[test]
    fn digest_skips_prefilled_and_keeps_real_indexes() {
        let txs = vec![vec![0x01], vec![0x02], vec![0x03], vec![0x04]];
        let digest = mempool_slot_digest(&txs, &[0, 2]);
        let indexes: Vec<&str> = digest
            .split(',')
            .map(|p| p.split(':').next().unwrap())
            .collect();
        assert_eq!(indexes, vec!["1", "3"]);
        assert!(digest.contains(&display_hex(&txid_from_tx_bytes(&txs[1]))));
    }

    #[test]
    fn digest_is_empty_when_everything_was_prefilled() {
        let txs = vec![vec![0x01], vec![0x02]];
        assert_eq!(mempool_slot_digest(&txs, &[0, 1]), "");
    }
}

#[cfg(test)]
mod body_tests {
    use super::*;
    use crate::test_support::{
        committed_header, parseable_transaction, parseable_transaction_with_script, raw_block,
    };

    fn real_block() -> (Vec<u8>, Vec<Vec<u8>>, Vec<u8>) {
        let header = zcash_pool_common::fixtures::mainnet_serialized_header();
        let txs = zcash_pool_common::fixtures::mainnet_transactions();
        let raw = raw_block(&header, &txs);
        assert_eq!(raw, zcash_pool_common::fixtures::mainnet_raw_block());
        (header, txs, raw)
    }

    fn test_block(count: u32) -> (Vec<u8>, Vec<Vec<u8>>) {
        let txs: Vec<Vec<u8>> = (0..count).map(parseable_transaction).collect();
        (committed_header(0xcd, &txs), txs)
    }

    #[test]
    fn validates_the_real_block() {
        let (header, txs, raw) = real_block();
        assert_eq!(validate_block_body(&raw), Ok(7));
        assert_eq!(
            validate_block_transactions(&header, txs.iter().map(Vec::as_slice)),
            Ok(7)
        );
    }

    /// The tree pairs block 3470793's odd last transaction with itself, so a
    /// second copy of it keeps the root the real header commits to.
    #[test]
    fn a_repeated_final_transaction_keeps_the_root_and_is_refused() {
        let (header, mut txs, _) = real_block();
        let last = txs[6].clone();
        txs.push(last);
        let txids: Vec<[u8; 32]> = txs.iter().map(|tx| txid_from_tx_bytes(tx)).collect();
        assert_eq!(merkle_root(&txids), header_merkle_root(&header));

        assert!(!transactions_match_merkle_root(&header, &txs));
        assert_eq!(
            validate_block_body(&raw_block(&header, &txs)),
            Err(BlockBodyError::DuplicateTxid { index: 7 })
        );
        assert_eq!(
            validate_block_transactions(&header, txs.iter().map(Vec::as_slice)),
            Err(BlockBodyError::DuplicateTxid { index: 7 })
        );
    }

    #[test]
    fn a_repeated_final_pair_keeps_the_root_and_is_refused() {
        let (header, mut txs) = test_block(6);
        txs.extend_from_slice(&txs.clone()[4..]);
        let txids: Vec<[u8; 32]> = txs.iter().map(|tx| txid_from_tx_bytes(tx)).collect();
        assert_eq!(merkle_root(&txids), header_merkle_root(&header));
        assert_eq!(
            validate_block_body(&raw_block(&header, &txs)),
            Err(BlockBodyError::DuplicateTxid { index: 6 })
        );
    }

    /// Position does not matter, and neither does the root: each header here
    /// commits to the list that repeats a transaction.
    #[test]
    fn a_repeat_at_any_position_is_refused() {
        let (_, txs) = test_block(3);
        let at = |positions: &[usize]| -> Vec<Vec<u8>> {
            positions.iter().map(|&index| txs[index].clone()).collect()
        };
        for (list, index) in [
            (at(&[0, 0, 1]), 1),
            (at(&[0, 1, 0]), 2),
            (at(&[0, 1, 2, 1]), 3),
        ] {
            let header = committed_header(0xcd, &list);
            let expected = Err(BlockBodyError::DuplicateTxid { index });
            assert!(!transactions_match_merkle_root(&header, &list));
            assert_eq!(validate_block_body(&raw_block(&header, &list)), expected);
            assert_eq!(
                validate_block_transactions(&header, list.iter().map(Vec::as_slice)),
                expected
            );
        }
    }

    /// A v6 txid leaves out the scriptSig, so these two encodings share a txid.
    /// The rule compares txids, not bytes.
    #[test]
    fn a_repeat_is_a_repeated_txid_not_repeated_bytes() {
        let (header, mut txs, _) = real_block();
        let mut other_encoding = txs[2].clone();
        other_encoding[70] ^= 0x01;
        assert_ne!(other_encoding, txs[2]);
        assert_eq!(
            txid_from_tx_bytes(&other_encoding),
            txid_from_tx_bytes(&txs[2])
        );
        txs.insert(3, other_encoding);

        let expected = Err(BlockBodyError::DuplicateTxid { index: 3 });
        assert_eq!(validate_block_body(&raw_block(&header, &txs)), expected);
        assert_eq!(
            validate_block_transactions(&header, txs.iter().map(Vec::as_slice)),
            expected
        );
    }

    #[test]
    fn a_changed_transaction_fails_the_root() {
        let (header, mut txs, _) = real_block();
        txs[3][60] ^= 0x01; // inside tx 3's scriptSig: still parses, new txid
        assert_eq!(
            validate_block_body(&raw_block(&header, &txs)),
            Err(BlockBodyError::MerkleMismatch)
        );
    }

    /// `txid_from_tx_bytes` hashes what it cannot parse, so a header can commit
    /// to bytes that are not a transaction. The merkle-only check passes them;
    /// validation must not.
    #[test]
    fn an_unparseable_transaction_is_refused_even_if_the_root_matches() {
        let garbage = vec![0xff; 40];
        let txs = vec![parseable_transaction(1), garbage];
        let header = committed_header(0xcd, &txs);
        assert!(transactions_match_merkle_root(&header, &txs));
        assert_eq!(
            validate_block_body(&raw_block(&header, &txs)),
            Err(BlockBodyError::Transaction { index: 1 })
        );
        assert_eq!(
            validate_block_transactions(&header, txs.iter().map(Vec::as_slice)),
            Err(BlockBodyError::Transaction { index: 1 })
        );
    }

    #[test]
    fn a_non_canonical_count_is_refused() {
        let (header, txs, _) = real_block();
        let mut raw = header;
        raw.extend_from_slice(&[0xfd, 7, 0]);
        txs.iter().for_each(|tx| raw.extend_from_slice(tx));
        assert_eq!(validate_block_body(&raw), Err(BlockBodyError::InvalidCount));
    }

    /// 252 is the last count that fits one byte; 253 needs `fd fd 00`.
    #[test]
    fn the_count_encoding_changes_between_252_and_253() {
        let (header, txs) = test_block(252);
        let raw = raw_block(&header, &txs);
        assert_eq!(raw[ZCASH_FULL_HEADER_SIZE], 0xfc);
        assert_eq!(validate_block_body(&raw), Ok(252));

        let mut padded = header.clone();
        padded.extend_from_slice(&[0xfd, 0xfc, 0x00]);
        txs.iter().for_each(|tx| padded.extend_from_slice(tx));
        assert_eq!(
            validate_block_body(&padded),
            Err(BlockBodyError::InvalidCount)
        );

        let (header, txs) = test_block(253);
        let raw = raw_block(&header, &txs);
        assert_eq!(
            raw[ZCASH_FULL_HEADER_SIZE..ZCASH_FULL_HEADER_SIZE + 3],
            [0xfd, 0xfd, 0x00]
        );
        assert_eq!(validate_block_body(&raw), Ok(253));
    }

    #[test]
    fn trailing_bytes_are_refused() {
        let (_, _, mut raw) = real_block();
        raw.push(0);
        assert_eq!(
            validate_block_body(&raw),
            Err(BlockBodyError::TrailingBytes { bytes: 1 })
        );
    }

    /// `TrailingBytes` is the reason a valid block in an unknown layout can give,
    /// so it must not cover a body that does not match its header.
    #[test]
    fn trailing_bytes_do_not_hide_a_body_that_misses_its_header() {
        let (_, _, mut raw) = real_block();
        raw.push(0);
        raw[MERKLE_ROOT_RANGE.start] ^= 1;

        assert_eq!(
            validate_block_body(&raw),
            Err(BlockBodyError::MerkleMismatch)
        );
    }

    /// `Transaction` must mean nothing is known against the body, because the
    /// emergency bypass relies on it. A repeat already read is known.
    #[test]
    fn a_repeat_read_before_an_unreadable_transaction_is_reported() {
        let (header, txs, _) = real_block();
        let unreadable = vec![0xff; 40];
        let repeated = [
            txs[0].clone(),
            txs[1].clone(),
            txs[1].clone(),
            unreadable.clone(),
        ];
        let distinct = [txs[0].clone(), txs[1].clone(), unreadable];

        assert_eq!(
            validate_block_body(&raw_block(&header, &repeated)),
            Err(BlockBodyError::DuplicateTxid { index: 2 })
        );
        assert_eq!(
            validate_block_body(&raw_block(&header, &distinct)),
            Err(BlockBodyError::Transaction { index: 2 })
        );
    }

    #[test]
    fn trailing_bytes_do_not_hide_a_repeated_txid() {
        let (header, txs, _) = real_block();
        let mut repeated = txs.clone();
        repeated.push(txs[6].clone());
        let mut raw = raw_block(&header, &repeated);
        raw.push(0);

        assert_eq!(
            validate_block_body(&raw),
            Err(BlockBodyError::DuplicateTxid { index: 7 })
        );
    }

    /// A stride, the lengths around the end, and both sides of each edge the
    /// parser turns on: parsing each of the 36,000 prefixes takes minutes in a
    /// debug build.
    #[test]
    fn no_prefix_of_the_real_block_validates() {
        let (_, txs, raw) = real_block();
        let first_tx = raw.len() - txs.iter().map(Vec::len).sum::<usize>();
        let tx_starts: Vec<usize> = txs
            .iter()
            .scan(first_tx, |next, tx| {
                Some(std::mem::replace(next, *next + tx.len()))
            })
            .collect();
        assert_eq!(
            validate_block_body(&raw[..ZCASH_FULL_HEADER_SIZE]),
            Err(BlockBodyError::InvalidCount)
        );
        for (index, &start) in tx_starts.iter().enumerate() {
            assert_eq!(
                validate_block_body(&raw[..start]),
                Err(BlockBodyError::Transaction { index })
            );
        }
        let around_edges = tx_starts
            .iter()
            .chain([&ZCASH_FULL_HEADER_SIZE])
            .flat_map(|edge| edge - 1..=edge + 1);
        let near_the_end = raw.len() - 64..raw.len();
        let lengths = (0..raw.len()).step_by(499).chain(near_the_end);
        for len in lengths.chain(around_edges) {
            assert!(validate_block_body(&raw[..len]).is_err(), "prefix {len}");
        }
    }

    #[test]
    fn a_wrong_count_is_refused() {
        let (header, txs, _) = real_block();
        let with_count = |count: u8, txs: &[Vec<u8>]| {
            let mut raw = header.clone();
            raw.push(count);
            txs.iter().for_each(|tx| raw.extend_from_slice(tx));
            raw
        };
        assert_eq!(
            validate_block_body(&with_count(8, &txs)),
            Err(BlockBodyError::Transaction { index: 7 })
        );
        assert_eq!(
            validate_block_body(&with_count(6, &txs)),
            Err(BlockBodyError::MerkleMismatch)
        );
        assert_eq!(
            validate_block_body(&with_count(0, &[])),
            Err(BlockBodyError::EmptyTransactions)
        );
    }

    #[test]
    fn oversized_blocks_and_wrong_headers_are_refused() {
        assert_eq!(
            validate_block_body(&vec![0; MAX_BLOCK_BYTES + 1]),
            Err(BlockBodyError::TooLarge {
                bytes: MAX_BLOCK_BYTES + 1
            })
        );
        assert_eq!(
            validate_block_transactions(&[0; 80], [[0u8; 1].as_slice()].into_iter()),
            Err(BlockBodyError::InvalidHeaderLength)
        );
    }

    /// `count` transactions, the first padded so the block serializes to exactly
    /// `block_bytes`.
    fn block_of_size(count: usize, block_bytes: usize) -> (Vec<u8>, Vec<Vec<u8>>) {
        let small: Vec<Vec<u8>> = (1..count as u32).map(parseable_transaction).collect();
        let padding_overhead = parseable_transaction_with_script(0, 65_536).len() - 65_536;
        let padded_bytes = block_bytes
            - ZCASH_FULL_HEADER_SIZE
            - CompactSize::serialized_size(count)
            - small.iter().map(Vec::len).sum::<usize>();
        let mut txs = vec![parseable_transaction_with_script(
            0,
            padded_bytes - padding_overhead,
        )];
        txs.extend(small);
        (committed_header(0xcd, &txs), txs)
    }

    /// Both entry points limit what the block serializes to, which includes the
    /// transaction count, and that count takes more bytes from 253 transactions.
    #[test]
    fn both_entry_points_limit_the_serialized_block() {
        let mut disagreements = Vec::new();
        for count in [1, 252, 253] {
            for block_bytes in [MAX_BLOCK_BYTES, MAX_BLOCK_BYTES + 1] {
                let (header, txs) = block_of_size(count, block_bytes);
                let raw = raw_block(&header, &txs);
                assert_eq!(raw.len(), block_bytes);

                let expected = if block_bytes > MAX_BLOCK_BYTES {
                    Err(BlockBodyError::TooLarge { bytes: block_bytes })
                } else {
                    Ok(count)
                };
                let from_raw = validate_block_body(&raw);
                let from_slices =
                    validate_block_transactions(&header, txs.iter().map(Vec::as_slice));
                if from_raw != expected || from_slices != expected {
                    disagreements.push((count, block_bytes, from_raw, from_slices));
                }
            }
        }
        assert!(disagreements.is_empty(), "{disagreements:#?}");
    }

    /// Without the limit this would pass: the one oversized transaction parses
    /// and the header commits to it.
    #[test]
    fn oversized_transaction_slices_are_refused() {
        let tx = parseable_transaction_with_script(1, MAX_BLOCK_BYTES);
        let header = committed_header(0xcd, std::slice::from_ref(&tx));
        assert_eq!(
            validate_block_transactions(&header, [tx.as_slice()].into_iter()),
            Err(BlockBodyError::TooLarge {
                bytes: raw_block(&header, std::slice::from_ref(&tx)).len()
            })
        );
    }

    /// Each slice must be one transaction, even when the joined bytes would
    /// parse: this is what validating the concatenated block cannot see.
    #[test]
    fn slices_must_each_be_exactly_one_transaction() {
        let (header, txs) = test_block(3);
        let two_in_one = [txs[0].concat_with(&txs[1]), txs[2].clone()];
        assert_eq!(
            validate_block_transactions(&header, two_in_one.iter().map(Vec::as_slice)),
            Err(BlockBodyError::TransactionBoundary { index: 0 })
        );

        let mut extra_byte = txs.clone();
        extra_byte[1].push(0);
        assert_eq!(
            validate_block_transactions(&header, extra_byte.iter().map(Vec::as_slice)),
            Err(BlockBodyError::TransactionBoundary { index: 1 })
        );

        let (head, tail) = txs[1].split_at(10);
        let shifted = [
            txs[0].clone(),
            head.to_vec(),
            tail.iter().chain(&txs[2]).copied().collect::<Vec<u8>>(),
        ];
        assert_eq!(
            raw_block(&header, &shifted)[..],
            raw_block(&header, &txs)[..],
            "the joined bytes are the valid block"
        );
        assert_eq!(
            validate_block_transactions(&header, shifted.iter().map(Vec::as_slice)),
            Err(BlockBodyError::Transaction { index: 1 })
        );
    }

    /// The boundaries cover the body with no gap, so joining the transactions
    /// gives back the block.
    #[test]
    fn the_parsed_transactions_are_the_block_in_order() {
        let (_, txs, raw) = real_block();
        let (long_header, long_txs) = test_block(253);
        for (raw, txs) in [(raw, txs), (raw_block(&long_header, &long_txs), long_txs)] {
            let parsed = parse_block_body(raw.clone()).unwrap();
            assert_eq!(parsed.transactions().collect::<Vec<_>>(), txs);
            let boundaries = &parsed.boundaries;
            assert!(
                boundaries
                    .windows(2)
                    .all(|pair| pair[0].end == pair[1].start)
            );
            assert_eq!(boundaries.last().unwrap().end, raw.len());
        }
    }

    /// Nothing takes a parsed block and a second payload, so each one answers
    /// only from the bytes it checked.
    #[test]
    fn a_parsed_block_answers_from_the_bytes_it_checked() {
        let (header, txs) = test_block(3);
        let (_, _, real) = real_block();
        for raw in [raw_block(&header, &txs), real] {
            let parsed = parse_block_body(raw.clone()).unwrap();
            assert_eq!(parsed.raw_block(), raw);
            assert_eq!(parsed.header(), &raw[..ZCASH_FULL_HEADER_SIZE]);
        }
    }

    #[test]
    fn the_parsed_coinbase_is_the_first_transaction() {
        let (_, txs, raw) = real_block();
        let parsed = parse_block_body(raw).unwrap();
        assert_eq!(
            *parsed.coinbase().txid().as_ref(),
            txid_from_tx_bytes(&txs[0])
        );
    }

    /// It has to come back from a blocking task, so it cannot borrow from one.
    #[test]
    fn a_parsed_block_owns_what_it_reads() {
        fn assert_owned<T: Send + 'static>() {}
        assert_owned::<ParsedBlockBody>();
    }

    /// Written out here on purpose: swapping two labels fails, and a new kind
    /// stops this match compiling until it is added here and to `ALL`.
    #[test]
    fn every_kind_is_listed_once_with_its_own_label() {
        use BlockBodyError::*;
        let expected = |error: &BlockBodyError| match error {
            TooLarge { .. } => "too_large",
            InvalidHeaderLength => "invalid_header_length",
            HeaderTarget => "header_target",
            InvalidCount => "invalid_count",
            EmptyTransactions => "empty_transactions",
            Transaction { .. } => "transaction",
            TransactionBoundary { .. } => "transaction_boundary",
            TrailingBytes { .. } => "trailing_bytes",
            DuplicateTxid { .. } => "duplicate_txid",
            MerkleMismatch => "merkle_mismatch",
        };
        assert_eq!(BlockBodyError::ALL.len(), 10);
        let labels: HashSet<&str> = BlockBodyError::ALL.iter().map(|e| e.label()).collect();
        assert_eq!(labels.len(), BlockBodyError::ALL.len());
        for (position, kind) in BlockBodyError::ALL.iter().enumerate() {
            assert_eq!(kind.label(), expected(kind));
            assert_eq!(kind.kind_index(), position);
        }
        assert_eq!(
            Transaction { index: 7 }.kind_index(),
            Transaction { index: 0 }.kind_index()
        );
    }

    trait ConcatWith {
        fn concat_with(&self, other: &[u8]) -> Vec<u8>;
    }

    impl ConcatWith for Vec<u8> {
        fn concat_with(&self, other: &[u8]) -> Vec<u8> {
            [self.as_slice(), other].concat()
        }
    }
}

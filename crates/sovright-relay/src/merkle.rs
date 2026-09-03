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

use std::io::Cursor;

use sha2::{Digest, Sha256};
use zcash_primitives::transaction::{Transaction, TxVersion};
use zcash_protocol::consensus::BranchId;

/// Byte range of the merkle root inside a serialized Zcash block header.
///
/// Header layout: version(4) prev(32) merkle(32) commitments(32) time(4)
/// bits(4) nonce(32) then the Equihash solution. Verified against mainnet
/// block 3470793 in the tests.
const MERKLE_ROOT_RANGE: std::ops::Range<usize> = 36..68;

/// Branch id handed to the transaction reader.
///
/// For v5/v6 -- the only versions whose txid is not a plain double-SHA256 --
/// `Transaction::read` takes the consensus branch id from the transaction bytes
/// themselves, so this argument never influences a txid we compute. It is
/// threaded only to satisfy the reader API. Bump it at each network upgrade to
/// keep the documented intent aligned with mainnet.
const CONSENSUS_BRANCH_ID: BranchId = BranchId::Nu6_3;

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
    if let Ok(tx) = Transaction::read(&mut cursor, CONSENSUS_BRANCH_ID) {
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
        for pair in level.chunks_exact(2) {
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
/// Fails closed: a header too short to carry a merkle root, or an empty
/// transaction list, is a mismatch rather than a pass.
pub fn transactions_match_merkle_root(header: &[u8], transactions: &[Vec<u8>]) -> bool {
    let Some(expected) = header_merkle_root(header) else {
        return false;
    };
    let txids: Vec<[u8; 32]> = transactions
        .iter()
        .map(|tx| txid_from_tx_bytes(tx))
        .collect();
    match merkle_root(&txids) {
        Some(actual) => actual == expected,
        None => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Mainnet block 3470793: header + all 7 transactions, in block order,
    /// fetched from Zebra (`getblock <hash> 0` / `getrawtransaction`). Five are
    /// v6 (ZIP-229, version group 0x98b684d8) and two are v4, so this fixture
    /// exercises BOTH txid rules. Synthetic bytes cannot: they parse as neither.
    const BLOCK_FIXTURE: &str = include_str!("../tests/fixtures/mainnet_block_3470793.txt");

    fn fixture() -> (Vec<u8>, Vec<Vec<u8>>) {
        let mut lines = BLOCK_FIXTURE.lines().filter(|l| !l.trim().is_empty());
        let header = hex::decode(lines.next().expect("header line").trim()).expect("header hex");
        let txs = lines
            .map(|l| hex::decode(l.trim()).expect("tx hex"))
            .collect();
        (header, txs)
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

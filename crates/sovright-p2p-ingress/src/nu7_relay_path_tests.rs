//! The NU7 activation block through the sidecar's short-ID submission path
//! and the 10+3 FEC decoder. Isolated qualification only; no production code
//! is changed.
//!
//! The body of a short-ID block is checked in `sovright_relay`'s reconstructor.
//! All-prefilled compact blocks and raw segments reach the same rule by their own
//! paths, so nothing here makes a claim about them. "Submitted" means the
//! counting submitter was called; no node accepts anything in these tests.
use sha2::{Digest, Sha256};
use sovright_relay::{
    BlockBodyError, BlockChunker, FecError, parse_block_body, txid_from_tx_bytes,
};
use sovright_relay_sidecar::submit::{
    RelayBlockError, SubmissionOutcome, SubmitBlock, SubmitBlockMode, SubmitFuture,
    build_submission_candidate, handle_relay_compact_block_with_mempool,
};

use super::nu7_fixture::{Nu7Fixture, tx_cache};
use crate::block::{compact_block_from_parsed, compact_block_from_parsed_with_tx_cache};
use crate::wtxid::{TX_READER_BRANCH_HINT, wtxid_from_tx_bytes};

/// Records every block it is asked to submit. It is not a node.
#[derive(Default)]
struct CountingSubmit {
    submitted: std::sync::Mutex<Vec<String>>,
}

impl CountingSubmit {
    fn submitted(&self) -> Vec<String> {
        self.submitted.lock().unwrap().clone()
    }
}

impl SubmitBlock for CountingSubmit {
    fn submit_block<'a>(&'a self, block_hex: &'a str) -> SubmitFuture<'a> {
        self.submitted.lock().unwrap().push(block_hex.to_owned());
        Box::pin(async move { Ok(None) })
    }
}

/// The NU7 block in cached compact form (coinbase prefilled, the v5
/// transaction as a short ID) through the sidecar's short-ID handler in live
/// mode. `entry`, if any, sits in the receiver's cache under the v5
/// transaction's wtxid, the way a mis-keyed tx-feed record would.
async fn submit_short_id_block(
    entry: Option<Vec<u8>>,
) -> (Result<SubmissionOutcome, RelayBlockError>, Vec<String>) {
    let fixture = Nu7Fixture::load();
    let origin = tx_cache();
    origin.insert(fixture.v5_wtxid(), fixture.v5_transaction());
    let parsed = parse_block_body(fixture.raw.clone()).unwrap();
    let compact = compact_block_from_parsed_with_tx_cache(&parsed, &origin).unwrap();
    assert_eq!(
        compact.short_ids.len(),
        1,
        "the v5 transaction must travel as a short ID"
    );

    let receiver = tx_cache();
    if let Some(bytes) = entry {
        receiver.insert(fixture.v5_wtxid(), bytes);
    }
    let submitter = CountingSubmit::default();
    let outcome = handle_relay_compact_block_with_mempool(
        &submitter,
        &compact,
        SubmitBlockMode::Live,
        &receiver,
    )
    .await;
    (outcome, submitter.submitted())
}

fn assert_body_rejected(
    outcome: Result<SubmissionOutcome, RelayBlockError>,
    submitted: &[String],
    expected: BlockBodyError,
) {
    match outcome {
        Err(RelayBlockError::InvalidBlockBody(error)) => assert_eq!(error, expected),
        other => panic!("expected {expected:?}, got {other:?}"),
    }
    assert!(
        submitted.is_empty(),
        "a rejected block reached submit_block"
    );
}

fn txid_display(tx: &[u8]) -> String {
    sovright_relay::merkle::display_hex(&txid_from_tx_bytes(tx))
}

#[tokio::test]
async fn nu7_short_id_block_with_the_right_transaction_is_submitted_once() {
    let fixture = Nu7Fixture::load();
    let (outcome, submitted) = submit_short_id_block(Some(fixture.v5_transaction())).await;

    assert!(
        matches!(outcome, Ok(SubmissionOutcome::Submitted { .. })),
        "{outcome:?}"
    );
    assert_eq!(submitted, vec![hex::encode(&fixture.raw)]);
}

/// Missing data prepares a getblocktxn request; the sidecar does not send it
/// from this path, and nothing is submitted.
#[tokio::test]
async fn nu7_short_id_block_without_the_transaction_prepares_a_request() {
    let (outcome, submitted) = submit_short_id_block(None).await;

    match outcome {
        Ok(SubmissionOutcome::NeedsTransactions {
            request,
            missing_indexes,
            ..
        }) => {
            assert_eq!(request.indexes, vec![1]);
            assert_eq!(missing_indexes, 1);
        }
        other => panic!("expected NeedsTransactions, got {other:?}"),
    }
    assert!(submitted.is_empty());
}

/// Truncated bytes cannot be parsed. The txid helper would fall back to sha256d
/// of them, but the reader refuses them first, so the reason names the slot.
#[tokio::test]
async fn nu7_truncated_transaction_is_refused_by_the_reader() {
    let truncated = Nu7Fixture::load().v5_transaction()[..139].to_vec();
    assert_eq!(wtxid_from_tx_bytes(&truncated, TX_READER_BRANCH_HINT), None);
    let sha256d: [u8; 32] = Sha256::digest(Sha256::digest(&truncated)).into();
    assert_eq!(txid_from_tx_bytes(&truncated), sha256d);

    let (outcome, submitted) = submit_short_id_block(Some(truncated)).await;
    assert_body_rejected(
        outcome,
        &submitted,
        BlockBodyError::Transaction { index: 1 },
    );
}

/// The first output's value (byte 169) is effecting data: the transaction
/// still parses, but its txid changes.
#[tokio::test]
async fn nu7_effecting_data_change_fails_the_merkle_check() {
    let fixture = Nu7Fixture::load();
    let mut changed = fixture.v5_transaction();
    changed[169] ^= 0x01;
    assert!(wtxid_from_tx_bytes(&changed, TX_READER_BRANCH_HINT).is_some());
    assert_ne!(txid_display(&changed), fixture.v5_txid_display());

    let (outcome, submitted) = submit_short_id_block(Some(changed)).await;
    assert_body_rejected(outcome, &submitted, BlockBodyError::MerkleMismatch);
}

/// A real v4 transaction is rejected because it is a different transaction,
/// not because of NU7's v4 rule; any other transaction would be too.
#[tokio::test]
async fn nu7_v4_transaction_under_the_v5_key_fails_the_merkle_check() {
    let v4 = zcash_pool_common::fixtures::mainnet_transactions()[3].clone();
    assert_eq!(&v4[..4], &[0x04, 0x00, 0x00, 0x80]);
    assert_eq!(wtxid_from_tx_bytes(&v4, TX_READER_BRANCH_HINT), None);

    let (outcome, submitted) = submit_short_id_block(Some(v4)).await;
    assert_body_rejected(outcome, &submitted, BlockBodyError::MerkleMismatch);
}

/// A real NU6.3 v6 transaction: rejected as a different transaction, not for
/// its pre-NU7 branch.
#[tokio::test]
async fn nu7_pre_nu7_v6_transaction_under_the_v5_key_fails_the_merkle_check() {
    let v6 = hex::decode(include_str!("../tests/fixtures/mainnet_v6_tx.hex").trim()).unwrap();
    assert_eq!(&v6[..4], &[0x06, 0x00, 0x00, 0x80]);
    assert_ne!(
        u32::from_le_bytes(v6[8..12].try_into().unwrap()),
        0x7719_0ad9
    );

    let (outcome, submitted) = submit_short_id_block(Some(v6)).await;
    assert_body_rejected(outcome, &submitted, BlockBodyError::MerkleMismatch);
}

/// Documents a current gap in the sidecar's short-ID path, not a guarantee
/// to preserve. A v5 scriptSig is authorizing data (ZIP 244): changing one of
/// its bytes keeps the txid, so the body check passes and the altered block is
/// submitted. Whichever layer gains authorization or block-commitment
/// verification, this expectation is re-evaluated then.
#[tokio::test]
async fn known_gap_nu7_auth_only_change_passes_the_body_check() {
    let fixture = Nu7Fixture::load();
    let mut altered = fixture.v5_transaction();
    altered[100] ^= 0x01; // inside the input's scriptSig, bytes 58..=163
    assert_eq!(txid_display(&altered), fixture.v5_txid_display());
    let altered_wtxid = wtxid_from_tx_bytes(&altered, TX_READER_BRANCH_HINT)
        .expect("the altered transaction still parses");
    assert_ne!(altered_wtxid, fixture.v5_wtxid(), "the auth digest changed");

    let (outcome, submitted) = submit_short_id_block(Some(altered)).await;

    assert!(
        matches!(outcome, Ok(SubmissionOutcome::Submitted { .. })),
        "{outcome:?}"
    );
    assert_eq!(submitted.len(), 1);
    let sent = hex::decode(&submitted[0]).unwrap();
    assert_eq!(sent.len(), fixture.raw.len());
    let differing = sent
        .iter()
        .zip(&fixture.raw)
        .filter(|(sent, raw)| sent != raw)
        .count();
    assert_eq!(differing, 1, "only the altered scriptSig byte differs");
}

// ---------------------------------------------------------------------------
// 10+3 FEC on the NU7 payload, at the decoder. The loopback transport has no
// point to inject loss, so network-level loss is not covered here.
// ---------------------------------------------------------------------------

/// Split the NU7 all-prefilled compact block into 10+3 chunks, drop `lost`,
/// decode, and return the raw block the sidecar would build from the result.
fn fec_round_trip(lost: &[usize]) -> Result<Vec<u8>, FecError> {
    let fixture = Nu7Fixture::load();
    let parsed = parse_block_body(fixture.raw.clone()).unwrap();
    let compact = compact_block_from_parsed(&parsed).unwrap();
    let chunker = BlockChunker::new(10, 3).unwrap();
    let chunks = chunker
        .compact_block_to_chunks(&compact, &sovright_relay::zcash_block_hash(&compact.header))
        .unwrap();
    assert_eq!(chunks.len(), 13, "one 10+3 group");
    for (index, chunk) in chunks.iter().enumerate() {
        assert_eq!(usize::from(chunk.header.chunk_id), index);
    }
    let serialized = BlockChunker::serialize_compact_block(&compact);

    let mut shards: Vec<Option<Vec<u8>>> = chunks.into_iter().map(|c| Some(c.payload)).collect();
    for &index in lost {
        shards[index] = None;
    }
    let recovered = chunker.chunks_to_compact_block(shards, serialized.len())?;
    assert_eq!(
        BlockChunker::serialize_compact_block(&recovered),
        serialized
    );
    let candidate = build_submission_candidate(&recovered).unwrap();
    Ok(hex::decode(candidate.block_hex).unwrap())
}

#[test]
fn nu7_fec_recovers_three_lost_data_shards() {
    assert_eq!(fec_round_trip(&[0, 4, 9]).unwrap(), Nu7Fixture::load().raw);
}

#[test]
fn nu7_fec_recovers_mixed_data_and_parity_loss() {
    assert_eq!(fec_round_trip(&[2, 7, 11]).unwrap(), Nu7Fixture::load().raw);
}

/// Every data shard arrives, so no recovery is needed.
#[test]
fn nu7_fec_tolerates_losing_only_parity() {
    assert_eq!(
        fec_round_trip(&[10, 11, 12]).unwrap(),
        Nu7Fixture::load().raw
    );
}

/// The data-only recovery above came from parity: without it, it fails.
#[test]
fn nu7_fec_cannot_recover_data_loss_without_parity() {
    assert!(matches!(
        fec_round_trip(&[0, 4, 9, 10, 11, 12]),
        Err(FecError::InsufficientShards { .. })
    ));
}

#[test]
fn nu7_fec_cannot_recover_four_lost_shards() {
    assert!(matches!(
        fec_round_trip(&[0, 1, 2, 10]),
        Err(FecError::InsufficientShards { .. })
    ));
}

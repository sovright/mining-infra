//! Local share validation for downstream-submitted Equihash shares.
//!
//! When a mining-hardware proxy submits a `SubmitEquihashShare` against a
//! declared job, the JDC validates it *locally* against the pool-granted share
//! target before telling the proxy Accepted and relaying it to the pool. The
//! pool re-verifies and is authoritative for credit; local validation exists so
//! the JDC can give the proxy an immediate verdict and avoid relaying garbage.
//!
//! The functions here are deliberately pure (no I/O, no shared state) so they
//! are unit-testable byte-for-byte. The stateful pieces — dedup set, relay
//! queue, block submission — live in the listener.

use crate::declared_job::CurrentDeclaredJob;
use sha2::{Digest, Sha256};
use zcash_equihash_validator::{EquihashValidator, ValidationError, compact_to_target};
use zcash_mining_protocol::messages::{RejectReason, ShareResult};

/// Fixed length of the miner-controlled nonce_2 portion served by the listener.
pub const NONCE_2_LEN: usize = 28;

/// Outcome of locally validating a single downstream share.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ShareOutcome {
    /// Share is valid at the share target. If `meets_block_target` is true the
    /// solution hash also satisfies the block (`bits`) target and a block
    /// should be assembled + submitted.
    Accepted {
        /// The reassembled full 32-byte nonce (nonce_1 ‖ nonce_2).
        nonce: [u8; 32],
        /// Whether the solution hash also meets the block target.
        meets_block_target: bool,
    },
    /// Share is rejected; carries the protocol reason to send downstream.
    Rejected(RejectReason),
}

impl ShareOutcome {
    /// Map the outcome to the wire-level `ShareResult` for the proxy.
    pub fn to_share_result(&self) -> ShareResult {
        match self {
            ShareOutcome::Accepted { .. } => ShareResult::Accepted,
            ShareOutcome::Rejected(reason) => ShareResult::Rejected(reason.clone()),
        }
    }
}

/// Reassemble the full 32-byte nonce from the listener's `nonce_1` and the
/// miner-supplied `nonce_2`.
///
/// `nonce_1` is the 4-byte channel-id prefix served in the job; `nonce_2` must
/// be exactly [`NONCE_2_LEN`] bytes. Returns `None` on any length mismatch
/// (caller maps that to `Rejected(Other("bad nonce_2 length"))`).
pub fn reassemble_nonce(nonce_1: &[u8], nonce_2: &[u8]) -> Option<[u8; 32]> {
    if nonce_2.len() != NONCE_2_LEN {
        return None;
    }
    if nonce_1.len() + nonce_2.len() != 32 {
        return None;
    }
    let mut nonce = [0u8; 32];
    nonce[..nonce_1.len()].copy_from_slice(nonce_1);
    nonce[nonce_1.len()..].copy_from_slice(nonce_2);
    Some(nonce)
}

/// Build the 140-byte Equihash header for a declared job + share.
///
/// Layout (all multi-byte fields little-endian):
/// `[0:4]=version | [4:36]=prev_hash | [36:68]=merkle_root |
///  [68:100]=block_commitments | [100:104]=time | [104:108]=bits |
///  [108:140]=nonce`.
pub fn build_header(job: &CurrentDeclaredJob, time: u32, nonce: &[u8; 32]) -> [u8; 140] {
    let mut header = [0u8; 140];
    header[0..4].copy_from_slice(&job.version.to_le_bytes());
    header[4..36].copy_from_slice(&job.prev_hash);
    header[36..68].copy_from_slice(&job.merkle_root);
    header[68..100].copy_from_slice(&job.block_commitments);
    header[100..104].copy_from_slice(&time.to_le_bytes());
    header[104..108].copy_from_slice(&job.bits.to_le_bytes());
    header[108..140].copy_from_slice(nonce);
    header
}

/// Compute the per-job dedup key for a share: `sha256(nonce ‖ time_le ‖
/// solution[..64])`.
///
/// Only the first 64 bytes of the 1344-byte Equihash-(200,9) solution are
/// hashed: those bytes encode the leading index pairs of the solution, so two
/// distinct valid solutions colliding on `(nonce, time, solution[..64])` is
/// astronomically unlikely. The truncation only bounds hashing cost — the full
/// 1344-byte solution is still verified in its entirety before any credit, so a
/// collision could at worst suppress a duplicate, never admit an invalid share.
/// (Mirrors `share_dedup_key` in zcash-jd-server.)
pub fn share_dedup_key(nonce: &[u8; 32], time: u32, solution: &[u8; 1344]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(nonce);
    hasher.update(time.to_le_bytes());
    hasher.update(&solution[..64]);
    hasher.finalize().into()
}

/// Verify a structurally-reassembled share against the job's share target.
///
/// Distinguishes a structurally valid solution that simply misses the share
/// target (`TargetNotMet` → `LowDifficulty`) from a structurally broken
/// solution (everything else → `InvalidSolution`). On success, also reports
/// whether the solution hash meets the block (`bits`) target so the caller can
/// trigger block assembly.
///
/// NOTE: dedup is the caller's responsibility (it must register-before-verify);
/// this function is the pure cryptographic core.
pub fn verify_share(
    job: &CurrentDeclaredJob,
    time: u32,
    nonce: &[u8; 32],
    solution: &[u8; 1344],
) -> ShareOutcome {
    let header = build_header(job, time, nonce);
    let validator = EquihashValidator::new();
    match validator.verify_share(&header, solution, &job.share_target) {
        Ok(hash) => {
            // Share target met. Now check the (harder) block target.
            let block_target = compact_to_target(job.bits);
            let meets_block_target = block_target.is_met_by(&hash);
            ShareOutcome::Accepted {
                nonce: *nonce,
                meets_block_target,
            }
        }
        Err(ValidationError::TargetNotMet) => ShareOutcome::Rejected(RejectReason::LowDifficulty),
        Err(_) => ShareOutcome::Rejected(RejectReason::InvalidSolution),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_job() -> CurrentDeclaredJob {
        CurrentDeclaredJob {
            job_id: 1,
            version: 5,
            prev_hash: [0xaa; 32],
            merkle_root: [0xbb; 32],
            block_commitments: [0xcc; 32],
            time: 0x1234_5678,
            bits: 0xaabb_ccdd,
            share_target: [0xff; 32],
            coinbase_tx: vec![],
            transactions: vec![],
        }
    }

    #[test]
    fn nonce_reassembly_concatenates_in_order() {
        let nonce_1 = [0x01, 0x02, 0x03, 0x04];
        let nonce_2 = [0xaa; NONCE_2_LEN];
        let nonce = reassemble_nonce(&nonce_1, &nonce_2).expect("valid");
        assert_eq!(&nonce[0..4], &[0x01, 0x02, 0x03, 0x04]);
        assert_eq!(&nonce[4..32], &[0xaa; 28]);
    }

    #[test]
    fn nonce_reassembly_rejects_bad_nonce2_length() {
        let nonce_1 = [0x01, 0x02, 0x03, 0x04];
        // 27 bytes — one short.
        assert!(reassemble_nonce(&nonce_1, &[0xaa; 27]).is_none());
        // 29 bytes — one long.
        assert!(reassemble_nonce(&nonce_1, &[0xaa; 29]).is_none());
    }

    #[test]
    fn nonce_reassembly_rejects_bad_nonce1_length() {
        // nonce_1 of 5 bytes + 28 = 33 != 32.
        assert!(reassemble_nonce(&[0u8; 5], &[0xaa; NONCE_2_LEN]).is_none());
    }

    #[test]
    fn header_layout_is_byte_exact() {
        let job = sample_job();
        let nonce = [0xff; 32];
        let header = build_header(&job, 0x1234_5678, &nonce);

        let mut expected = [0u8; 140];
        // version 5 LE
        expected[0..4].copy_from_slice(&[0x05, 0x00, 0x00, 0x00]);
        expected[4..36].copy_from_slice(&[0xaa; 32]);
        expected[36..68].copy_from_slice(&[0xbb; 32]);
        expected[68..100].copy_from_slice(&[0xcc; 32]);
        // time 0x12345678 LE
        expected[100..104].copy_from_slice(&[0x78, 0x56, 0x34, 0x12]);
        // bits 0xaabbccdd LE
        expected[104..108].copy_from_slice(&[0xdd, 0xcc, 0xbb, 0xaa]);
        expected[108..140].copy_from_slice(&[0xff; 32]);

        assert_eq!(header, expected);
    }

    #[test]
    fn header_uses_share_time_not_job_time() {
        let job = sample_job();
        let nonce = [0u8; 32];
        // Pass a different time than job.time; it must land in the header.
        let header = build_header(&job, 0x0000_0001, &nonce);
        assert_eq!(&header[100..104], &[0x01, 0x00, 0x00, 0x00]);
    }

    #[test]
    fn dedup_key_recipe_matches_components() {
        let nonce = [0x07; 32];
        let time = 0x0000_00ffu32;
        let mut solution = [0u8; 1344];
        solution[0] = 0xab;

        let key = share_dedup_key(&nonce, time, &solution);

        // Recompute the exact recipe independently.
        let mut hasher = Sha256::new();
        hasher.update(nonce);
        hasher.update(time.to_le_bytes());
        hasher.update(&solution[..64]);
        let expected: [u8; 32] = hasher.finalize().into();

        assert_eq!(key, expected);
    }

    #[test]
    fn dedup_key_ignores_solution_past_64_bytes() {
        let nonce = [0x07; 32];
        let time = 5u32;
        let mut sol_a = [0u8; 1344];
        let mut sol_b = [0u8; 1344];
        // Differ only at byte 64 (outside the hashed prefix).
        sol_a[64] = 0x01;
        sol_b[64] = 0x02;
        assert_eq!(
            share_dedup_key(&nonce, time, &sol_a),
            share_dedup_key(&nonce, time, &sol_b)
        );
    }

    #[test]
    fn dedup_key_distinguishes_prefix_difference() {
        let nonce = [0x07; 32];
        let time = 5u32;
        let mut sol_a = [0u8; 1344];
        let mut sol_b = [0u8; 1344];
        sol_a[0] = 0x01;
        sol_b[0] = 0x02;
        assert_ne!(
            share_dedup_key(&nonce, time, &sol_a),
            share_dedup_key(&nonce, time, &sol_b)
        );
    }

    #[test]
    fn garbage_solution_is_rejected_invalid() {
        // A structurally broken (all-zero) solution must verify as
        // InvalidSolution, never LowDifficulty or Accepted.
        let job = sample_job();
        let nonce = [0u8; 32];
        let solution = [0u8; 1344];
        match verify_share(&job, job.time, &nonce, &solution) {
            ShareOutcome::Rejected(RejectReason::InvalidSolution) => {}
            other => panic!("expected InvalidSolution, got {:?}", other),
        }
    }

    #[test]
    fn outcome_maps_to_share_result() {
        let accepted = ShareOutcome::Accepted {
            nonce: [0u8; 32],
            meets_block_target: false,
        };
        assert_eq!(accepted.to_share_result(), ShareResult::Accepted);

        let rejected = ShareOutcome::Rejected(RejectReason::StaleJob);
        assert_eq!(
            rejected.to_share_result(),
            ShareResult::Rejected(RejectReason::StaleJob)
        );
    }

    // =========================================================================
    // DELIBERATE COVERAGE GAP: the Accept path (a share whose hash is at/under
    // the share target) and the LowDifficulty path
    // (ValidationError::TargetNotMet, which requires a *structurally valid*
    // Equihash solution whose hash sits above the share target) are NOT
    // exercised here. No valid-Equihash-solution fixture exists in this suite —
    // the only way to produce one is a real CPU solver. Both paths (plus the
    // block-target branch and end-to-end submission) are covered by Task 7's
    // full-chain integration test. The tests above cover every rejection path
    // and pure-function recipe reachable without a valid solution.
    // =========================================================================
}

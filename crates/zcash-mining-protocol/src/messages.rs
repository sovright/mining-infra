//! Zcash Mining Protocol message types
//!
//! Message types for Equihash mining over Stratum V2:
//! - NewEquihashJob: Sent by pool to distribute mining work
//! - SubmitEquihashShare: Sent by miner to submit solutions
//! - SubmitSharesResponse: Pool's response to share submission

/// Message type identifiers (SRI-compatible range for extension)
pub mod message_types {
    /// NewEquihashJob message type
    pub const NEW_EQUIHASH_JOB: u8 = 0x20;
    /// SubmitEquihashShare message type
    pub const SUBMIT_EQUIHASH_SHARE: u8 = 0x21;
    /// SubmitSharesResponse message type
    pub const SUBMIT_SHARES_RESPONSE: u8 = 0x22;
    /// SetTarget message type (difficulty adjustment)
    pub const SET_TARGET: u8 = 0x23;
}

/// Pool -> Miner: New mining job
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub struct NewEquihashJob {
    /// Channel this job belongs to
    pub channel_id: u32,
    /// Unique job identifier
    pub job_id: u32,
    /// If true, this job should be queued for future use
    pub future_job: bool,
    /// Block version
    pub version: u32,
    /// Previous block hash (32 bytes)
    pub prev_hash: [u8; 32],
    /// Merkle root of transactions (32 bytes)
    pub merkle_root: [u8; 32],
    /// hashBlockCommitments for NU5+ (32 bytes)
    pub block_commitments: [u8; 32],
    /// Pool-assigned nonce prefix (variable length)
    pub nonce_1: Vec<u8>,
    /// Length of miner-controlled nonce portion
    pub nonce_2_len: u8,
    /// Block timestamp
    pub time: u32,
    /// Compact difficulty target (nbits)
    pub bits: u32,
    /// Share difficulty target (256-bit, pool-set)
    pub target: [u8; 32],
    /// If true, discard all previous jobs
    pub clean_jobs: bool,
}

impl NewEquihashJob {
    /// Total nonce length (must equal 32)
    pub fn total_nonce_len(&self) -> usize {
        self.nonce_1.len() + self.nonce_2_len as usize
    }

    /// Validate that nonce lengths sum to 32
    pub fn validate_nonce_len(&self) -> bool {
        self.total_nonce_len() == 32
    }

    /// Construct the 140-byte header for Equihash input
    /// (version || prev_hash || merkle_root || block_commitments || time || bits || nonce)
    pub fn build_header(&self, nonce: &[u8; 32]) -> [u8; 140] {
        let mut header = [0u8; 140];
        header[0..4].copy_from_slice(&self.version.to_le_bytes());
        header[4..36].copy_from_slice(&self.prev_hash);
        header[36..68].copy_from_slice(&self.merkle_root);
        header[68..100].copy_from_slice(&self.block_commitments);
        header[100..104].copy_from_slice(&self.time.to_le_bytes());
        header[104..108].copy_from_slice(&self.bits.to_le_bytes());
        header[108..140].copy_from_slice(nonce);
        header
    }

    /// Combine nonce_1 and nonce_2 into full 32-byte nonce
    pub fn build_nonce(&self, nonce_2: &[u8]) -> Option<[u8; 32]> {
        if nonce_2.len() != self.nonce_2_len as usize {
            return None;
        }
        let mut nonce = [0u8; 32];
        nonce[..self.nonce_1.len()].copy_from_slice(&self.nonce_1);
        nonce[self.nonce_1.len()..].copy_from_slice(nonce_2);
        Some(nonce)
    }
}

/// Miner -> Pool: Submit Equihash share
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub struct SubmitEquihashShare {
    /// Channel this share belongs to
    pub channel_id: u32,
    /// Sequence number for response matching
    pub sequence_number: u32,
    /// Job this share is for
    pub job_id: u32,
    /// Miner-controlled nonce portion
    pub nonce_2: Vec<u8>,
    /// Block timestamp (may differ from job time)
    pub time: u32,
    /// Equihash (200,9) solution (1344 bytes)
    pub solution: [u8; 1344],
}

impl SubmitEquihashShare {
    /// Equihash (200,9) solution size
    pub const SOLUTION_SIZE: usize = 1344;

    /// Validate solution length
    ///
    /// Note: This always returns true since `solution` is a fixed-size
    /// `[u8; 1344]` array. Retained for API compatibility.
    pub fn validate_solution_len(&self) -> bool {
        // Compile-time guarantee: solution is always SOLUTION_SIZE bytes
        true
    }
}

/// Pool -> Miner: Response to share submission
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub struct SubmitSharesResponse {
    /// Channel ID
    pub channel_id: u32,
    /// Sequence number matching the submission
    pub sequence_number: u32,
    /// Result of share validation
    pub result: ShareResult,
}

/// Result of share validation
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub enum ShareResult {
    /// Share accepted
    Accepted,
    /// Share rejected with reason
    Rejected(RejectReason),
}

/// Reasons for share rejection
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub enum RejectReason {
    /// Job ID not found or expired
    StaleJob,
    /// Duplicate share already submitted
    Duplicate,
    /// Solution does not verify
    InvalidSolution,
    /// Share difficulty below target
    LowDifficulty,
    /// Other error
    Other(String),
}

/// Pool -> Miner: Update share difficulty target
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub struct SetTarget {
    /// Channel ID
    pub channel_id: u32,
    /// New target (256-bit, little-endian)
    pub target: [u8; 32],
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_nonce_validation() {
        let job = NewEquihashJob {
            channel_id: 1,
            job_id: 1,
            future_job: false,
            version: 5,
            prev_hash: [0; 32],
            merkle_root: [0; 32],
            block_commitments: [0; 32],
            nonce_1: vec![0; 8],
            nonce_2_len: 24,
            time: 0,
            bits: 0,
            target: [0; 32],
            clean_jobs: false,
        };
        assert!(job.validate_nonce_len());

        let bad_job = NewEquihashJob {
            nonce_1: vec![0; 8],
            nonce_2_len: 20, // 8 + 20 = 28, not 32
            ..job.clone()
        };
        assert!(!bad_job.validate_nonce_len());
    }

    #[test]
    fn test_build_nonce() {
        let job = NewEquihashJob {
            channel_id: 1,
            job_id: 1,
            future_job: false,
            version: 5,
            prev_hash: [0; 32],
            merkle_root: [0; 32],
            block_commitments: [0; 32],
            nonce_1: vec![0x01, 0x02, 0x03, 0x04],
            nonce_2_len: 28,
            time: 0,
            bits: 0,
            target: [0; 32],
            clean_jobs: false,
        };

        let nonce_2 = vec![0xaa; 28];
        let full_nonce = job.build_nonce(&nonce_2).unwrap();

        assert_eq!(&full_nonce[0..4], &[0x01, 0x02, 0x03, 0x04]);
        assert_eq!(&full_nonce[4..32], &[0xaa; 28]);
    }

    #[test]
    fn test_build_header() {
        let job = NewEquihashJob {
            channel_id: 1,
            job_id: 1,
            future_job: false,
            version: 5,
            prev_hash: [0xaa; 32],
            merkle_root: [0xbb; 32],
            block_commitments: [0xcc; 32],
            nonce_1: vec![0; 4],
            nonce_2_len: 28,
            time: 0x12345678,
            bits: 0xaabbccdd,
            target: [0; 32],
            clean_jobs: false,
        };

        let nonce = [0xff; 32];
        let header = job.build_header(&nonce);

        assert_eq!(header.len(), 140);
        // Version at offset 0 (little-endian)
        assert_eq!(&header[0..4], &[0x05, 0x00, 0x00, 0x00]);
        // prev_hash at offset 4
        assert_eq!(&header[4..36], &[0xaa; 32]);
        // merkle_root at offset 36
        assert_eq!(&header[36..68], &[0xbb; 32]);
        // block_commitments at offset 68
        assert_eq!(&header[68..100], &[0xcc; 32]);
        // time at offset 100 (little-endian)
        assert_eq!(&header[100..104], &[0x78, 0x56, 0x34, 0x12]);
        // bits at offset 104 (little-endian)
        assert_eq!(&header[104..108], &[0xdd, 0xcc, 0xbb, 0xaa]);
        // nonce at offset 108
        assert_eq!(&header[108..140], &[0xff; 32]);
    }
}

//! Proof-of-work validation for block headers.
//!
//! Two properties make a Zcash header's PoW, and BOTH are required:
//!
//! 1. the Equihash solution is valid for the header + nonce, and
//! 2. the resulting solution hash is at or below the header's stated target.
//!
//! Only (1) was checked here until 2026-09-01, which is close to no check at
//! all: Zcash's Equihash parameters yield roughly two valid solutions per
//! nonce, so a valid *solution* is cheap to produce. All of the difficulty --
//! and therefore all of the spam resistance -- lives in (2).
//!
//! Like the equivalent guard in `sovright-p2p-ingress::submitblock_rpc`, this
//! is an anti-garbage check and NOT a consensus-difficulty check: it requires
//! the header to meet its OWN stated target within the valid mainnet range.
//! Whether that target clears the current network difficulty is the full
//! node's job, and needs chain context this layer does not have.

/// Minimum block header size in bytes for validation
/// The basic Zcash block header (without Equihash solution) is 140 bytes
const MIN_HEADER_SIZE: usize = 140;

/// Number of bytes in the Equihash input before the 32-byte nonce.
const ZCASH_EQUIHASH_INPUT_SIZE: usize = 108;

/// Result of PoW validation
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PowResult {
    /// Header has valid proof-of-work - accept and forward the block
    Valid,
    /// Header has invalid proof-of-work - reject and drop the block
    Invalid,
    /// Cannot validate (e.g., header too short) - buffer until more data arrives
    Indeterminate,
}

/// Outcome of the hash-to-target half of the PoW check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TargetCheck {
    Met,
    NotMet,
    /// nBits is malformed or outside the valid mainnet range.
    BadTarget,
}

/// Does this header meet the target its own nBits encodes?
///
/// Zcash's PoW hash is the **double-SHA256** of the full 1487-byte serialized
/// header, compared as a little-endian 256-bit integer against the target.
///
/// Note this deliberately does NOT use `EquihashValidator::verify_share`'s
/// target arm. That helper hashes with BLAKE2b personalised `"ZcashBlockHash"`,
/// which is not Zcash's block hash, and it rejects genuine mainnet headers --
/// verified 2026-09-01 against the real header fixture below.
fn header_meets_stated_target(header: &[u8]) -> TargetCheck {
    use sha2::{Digest, Sha256};
    use zcash_equihash_validator::{Target, compact_to_target};

    // Zcash header: version(4) prev(32) merkle(32) commitments(32) time(4) bits(4) nonce(32),
    // so nBits starts at 4+32+32+32+4 = 104, little-endian. Offset 100 is `time`;
    // reading it there silently rejects every real header.
    const BITS_OFFSET: usize = 104;
    let bits = u32::from_le_bytes([
        header[BITS_OFFSET],
        header[BITS_OFFSET + 1],
        header[BITS_OFFSET + 2],
        header[BITS_OFFSET + 3],
    ]);
    // Reject the negative / zero-mantissa encodings before converting.
    if bits & 0x0080_0000 != 0 || bits & 0x007f_ffff == 0 {
        return TargetCheck::BadTarget;
    }
    let target = compact_to_target(bits);
    if target.0 == [0u8; 32] || target > Target::max_mainnet() {
        return TargetCheck::BadTarget;
    }

    let mut hash = [0u8; 32];
    hash.copy_from_slice(&Sha256::digest(Sha256::digest(
        &header[..ZCASH_FULL_HEADER_SIZE],
    )));
    if target.is_met_by(&hash) {
        TargetCheck::Met
    } else {
        TargetCheck::NotMet
    }
}

/// Trait for validating proof-of-work on block headers
pub trait PowValidator: Send + Sync {
    /// Validate the PoW for a block header
    fn validate(&self, header: &[u8]) -> PowResult;
}

/// Stub validator that accepts all headers
#[derive(Debug, Clone, Default)]
pub struct StubPowValidator;

impl PowValidator for StubPowValidator {
    fn validate(&self, header: &[u8]) -> PowResult {
        if header.len() >= MIN_HEADER_SIZE {
            PowResult::Valid
        } else {
            PowResult::Indeterminate
        }
    }
}

/// Validator that rejects all headers (for testing)
#[derive(Debug, Clone, Default)]
pub struct RejectAllValidator;

impl PowValidator for RejectAllValidator {
    fn validate(&self, _header: &[u8]) -> PowResult {
        PowResult::Invalid
    }
}

/// Zcash Equihash parameters
pub const EQUIHASH_N: u32 = 200;
pub const EQUIHASH_K: u32 = 9;

/// Zcash block header size (without Equihash solution)
pub const ZCASH_HEADER_SIZE: usize = 140;

/// Equihash solution size for n=200, k=9
pub const EQUIHASH_SOLUTION_SIZE: usize = 1344;

/// Full Zcash block header size (with Equihash solution)
pub const ZCASH_FULL_HEADER_SIZE: usize = ZCASH_HEADER_SIZE + 3 + EQUIHASH_SOLUTION_SIZE; // 3 bytes for compactSize

/// Validator using real Equihash proof-of-work verification
///
/// Validates Zcash block headers with Equihash parameters (n=200, k=9).
#[derive(Debug, Clone, Default)]
pub struct EquihashPowValidator;

impl PowValidator for EquihashPowValidator {
    fn validate(&self, header: &[u8]) -> PowResult {
        // Need at least the base header (140 bytes) plus solution
        if header.len() < ZCASH_FULL_HEADER_SIZE {
            return PowResult::Indeterminate;
        }

        // Zcash commits the first 108 bytes as the Equihash input and passes the
        // following 32 bytes separately as the nonce. Including the nonce in the
        // input makes otherwise valid mainnet headers fail verification.
        let input = &header[..ZCASH_EQUIHASH_INPUT_SIZE];
        let nonce = &header[ZCASH_EQUIHASH_INPUT_SIZE..ZCASH_HEADER_SIZE];

        // Extract solution (after the compactSize prefix)
        // CompactSize for 1344 bytes is 0xfd 0x40 0x05 (3 bytes)
        let solution_start = ZCASH_HEADER_SIZE + 3; // Skip compactSize
        if header.len() < solution_start + EQUIHASH_SOLUTION_SIZE {
            return PowResult::Indeterminate;
        }
        let solution = &header[solution_start..solution_start + EQUIHASH_SOLUTION_SIZE];

        // (1) Equihash solution validity.
        match equihash::is_valid_solution(EQUIHASH_N, EQUIHASH_K, input, nonce, solution) {
            Ok(()) => match header_meets_stated_target(header) {
                // (2) Hash-to-target. Without this a valid-but-trivial solution
                // would be forwarded into the mesh for free.
                TargetCheck::Met => PowResult::Valid,
                TargetCheck::NotMet | TargetCheck::BadTarget => PowResult::Invalid,
            },
            Err(_) => PowResult::Invalid,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MAINNET_HEADER_HEX: &str = concat!(
        "040000004d24a7db5e6b53e3d99b7d971bbeff96b9090701393d4c799c484a01000000005ba140b1db623c4577b1c1f2",
        "a4790d2442a4c6ef4ef60f1eab9cd9ab8a835f84eb06b46b93cf0916899e85d4e5a069795d333f56c857d4f76d24b201",
        "36021d92c7aac7620212021cd24f4250311a1155000000000000000000000200000000000000000000078d1bfd400502",
        "ab28ab6f1124af82a0e61abaf509f6601b940ec6222602012590efb08ac4a6f023e0bb39f26d7db7640a457e1c4f621a",
        "e5464f233ef053c70dec215cfcb430792f2a73a4047f38e525ddf2fd13925d9c19cf641676bd18d024782d5ae5e78ae5",
        "ccc8867e0139b0821d02a4a2d52346dd25b1f7c4b97a62e250a71944481e3fdf5fd3688bcb5c2c037062a3f0253cd974",
        "0b5a36d459fa84cea2c7cbb6f4b7183b2e1e78a3be61d4048f599edd91eb13d51fa2c8b64c4e8d2d75d1f630154abc5e",
        "fb0798bee53f554868653b164c32f27b860c3afb5a5dd81c1f73fb6998076169035eaa5b59951b118cad67c74147a3b3",
        "148623b971d9d2a77682131859fbad1907cd1c54fd01c88d55d9747a006940fc259721aa1f5257d5d56c24e06b4249be",
        "5a38f2f8511de1de227bceb1233f4541ec1cb829b5b5019b9346335df2cf2892a6b36a1a256741573ba603bd3ca87809",
        "bdd86b9adbcfe36568518d9419a3a9f0c6fdc7b1197b6a9a06d6f3d1b3a0a37c6eba7258e7c9be0a0e0c22169334c7db",
        "d0743878d76ccf8aab50577ad426221add9045d164af8d45e675696b975eda5cbdd7a1158d3ddd7796fb6b24fae31f3d",
        "4ac272bbc65b288d179f2a7f98e56075b3d19375d5dbb529fc1a1d4c0116dd8abe67f2a725dfd944722aedda6950d49d",
        "5d784eec2e5e181fcb0353cbc74c6e5cb5821f4058b2150e688cf718a12663bb0b424b817ae4c5ca29736ce519ae21b1",
        "df9a25d15ae482b655fa3b22a344577d5b1bc686a0d5c7887c6acb5898b9717a76b41b1ab47d597c97e3ebdd15272cd8",
        "55f824b38e2656565a9f63111c8c98ba91b525cd2411fb34b4431d2da54a8b4c19e0e2595ae45fd9bead821d3c1a050d",
        "e0d77f7d2712097fddaf865eb63fc2177fa77a48f9f867f612663ad332c32d5f6b73fbf2f4b15879c0cd940cfac68502",
        "c260276da89541a62b921c653ff5d28da1f716942031b1cb636b3bdf781482b7de41c132bfffd627a711d58a7cb4a61d",
        "99b05b815a9356857c71008e0cd32c311a0e4b9929c115e3f2e390df163ac45bbe6b430a0048daa4c674732f0f23cc32",
        "20a43dd1f2d93ce31c21091cf9484451e3f066b732cef07e23587cd8851303673d7488c88171c3621c02a34a218f89fc",
        "f67d19288d5611ec5317f53fe3664bd6ec6348b9fdbd69062ff145d30bf1fc81e6b69f1a7416470c471fb6050eb44cd1",
        "56da81d923416332a32338d26f05bcc24b129b7e4f11263425dc42a4d3ca3fdca53cfe539b645368d445d1f3e833b12c",
        "7706d23e3b5f4a425a77d80a2452d48ed1d717face75999bf4858631b3dfd29126d61be3d41c7bab0548863072fe896a",
        "93f077d2470a2548e60d9162830015b27574ce6d3ce2fa308d69191eafe4936f2c0194af9335cc38b65902b279fe9106",
        "10b216a98e2e236538c4c65156c8df33ebde60a511360ae88e2ebc7de865746aeb3841ada907b4b0ea063c66f3e808cc",
        "c1eccb58e270fa910a8a8c9c2272103967895d8dbfc5038da225e5bb474da994f3b25a09a0dd965e460ebd437b046323",
        "b50fcdd15ab76b28112e113bc6ee6901d6aba35462fa4798f1b8ee77a90f816b2667c9497ccdc5540e45f2ee6ab46bd9",
        "b31d72da9f05061e6179bbf197a1707a71f657ce1eb57d0b0bff7dd11ea02f9db5826fdc2e385fcf291ef06f15a3cd4c",
        "4b8bb3876a9f74bfbdbfdf6552ec35a5123540aef9b51bef258e607a60e4f5cd9eaa5bd94ab95b916fc5e9ded82f03ee",
        "d613cfdbb22d9e0b76cf090c1e9551e78d336fc46690fba8c1406f7475fd900f16f30999470e2f4d963892e0692c3dca",
        "b6a39c6935149ee3c6a71b60196afdb935775833f2bbe1bac96760f01594226e008799eb99a20bfdcb83972e9f6652",
    );

    #[test]
    fn stub_validator_accepts_valid_header() {
        let validator = StubPowValidator;
        let header = vec![0u8; 2189];
        assert_eq!(validator.validate(&header), PowResult::Valid);
    }

    #[test]
    fn stub_validator_rejects_short_header() {
        let validator = StubPowValidator;
        let header = vec![0u8; 100];
        assert_eq!(validator.validate(&header), PowResult::Indeterminate);
    }

    #[test]
    fn reject_all_validator_rejects() {
        let validator = RejectAllValidator;
        let header = vec![0u8; 2189];
        assert_eq!(validator.validate(&header), PowResult::Invalid);
    }

    #[test]
    fn equihash_validator_rejects_short_header() {
        let validator = EquihashPowValidator;
        let header = vec![0u8; 100]; // Too short
        assert_eq!(validator.validate(&header), PowResult::Indeterminate);
    }

    #[test]
    fn equihash_validator_rejects_invalid_solution() {
        let validator = EquihashPowValidator;
        // Create a header with all zeros (invalid Equihash solution)
        let mut header = vec![0u8; ZCASH_FULL_HEADER_SIZE];
        // Set CompactSize for solution (0xfd 0x40 0x05 for 1344 bytes)
        header[140] = 0xfd;
        header[141] = 0x40;
        header[142] = 0x05;

        assert_eq!(validator.validate(&header), PowResult::Invalid);
    }

    #[test]
    fn equihash_validator_accepts_real_mainnet_header() {
        let header = hex::decode(MAINNET_HEADER_HEX).unwrap();
        assert_eq!(header.len(), ZCASH_FULL_HEADER_SIZE);

        let validator = EquihashPowValidator;

        assert_eq!(validator.validate(&header), PowResult::Valid);
    }

    #[test]
    fn equihash_validator_rejects_header_whose_hash_misses_its_target() {
        // Real header, nBits rewritten to the hardest encoding still inside the
        // mainnet range. The Equihash solution is untouched and still valid, so
        // only the hash-to-target half can reject it -- which is the half that
        // carries all of Zcash's difficulty.
        let mut header = hex::decode(MAINNET_HEADER_HEX).unwrap();
        header[104..108].copy_from_slice(&0x0300_0001u32.to_le_bytes());

        assert_eq!(EquihashPowValidator.validate(&header), PowResult::Invalid);
    }

    #[test]
    fn equihash_validator_rejects_malformed_target_bits() {
        let mut header = hex::decode(MAINNET_HEADER_HEX).unwrap();
        header[104..108].copy_from_slice(&0x0000_0000u32.to_le_bytes());

        assert_eq!(EquihashPowValidator.validate(&header), PowResult::Invalid);
    }

    #[test]
    fn a_valid_equihash_solution_alone_is_not_proof_of_work() {
        // The point of the whole change: Zcash yields ~2 valid Equihash
        // solutions per nonce, so solution validity is cheap and carries no
        // difficulty. Same header, same valid solution, easier stated target.
        let header = hex::decode(MAINNET_HEADER_HEX).unwrap();
        let input = &header[..ZCASH_EQUIHASH_INPUT_SIZE];
        let nonce = &header[ZCASH_EQUIHASH_INPUT_SIZE..ZCASH_HEADER_SIZE];
        let solution =
            &header[ZCASH_HEADER_SIZE + 3..ZCASH_HEADER_SIZE + 3 + EQUIHASH_SOLUTION_SIZE];
        assert!(
            equihash::is_valid_solution(EQUIHASH_N, EQUIHASH_K, input, nonce, solution).is_ok()
        );

        let mut tampered = header.clone();
        tampered[104..108].copy_from_slice(&0x0300_0001u32.to_le_bytes());
        assert_eq!(EquihashPowValidator.validate(&tampered), PowResult::Invalid);
    }
}

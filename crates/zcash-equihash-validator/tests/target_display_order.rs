//! Regression guard for sovright/mining-infra#103: `parse_target` must turn a
//! big-endian `target` hex string back into the little-endian bytes
//! `compact_to_target` produces.
//!
//! This is a guard, not evidence. The display string is built here by reversing
//! `compact_to_target`'s own bytes, so the test encodes the convention it checks. The
//! evidence that Zebra sends `target` big-endian is Zebra's own template, in
//! zcash-template-provider's `zebra_getblocktemplate_display_order` tests.

use zcash_equihash_validator::compact_to_target;
use zcash_template_provider::parse_target;

#[test]
fn parse_target_inverts_the_big_endian_encoding_of_compact_targets() {
    for bits in [
        0x1c00_a48e_u32,
        0x1f05_5554,
        0x1f07_ffff,
        0x2007_ffff,
        0x1d00_ffff,
    ] {
        let little_endian = compact_to_target(bits).to_le_bytes();
        let mut big_endian = little_endian;
        big_endian.reverse();

        let parsed = parse_target(&hex::encode(big_endian)).expect("valid target hex");
        assert_eq!(parsed.0, little_endian, "nBits {bits:#010x}");
    }
}

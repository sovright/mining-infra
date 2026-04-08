#![no_main]
use libfuzzer_sys::fuzz_target;
use zcash_equihash_validator::Target;

fuzz_target!(|data: &[u8]| {
    if data.len() < 96 {
        return;
    }

    // Extract two targets and a hash from the fuzz input
    let mut a_bytes = [0u8; 32];
    let mut b_bytes = [0u8; 32];
    let mut hash = [0u8; 32];
    a_bytes.copy_from_slice(&data[0..32]);
    b_bytes.copy_from_slice(&data[32..64]);
    hash.copy_from_slice(&data[64..96]);

    let a = Target::from_le_bytes(a_bytes);
    let b = Target::from_le_bytes(b_bytes);

    // Ord must be consistent: if a < b then b > a
    use std::cmp::Ordering;
    let ab = a.cmp(&b);
    let ba = b.cmp(&a);
    match ab {
        Ordering::Less => assert_eq!(ba, Ordering::Greater),
        Ordering::Greater => assert_eq!(ba, Ordering::Less),
        Ordering::Equal => assert_eq!(ba, Ordering::Equal),
    }

    // Transitivity with self
    assert_eq!(a.cmp(&a), Ordering::Equal);
    assert_eq!(b.cmp(&b), Ordering::Equal);

    // is_met_by consistency: if hash meets target a, and a <= b, then hash meets b
    let meets_a = a.is_met_by(&hash);
    let meets_b = b.is_met_by(&hash);
    if meets_a && a >= b {
        // hash <= a and a <= b implies hash <= b (only when a >= b as Target,
        // which means a is a higher/easier target)
    }
    if ab == Ordering::Less && meets_b {
        // a < b (a is harder target). hash <= b doesn't imply hash <= a.
    }
    if ab == Ordering::Greater && meets_a {
        // a > b (a is easier target). hash <= a doesn't imply hash <= b.
    }
    // Key invariant: if a <= b (a is harder) and hash meets a, hash must meet b
    if ab != Ordering::Greater && meets_a {
        assert!(
            meets_b,
            "hash meets harder target a but not easier target b"
        );
    }
});

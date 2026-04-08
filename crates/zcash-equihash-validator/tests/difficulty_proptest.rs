use proptest::prelude::*;
use zcash_equihash_validator::{
    Target, compact_to_target, target_to_difficulty, difficulty_to_target,
};

proptest! {
    #[test]
    fn difficulty_roundtrip(difficulty in 1.0f64..1e15) {
        let target = difficulty_to_target(difficulty);
        let recovered = target_to_difficulty(&target);
        let ratio = recovered / difficulty;
        prop_assert!(
            ratio > 0.99 && ratio < 1.01,
            "roundtrip failed: difficulty={}, recovered={}, ratio={}",
            difficulty, recovered, ratio
        );
    }

    #[test]
    fn difficulty_monotonicity(
        d1 in 1.0f64..1e12,
        d2 in 1.0f64..1e12,
    ) {
        prop_assume!(d1 != d2);
        let t1 = difficulty_to_target(d1);
        let t2 = difficulty_to_target(d2);
        if d1 > d2 {
            prop_assert!(t1 <= t2, "higher difficulty {} should give <= target than {}", d1, d2);
        } else {
            prop_assert!(t1 >= t2, "lower difficulty {} should give >= target than {}", d1, d2);
        }
    }

    #[test]
    fn target_is_met_by_monotonic(
        hash_seed in any::<[u8; 32]>(),
        d1 in 1.0f64..1e9,
        d2 in 1.0f64..1e9,
    ) {
        let t1 = difficulty_to_target(d1);
        let t2 = difficulty_to_target(d2);
        let (harder, easier) = if d1 > d2 { (t1, t2) } else { (t2, t1) };
        if harder.is_met_by(&hash_seed) {
            prop_assert!(
                easier.is_met_by(&hash_seed),
                "hash meeting harder target must meet easier target"
            );
        }
    }

    #[test]
    fn compact_to_target_no_panic(compact in any::<u32>()) {
        let _target = compact_to_target(compact);
    }

    #[test]
    fn target_ord_consistent(a in any::<[u8; 32]>(), b in any::<[u8; 32]>()) {
        let ta = Target::from_le_bytes(a);
        let tb = Target::from_le_bytes(b);
        prop_assert!(ta == ta);
        if ta <= tb && tb <= ta {
            prop_assert_eq!(ta, tb);
        }
    }
}

use proptest::prelude::*;
use zcash_pool_common::{read_compact_size, write_compact_size};

proptest! {
    #[test]
    fn compact_size_roundtrip(value in any::<u64>()) {
        let mut buf = Vec::new();
        write_compact_size(value, &mut buf);
        let mut cursor = 0;
        let decoded = read_compact_size(&buf, &mut cursor).unwrap();
        prop_assert_eq!(value, decoded);
        prop_assert_eq!(cursor, buf.len());
    }

    #[test]
    fn compact_size_encoding_length(value in any::<u64>()) {
        let mut buf = Vec::new();
        write_compact_size(value, &mut buf);
        let expected_len = if value < 0xfd {
            1
        } else if value <= 0xffff {
            3
        } else if value <= 0xffff_ffff {
            5
        } else {
            9
        };
        prop_assert_eq!(buf.len(), expected_len, "value={}", value);
    }

    #[test]
    fn compact_size_truncated_never_succeeds(value in any::<u64>()) {
        let mut buf = Vec::new();
        write_compact_size(value, &mut buf);
        if buf.len() > 1 {
            let truncated = &buf[..buf.len() - 1];
            let mut cursor = 0;
            let result = read_compact_size(truncated, &mut cursor);
            prop_assert!(result.is_err());
        }
    }

    #[test]
    fn compact_size_sequential(values in prop::collection::vec(any::<u64>(), 0..20)) {
        let mut buf = Vec::new();
        for &v in &values {
            write_compact_size(v, &mut buf);
        }
        let mut cursor = 0;
        for &v in &values {
            let decoded = read_compact_size(&buf, &mut cursor).unwrap();
            prop_assert_eq!(v, decoded);
        }
        prop_assert_eq!(cursor, buf.len());
    }
}

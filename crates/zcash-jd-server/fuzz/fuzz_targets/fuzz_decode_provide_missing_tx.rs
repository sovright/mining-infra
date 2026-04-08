#![no_main]
use libfuzzer_sys::fuzz_target;
use zcash_jd_server::decode_provide_missing_transactions;

fuzz_target!(|data: &[u8]| {
    let _ = decode_provide_missing_transactions(data);
});

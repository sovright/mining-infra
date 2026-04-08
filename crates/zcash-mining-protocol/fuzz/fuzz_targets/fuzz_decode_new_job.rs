#![no_main]
use libfuzzer_sys::fuzz_target;
use zcash_mining_protocol::codec::decode_new_equihash_job;

fuzz_target!(|data: &[u8]| {
    let _ = decode_new_equihash_job(data);
});

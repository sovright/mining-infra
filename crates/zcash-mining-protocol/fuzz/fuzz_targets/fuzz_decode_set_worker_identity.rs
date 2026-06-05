#![no_main]
use libfuzzer_sys::fuzz_target;
use zcash_mining_protocol::codec::decode_set_worker_identity;

fuzz_target!(|data: &[u8]| {
    let _ = decode_set_worker_identity(data);
});

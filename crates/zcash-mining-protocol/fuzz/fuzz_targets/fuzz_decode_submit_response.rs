#![no_main]
use libfuzzer_sys::fuzz_target;
use zcash_mining_protocol::codec::decode_submit_shares_response;

fuzz_target!(|data: &[u8]| {
    let _ = decode_submit_shares_response(data);
});

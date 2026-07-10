#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    desertemail::dns::fuzz_parse_response(data);
});

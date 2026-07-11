#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    desertemail::tarball::fuzz_parse_tar(data);
});

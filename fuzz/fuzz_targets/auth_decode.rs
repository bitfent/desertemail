#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let s = String::from_utf8_lossy(data);
    let _ = desertemail::util::base64_decode(&s);
    let _ = desertemail::util::base64_encode(data);
    let _ = desertemail::auth::decode_plain(&s);
    // Password verify should never panic on arbitrary stored/pass strings.
    let _ = desertemail::passwd::verify_password(&s, &s);
});

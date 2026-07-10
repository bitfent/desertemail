// Independent cross-verification: a message signed by Python's dkimpy (a
// known-good, widely-used implementation) MUST verify as Pass through our
// hand-rolled verifier, and a tampered copy MUST NOT. This proves the verifier
// is correct against an external reference — not merely self-consistent with
// our own signer.
//
// The signed message + public key are produced by the harness and passed in via
// env vars DKIM_SIGNED_EML and DKIM_TXT (see the shell driver).

use std::fs;

#[test]
fn dkimpy_signature_verifies() {
    let eml_path = match std::env::var("DKIM_SIGNED_EML") {
        Ok(p) => p,
        Err(_) => {
            eprintln!("skip: DKIM_SIGNED_EML not set");
            return;
        }
    };
    let txt = std::env::var("DKIM_TXT").expect("DKIM_TXT must be set");
    let raw = fs::read(&eml_path).expect("read signed eml");

    let lookup = |_name: &str| Some(txt.clone());
    let results = desertemail::dkim::verify(&raw, &lookup);
    assert!(!results.is_empty(), "no DKIM-Signature parsed");
    assert_eq!(
        results[0].status,
        desertemail::dkim::DkimStatus::Pass,
        "dkimpy signature should verify Pass, got {:?}: {}",
        results[0].status,
        results[0].detail
    );

    // Tamper the body: flip the last non-CRLF byte, expect Fail.
    let mut bad = raw.clone();
    if let Some(pos) = bad.iter().rposition(|&b| b != b'\r' && b != b'\n' && b != b'.') {
        bad[pos] ^= 0x20;
    }
    let bad_results = desertemail::dkim::verify(&bad, &lookup);
    assert_eq!(
        bad_results[0].status,
        desertemail::dkim::DkimStatus::Fail,
        "tampered body should fail DKIM"
    );
}

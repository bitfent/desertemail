# DesertEmail fuzz targets

Parser hardening harnesses for cargo-fuzz / libFuzzer. Requires **nightly** Rust
and `cargo-fuzz`:

```bash
rustup install nightly
cargo install cargo-fuzz
```

## Targets

| Target | Exercises |
|--------|-----------|
| `smtp_line` | SMTP path extraction, Received-header counting, token split |
| `imap_line` | LOGIN args, sequence sets, tag/command split |
| `dns_response` | DNS name compression / answer walk |
| `http_request` | HTTP request + URL/MIME helpers |
| `config_parse` | hand-rolled config TOML-like parser |
| `auth_decode` | base64, AUTH PLAIN decode, password verify |

## Run (example)

```bash
cd /path/to/desertemail

# Build + run one target (default corpus dir under fuzz/corpus/<target>)
cargo +nightly fuzz run smtp_line
cargo +nightly fuzz run imap_line
cargo +nightly fuzz run dns_response
cargo +nightly fuzz run http_request
cargo +nightly fuzz run config_parse
cargo +nightly fuzz run auth_decode

# Optional: limit runtime
cargo +nightly fuzz run smtp_line -- -max_total_time=60
```

If `cargo +nightly fuzz` is unavailable (no nightly, or cargo-fuzz not
installed), the targets still live under `fuzz/fuzz_targets/` and should
compile once the toolchain is present:

```bash
cargo +nightly fuzz build
```

Do **not** expect a long campaign in CI here — these are compile-shaped
harnesses for local hardening work.

## Notes

- Fuzz crate is an isolated workspace (`fuzz/Cargo.toml` has its own
  `[workspace]`) so it does not break the main package.
- Targets must not panic on any input; panics are findings.

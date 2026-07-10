# DesertEmail 🏜️📧

**A truly minimal, from-scratch open-source email server written in pure Rust with ZERO external dependencies.**

Designed to run on the tiniest computers: Raspberry Pi Zero, old netbooks, VPS with 128MB RAM, anything with a public IP (or port-forward + DynDNS).

Anyone can deploy it, configure DNS (or use simple auto-routing), and have their own private email.

## Why DesertEmail?

- **From scratch**: SMTP (receive + submit) and IMAP protocols implemented by hand. No lettre, no mail-parser crates, no heavy frameworks.
- **Zero deps**: Only the Rust standard library. Binary is tiny (~300-500KB stripped). Compiles everywhere.
- **Low resource**: Perfect for always-on home servers. Uses threads (not async) for simplicity and tiny footprint.
- **Open source**: MIT/Apache-2.0. Fork, improve, self-host forever.
- **DNS ready**: Full instructions for MX/A/SPF. Or use the built-in **auto-routing** mode that accepts any address under your domain and maps to local mailboxes (or a catch-all).
- **Maildir storage**: Standard, simple, filesystem-based. Easy to backup, rsync, or even mount remotely.
- **Secure-ish by design**: Passwords (plain for simplicity; hash later), AUTH PLAIN, basic command validation. Add TLS via stunnel/socat or future rustls.

> ⚠️ **This is an educational / personal-use MVP.** Not production-hardened yet (no TLS by default, no DKIM/SPF auto, limited IMAP commands, no spam filter, no rate limiting). Great starting point to learn email protocols and extend!

## Features (v0.1)

- [x] SMTP server (port 25): receive inbound mail from the internet
- [x] SMTP submission (port 587): authenticated clients can send (currently queues or relays via optional smarthost; full MX resolution in pure std is limited)
- [x] IMAP server (port 143): basic clients can LOGIN, SELECT Inbox, FETCH, LIST, etc.
- [x] Maildir storage per user
- [x] Simple TOML-like config (parsed by hand)
- [x] Multi-domain / multi-user
- [x] Catch-all / auto-routing for any@yourdomain
- [x] Logging to stdout
- [ ] STARTTLS / TLS (use external wrapper for now)
- [ ] DKIM signing
- [ ] Full outbound MTA (MX lookup + retry queue) — partial
- [ ] Web admin / simple webmail
- [ ] Let's Encrypt auto

## Quick Start (Raspberry Pi / any Linux)

```bash
# 1. Install Rust (if needed) - https://rustup.rs
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# 2. Clone & build (optimized for size)
git clone https://github.com/yourusername/desertemail
cd desertemail
cargo build --release

# Binary is target/release/desertemail  (~ few hundred KB)

# 3. Create config
cp config.example.toml config.toml
# Edit: set your domain, users, data_dir, ports...

# 4. Run (as root if binding low ports, or use setcap / authbind)
sudo ./target/release/desertemail --config config.toml

# Or without root: change ports to 2525/2587/2143 and use a reverse proxy / port forward.
```

### Systemd service example

See `deploy/desertemail.service`.

## Configuration (config.toml)

```toml
# Domain(s) this server is responsible for
domains = ["example.com", "mail.example.com"]

# Data directory for Maildirs (created automatically)
data_dir = "/var/lib/desertemail"

# Listen addresses (use 0.0.0.0 for all interfaces)
smtp_listen = "0.0.0.0:25"
submission_listen = "0.0.0.0:587"
imap_listen = "0.0.0.0:143"

# Optional: smarthost for outbound (e.g. your ISP or free relay)
# smarthost = "smtp.example.com:587"
# smarthost_user = "user"
# smarthost_pass = "pass"

# Users: local-part or full email -> password (plain for now)
# Auto-routing: if catch_all = true, any unknown local@domain creates/uses a mailbox
[users]
"alice" = "s3cret"
"bob@example.com" = "p@ssw0rd"
"catch-all" = "defaultpass"   # used if catch_all enabled

catch_all = true
```

The parser is hand-written and very simple (key = "value", sections).

## DNS Setup (the "configure with DNS" path)

1. Point an **A (or AAAA)** record for `mail.example.com` → your public IP (use DynDNS like duckdns.org / freedns if dynamic home IP).
2. Add **MX** record for `example.com` → `mail.example.com` (priority 10).
3. (Recommended) SPF: `v=spf1 mx a:mail.example.com ~all` as TXT.
4. (Later) DKIM: generate key, publish TXT.
5. Open ports 25, 587, 143 (and 993/465 for TLS later) in your firewall / router port-forward.

Test with: `swaks --to you@example.com --server your-ip` or real email from Gmail etc.

**Note on residential ISPs**: Many block outbound port 25. Use a cheap VPS ($3/mo) or a smart-host / relay for sending. Receiving usually works if you have public IP + port forward.

## Automatically Generated Routing System

Enable `catch_all = true`. Then:

- Any email to `anything@yourdomain` is accepted and stored in a Maildir named after the local part (auto-created).
- Or force everything to one user: set a default user.
- Perfect for "I just want myname@mydomain without managing users" or disposable-style but permanent storage.
- Future: HTTP endpoint `/register?email=foo@bar.com` that returns a password or just confirms routing.

You can also run multiple instances or use subdomains for isolation.

## Architecture (from scratch)

```
src/
├── main.rs          # CLI, config load, start 3 listeners (SMTP/IMAP/submission)
├── config.rs        # Hand-rolled simple config parser (no serde/toml crate!)
├── storage.rs       # Maildir create/write/list/read (pure std::fs)
├── smtp.rs          # Full SMTP state machine (inbound + auth submission)
├── imap.rs          # Basic IMAP state machine + command handlers
├── auth.rs          # Simple password check + AUTH PLAIN decoder (hand-rolled base64)
└── util.rs          # Line reader, logging helpers, etc.
```

All protocol handling is pure string matching + state machines. No PEG, no external parsers.

Storage is classic Maildir (cur/new/tmp) so any mail client or even `mutt`, `mbsync`, or file browser works.

## Building for Raspberry Pi

Cross-compile or build natively:

```bash
# On Pi itself (recommended for simplicity)
cargo build --release

# Or cross from x86:
# rustup target add aarch64-unknown-linux-gnu
# cargo build --release --target aarch64-unknown-linux-gnu
```

The release profile is size-optimized (`opt-level = "z"`, LTO, strip).

## Extending / Contributing

This is intentionally minimal so you can:

1. Read the SMTP/IMAP RFCs alongside the code.
2. Add STARTTLS (rustls is easy once deps allowed).
3. Add DKIM (implement RSA signing with pure or tiny crypto).
4. Add a tiny webmail with std HTTP (or hyper later).
5. Make full asynchronous with tokio (if you accept the dep).
6. Add proper password hashing (argon2id pure Rust exists).

PRs welcome! Especially:

- Better IMAP (SEARCH, IDLE, APPEND for drafts)
- Outbound queue + exponential backoff + MX (using pure DNS over UDP is fun!)
- Config hot-reload
- Metrics / Prometheus exporter (text)

## License

MIT OR Apache-2.0

## Credits & Inspiration

- edgemail (Piotr Sarna) — disposable SMTP state machine
- Classic Unix maildir + postfix/dovecot architecture, but 1000x simpler
- "Write your own X" philosophy

---

**Deploy it. Own your email. Understand the protocol. Have fun.** 🚀🏜️

Questions? Open an issue. Let's make email fun and decentralized again.

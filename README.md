# DesertEmail 🏜️📧

**A pure-Rust, from-scratch open-source email server. The only dependency is rustls for TLS — because you should never roll your own crypto.**

Designed to run on the tiniest computers: Raspberry Pi Zero, old netbooks, VPS with 128MB RAM, anything with a public IP (or port-forward + DynDNS).

Anyone can deploy it, configure DNS (or use simple auto-routing), and have their own private email.

## Why DesertEmail?

- **From scratch**: SMTP (receive + submit), IMAP, webmail, DKIM, DNS, and HTTP are hand-rolled pure `std`. No lettre, no mail-parser crates, no async runtime (no tokio).
- **TLS via rustls only**: The deliberate exception. Server STARTTLS + implicit SMTPS/IMAPS/HTTPS, and outbound opportunistic STARTTLS with webpki-roots validation. Binary is ~1.2MB stripped with rustls+ring.
- **Low resource**: Perfect for always-on home servers. Uses threads (not async) for simplicity and tiny footprint.
- **Open source**: MIT/Apache-2.0. Fork, improve, self-host forever.
- **DNS ready**: Full instructions for MX/A/SPF. Or use the built-in **auto-routing** mode that accepts any address under your domain and maps to local mailboxes (or a catch-all).
- **Maildir storage**: Standard, simple, filesystem-based. Easy to backup, rsync, or even mount remotely.
- **Secure-ish by design**: Passwords (plain for simplicity; hash later), AUTH PLAIN, basic command validation. Built-in TLS when you supply a cert+key; optional `require_tls_for_auth` rejects AUTH on plaintext (538).

> ⚠️ **This is an educational / personal-use MVP.** Not production-hardened yet (TLS is optional and off until you configure cert/key; plaintext passwords in config; limited IMAP commands; no spam filter; no rate limiting; no ACME auto-cert). Great starting point to learn email protocols and extend!

## Features (v0.2)

- [x] SMTP server (port 25): receive inbound mail from the internet
- [x] SMTP submission (port 587): authenticated clients can send
- [x] IMAP server (port 143): basic clients can LOGIN, SELECT Inbox, FETCH, LIST, etc.
- [x] Maildir storage per user
- [x] Simple TOML-like config (parsed by hand)
- [x] Multi-domain / multi-user
- [x] Catch-all / auto-routing for any@yourdomain
- [x] Logging to stdout
- [x] **Full outbound MTA**: pure-std DNS client (MX/A over UDP), persistent disk queue, exponential backoff (1m→5m→15m→1h→4h), bounces after 24h, optional smarthost relay, opportunistic STARTTLS to remote MX
- [x] **DKIM signing**: from-scratch SHA-256 + bignum RSA (PKCS#1 v1.5), relaxed/relaxed canonicalization, `--dkim-dns` prints the TXT record to publish (verified against dkimpy)
- [x] **Webmail + admin UI**: pure-std HTTP server with session login — inbox, read, compose, sent; admin page shows domains/users and lets you inspect/delete the outbound queue; optional HTTPS (`web_tls_listen`) sets Secure cookies
- [x] **STARTTLS / TLS** via rustls: STARTTLS on 25/587 (RFC 3207) and 143 (RFC 2595); implicit SMTPS (465), IMAPS (993), HTTPS webmail; supply `tls_cert_file` + `tls_key_file`
- [ ] Let's Encrypt auto (bring your own cert via certbot/acme.sh, or terminate TLS on a reverse proxy)

## Quick Start (Raspberry Pi / any Linux)

```bash
# 1. Install Rust (if needed) - https://rustup.rs
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# 2. Clone & build (optimized for size)
git clone https://github.com/yourusername/desertemail
cd desertemail
cargo build --release

# Binary is target/release/desertemail  (~1.2 MB with rustls)

# 3. Create config
cp config.example.toml config.toml
# Edit: set your domain, users, data_dir, ports...

# 4. (Recommended for anything not pure LAN) enable TLS
openssl req -x509 -newkey rsa:2048 -nodes -days 365 \
  -subj "/CN=mail.example.com" -keyout tls.key -out tls.crt
# Then in config.toml set tls_cert_file / tls_key_file and optional
# smtps_listen / imaps_listen / web_tls_listen (see config.example.toml).

# 5. Run (as root if binding low ports, or use setcap / authbind)
sudo ./target/release/desertemail --config config.toml

# Or without root: change ports to 2525/2587/2143 and use a reverse proxy / port forward.
```

Without `tls_cert_file` + `tls_key_file`, the server runs plaintext (fine for localhost/LAN/VPN). With both set, STARTTLS is advertised on the plaintext SMTP/IMAP ports and optional implicit-TLS listeners bind when non-empty.

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

# Webmail / admin UI (empty string disables)
web_listen = "0.0.0.0:8080"
# admin_user = "alice"   # user allowed on /admin (unset = admin disabled)

# Optional: smarthost for outbound (e.g. your ISP or free relay).
# When unset, mail is delivered directly via MX lookup.
# smarthost = "smtp.example.com:587"
# smarthost_user = "user"
# smarthost_pass = "pass"

# DKIM signing of outbound mail (recommended for deliverability)
# dkim_selector = "mail"
# dkim_key_file = "/etc/desertemail/dkim.pem"

# --- TLS (optional; both cert + key required to enable) ---
# tls_cert_file = "/etc/desertemail/tls.crt"
# tls_key_file = "/etc/desertemail/tls.key"
# smtps_listen = "0.0.0.0:465"      # implicit SMTPS
# imaps_listen = "0.0.0.0:993"      # implicit IMAPS
# web_tls_listen = "0.0.0.0:8443"   # HTTPS webmail
# require_tls_for_auth = false      # true => reject AUTH on plaintext (538)

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
4. (Recommended) DKIM:
   ```bash
   openssl genrsa -out dkim.pem 2048
   # set dkim_key_file = "dkim.pem" in config.toml, then:
   ./desertemail --dkim-dns example.com
   # publishes instructions: TXT at mail._domainkey.example.com
   ```
5. Open ports 25, 587, 143, and (with TLS configured) 465 / 993 / 8443 as needed in your firewall / router port-forward.

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
├── main.rs          # CLI, config load, start listeners (SMTP/IMAP/submission/web + TLS)
├── config.rs        # Hand-rolled simple config parser (no serde/toml crate!)
├── storage.rs       # Maildir create/write/list/read (pure std::fs)
├── smtp.rs          # Full SMTP state machine (inbound + auth submission + STARTTLS)
├── imap.rs          # Basic IMAP state machine + STARTTLS (RFC 2595)
├── auth.rs          # Simple password check + AUTH PLAIN decoder (hand-rolled base64)
├── dns.rs           # DNS client over UDP: MX/A/AAAA, name compression (pure std)
├── queue.rs         # Outbound queue: disk persistence, retries/backoff, opportunistic STARTTLS
├── crypto.rs        # SHA-256, bignum RSA (PKCS#1 v1.5), PEM/DER key parsing
├── dkim.rs          # DKIM signing: relaxed/relaxed canonicalization (RFC 6376)
├── web.rs           # Webmail + admin: HTTP/1.1 (+ optional HTTPS), sessions, HTML
├── tls.rs           # rustls: server Conn, client ClientConn, PEM load, webpki-roots
└── util.rs          # Line reader, base64, RFC 2822 dates, logging
```

Mail, IMAP, webmail, DKIM, DNS, and HTTP protocol handling is pure string matching + state machines (no PEG, no external parsers). **Only TLS** uses crates: `rustls` (ring), `rustls-pemfile`, `webpki-roots`.

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

The release profile is size-optimized (`opt-level = "z"`, LTO, strip). With rustls+ring the binary is roughly **~1.2 MB**.

## Hardening roadmap (MVP → production self-hostable)

DesertEmail is an educational / personal-use MVP today. The gap to a hardened,
internet-facing mail server is tracked below, in priority order. **We intend to
work through these as soon as possible.** Until Tier 1 is done, run it only on a
LAN, over a VPN/Tailscale, or behind a TLS-terminating proxy — not on the open
internet with real credentials.

**Guiding principle:** keep the core hand-rolled and small, but shell out to
battle-tested tools where rolling our own is a bad trade (spam filtering, TLS
cert issuance). Treat a security audit + fuzzing of the hand-rolled parsers as a
hard gate before pointing MX at it.

### Tier 1 — Security must-haves (block public exposure on these)
- [ ] **Password hashing** — stop storing plaintext passwords in `config.toml`; use argon2id (verify against a hash).
- [ ] **Fix the auth model** — `catch_all = true` + `default_password` currently lets *any* username authenticate with the default password. Require real per-user credentials; make insecure defaults (`default_password`, `catch_all = true`) opt-in.
- [ ] **Rate limiting / brute-force lockout** on SMTP AUTH, IMAP LOGIN, and webmail login.
- [ ] **Connection limits** — cap concurrent connections (global + per-IP) and enforce idle timeouts; thread-per-connection is unbounded today (DoS/slowloris risk).
- [ ] **Parser hardening** — sweep hand-rolled parsers for `unwrap`/indexing/overflow (a panic in a handler is a remote DoS), then `cargo-fuzz` SMTP/IMAP/DNS/MIME/config.
- [ ] **Relay/loop/abuse audit** — prove port 25 only accepts local domains (not an open relay), add a max-Received-hops loop guard, throttle outbound so a compromised account can't become a spam cannon.

### Tier 2 — Inbound trust & deliverability (needed for real-world mail)
- [ ] **Inbound SPF check, DKIM verify, DMARC evaluation** (we sign outbound DKIM but accept anything inbound today).
- [ ] **Greylisting + blocklist (RBL) lookups**; spam scoring (consider integrating rspamd rather than hand-rolling).
- [ ] **Deliverability ops** — rDNS/PTR, MTA-STS, TLS-RPT, IP warm-up (SPF/DKIM publishing already supported).

### Tier 3 — Protocol completeness & reliability
- [ ] **IMAP gaps** — `SEARCH` (currently errors), `IDLE` (push; mobile clients need it), `APPEND`, robust flag/UID persistence.
- [ ] **ACME / Let's Encrypt** auto-issue + renewal (certs are BYO today).
- [ ] **Graceful shutdown** (drain connections + flush queue on SIGTERM), **per-user quotas**, **structured logs** (fail2ban-friendly).

### Tier 4 — Assurance & ops
- [ ] Security audit sign-off + load testing.
- [ ] Backup/restore docs, monitoring, alerting.
- [ ] User management without editing config + restart (add/remove users; optional web admin CRUD).

## Extending / Contributing

This is intentionally minimal so you can read the SMTP/IMAP/DKIM RFCs alongside
the code and extend it. See the hardening roadmap above for the highest-value
work; PRs welcome, Tier 1 especially.

## License

MIT OR Apache-2.0

## Credits & Inspiration

- edgemail (Piotr Sarna) — disposable SMTP state machine
- Classic Unix maildir + postfix/dovecot architecture, but 1000x simpler
- "Write your own X" philosophy

---

**Deploy it. Own your email. Understand the protocol. Have fun.** 🚀🏜️

Questions? Open an issue. Let's make email fun and decentralized again.

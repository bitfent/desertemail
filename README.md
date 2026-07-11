# DesertEmail 🏜️📧

**A pure-Rust, from-scratch open-source email server. The only dependency is rustls for TLS — because you should never roll your own crypto.**

Designed to run on the tiniest computers: Raspberry Pi Zero, old netbooks, VPS with 128MB RAM, anything with a public IP (or port-forward + DynDNS).

Anyone can deploy it, configure DNS (or use simple auto-routing), and have their own private email.

**Installer vs doctor:** the installer (or a manual `config.toml`) sets up the **software**. `desertemail doctor` verifies the **environment** — DNS, ports, rDNS, TLS, and config sanity — so mail actually delivers. Run doctor after DNS setup and before you announce the address.

## Why DesertEmail?

- **From scratch**: SMTP (receive + submit), IMAP, webmail, DKIM, DNS, and HTTP are hand-rolled pure `std`. No lettre, no mail-parser crates, no async runtime (no tokio).
- **TLS via rustls only**: The deliberate exception. Server STARTTLS + implicit SMTPS/IMAPS/HTTPS, and outbound opportunistic STARTTLS with webpki-roots validation. Binary is ~1.2MB stripped with rustls+ring.
- **Low resource**: Perfect for always-on home servers. Uses threads (not async) for simplicity and tiny footprint.
- **Open source**: MIT/Apache-2.0. Fork, improve, self-host forever.
- **DNS ready**: Full instructions for MX/A/SPF. Or use the built-in **auto-routing** mode that accepts any address under your domain and maps to local mailboxes (or a catch-all).
- **Maildir storage**: Standard, simple, filesystem-based. Easy to backup, rsync, or even mount remotely.
- **Secure-ish by design**: PBKDF2-HMAC-SHA256 password hashes (`desertemail --hash-password`), AUTH PLAIN, auth lockout, connection limits, basic command validation. Built-in TLS when you supply a cert+key; optional `require_tls_for_auth` rejects AUTH on plaintext (538).

> ⚠️ **This is an educational / personal-use MVP.** Tiers 1–4 are largely in tree (auth lockout, SPF/DKIM/DMARC, IMAP SEARCH/IDLE/APPEND/STORE/EXPUNGE, optional ACME, quotas, structured logs, user CLI/admin CRUD, health/metrics, backup helper) but TLS/ACME still need correct DNS + port 80 for issuance; no full Bayesian/ML spam filter. Great starting point to learn email protocols and extend!

## Features (v0.2)

- [x] SMTP server (port 25): receive inbound mail from the internet
- [x] SMTP submission (port 587): authenticated clients can send
- [x] IMAP server (port 143): LOGIN, SELECT, LIST, FETCH, SEARCH, STORE, EXPUNGE, CLOSE, APPEND, IDLE, UID variants
- [x] Maildir storage per user
- [x] Simple TOML-like config (parsed by hand)
- [x] Multi-domain / multi-user
- [x] Catch-all / auto-routing for any@yourdomain
- [x] Logging to stdout
- [x] **Full outbound MTA**: pure-std DNS client (MX/A over UDP), persistent disk queue, exponential backoff (1m→5m→15m→1h→4h), bounces after 24h, optional smarthost relay, opportunistic STARTTLS to remote MX
- [x] **DKIM signing**: from-scratch SHA-256 + bignum RSA (PKCS#1 v1.5), relaxed/relaxed canonicalization, `--dkim-dns` prints the TXT record to publish (verified against dkimpy)
- [x] **Webmail + admin UI**: pure-std HTTP server with session login — inbox, read, compose, sent; admin page shows domains/users and lets you inspect/delete the outbound queue; optional HTTPS (`web_tls_listen`) sets Secure cookies
- [x] **STARTTLS / TLS** via rustls: STARTTLS on 25/587 (RFC 3207) and 143 (RFC 2595); implicit SMTPS (465), IMAPS (993), HTTPS webmail; supply `tls_cert_file` + `tls_key_file`
- [x] **ACME / Let's Encrypt** (optional `acme = true`): HTTP-01 via webmail, RS256 JWS, background renew when &lt;30d remain — needs public domain + port 80
- [x] **Quotas**, **structured JSON logs** (fail2ban filter in `deploy/`), **graceful SIGTERM/SIGINT**
- [x] **Ops**: `user` CLI + admin CRUD (live user map reload), `/healthz` + Prometheus `/metrics`, `deploy/backup.sh`, loadtest script
- [x] **`desertemail doctor`**: deployment readiness probe (DNS MX/A/SPF/DKIM/DMARC/rDNS, outbound :25, inbound :25/:587/:143, port 80 for ACME, TLS expiry/SAN, config sanity). **Headline check: DKIM published TXT `p=` vs local key** — catches the #1 silent deliverability failure (wrong or stale DKIM record)

## Quick Start (Raspberry Pi / any Linux)

```bash
# 1. Install Rust (if needed) - https://rustup.rs
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# 2. Clone & build (optimized for size)
git clone https://github.com/bitfent/desertemail
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

### Verify your setup (`desertemail doctor`)

After config + DNS (MX/SPF/DKIM/DMARC/rDNS) and before you go live, run the readiness probe:

```bash
desertemail doctor
# or, if config/domain need overriding:
desertemail doctor --config config.toml --domain example.com
desertemail doctor --host mail.example.com --public-ip 203.0.113.10
```

Doctor prints a green/red report grouped as **Config / DNS / Network / TLS**. Each failed or warned check can include a `→ fix:` line. The process exits with code = number of **blockers** (Fail checks); `0` means ready (warnings are allowed). Flags: `--config`, `--domain`, `--host`, `--public-ip`, `--json`, `--no-net` (DNS-only, skip TCP probes).

Sample (trimmed):

```text
DesertEmail doctor — deployment readiness
  host=mail.example.com  public_ip=203.0.113.10  egress=203.0.113.10

── DNS ──
  ✓ MX example.com — top=mail.example.com pref=10; A includes 203.0.113.10
  ✓ SPF example.com — v=spf1 mx a -all (policy -all (hard fail))
  ✗ DKIM example.com (s=mail) — p= mismatch at mail._domainkey.example.com
      → fix: Update TXT at mail._domainkey.example.com to exactly:
  ⚠ DMARC example.com — no v=DMARC1 TXT at _dmarc.example.com
      → fix: Publish TXT at _dmarc.example.com: v=DMARC1; p=none; ...
── Network ──
  ✓ outbound port 25 — connected to 142.251.x.x:25 (via gmail-smtp-in.l.google.com)
── TLS ──
  ⚠ TLS certificate — plaintext only — fine for LAN, not for public internet

VERDICT: 1 blocker(s), 2 warning(s)
Not ready: fix the red items
```

The DKIM check compares the published `p=` at `<selector>._domainkey.<domain>` to the local key from `dkim_key_file` — that mismatch is the classic “everything looks published but receivers still fail DKIM” bug. PTR/rDNS is set in your **hosting provider’s** panel (not domain DNS).

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

# Mail routing: accept any local-part@domain (does NOT grant authentication)
catch_all = true
# default_password is only used when allow_default_password_auth = true (keep false)
default_password = "changeme"
allow_default_password_auth = false

# Auth brute-force lockout (SMTP AUTH / IMAP LOGIN / webmail)
auth_max_failures = 10
auth_window_secs = 300
auth_lockout_secs = 900

# Connection limits + idle timeouts (DoS / slowloris)
max_connections = 512
max_connections_per_ip = 20
io_timeout_secs = 120

# Relay / loop / abuse
max_received_hops = 30              # inbound DATA with more Received: => 554
outbound_max_rcpts_per_hour = 200   # per authenticated submission user

# Inbound trust (Tier 2) — evaluate + annotate always; reject only if enabled
spf_enforce = false                 # true: SPF Fail + DMARC reject => 550
dmarc_enforce = false               # true: honor p=reject / p=quarantine
greylist = false                    # true: 451 first (ip/24,from,rcpt) sight
greylist_delay_secs = 60
greylist_ttl_secs = 2592000         # 30 days whitelist after success
dnsbls = []                         # e.g. ["zen.spamhaus.org"]
dnsbl_reject = false
spam_score_tag = 5                  # >= tag => X-Spam-Flag: YES
spam_score_reject = 0               # 0 = reject disabled
spam_check_ptr = true

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

# Quotas (0 = unlimited). Inbound over-quota => SMTP 452; IMAP APPEND => NO [OVERQUOTA]
default_quota_mb = 0
# [quotas]
# "alice" = 512

# Logging: "text" (default) or "json" (one object per line; event=auth_fail for fail2ban)
log_format = "text"

# ACME auto-cert (optional). Port 80 / web_listen must serve HTTP-01.
# Test staging first: acme_directory = "https://acme-staging-v02.api.letsencrypt.org/directory"
acme = false
# acme_email = "admin@example.com"
# acme_domains = ["mail.example.com"]
# tls_cert_file / tls_key_file are the paths ACME writes (and TLS loads)

# Max message size (SMTP DATA / IMAP APPEND); oversize => 552 / NO
max_message_bytes = 26214400
# Optional: gate GET /metrics with Bearer token or ?token=
# metrics_token = "change-me"

# Users: local-part or full email -> password or PBKDF2 hash
# Generate: desertemail --hash-password
#   "alice" = "pbkdf2_sha256$210000$....$...."
# Plaintext still works (migration) but logs a startup WARNING.
# Or manage without editing by hand:
#   desertemail user add alice --password secret
#   desertemail user list / remove / passwd
[users]
"alice" = "s3cret"
"bob@example.com" = "p@ssw0rd"
```

The parser is hand-written and very simple (key = "value", sections).

**Passwords:** prefer hashes from `desertemail --hash-password` (or
`desertemail --hash-password 'secret'` for scripts). Format:
`pbkdf2_sha256$<iters>$<salt_b64>$<hash_b64>` (PBKDF2-HMAC-SHA256, 210k iters).

### User management (no hand-edit)

```bash
desertemail --config config.toml user add alice@example.com          # prompts for password
desertemail --config config.toml user add bob --password secret --quota 512
desertemail --config config.toml user list
desertemail --config config.toml user passwd alice
desertemail --config config.toml user remove bob
```

These rewrite only the `[users]` / `[quotas]` blocks in place (atomic temp+rename).
The running server also reloads users/quotas live when you use the admin web UI
(forms on `/admin` for `admin_user`).

### Health & metrics

- `GET /healthz` — liveness (`200 ok`, no auth)
- `GET /metrics` — Prometheus text counters (connections, auth, messages, greylist/spam, queue depth). Optional `metrics_token`.

Sample scrape:

```yaml
# prometheus.yml
scrape_configs:
  - job_name: desertemail
    static_configs:
      - targets: ["mail.example.com:8080"]
    # metrics_path: /metrics
    # authorization: { credentials: "change-me" }   # if metrics_token set
```

### Backup

```bash
./deploy/backup.sh /var/lib/desertemail /var/backups/desertemail
# with extras:
CONFIG=/etc/desertemail/config.toml DKIM=/etc/desertemail/dkim.pem \
  TLS_CERT=/etc/desertemail/tls.crt TLS_KEY=/etc/desertemail/tls.key \
  ./deploy/backup.sh /var/lib/desertemail /var/backups/desertemail
```

See the script header for restore notes and the live-rsync consistency caveat.

## DNS Setup (the "configure with DNS" path)

1. Point an **A (or AAAA)** record for `mail.example.com` → your public IP (use DynDNS like duckdns.org / freedns if dynamic home IP).
2. Add **MX** record for `example.com` → `mail.example.com` (priority 10).
3. **SPF** (TXT on the apex): e.g. `v=spf1 mx a:mail.example.com ~all`.
4. **DKIM**:
   ```bash
   openssl genrsa -out dkim.pem 2048
   # set dkim_key_file = "dkim.pem" in config.toml, then:
   ./desertemail --dkim-dns example.com
   # publish the printed TXT at mail._domainkey.example.com
   ```
5. **DMARC** (TXT at `_dmarc.example.com`): start with
   `v=DMARC1; p=none; rua=mailto:dmarc@example.com` then move to `p=quarantine` / `p=reject` after monitoring.
6. **rDNS / PTR**: ask your VPS/host to set reverse DNS for your public IP to your mail hostname (e.g. `mail.example.com`). Many receivers require PTR that matches a forward A/AAAA. Home ISPs rarely allow this.
7. **MTA-STS** (optional): TXT at `_mta-sts.example.com` with `v=STSv1; id=YYYYMMDD01`, plus a policy file at
   `https://mta-sts.example.com/.well-known/mta-sts.txt`. DesertEmail does **not** serve that policy file — host it on the webmail HTTPS vhost or any static HTTPS host.
8. **TLS-RPT** (optional): TXT at `_smtp._tls.example.com` —
   `v=TLSRPTv1; rua=mailto:tlsrpt@example.com`.
9. Open ports 25, 587, 143, and (with TLS configured) 465 / 993 / 8443 as needed in your firewall / router port-forward.
10. **Verify**: `desertemail doctor` (or `desertemail doctor --domain example.com`) — green/red report; exit code = blocker count. See [Verify your setup](#verify-your-setup-desertemail-doctor).

### Why my mail goes to spam (checklist)

`desertemail doctor` automates most of these checks (MX/A/SPF/DKIM-match/DMARC/rDNS/FCrDNS, outbound :25, inbound ports, TLS expiry/SAN, config sanity). Fix its blockers first, then:

- [ ] SPF, DKIM, and DMARC all published and consistent (same domain alignment)
- [ ] PTR/rDNS set to your mail hostname and forward-confirms (FCrDNS)
- [ ] Not sending from a residential/shared IP with bad reputation (use a VPS or smarthost)
- [ ] TLS on submission; valid cert for the EHLO/hostname when possible
- [ ] Warm up a new IP gradually; avoid spammy content and purchased lists
- [ ] Check that your IP is not on major DNSBLs before going live

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
├── main.rs          # CLI, config load, listeners, graceful shutdown, ACME start
├── lib.rs           # Library root (shared with cargo-fuzz targets)
├── config.rs        # Hand-rolled simple config parser (no serde/toml crate!)
├── storage.rs       # Maildir create/write/list/flags/quota (pure std::fs)
├── smtp.rs          # Full SMTP state machine (inbound + auth submission + STARTTLS)
├── imap.rs          # IMAP4rev1 subset: SEARCH/IDLE/APPEND/STORE/EXPUNGE/UID + STARTTLS
├── acme.rs          # ACME v2 client (RS256 JWS, HTTP-01, PKCS#10 CSR)
├── shutdown.rs      # SIGTERM/SIGINT (unix) / console Ctrl-C (windows)
├── auth.rs          # AUTH PLAIN decoder + authenticate()
├── passwd.rs        # PBKDF2-HMAC-SHA256 password hashing (from crypto::sha256)
├── ratelimit.rs     # Auth brute-force lockout + outbound rcpt throttle
├── limits.rs        # Global/per-IP connection caps + I/O timeouts
├── dns.rs           # DNS client over UDP: MX/A/AAAA/TXT/PTR, name compression (pure std)
├── queue.rs         # Outbound queue: disk persistence, retries/backoff, opportunistic STARTTLS
├── crypto.rs        # SHA-256, bignum RSA (PKCS#1 v1.5 sign+verify), PEM/DER, CSR
├── dkim.rs          # DKIM sign + verify: shared relaxed/relaxed canonicalization (RFC 6376)
├── spf.rs           # Inbound SPF evaluation (RFC 7208 core subset)
├── dmarc.rs         # DMARC evaluation + alignment (RFC 7489 core)
├── spamscore.rs     # Greylisting, DNSBL, lightweight additive spam score
├── web.rs           # Webmail + admin CRUD + /healthz + /metrics + ACME HTTP-01
├── useredit.rs      # Safe in-place [users]/[quotas] config editor
├── metrics.rs       # Prometheus text counters
├── tls.rs           # rustls: server Conn, client ClientConn, PEM load, webpki-roots
├── doctor.rs        # `desertemail doctor` — DNS/ports/rDNS/TLS/config readiness probe
└── util.rs          # Line reader, base64url, structured logging (text/json)
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
- [x] **Password hashing** — PBKDF2-HMAC-SHA256 hashes (`desertemail --hash-password`); plaintext configs still work but warn at startup.
- [x] **Fix the auth model** — `catch_all = true` + `default_password` currently lets *any* username authenticate with the default password. Require real per-user credentials; make insecure defaults (`default_password`, `catch_all = true`) opt-in.
- [x] **Rate limiting / brute-force lockout** on SMTP AUTH, IMAP LOGIN, and webmail login.
- [x] **Connection limits** — cap concurrent connections (global + per-IP) and enforce idle timeouts; thread-per-connection is unbounded today (DoS/slowloris risk).
- [x] **Parser hardening** — sweep hand-rolled parsers for `unwrap`/indexing/overflow (a panic in a handler is a remote DoS), then `cargo-fuzz` SMTP/IMAP/DNS/MIME/config.
- [x] **Relay/loop/abuse audit** — prove port 25 only accepts local domains (not an open relay), add a max-Received-hops loop guard, throttle outbound so a compromised account can't become a spam cannon.

### Tier 2 — Inbound trust & deliverability (needed for real-world mail)
- [x] **Inbound SPF check, DKIM verify, DMARC evaluation** (we sign outbound DKIM but accept anything inbound today).
- [x] **Greylisting + blocklist (RBL) lookups**; spam scoring (consider integrating rspamd rather than hand-rolling).
- [x] **Deliverability ops** — rDNS/PTR, MTA-STS, TLS-RPT, IP warm-up (SPF/DKIM publishing already supported).

### Tier 3 — Protocol completeness & reliability
- [x] **IMAP gaps** — `SEARCH` (currently errors), `IDLE` (push; mobile clients need it), `APPEND`, robust flag/UID persistence.
- [x] **ACME / Let's Encrypt** auto-issue + renewal (certs are BYO today).
- [x] **Graceful shutdown** (drain connections + flush queue on SIGTERM), **per-user quotas**, **structured logs** (fail2ban-friendly).

### Tier 4 — Assurance & ops
- [x] Security audit sign-off + load testing.
- [x] Backup/restore docs, monitoring, alerting.
- [x] User management without editing config + restart (add/remove users; optional web admin CRUD).

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

# Deploying DesertEmail (binaries + install site)

Operator guide. Binaries are **not** published to GitHub Releases and there is
**no GitHub Actions / CI**. The maintainer builds every target **locally** with
one script (`build-binaries.sh`) and commits them into `bin-dist/`; Render runs
`site-build.sh` and serves them under `/bin/` next to the per-platform
installers.

**TLS note:** release binaries include rustls-based TLS (STARTTLS + optional
implicit SMTPS/IMAPS/HTTPS) **and built-in ACME (Let's Encrypt HTTP-01)**.
Operators either enable ACME (`acme = true`, via the `/dns` web page or
`desertemail setup https`) or supply their own `tls_cert_file` /
`tls_key_file` in `config.toml` (self-signed, certbot/acme.sh, etc.). No
behavior change to the install/site pipeline — installers and `site-build.sh`
are unchanged.

## (a) Build ALL binaries locally into `bin-dist/` — no GitHub, no cloud

`build-binaries.sh` builds every target on one machine (a Mac):

- **macOS** (aarch64 + x86_64) natively via `cargo`.
- **Linux musl** (x86_64, aarch64, armv7, armv6) and **Windows** via
  [`cargo-zigbuild`](https://github.com/rust-cross/cargo-zigbuild), which uses
  **Zig** as the cross-compiler/linker — no Docker daemon, no CI.

macOS binaries can only be built on macOS, so a Mac is the natural build host
(it produces all the others too).

### One-time setup

```bash
brew install zig                 # or https://ziglang.org/download/
cargo install cargo-zigbuild
rustup target add \
  x86_64-unknown-linux-musl aarch64-unknown-linux-musl \
  armv7-unknown-linux-musleabihf arm-unknown-linux-musleabihf \
  x86_64-pc-windows-gnu \
  x86_64-apple-darwin aarch64-apple-darwin
```

### Build + publish

```bash
sh build-binaries.sh             # all 7 binaries -> bin-dist/
git add bin-dist
git commit -m "release binaries"
git push                         # Render redeploys, serves them under /bin/
```

Produced (names must match the installers exactly):

```text
desertemail-x86_64-unknown-linux-musl
desertemail-aarch64-unknown-linux-musl
desertemail-armv7-unknown-linux-musleabihf
desertemail-arm-unknown-linux-musleabihf        # ARMv6 (Pi Zero / Pi 1)
desertemail-x86_64-apple-darwin
desertemail-aarch64-apple-darwin
desertemail-x86_64-pc-windows-msvc.exe          # built via windows-gnu; runs on stock Windows
```

Notes:
- The Windows `.exe` is cross-built with the `windows-gnu` toolchain (self-contained,
  runs on stock Windows) but named `...-msvc.exe` to match the installer's expected
  asset name.
- `site-build.sh` regenerates `site/bin/SHA256SUMS` from whatever is in `bin-dist/`
  — do not hand-maintain checksums under `site/`.
- No Rust toolchain, `cross`, Docker, or CI is required on Render — it only copies
  the committed binaries and stamps the installers.

## (b) Host the landing page + installers on Render

1. Ensure `render.yaml` is on the default branch.
2. Render dashboard → **New** → **Blueprint** → select this repo → apply.
3. Set env var **`SITE_BASE_URL`** to your public origin (e.g.
   `https://desertemail.onrender.com`) if `RENDER_EXTERNAL_URL` is not injected
   for static sites on your plan. Installers embed this origin so
   `curl|sh` downloads `${SITE_BASE_URL}/bin/desertemail-<target>`.
4. Service `desertemail-site` runs `sh site-build.sh` and publishes `site/`:
   - `site/index.html` — platform picker landing page
   - `site/install-<platform>.sh` — generated from `installers/template.sh`
   - `site/install-windows.ps1` — generated from `installers/install-windows.ps1`
   - `site/install-from-source.sh` — copy of `installers/build-from-source.sh`
   - `site/bin/*` + `site/bin/SHA256SUMS` — from `bin-dist/` when present

Each `/install-*.sh` and `/install-windows.ps1` path is served as `text/plain`.

## (c) User install

After the static site is live, open the landing page and pick a platform. Each
button shows an install command like:

```bash
# Linux / macOS / Android (Termux)
curl -fsSL https://<your-render-host>/install-linux-x86_64.sh | sh

# Windows (PowerShell)
irm https://<your-render-host>/install-windows.ps1 | iex
# if execution policy blocks scripts:
powershell -ExecutionPolicy Bypass -c "irm https://<your-render-host>/install-windows.ps1 | iex"
```

Supported installer names:

| Button                    | Script                              | Binary target                         |
|---------------------------|-------------------------------------|---------------------------------------|
| Linux x86_64              | `/install-linux-x86_64.sh`          | `x86_64-unknown-linux-musl`           |
| Linux ARM64               | `/install-linux-arm64.sh`           | `aarch64-unknown-linux-musl`          |
| Linux ARMv7               | `/install-linux-armv7.sh`           | `armv7-unknown-linux-musleabihf`      |
| Linux ARMv6 (Pi Zero)     | `/install-linux-armv6.sh`           | `arm-unknown-linux-musleabihf`        |
| macOS Apple Silicon       | `/install-macos-apple-silicon.sh`   | `aarch64-apple-darwin`                |
| macOS Intel               | `/install-macos-intel.sh`           | `x86_64-apple-darwin`                 |
| Windows (PowerShell)      | `/install-windows.ps1`              | `x86_64-pc-windows-msvc` (`.exe`)     |
| Android (Termux)          | same as Linux ARM64                 | `aarch64-unknown-linux-musl`          |
| Build from source         | `/install-from-source.sh`           | (local `cargo build --release`)       |

**Android (Termux):** static musl ARM64 binaries run unmodified under Termux.
Install Termux from F-Droid, run `pkg install curl openssl`, then use the
Linux ARM64 one-liner. No root is needed when using the high-port set
(2525/2587/2143).

Headless / CI (example for Linux x86_64):

```bash
curl -fsSL https://<your-render-host>/install-linux-x86_64.sh \
  | DESERTEMAIL_NONINTERACTIVE=1 sh
```

Optional env overrides: `DESERTEMAIL_PREFIX`, `DESERTEMAIL_DOMAIN`,
`DESERTEMAIL_ADMIN_USER`, `DESERTEMAIL_ADMIN_PASSWORD`, `DESERTEMAIL_DATA_DIR`,
`DESERTEMAIL_WEBMAIL`, `DESERTEMAIL_PORTS`, `DESERTEMAIL_DKIM`,
`DESERTEMAIL_SYSTEMD` (POSIX installers only; Windows has no systemd).

There is **no** platform auto-detection and **no** GitHub Releases/API in the
install path. Users choose their installer; binaries and `SHA256SUMS` come from
this site under `/bin/`.

### Verify with doctor

After install and DNS (MX/SPF/DKIM/DMARC/rDNS), **before announcing the address**,
run the readiness probe:

```bash
desertemail doctor
# or:
desertemail doctor --config /etc/desertemail/config.toml --domain example.com
```

Exit code = number of Fail blockers (`0` = ready). Doctor checks config sanity,
DNS (including DKIM published `p=` vs local key), outbound/inbound ports, and
TLS cert expiry/SAN. PTR/rDNS is set in the hosting provider panel, not domain
DNS. See README and the site docs section “Readiness check (doctor)”.

## Local-dev loop

```bash
# from repo root
SITE_BASE_URL=http://127.0.0.1:4173 sh site-build.sh

# serve the publish tree (any static server)
cd site && python3 -m http.server 4173
```

Open `http://127.0.0.1:4173/`. The picker fills origin automatically. If you put
binaries in `bin-dist/` before running `site-build.sh`, they appear under
`/bin/` for the installers to download.

If `SITE_BASE_URL` and `RENDER_EXTERNAL_URL` are both unset, `site-build.sh`
defaults to `http://127.0.0.1:4173` and prints a warning.

## Operations (server lifecycle)

### Domain & HTTPS setup over SSH

Start with the guided status screen — it shows what is configured and prints
the exact commands (with your `--config` path) still needed, in order:

```bash
desertemail setup --config /etc/desertemail/config.toml
```

Then run the steps it suggests:

```bash
desertemail setup domain example.com --host mail.example.com -c /etc/desertemail/config.toml
desertemail setup dkim -c /etc/desertemail/config.toml        # prints the DKIM TXT to publish
desertemail setup https mail.example.com --email you@example.com -c /etc/desertemail/config.toml
sudo systemctl restart desertemail   # ACME worker requests the cert at startup
```

`setup https` probes A/AAAA + port 80 first (`--check-only` to probe without
writing; `--yes` to write config even if checks fail). Same atomic config
edits as the `/dns` web page.

Note: generating production RSA keys (DKIM, ACME) requires the `openssl` CLI
on the box — there is no *silent* in-repo fallback for real keys. Missing
openssl yields a clear error with install instructions; operators can knowingly
opt in to the unaudited built-in generator with
`DESERTEMAIL_ALLOW_UNAUDITED_KEYGEN=1` (logged loudly).

### User management

```bash
desertemail --config /etc/desertemail/config.toml user add alice@example.com
desertemail --config /etc/desertemail/config.toml user list
desertemail --config /etc/desertemail/config.toml user passwd alice
desertemail --config /etc/desertemail/config.toml user remove bob
```

Admin webmail (`admin_user`) can also add/remove users and set quotas; the
running process reloads the users/quotas map without a full restart. Other
config keys still need `systemctl restart desertemail`.

### Backup / restore

```bash
./deploy/backup.sh /var/lib/desertemail /var/backups/desertemail
```

See `deploy/backup.sh` for remote rsync targets, optional `CONFIG`/`DKIM`/
`TLS_*` extras, and restore notes. Maildir is generally safe to rsync live;
stop the service for a fully consistent snapshot.

### Health & metrics

- `GET http://host:8080/healthz` → `200 ok`
- `GET http://host:8080/metrics` → Prometheus text (`desertemail_*` counters)

Optional `metrics_token` in config gates `/metrics`. Point Prometheus at
`web_listen` (or a reverse proxy); Grafana can graph queue depth and auth
failure rates.

### Systemd graceful restart

```bash
sudo systemctl restart desertemail   # SIGTERM → graceful drain (see src/shutdown.rs)
```

Unit template: `deploy/desertemail.service`. Fail2ban filter/jail samples live
under `deploy/fail2ban-*`.

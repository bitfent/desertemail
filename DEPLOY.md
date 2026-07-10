# Deploying DesertEmail (binaries + install site)

Operator guide. Binaries are **not** published to GitHub Releases. CI (or a
maintainer) commits prebuilt binaries into `bin-dist/`; Render runs
`site-build.sh` and serves them under `/bin/` next to the per-platform
installers.

## (a) Build binaries into `bin-dist/`

### Via GitHub Actions (recommended)

The CI workflow lives at **`deploy/release.yml`** — it is NOT active there.
GitHub only runs workflows from `.github/workflows/`, and pushing to that path
needs a token with the `workflow` scope, so we ship it out-of-band. One-time
activation via the GitHub web UI (your browser session has full permissions):

1. On github.com open the repo → **Add file → Create new file**.
2. Name it `.github/workflows/release.yml`.
3. Paste the contents of `deploy/release.yml` and commit.

From then on, GitHub Actions builds static binaries when you push a version tag
or run **workflow_dispatch**:

```bash
# from a clean main with the version you want
git tag v0.1.0
git push origin v0.1.0
```

The workflow:

1. Builds the 4 Linux musl targets with `cross`, both macOS Darwin targets, and
   Windows `x86_64-pc-windows-msvc` (artifact ends in `.exe`).
2. Names each artifact `desertemail-<rust-triple>` (no version in the filename;
   Windows adds `.exe`).
3. Copies them into `bin-dist/` and commits + pushes to the default branch
   (`CI: update prebuilt binaries`), using `GITHUB_TOKEN` with `contents: write`.
4. Empty diffs are skipped (`git diff --cached --quiet`).

Pushing `bin-dist/` triggers a Render redeploy, which publishes the binaries
under `/bin/`.

### Locally (macOS binaries, or offline)

On a Mac with the Rust toolchain:

```bash
rustup target add aarch64-apple-darwin x86_64-apple-darwin

cargo build --release --target aarch64-apple-darwin
cargo build --release --target x86_64-apple-darwin

mkdir -p bin-dist
cp target/aarch64-apple-darwin/release/desertemail \
  bin-dist/desertemail-aarch64-apple-darwin
cp target/x86_64-apple-darwin/release/desertemail \
  bin-dist/desertemail-x86_64-apple-darwin

# strip if desired
strip -x bin-dist/desertemail-aarch64-apple-darwin 2>/dev/null || true
strip -x bin-dist/desertemail-x86_64-apple-darwin 2>/dev/null || true

git add bin-dist
git commit -m "update prebuilt macOS binaries"
git push
```

Linux musl targets are easiest via the CI `cross` jobs (or install `cross`
locally). Filenames must match exactly:

```text
desertemail-x86_64-unknown-linux-musl
desertemail-aarch64-unknown-linux-musl
desertemail-armv7-unknown-linux-musleabihf
desertemail-arm-unknown-linux-musleabihf
desertemail-x86_64-apple-darwin
desertemail-aarch64-apple-darwin
desertemail-x86_64-pc-windows-msvc.exe
```

`site-build.sh` regenerates `site/bin/SHA256SUMS` from whatever is in
`bin-dist/` — do not hand-maintain checksums under `site/`.

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

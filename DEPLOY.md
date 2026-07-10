# Deploying DesertEmail (binaries + install site)

Short operator guide. Placeholders: leave `bitfent/desertemail` as `OWNER/REPO` until you set the real slug in `install.sh` and `site/index.html`.

## (a) Publish a release (prebuilt binaries)

The CI workflow lives at **`deploy/release.yml`** in this repo — it is NOT active
there. GitHub only runs workflows from `.github/workflows/`, and pushing to that
path needs a token with the `workflow` scope, so we ship it out-of-band. One-time
activation via the GitHub web UI (your browser session has full permissions):

1. On github.com open the repo → **Add file → Create new file**.
2. Name it `.github/workflows/release.yml`.
3. Paste the contents of `deploy/release.yml` and commit.

From then on, GitHub Actions builds fully-static binaries when you push a version tag:

```bash
# from a clean main with the version you want
git tag v0.1.0
git push origin v0.1.0
```

That produces assets named:

```text
desertemail-v0.1.0-x86_64-unknown-linux-musl
desertemail-v0.1.0-x86_64-unknown-linux-musl.tar.gz
desertemail-v0.1.0-aarch64-unknown-linux-musl
desertemail-v0.1.0-aarch64-unknown-linux-musl.tar.gz
desertemail-v0.1.0-armv7-unknown-linux-musleabihf
desertemail-v0.1.0-armv7-unknown-linux-musleabihf.tar.gz
desertemail-v0.1.0-arm-unknown-linux-musleabihf
desertemail-v0.1.0-arm-unknown-linux-musleabihf.tar.gz
desertemail-v0.1.0-x86_64-apple-darwin
desertemail-v0.1.0-x86_64-apple-darwin.tar.gz
desertemail-v0.1.0-aarch64-apple-darwin
desertemail-v0.1.0-aarch64-apple-darwin.tar.gz
SHA256SUMS
```

…and attaches them to a GitHub Release for that tag. `install.sh` downloads by the same names.

**Before the first public install:** replace `bitfent/desertemail` in `install.sh` (and the GitHub link in `site/index.html`) with your `owner/repo`.

## (b) Host the landing page + installer on Render

1. Ensure `render.yaml` is on the default branch.
2. Render dashboard → **New** → **Blueprint** → select this repo → apply.
3. Service `desertemail-site` publishes `site/` after `cp install.sh site/install.sh`, so `/install.sh` is the same script as the repo root. `Content-Type: text/plain` is set for that path.

Binaries stay on GitHub Releases; Render only serves HTML + `install.sh`.

## (c) User install command

After the static site is live:

```bash
curl -fsSL https://<your-render-host>/install.sh | sh
```

Headless / CI:

```bash
curl -fsSL https://<your-render-host>/install.sh | DESERTEMAIL_NONINTERACTIVE=1 sh
```

Optional env overrides: `DESERTEMAIL_VERSION`, `DESERTEMAIL_PREFIX`, `DESERTEMAIL_DOMAIN`, `DESERTEMAIL_ADMIN_USER`, `DESERTEMAIL_ADMIN_PASSWORD`, `DESERTEMAIL_DATA_DIR`, `DESERTEMAIL_WEBMAIL`, `DESERTEMAIL_PORTS`, `DESERTEMAIL_DKIM`, `DESERTEMAIL_SYSTEMD`.

Pin a version:

```bash
DESERTEMAIL_VERSION=v0.1.0 curl -fsSL https://<your-render-host>/install.sh | sh
```

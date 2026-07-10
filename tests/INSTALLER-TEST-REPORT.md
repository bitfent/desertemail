# DesertEmail installer test report

**Suite:** `tests/test-installers.sh`  
**Host:** macOS arm64  
**Result:** **20/20 passed**

## What was tested

Isolated staging site (temp work tree + `python3 -m http.server`), fake `HOME` per install, Linux binaries faked for download/verify/install path coverage.

| # | Test | Result | Notes |
|---|------|--------|--------|
| 1–6 | Platform installers (4× Linux + 2× macOS) | pass | curl\|sh, SHA256 verified, binary + config keys |
| 7 | macOS Apple Silicon run | pass | 4 listeners (SMTP/submission/IMAP/web) within 3s |
| 8 | SHA256 mismatch | pass | non-zero exit, no binary installed |
| 9 | Missing binary (404) | pass | build-from-source message |
| 10 | Missing SHA256SUMS | pass | warns, still installs |
| 11 | Env overrides | pass | privileged ports, no webmail, domain/user |
| 12 | DKIM env | pass | `dkim.pem` mode 0600 + config fields |
| 13 | Config overwrite protect | pass | hand-edit survives 2nd non-interactive run |
| 14 | PATH marker idempotency | pass | exactly one marker block in `.zshrc` |
| 15 | Interactive pty wizard | pass | curl\|sh + `/dev/tty` answers (domain/user) |
| 16 | build-from-source | pass | `file://` local clone + `cargo build --release` |
| 17 | install-windows.ps1 | pass | **static only** (no `pwsh` on host) |
| 18 | No GitHub API / no `uname` | pass | generated platform installers |
| 19 | `sh -n` / `dash -n` / shellcheck | pass | 7 sh artifacts + shellcheck on linux-x86_64 |
| 20 | SHA256SUMS format + verify | pass | one entry per bin; `shasum -a 256 -c` |

## Statically verified only

- **Windows (`install-windows.ps1`):** no PowerShell runtime. Checks: no leftover `__TARGET__`/`__BASE_URL__`, balanced braces, contains `Get-FileHash`, `SetEnvironmentVariable`, `Read-Host -AsSecureString`.
- **Linux installers:** full download → checksum → install → config path exercised with **fake** shell-script “binaries.” The real musl binaries were **not** executed on this host.

## Runtime-verified on this host

- Real **macOS arm64** binary install + listen smoke (test 7).
- Real **macOS x86_64** binary install (Rosetta-capable host; install path only in 1–6).
- **build-from-source** compiles and installs a runnable binary.

## Remaining risk

1. **Linux targets** never run real `desertemail-*linux*` binaries here (fake stubs only).
2. **Windows** never downloads/installs/runs `desertemail.exe`.
3. **Privileged ports (25/587/143)** and **systemd** unit install are not exercised as root.
4. **Production CDN/TLS** path differs from local `http://127.0.0.1` staging.

**Recommendation:** post-deploy smoke on a real Pi/VPS (each Linux triple you publish) and a Windows box (`irm … \| iex`), confirming download, SHA verify, first start, and mail/web ports.

## How to re-run

```sh
sh tests/test-installers.sh
```

Self-cleaning (temp dirs, HTTP server). Leaves `site/` regenerated with  
`SITE_BASE_URL=http://127.0.0.1:4173`.

#!/bin/sh
# Build ALL release binaries locally into bin-dist/ — no GitHub, no cloud CI.
#
# This machine (macOS) builds:
#   - macOS binaries natively via `cargo` (aarch64 + x86_64 darwin)
#   - Linux (musl, all 4 arches) + Windows via `cargo-zigbuild`, which uses
#     Zig as the cross-compiler/linker (no Docker daemon required).
#
# One-time setup:
#   brew install zig                 # or: https://ziglang.org/download/
#   cargo install cargo-zigbuild
#   rustup target add \
#     x86_64-unknown-linux-musl aarch64-unknown-linux-musl \
#     armv7-unknown-linux-musleabihf arm-unknown-linux-musleabihf \
#     x86_64-pc-windows-gnu \
#     x86_64-apple-darwin aarch64-apple-darwin
#
# Usage:
#   sh build-binaries.sh              # build everything into bin-dist/
#   sh build-binaries.sh --skip-macos # skip the two darwin targets
# Then:
#   git add bin-dist && git commit -m "release binaries" && git push
#   (Render redeploys and serves them under /bin/)

set -eu

ROOT=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
cd "$ROOT"
mkdir -p bin-dist

SKIP_MACOS=0
[ "${1:-}" = "--skip-macos" ] && SKIP_MACOS=1

# target-triple | output-name (must match installers' expected asset names)
NATIVE_TARGETS="
aarch64-apple-darwin|desertemail-aarch64-apple-darwin
x86_64-apple-darwin|desertemail-x86_64-apple-darwin
"
ZIG_TARGETS="
x86_64-unknown-linux-musl|desertemail-x86_64-unknown-linux-musl
aarch64-unknown-linux-musl|desertemail-aarch64-unknown-linux-musl
armv7-unknown-linux-musleabihf|desertemail-armv7-unknown-linux-musleabihf
arm-unknown-linux-musleabihf|desertemail-arm-unknown-linux-musleabihf
x86_64-pc-windows-gnu|desertemail-x86_64-pc-windows-msvc.exe
"

need() { command -v "$1" >/dev/null 2>&1 || { echo "error: missing '$1' — see setup notes at top of this script" >&2; exit 1; }; }

copy_out() {
  # copy_out <target-triple> <out-name>
  _t=$1; _o=$2
  _bin="target/${_t}/release/desertemail"
  case "$_t" in *windows*) _bin="${_bin}.exe" ;; esac
  [ -f "$_bin" ] || { echo "error: expected binary not found: $_bin" >&2; exit 1; }
  strip "$_bin" 2>/dev/null || true
  cp "$_bin" "bin-dist/$_o"
  echo "  built $_o ($(wc -c < "bin-dist/$_o" | tr -d ' ') bytes)"
}

echo "== macOS (native cargo) =="
if [ "$SKIP_MACOS" -eq 1 ]; then
  echo "  skipped (--skip-macos)"
else
  need cargo
  printf '%s\n' "$NATIVE_TARGETS" | while IFS='|' read -r t o; do
    [ -n "$t" ] || continue
    echo "  cargo build $t"
    cargo build --release --target "$t" >/dev/null
    copy_out "$t" "$o"
  done
fi

echo "== Linux (musl) + Windows (cross via zig) =="
need cargo-zigbuild
need zig
printf '%s\n' "$ZIG_TARGETS" | while IFS='|' read -r t o; do
  [ -n "$t" ] || continue
  echo "  cargo zigbuild $t"
  cargo zigbuild --release --target "$t" >/dev/null
  copy_out "$t" "$o"
done

sh scripts/source-hash.sh > bin-dist/SOURCE_HASH
echo "  stamped bin-dist/SOURCE_HASH (pre-push guard)"

echo "== done — bin-dist/ =="
for f in bin-dist/desertemail-*; do [ -f "$f" ] && echo "  $(basename "$f")"; done
echo
echo "Next: git add bin-dist && git commit -m 'release binaries' && git push"
echo "Then site-build.sh (on Render) copies them to site/bin/ + regenerates SHA256SUMS."

#!/bin/sh
# Deterministic hash of the source that determines the release binaries.
# Shared by build-binaries.sh (stamps bin-dist/SOURCE_HASH) and the pre-push
# hook (compares, to refuse pushing binaries that don't match the source).
# Fast: hashes file contents only, no compile. 100% local, no CI.
set -eu

ROOT=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
cd "$ROOT"

if command -v sha256sum >/dev/null 2>&1; then
  HASH="sha256sum"
else
  HASH="shasum -a 256"
fi

{
  # every .rs under src/, in a stable order, name + contents
  find src -type f -name '*.rs' | LC_ALL=C sort | while IFS= read -r f; do
    printf '%s\n' "$f"
    cat "$f"
  done
  # manifest + lockfile (dep versions affect the binary too)
  cat Cargo.toml Cargo.lock 2>/dev/null || true
} | $HASH | cut -d' ' -f1

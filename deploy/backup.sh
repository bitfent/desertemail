#!/bin/sh
# DesertEmail backup helper (POSIX sh).
#
# Backs up the data directory (Maildirs + queue + greylist) and optional config,
# DKIM key, and TLS certs to a local path or remote (via rsync if available).
#
# Atomicity caveat:
#   - Maildir is designed for concurrent access; rsync while the server runs is
#     usually fine (you may miss a message mid-delivery or see a transient empty
#     file). For a perfectly consistent snapshot, stop the service first:
#       systemctl stop desertemail
#       ./deploy/backup.sh ...
#       systemctl start desertemail
#   - The outbound queue is durable on disk; a live rsync may capture a message
#     that is also being rewritten — rare and recoverable on next delivery attempt.
#
# Usage:
#   ./deploy/backup.sh <data_dir> <dest>
#   ./deploy/backup.sh /var/lib/desertemail /var/backups/desertemail
#   ./deploy/backup.sh /var/lib/desertemail user@host:/backups/desertemail
#   CONFIG=/etc/desertemail/config.toml DKIM=/etc/desertemail/dkim.pem \
#     TLS_CERT=/etc/desertemail/tls.crt TLS_KEY=/etc/desertemail/tls.key \
#     ./deploy/backup.sh /var/lib/desertemail /var/backups/desertemail
#
# Restore:
#   1. Stop desertemail.
#   2. rsync -a <backup>/data/ <data_dir>/
#   3. Restore config.toml, dkim.pem, tls.crt, tls.key from the backup extras/
#      if present (paths depend on your layout).
#   4. chown/chmod as your unit expects; start desertemail.
#   5. Verify: curl -s http://127.0.0.1:8080/healthz  → ok

set -eu

if [ "$#" -lt 2 ]; then
  echo "Usage: $0 <data_dir> <dest>" >&2
  echo "  Optional env: CONFIG DKIM TLS_CERT TLS_KEY" >&2
  exit 1
fi

DATA_DIR=$1
DEST=$2
STAMP=$(date -u +%Y%m%dT%H%M%SZ 2>/dev/null || date +%Y%m%d%H%M%S)
LABEL="desertemail-backup-$STAMP"

if [ ! -d "$DATA_DIR" ]; then
  echo "error: data_dir not a directory: $DATA_DIR" >&2
  exit 1
fi

# Local dest: create stamped subdirectory.
case "$DEST" in
  *:*/*|*:*)
    # remote rsync target (host:path) — send into DEST/$LABEL
    REMOTE=1
    TARGET="$DEST/$LABEL"
    ;;
  *)
    REMOTE=0
    TARGET="$DEST/$LABEL"
    mkdir -p "$TARGET"
    ;;
esac

echo "Backing up data_dir=$DATA_DIR -> $TARGET"

if command -v rsync >/dev/null 2>&1; then
  if [ "$REMOTE" -eq 1 ]; then
    rsync -a --delete --exclude '.tmp*' "$DATA_DIR/" "$TARGET/data/"
  else
    mkdir -p "$TARGET/data"
    rsync -a --exclude '.tmp*' "$DATA_DIR/" "$TARGET/data/"
  fi
else
  # Fallback: tar when rsync missing (local only).
  if [ "$REMOTE" -eq 1 ]; then
    echo "error: rsync required for remote dest" >&2
    exit 1
  fi
  mkdir -p "$TARGET"
  tar -C "$(dirname "$DATA_DIR")" -czf "$TARGET/data.tar.gz" "$(basename "$DATA_DIR")"
fi

# Optional extras (config, keys, certs).
if [ "$REMOTE" -eq 0 ]; then
  EXTRAS="$TARGET/extras"
  mkdir -p "$EXTRAS"
  copy_if() {
    src=$1
    name=$2
    if [ -n "${src:-}" ] && [ -f "$src" ]; then
      cp -p "$src" "$EXTRAS/$name"
      echo "  + extras/$name"
    fi
  }
  copy_if "${CONFIG:-}" config.toml
  copy_if "${DKIM:-}" dkim.pem
  copy_if "${TLS_CERT:-}" tls.crt
  copy_if "${TLS_KEY:-}" tls.key

  # Manifest
  {
    echo "stamp=$STAMP"
    echo "data_dir=$DATA_DIR"
    echo "host=$(hostname 2>/dev/null || echo unknown)"
    date -u 2>/dev/null || date
  } >"$TARGET/MANIFEST.txt"

  echo "Done: $TARGET"
  ls -la "$TARGET" || true
else
  echo "Done (remote): $TARGET"
fi

echo ""
echo "Restore notes:"
echo "  systemctl stop desertemail"
echo "  rsync -a $TARGET/data/ $DATA_DIR/"
echo "  # restore extras/* to their original paths if needed"
echo "  systemctl start desertemail"

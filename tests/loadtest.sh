#!/bin/sh
# Short load test against a running DesertEmail instance.
# Opens N concurrent SMTP DATA deliveries and M IMAP LOGINs; reports throughput
# and that excess connections beyond max_connections get 421/BYE without crash.
#
# Usage:
#   ./tests/loadtest.sh [base]
# Env overrides:
#   SMTP_HOST SMTP_PORT IMAP_HOST IMAP_PORT WEB_URL
#   N_SMTP M_IMAP MAX_CONN RCPT FROM USER PASS
#
# Expects a local test config (see script defaults matching high ports).

set -eu

SMTP_HOST=${SMTP_HOST:-127.0.0.1}
SMTP_PORT=${SMTP_PORT:-2525}
IMAP_HOST=${IMAP_HOST:-127.0.0.1}
IMAP_PORT=${IMAP_PORT:-2143}
WEB_URL=${WEB_URL:-http://127.0.0.1:8080}
N_SMTP=${N_SMTP:-20}
M_IMAP=${M_IMAP:-10}
MAX_CONN=${MAX_CONN:-8}
RCPT=${RCPT:-alice@example.com}
FROM=${FROM:-loadtest@example.com}
USER=${USER:-alice}
PASS=${PASS:-alicepass}
WORKDIR=${WORKDIR:-/tmp/desertemail-loadtest-$$}

mkdir -p "$WORKDIR"
cleanup() { rm -rf "$WORKDIR"; }
trap cleanup EXIT

echo "=== DesertEmail loadtest ==="
echo "SMTP $SMTP_HOST:$SMTP_PORT  IMAP $IMAP_HOST:$IMAP_PORT  WEB $WEB_URL"
echo "N_SMTP=$N_SMTP M_IMAP=$M_IMAP (parallel)"

# --- SMTP flood: concurrent short sessions ---
smtp_one() {
  id=$1
  # shellcheck disable=SC2016
  {
    printf 'EHLO loadtest.local\r\n'
    printf 'MAIL FROM:<%s>\r\n' "$FROM"
    printf 'RCPT TO:<%s>\r\n' "$RCPT"
    printf 'DATA\r\n'
    printf 'From: %s\r\nTo: %s\r\nSubject: load %s\r\n\r\nbody %s\r\n.\r\n' \
      "$FROM" "$RCPT" "$id" "$id"
    printf 'QUIT\r\n'
  } | nc -w 3 "$SMTP_HOST" "$SMTP_PORT" >"$WORKDIR/smtp-$id.out" 2>"$WORKDIR/smtp-$id.err" || true
}

imap_one() {
  id=$1
  {
    printf 'a LOGIN %s %s\r\n' "$USER" "$PASS"
    printf 'b LOGOUT\r\n'
  } | nc -w 3 "$IMAP_HOST" "$IMAP_PORT" >"$WORKDIR/imap-$id.out" 2>"$WORKDIR/imap-$id.err" || true
}

# Cap storm: open more connections than MAX_CONN briefly
cap_storm() {
  i=0
  while [ "$i" -lt $((MAX_CONN + 6)) ]; do
    ( printf 'EHLO x\r\n'; sleep 2; printf 'QUIT\r\n' ) \
      | nc -w 4 "$SMTP_HOST" "$SMTP_PORT" >"$WORKDIR/cap-$i.out" 2>/dev/null &
    i=$((i + 1))
  done
  wait
}

t0=$(date +%s 2>/dev/null || echo 0)

# Launch SMTP workers
i=0
while [ "$i" -lt "$N_SMTP" ]; do
  smtp_one "$i" &
  i=$((i + 1))
done

# Launch IMAP workers
i=0
while [ "$i" -lt "$M_IMAP" ]; do
  imap_one "$i" &
  i=$((i + 1))
done

wait

t1=$(date +%s 2>/dev/null || echo 0)
elapsed=$((t1 - t0))
if [ "$elapsed" -lt 1 ]; then elapsed=1; fi

smtp_ok=0
smtp_fail=0
for f in "$WORKDIR"/smtp-*.out; do
  [ -f "$f" ] || continue
  if grep -q '250 OK' "$f" 2>/dev/null; then
    smtp_ok=$((smtp_ok + 1))
  else
    smtp_fail=$((smtp_fail + 1))
  fi
done

imap_ok=0
imap_fail=0
for f in "$WORKDIR"/imap-*.out; do
  [ -f "$f" ] || continue
  if grep -qi 'OK LOGIN' "$f" 2>/dev/null; then
    imap_ok=$((imap_ok + 1))
  else
    imap_fail=$((imap_fail + 1))
  fi
done

echo ""
echo "--- Results ---"
echo "SMTP delivered OK: $smtp_ok / $N_SMTP  (fail/other: $smtp_fail)"
echo "IMAP LOGIN OK:     $imap_ok / $M_IMAP  (fail/other: $imap_fail)"
echo "Elapsed: ${elapsed}s"
echo "Throughput (approx): SMTP $((smtp_ok / elapsed))/s  IMAP $((imap_ok / elapsed))/s"

# Connection cap check (best-effort; needs max_connections low on server)
echo ""
echo "--- Connection cap storm (MAX_CONN=$MAX_CONN) ---"
cap_storm
cap_reject=0
cap_ok=0
for f in "$WORKDIR"/cap-*.out; do
  [ -f "$f" ] || continue
  if grep -qi 'too many\|421\|BYE' "$f" 2>/dev/null; then
    cap_reject=$((cap_reject + 1))
  elif grep -qi '220\|250' "$f" 2>/dev/null; then
    cap_ok=$((cap_ok + 1))
  fi
done
echo "Cap storm accepted≈$cap_ok rejected≈$cap_reject (expect some rejects when over max_connections)"

# Health / metrics if web is up
# Optional METRICS_TOKEN for gated /metrics (Authorization: Bearer or ?token=).
if command -v curl >/dev/null 2>&1; then
  echo ""
  echo "--- /healthz /metrics ---"
  code=$(curl -s -o "$WORKDIR/healthz" -w '%{http_code}' "$WEB_URL/healthz" || echo 000)
  echo "GET /healthz -> $code $(cat "$WORKDIR/healthz" 2>/dev/null || true)"
  if [ -n "${METRICS_TOKEN:-}" ]; then
    curl -s -H "Authorization: Bearer $METRICS_TOKEN" "$WEB_URL/metrics" >"$WORKDIR/metrics" || true
  else
    curl -s "$WEB_URL/metrics" >"$WORKDIR/metrics" || true
  fi
  if [ -s "$WORKDIR/metrics" ]; then
    echo "metrics sample:"
    grep -E '^desertemail_' "$WORKDIR/metrics" | head -20
  else
    echo "(no metrics body — is web_listen up? set METRICS_TOKEN if metrics_token is configured)"
  fi
fi

echo ""
echo "Loadtest finished. Server should still be running (check process / healthz)."

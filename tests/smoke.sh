#!/bin/sh
# End-to-end smoke test for DesertEmail. Drives a FRESH instance (empty
# [users]) through: first-run setup, login, self-service password change,
# admin add/reset/log-out/rename/remove, invites, inbound SMTP
# (spam-filtered), IMAP, and authenticated submission — plain curl + nc.
#
# Start a fresh instance first, e.g.:
#   cat > /tmp/smoke.toml <<EOF
#   domains = ["example.com"]
#   data_dir = "/tmp/smoke-data"
#   web_listen = "127.0.0.1:8099"
#   smtp_listen = "127.0.0.1:12525"
#   submission_listen = "127.0.0.1:12587"
#   imap_listen = "127.0.0.1:12143"
#
#   [users]
#   EOF
#   desertemail --config /tmp/smoke.toml &
#
# Then:
#   ./tests/smoke.sh
# Env overrides: WEB_URL SMTP_PORT SUB_PORT IMAP_PORT WORKDIR
set -u
BASE=${WEB_URL:-http://127.0.0.1:8099}
SMTP_PORT=${SMTP_PORT:-12525}
SUB_PORT=${SUB_PORT:-12587}
IMAP_PORT=${IMAP_PORT:-12143}
WORKDIR=${WORKDIR:-$(mktemp -d /tmp/desertemail-smoke.XXXXXX)}
cd "$WORKDIR"
PASS=0; FAIL=0
ok()   { PASS=$((PASS+1)); echo "PASS: $1"; }
bad()  { FAIL=$((FAIL+1)); echo "FAIL: $1"; }
check() { # check <desc> <expected> <actual>
  if [ "$2" = "$3" ]; then ok "$1"; else bad "$1 (want '$2' got '$3')"; fi
}

csrf() { curl -s -b "$1" "$BASE/admin" | grep -o 'name="csrf" value="[a-f0-9]*"' | head -1 | grep -o '[a-f0-9]\{64\}'; }
flash() { grep -o 'class="ok">[^<]*\|class="err">[^<]*' | head -1; }

echo "== first-run setup =="
check "fresh instance redirects to /setup" "/setup" "$(curl -s -o /dev/null -w '%{redirect_url}' $BASE/ | sed 's|^.*//[^/]*||')"
check "setup wizard completes + signs in" "302" "$(curl -s -c adm-setup.txt -o /dev/null -w '%{http_code}' -d 'username=admin&password=sonoran-admin-9&password2=sonoran-admin-9&domain=example.com' $BASE/setup)"
check "setup is one-time (now redirects)" "/login" "$(curl -s -o /dev/null -w '%{redirect_url}' $BASE/setup | sed 's|^.*//[^/]*||')"

echo "== ops endpoints =="
check "healthz" "200" "$(curl -s -o /dev/null -w '%{http_code}' $BASE/healthz)"
check "metrics" "200" "$(curl -s -o /dev/null -w '%{http_code}' $BASE/metrics)"

echo "== login =="
check "wrong password rejected" "200" "$(curl -s -o /dev/null -w '%{http_code}' -d 'username=admin&password=wrong-wrong' $BASE/login)"
check "admin login" "302" "$(curl -s -c adm.txt -o /dev/null -w '%{http_code}' -d 'username=admin&password=sonoran-admin-9' $BASE/login)"

echo "== admin: add user =="
C=$(csrf adm.txt)
curl -s -b adm.txt -d "csrf=$C&email=bob&password=bobs-first-pw1" $BASE/admin/user/add | flash
check "short password refused on add" 'class="err">error: password must be at least 8 characters' \
  "$(curl -s -b adm.txt -d "csrf=$C&email=tiny&password=short" $BASE/admin/user/add | flash)"
check "duplicate add refused" 'class="err">error: user bob already exists — use Reset password below' \
  "$(curl -s -b adm.txt -d "csrf=$C&email=bob&password=whatever-99" $BASE/admin/user/add | flash)"

echo "== bob: self-service password change =="
check "bob login" "302" "$(curl -s -c bob.txt -o /dev/null -w '%{http_code}' -d 'username=bob&password=bobs-first-pw1' $BASE/login)"
CB=$(curl -s -b bob.txt $BASE/account | grep -o 'name="csrf" value="[a-f0-9]*"' | head -1 | grep -o '[a-f0-9]\{64\}')
check "wrong current pw refused" 'class="err">error: current password is incorrect' \
  "$(curl -s -b bob.txt -d "csrf=$CB&current=nope-nope-nope&password=bobs-second-pw2&password2=bobs-second-pw2" $BASE/account/password | flash)"
check "mismatched new pws refused" 'class="err">error: new passwords do not match' \
  "$(curl -s -b bob.txt -d "csrf=$CB&current=bobs-first-pw1&password=bobs-second-pw2&password2=different-pw-3" $BASE/account/password | flash)"
check "password change works" 'class="ok">Password updated.' \
  "$(curl -s -b bob.txt -d "csrf=$CB&current=bobs-first-pw1&password=bobs-second-pw2&password2=bobs-second-pw2" $BASE/account/password | flash)"
check "old pw dead" "200" "$(curl -s -o /dev/null -w '%{http_code}' -d 'username=bob&password=bobs-first-pw1' $BASE/login)"
check "new pw live" "302" "$(curl -s -o /dev/null -w '%{http_code}' -d 'username=bob&password=bobs-second-pw2' $BASE/login)"

echo "== admin: reset + logout =="
check "reset unknown user refused" 'class="err">error: user not found: ghost' \
  "$(curl -s -b adm.txt -d "csrf=$C&email=ghost&password=whatever-99" $BASE/admin/user/password | flash)"
# Two live bob sessions exist here: bob.txt plus the throwaway "new pw live" login.
check "reset bob + logout sessions" 'class="ok">Password reset for bob (live; no restart needed); 2 session(s) logged out.' \
  "$(curl -s -b adm.txt -d "csrf=$C&email=bob&password=bobs-reset-pw3&logout=on" $BASE/admin/user/password | flash)"
check "bob session kicked" "302" "$(curl -s -b bob.txt -o /dev/null -w '%{http_code}' $BASE/account)"
check "bob reset pw live" "302" "$(curl -s -c bob2.txt -o /dev/null -w '%{http_code}' -d 'username=bob&password=bobs-reset-pw3' $BASE/login)"
check "logout button kicks bob" 'class="ok">Logged out 1 session(s) for bob.' \
  "$(curl -s -b adm.txt -d "csrf=$C&email=bob" $BASE/admin/user/logout | flash)"
check "non-admin cannot reset" 'class="err">Access denied.' \
  "$(curl -s -c bob3.txt -o /dev/null -d 'username=bob&password=bobs-reset-pw3' $BASE/login; CB3=$(curl -s -b bob3.txt $BASE/account | grep -o 'name=.csrf. value=.[a-f0-9]*' | head -1 | grep -o '[a-f0-9]\{64\}'); curl -s -b bob3.txt -d "csrf=$CB3&email=admin&password=evil-pw-99999" $BASE/admin/user/password | grep -o 'class="err">[^<]*' | head -1)"

echo "== invite flow (carol) =="
INV=$(curl -s -b adm.txt -d "csrf=$C&email=carol@example.com" $BASE/admin/invite | grep -o '/invite?token=[a-zA-Z0-9_-]*' | head -1)
if [ -n "$INV" ]; then ok "invite link created"; else bad "invite link created"; fi
TOK=${INV#/invite?token=}
check "invite page renders" "200" "$(curl -s -o /dev/null -w '%{http_code}' "$BASE$INV")"
check "invite short pw refused" "200" "$(curl -s -o /dev/null -w '%{http_code}' -d "token=$TOK&password=tiny&password2=tiny" $BASE/invite)"
check "invite redeem sets pw + signs in" "302" "$(curl -s -c carol.txt -o /dev/null -w '%{http_code}' -d "token=$TOK&password=carols-own-pw4&password2=carols-own-pw4" $BASE/invite)"
check "invite token single-use (404 after redeem)" "404" "$(curl -s -o /dev/null -w '%{http_code}' -d "token=$TOK&password=carols-own-pw4&password2=carols-own-pw4" $BASE/invite)"
check "carol can login" "302" "$(curl -s -o /dev/null -w '%{http_code}' -d 'username=carol@example.com&password=carols-own-pw4' $BASE/login)"

echo "== SMTP inbound delivery =="
SMTP_OUT=$( (printf 'HELO tester\r\nMAIL FROM:<friend@elsewhere.org>\r\nRCPT TO:<bob@example.com>\r\nDATA\r\n'; sleep 0.3; printf 'From: friend@elsewhere.org\r\nTo: bob@example.com\r\nSubject: smoke hello\r\n\r\nHowdy from the smoke test.\r\n.\r\nQUIT\r\n'; sleep 0.3) | nc -w 5 127.0.0.1 $SMTP_PORT )
if echo "$SMTP_OUT" | grep -q "250 OK: queued"; then ok "smtp delivery accepted"; else
  if echo "$SMTP_OUT" | grep -qE "^45[01]"; then echo "note: greylisted, retrying"; sleep 1;
    SMTP_OUT=$( (printf 'HELO tester\r\nMAIL FROM:<friend@elsewhere.org>\r\nRCPT TO:<bob@example.com>\r\nDATA\r\n'; sleep 0.3; printf 'From: friend@elsewhere.org\r\nTo: bob@example.com\r\nSubject: smoke hello\r\n\r\nHowdy from the smoke test.\r\n.\r\nQUIT\r\n'; sleep 0.3) | nc -w 5 127.0.0.1 $SMTP_PORT )
    if echo "$SMTP_OUT" | grep -q "250 OK: queued"; then ok "smtp delivery accepted (after greylist)"; else bad "smtp delivery accepted"; fi
  else bad "smtp delivery accepted"; fi
fi

echo "== bob sees the mail (web + IMAP) =="
sleep 1
# A bare external message (no Date/Message-ID/SPF) is EXPECTED to be junked.
check "external bare mail filed to Spam" "smoke hello" "$(curl -s -b bob3.txt $BASE/spam | grep -o 'smoke hello' | head -1)"
IMAP_OUT=$( (printf 'a1 LOGIN bob bobs-reset-pw3\r\n'; sleep 0.4; printf 'a2 SELECT Junk\r\n'; sleep 0.4; printf 'a3 LOGOUT\r\n'; sleep 0.2) | nc -w 5 127.0.0.1 $IMAP_PORT )
if echo "$IMAP_OUT" | grep -q "a1 OK"; then ok "imap login with reset password"; else bad "imap login with reset password"; fi
if echo "$IMAP_OUT" | tr -d '\r' | grep -qE '^\* [1-9][0-9]* EXISTS'; then ok "imap sees message in Junk"; else bad "imap sees message in Junk"; fi
IMAP_BAD=$( (printf 'a1 LOGIN bob wrong-password-x\r\n'; sleep 0.4; printf 'a2 LOGOUT\r\n'; sleep 0.2) | nc -w 5 127.0.0.1 $IMAP_PORT )
if echo "$IMAP_BAD" | grep -q "a1 NO"; then ok "imap rejects wrong password"; else bad "imap rejects wrong password"; fi

echo "== authenticated submission bob -> carol (should reach inbox) =="
AUTH_B64="AGJvYgBib2JzLXJlc2V0LXB3Mw=="   # \0bob\0bobs-reset-pw3
SUB_OUT=$( (printf 'EHLO tester\r\nAUTH PLAIN %s\r\n' "$AUTH_B64"; sleep 0.3; printf 'MAIL FROM:<bob@example.com>\r\nRCPT TO:<carol@example.com>\r\nDATA\r\n'; sleep 0.3; printf 'From: bob@example.com\r\nTo: carol@example.com\r\nSubject: lunch friday\r\nDate: Tue, 15 Jul 2026 12:00:00 +0000\r\nMessage-ID: <smoke-1@example.com>\r\n\r\nTacos?\r\n.\r\nQUIT\r\n'; sleep 0.3) | nc -w 5 127.0.0.1 $SUB_PORT )
if echo "$SUB_OUT" | grep -q "235 "; then ok "submission auth accepted"; else bad "submission auth accepted"; fi
if echo "$SUB_OUT" | grep -q "250 OK: queued"; then ok "submission accepted message"; else bad "submission accepted message"; fi
sleep 1
check "carol inbox shows subject" "lunch friday" "$(curl -s -b carol.txt $BASE/ | grep -o 'lunch friday' | head -1)"
SUB_BAD=$( (printf 'EHLO tester\r\nAUTH PLAIN AGJvYgB3cm9uZy1wdw==\r\n'; sleep 0.3; printf 'QUIT\r\n') | nc -w 5 127.0.0.1 $SUB_PORT )
if echo "$SUB_BAD" | grep -q "535 "; then ok "submission rejects wrong password"; else bad "submission rejects wrong password"; fi

echo "== rename bob -> robert (keeps password, mail, sessions) =="
# bob3.txt is bob's only live session at this point.
check "rename works" 'class="ok">Renamed bob to robert (mailbox moved; 1 session(s) stay signed in; same password).' \
  "$(curl -s -b adm.txt -d "csrf=$C&email=bob&new_email=robert" $BASE/admin/user/rename | flash)"
check "open session remapped to new name" "robert" "$(curl -s -b bob3.txt $BASE/account | grep -o '<code>robert</code>' | grep -o robert)"
check "old name no longer logs in" "200" "$(curl -s -o /dev/null -w '%{http_code}' -d 'username=bob&password=bobs-reset-pw3' $BASE/login)"
check "new name logs in with same password" "302" "$(curl -s -c robert.txt -o /dev/null -w '%{http_code}' -d 'username=robert&password=bobs-reset-pw3' $BASE/login)"
check "mailbox moved with the rename" "smoke hello" "$(curl -s -b robert.txt $BASE/spam | grep -o 'smoke hello' | head -1)"
check "rename onto existing user refused" 'class="err">error: user already exists: carol@example.com' \
  "$(curl -s -b adm.txt -d "csrf=$C&email=robert&new_email=carol@example.com" $BASE/admin/user/rename | flash)"

echo "== remove user (revokes access) =="
# robert has two live sessions here: the remapped bob3.txt and robert.txt.
check "remove reports revoked sessions" 'class="ok">User robert removed; 2 session(s) logged out. Mailbox data stays on disk until you delete it.' \
  "$(curl -s -b adm.txt -d "csrf=$C&email=robert" $BASE/admin/user/remove | flash)"
check "removed user's web session revoked" "302" "$(curl -s -b robert.txt -o /dev/null -w '%{http_code}' $BASE/account)"
check "removed user cannot log in" "200" "$(curl -s -o /dev/null -w '%{http_code}' -d 'username=robert&password=bobs-reset-pw3' $BASE/login)"
IMAP_GONE=$( (printf 'a1 LOGIN robert bobs-reset-pw3\r\n'; sleep 0.4; printf 'a2 LOGOUT\r\n'; sleep 0.2) | nc -w 5 127.0.0.1 $IMAP_PORT )
if echo "$IMAP_GONE" | grep -q "a1 NO"; then ok "removed user IMAP access revoked"; else bad "removed user IMAP access revoked"; fi

echo ""
echo "== RESULT: $PASS passed, $FAIL failed =="
[ "$FAIL" -eq 0 ]

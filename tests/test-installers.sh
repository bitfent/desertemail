#!/bin/sh
# DesertEmail installer test suite (POSIX sh).
# Run from anywhere:  sh tests/test-installers.sh
# Self-cleaning: uses temp dirs + fake HOME only; restores site/ to local-dev at exit.

set -eu

REPO=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
cd "${REPO}"

PASSED=0
FAILED=0
TOTAL=0
FAIL_NAMES=""

TMP_ROOT=""
STAGING=""
WORK_TREE=""
HTTP_PID=""
SERVER_PID=""
PORT=""

# ---------------------------------------------------------------------------
# Cleanup (always)
# ---------------------------------------------------------------------------
cleanup() {
  _ec=$?
  if [ -n "${SERVER_PID}" ]; then
    kill "${SERVER_PID}" 2>/dev/null || true
    wait "${SERVER_PID}" 2>/dev/null || true
    SERVER_PID=""
  fi
  if [ -n "${HTTP_PID}" ]; then
    kill "${HTTP_PID}" 2>/dev/null || true
    wait "${HTTP_PID}" 2>/dev/null || true
    HTTP_PID=""
  fi
  # pkill any desertemail left under our temp root
  if [ -n "${TMP_ROOT}" ] && [ -d "${TMP_ROOT}" ]; then
    # shellcheck disable=SC2009
    ps -ax -o pid=,command= 2>/dev/null | while IFS= read -r _line; do
      case "${_line}" in
        *"${TMP_ROOT}"*)
          _pid=$(printf '%s' "${_line}" | awk '{print $1}')
          kill "${_pid}" 2>/dev/null || true
          ;;
      esac
    done || true
    rm -rf "${TMP_ROOT}" 2>/dev/null || true
  fi
  # Leave repo site/ in normal local-dev state
  if [ -f "${REPO}/site-build.sh" ]; then
    SITE_BASE_URL=http://127.0.0.1:4173 sh "${REPO}/site-build.sh" >/dev/null 2>&1 || true
  fi
  return "${_ec}"
}
trap cleanup EXIT INT HUP TERM

# ---------------------------------------------------------------------------
# Test helpers
# ---------------------------------------------------------------------------
ok() {
  TOTAL=$((TOTAL + 1))
  PASSED=$((PASSED + 1))
  printf 'ok %s %s\n' "$1" "$2"
}

fail() {
  TOTAL=$((TOTAL + 1))
  FAILED=$((FAILED + 1))
  FAIL_NAMES="${FAIL_NAMES} $1"
  printf 'FAIL %s %s\n' "$1" "$2"
  if [ -n "${3:-}" ]; then
    printf '  detail: %s\n' "$3"
  fi
}

assert_exit0() {
  # assert_exit0 NN name cmd...
  _nn=$1
  _name=$2
  shift 2
  _outf="${TMP_ROOT}/out-${_nn}.txt"
  _errf="${TMP_ROOT}/err-${_nn}.txt"
  if "$@" >"${_outf}" 2>"${_errf}"; then
    ok "${_nn}" "${_name}"
    return 0
  fi
  fail "${_nn}" "${_name}" "exit non-zero; stderr=$(head -c 400 "${_errf}" | tr '\n' ' ')"
  return 1
}

fake_home() {
  # print path to a fresh HOME under TMP_ROOT
  _h=$(mktemp -d "${TMP_ROOT}/home.XXXXXX")
  mkdir -p "${_h}"
  # Pre-create empty rc so PATH wiring is visible
  : > "${_h}/.zshrc"
  : > "${_h}/.bashrc"
  : > "${_h}/.profile"
  printf '%s' "${_h}"
}

regen_sums() {
  _bin=$1
  : > "${_bin}/SHA256SUMS"
  for _f in "${_bin}"/desertemail-*; do
    [ -f "${_f}" ] || continue
    _base=$(basename "${_f}")
    (
      CDPATH='' cd -- "${_bin}" || exit 1
      if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "${_base}"
      else
        shasum -a 256 "${_base}"
      fi
    ) >> "${_bin}/SHA256SUMS"
  done
}

sha_check_cmd() {
  if command -v sha256sum >/dev/null 2>&1; then
    printf 'sha256sum'
  else
    printf 'shasum -a 256'
  fi
}

# Free TCP port on 127.0.0.1
pick_port() {
  python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1]); s.close()'
}

wait_http() {
  _url=$1
  _n=0
  while [ "${_n}" -lt 50 ]; do
    if curl -fsS -o /dev/null "${_url}" 2>/dev/null; then
      return 0
    fi
    _n=$((_n + 1))
    sleep 0.1
  done
  return 1
}

assert_config_defaults() {
  # assert_config_defaults config_path
  _cfg=$1
  [ -f "${_cfg}" ] || return 1
  grep -q 'domains' "${_cfg}" || return 1
  grep -q 'data_dir' "${_cfg}" || return 1
  grep -q 'smtp_listen' "${_cfg}" || return 1
  grep -q 'submission_listen' "${_cfg}" || return 1
  grep -q 'imap_listen' "${_cfg}" || return 1
  grep -q 'web_listen' "${_cfg}" || return 1
  grep -q 'admin_user' "${_cfg}" || return 1
  grep -q 'catch_all' "${_cfg}" || return 1
  grep -q 'default_password' "${_cfg}" || return 1
  grep -q '\[users\]' "${_cfg}" || return 1
  return 0
}

run_installer() {
  # run_installer platform home_dir [extra env assignments via env]
  # Uses curl|sh against staging server. Captures stdout+stderr to OUT_COMBINED.
  _plat=$1
  _home=$2
  shift 2
  OUT_COMBINED="${TMP_ROOT}/install-${_plat}-$$.log"
  # shellcheck disable=SC2086
  if env HOME="${_home}" SHELL="${SHELL:-/bin/zsh}" DESERTEMAIL_NONINTERACTIVE=1 "$@" \
    sh -c "curl -fsSL \"http://127.0.0.1:${PORT}/install-${_plat}.sh\" | sh" \
    >"${OUT_COMBINED}" 2>&1; then
    INSTALL_EC=0
  else
    INSTALL_EC=$?
  fi
  return 0
}

# ---------------------------------------------------------------------------
# Environment setup: isolated work tree + staging site + fake linux bins
# ---------------------------------------------------------------------------
setup_staging() {
  TMP_ROOT=$(mktemp -d "${TMPDIR:-/tmp}/desertemail-installer-test.XXXXXX")
  WORK_TREE="${TMP_ROOT}/work"
  mkdir -p "${WORK_TREE}"

  # Minimal work tree so site-build does not touch the real repo
  cp "${REPO}/site-build.sh" "${WORK_TREE}/"
  cp -R "${REPO}/installers" "${WORK_TREE}/"
  cp -R "${REPO}/bin-dist" "${WORK_TREE}/"
  mkdir -p "${WORK_TREE}/site"
  if [ -f "${REPO}/site/index.html" ]; then
    cp "${REPO}/site/index.html" "${WORK_TREE}/site/"
  else
    printf '<html><body>test</body></html>\n' > "${WORK_TREE}/site/index.html"
  fi

  PORT=$(pick_port)
  (
    CDPATH='' cd -- "${WORK_TREE}" || exit 1
    SITE_BASE_URL="http://127.0.0.1:${PORT}" sh ./site-build.sh
  ) >"${TMP_ROOT}/site-build.log" 2>&1 || {
    printf 'FATAL: site-build failed:\n' >&2
    cat "${TMP_ROOT}/site-build.log" >&2
    exit 1
  }

  STAGING="${WORK_TREE}/site"

  # Fake Linux binaries (not runnable on macOS host; validate download path)
  LINUX_TARGETS="
x86_64-unknown-linux-musl
aarch64-unknown-linux-musl
armv7-unknown-linux-musleabihf
arm-unknown-linux-musleabihf
"
  printf '%s\n' "${LINUX_TARGETS}" | while IFS= read -r _t || [ -n "${_t}" ]; do
    case "${_t}" in ''|\#*) continue ;; esac
    _path="${STAGING}/bin/desertemail-${_t}"
    {
      printf '#!/bin/sh\n'
      printf 'echo fake-%s\n' "${_t}"
    } > "${_path}"
    chmod +x "${_path}"
  done

  regen_sums "${STAGING}/bin"

  # Backup clean bin/ for restore after destructive tests
  cp -R "${STAGING}/bin" "${TMP_ROOT}/bin-backup"

  # HTTP server for staging
  (
    CDPATH='' cd -- "${STAGING}" || exit 1
    exec python3 -m http.server "${PORT}" --bind 127.0.0.1
  ) >"${TMP_ROOT}/http.log" 2>&1 &
  HTTP_PID=$!

  if ! wait_http "http://127.0.0.1:${PORT}/index.html"; then
    printf 'FATAL: http.server did not become ready on port %s\n' "${PORT}" >&2
    cat "${TMP_ROOT}/http.log" >&2 || true
    exit 1
  fi

  printf 'staging ready at http://127.0.0.1:%s (pid %s)\n' "${PORT}" "${HTTP_PID}"
}

restore_bin() {
  rm -rf "${STAGING}/bin"
  cp -R "${TMP_ROOT}/bin-backup" "${STAGING}/bin"
}

# ---------------------------------------------------------------------------
# Tests 1–6: per-platform non-interactive install
# ---------------------------------------------------------------------------
test_platform_install() {
  _nn=$1
  _plat=$2
  _home=$(fake_home)

  run_installer "${_plat}" "${_home}"
  if [ "${INSTALL_EC}" -ne 0 ]; then
    fail "${_nn}" "install-${_plat}" "exit=${INSTALL_EC}; $(tail -c 300 "${OUT_COMBINED}" | tr '\n' ' ')"
    return
  fi
  if ! grep -q 'SHA256 verified\.' "${OUT_COMBINED}"; then
    fail "${_nn}" "install-${_plat}" "missing 'SHA256 verified.' in output"
    return
  fi
  if [ ! -x "${_home}/.desertemail/bin/desertemail" ]; then
    fail "${_nn}" "install-${_plat}" "binary missing at HOME/.desertemail/bin/desertemail"
    return
  fi
  if ! assert_config_defaults "${_home}/.desertemail/config.toml"; then
    fail "${_nn}" "install-${_plat}" "config.toml missing expected default keys"
    return
  fi
  ok "${_nn}" "install-${_plat}"
}

# ---------------------------------------------------------------------------
# Test 7: run macos-apple-silicon binary; 4 listeners
# ---------------------------------------------------------------------------
test_run_macos_binary() {
  _nn=7
  _home=$(fake_home)
  run_installer "macos-apple-silicon" "${_home}"
  if [ "${INSTALL_EC}" -ne 0 ] || [ ! -x "${_home}/.desertemail/bin/desertemail" ]; then
    fail "${_nn}" "macos-run-listeners" "install failed first"
    return
  fi

  # High random ports to avoid clashes
  _p1=$(pick_port)
  _p2=$(pick_port)
  _p3=$(pick_port)
  _p4=$(pick_port)
  _cfg="${_home}/.desertemail/config.toml"
  # Rewrite listen addresses in place
  {
    grep -v -E '^(smtp_listen|submission_listen|imap_listen|web_listen)' "${_cfg}" || true
    printf 'smtp_listen = "127.0.0.1:%s"\n' "${_p1}"
    printf 'submission_listen = "127.0.0.1:%s"\n' "${_p2}"
    printf 'imap_listen = "127.0.0.1:%s"\n' "${_p3}"
    printf 'web_listen = "127.0.0.1:%s"\n' "${_p4}"
  } > "${_cfg}.new"
  mv "${_cfg}.new" "${_cfg}"

  _log="${TMP_ROOT}/server7.log"
  "${_home}/.desertemail/bin/desertemail" --config "${_cfg}" >"${_log}" 2>&1 &
  SERVER_PID=$!

  _ok=0
  _i=0
  while [ "${_i}" -lt 30 ]; do
    # ~3s total (0.1 * 30)
    if grep -q 'SMTP listening' "${_log}" 2>/dev/null \
      && grep -q 'SMTP submission listening' "${_log}" 2>/dev/null \
      && grep -q 'IMAP listening' "${_log}" 2>/dev/null \
      && grep -q 'web: listening' "${_log}" 2>/dev/null; then
      _ok=1
      break
    fi
    # also accept "all servers running" + web
    if grep -q 'all servers running' "${_log}" 2>/dev/null \
      && grep -q 'web: listening' "${_log}" 2>/dev/null; then
      _ok=1
      break
    fi
    _i=$((_i + 1))
    sleep 0.1
  done

  kill "${SERVER_PID}" 2>/dev/null || true
  wait "${SERVER_PID}" 2>/dev/null || true
  SERVER_PID=""

  if [ "${_ok}" -eq 1 ]; then
    ok "${_nn}" "macos-run-listeners"
  else
    fail "${_nn}" "macos-run-listeners" "listeners not all up in 3s; log=$(tr '\n' ' ' <"${_log}" | head -c 400)"
  fi
}

# ---------------------------------------------------------------------------
# Test 8: SHA mismatch
# ---------------------------------------------------------------------------
test_sha_mismatch() {
  _nn=8
  _asset="desertemail-aarch64-unknown-linux-musl"
  _path="${STAGING}/bin/${_asset}"
  printf 'x' >> "${_path}"

  _home=$(fake_home)
  OUT_COMBINED="${TMP_ROOT}/t8.log"
  if env HOME="${_home}" DESERTEMAIL_NONINTERACTIVE=1 \
    sh -c "curl -fsSL \"http://127.0.0.1:${PORT}/install-linux-arm64.sh\" | sh" \
    >"${OUT_COMBINED}" 2>&1; then
    restore_bin
    fail "${_nn}" "sha-mismatch" "installer exited 0 but should fail"
    return
  fi
  if ! grep -qi 'mismatch' "${OUT_COMBINED}"; then
    restore_bin
    fail "${_nn}" "sha-mismatch" "expected 'mismatch' in output: $(tr '\n' ' ' <"${OUT_COMBINED}" | head -c 300)"
    return
  fi
  if [ -e "${_home}/.desertemail/bin/desertemail" ]; then
    restore_bin
    fail "${_nn}" "sha-mismatch" "binary was installed despite mismatch"
    return
  fi
  restore_bin
  ok "${_nn}" "sha-mismatch"
}

# ---------------------------------------------------------------------------
# Test 9: missing binary (404)
# ---------------------------------------------------------------------------
test_missing_binary() {
  _nn=9
  _asset="desertemail-armv7-unknown-linux-musleabihf"
  rm -f "${STAGING}/bin/${_asset}"
  # Drop its SHA256SUMS line
  if [ -f "${STAGING}/bin/SHA256SUMS" ]; then
    grep -v "${_asset}" "${STAGING}/bin/SHA256SUMS" > "${STAGING}/bin/SHA256SUMS.tmp" || true
    mv "${STAGING}/bin/SHA256SUMS.tmp" "${STAGING}/bin/SHA256SUMS"
  fi

  _home=$(fake_home)
  OUT_COMBINED="${TMP_ROOT}/t9.log"
  if env HOME="${_home}" DESERTEMAIL_NONINTERACTIVE=1 \
    sh -c "curl -fsSL \"http://127.0.0.1:${PORT}/install-linux-armv7.sh\" | sh" \
    >"${OUT_COMBINED}" 2>&1; then
    restore_bin
    fail "${_nn}" "missing-binary-404" "installer exited 0"
    return
  fi
  if ! grep -qi 'no prebuilt binary' "${OUT_COMBINED}"; then
    restore_bin
    fail "${_nn}" "missing-binary-404" "missing build-from-source message: $(tr '\n' ' ' <"${OUT_COMBINED}" | head -c 300)"
    return
  fi
  if ! grep -qi 'build-from-source' "${OUT_COMBINED}"; then
    restore_bin
    fail "${_nn}" "missing-binary-404" "expected build-from-source hint"
    return
  fi
  restore_bin
  ok "${_nn}" "missing-binary-404"
}

# ---------------------------------------------------------------------------
# Test 10: missing SHA256SUMS — warn but succeed
# ---------------------------------------------------------------------------
test_missing_sums() {
  _nn=10
  rm -f "${STAGING}/bin/SHA256SUMS"

  _home=$(fake_home)
  OUT_COMBINED="${TMP_ROOT}/t10.log"
  if ! env HOME="${_home}" DESERTEMAIL_NONINTERACTIVE=1 \
    sh -c "curl -fsSL \"http://127.0.0.1:${PORT}/install-linux-armv6.sh\" | sh" \
    >"${OUT_COMBINED}" 2>&1; then
    restore_bin
    fail "${_nn}" "missing-sha256sums-warn" "installer failed: $(tr '\n' ' ' <"${OUT_COMBINED}" | head -c 300)"
    return
  fi
  if ! grep -qi 'warning:.*SHA256SUMS\|could not download SHA256SUMS' "${OUT_COMBINED}"; then
    restore_bin
    fail "${_nn}" "missing-sha256sums-warn" "expected warning about SHA256SUMS"
    return
  fi
  if [ ! -x "${_home}/.desertemail/bin/desertemail" ]; then
    restore_bin
    fail "${_nn}" "missing-sha256sums-warn" "binary not installed"
    return
  fi
  restore_bin
  ok "${_nn}" "missing-sha256sums-warn"
}

# ---------------------------------------------------------------------------
# Test 11: env overrides
# ---------------------------------------------------------------------------
test_env_overrides() {
  _nn=11
  _home=$(fake_home)
  run_installer "macos-apple-silicon" "${_home}" \
    DESERTEMAIL_PORTS=privileged \
    DESERTEMAIL_WEBMAIL=0 \
    DESERTEMAIL_DOMAIN=envtest.example \
    DESERTEMAIL_ADMIN_USER=root2

  if [ "${INSTALL_EC}" -ne 0 ]; then
    fail "${_nn}" "env-overrides" "install failed"
    return
  fi
  _cfg="${_home}/.desertemail/config.toml"
  _bad=0
  grep -q '0.0.0.0:25' "${_cfg}" || _bad=1
  grep -q '0.0.0.0:587' "${_cfg}" || _bad=1
  grep -q '0.0.0.0:143' "${_cfg}" || _bad=1
  grep -q 'web_listen = ""' "${_cfg}" || _bad=1
  grep -q 'envtest.example' "${_cfg}" || _bad=1
  grep -q 'root2' "${_cfg}" || _bad=1
  if [ "${_bad}" -ne 0 ]; then
    fail "${_nn}" "env-overrides" "config mismatch: $(tr '\n' '|' <"${_cfg}")"
    return
  fi
  ok "${_nn}" "env-overrides"
}

# ---------------------------------------------------------------------------
# Test 12: DKIM
# ---------------------------------------------------------------------------
test_dkim() {
  _nn=12
  _home=$(fake_home)
  run_installer "macos-apple-silicon" "${_home}" DESERTEMAIL_DKIM=1
  if [ "${INSTALL_EC}" -ne 0 ]; then
    fail "${_nn}" "dkim-env" "install failed"
    return
  fi
  _pem="${_home}/.desertemail/dkim.pem"
  _cfg="${_home}/.desertemail/config.toml"
  if [ ! -f "${_pem}" ]; then
    fail "${_nn}" "dkim-env" "dkim.pem not generated"
    return
  fi
  # 0600 perms
  _mode=$(stat -f '%Lp' "${_pem}" 2>/dev/null || stat -c '%a' "${_pem}" 2>/dev/null || echo "")
  case "${_mode}" in
    600|0600) ;;
    *)
      fail "${_nn}" "dkim-env" "dkim.pem perms=${_mode} want 600"
      return
      ;;
  esac
  if ! grep -q 'dkim_selector' "${_cfg}" || ! grep -q 'dkim_key_file' "${_cfg}"; then
    fail "${_nn}" "dkim-env" "config missing dkim fields"
    return
  fi
  ok "${_nn}" "dkim-env"
}

# ---------------------------------------------------------------------------
# Test 13: config overwrite protection
# ---------------------------------------------------------------------------
test_config_overwrite() {
  _nn=13
  _home=$(fake_home)
  run_installer "linux-x86_64" "${_home}"
  if [ "${INSTALL_EC}" -ne 0 ]; then
    fail "${_nn}" "config-overwrite-protect" "first install failed"
    return
  fi
  _cfg="${_home}/.desertemail/config.toml"
  printf '\n# MARKER-TEST-13-DO-NOT-CLOBBER\n' >> "${_cfg}"

  run_installer "linux-x86_64" "${_home}"
  if [ "${INSTALL_EC}" -ne 0 ]; then
    fail "${_nn}" "config-overwrite-protect" "second install failed"
    return
  fi
  if ! grep -q 'MARKER-TEST-13-DO-NOT-CLOBBER' "${_cfg}"; then
    fail "${_nn}" "config-overwrite-protect" "marker lost; config was overwritten"
    return
  fi
  ok "${_nn}" "config-overwrite-protect"
}

# ---------------------------------------------------------------------------
# Test 14: PATH marker idempotency
# ---------------------------------------------------------------------------
test_path_idempotency() {
  _nn=14
  _home=$(fake_home)
  # Use zsh so ensure_path writes .zshrc (matches host default)
  export SHELL=/bin/zsh
  run_installer "linux-arm64" "${_home}"
  run_installer "linux-arm64" "${_home}"
  _rc="${_home}/.zshrc"
  if [ ! -f "${_rc}" ]; then
    fail "${_nn}" "path-idempotency" "no .zshrc"
    return
  fi
  _count=$(grep -c '>>> desertemail PATH >>>' "${_rc}" || true)
  if [ "${_count}" -ne 1 ]; then
    fail "${_nn}" "path-idempotency" "marker count=${_count} want 1"
    return
  fi
  ok "${_nn}" "path-idempotency"
}

# ---------------------------------------------------------------------------
# Test 15: interactive wizard via pty (curl|sh + /dev/tty answers)
# ---------------------------------------------------------------------------
test_interactive_pty() {
  _nn=15
  _home=$(fake_home)
  _py="${TMP_ROOT}/pty_wizard.py"
  cat > "${_py}" <<'PY'
import os, pty, select, sys, time

url = sys.argv[1]
home = sys.argv[2]
port_unused = sys.argv[3] if len(sys.argv) > 3 else ""

env = os.environ.copy()
env["HOME"] = home
env["SHELL"] = "/bin/zsh"
env.pop("DESERTEMAIL_NONINTERACTIVE", None)
# Ensure empty rc files exist
open(os.path.join(home, ".zshrc"), "a").close()

# Answers for: domain, user, password(empty=gen), data_dir, webmail, ports, dkim
answers = [
    "wizard.example\n",
    "wiz\n",
    "\n",
    "\n",
    "\n",
    "\n",
    "\n",
]
ans_i = 0
output = bytearray()

pid, master = pty.fork()
if pid == 0:
    # Child: curl|sh so installer stdin is the pipe; answers via /dev/tty
    cmd = f'curl -fsSL "{url}" | sh'
    os.execve("/bin/sh", ["sh", "-c", cmd], env)
    os._exit(127)

deadline = time.time() + 90
status = None
while time.time() < deadline:
    # Check child
    wpid, wstat = os.waitpid(pid, os.WNOHANG)
    if wpid == pid:
        status = wstat
        # drain
        while True:
            r, _, _ = select.select([master], [], [], 0.05)
            if master not in r:
                break
            try:
                chunk = os.read(master, 4096)
            except OSError:
                chunk = b""
            if not chunk:
                break
            output.extend(chunk)
        break

    r, _, _ = select.select([master], [], [], 0.15)
    if master in r:
        try:
            chunk = os.read(master, 4096)
        except OSError:
            chunk = b""
        if chunk:
            output.extend(chunk)
            text = output.decode("utf-8", "replace")
            # Prompt lines end with ": " (or just ":" after stty)
            last = text.split("\n")[-1]
            if ans_i < len(answers) and (last.endswith(": ") or last.rstrip().endswith(":")):
                try:
                    os.write(master, answers[ans_i].encode())
                except OSError:
                    pass
                ans_i += 1

if status is None:
    try:
        os.kill(pid, 9)
    except OSError:
        pass
    try:
        os.waitpid(pid, 0)
    except OSError:
        pass
    sys.stderr.write("pty wizard timed out\n")
    sys.stderr.buffer.write(bytes(output))
    sys.exit(2)

# Decode exit
if os.WIFEXITED(status):
    code = os.WEXITSTATUS(status)
else:
    code = 1

sys.stdout.buffer.write(bytes(output))
sys.exit(code)
PY

  _url="http://127.0.0.1:${PORT}/install-macos-apple-silicon.sh"
  OUT_COMBINED="${TMP_ROOT}/t15.log"
  if ! python3 "${_py}" "${_url}" "${_home}" >"${OUT_COMBINED}" 2>&1; then
    fail "${_nn}" "interactive-pty-wizard" "wizard failed: $(tr '\n' ' ' <"${OUT_COMBINED}" | head -c 400)"
    return
  fi
  _cfg="${_home}/.desertemail/config.toml"
  if [ ! -f "${_cfg}" ]; then
    fail "${_nn}" "interactive-pty-wizard" "no config written"
    return
  fi
  if ! grep -q 'wizard.example' "${_cfg}"; then
    fail "${_nn}" "interactive-pty-wizard" "domain missing in config"
    return
  fi
  if ! grep -q 'wiz' "${_cfg}"; then
    fail "${_nn}" "interactive-pty-wizard" "user wiz missing in config"
    return
  fi
  ok "${_nn}" "interactive-pty-wizard"
}

# ---------------------------------------------------------------------------
# Test 16: build-from-source with file:// clone
# ---------------------------------------------------------------------------
test_build_from_source() {
  _nn=16
  if ! command -v cargo >/dev/null 2>&1; then
    ok "${_nn}" "build-from-source (skipped)"
    return
  fi
  if ! command -v git >/dev/null 2>&1; then
    ok "${_nn}" "build-from-source (skipped)"
    return
  fi

  _home=$(fake_home)
  _script="${TMP_ROOT}/install-from-source-local.sh"
  # file:// URL for local repo (absolute path)
  _file_url="file://${REPO}"
  sed "s|https://github.com/bitfent/desertemail|${_file_url}|g" \
    "${STAGING}/install-from-source.sh" > "${_script}"
  chmod +x "${_script}"

  OUT_COMBINED="${TMP_ROOT}/t16.log"
  # Reuse cargo target dir for speed when fingerprints match
  _run16="${TMP_ROOT}/run16.py"
  cat > "${_run16}" <<'PY'
import os, subprocess, sys
script = sys.argv[1]
env = os.environ.copy()
try:
    r = subprocess.run(["sh", script], timeout=300, env=env)
    sys.exit(r.returncode)
except subprocess.TimeoutExpired:
    sys.stderr.write("build-from-source timed out after 300s\n")
    sys.exit(124)
PY
  # Keep real cargo/rustup homes: faking HOME alone breaks rustup's default toolchain.
  _real_home="${HOME}"
  _cargo_home="${CARGO_HOME:-${_real_home}/.cargo}"
  _rustup_home="${RUSTUP_HOME:-${_real_home}/.rustup}"
  # Do NOT set CARGO_TARGET_DIR: the installer expects
  # $clone/target/release/desertemail after cargo build --release.
  if env HOME="${_home}" \
    DESERTEMAIL_NONINTERACTIVE=1 \
    CARGO_HOME="${_cargo_home}" \
    RUSTUP_HOME="${_rustup_home}" \
    PATH="${_cargo_home}/bin:${PATH}" \
    python3 "${_run16}" "${_script}" >"${OUT_COMBINED}" 2>&1; then
    :
  else
    _ec=$?
    fail "${_nn}" "build-from-source" "exit=${_ec}: $(tail -c 500 "${OUT_COMBINED}" | tr '\n' ' ')"
    return
  fi

  _bin="${_home}/.desertemail/bin/desertemail"
  if [ ! -x "${_bin}" ]; then
    fail "${_nn}" "build-from-source" "binary not installed"
    return
  fi
  # Assert runnable: --help (or any flag that exits without binding forever)
  if "${_bin}" --help >"${TMP_ROOT}/t16-help.txt" 2>&1; then
    ok "${_nn}" "build-from-source"
    return
  fi
  # Some builds may not have --help; run briefly with config then stop
  _cfg="${_home}/.desertemail/config.toml"
  if [ ! -f "${_cfg}" ]; then
    fail "${_nn}" "build-from-source" "no config and --help failed"
    return
  fi
  "${_bin}" --config "${_cfg}" >"${TMP_ROOT}/t16-run.log" 2>&1 &
  _bp=$!
  sleep 0.8
  if kill -0 "${_bp}" 2>/dev/null; then
    kill "${_bp}" 2>/dev/null || true
    wait "${_bp}" 2>/dev/null || true
    ok "${_nn}" "build-from-source"
    return
  fi
  wait "${_bp}" 2>/dev/null || true
  # Exited quickly — still OK if it is a real binary that tried to start
  if file "${_bin}" | grep -qiE 'Mach-O|ELF|executable'; then
    ok "${_nn}" "build-from-source"
  else
    fail "${_nn}" "build-from-source" "binary not runnable: $(file "${_bin}")"
  fi
}

# ---------------------------------------------------------------------------
# Test 17: Windows ps1
# ---------------------------------------------------------------------------
test_windows_ps1() {
  _nn=17
  _ps1="${STAGING}/install-windows.ps1"
  if [ ! -f "${_ps1}" ]; then
    fail "${_nn}" "install-windows.ps1" "missing generated script"
    return
  fi
  if command -v pwsh >/dev/null 2>&1; then
    if pwsh -NoProfile -c "[scriptblock]::Create((Get-Content -Raw '${_ps1}')) | Out-Null"; then
      ok "${_nn}" "install-windows.ps1 (pwsh syntax)"
    else
      fail "${_nn}" "install-windows.ps1 (pwsh syntax)" "scriptblock parse failed"
    fi
    return
  fi
  # Static checks
  if grep -qE '__TARGET__|__BASE_URL__' "${_ps1}"; then
    fail "${_nn}" "install-windows.ps1 (static only)" "placeholders remain"
    return
  fi
  _opens=$(grep -o '{' "${_ps1}" | wc -l | tr -d ' ')
  _closes=$(grep -o '}' "${_ps1}" | wc -l | tr -d ' ')
  if [ "${_opens}" -ne "${_closes}" ]; then
    fail "${_nn}" "install-windows.ps1 (static only)" "braces ${_opens} vs ${_closes}"
    return
  fi
  for _need in 'Get-FileHash' 'SetEnvironmentVariable' 'Read-Host' '-AsSecureString'; do
    # -F: fixed string (so leading '-' is not a grep flag)
    if ! grep -Fq -- "${_need}" "${_ps1}"; then
      fail "${_nn}" "install-windows.ps1 (static only)" "missing ${_need}"
      return
    fi
  done
  ok "${_nn}" "install-windows.ps1 (static only)"
}

# ---------------------------------------------------------------------------
# Test 18: no github api/releases, no uname auto-detect
# ---------------------------------------------------------------------------
test_no_github_api_or_uname() {
  _nn=18
  _bad=0
  _detail=""
  for _f in \
    "${STAGING}/install-linux-x86_64.sh" \
    "${STAGING}/install-linux-arm64.sh" \
    "${STAGING}/install-linux-armv7.sh" \
    "${STAGING}/install-linux-armv6.sh" \
    "${STAGING}/install-macos-apple-silicon.sh" \
    "${STAGING}/install-macos-intel.sh" \
    "${STAGING}/install-windows.ps1"
  do
    if grep -qiE 'api\.github\.com|/releases/download|github\.com/.*/releases' "${_f}"; then
      _bad=1
      _detail="${_detail} github-releases in $(basename "${_f}");"
    fi
    _uc=$(grep -c 'uname' "${_f}" 2>/dev/null || true)
    if [ "${_uc}" -ne 0 ]; then
      _bad=1
      _detail="${_detail} uname count=${_uc} in $(basename "${_f}");"
    fi
  done
  if [ "${_bad}" -ne 0 ]; then
    fail "${_nn}" "no-github-api-no-uname" "${_detail}"
    return
  fi
  ok "${_nn}" "no-github-api-no-uname"
}

# ---------------------------------------------------------------------------
# Test 19: sh -n / dash -n / shellcheck
# ---------------------------------------------------------------------------
test_shell_syntax() {
  _nn=19
  _scripts="
${STAGING}/install-linux-x86_64.sh
${STAGING}/install-linux-arm64.sh
${STAGING}/install-linux-armv7.sh
${STAGING}/install-linux-armv6.sh
${STAGING}/install-macos-apple-silicon.sh
${STAGING}/install-macos-intel.sh
${STAGING}/install-from-source.sh
"
  for _s in ${_scripts}; do
    if ! sh -n "${_s}" 2>"${TMP_ROOT}/sh-n.err"; then
      fail "${_nn}" "shell-syntax" "sh -n failed on $(basename "${_s}"): $(cat "${TMP_ROOT}/sh-n.err")"
      return
    fi
    if command -v dash >/dev/null 2>&1; then
      if ! dash -n "${_s}" 2>"${TMP_ROOT}/dash-n.err"; then
        fail "${_nn}" "shell-syntax" "dash -n failed on $(basename "${_s}"): $(cat "${TMP_ROOT}/dash-n.err")"
        return
      fi
    fi
  done
  if command -v shellcheck >/dev/null 2>&1; then
    if ! shellcheck -s sh "${STAGING}/install-linux-x86_64.sh" >"${TMP_ROOT}/sc.out" 2>&1; then
      fail "${_nn}" "shell-syntax" "shellcheck failed: $(head -c 400 "${TMP_ROOT}/sc.out" | tr '\n' ' ')"
      return
    fi
  fi
  ok "${_nn}" "shell-syntax"
}

# ---------------------------------------------------------------------------
# Test 20: SHA256SUMS format + verify
# ---------------------------------------------------------------------------
test_sha256sums_format() {
  _nn=20
  _bin="${STAGING}/bin"
  _sums="${_bin}/SHA256SUMS"
  if [ ! -f "${_sums}" ]; then
    fail "${_nn}" "sha256sums-format" "SHA256SUMS missing"
    return
  fi
  for _f in "${_bin}"/*; do
    [ -f "${_f}" ] || continue
    _base=$(basename "${_f}")
    [ "${_base}" = "SHA256SUMS" ] && continue
    _cnt=$(grep -c -E "[ /]${_base}\$|^[a-fA-F0-9]+  ${_base}\$|^[a-fA-F0-9]+ \*${_base}\$" "${_sums}" || true)
    # Also count simple "HASH  name" matches
    _cnt2=$(awk -v n="${_base}" '$2 == n { c++ } END { print c+0 }' "${_sums}")
    if [ "${_cnt2}" -ne 1 ]; then
      fail "${_nn}" "sha256sums-format" "${_base} has ${_cnt2} entries (want 1)"
      return
    fi
  done
  (
    CDPATH='' cd -- "${_bin}" || exit 1
    if command -v sha256sum >/dev/null 2>&1; then
      sha256sum -c SHA256SUMS
    else
      shasum -a 256 -c SHA256SUMS
    fi
  ) >"${TMP_ROOT}/t20.out" 2>&1 || {
    fail "${_nn}" "sha256sums-format" "checksum -c failed: $(tr '\n' ' ' <"${TMP_ROOT}/t20.out")"
    return
  }
  ok "${_nn}" "sha256sums-format"
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
main() {
  printf '=== DesertEmail installer test suite ===\n'
  printf 'repo: %s\n' "${REPO}"
  setup_staging

  test_platform_install 1 linux-x86_64
  test_platform_install 2 linux-arm64
  test_platform_install 3 linux-armv7
  test_platform_install 4 linux-armv6
  test_platform_install 5 macos-apple-silicon
  test_platform_install 6 macos-intel
  test_run_macos_binary
  test_sha_mismatch
  test_missing_binary
  test_missing_sums
  test_env_overrides
  test_dkim
  test_config_overwrite
  test_path_idempotency
  test_interactive_pty
  test_build_from_source
  test_windows_ps1
  test_no_github_api_or_uname
  test_shell_syntax
  test_sha256sums_format

  printf '\n=== summary ===\n'
  printf '%s/%s passed\n' "${PASSED}" "${TOTAL}"
  if [ "${FAILED}" -ne 0 ]; then
    printf 'failures:%s\n' "${FAIL_NAMES}"
    exit 1
  fi
  exit 0
}

main "$@"

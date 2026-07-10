#!/bin/sh
# DesertEmail build-from-source installer (unsupported / other platforms).
# Usage:  curl -fsSL https://<site>/install-from-source.sh | sh
# Optional env:
#   DESERTEMAIL_PREFIX, DESERTEMAIL_NONINTERACTIVE=1
#   DESERTEMAIL_DOMAIN, DESERTEMAIL_ADMIN_USER, DESERTEMAIL_ADMIN_PASSWORD
#   DESERTEMAIL_DATA_DIR, DESERTEMAIL_WEBMAIL=1|0, DESERTEMAIL_PORTS=high|privileged
#   DESERTEMAIL_DKIM=1|0, DESERTEMAIL_SYSTEMD=1|0
#
# Requires: git, cargo (https://rustup.rs). Clones the source repo and compiles.

set -eu

APP_NAME="desertemail"
SOURCE_REPO="https://github.com/bitfent/desertemail"
DEFAULT_PREFIX="${HOME}/.desertemail"
PREFIX="${DESERTEMAIL_PREFIX:-$DEFAULT_PREFIX}"
BIN_DIR="${PREFIX}/bin"
CONFIG_PATH="${PREFIX}/config.toml"
TMPDIR_INSTALL=""
INTERACTIVE=1

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

die() {
  printf '%s\n' "error: $*" >&2
  exit 1
}

info() {
  printf '%s\n' "$*"
}

warn() {
  printf '%s\n' "warning: $*" >&2
}

cleanup() {
  if [ -n "${TMPDIR_INSTALL}" ] && [ -d "${TMPDIR_INSTALL}" ]; then
    rm -rf "${TMPDIR_INSTALL}"
  fi
  # Restore terminal echo if we left it off
  if [ -n "${TTY_IN}" ]; then
    stty echo <"${TTY_IN}" 2>/dev/null || true
  elif [ -t 0 ] 2>/dev/null; then
    stty echo 2>/dev/null || true
  fi
}
trap cleanup EXIT INT HUP TERM

# Interactivity: with `curl ... | sh` stdin is the pipe, not the terminal, so
# prompts must read from /dev/tty when it is available. Only fall back to
# non-interactive when there is genuinely no controlling terminal (CI, cron)
# or the user asked for it.
TTY_IN=""
if [ "${DESERTEMAIL_NONINTERACTIVE:-0}" = "1" ]; then
  INTERACTIVE=0
elif [ -t 0 ]; then
  INTERACTIVE=1
elif (exec 3</dev/tty) 2>/dev/null; then
  INTERACTIVE=1
  TTY_IN=/dev/tty
else
  INTERACTIVE=0
fi

read_reply() {
  # Read one line into REPLY from the terminal (or stdin when it is a TTY).
  if [ -n "${TTY_IN}" ]; then
    IFS= read -r REPLY <"${TTY_IN}" || true
  else
    IFS= read -r REPLY || true
  fi
}

stty_echo_off() {
  if [ -n "${TTY_IN}" ]; then
    stty -echo <"${TTY_IN}" 2>/dev/null || true
  else
    stty -echo 2>/dev/null || true
  fi
}

stty_echo_on() {
  if [ -n "${TTY_IN}" ]; then
    stty echo <"${TTY_IN}" 2>/dev/null || true
  else
    stty echo 2>/dev/null || true
  fi
}

toml_escape() {
  # Escape for double-quoted TOML strings
  printf '%s' "$1" | sed 's/\\/\\\\/g; s/"/\\"/g'
}

prompt() {
  # prompt "Question" "default" -> sets REPLY
  _q=$1
  _def=$2
  if [ "${INTERACTIVE}" -eq 0 ]; then
    REPLY="${_def}"
    return 0
  fi
  if [ -n "${_def}" ]; then
    printf '%s [%s]: ' "${_q}" "${_def}"
  else
    printf '%s: ' "${_q}"
  fi
  read_reply
  if [ -z "${REPLY}" ]; then
    REPLY="${_def}"
  fi
}

prompt_secret() {
  # prompt_secret "Question" "default_if_empty" -> sets REPLY (never echoes input)
  _q=$1
  _def=$2
  if [ "${INTERACTIVE}" -eq 0 ]; then
    REPLY="${_def}"
    return 0
  fi
  printf '%s [hidden, Enter=generate]: ' "${_q}"
  stty_echo_off
  read_reply
  stty_echo_on
  printf '\n'
  if [ -z "${REPLY}" ]; then
    REPLY="${_def}"
  fi
}

yes_no() {
  # yes_no "Question" "Y|N" -> sets REPLY to y or n
  _q=$1
  _def=$2
  if [ "${INTERACTIVE}" -eq 0 ]; then
    case "${_def}" in
      Y|y|yes|YES) REPLY=y ;;
      *) REPLY=n ;;
    esac
    return 0
  fi
  printf '%s [%s]: ' "${_q}" "${_def}"
  read_reply
  if [ -z "${REPLY}" ]; then
    REPLY="${_def}"
  fi
  case "${REPLY}" in
    Y|y|yes|YES) REPLY=y ;;
    *) REPLY=n ;;
  esac
}

random_password() {
  # ~16 chars from base64(/dev/urandom)
  if [ -r /dev/urandom ]; then
    _pw=$(dd if=/dev/urandom bs=12 count=1 2>/dev/null | base64 2>/dev/null | tr -d '\n=+/')
    # base64 of 12 bytes is 16 chars before padding; trim to 16
    printf '%s' "${_pw}" | cut -c1-16
  else
    # Extremely weak fallback; should almost never hit
    printf 'change-me-%s' "$$"
  fi
}

# ---------------------------------------------------------------------------
# Toolchain + RAM checks, then build from source
# ---------------------------------------------------------------------------

check_tools() {
  _missing=0
  if ! command -v git >/dev/null 2>&1; then
    warn "git is not installed"
    _missing=1
  fi
  if ! command -v cargo >/dev/null 2>&1; then
    warn "cargo is not installed"
    _missing=1
  fi
  if [ "${_missing}" -ne 0 ]; then
    die "need git and cargo to build from source. Install Rust from https://rustup.rs then re-run this installer."
  fi
}

check_ram() {
  # Warn if total RAM < ~1 GB. Skip if we cannot determine.
  _mb=""
  if [ -r /proc/meminfo ]; then
    _kb=$(awk '/^MemTotal:/ {print $2; exit}' /proc/meminfo 2>/dev/null || true)
    if [ -n "${_kb}" ]; then
      _mb=$((_kb / 1024))
    fi
  elif command -v sysctl >/dev/null 2>&1; then
    _bytes=$(sysctl -n hw.memsize 2>/dev/null || true)
    if [ -n "${_bytes}" ] && [ "${_bytes}" -gt 0 ] 2>/dev/null; then
      _mb=$((_bytes / 1024 / 1024))
    fi
  fi
  if [ -n "${_mb}" ] && [ "${_mb}" -lt 1024 ]; then
    warn "system reports ~${_mb} MB RAM; compiling Rust may be slow or run out of memory"
  fi
}

install_from_source() {
  check_tools
  check_ram

  TMPDIR_INSTALL=$(mktemp -d 2>/dev/null || mktemp -d -t desertemail)
  _src="${TMPDIR_INSTALL}/src"

  info "Cloning ${SOURCE_REPO} ..."
  git clone --depth 1 "${SOURCE_REPO}" "${_src}" \
    || die "git clone failed"

  info "Building release binary (this may take several minutes) ..."
  (
    CDPATH='' cd -- "${_src}" || exit 1
    cargo build --release
  ) || die "cargo build --release failed"

  _built="${_src}/target/release/${APP_NAME}"
  if [ ! -f "${_built}" ]; then
    die "build succeeded but binary not found at ${_built}"
  fi

  mkdir -p "${BIN_DIR}"
  _dest="${BIN_DIR}/${APP_NAME}"
  cp "${_built}" "${_dest}"
  chmod +x "${_dest}"
  info "Installed binary -> ${_dest}"
}

# ---------------------------------------------------------------------------
# PATH wiring
# ---------------------------------------------------------------------------

PATH_MARKER_BEGIN="# >>> desertemail PATH >>>"
PATH_MARKER_END="# <<< desertemail PATH <<<"

ensure_path() {
  case ":${PATH}:" in
    *":${BIN_DIR}:"*) return 0 ;;
  esac

  _block=$(
    printf '%s\n' "${PATH_MARKER_BEGIN}"
    printf "export PATH=\"%s:\$PATH\"\n" "${BIN_DIR}"
    printf '%s\n' "${PATH_MARKER_END}"
  )

  _shell_name=$(basename "${SHELL:-}")
  _rc=""
  case "${_shell_name}" in
    zsh)  _rc="${HOME}/.zshrc" ;;
    bash) _rc="${HOME}/.bashrc" ;;
    fish)
      _fish_dir="${HOME}/.config/fish"
      mkdir -p "${_fish_dir}"
      _rc="${_fish_dir}/config.fish"
      _block=$(
        printf '%s\n' "${PATH_MARKER_BEGIN}"
        printf "set -gx PATH \"%s\" \$PATH\n" "${BIN_DIR}"
        printf '%s\n' "${PATH_MARKER_END}"
      )
      ;;
    *)
      # Fall back to .profile (POSIX)
      _rc="${HOME}/.profile"
      ;;
  esac

  if [ -f "${_rc}" ] && grep -F "${PATH_MARKER_BEGIN}" "${_rc}" >/dev/null 2>&1; then
    info "PATH already configured in ${_rc}"
    return 0
  fi

  info "Adding ${BIN_DIR} to PATH via ${_rc}"
  printf '\n%s\n' "${_block}" >> "${_rc}"
  export PATH="${BIN_DIR}:${PATH}"
}

# ---------------------------------------------------------------------------
# Config wizard
# ---------------------------------------------------------------------------

write_config() {
  _domain=$1
  _admin=$2
  _password=$3
  _data_dir=$4
  _web_listen=$5
  _smtp=$6
  _sub=$7
  _imap=$8
  _dkim_key=$9

  _esc_pw=$(toml_escape "${_password}")
  _esc_admin=$(toml_escape "${_admin}")
  _esc_domain=$(toml_escape "${_domain}")
  _esc_data=$(toml_escape "${_data_dir}")
  _esc_web=$(toml_escape "${_web_listen}")
  _esc_smtp=$(toml_escape "${_smtp}")
  _esc_sub=$(toml_escape "${_sub}")
  _esc_imap=$(toml_escape "${_imap}")

  {
    printf '# Generated by desertemail installer — edit as needed\n'
    printf 'domains = ["%s"]\n' "${_esc_domain}"
    printf 'data_dir = "%s"\n' "${_esc_data}"
    printf 'smtp_listen = "%s"\n' "${_esc_smtp}"
    printf 'submission_listen = "%s"\n' "${_esc_sub}"
    printf 'imap_listen = "%s"\n' "${_esc_imap}"
    printf 'web_listen = "%s"\n' "${_esc_web}"
    printf 'admin_user = "%s"\n' "${_esc_admin}"
    printf 'catch_all = true\n'
    printf 'default_password = "%s"\n' "${_esc_pw}"
    if [ -n "${_dkim_key}" ]; then
      _esc_dkim=$(toml_escape "${_dkim_key}")
      printf 'dkim_selector = "mail"\n'
      printf 'dkim_key_file = "%s"\n' "${_esc_dkim}"
    fi
    printf '\n[users]\n'
    printf '"%s" = "%s"\n' "${_esc_admin}" "${_esc_pw}"
  } > "${CONFIG_PATH}"

  chmod 600 "${CONFIG_PATH}" 2>/dev/null || true
}

configure() {
  info ""
  info "=== DesertEmail setup ==="
  info ""

  # Defaults from env or sensible values
  _def_domain="${DESERTEMAIL_DOMAIN:-localhost}"
  _def_admin="${DESERTEMAIL_ADMIN_USER:-admin}"
  _def_data="${DESERTEMAIL_DATA_DIR:-${PREFIX}/data}"
  _gen_pw=$(random_password)
  _def_pw="${DESERTEMAIL_ADMIN_PASSWORD:-${_gen_pw}}"

  if [ "${INTERACTIVE}" -eq 1 ]; then
    prompt "Primary domain" "${_def_domain}"
    DOMAIN="${REPLY}"

    prompt "Admin username" "${_def_admin}"
    ADMIN_USER="${REPLY}"

    prompt_secret "Admin password" "${_def_pw}"
    ADMIN_PASSWORD="${REPLY}"

    prompt "Data directory" "${_def_data}"
    DATA_DIR="${REPLY}"

    yes_no "Enable webmail?" "Y"
    if [ "${REPLY}" = "y" ]; then
      WEB_LISTEN="0.0.0.0:8080"
    else
      WEB_LISTEN=""
    fi

    info "Ports:"
    info "  1) high (2525/2587/2143) — no root required [default]"
    info "  2) privileged (25/587/143) — needs CAP_NET_BIND_SERVICE or root"
    prompt "Port set (high/privileged)" "high"
    PORT_SET="${REPLY}"

    yes_no "Enable DKIM signing?" "N"
    ENABLE_DKIM="${REPLY}"
  else
    DOMAIN="${_def_domain}"
    ADMIN_USER="${_def_admin}"
    ADMIN_PASSWORD="${_def_pw}"
    DATA_DIR="${_def_data}"
    case "${DESERTEMAIL_WEBMAIL:-1}" in
      0|n|N|false|FALSE|no|NO) WEB_LISTEN="" ;;
      *) WEB_LISTEN="0.0.0.0:8080" ;;
    esac
    PORT_SET="${DESERTEMAIL_PORTS:-high}"
    case "${DESERTEMAIL_DKIM:-0}" in
      1|y|Y|true|TRUE|yes|YES) ENABLE_DKIM=y ;;
      *) ENABLE_DKIM=n ;;
    esac
  fi

  case "${PORT_SET}" in
    privileged|priv|2)
      SMTP_LISTEN="0.0.0.0:25"
      SUB_LISTEN="0.0.0.0:587"
      IMAP_LISTEN="0.0.0.0:143"
      ;;
    *)
      SMTP_LISTEN="0.0.0.0:2525"
      SUB_LISTEN="0.0.0.0:2587"
      IMAP_LISTEN="0.0.0.0:2143"
      ;;
  esac

  DKIM_KEY=""
  if [ "${ENABLE_DKIM}" = "y" ]; then
    if command -v openssl >/dev/null 2>&1; then
      DKIM_KEY="${PREFIX}/dkim.pem"
      if [ ! -f "${DKIM_KEY}" ]; then
        info "Generating DKIM key at ${DKIM_KEY} ..."
        openssl genrsa -out "${DKIM_KEY}" 2048 2>/dev/null \
          || die "openssl genrsa failed"
        chmod 600 "${DKIM_KEY}" 2>/dev/null || true
      else
        info "Using existing DKIM key ${DKIM_KEY}"
      fi
    else
      warn "openssl not found; skipping DKIM key generation"
      DKIM_KEY=""
    fi
  fi

  mkdir -p "${PREFIX}"
  mkdir -p "${DATA_DIR}"

  if [ -f "${CONFIG_PATH}" ]; then
    if [ "${INTERACTIVE}" -eq 1 ]; then
      yes_no "Config already exists at ${CONFIG_PATH}. Overwrite?" "N"
      if [ "${REPLY}" != "y" ]; then
        info "Keeping existing config."
        SKIP_CONFIG=1
      else
        SKIP_CONFIG=0
      fi
    else
      info "Config already exists; keeping it (non-interactive)."
      SKIP_CONFIG=1
    fi
  else
    SKIP_CONFIG=0
  fi

  if [ "${SKIP_CONFIG}" -eq 0 ]; then
    write_config \
      "${DOMAIN}" \
      "${ADMIN_USER}" \
      "${ADMIN_PASSWORD}" \
      "${DATA_DIR}" \
      "${WEB_LISTEN}" \
      "${SMTP_LISTEN}" \
      "${SUB_LISTEN}" \
      "${IMAP_LISTEN}" \
      "${DKIM_KEY}"
    info "Wrote config -> ${CONFIG_PATH}"
  fi
}

# ---------------------------------------------------------------------------
# Optional systemd unit
# ---------------------------------------------------------------------------

install_systemd() {
  _bin="${BIN_DIR}/${APP_NAME}"
  _want_systemd=0

  if [ ! -d /run/systemd/system ] && [ ! -d /etc/systemd/system ]; then
    return 0
  fi
  if ! command -v systemctl >/dev/null 2>&1; then
    return 0
  fi

  if [ "${INTERACTIVE}" -eq 1 ]; then
    yes_no "Install and enable systemd unit (desertemail.service)?" "N"
    if [ "${REPLY}" = "y" ]; then
      _want_systemd=1
    fi
  else
    case "${DESERTEMAIL_SYSTEMD:-0}" in
      1|y|Y|true|TRUE|yes|YES) _want_systemd=1 ;;
      *) _want_systemd=0 ;;
    esac
  fi

  if [ "${_want_systemd}" -eq 0 ]; then
    return 0
  fi

  _unit_body=""
  _svc_user=$(id -un 2>/dev/null || echo root)
  _svc_group=$(id -gn 2>/dev/null || echo "${_svc_user}")

  # Prefer template from a source checkout if present next to this script.
  _script_dir=$(CDPATH='' cd -- "$(dirname -- "$0" 2>/dev/null || echo .)" && pwd 2>/dev/null || echo "")
  _template=""
  if [ -n "${_script_dir}" ] && [ -f "${_script_dir}/deploy/desertemail.service" ]; then
    _template="${_script_dir}/deploy/desertemail.service"
  elif [ -f "./deploy/desertemail.service" ]; then
    _template="./deploy/desertemail.service"
  fi

  if [ -n "${_template}" ]; then
    # Adapt paths from the checked-in unit template.
    _unit_body=$(
      sed \
        -e "s|ExecStart=.*|ExecStart=${_bin} --config ${CONFIG_PATH}|" \
        -e "s|WorkingDirectory=.*|WorkingDirectory=${PREFIX}|" \
        -e "s|^User=.*|User=${_svc_user}|" \
        -e "s|^Group=.*|Group=${_svc_group}|" \
        "${_template}"
    )
    # Ensure capability for privileged ports if missing from the template.
    if ! printf '%s\n' "${_unit_body}" | grep -q AmbientCapabilities; then
      _unit_body=$(
        printf '%s\n' "${_unit_body}" | while IFS= read -r _line || [ -n "${_line}" ]; do
          printf '%s\n' "${_line}"
          if [ "${_line}" = "[Service]" ]; then
            printf '%s\n' "AmbientCapabilities=CAP_NET_BIND_SERVICE"
          fi
        done
      )
    fi
  else
    _unit_body=$(cat <<EOF
[Unit]
Description=DesertEmail minimal email server
After=network.target

[Service]
Type=simple
User=${_svc_user}
Group=${_svc_group}
WorkingDirectory=${PREFIX}
ExecStart=${_bin} --config ${CONFIG_PATH}
Restart=on-failure
RestartSec=5
AmbientCapabilities=CAP_NET_BIND_SERVICE

[Install]
WantedBy=multi-user.target
EOF
)
  fi

  _unit_path="/etc/systemd/system/desertemail.service"
  _wrote=0
  if [ "$(id -u)" -eq 0 ]; then
    printf '%s\n' "${_unit_body}" > "${_unit_path}"
    _wrote=1
  elif command -v sudo >/dev/null 2>&1; then
    if [ "${INTERACTIVE}" -eq 1 ]; then
      info "Need root to install systemd unit at ${_unit_path}"
      if printf '%s\n' "${_unit_body}" | sudo tee "${_unit_path}" >/dev/null; then
        _wrote=1
      else
        warn "sudo install of unit failed"
      fi
    else
      # Non-interactive: only if passwordless sudo works
      if sudo -n true 2>/dev/null; then
        if printf '%s\n' "${_unit_body}" | sudo -n tee "${_unit_path}" >/dev/null; then
          _wrote=1
        else
          warn "could not write systemd unit"
        fi
      else
        warn "systemd unit requested but not root and no passwordless sudo; skipping"
      fi
    fi
  else
    warn "not root and no sudo; skipping systemd unit"
  fi

  if [ "${_wrote}" -eq 1 ]; then
    if [ "$(id -u)" -eq 0 ]; then
      systemctl daemon-reload
      if systemctl enable --now desertemail.service; then
        info "systemd: desertemail.service enabled and started"
      else
        warn "systemctl enable/start failed"
      fi
    else
      sudo systemctl daemon-reload
      if sudo systemctl enable --now desertemail.service; then
        info "systemd: desertemail.service enabled and started"
      else
        warn "systemctl enable/start failed"
      fi
    fi
  fi
}

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------

print_summary() {
  _bin="${BIN_DIR}/${APP_NAME}"
  info ""
  info "========================================"
  info " DesertEmail install complete"
  info "========================================"
  info " Binary : ${_bin}"
  info " Config : ${CONFIG_PATH}"
  info " Prefix : ${PREFIX}"
  info " Ports  : SMTP ${SMTP_LISTEN:-?} | submission ${SUB_LISTEN:-?} | IMAP ${IMAP_LISTEN:-?}"
  if [ -n "${WEB_LISTEN:-}" ]; then
    info " Webmail: http://127.0.0.1:8080  (listen ${WEB_LISTEN})"
  else
    info " Webmail: disabled"
  fi
  info ""
  info "Start manually:"
  info "  ${_bin} --config ${CONFIG_PATH}"
  info ""
  info "If PATH was updated, open a new shell or:"
  info "  export PATH=\"${BIN_DIR}:\$PATH\""
  info ""

  if [ -n "${DKIM_KEY:-}" ] && [ -f "${DKIM_KEY}" ]; then
    info "DNS records to publish for domain '${DOMAIN}':"
    info "  MX  ${DOMAIN}.  10  <your-server-hostname>."
    info "  A   <your-server-hostname>.  <your-public-ip>"
    info "  TXT ${DOMAIN}.  \"v=spf1 mx ~all\""
    info ""
    info "DKIM TXT (from binary --dkim-dns):"
    if "${_bin}" --dkim-dns "${DOMAIN}" --config "${CONFIG_PATH}" 2>/dev/null; then
      :
    else
      # Some builds accept flags in either order; try again reversed if needed
      "${_bin}" --config "${CONFIG_PATH}" --dkim-dns "${DOMAIN}" 2>/dev/null \
        || warn "could not run --dkim-dns; run: ${_bin} --dkim-dns ${DOMAIN} --config ${CONFIG_PATH}"
    fi
  else
    info "DNS (when going public): MX + A/AAAA + SPF TXT for your domain."
  fi
  info ""
  info "Admin password is stored in ${CONFIG_PATH} (not shown here)."
  info "========================================"
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

main() {
  info "DesertEmail installer (build from source)"

  install_from_source
  ensure_path
  configure
  install_systemd
  print_summary
}

main "$@"

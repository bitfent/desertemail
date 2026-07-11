#!/bin/sh
# DesertEmail build-from-source installer (unsupported / other platforms).
# Usage:  curl -fsSL https://<site>/install-from-source.sh | sh
# Optional env:
#   DESERTEMAIL_PREFIX, DESERTEMAIL_NONINTERACTIVE=1
#   DESERTEMAIL_DOMAIN, DESERTEMAIL_ADMIN_USER, DESERTEMAIL_ADMIN_PASSWORD
#   DESERTEMAIL_DATA_DIR, DESERTEMAIL_WEBMAIL=1|0, DESERTEMAIL_PORTS=high|privileged
#   DESERTEMAIL_DKIM=1|0, DESERTEMAIL_SYSTEMD=1|0
#   DESERTEMAIL_AUTOSTART=1|0  (default: 1 interactive, 0 non-interactive)
#   (re-install) non-interactive keeps existing config; interactive offers keep/fresh
#
# Requires: git, cargo (https://rustup.rs). Clones the source repo and compiles.

set -eu

APP_NAME="desertemail"
SOURCE_REPO="https://github.com/bitfent/desertemail"
DEFAULT_PREFIX="${HOME}/.desertemail"
PREFIX="${DESERTEMAIL_PREFIX:-$DEFAULT_PREFIX}"
BIN_DIR="${PREFIX}/bin"
CONFIG_PATH="${PREFIX}/config.toml"
LOG_PATH="${PREFIX}/desertemail.log"
LAUNCHD_LABEL="org.desertemail"
LAUNCHD_PLIST=""
TMPDIR_INSTALL=""
INTERACTIVE=1
SHOW_ADMIN_PASSWORD=0
# 1 = interactive express: empty [users], finish setup in the browser
SETUP_VIA_BROWSER=0
SERVER_STARTED=0
SYSTEMD_INSTALLED=0
LAUNCHD_INSTALLED=0

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

use_color() {
  if [ -t 1 ] 2>/dev/null && [ "${TERM:-}" != "dumb" ] && [ -n "${TERM:-}" ]; then
    return 0
  fi
  return 1
}

print_logo() {
  # Figlet-style DESERTEMAIL + pixel cactus; ≤80 cols, ≤12 lines.
  # POSIX printf %s does NOT interpret \033 in arguments — embed a real ESC byte.
  if use_color; then
    _esc=$(printf '\033')
    _sand="${_esc}[38;5;180m"
    _orange="${_esc}[38;5;208m"
    _cactus="${_esc}[38;5;107m"
    _rst="${_esc}[0m"
  else
    _sand=''
    _orange=''
    _cactus=''
    _rst=''
  fi
  printf '%s\n' ""
  printf '%s\n' "${_cactus}      .${_rst}"
  printf '%s\n' "${_cactus}     /|\\  ${_orange} ____  _____ ____  _____ ____ _____ _____ __  __    _    ___ _     ${_rst}"
  printf '%s\n' "${_cactus}    / | \\ ${_orange}|  _ \\| ____/ ___|| ____|  _ \\_   _| ____|  \\/  |  / \\  |_ _| |    ${_rst}"
  printf '%s\n' "${_cactus}    \\ | / ${_orange}| | | |  _| \\___ \\|  _| | |_) || | |  _| | |\\/| | / _ \\  | || |    ${_rst}"
  printf '%s\n' "${_cactus}     \\|/  ${_orange}| |_| | |___ ___) | |___|  _ < | | | |___| |  | |/ ___ \\ | || |___ ${_rst}"
  printf '%s\n' "${_cactus}      |   ${_orange}|____/|_____|____/|_____|_| \\_\\|_| |_____|_|  |_/_/   \\_\\___|_____|${_rst}"
  printf '%s\n' "${_cactus}     / \\${_rst}"
  printf '%s\n' "${_sand}  your own email server — one command${_rst}"
  printf '%s\n' ""
}

step() {
  info ""
  info "[$1/4] $2"
  info "----------------------------------------"
}

cleanup() {
  if [ -n "${TMPDIR_INSTALL}" ] && [ -d "${TMPDIR_INSTALL}" ]; then
    rm -rf "${TMPDIR_INSTALL}"
  fi
  if [ -n "${TTY_IN}" ]; then
    stty echo <"${TTY_IN}" 2>/dev/null || true
  elif [ -t 0 ] 2>/dev/null; then
    stty echo 2>/dev/null || true
  fi
}
trap cleanup EXIT INT HUP TERM

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
  printf '%s' "$1" | sed 's/\\/\\\\/g; s/"/\\"/g'
}

prompt() {
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
  _q=$1
  _def=$2
  SECRET_WAS_DEFAULT=0
  if [ "${INTERACTIVE}" -eq 0 ]; then
    REPLY="${_def}"
    SECRET_WAS_DEFAULT=1
    return 0
  fi
  printf '%s [hidden, Enter=generate]: ' "${_q}"
  stty_echo_off
  read_reply
  stty_echo_on
  printf '\n'
  if [ -z "${REPLY}" ]; then
    REPLY="${_def}"
    SECRET_WAS_DEFAULT=1
  fi
}

yes_no() {
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
  if [ -r /dev/urandom ]; then
    _pw=$(dd if=/dev/urandom bs=12 count=1 2>/dev/null | base64 2>/dev/null | tr -d '\n=+/')
    printf '%s' "${_pw}" | cut -c1-16
  else
    printf 'change-me-%s' "$$"
  fi
}

is_darwin() {
  [ "$(uname -s 2>/dev/null || true)" = "Darwin" ]
}

web_url() {
  if [ "${SETUP_VIA_BROWSER:-0}" -eq 1 ]; then
    printf '%s' "http://127.0.0.1:8080/setup"
  else
    printf '%s' "http://127.0.0.1:8080"
  fi
}

# ---------------------------------------------------------------------------
# Previous-instance detection / fresh-install cleanup
# ---------------------------------------------------------------------------

PATH_MARKER_BEGIN="# >>> desertemail PATH >>>"
PATH_MARKER_END="# <<< desertemail PATH <<<"

parse_existing_data_dir() {
  EXISTING_DATA_DIR=""
  if [ -f "${CONFIG_PATH}" ]; then
    _line=$(grep -E '^[[:space:]]*data_dir[[:space:]]*=' "${CONFIG_PATH}" 2>/dev/null | head -n 1 || true)
    if [ -n "${_line}" ]; then
      EXISTING_DATA_DIR=$(printf '%s' "${_line}" | sed \
        -e 's/^[[:space:]]*data_dir[[:space:]]*=[[:space:]]*//' \
        -e 's/^"//' -e 's/"[[:space:]]*$//' \
        -e "s/^'//" -e "s/'[[:space:]]*$//" \
        -e 's/[[:space:]]*$//')
    fi
  fi
  if [ -z "${EXISTING_DATA_DIR}" ] && [ -d "${PREFIX}/data" ]; then
    EXISTING_DATA_DIR="${PREFIX}/data"
  fi
}

stop_existing_instance() {
  _bin="${BIN_DIR}/${APP_NAME}"
  if is_darwin && command -v launchctl >/dev/null 2>&1; then
    _plist="${HOME}/Library/LaunchAgents/${LAUNCHD_LABEL}.plist"
    launchctl bootout "gui/$(id -u)/${LAUNCHD_LABEL}" 2>/dev/null || true
    if [ -f "${_plist}" ]; then
      launchctl unload "${_plist}" 2>/dev/null || true
    fi
  fi
  if command -v systemctl >/dev/null 2>&1; then
    if [ "$(id -u)" -eq 0 ]; then
      systemctl stop desertemail 2>/dev/null || true
      systemctl stop desertemail.service 2>/dev/null || true
    elif command -v sudo >/dev/null 2>&1 && sudo -n true 2>/dev/null; then
      sudo -n systemctl stop desertemail 2>/dev/null || true
      sudo -n systemctl stop desertemail.service 2>/dev/null || true
    fi
  fi
  if [ -e "${_bin}" ]; then
    _me=$(id -u)
    if command -v pgrep >/dev/null 2>&1; then
      _pgrep_out=$(pgrep -u "${_me}" -f "${_bin}" 2>/dev/null || true)
      if [ -n "${_pgrep_out}" ]; then
        printf '%s\n' "${_pgrep_out}" | while IFS= read -r _pid || [ -n "${_pid}" ]; do
          [ -n "${_pid}" ] || continue
          case "${_pid}" in
            ''|*[!0-9]*) continue ;;
          esac
          if [ "${_pid}" -eq "$$" ] 2>/dev/null; then
            continue
          fi
          kill "${_pid}" 2>/dev/null || true
          sleep 0.2 2>/dev/null || true
          kill -9 "${_pid}" 2>/dev/null || true
        done
      fi
    else
      # shellcheck disable=SC2009
      ps -ax -o pid=,uid=,command= 2>/dev/null | while IFS= read -r _line || [ -n "${_line}" ]; do
        case "${_line}" in
          *"${_bin}"*)
            _pid=$(printf '%s' "${_line}" | awk '{print $1}')
            _uid=$(printf '%s' "${_line}" | awk '{print $2}')
            case "${_pid}" in
              ''|*[!0-9]*) continue ;;
            esac
            if [ "${_uid}" = "${_me}" ] && [ "${_pid}" -ne "$$" ] 2>/dev/null; then
              kill "${_pid}" 2>/dev/null || true
              sleep 0.2 2>/dev/null || true
              kill -9 "${_pid}" 2>/dev/null || true
            fi
            ;;
        esac
      done || true
    fi
  fi
}

fresh_install_cleanup() {
  # Parse data_dir before config is deleted.
  parse_existing_data_dir

  info "Fresh install: stopping previous instance and clearing old files ..."
  stop_existing_instance

  _plist="${HOME}/Library/LaunchAgents/${LAUNCHD_LABEL}.plist"
  if [ -f "${_plist}" ]; then
    rm -f "${_plist}"
    info "Removed ${_plist}"
  fi

  _bin="${BIN_DIR}/${APP_NAME}"
  if [ -e "${_bin}" ]; then
    rm -f "${_bin}"
    info "Removed ${_bin}"
  fi
  if [ -f "${CONFIG_PATH}" ]; then
    rm -f "${CONFIG_PATH}"
    info "Removed ${CONFIG_PATH}"
  fi
  if [ -f "${PREFIX}/dkim.pem" ]; then
    rm -f "${PREFIX}/dkim.pem"
    info "Removed ${PREFIX}/dkim.pem"
  fi
  if [ -f "${LOG_PATH}" ]; then
    rm -f "${LOG_PATH}"
  fi

  if [ -z "${EXISTING_DATA_DIR}" ] && [ -d "${PREFIX}/data" ]; then
    EXISTING_DATA_DIR="${PREFIX}/data"
  fi

  if [ -n "${EXISTING_DATA_DIR}" ] && [ -d "${EXISTING_DATA_DIR}" ]; then
    if [ "${INTERACTIVE}" -eq 1 ]; then
      yes_no "Also delete all mail data at ${EXISTING_DATA_DIR}?" "N"
      if [ "${REPLY}" = "y" ]; then
        rm -rf "${EXISTING_DATA_DIR}"
        info "Removed mail data at ${EXISTING_DATA_DIR}"
      else
        info "Keeping mail data at ${EXISTING_DATA_DIR}"
      fi
    else
      info "Keeping mail data at ${EXISTING_DATA_DIR}"
    fi
  fi
}

maybe_handle_existing_install() {
  _bin="${BIN_DIR}/${APP_NAME}"
  _has=0
  if [ -e "${_bin}" ] || [ -f "${CONFIG_PATH}" ]; then
    _has=1
  fi
  if [ "${_has}" -eq 0 ]; then
    return 0
  fi

  info ""
  info "Existing installation found at ${PREFIX}"
  if [ -e "${_bin}" ]; then
    info "  binary: ${_bin}"
  fi
  if [ -f "${CONFIG_PATH}" ]; then
    info "  config: ${CONFIG_PATH}"
  fi

  if [ "${INTERACTIVE}" -eq 0 ]; then
    info "Non-interactive: keeping config and updating binary."
    stop_existing_instance
    return 0
  fi

  info ""
  info "  [k]eep config and update binary (default)"
  info "  [f]resh install (stop services, remove old binary/config first)"
  prompt "Existing installation found. keep or fresh?" "k"
  case "${REPLY}" in
    f|F|fresh|FRESH|Fresh)
      fresh_install_cleanup
      ;;
    *)
      info "Keeping existing config; will update binary only."
      stop_existing_instance
      ;;
  esac
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
  # Args: domain admin password data_dir web_listen smtp sub imap dkim_key
  # If admin or password is empty → setup-pending config (empty [users], no admin_user).
  _domain=$1
  _admin=$2
  _password=$3
  _data_dir=$4
  _web_listen=$5
  _smtp=$6
  _sub=$7
  _imap=$8
  _dkim_key=$9

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
    printf 'catch_all = true\n'
    if [ -n "${_admin}" ] && [ -n "${_password}" ]; then
      _esc_pw=$(toml_escape "${_password}")
      _esc_admin=$(toml_escape "${_admin}")
      printf 'admin_user = "%s"\n' "${_esc_admin}"
      printf 'default_password = "%s"\n' "${_esc_pw}"
    fi
    if [ -n "${_dkim_key}" ]; then
      _esc_dkim=$(toml_escape "${_dkim_key}")
      printf 'dkim_selector = "mail"\n'
      printf 'dkim_key_file = "%s"\n' "${_esc_dkim}"
    fi
    printf '\n[users]\n'
    if [ -n "${_admin}" ] && [ -n "${_password}" ]; then
      _esc_pw=$(toml_escape "${_password}")
      _esc_admin=$(toml_escape "${_admin}")
      printf '"%s" = "%s"\n' "${_esc_admin}" "${_esc_pw}"
    fi
  } > "${CONFIG_PATH}"

  chmod 600 "${CONFIG_PATH}" 2>/dev/null || true
}

apply_port_set() {
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
}

maybe_generate_dkim() {
  DKIM_KEY=""
  if [ "${ENABLE_DKIM}" != "y" ]; then
    return 0
  fi
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
}

configure() {
  info ""
  info "Recommended settings: domain=localhost, webmail on, high ports (no root),"
  info "  DKIM off — create your admin account in the browser after install."
  info ""

  _def_domain="${DESERTEMAIL_DOMAIN:-localhost}"
  _def_admin="${DESERTEMAIL_ADMIN_USER:-admin}"
  _def_data="${DESERTEMAIL_DATA_DIR:-${PREFIX}/data}"
  _gen_pw=$(random_password)
  _pw_from_env=0
  if [ -n "${DESERTEMAIL_ADMIN_PASSWORD+x}" ] && [ -n "${DESERTEMAIL_ADMIN_PASSWORD}" ]; then
    _def_pw="${DESERTEMAIL_ADMIN_PASSWORD}"
    _pw_from_env=1
  else
    _def_pw="${_gen_pw}"
  fi

  SHOW_ADMIN_PASSWORD=0
  SETUP_VIA_BROWSER=0

  if [ "${INTERACTIVE}" -eq 1 ]; then
    prompt "Press Enter to install with recommended settings, or type 'custom' for advanced setup" ""
    case "${REPLY}" in
      custom|CUSTOM|Custom|advanced|ADVANCED|a|A)
        info ""
        info "Advanced setup — answer a few questions (Enter accepts the default)."
        info ""

        prompt "Primary domain" "${_def_domain}"
        DOMAIN="${REPLY}"

        prompt "Admin username" "${_def_admin}"
        ADMIN_USER="${REPLY}"

        prompt_secret "Admin password" "${_def_pw}"
        ADMIN_PASSWORD="${REPLY}"
        if [ "${SECRET_WAS_DEFAULT}" -eq 1 ] && [ "${_pw_from_env}" -eq 0 ]; then
          SHOW_ADMIN_PASSWORD=1
        else
          SHOW_ADMIN_PASSWORD=0
        fi

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
        SETUP_VIA_BROWSER=0
        ;;
      *)
        info "Using recommended settings (express install)."
        info "You will create your admin account in the browser after install."
        DOMAIN="${_def_domain}"
        ADMIN_USER=""
        ADMIN_PASSWORD=""
        DATA_DIR="${_def_data}"
        WEB_LISTEN="0.0.0.0:8080"
        PORT_SET="high"
        ENABLE_DKIM=n
        SHOW_ADMIN_PASSWORD=0
        SETUP_VIA_BROWSER=1
        ;;
    esac
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
    if [ "${_pw_from_env}" -eq 0 ]; then
      SHOW_ADMIN_PASSWORD=1
    else
      SHOW_ADMIN_PASSWORD=0
    fi
    SETUP_VIA_BROWSER=0
  fi

  apply_port_set
  maybe_generate_dkim

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
# Optional systemd unit (Linux)
# ---------------------------------------------------------------------------

install_systemd() {
  _bin="${BIN_DIR}/${APP_NAME}"
  _want_systemd=0
  SYSTEMD_INSTALLED=0

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

  _script_dir=$(CDPATH='' cd -- "$(dirname -- "$0" 2>/dev/null || echo .)" && pwd 2>/dev/null || echo "")
  _template=""
  if [ -n "${_script_dir}" ] && [ -f "${_script_dir}/deploy/desertemail.service" ]; then
    _template="${_script_dir}/deploy/desertemail.service"
  elif [ -f "./deploy/desertemail.service" ]; then
    _template="./deploy/desertemail.service"
  fi

  if [ -n "${_template}" ]; then
    _unit_body=$(
      sed \
        -e "s|ExecStart=.*|ExecStart=${_bin} --config ${CONFIG_PATH}|" \
        -e "s|WorkingDirectory=.*|WorkingDirectory=${PREFIX}|" \
        -e "s|^User=.*|User=${_svc_user}|" \
        -e "s|^Group=.*|Group=${_svc_group}|" \
        "${_template}"
    )
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
    SYSTEMD_INSTALLED=1
    if [ "$(id -u)" -eq 0 ]; then
      systemctl daemon-reload
      if systemctl enable --now desertemail.service; then
        info "systemd: desertemail.service enabled and started"
        SERVER_STARTED=1
      else
        warn "systemctl enable/start failed"
      fi
    else
      sudo systemctl daemon-reload
      if sudo systemctl enable --now desertemail.service; then
        info "systemd: desertemail.service enabled and started"
        SERVER_STARTED=1
      else
        warn "systemctl enable/start failed"
      fi
    fi
  fi
}

# ---------------------------------------------------------------------------
# macOS launchd user agent
# ---------------------------------------------------------------------------

install_launchd() {
  LAUNCHD_INSTALLED=0
  if ! is_darwin; then
    return 0
  fi
  if ! command -v launchctl >/dev/null 2>&1; then
    warn "launchctl not found; skipping launchd agent"
    return 0
  fi

  _bin="${BIN_DIR}/${APP_NAME}"
  _agents_dir="${HOME}/Library/LaunchAgents"
  mkdir -p "${_agents_dir}"
  LAUNCHD_PLIST="${_agents_dir}/${LAUNCHD_LABEL}.plist"

  launchctl bootout "gui/$(id -u)/${LAUNCHD_LABEL}" 2>/dev/null || true
  launchctl unload "${LAUNCHD_PLIST}" 2>/dev/null || true

  {
    printf '%s\n' '<?xml version="1.0" encoding="UTF-8"?>'
    printf '%s\n' '<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">'
    printf '%s\n' '<plist version="1.0">'
    printf '%s\n' '<dict>'
    printf '%s\n' '  <key>Label</key>'
    printf '  <string>%s</string>\n' "${LAUNCHD_LABEL}"
    printf '%s\n' '  <key>ProgramArguments</key>'
    printf '%s\n' '  <array>'
    printf '    <string>%s</string>\n' "${_bin}"
    printf '    <string>--config</string>\n'
    printf '    <string>%s</string>\n' "${CONFIG_PATH}"
    printf '%s\n' '  </array>'
    printf '%s\n' '  <key>WorkingDirectory</key>'
    printf '  <string>%s</string>\n' "${PREFIX}"
    printf '%s\n' '  <key>RunAtLoad</key>'
    printf '%s\n' '  <true/>'
    printf '%s\n' '  <key>KeepAlive</key>'
    printf '%s\n' '  <dict>'
    printf '%s\n' '    <key>SuccessfulExit</key>'
    printf '%s\n' '    <false/>'
    printf '%s\n' '  </dict>'
    printf '%s\n' '  <key>StandardOutPath</key>'
    printf '  <string>%s</string>\n' "${LOG_PATH}"
    printf '%s\n' '  <key>StandardErrorPath</key>'
    printf '  <string>%s</string>\n' "${LOG_PATH}"
    printf '%s\n' '</dict>'
    printf '%s\n' '</plist>'
  } > "${LAUNCHD_PLIST}"

  _uid=$(id -u)
  if launchctl bootstrap "gui/${_uid}" "${LAUNCHD_PLIST}" 2>/dev/null; then
    LAUNCHD_INSTALLED=1
    SERVER_STARTED=1
    info "launchd: installed and loaded ${LAUNCHD_PLIST}"
    return 0
  fi
  if launchctl load "${LAUNCHD_PLIST}" 2>/dev/null; then
    LAUNCHD_INSTALLED=1
    SERVER_STARTED=1
    info "launchd: installed and loaded ${LAUNCHD_PLIST}"
    return 0
  fi

  warn "launchctl bootstrap/load failed; will start in background instead"
  return 1
}

# ---------------------------------------------------------------------------
# Start server, wait for web, open browser
# ---------------------------------------------------------------------------

web_is_up() {
  # Probe healthz (always 200, works in setup-pending too) then port.
  if command -v curl >/dev/null 2>&1; then
    if curl -fsS -o /dev/null --connect-timeout 1 "http://127.0.0.1:8080/healthz" 2>/dev/null; then
      return 0
    fi
  fi
  if command -v nc >/dev/null 2>&1; then
    if nc -z 127.0.0.1 8080 2>/dev/null; then
      return 0
    fi
  fi
  return 1
}

wait_for_web() {
  _n=0
  while [ "${_n}" -lt 20 ]; do
    if web_is_up; then
      return 0
    fi
    _n=$((_n + 1))
    sleep 0.5
  done
  return 1
}

start_background() {
  _bin="${BIN_DIR}/${APP_NAME}"
  mkdir -p "${PREFIX}"
  : >> "${LOG_PATH}" 2>/dev/null || true

  info "Starting DesertEmail in the background ..."
  info "  log: ${LOG_PATH}"

  if command -v setsid >/dev/null 2>&1; then
    setsid "${_bin}" --config "${CONFIG_PATH}" >>"${LOG_PATH}" 2>&1 </dev/null &
  else
    nohup "${_bin}" --config "${CONFIG_PATH}" >>"${LOG_PATH}" 2>&1 </dev/null &
  fi
  SERVER_STARTED=1
}

open_browser() {
  _url=$(web_url)
  if is_darwin && command -v open >/dev/null 2>&1; then
    open "${_url}" 2>/dev/null || true
    return 0
  fi
  if command -v xdg-open >/dev/null 2>&1; then
    xdg-open "${_url}" 2>/dev/null || true
    return 0
  fi
  return 1
}

maybe_autostart() {
  _want=0
  if [ "${INTERACTIVE}" -eq 1 ]; then
    yes_no "Start DesertEmail now and open webmail?" "Y"
    if [ "${REPLY}" = "y" ]; then
      _want=1
    fi
  else
    case "${DESERTEMAIL_AUTOSTART:-0}" in
      1|y|Y|true|TRUE|yes|YES) _want=1 ;;
      *) _want=0 ;;
    esac
  fi

  if [ "${_want}" -eq 0 ]; then
    info "Skipping autostart (start manually when ready)."
    return 0
  fi

  if [ "${SERVER_STARTED}" -eq 0 ]; then
    if is_darwin; then
      if ! install_launchd; then
        start_background
      fi
    else
      start_background
    fi
  fi

  if [ -n "${WEB_LISTEN:-}" ]; then
    info "Waiting for webmail at $(web_url) ..."
    if wait_for_web; then
      info "Webmail is up."
      if [ "${SETUP_VIA_BROWSER:-0}" -eq 1 ]; then
        info "Finish setup in your browser: create your admin account at $(web_url)"
      fi
      if open_browser; then
        info "Opened browser to $(web_url)"
      else
        info "Open this URL in your browser: $(web_url)"
      fi
    else
      warn "server did not become ready within ~10s"
      warn "check the log: ${LOG_PATH}"
      warn "start manually: ${BIN_DIR}/${APP_NAME} --config ${CONFIG_PATH}"
      if [ "${SETUP_VIA_BROWSER:-0}" -eq 1 ]; then
        warn "then open http://127.0.0.1:8080/setup"
      fi
    fi
  else
    info "Webmail is disabled; server start was still requested."
    sleep 1
  fi
}

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------

print_summary() {
  _bin="${BIN_DIR}/${APP_NAME}"
  _url=$(web_url)
  info ""
  info "========================================"
  info " DesertEmail install complete"
  info "========================================"
  info " Binary : ${_bin}"
  info " Config : ${CONFIG_PATH}"
  info " Prefix : ${PREFIX}"
  info " Log    : ${LOG_PATH}"
  info " Ports  : SMTP ${SMTP_LISTEN:-?} | submission ${SUB_LISTEN:-?} | IMAP ${IMAP_LISTEN:-?}"
  if [ -n "${WEB_LISTEN:-}" ]; then
    info " Webmail: ${_url}"
  else
    info " Webmail: disabled"
  fi
  if [ "${SETUP_VIA_BROWSER:-0}" -eq 1 ]; then
    info " Setup  : Finish setup in your browser: create your admin account at"
    info "          http://127.0.0.1:8080/setup"
  elif [ -n "${ADMIN_USER:-}" ]; then
    if [ "${SHOW_ADMIN_PASSWORD}" -eq 1 ] && [ -n "${ADMIN_PASSWORD:-}" ]; then
      info " Login  : ${ADMIN_USER} / ${ADMIN_PASSWORD}"
      info "          (save this password — it will not be shown again)"
    else
      info " Login  : ${ADMIN_USER} / (password stored in ${CONFIG_PATH})"
    fi
  fi
  info ""
  if [ "${SERVER_STARTED}" -eq 1 ]; then
    info " Status : running (started by installer)"
  else
    info " Status : not started"
    info " Start  : ${_bin} --config ${CONFIG_PATH}"
    if [ "${SETUP_VIA_BROWSER:-0}" -eq 1 ] && [ -n "${WEB_LISTEN:-}" ]; then
      info " Then   : open http://127.0.0.1:8080/setup to create your admin account"
    fi
  fi
  if [ "${LAUNCHD_INSTALLED}" -eq 1 ]; then
    info " Service: launchd ${LAUNCHD_LABEL}"
    info " Stop   : launchctl bootout gui/$(id -u)/${LAUNCHD_LABEL}"
    info " Start  : launchctl bootstrap gui/$(id -u) ${LAUNCHD_PLIST:-~/Library/LaunchAgents/${LAUNCHD_LABEL}.plist}"
  elif [ "${SYSTEMD_INSTALLED}" -eq 1 ]; then
    info " Service: systemd desertemail.service"
    info " Stop   : sudo systemctl stop desertemail"
    info " Start  : sudo systemctl start desertemail"
  else
    info " Stop   : kill the desertemail process (or Ctrl-C if foreground)"
  fi
  info ""
  info "If PATH was updated, open a new shell or:"
  info "  export PATH=\"${BIN_DIR}:\$PATH\""
  info ""

  if [ -n "${WEB_LISTEN:-}" ]; then
    info "Configure DNS in your browser: http://127.0.0.1:8080/dns"
    case "${DOMAIN:-localhost}" in
      localhost|local|127.0.0.1|"")
        ;;
      *)
        info "After DNS, enable TLS on the DNS page (Security / Let's Encrypt)."
        ;;
    esac
  elif [ -n "${DKIM_KEY:-}" ] && [ -f "${DKIM_KEY}" ]; then
    info "DNS: publish MX + A/AAAA + SPF + DKIM for domain '${DOMAIN}'."
    info "DKIM TXT (from binary --dkim-dns):"
    if "${_bin}" --dkim-dns "${DOMAIN}" --config "${CONFIG_PATH}" 2>/dev/null; then
      :
    else
      "${_bin}" --config "${CONFIG_PATH}" --dkim-dns "${DOMAIN}" 2>/dev/null \
        || warn "could not run --dkim-dns; run: ${_bin} --dkim-dns ${DOMAIN} --config ${CONFIG_PATH}"
    fi
  else
    info "DNS (when going public): MX + A/AAAA + SPF TXT for your domain."
  fi
  info "========================================"
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

main() {
  print_logo
  info "Build-from-source installer"

  maybe_handle_existing_install

  step "1" "Build"
  install_from_source
  ensure_path

  step "2" "Configure"
  configure

  if ! is_darwin; then
    install_systemd
  fi

  step "3" "Start"
  maybe_autostart

  step "4" "Done"
  print_summary
}

main "$@"

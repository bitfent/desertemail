#!/bin/sh
# DesertEmail uninstaller.
# Usage:  curl -fsSL https://desertemail.org/uninstall.sh | sh
# Optional env:
#   DESERTEMAIL_PREFIX          install root (default ~/.desertemail)
#   DESERTEMAIL_NONINTERACTIVE=1
#   DESERTEMAIL_UNINSTALL=1     required in non-interactive mode to proceed
#   DESERTEMAIL_PURGE_DATA=1    also delete mail data (default: keep)

set -eu

APP_NAME="desertemail"
DEFAULT_PREFIX="${HOME}/.desertemail"
PREFIX="${DESERTEMAIL_PREFIX:-$DEFAULT_PREFIX}"
BIN_DIR="${PREFIX}/bin"
BIN_PATH="${BIN_DIR}/${APP_NAME}"
CONFIG_PATH="${PREFIX}/config.toml"
LOG_PATH="${PREFIX}/desertemail.log"
DKIM_PATH="${PREFIX}/dkim.pem"
LAUNCHD_LABEL="org.desertemail"
PATH_MARKER_BEGIN="# >>> desertemail PATH >>>"
PATH_MARKER_END="# <<< desertemail PATH <<<"
SYSTEMD_UNIT="/etc/systemd/system/desertemail.service"

INTERACTIVE=1
PURGE_DATA=0
DATA_DIR=""
DATA_SIZE=""
FOUND_ANY=0
REMOVED_BIN=0
REMOVED_CONFIG=0
REMOVED_DKIM=0
REMOVED_LOG=0
REMOVED_PLIST=0
REMOVED_SYSTEMD=0
REMOVED_PATH=0
REMOVED_PREFIX=0
REMOVED_DATA=0
KEPT_DATA=0
PATH_RCS=""

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
  if use_color; then
    _sand='\033[38;5;180m'
    _orange='\033[38;5;208m'
    _cactus='\033[38;5;107m'
    _rst='\033[0m'
  else
    _sand=''
    _orange=''
    _cactus=''
    _rst=''
  fi
  printf '%s\n' ""
  printf '%s\n' "${_sand}        .    '    .${_rst}"
  printf '%s\n' "${_orange}    ____|____    DesertEmail${_rst}"
  printf '%s\n' "${_sand}   /  .---.  \\   lightweight mail server${_rst}"
  printf '%s\n' "${_cactus}  |  | o o |  |  + simple uninstall${_rst}"
  printf '%s\n' "${_cactus}   \\  '---'  /${_rst}"
  printf '%s\n' "${_sand}    '---^---'${_rst}"
  printf '%s\n' ""
}

step() {
  info ""
  info "[$1/4] $2"
  info "----------------------------------------"
}

cleanup() {
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

is_darwin() {
  [ "$(uname -s 2>/dev/null || true)" = "Darwin" ]
}

# ---------------------------------------------------------------------------
# Detection
# ---------------------------------------------------------------------------

parse_data_dir() {
  DATA_DIR=""
  if [ -f "${CONFIG_PATH}" ]; then
    _line=$(grep -E '^[[:space:]]*data_dir[[:space:]]*=' "${CONFIG_PATH}" 2>/dev/null | head -n 1 || true)
    if [ -n "${_line}" ]; then
      DATA_DIR=$(printf '%s' "${_line}" | sed \
        -e 's/^[[:space:]]*data_dir[[:space:]]*=[[:space:]]*//' \
        -e 's/^"//' -e 's/"[[:space:]]*$//' \
        -e "s/^'//" -e "s/'[[:space:]]*$//" \
        -e 's/[[:space:]]*$//')
    fi
  fi
  if [ -z "${DATA_DIR}" ] && [ -d "${PREFIX}/data" ]; then
    DATA_DIR="${PREFIX}/data"
  fi
}

dir_size_human() {
  # dir_size_human PATH -> prints e.g. "12M" or "unknown"
  _d=$1
  if [ ! -d "${_d}" ]; then
    printf '%s' "n/a"
    return 0
  fi
  if _sz=$(du -sh "${_d}" 2>/dev/null | awk '{print $1}'); then
    if [ -n "${_sz}" ]; then
      printf '%s' "${_sz}"
      return 0
    fi
  fi
  printf '%s' "unknown"
}

path_rc_candidates() {
  printf '%s\n' \
    "${HOME}/.zshrc" \
    "${HOME}/.bashrc" \
    "${HOME}/.bash_profile" \
    "${HOME}/.profile" \
    "${HOME}/.config/fish/config.fish"
}

detect_path_blocks() {
  PATH_RCS=""
  for _rc in $(path_rc_candidates); do
    if [ -f "${_rc}" ] && grep -F "${PATH_MARKER_BEGIN}" "${_rc}" >/dev/null 2>&1; then
      if [ -z "${PATH_RCS}" ]; then
        PATH_RCS="${_rc}"
      else
        PATH_RCS="${PATH_RCS}
${_rc}"
      fi
    fi
  done
}

detect_install() {
  FOUND_ANY=0
  parse_data_dir
  detect_path_blocks
  DATA_SIZE=""
  if [ -n "${DATA_DIR}" ] && [ -d "${DATA_DIR}" ]; then
    DATA_SIZE=$(dir_size_human "${DATA_DIR}")
  fi

  if [ -x "${BIN_PATH}" ] || [ -f "${BIN_PATH}" ]; then
    FOUND_ANY=1
  fi
  if [ -f "${CONFIG_PATH}" ]; then
    FOUND_ANY=1
  fi
  if [ -d "${PREFIX}" ]; then
    # prefix exists with any of our artifacts
    if [ -f "${LOG_PATH}" ] || [ -f "${DKIM_PATH}" ] || [ -d "${PREFIX}/data" ]; then
      FOUND_ANY=1
    fi
  fi
  if [ -n "${PATH_RCS}" ]; then
    FOUND_ANY=1
  fi
  if is_darwin && [ -f "${HOME}/Library/LaunchAgents/${LAUNCHD_LABEL}.plist" ]; then
    FOUND_ANY=1
  fi
  if [ -f "${SYSTEMD_UNIT}" ]; then
    FOUND_ANY=1
  fi
}

print_detection_summary() {
  info "Install prefix : ${PREFIX}"
  if [ -x "${BIN_PATH}" ] || [ -f "${BIN_PATH}" ]; then
    info "  binary       : ${BIN_PATH}"
  else
    info "  binary       : (not found)"
  fi
  if [ -f "${CONFIG_PATH}" ]; then
    info "  config       : ${CONFIG_PATH}"
  else
    info "  config       : (not found)"
  fi
  if [ -n "${DATA_DIR}" ] && [ -d "${DATA_DIR}" ]; then
    info "  data dir     : ${DATA_DIR} (${DATA_SIZE})"
  else
    info "  data dir     : (not found)"
  fi
  if [ -f "${DKIM_PATH}" ]; then
    info "  DKIM key     : ${DKIM_PATH}"
  fi
  if [ -f "${LOG_PATH}" ]; then
    info "  log          : ${LOG_PATH}"
  fi
  if is_darwin; then
    _plist="${HOME}/Library/LaunchAgents/${LAUNCHD_LABEL}.plist"
    if [ -f "${_plist}" ]; then
      info "  launchd      : ${_plist}"
    else
      info "  launchd      : (not found)"
    fi
  fi
  if [ -f "${SYSTEMD_UNIT}" ]; then
    info "  systemd unit : ${SYSTEMD_UNIT}"
  fi
  if [ -n "${PATH_RCS}" ]; then
    info "  PATH block in:"
    printf '%s\n' "${PATH_RCS}" | while IFS= read -r _rc || [ -n "${_rc}" ]; do
      [ -n "${_rc}" ] || continue
      info "    ${_rc}"
    done
  else
    info "  PATH block   : (not found in shell rc files)"
  fi
}

# ---------------------------------------------------------------------------
# Stop services + processes
# ---------------------------------------------------------------------------

stop_launchd() {
  if ! is_darwin; then
    return 0
  fi
  _plist="${HOME}/Library/LaunchAgents/${LAUNCHD_LABEL}.plist"
  if command -v launchctl >/dev/null 2>&1; then
    launchctl bootout "gui/$(id -u)/${LAUNCHD_LABEL}" 2>/dev/null || true
    if [ -f "${_plist}" ]; then
      launchctl unload "${_plist}" 2>/dev/null || true
    fi
  fi
  if [ -f "${_plist}" ]; then
    rm -f "${_plist}"
    REMOVED_PLIST=1
    info "Removed launchd agent ${_plist}"
  fi
}

stop_systemd() {
  if [ ! -f "${SYSTEMD_UNIT}" ]; then
    return 0
  fi
  if ! command -v systemctl >/dev/null 2>&1; then
    warn "systemd unit present but systemctl not found; leaving ${SYSTEMD_UNIT}"
    return 0
  fi

  _ok=0
  if [ "$(id -u)" -eq 0 ]; then
    systemctl disable --now desertemail 2>/dev/null || true
    systemctl disable --now desertemail.service 2>/dev/null || true
    rm -f "${SYSTEMD_UNIT}"
    systemctl daemon-reload 2>/dev/null || true
    _ok=1
  elif command -v sudo >/dev/null 2>&1; then
    if sudo -n true 2>/dev/null; then
      sudo -n systemctl disable --now desertemail 2>/dev/null || true
      sudo -n systemctl disable --now desertemail.service 2>/dev/null || true
      sudo -n rm -f "${SYSTEMD_UNIT}" 2>/dev/null || true
      sudo -n systemctl daemon-reload 2>/dev/null || true
      if [ ! -f "${SYSTEMD_UNIT}" ]; then
        _ok=1
      fi
    else
      # Interactive sudo only when a TTY is available
      if [ "${INTERACTIVE}" -eq 1 ]; then
        info "Need root to remove systemd unit at ${SYSTEMD_UNIT}"
        if sudo systemctl disable --now desertemail 2>/dev/null \
          || sudo systemctl disable --now desertemail.service 2>/dev/null; then
          :
        fi
        if sudo rm -f "${SYSTEMD_UNIT}" 2>/dev/null; then
          sudo systemctl daemon-reload 2>/dev/null || true
          if [ ! -f "${SYSTEMD_UNIT}" ]; then
            _ok=1
          fi
        fi
      else
        warn "systemd unit present but no passwordless sudo; skipping unit removal"
      fi
    fi
  else
    warn "systemd unit present but not root and no sudo; skipping unit removal"
  fi

  if [ "${_ok}" -eq 1 ]; then
    REMOVED_SYSTEMD=1
    info "Removed systemd unit desertemail.service"
  fi
}

kill_installed_process() {
  # Kill only processes owned by this user whose command line includes our binary path.
  # Match on the installed path (not bare "desertemail") to avoid collateral damage.
  _bin="${BIN_PATH}"
  if [ ! -e "${_bin}" ]; then
    return 0
  fi
  if command -v realpath >/dev/null 2>&1; then
    _bin=$(realpath "${_bin}" 2>/dev/null || printf '%s' "${_bin}")
  fi

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
        info "Stopped process ${_pid} (${_bin})"
      done
    fi
    return 0
  fi

  # Fallback: parse ps (macOS / Linux)
  # shellcheck disable=SC2009
  ps -ax -o pid=,uid=,command= 2>/dev/null | while IFS= read -r _line || [ -n "${_line}" ]; do
    case "${_line}" in
      *"${_bin}"*)
        _pid=$(printf '%s' "${_line}" | awk '{print $1}')
        _uid=$(printf '%s' "${_line}" | awk '{print $2}')
        case "${_pid}" in
          ''|*[!0-9]*) continue ;;
        esac
        if [ "${_uid}" != "${_me}" ]; then
          continue
        fi
        if [ "${_pid}" -eq "$$" ] 2>/dev/null; then
          continue
        fi
        kill "${_pid}" 2>/dev/null || true
        sleep 0.2 2>/dev/null || true
        kill -9 "${_pid}" 2>/dev/null || true
        info "Stopped process ${_pid} (${_bin})"
        ;;
    esac
  done || true
}

# ---------------------------------------------------------------------------
# PATH block removal
# ---------------------------------------------------------------------------

remove_path_block_from_file() {
  _rc=$1
  if [ ! -f "${_rc}" ]; then
    return 0
  fi
  if ! grep -F "${PATH_MARKER_BEGIN}" "${_rc}" >/dev/null 2>&1; then
    return 0
  fi

  _tmp=$(mktemp "${TMPDIR:-/tmp}/desertemail-unpath.XXXXXX")
  # Drop the marker block (inclusive). Also drop a single blank line that
  # immediately preceded the block when it was appended with a leading newline.
  awk -v b="${PATH_MARKER_BEGIN}" -v e="${PATH_MARKER_END}" '
    $0 == b { skip=1; next }
    skip && $0 == e { skip=0; next }
    skip { next }
    { print }
  ' "${_rc}" > "${_tmp}" || {
    rm -f "${_tmp}"
    warn "failed to edit ${_rc}"
    return 1
  }
  # Preserve permissions when possible
  if command -v chmod >/dev/null 2>&1; then
    _mode=$(stat -f '%Lp' "${_rc}" 2>/dev/null || stat -c '%a' "${_rc}" 2>/dev/null || true)
    if [ -n "${_mode}" ]; then
      chmod "${_mode}" "${_tmp}" 2>/dev/null || true
    fi
  fi
  mv "${_tmp}" "${_rc}"
  REMOVED_PATH=1
  info "Removed PATH block from ${_rc}"
}

remove_all_path_blocks() {
  for _rc in $(path_rc_candidates); do
    remove_path_block_from_file "${_rc}"
  done
}

# ---------------------------------------------------------------------------
# File / directory removal
# ---------------------------------------------------------------------------

path_is_under() {
  # path_is_under CHILD PARENT — true if CHILD is PARENT or under it
  _child=$1
  _parent=$2
  case "${_child}" in
    "${_parent}"|"${_parent}"/*) return 0 ;;
    *) return 1 ;;
  esac
}

remove_install_files() {
  if [ -e "${BIN_PATH}" ]; then
    rm -f "${BIN_PATH}"
    REMOVED_BIN=1
    info "Removed ${BIN_PATH}"
  fi
  # Remove empty bin dir
  if [ -d "${BIN_DIR}" ]; then
    rmdir "${BIN_DIR}" 2>/dev/null || true
  fi

  if [ -f "${CONFIG_PATH}" ]; then
    rm -f "${CONFIG_PATH}"
    REMOVED_CONFIG=1
    info "Removed ${CONFIG_PATH}"
  fi

  if [ -f "${DKIM_PATH}" ]; then
    rm -f "${DKIM_PATH}"
    REMOVED_DKIM=1
    info "Removed ${DKIM_PATH}"
  fi

  if [ -f "${LOG_PATH}" ]; then
    rm -f "${LOG_PATH}"
    REMOVED_LOG=1
    info "Removed ${LOG_PATH}"
  fi

  if [ "${PURGE_DATA}" -eq 1 ] && [ -n "${DATA_DIR}" ] && [ -d "${DATA_DIR}" ]; then
    rm -rf "${DATA_DIR}"
    REMOVED_DATA=1
    info "Removed data directory ${DATA_DIR}"
  elif [ -n "${DATA_DIR}" ] && [ -d "${DATA_DIR}" ]; then
    KEPT_DATA=1
  fi

  # Remove prefix if empty, or if fully purged. If data lives inside PREFIX and
  # was kept, leave PREFIX (with data) in place.
  if [ -d "${PREFIX}" ]; then
    if [ "${PURGE_DATA}" -eq 1 ] || [ "${KEPT_DATA}" -eq 0 ]; then
      # Try full remove when nothing important remains
      if [ "${KEPT_DATA}" -eq 0 ]; then
        # Remove leftover empty dirs under prefix, then prefix itself
        find "${PREFIX}" -type d -empty -delete 2>/dev/null || true
        if rmdir "${PREFIX}" 2>/dev/null; then
          REMOVED_PREFIX=1
          info "Removed prefix ${PREFIX}"
        elif [ -z "$(ls -A "${PREFIX}" 2>/dev/null || true)" ]; then
          rm -rf "${PREFIX}"
          REMOVED_PREFIX=1
          info "Removed prefix ${PREFIX}"
        else
          # Still has content (unexpected leftovers) — leave it
          info "Left ${PREFIX} (not empty)"
        fi
      fi
    else
      # Data kept under prefix: leave prefix + data, clean other empties
      if path_is_under "${DATA_DIR}" "${PREFIX}"; then
        info "Kept data at ${DATA_DIR} (prefix left in place)"
      fi
    fi
  fi
}

print_closing_summary() {
  info ""
  info "========================================"
  info " DesertEmail uninstall complete"
  info "========================================"
  if [ "${REMOVED_BIN}" -eq 1 ]; then
    info " Removed : binary"
  fi
  if [ "${REMOVED_CONFIG}" -eq 1 ]; then
    info " Removed : config"
  fi
  if [ "${REMOVED_DKIM}" -eq 1 ]; then
    info " Removed : DKIM key"
  fi
  if [ "${REMOVED_LOG}" -eq 1 ]; then
    info " Removed : log"
  fi
  if [ "${REMOVED_PLIST}" -eq 1 ]; then
    info " Removed : launchd agent"
  fi
  if [ "${REMOVED_SYSTEMD}" -eq 1 ]; then
    info " Removed : systemd unit"
  fi
  if [ "${REMOVED_PATH}" -eq 1 ]; then
    info " Removed : PATH block(s)"
  fi
  if [ "${REMOVED_DATA}" -eq 1 ]; then
    info " Removed : mail data"
  fi
  if [ "${REMOVED_PREFIX}" -eq 1 ]; then
    info " Removed : prefix ${PREFIX}"
  fi
  if [ "${KEPT_DATA}" -eq 1 ]; then
    info " Kept    : mail data at ${DATA_DIR}"
    info "           (re-run with DESERTEMAIL_PURGE_DATA=1 or answer yes to delete)"
  fi
  info ""
  info "Thanks for trying DesertEmail. Reinstall anytime from desertemail.org."
  info "========================================"
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

main() {
  print_logo

  step "1" "Detect"
  detect_install
  if [ "${FOUND_ANY}" -eq 0 ]; then
    info "No DesertEmail install found at ${PREFIX}."
    info "Nothing to do — you're already clean. 🌵"
    exit 0
  fi
  info "Found a DesertEmail install:"
  print_detection_summary

  step "2" "Confirm"
  if [ "${INTERACTIVE}" -eq 0 ]; then
    if [ "${DESERTEMAIL_UNINSTALL:-0}" != "1" ]; then
      die "non-interactive uninstall requires DESERTEMAIL_UNINSTALL=1 (and DESERTEMAIL_NONINTERACTIVE=1). Refusing to remove anything."
    fi
    case "${DESERTEMAIL_PURGE_DATA:-0}" in
      1|y|Y|true|TRUE|yes|YES) PURGE_DATA=1 ;;
      *) PURGE_DATA=0 ;;
    esac
    info "Non-interactive uninstall confirmed (DESERTEMAIL_UNINSTALL=1)."
    if [ "${PURGE_DATA}" -eq 1 ]; then
      info "Mail data will be deleted (DESERTEMAIL_PURGE_DATA=1)."
    else
      info "Mail data will be kept (set DESERTEMAIL_PURGE_DATA=1 to delete)."
    fi
  else
    yes_no "Remove DesertEmail?" "N"
    if [ "${REPLY}" != "y" ]; then
      info "Aborted. Nothing was removed."
      exit 0
    fi
    if [ -n "${DATA_DIR}" ] && [ -d "${DATA_DIR}" ]; then
      yes_no "Also delete all mail data at ${DATA_DIR}?" "N"
      if [ "${REPLY}" = "y" ]; then
        PURGE_DATA=1
      else
        PURGE_DATA=0
      fi
    else
      PURGE_DATA=0
    fi
  fi

  step "3" "Stop & remove"
  info "Stopping services and processes ..."
  stop_launchd
  stop_systemd
  kill_installed_process

  info "Cleaning PATH and install files ..."
  remove_all_path_blocks
  remove_install_files

  step "4" "Done"
  print_closing_summary
}

main "$@"

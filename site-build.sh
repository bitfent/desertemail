#!/bin/sh
# DesertEmail site build (Render buildCommand, also used for local dev).
# Generates per-platform installers under site/ and copies prebuilt binaries
# from bin-dist/ to site/bin/ when present.
#
# Env:
#   RENDER_EXTERNAL_URL  set automatically by Render
#   SITE_BASE_URL        override / local-dev origin (e.g. http://127.0.0.1:4173)
#
# Local dev:
#   SITE_BASE_URL=http://127.0.0.1:4173 sh site-build.sh
#   then serve site/ on port 4173

set -eu

ROOT=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
cd "${ROOT}"

BASE_URL="${RENDER_EXTERNAL_URL:-${SITE_BASE_URL:-}}"
if [ -z "${BASE_URL}" ]; then
  # Local / offline build: installers still need an absolute origin for curl|sh.
  warn_msg="SITE_BASE_URL and RENDER_EXTERNAL_URL unset; defaulting to http://127.0.0.1:4173 (local dev)"
  printf '%s\n' "warning: ${warn_msg}" >&2
  BASE_URL="http://127.0.0.1:4173"
fi

# Strip trailing slash for clean URL joins in generated installers.
BASE_URL=$(printf '%s' "${BASE_URL}" | sed 's|/*$||')

TEMPLATE="${ROOT}/installers/template.sh"
SOURCE_INSTALLER="${ROOT}/installers/build-from-source.sh"
WIN_TEMPLATE="${ROOT}/installers/install-windows.ps1"
SITE_DIR="${ROOT}/site"

if [ ! -f "${TEMPLATE}" ]; then
  printf '%s\n' "error: missing ${TEMPLATE}" >&2
  exit 1
fi
if [ ! -f "${SOURCE_INSTALLER}" ]; then
  printf '%s\n' "error: missing ${SOURCE_INSTALLER}" >&2
  exit 1
fi
if [ ! -f "${WIN_TEMPLATE}" ]; then
  printf '%s\n' "error: missing ${WIN_TEMPLATE}" >&2
  exit 1
fi
if [ ! -d "${SITE_DIR}" ]; then
  printf '%s\n' "error: missing ${SITE_DIR}" >&2
  exit 1
fi

# name|rust-triple
# shellcheck disable=SC2034
TARGETS="
linux-x86_64|x86_64-unknown-linux-musl
linux-arm64|aarch64-unknown-linux-musl
linux-armv7|armv7-unknown-linux-musleabihf
linux-armv6|arm-unknown-linux-musleabihf
macos-apple-silicon|aarch64-apple-darwin
macos-intel|x86_64-apple-darwin
"

gen_installer() {
  _name=$1
  _triple=$2
  _out="${SITE_DIR}/install-${_name}.sh"
  # Use | as sed delimiter so URLs (with /) are safe.
  sed \
    -e "s|__TARGET__|${_triple}|g" \
    -e "s|__BASE_URL__|${BASE_URL}|g" \
    "${TEMPLATE}" > "${_out}"
  printf '%s\n' "wrote ${_out} (target=${_triple})"
}

printf '%s\n' "site-build: BASE_URL=${BASE_URL}"

# Generate platform installers
printf '%s\n' "${TARGETS}" | while IFS= read -r _line || [ -n "${_line}" ]; do
  # skip blank lines
  case "${_line}" in
    ''|\#*) continue ;;
  esac
  _name=$(printf '%s' "${_line}" | cut -d'|' -f1)
  _triple=$(printf '%s' "${_line}" | cut -d'|' -f2)
  gen_installer "${_name}" "${_triple}"
done

# Build-from-source installer (no placeholders)
cp "${SOURCE_INSTALLER}" "${SITE_DIR}/install-from-source.sh"
printf '%s\n' "wrote ${SITE_DIR}/install-from-source.sh"

# Windows PowerShell installer
_win_out="${SITE_DIR}/install-windows.ps1"
_win_triple="x86_64-pc-windows-msvc"
sed \
  -e "s|__TARGET__|${_win_triple}|g" \
  -e "s|__BASE_URL__|${BASE_URL}|g" \
  "${WIN_TEMPLATE}" > "${_win_out}"
printf '%s\n' "wrote ${_win_out} (target=${_win_triple})"

# Optional prebuilt binaries from bin-dist/
if [ -d "${ROOT}/bin-dist" ]; then
  mkdir -p "${SITE_DIR}/bin"
  # Copy files only (ignore empty dir / subdirs)
  # shellcheck disable=SC2045
  for _f in "${ROOT}/bin-dist"/*; do
    if [ -f "${_f}" ]; then
      cp "${_f}" "${SITE_DIR}/bin/"
      printf '%s\n' "copied bin-dist/$(basename "${_f}") -> site/bin/"
    fi
  done

  # Regenerate SHA256SUMS with entries named exactly desertemail-<target>
  # (only for files that look like prebuilt binaries).
  : > "${SITE_DIR}/bin/SHA256SUMS"
  _any=0
  for _f in "${SITE_DIR}/bin"/desertemail-*; do
    if [ -f "${_f}" ]; then
      _base=$(basename "${_f}")
      if command -v sha256sum >/dev/null 2>&1; then
        # sha256sum prints "HASH  name" relative to cwd
        (
          CDPATH='' cd -- "${SITE_DIR}/bin" || exit 1
          sha256sum "${_base}"
        ) >> "${SITE_DIR}/bin/SHA256SUMS"
      elif command -v shasum >/dev/null 2>&1; then
        (
          CDPATH='' cd -- "${SITE_DIR}/bin" || exit 1
          shasum -a 256 "${_base}"
        ) >> "${SITE_DIR}/bin/SHA256SUMS"
      else
        printf '%s\n' "warning: neither sha256sum nor shasum found; empty SHA256SUMS" >&2
        break
      fi
      _any=1
    fi
  done
  if [ "${_any}" -eq 1 ]; then
    printf '%s\n' "wrote ${SITE_DIR}/bin/SHA256SUMS"
  else
    printf '%s\n' "site-build: bin-dist present but no desertemail-* binaries yet"
  fi
else
  printf '%s\n' "site-build: no bin-dist/; skipping site/bin/"
fi

# Stamp the absolute site origin into the Open Graph / Twitter meta tags.
# Social crawlers (WhatsApp especially) require ABSOLUTE og:image URLs, so the
# committed HTML keeps a __OG_BASE__ placeholder that we replace at build time.
# In place is fine: Render builds a throwaway checkout; local runs restore via git.
for _html in "${SITE_DIR}/index.html" "${SITE_DIR}/docs.html"; do
  if [ -f "${_html}" ] && grep -q '__OG_BASE__' "${_html}"; then
    _tmp="${_html}.tmp.$$"
    sed "s|__OG_BASE__|${BASE_URL}|g" "${_html}" > "${_tmp}" && mv "${_tmp}" "${_html}"
    printf '%s\n' "stamped OG base ${BASE_URL} -> $(basename "${_html}")"
  fi
done

# Remove legacy single installer if still present from older layout
if [ -f "${SITE_DIR}/install.sh" ]; then
  rm -f "${SITE_DIR}/install.sh"
  printf '%s\n' "removed legacy site/install.sh"
fi

printf '%s\n' "site-build: done"

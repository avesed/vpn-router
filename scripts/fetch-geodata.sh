#!/usr/bin/env bash
set -euo pipefail

OUTPUT_DIR="${1:-${RULESET_DIR:-/etc/sing-box}}"
READY_FLAG="${2:-}"
FORCE_UPDATE="${FORCE_GEODATA_REFRESH:-0}"
GEOIP_URL="${GEOIP_URL:-https://github.com/SagerNet/sing-geoip/releases/latest/download/geoip.db}"
GEOSITE_URL="${GEOSITE_URL:-https://github.com/SagerNet/sing-geosite/releases/latest/download/geosite.db}"
RULESET_OUTPUT_DIR="${RULESET_OUTPUT_DIR:-${OUTPUT_DIR}/rulesets}"
GEOSITE_CATEGORIES="${GEOSITE_CATEGORIES:-cn}"
GEOIP_COUNTRIES="${GEOIP_COUNTRIES:-cn,ca}"
SING_BOX_BIN="${SING_BOX_BIN:-}"

mkdir -p "${OUTPUT_DIR}"
mkdir -p "${RULESET_OUTPUT_DIR}"

if [ -z "${SING_BOX_BIN}" ] && { [ -n "${GEOSITE_CATEGORIES// }" ] || [ -n "${GEOIP_COUNTRIES// }" ]; }; then
  SING_BOX_BIN="$(command -v sing-box || true)"
  if [ -z "${SING_BOX_BIN}" ]; then
    echo "[geodata] sing-box binary not found, cannot export rule-sets" >&2
    exit 1
  fi
fi

fetch_file() {
  local url="$1"
  local destination="$2"

  if [ "${FORCE_UPDATE}" != "1" ] && [ -s "${destination}" ]; then
    return
  fi

  echo "[geodata] downloading ${url}"
  tmp="${destination}.download"
  rm -f "${tmp}"
  curl -fL --retry 3 --connect-timeout 10 -o "${tmp}" "${url}"
  mv "${tmp}" "${destination}"
}

fetch_file "${GEOIP_URL}" "${OUTPUT_DIR}/geoip.db"
fetch_file "${GEOSITE_URL}" "${OUTPUT_DIR}/geosite.db"

generate_geosite_rulesets() {
  local categories=("$@")
  local geosite_file="${OUTPUT_DIR}/geosite.db"
  if [ ! -s "${geosite_file}" ] || [ -z "${categories[*]}" ]; then
    return
  fi
  for category in "${categories[@]}"; do
    [ -z "${category}" ] && continue
    local output="${RULESET_OUTPUT_DIR}/geosite-${category}.json"
    if [ "${FORCE_UPDATE}" != "1" ] && [ -s "${output}" ] && [ "${output}" -nt "${geosite_file}" ]; then
      continue
    fi
    echo "[geodata] exporting geosite ${category} -> ${output}"
    local tmp="${output}.tmp"
    rm -f "${tmp}"
    if ! "${SING_BOX_BIN}" geosite --file "${geosite_file}" export "${category}" --output "${tmp}"; then
      rm -f "${tmp}"
      echo "[geodata] failed to export geosite ${category}" >&2
      exit 1
    fi
    mv "${tmp}" "${output}"
  done
}

generate_geoip_rulesets() {
  local countries=("$@")
  local geoip_file="${OUTPUT_DIR}/geoip.db"
  if [ ! -s "${geoip_file}" ] || [ -z "${countries[*]}" ]; then
    return
  fi
  for country in "${countries[@]}"; do
    [ -z "${country}" ] && continue
    local normalized="${country,,}"
    local output="${RULESET_OUTPUT_DIR}/geoip-${normalized}.json"
    if [ "${FORCE_UPDATE}" != "1" ] && [ -s "${output}" ] && [ "${output}" -nt "${geoip_file}" ]; then
      continue
    fi
    echo "[geodata] exporting geoip ${normalized} -> ${output}"
    local tmp="${output}.tmp"
    rm -f "${tmp}"
    if ! "${SING_BOX_BIN}" geoip --file "${geoip_file}" export "${normalized}" --output "${tmp}"; then
      rm -f "${tmp}"
      echo "[geodata] failed to export geoip ${normalized}" >&2
      exit 1
    fi
    mv "${tmp}" "${output}"
  done
}

parse_list() {
  local raw="$1"
  local -n out_ref="$2"
  out_ref=()
  raw="${raw//,/ }"
  for entry in ${raw}; do
    entry="${entry// /}"
    [ -z "${entry}" ] && continue
    out_ref+=("${entry}")
  done
}

if [ -n "${GEOSITE_CATEGORIES// }" ]; then
  parse_list "${GEOSITE_CATEGORIES}" geosite_list
  generate_geosite_rulesets "${geosite_list[@]}"
fi
if [ -n "${GEOIP_COUNTRIES// }" ]; then
  parse_list "${GEOIP_COUNTRIES}" geoip_list
  generate_geoip_rulesets "${geoip_list[@]}"
fi

if [ -n "${READY_FLAG}" ]; then
  touch "${READY_FLAG}"
fi

#!/usr/bin/env bash
set -euo pipefail

OUTPUT_DIR="${1:-${RULESET_DIR:-/etc/sing-box}}"
READY_FLAG="${2:-}"
FORCE_UPDATE="${FORCE_GEODATA_REFRESH:-0}"
GEOIP_URL="${GEOIP_URL:-https://github.com/SagerNet/sing-geoip/releases/latest/download/geoip.db}"
GEOSITE_URL="${GEOSITE_URL:-https://github.com/SagerNet/sing-geosite/releases/latest/download/geosite.db}"

mkdir -p "${OUTPUT_DIR}"

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

if [ -n "${READY_FLAG}" ]; then
  touch "${READY_FLAG}"
fi

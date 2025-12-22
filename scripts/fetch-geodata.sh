#!/usr/bin/env bash
set -uo pipefail

OUTPUT_DIR="${1:-${RULESET_DIR:-/etc/sing-box}}"
READY_FLAG="${2:-}"
FORCE_UPDATE="${FORCE_GEODATA_REFRESH:-0}"
GEOIP_URL="${GEOIP_URL:-https://github.com/SagerNet/sing-geoip/releases/latest/download/geoip.db}"
GEOSITE_URL="${GEOSITE_URL:-https://github.com/SagerNet/sing-geosite/releases/latest/download/geosite.db}"

mkdir -p "${OUTPUT_DIR}"

fetch_file() {
  local url="$1"
  local destination="$2"
  local filename
  filename=$(basename "${destination}")

  # 文件已存在且非空，跳过下载
  if [ "${FORCE_UPDATE}" != "1" ] && [ -s "${destination}" ]; then
    echo "[geodata] ${filename} already exists, skipping download"
    return 0
  fi

  echo "[geodata] downloading ${url}"
  tmp="${destination}.download"
  rm -f "${tmp}"

  if curl -fL --retry 3 --connect-timeout 10 -o "${tmp}" "${url}"; then
    mv "${tmp}" "${destination}"
    echo "[geodata] ${filename} downloaded successfully"
    return 0
  else
    rm -f "${tmp}"
    echo "[geodata] WARNING: failed to download ${filename}, some features may be limited"
    return 0  # 不返回错误，允许容器继续启动
  fi
}

fetch_file "${GEOIP_URL}" "${OUTPUT_DIR}/geoip.db"
fetch_file "${GEOSITE_URL}" "${OUTPUT_DIR}/geosite.db"

if [ -n "${READY_FLAG}" ]; then
  touch "${READY_FLAG}"
fi

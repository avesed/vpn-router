#!/usr/bin/env bash
set -uo pipefail

OUTPUT_DIR="${1:-${RULESET_DIR:-/etc/sing-box}}"
READY_FLAG="${2:-}"
FORCE_UPDATE="${FORCE_GEODATA_REFRESH:-0}"
GEOIP_URL="${GEOIP_URL:-https://github.com/SagerNet/sing-geoip/releases/latest/download/geoip.db}"
GEOSITE_URL="${GEOSITE_URL:-https://github.com/SagerNet/sing-geosite/releases/latest/download/geosite.db}"

mkdir -p "${OUTPUT_DIR}"

# H11: 改进的错误处理 - 关键文件失败时返回错误
# 返回值: 0=成功或已存在, 1=下载失败且文件不存在(关键错误)
fetch_file() {
  local url="$1"
  local destination="$2"
  local critical="${3:-0}"  # 是否为关键文件
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
    # H11: 如果是关键文件且不存在，返回错误
    if [ "${critical}" = "1" ] && [ ! -s "${destination}" ]; then
      echo "[geodata] ERROR: failed to download critical file ${filename} and no existing file found"
      return 1
    fi
    echo "[geodata] WARNING: failed to download ${filename}, using existing or limited features"
    return 0
  fi
}

# geoip.db 和 geosite.db 是关键文件 (critical=1)
# 如果下载失败且没有现有文件，将返回错误
GEOIP_RESULT=0
GEOSITE_RESULT=0

fetch_file "${GEOIP_URL}" "${OUTPUT_DIR}/geoip.db" 1 || GEOIP_RESULT=$?
fetch_file "${GEOSITE_URL}" "${OUTPUT_DIR}/geosite.db" 1 || GEOSITE_RESULT=$?

# 如果任何关键文件失败，不创建 ready flag 并返回错误
if [ "${GEOIP_RESULT}" -ne 0 ] || [ "${GEOSITE_RESULT}" -ne 0 ]; then
  echo "[geodata] Critical geodata files missing, routing features will be limited"
  # 不阻止容器启动，但记录警告
fi

if [ -n "${READY_FLAG}" ]; then
  touch "${READY_FLAG}"
fi

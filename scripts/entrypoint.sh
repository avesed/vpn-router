#!/usr/bin/env bash
set -euo pipefail

cleanup() {
  if [ -n "${API_PID:-}" ] && kill -0 "${API_PID}" >/dev/null 2>&1; then
    kill "${API_PID}" >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT
API_PID=""

BASE_CONFIG_PATH="${SING_BOX_CONFIG:-/etc/sing-box/sing-box.json}"
GENERATED_CONFIG_PATH="${SING_BOX_GENERATED_CONFIG:-/etc/sing-box/sing-box.generated.json}"
WG_CONFIG_PATH="${WG_CONFIG_PATH:-/etc/sing-box/wireguard/server.json}"
RULESET_DIR="${RULESET_DIR:-/etc/sing-box}"
GEO_DATA_READY_FLAG="${RULESET_DIR}/.geodata-ready"

if [ ! -f "${BASE_CONFIG_PATH}" ]; then
  echo "[entrypoint] config ${BASE_CONFIG_PATH} not found" >&2
  exit 1
fi

sysctl -w net.ipv4.ip_forward=1 >/dev/null 2>&1 || true
sysctl -w net.ipv4.conf.all.rp_filter=0 >/dev/null 2>&1 || true
sysctl -w net.ipv4.conf.default.rp_filter=0 >/dev/null 2>&1 || true

if [ "${DISABLE_IPV6:-1}" = "1" ]; then
  sysctl -w net.ipv6.conf.all.disable_ipv6=1 >/dev/null || true
  sysctl -w net.ipv6.conf.default.disable_ipv6=1 >/dev/null || true
fi

/usr/local/bin/fetch-geodata.sh "${RULESET_DIR}" "${GEO_DATA_READY_FLAG}"

if [ -n "${WG_CONFIG_PATH}" ]; then
  export WG_CONFIG_PATH
  /usr/local/bin/setup-wg.sh
fi

start_api_server() {
  if [ "${ENABLE_API:-1}" = "1" ]; then
    local api_port="${API_PORT:-8000}"
    export API_PORT="${api_port}"
    echo "[entrypoint] starting API server on port ${api_port}"
    python3 /usr/local/bin/api_server.py >/var/log/api-server.log 2>&1 &
    API_PID=$!
  fi
}

CONFIG_PATH="${BASE_CONFIG_PATH}"
if [ -n "${PIA_USERNAME:-}" ] && [ -n "${PIA_PASSWORD:-}" ]; then
  export PIA_PROFILES_FILE="${PIA_PROFILES_FILE:-/etc/sing-box/pia/profiles.yml}"
  export PIA_PROFILES_OUTPUT="${PIA_PROFILES_OUTPUT:-/etc/sing-box/pia-profiles.json}"
  export SING_BOX_BASE_CONFIG="${BASE_CONFIG_PATH}"
  export SING_BOX_GENERATED_CONFIG="${GENERATED_CONFIG_PATH}"

  echo "[entrypoint] provisioning PIA WireGuard profiles"
  if ! python3 /usr/local/bin/pia_provision.py; then
    echo "[entrypoint] pia provisioning failed" >&2
    exit 1
  fi
  if ! python3 /usr/local/bin/render_singbox.py; then
    echo "[entrypoint] render sing-box config failed" >&2
    exit 1
  fi
  CONFIG_PATH="${GENERATED_CONFIG_PATH}"
fi

start_api_server

echo "[entrypoint] starting sing-box with ${CONFIG_PATH}"

# 启动 sing-box 并监控，支持 API 触发的重启
# 不使用 exec，以便 API 可以重启 sing-box 而不影响容器
SINGBOX_PID=""

start_singbox() {
  local config="$1"
  if [ -z "$config" ]; then
    # 优先使用生成的配置
    if [ -f "${GENERATED_CONFIG_PATH}" ]; then
      config="${GENERATED_CONFIG_PATH}"
    else
      config="${BASE_CONFIG_PATH}"
    fi
  fi
  echo "[entrypoint] starting sing-box with ${config}"
  sing-box run -c "${config}" &
  SINGBOX_PID=$!
}

handle_signals() {
  echo "[entrypoint] received signal, shutting down..."
  if [ -n "${SINGBOX_PID:-}" ] && kill -0 "${SINGBOX_PID}" 2>/dev/null; then
    kill "${SINGBOX_PID}" 2>/dev/null || true
    wait "${SINGBOX_PID}" 2>/dev/null || true
  fi
  cleanup
  exit 0
}

trap handle_signals SIGTERM SIGINT

start_singbox "${CONFIG_PATH}"

# 主循环：监控 sing-box 进程
# 如果 sing-box 退出，检查是否有新配置需要加载
while true; do
  if ! kill -0 "${SINGBOX_PID}" 2>/dev/null; then
    wait "${SINGBOX_PID}" 2>/dev/null || true
    EXIT_CODE=$?
    echo "[entrypoint] sing-box exited with code ${EXIT_CODE}"

    # 检查是否有生成的配置
    if [ -f "${GENERATED_CONFIG_PATH}" ]; then
      echo "[entrypoint] restarting sing-box with generated config"
      start_singbox "${GENERATED_CONFIG_PATH}"
    else
      echo "[entrypoint] sing-box exited, no generated config available"
      # 等待一段时间后尝试重新启动
      sleep 5
      start_singbox "${BASE_CONFIG_PATH}"
    fi
  fi
  sleep 1
done

#!/usr/bin/env bash
set -euo pipefail

cleanup() {
  if [ -n "${NGINX_PID:-}" ] && kill -0 "${NGINX_PID}" >/dev/null 2>&1; then
    echo "[entrypoint] stopping nginx (PID ${NGINX_PID})"
    kill "${NGINX_PID}" >/dev/null 2>&1 || true
  fi
  if [ -n "${API_PID:-}" ] && kill -0 "${API_PID}" >/dev/null 2>&1; then
    kill "${API_PID}" >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT
API_PID=""
NGINX_PID=""

BASE_CONFIG_PATH="${SING_BOX_CONFIG:-/etc/sing-box/sing-box.json}"
GENERATED_CONFIG_PATH="${SING_BOX_GENERATED_CONFIG:-/etc/sing-box/sing-box.generated.json}"
WG_CONFIG_PATH="${WG_CONFIG_PATH:-/etc/sing-box/wireguard/server.json}"
RULESET_DIR="${RULESET_DIR:-/etc/sing-box}"
GEO_DATA_READY_FLAG="${RULESET_DIR}/.geodata-ready"
USER_DB_PATH="${USER_DB_PATH:-/etc/sing-box/user-config.db}"
GEODATA_DB_PATH="${GEODATA_DB_PATH:-/etc/sing-box/geoip-geodata.db}"
DEFAULT_CONFIG_DIR="/opt/default-config"
GEODATA_RELEASE_URL="https://github.com/avesed/vpn-router/releases/download/geodata/geoip-geodata.db"

# Port configuration
export WEB_PORT="${WEB_PORT:-36000}"
export WG_LISTEN_PORT="${WG_LISTEN_PORT:-36100}"

# 首次启动初始化：下载或复制 geodata 数据库
if [ ! -f "${GEODATA_DB_PATH}" ]; then
  echo "[entrypoint] geodata database not found, attempting to download..."
  if curl -fsSL -o "${GEODATA_DB_PATH}" "${GEODATA_RELEASE_URL}"; then
    echo "[entrypoint] geodata database downloaded successfully"
  elif [ -f "${DEFAULT_CONFIG_DIR}/geoip-geodata.db" ]; then
    echo "[entrypoint] download failed, using default config"
    cp "${DEFAULT_CONFIG_DIR}/geoip-geodata.db" "${GEODATA_DB_PATH}"
  else
    echo "[entrypoint] WARNING: geodata database not available, some features may be limited"
  fi
fi

if [ ! -f "${BASE_CONFIG_PATH}" ] && [ -f "${DEFAULT_CONFIG_DIR}/sing-box.json" ]; then
  echo "[entrypoint] initializing sing-box config from default config"
  cp "${DEFAULT_CONFIG_DIR}/sing-box.json" "${BASE_CONFIG_PATH}"
fi

if [ ! -f "${BASE_CONFIG_PATH}" ]; then
  echo "[entrypoint] config ${BASE_CONFIG_PATH} not found" >&2
  exit 1
fi

# 初始化/升级用户数据库（使用 CREATE TABLE IF NOT EXISTS，安全运行）
echo "[entrypoint] initializing user database: ${USER_DB_PATH}"
python3 /usr/local/bin/init_user_db.py /etc/sing-box
if [ $? -ne 0 ]; then
  echo "[entrypoint] failed to initialize user database" >&2
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

# Note: WireGuard server is now handled by sing-box endpoint (wg-server)
# setup-wg.sh is no longer needed - sing-box binds to listen_port directly

start_api_server() {
  if [ "${ENABLE_API:-1}" = "1" ]; then
    local api_port="${API_PORT:-8000}"
    export API_PORT="${api_port}"
    echo "[entrypoint] starting API server on port ${api_port}"
    python3 /usr/local/bin/api_server.py >/var/log/api-server.log 2>&1 &
    API_PID=$!
  fi
}

start_nginx() {
  echo "[entrypoint] starting nginx on port ${WEB_PORT}"

  # Generate nginx.conf from template with environment variables
  NGINX_TEMPLATE="/etc/nginx/nginx.conf.template"
  NGINX_CONF="/etc/nginx/conf.d/default.conf"
  if [ -f "${NGINX_TEMPLATE}" ]; then
    envsubst '${WEB_PORT}' < "${NGINX_TEMPLATE}" > "${NGINX_CONF}"
    echo "[entrypoint] generated nginx config with WEB_PORT=${WEB_PORT}"
  fi

  # Test nginx configuration
  nginx -t
  if [ $? -ne 0 ]; then
    echo "[entrypoint] nginx configuration test failed" >&2
    exit 1
  fi

  # Start nginx in foreground mode (daemon off)
  nginx -g "daemon off;" &
  NGINX_PID=$!
  echo "[entrypoint] nginx started with PID ${NGINX_PID}"

  # Verify startup success
  sleep 2
  if ! kill -0 "${NGINX_PID}" 2>/dev/null; then
    echo "[entrypoint] nginx failed to start" >&2
    exit 1
  fi
}

# PIA provisioning (if credentials provided)
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
fi

# Always render sing-box config (adds wg-server endpoint, sniff action, etc.)
export SING_BOX_BASE_CONFIG="${BASE_CONFIG_PATH}"
export SING_BOX_GENERATED_CONFIG="${GENERATED_CONFIG_PATH}"
echo "[entrypoint] rendering sing-box config"
if ! python3 /usr/local/bin/render_singbox.py; then
  echo "[entrypoint] render sing-box config failed" >&2
  exit 1
fi
CONFIG_PATH="${GENERATED_CONFIG_PATH}"

start_api_server
start_nginx

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

# 主循环：监控 nginx, API 和 sing-box 进程
while true; do
  # Check nginx
  if [ -n "${NGINX_PID}" ] && ! kill -0 "${NGINX_PID}" 2>/dev/null; then
    echo "[entrypoint] WARNING: nginx died" >&2
  fi

  # Check API server
  if [ -n "${API_PID}" ] && ! kill -0 "${API_PID}" 2>/dev/null; then
    echo "[entrypoint] WARNING: API server died" >&2
  fi

  # Check sing-box
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

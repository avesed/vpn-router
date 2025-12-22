#!/usr/bin/env bash
set -euo pipefail

cleanup() {
  if [ -n "${XRAY_MGR_PID:-}" ] && kill -0 "${XRAY_MGR_PID}" >/dev/null 2>&1; then
    echo "[entrypoint] stopping Xray manager (PID ${XRAY_MGR_PID})"
    kill "${XRAY_MGR_PID}" >/dev/null 2>&1 || true
  fi
  if [ -n "${OPENVPN_MGR_PID:-}" ] && kill -0 "${OPENVPN_MGR_PID}" >/dev/null 2>&1; then
    echo "[entrypoint] stopping OpenVPN manager (PID ${OPENVPN_MGR_PID})"
    kill "${OPENVPN_MGR_PID}" >/dev/null 2>&1 || true
  fi
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
OPENVPN_MGR_PID=""
XRAY_MGR_PID=""
XRAY_EGRESS_MGR_PID=""

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

# 初始化 domain catalog 文件（规则库）
DOMAIN_CATALOG="${RULESET_DIR}/domain-catalog.json"
if [ ! -f "${DOMAIN_CATALOG}" ] && [ -f "${DEFAULT_CONFIG_DIR}/domain-catalog.json" ]; then
  echo "[entrypoint] initializing domain catalog from default config"
  cp "${DEFAULT_CONFIG_DIR}/domain-catalog.json" "${DOMAIN_CATALOG}"
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

# === Kernel WireGuard Setup ===
# Creates wg-ingress interface and configures TPROXY to sing-box

WG_INTERFACE="${WG_INTERFACE:-wg-ingress}"
WG_SUBNET="${WG_SUBNET:-10.23.0.0/24}"
TPROXY_PORT="${TPROXY_PORT:-7893}"
TPROXY_MARK="1"
TPROXY_TABLE="100"

setup_kernel_wireguard() {
  echo "[entrypoint] setting up kernel WireGuard interface"

  # Create WireGuard interface if not exists
  if ! ip link show "${WG_INTERFACE}" >/dev/null 2>&1; then
    echo "[entrypoint] creating ${WG_INTERFACE} interface"
    ip link add "${WG_INTERFACE}" type wireguard
  fi

  # Apply WireGuard config from database
  if ! python3 /usr/local/bin/setup_kernel_wg.py --interface "${WG_INTERFACE}"; then
    echo "[entrypoint] failed to setup kernel WireGuard" >&2
    return 1
  fi

  # Get WireGuard server subnet from database
  WG_SUBNET=$(python3 -c "
import sys
sys.path.insert(0, '/usr/local/bin')
from db_helper import get_db
import os
db = get_db(
    os.environ.get('GEODATA_DB_PATH', '/etc/sing-box/geoip-geodata.db'),
    os.environ.get('USER_DB_PATH', '/etc/sing-box/user-config.db')
)
server = db.get_wireguard_server()
if server:
    addr = server.get('address', '10.23.0.1/24')
    # Convert address to subnet (e.g., 10.23.0.1/24 -> 10.23.0.0/24)
    import ipaddress
    net = ipaddress.ip_network(addr, strict=False)
    print(str(net))
else:
    print('10.23.0.0/24')
" 2>/dev/null || echo "10.23.0.0/24")

  echo "[entrypoint] WireGuard subnet: ${WG_SUBNET}"
  echo "[entrypoint] kernel WireGuard interface ready"
}

setup_tproxy_routing() {
  # Setup TPROXY for transparent proxying of WireGuard traffic to sing-box
  echo "[entrypoint] setting up TPROXY routing for WireGuard traffic"

  # Enable ip_nonlocal_bind for TPROXY to work correctly
  # This allows sing-box to send responses with non-local source IPs
  sysctl -w net.ipv4.ip_nonlocal_bind=1 >/dev/null 2>&1 || true
  sysctl -w net.ipv6.ip_nonlocal_bind=1 >/dev/null 2>&1 || true

  # Setup routing table for TPROXY marked packets
  # Marked packets go to local (loopback) for TPROXY processing
  if ! grep -q "^${TPROXY_TABLE}[[:space:]]" /etc/iproute2/rt_tables 2>/dev/null; then
    echo "${TPROXY_TABLE} tproxy" >> /etc/iproute2/rt_tables
    echo "[entrypoint] added routing table tproxy (${TPROXY_TABLE})"
  fi

  # Clear existing rules (including any stale 'from' rules that might break routing)
  ip rule del fwmark ${TPROXY_MARK} lookup ${TPROXY_TABLE} 2>/dev/null || true
  ip rule del from ${WG_SUBNET} lookup ${TPROXY_TABLE} 2>/dev/null || true
  ip route flush table ${TPROXY_TABLE} 2>/dev/null || true

  # Add policy routing: marked packets -> local delivery
  ip rule add fwmark ${TPROXY_MARK} lookup ${TPROXY_TABLE}
  ip route add local 0.0.0.0/0 dev lo table ${TPROXY_TABLE}

  # Clear existing TPROXY iptables rules
  iptables -t mangle -F PREROUTING 2>/dev/null || true

  # Skip traffic to WireGuard server itself (local subnet)
  iptables -t mangle -A PREROUTING -i "${WG_INTERFACE}" -d "${WG_SUBNET}" -j RETURN

  # TPROXY TCP traffic from WireGuard interface to sing-box
  iptables -t mangle -A PREROUTING -i "${WG_INTERFACE}" -p tcp \
    -j TPROXY --on-port ${TPROXY_PORT} --on-ip 127.0.0.1 --tproxy-mark ${TPROXY_MARK}

  # TPROXY UDP traffic from WireGuard interface to sing-box
  iptables -t mangle -A PREROUTING -i "${WG_INTERFACE}" -p udp \
    -j TPROXY --on-port ${TPROXY_PORT} --on-ip 127.0.0.1 --tproxy-mark ${TPROXY_MARK}

  echo "[entrypoint] TPROXY configured: ${WG_INTERFACE} -> 127.0.0.1:${TPROXY_PORT}"

  # NAT/MASQUERADE for WireGuard ingress traffic going to internet
  # Without this, responses from internet can't route back to private WG IPs
  iptables -t nat -D POSTROUTING -s "${WG_SUBNET}" ! -o "${WG_INTERFACE}" -j MASQUERADE 2>/dev/null || true
  iptables -t nat -A POSTROUTING -s "${WG_SUBNET}" ! -o "${WG_INTERFACE}" -j MASQUERADE
  echo "[entrypoint] NAT configured: ${WG_SUBNET} -> MASQUERADE (for internet access)"
}

# Setup kernel WireGuard ingress before other services
setup_kernel_wireguard

# === Kernel WireGuard Egress Setup ===
# Creates wg-pia-* and wg-eg-* interfaces for outbound traffic

setup_kernel_wireguard_egress() {
  echo "[entrypoint] setting up kernel WireGuard egress interfaces"

  # Apply WireGuard egress config from database
  if ! python3 /usr/local/bin/setup_kernel_wg_egress.py; then
    echo "[entrypoint] warning: failed to setup kernel WireGuard egress" >&2
    # Don't fail the container, just log the warning
    return 0
  fi

  echo "[entrypoint] kernel WireGuard egress interfaces ready"
}

# Setup kernel WireGuard egress interfaces (PIA + custom)
setup_kernel_wireguard_egress

start_api_server() {
  if [ "${ENABLE_API:-1}" = "1" ]; then
    local api_port="${API_PORT:-8000}"
    export API_PORT="${api_port}"
    echo "[entrypoint] starting API server on port ${api_port}"
    python3 /usr/local/bin/api_server.py >/var/log/api-server.log 2>&1 &
    API_PID=$!
  fi
}

start_openvpn_manager() {
  # 检查是否有启用的 OpenVPN 配置
  local count
  count=$(python3 -c "
import sys
sys.path.insert(0, '/usr/local/bin')
from db_helper import get_db
db = get_db('/etc/sing-box/geoip-geodata.db', '/etc/sing-box/user-config.db')
print(len(db.get_openvpn_egress_list(enabled_only=True)))
" 2>/dev/null || echo "0")

  if [ "${count}" != "0" ] && [ "${count}" != "" ]; then
    echo "[entrypoint] starting OpenVPN manager (${count} tunnels)"
    python3 /usr/local/bin/openvpn_manager.py daemon >/var/log/openvpn-manager.log 2>&1 &
    OPENVPN_MGR_PID=$!
    echo "[entrypoint] OpenVPN manager started with PID ${OPENVPN_MGR_PID}"
  else
    echo "[entrypoint] no OpenVPN tunnels configured, skipping manager"
  fi
}

# === Xray TUN + TPROXY Setup ===
# Xray for V2Ray ingress uses TUN interface similar to WireGuard

XRAY_INTERFACE="${XRAY_INTERFACE:-xray-tun0}"
XRAY_SUBNET="${XRAY_SUBNET:-10.24.0.0/24}"

setup_xray_tproxy() {
  # Get Xray TUN configuration from database
  local xray_config
  xray_config=$(python3 -c "
import sys
sys.path.insert(0, '/usr/local/bin')
from db_helper import get_db
import os
import json
db = get_db(
    os.environ.get('GEODATA_DB_PATH', '/etc/sing-box/geoip-geodata.db'),
    os.environ.get('USER_DB_PATH', '/etc/sing-box/user-config.db')
)
config = db.get_v2ray_inbound_config()
if config and config.get('enabled'):
    print(json.dumps({
        'enabled': True,
        'tun_device': config.get('tun_device', 'xray-tun0'),
        'tun_subnet': config.get('tun_subnet', '10.24.0.0/24')
    }))
else:
    print(json.dumps({'enabled': False}))
" 2>/dev/null || echo '{"enabled": false}')

  local enabled
  enabled=$(echo "${xray_config}" | python3 -c "import sys, json; print(json.load(sys.stdin).get('enabled', False))")

  if [ "${enabled}" != "True" ]; then
    echo "[entrypoint] Xray V2Ray ingress is disabled, skipping TPROXY setup"
    return 0
  fi

  XRAY_INTERFACE=$(echo "${xray_config}" | python3 -c "import sys, json; print(json.load(sys.stdin).get('tun_device', 'xray-tun0'))")
  XRAY_SUBNET=$(echo "${xray_config}" | python3 -c "import sys, json; print(json.load(sys.stdin).get('tun_subnet', '10.24.0.0/24'))")

  echo "[entrypoint] setting up TPROXY routing for Xray traffic"
  echo "[entrypoint] Xray TUN interface: ${XRAY_INTERFACE}, subnet: ${XRAY_SUBNET}"

  # Skip traffic to Xray server subnet (local subnet)
  iptables -t mangle -A PREROUTING -i "${XRAY_INTERFACE}" -d "${XRAY_SUBNET}" -j RETURN 2>/dev/null || true

  # TPROXY TCP traffic from Xray TUN interface to sing-box
  iptables -t mangle -A PREROUTING -i "${XRAY_INTERFACE}" -p tcp \
    -j TPROXY --on-port ${TPROXY_PORT} --on-ip 127.0.0.1 --tproxy-mark ${TPROXY_MARK} 2>/dev/null || true

  # TPROXY UDP traffic from Xray TUN interface to sing-box
  iptables -t mangle -A PREROUTING -i "${XRAY_INTERFACE}" -p udp \
    -j TPROXY --on-port ${TPROXY_PORT} --on-ip 127.0.0.1 --tproxy-mark ${TPROXY_MARK} 2>/dev/null || true

  echo "[entrypoint] Xray TPROXY configured: ${XRAY_INTERFACE} -> 127.0.0.1:${TPROXY_PORT}"

  # NAT/MASQUERADE for Xray V2Ray ingress traffic going to internet
  iptables -t nat -D POSTROUTING -s "${XRAY_SUBNET}" ! -o "${XRAY_INTERFACE}" -j MASQUERADE 2>/dev/null || true
  iptables -t nat -A POSTROUTING -s "${XRAY_SUBNET}" ! -o "${XRAY_INTERFACE}" -j MASQUERADE
  echo "[entrypoint] NAT configured: ${XRAY_SUBNET} -> MASQUERADE (for internet access)"
}

start_xray_manager() {
  # 检查 V2Ray 入口是否启用
  local enabled
  enabled=$(python3 -c "
import sys
sys.path.insert(0, '/usr/local/bin')
from db_helper import get_db
db = get_db('/etc/sing-box/geoip-geodata.db', '/etc/sing-box/user-config.db')
config = db.get_v2ray_inbound_config()
print('1' if config and config.get('enabled') else '0')
" 2>/dev/null || echo "0")

  if [ "${enabled}" = "1" ]; then
    echo "[entrypoint] starting Xray manager for V2Ray ingress"
    python3 /usr/local/bin/xray_manager.py daemon >/var/log/xray-manager.log 2>&1 &
    XRAY_MGR_PID=$!
    echo "[entrypoint] Xray manager started with PID ${XRAY_MGR_PID}"
  else
    echo "[entrypoint] V2Ray ingress not enabled, skipping Xray manager"
  fi
}

start_xray_egress_manager() {
  # 检查是否有启用的 V2Ray 出口
  local egress_count
  egress_count=$(python3 -c "
import sys
sys.path.insert(0, '/usr/local/bin')
from db_helper import get_db
db = get_db('/etc/sing-box/geoip-geodata.db', '/etc/sing-box/user-config.db')
egress_list = db.get_v2ray_egress_list(enabled_only=True)
print(len(egress_list))
" 2>/dev/null || echo "0")

  if [ "${egress_count}" -gt "0" ]; then
    echo "[entrypoint] starting Xray egress manager for ${egress_count} V2Ray egress"
    python3 /usr/local/bin/xray_egress_manager.py daemon >/var/log/xray-egress-manager.log 2>&1 &
    XRAY_EGRESS_MGR_PID=$!
    echo "[entrypoint] Xray egress manager started with PID ${XRAY_EGRESS_MGR_PID}"
  else
    echo "[entrypoint] No V2Ray egress configured, skipping Xray egress manager"
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
start_openvpn_manager
start_xray_manager
start_xray_egress_manager

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

# Setup TPROXY routing for WireGuard traffic (no need to wait for sing-box)
setup_tproxy_routing

# Setup TPROXY routing for Xray V2Ray ingress traffic
setup_xray_tproxy

# Log rotation configuration
LOG_MAX_SIZE="${LOG_MAX_SIZE:-10485760}"  # 10 MB default
LOG_ROTATE_COUNT=0

rotate_logs() {
  # Only check every 60 seconds
  LOG_ROTATE_COUNT=$((LOG_ROTATE_COUNT + 1))
  if [ $((LOG_ROTATE_COUNT % 60)) -ne 0 ]; then
    return
  fi

  # Rotate sing-box log
  local log_file="/var/log/sing-box.log"
  if [ -f "${log_file}" ]; then
    local size
    size=$(stat -c%s "${log_file}" 2>/dev/null || echo 0)
    if [ "${size}" -gt "${LOG_MAX_SIZE}" ]; then
      echo "[entrypoint] rotating ${log_file} (${size} bytes > ${LOG_MAX_SIZE})"
      # Keep last 1000 lines and truncate
      tail -n 1000 "${log_file}" > "${log_file}.tmp" && mv "${log_file}.tmp" "${log_file}"
    fi
  fi

  # Rotate API server log
  log_file="/var/log/api-server.log"
  if [ -f "${log_file}" ]; then
    local size
    size=$(stat -c%s "${log_file}" 2>/dev/null || echo 0)
    if [ "${size}" -gt "${LOG_MAX_SIZE}" ]; then
      echo "[entrypoint] rotating ${log_file} (${size} bytes)"
      tail -n 1000 "${log_file}" > "${log_file}.tmp" && mv "${log_file}.tmp" "${log_file}"
    fi
  fi

  # Rotate nginx logs
  for log_file in /var/log/nginx/*.log; do
    if [ -f "${log_file}" ]; then
      local size
      size=$(stat -c%s "${log_file}" 2>/dev/null || echo 0)
      if [ "${size}" -gt "${LOG_MAX_SIZE}" ]; then
        echo "[entrypoint] rotating ${log_file} (${size} bytes)"
        tail -n 1000 "${log_file}" > "${log_file}.tmp" && mv "${log_file}.tmp" "${log_file}"
      fi
    fi
  done
}

# 主循环：监控 nginx, API 和 sing-box 进程
while true; do
  rotate_logs
  # Check nginx
  if [ -n "${NGINX_PID}" ] && ! kill -0 "${NGINX_PID}" 2>/dev/null; then
    echo "[entrypoint] WARNING: nginx died" >&2
  fi

  # Check API server
  if [ -n "${API_PID}" ] && ! kill -0 "${API_PID}" 2>/dev/null; then
    echo "[entrypoint] WARNING: API server died" >&2
  fi

  # Check OpenVPN manager
  if [ -n "${OPENVPN_MGR_PID}" ] && ! kill -0 "${OPENVPN_MGR_PID}" 2>/dev/null; then
    echo "[entrypoint] WARNING: OpenVPN manager died, restarting..." >&2
    start_openvpn_manager
  fi

  # Check Xray manager (ingress)
  if [ -n "${XRAY_MGR_PID}" ] && ! kill -0 "${XRAY_MGR_PID}" 2>/dev/null; then
    echo "[entrypoint] WARNING: Xray manager died, restarting..." >&2
    start_xray_manager
  fi

  # Check Xray egress manager
  if [ -n "${XRAY_EGRESS_MGR_PID}" ] && ! kill -0 "${XRAY_EGRESS_MGR_PID}" 2>/dev/null; then
    echo "[entrypoint] WARNING: Xray egress manager died, restarting..." >&2
    start_xray_egress_manager
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

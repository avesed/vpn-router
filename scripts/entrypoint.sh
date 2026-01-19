#!/usr/bin/env bash
set -euo pipefail

# VPN Router Entrypoint - Userspace WireGuard Only
# All traffic is handled by rust-router with boringtun userspace WireGuard

# ============================================================================
# Utility Functions
# ============================================================================

# Phase 11-Fix.Y: Unified iptables backend selection
select_iptables_backend() {
  local nft_pkts legacy_pkts
  nft_pkts=$(iptables-nft -t mangle -L -v -n 2>/dev/null | grep -E "^[[:space:]]*[0-9]+" | awk '{sum+=$1} END {print sum+0}')
  legacy_pkts=$(iptables-legacy -t mangle -L -v -n 2>/dev/null | grep -E "^[[:space:]]*[0-9]+" | awk '{sum+=$1} END {print sum+0}')

  if [ "$nft_pkts" -gt "$legacy_pkts" ] 2>/dev/null; then
    echo "iptables-nft"
  elif [ "$legacy_pkts" -gt 0 ] 2>/dev/null; then
    echo "iptables-legacy"
  else
    echo "iptables-nft"
  fi
}

IPTABLES_BACKEND=$(select_iptables_backend)
IPTABLES="${IPTABLES_BACKEND}"
IP6TABLES="${IPTABLES_BACKEND/iptables/ip6tables}"
echo "[entrypoint] Using iptables backend: ${IPTABLES_BACKEND}"

run_iptables() {
  ${IPTABLES} "$@"
}

# ============================================================================
# Cleanup Functions
# ============================================================================

cleanup() {
  echo "[entrypoint] cleanup: stopping all managed processes..."

  # Stop rust-router
  if [ -n "${RUST_ROUTER_PID:-}" ] && kill -0 "${RUST_ROUTER_PID}" >/dev/null 2>&1; then
    echo "[entrypoint] stopping rust-router (PID ${RUST_ROUTER_PID})"
    kill "${RUST_ROUTER_PID}" >/dev/null 2>&1 || true
  fi

  # Stop health checker
  if [ -n "${HEALTH_CHECKER_PID:-}" ] && kill -0 "${HEALTH_CHECKER_PID}" >/dev/null 2>&1; then
    echo "[entrypoint] stopping health checker (PID ${HEALTH_CHECKER_PID})"
    kill "${HEALTH_CHECKER_PID}" >/dev/null 2>&1 || true
  fi

  # Stop peer tunnel manager
  if [ -n "${PEER_TUNNEL_MGR_PID:-}" ] && kill -0 "${PEER_TUNNEL_MGR_PID}" >/dev/null 2>&1; then
    echo "[entrypoint] stopping peer tunnel manager (PID ${PEER_TUNNEL_MGR_PID})"
    kill "${PEER_TUNNEL_MGR_PID}" >/dev/null 2>&1 || true
  fi

  # Stop tunnel managers
  if [ -n "${WARP_MGR_PID:-}" ] && kill -0 "${WARP_MGR_PID}" >/dev/null 2>&1; then
    echo "[entrypoint] stopping WARP manager (PID ${WARP_MGR_PID})"
    kill "${WARP_MGR_PID}" >/dev/null 2>&1 || true
  fi
  if [ -n "${XRAY_EGRESS_MGR_PID:-}" ] && kill -0 "${XRAY_EGRESS_MGR_PID}" >/dev/null 2>&1; then
    echo "[entrypoint] stopping Xray egress manager (PID ${XRAY_EGRESS_MGR_PID})"
    kill "${XRAY_EGRESS_MGR_PID}" >/dev/null 2>&1 || true
  fi
  if [ -n "${XRAY_MGR_PID:-}" ] && kill -0 "${XRAY_MGR_PID}" >/dev/null 2>&1; then
    echo "[entrypoint] stopping Xray manager (PID ${XRAY_MGR_PID})"
    kill "${XRAY_MGR_PID}" >/dev/null 2>&1 || true
  fi
  if [ -n "${OPENVPN_MGR_PID:-}" ] && kill -0 "${OPENVPN_MGR_PID}" >/dev/null 2>&1; then
    echo "[entrypoint] stopping OpenVPN manager (PID ${OPENVPN_MGR_PID})"
    kill "${OPENVPN_MGR_PID}" >/dev/null 2>&1 || true
  fi

  # Stop web services
  if [ -n "${NGINX_PID:-}" ] && kill -0 "${NGINX_PID}" >/dev/null 2>&1; then
    echo "[entrypoint] stopping nginx (PID ${NGINX_PID})"
    kill "${NGINX_PID}" >/dev/null 2>&1 || true
  fi
  if [ -n "${API_PID:-}" ] && kill -0 "${API_PID}" >/dev/null 2>&1; then
    echo "[entrypoint] stopping API server (PID ${API_PID})"
    kill "${API_PID}" >/dev/null 2>&1 || true
  fi

  # Cleanup DSCP rules
  echo "[entrypoint] cleaning up DSCP rules..."
  python3 /usr/local/bin/dscp_manager.py cleanup 2>/dev/null || true

  # Cleanup rust-router socket
  rm -f "${RUST_ROUTER_SOCKET}" 2>/dev/null || true

  # Cleanup stale WireGuard egress interfaces (wg-warp-*, wg-peer-*)
  for iface in $(ip -br link show type wireguard 2>/dev/null | awk '{print $1}' | grep -E '^wg-(warp|peer)-'); do
    echo "[entrypoint] removing interface: ${iface}"
    ip link delete "${iface}" 2>/dev/null || true
  done

  # Cleanup Xray TUN interface
  if ip link show xray-tun0 >/dev/null 2>&1; then
    echo "[entrypoint] removing xray-tun0 interface"
    ip link delete xray-tun0 2>/dev/null || true
  fi

  echo "[entrypoint] cleanup complete"
}

trap cleanup EXIT

# ============================================================================
# PID Variables
# ============================================================================

API_PID=""
NGINX_PID=""
OPENVPN_MGR_PID=""
XRAY_MGR_PID=""
XRAY_EGRESS_MGR_PID=""
WARP_MGR_PID=""
HEALTH_CHECKER_PID=""
PEER_TUNNEL_MGR_PID=""
RUST_ROUTER_PID=""

# ============================================================================
# Configuration
# ============================================================================

BASE_CONFIG_PATH="${SING_BOX_CONFIG:-/etc/sing-box/sing-box.json}"
GENERATED_CONFIG_PATH="${SING_BOX_GENERATED_CONFIG:-/etc/sing-box/sing-box.generated.json}"
RULESET_DIR="${RULESET_DIR:-/etc/sing-box}"
GEO_DATA_READY_FLAG="${RULESET_DIR}/.geodata-ready"
USER_DB_PATH="${USER_DB_PATH:-/etc/sing-box/user-config.db}"
DEFAULT_CONFIG_DIR="/opt/default-config"

# Port configuration
export WEB_PORT="${WEB_PORT:-36000}"
export WG_LISTEN_PORT="${WG_LISTEN_PORT:-36100}"

# Rust Router configuration
RUST_ROUTER_BIN="${RUST_ROUTER_BIN:-/usr/local/bin/rust-router}"
RUST_ROUTER_CONFIG="${RUST_ROUTER_CONFIG:-/etc/rust-router/config.json}"
RUST_ROUTER_SOCKET="${RUST_ROUTER_SOCKET:-/var/run/rust-router.sock}"
RUST_ROUTER_LOG="${RUST_ROUTER_LOG:-/var/log/rust-router.log}"
RUST_ROUTER_DNS_PORT="${RUST_ROUTER_DNS_PORT:-7853}"

# Userspace WireGuard is always enabled (kernel mode removed)
USERSPACE_WG="true"
export USERSPACE_WG

# ============================================================================
# Startup Cleanup (for host network mode)
# ============================================================================

cleanup_stale_interfaces() {
  # With host network mode, WireGuard interfaces persist after container exit.
  # Clean them up at startup to prevent port conflicts.
  echo "[entrypoint] cleaning up stale interfaces from previous run..."

  # Cleanup wg-ingress if it exists
  if ip link show wg-ingress >/dev/null 2>&1; then
    echo "[entrypoint] removing stale wg-ingress interface"
    ip link delete wg-ingress 2>/dev/null || true
  fi

  # Cleanup PIA egress interfaces (wg-pia-*)
  for iface in $(ip -br link show type wireguard 2>/dev/null | awk '{print $1}' | grep -E '^wg-pia-'); do
    echo "[entrypoint] removing stale interface: ${iface}"
    ip link delete "${iface}" 2>/dev/null || true
  done

  # Cleanup WARP and peer interfaces (wg-warp-*, wg-peer-*)
  for iface in $(ip -br link show type wireguard 2>/dev/null | awk '{print $1}' | grep -E '^wg-(warp|peer)-'); do
    echo "[entrypoint] removing stale interface: ${iface}"
    ip link delete "${iface}" 2>/dev/null || true
  done

  echo "[entrypoint] stale interface cleanup complete"
}

# ============================================================================
# Port Conflict Checks
# ============================================================================

check_port_conflicts() {
  local port="$1"
  local service="$2"
  local protocol="${3:-tcp}"

  if [ "${protocol}" = "udp" ]; then
    if ss -uln "sport = :${port}" 2>/dev/null | grep -q ":${port}"; then
      echo "[entrypoint] ERROR: Port ${port}/udp is already in use (required for ${service})" >&2
      return 1
    fi
  else
    if ss -tln "sport = :${port}" 2>/dev/null | grep -q ":${port}"; then
      echo "[entrypoint] ERROR: Port ${port}/tcp is already in use (required for ${service})" >&2
      return 1
    fi
  fi
  return 0
}

verify_required_ports() {
  local has_conflict=0

  echo "[entrypoint] checking for port conflicts..."

  if ! check_port_conflicts "${WEB_PORT}" "nginx/web UI" "tcp"; then
    has_conflict=1
  fi

  if ! check_port_conflicts "${API_PORT:-8000}" "API server" "tcp"; then
    has_conflict=1
  fi

  if ! check_port_conflicts "${WG_LISTEN_PORT}" "WireGuard ingress" "udp"; then
    has_conflict=1
  fi

  if [ ${has_conflict} -eq 1 ]; then
    echo "[entrypoint] FATAL: Port conflicts detected." >&2
    exit 1
  fi

  echo "[entrypoint] no port conflicts detected"
}

# ============================================================================
# Initialization
# ============================================================================

# Copy default configs if not present
if [ ! -f "${BASE_CONFIG_PATH}" ] && [ -f "${DEFAULT_CONFIG_DIR}/sing-box.json" ]; then
  echo "[entrypoint] initializing sing-box config from default config"
  cp "${DEFAULT_CONFIG_DIR}/sing-box.json" "${BASE_CONFIG_PATH}"
fi

DOMAIN_CATALOG="${RULESET_DIR}/domain-catalog.json"
if [ ! -f "${DOMAIN_CATALOG}" ] && [ -f "${DEFAULT_CONFIG_DIR}/domain-catalog.json" ]; then
  echo "[entrypoint] initializing domain catalog from default config"
  cp "${DEFAULT_CONFIG_DIR}/domain-catalog.json" "${DOMAIN_CATALOG}"
fi

GEOIP_CATALOG="${RULESET_DIR}/geoip-catalog.json"
GEOIP_DIR="${RULESET_DIR}/geoip"
if [ ! -f "${GEOIP_CATALOG}" ] && [ -f "${DEFAULT_CONFIG_DIR}/geoip-catalog.json" ]; then
  echo "[entrypoint] initializing GeoIP catalog from default config"
  cp "${DEFAULT_CONFIG_DIR}/geoip-catalog.json" "${GEOIP_CATALOG}"
fi
if [ ! -d "${GEOIP_DIR}" ] && [ -d "${DEFAULT_CONFIG_DIR}/geoip" ]; then
  echo "[entrypoint] initializing GeoIP data directory from default config"
  cp -r "${DEFAULT_CONFIG_DIR}/geoip" "${GEOIP_DIR}"
fi

if [ ! -f "${BASE_CONFIG_PATH}" ]; then
  echo "[entrypoint] config ${BASE_CONFIG_PATH} not found" >&2
  exit 1
fi

# SQLCipher key management
echo "[entrypoint] initializing encryption key"
export SQLCIPHER_KEY=$(python3 -c "from key_manager import KeyManager; print(KeyManager.get_or_create_key())")
if [ -z "${SQLCIPHER_KEY}" ]; then
  echo "[entrypoint] warning: failed to get encryption key, database will be unencrypted"
fi

# Database backup and migration
if [ -f "${USER_DB_PATH}" ]; then
  BACKUP_DIR="${RULESET_DIR}/backups"
  mkdir -p "${BACKUP_DIR}"
  BACKUP_FILE="${BACKUP_DIR}/user-config.db.$(date +%Y%m%d_%H%M%S).bak"
  cp "${USER_DB_PATH}" "${BACKUP_FILE}" 2>/dev/null || true
  echo "[entrypoint] created database backup: ${BACKUP_FILE}"
  ls -t "${BACKUP_DIR}"/user-config.db.*.bak 2>/dev/null | tail -n +6 | xargs rm -f 2>/dev/null || true

  python3 -c "
from key_manager import KeyManager
import os
db_path = os.environ.get('USER_DB_PATH', '/etc/sing-box/user-config.db')
if KeyManager.is_database_encrypted(db_path):
    print('[entrypoint] database already encrypted')
else:
    print('[entrypoint] migrating unencrypted database to encrypted')
    KeyManager.migrate_unencrypted_database(db_path)
"
fi

# Initialize user database
echo "[entrypoint] initializing user database: ${USER_DB_PATH}"
python3 /usr/local/bin/init_user_db.py /etc/sing-box
if [ $? -ne 0 ]; then
  echo "[entrypoint] failed to initialize user database" >&2
  exit 1
fi

# Cleanup stale interfaces from previous container run (host network mode)
cleanup_stale_interfaces

# Verify ports
verify_required_ports

# System settings
sysctl -w net.ipv4.ip_forward=1 >/dev/null 2>&1 || true
sysctl -w net.ipv4.conf.all.rp_filter=0 >/dev/null 2>&1 || true
sysctl -w net.ipv4.conf.default.rp_filter=0 >/dev/null 2>&1 || true

if [ "${DISABLE_IPV6:-1}" = "1" ]; then
  sysctl -w net.ipv6.conf.all.disable_ipv6=1 >/dev/null || true
  sysctl -w net.ipv6.conf.default.disable_ipv6=1 >/dev/null || true
fi

# Fetch geodata
/usr/local/bin/fetch-geodata.sh "${RULESET_DIR}" "${GEO_DATA_READY_FLAG}"

# ============================================================================
# ECMP and Chain Routes
# ============================================================================

# NOTE: sync_ecmp_routes removed - kernel ECMP routes no longer needed.
# rust-router handles load balancing internally with userspace WireGuard.
sync_ecmp_routes() {
  # Legacy function - now a no-op since rust-router handles ECMP internally
  echo "[entrypoint] ECMP routes managed by rust-router (userspace mode)"
}

sync_chain_routes() {
  # Phase 12: No-op - rust-router handles DSCP routing in userspace
  # Chain routes are managed by rust-router's ChainManager
  # See rust-router/src/ingress/processor.rs for DSCP routing logic
  echo "[entrypoint] chain routes managed by rust-router (userspace DSCP routing)"
}

restore_dscp_rules() {
  # Phase 12: No-op - rust-router handles DSCP routing in userspace
  # No kernel iptables/policy routing rules needed
  echo "[entrypoint] DSCP rules managed by rust-router (userspace mode)"
}

sync_ecmp_routes
sync_chain_routes
restore_dscp_rules

# ============================================================================
# Rust Router Sync
# ============================================================================

sync_rust_router() {
  local max_wait=30
  local waited=0
  while [ ! -S "${RUST_ROUTER_SOCKET}" ] && [ $waited -lt $max_wait ]; do
    sleep 1
    waited=$((waited + 1))
    if [ $((waited % 5)) -eq 0 ]; then
      echo "[entrypoint] waiting for rust-router socket... (${waited}/${max_wait}s)"
    fi
  done

  if [ ! -S "${RUST_ROUTER_SOCKET}" ]; then
    echo "[entrypoint] WARNING: rust-router socket not available after ${max_wait}s, skipping sync"
    return 1
  fi

  echo "[entrypoint] syncing configuration to rust-router via IPC"
  if python3 /usr/local/bin/rust_router_manager.py sync 2>&1 | head -50; then
    echo "[entrypoint] rust-router sync completed"
  else
    echo "[entrypoint] WARNING: rust-router sync failed"
    return 1
  fi
}

# ============================================================================
# Service Start Functions
# ============================================================================

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
  else
    echo "[entrypoint] no OpenVPN tunnels configured, skipping manager"
  fi
}

start_xray_manager() {
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
  else
    echo "[entrypoint] V2Ray ingress not enabled, skipping Xray manager"
  fi
}

start_xray_egress_manager() {
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
  else
    echo "[entrypoint] No V2Ray egress configured, skipping Xray egress manager"
  fi
}

# Phase 3: start_warp_manager() removed - MASQUE deprecated, WireGuard managed via rust-router IPC

start_health_checker() {
  local group_count
  group_count=$(python3 -c "
import sys
sys.path.insert(0, '/usr/local/bin')
from db_helper import get_db
db = get_db('/etc/sing-box/geoip-geodata.db', '/etc/sing-box/user-config.db')
groups = db.get_outbound_groups(enabled_only=True)
print(len(groups))
" 2>/dev/null || echo "0")

  if [ "${group_count}" -gt "0" ]; then
    echo "[entrypoint] starting health checker for ${group_count} outbound groups"
    python3 /usr/local/bin/health_checker.py --daemon >/var/log/health-checker.log 2>&1 &
    HEALTH_CHECKER_PID=$!
  else
    echo "[entrypoint] No outbound groups configured, skipping health checker"
  fi
}

start_peer_tunnel_manager() {
  # Phase 12: peer_tunnel_manager.py uses kernel WireGuard (wg set/show).
  # In userspace mode, peer tunnels are managed by rust-router via IPC.
  # Skip this legacy manager.
  echo "[entrypoint] peer tunnels managed by rust-router (userspace mode)"
}

start_nginx() {
  echo "[entrypoint] starting nginx on port ${WEB_PORT}"

  mkdir -p /var/log/nginx
  chown www-data:www-data /var/log/nginx 2>/dev/null || true

  NGINX_TEMPLATE="/etc/nginx/nginx.conf.template"
  NGINX_CONF="/etc/nginx/conf.d/default.conf"
  if [ -f "${NGINX_TEMPLATE}" ]; then
    envsubst '${WEB_PORT} ${API_PORT}' < "${NGINX_TEMPLATE}" > "${NGINX_CONF}"
  fi

  nginx -t
  if [ $? -ne 0 ]; then
    echo "[entrypoint] nginx configuration test failed" >&2
    exit 1
  fi

  nginx -g "daemon off;" &
  NGINX_PID=$!

  sleep 2
  if ! kill -0 "${NGINX_PID}" 2>/dev/null; then
    echo "[entrypoint] nginx failed to start" >&2
    exit 1
  fi
}

start_rust_router() {
  if [ ! -x "${RUST_ROUTER_BIN}" ]; then
    echo "[entrypoint] rust-router binary not found at ${RUST_ROUTER_BIN}" >&2
    return 1
  fi

  if [ ! -f "${RUST_ROUTER_CONFIG}" ]; then
    echo "[entrypoint] rust-router config not found at ${RUST_ROUTER_CONFIG}" >&2
    return 1
  fi

  echo "[entrypoint] starting rust-router with ${RUST_ROUTER_CONFIG}"

  # Environment variables for rust-router
  export RUST_ROUTER_LISTEN="0.0.0.0:7894"
  export RUST_ROUTER_CONFIG="${RUST_ROUTER_CONFIG}"
  export RUST_ROUTER_SOCKET="${RUST_ROUTER_SOCKET}"
  # Log level: RUST_LOG takes precedence, then RUST_ROUTER_LOG_LEVEL
  export RUST_LOG="${RUST_LOG:-info}"
  if [ -n "${RUST_ROUTER_LOG_LEVEL:-}" ]; then
    export RUST_ROUTER_LOG_LEVEL="${RUST_ROUTER_LOG_LEVEL}"
  fi

  # Userspace WireGuard configuration
  export RUST_ROUTER_USERSPACE_WG="true"
  export RUST_ROUTER_WG_LISTEN_PORT="${WG_LISTEN_PORT}"

  # Get WireGuard private key from database
  RUST_ROUTER_WG_PRIVATE_KEY=$(python3 -c "
import sys
sys.path.insert(0, '/usr/local/bin')
from db_helper import get_db
import os
from pathlib import Path

encryption_key = os.environ.get('SQLCIPHER_KEY')
if not encryption_key:
    key_file = Path(os.environ.get('USER_DB_PATH', '/etc/sing-box/user-config.db')).parent / 'encryption.key'
    if key_file.exists():
        encryption_key = key_file.read_text().strip()

db = get_db(
    os.environ.get('GEODATA_DB_PATH', '/etc/sing-box/geoip-geodata.db'),
    os.environ.get('USER_DB_PATH', '/etc/sing-box/user-config.db'),
    encryption_key
)
server = db.get_wireguard_server()
if server and server.get('private_key'):
    print(server['private_key'])
else:
    print('')
" 2>/dev/null || echo "")

  if [ -n "${RUST_ROUTER_WG_PRIVATE_KEY}" ]; then
    export RUST_ROUTER_WG_PRIVATE_KEY
    echo "[entrypoint] rust-router userspace WireGuard enabled (port ${WG_LISTEN_PORT})"
  else
    echo "[entrypoint] WARNING: No WireGuard private key found in database" >&2
  fi

  # Start rust-router
  "${RUST_ROUTER_BIN}" >> "${RUST_ROUTER_LOG}" 2>&1 &
  RUST_ROUTER_PID=$!

  sleep 1
  if ! kill -0 "${RUST_ROUTER_PID}" 2>/dev/null; then
    echo "[entrypoint] rust-router failed to start, check ${RUST_ROUTER_LOG}" >&2
    RUST_ROUTER_PID=""
    return 1
  fi

  echo "[entrypoint] rust-router started (PID: ${RUST_ROUTER_PID})"
  return 0
}

# ============================================================================
# Signal Handling
# ============================================================================

handle_signals() {
  echo "[entrypoint] received signal, shutting down..."

  if [ -n "${RUST_ROUTER_PID:-}" ] && kill -0 "${RUST_ROUTER_PID}" 2>/dev/null; then
    echo "[entrypoint] stopping rust-router"
    kill "${RUST_ROUTER_PID}" 2>/dev/null || true
    wait "${RUST_ROUTER_PID}" 2>/dev/null || true
  fi

  cleanup
  exit 0
}

trap handle_signals SIGTERM SIGINT

# ============================================================================
# Config Generation
# ============================================================================

# PIA provisioning
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

# NOTE: render_singbox.py removed - sing-box is no longer used.
# rust-router handles all routing and WireGuard tunnels in userspace.
# The sing-box.generated.json file is no longer needed.

# Generate rust-router config
echo "[entrypoint] rendering rust-router config"
mkdir -p "$(dirname "${RUST_ROUTER_CONFIG}")"
export RUST_ROUTER_PORT="7894"
if ! python3 /usr/local/bin/render_routing_config.py \
    --format=rust-router \
    --output="${RUST_ROUTER_CONFIG}"; then
  echo "[entrypoint] rust-router config generation failed" >&2
  exit 1
fi
echo "[entrypoint] rust-router config generated: ${RUST_ROUTER_CONFIG}"

# ============================================================================
# Start Services
# ============================================================================

start_api_server
start_nginx
start_openvpn_manager
start_xray_manager
start_xray_egress_manager

# Start rust-router first (health_checker needs IPC socket)
echo "[entrypoint] starting rust-router (userspace WireGuard mode)"
if start_rust_router; then
  echo "[entrypoint] rust-router started successfully"
  sync_rust_router || echo "[entrypoint] WARNING: initial sync failed, will retry later"
else
  echo "[entrypoint] FATAL: rust-router failed to start" >&2
  exit 1
fi

# Start health checker AFTER rust-router (needs IPC socket)
start_health_checker
start_peer_tunnel_manager

# Phase 3: WARP manager removed - WARP tunnels managed via rust-router IPC

# NOTE: Peer tunnel subnet routing removed - userspace WireGuard mode
# routes HTTP traffic through rust-router's internal WireGuard implementation

echo "[entrypoint] DNS engine: enabled (port ${RUST_ROUTER_DNS_PORT})"

# ============================================================================
# Log Rotation
# ============================================================================

LOG_MAX_SIZE="${LOG_MAX_SIZE:-10485760}"
LOG_ROTATE_COUNT=0

rotate_logs() {
  LOG_ROTATE_COUNT=$((LOG_ROTATE_COUNT + 1))
  if [ $((LOG_ROTATE_COUNT % 60)) -ne 0 ]; then
    return
  fi

  for log_file in /var/log/api-server.log /var/log/rust-router.log /var/log/nginx/*.log; do
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

# ============================================================================
# Main Loop
# ============================================================================

SYNC_CHECK_COUNT=0

while true; do
  rotate_logs

  # Periodic rust-router sync (every 5 minutes)
  SYNC_CHECK_COUNT=$((SYNC_CHECK_COUNT + 1))
  if [ $((SYNC_CHECK_COUNT % 300)) -eq 0 ]; then
    if [ -S "${RUST_ROUTER_SOCKET}" ]; then
      sync_rust_router >/dev/null 2>&1 || true
    fi
  fi

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

  # Check Xray manager
  if [ -n "${XRAY_MGR_PID}" ] && ! kill -0 "${XRAY_MGR_PID}" 2>/dev/null; then
    echo "[entrypoint] WARNING: Xray manager died, restarting..." >&2
    start_xray_manager
  fi

  # Check Xray egress manager
  if [ -n "${XRAY_EGRESS_MGR_PID}" ] && ! kill -0 "${XRAY_EGRESS_MGR_PID}" 2>/dev/null; then
    echo "[entrypoint] WARNING: Xray egress manager died, restarting..." >&2
    start_xray_egress_manager
  fi

  # Phase 3: WARP manager check removed (deprecated)

  # Check health checker
  if [ -n "${HEALTH_CHECKER_PID}" ] && ! kill -0 "${HEALTH_CHECKER_PID}" 2>/dev/null; then
    echo "[entrypoint] WARNING: health checker died, restarting..." >&2
    start_health_checker
  fi

  # Check peer tunnel manager
  if [ -n "${PEER_TUNNEL_MGR_PID}" ] && ! kill -0 "${PEER_TUNNEL_MGR_PID}" 2>/dev/null; then
    echo "[entrypoint] WARNING: peer tunnel manager died, restarting..." >&2
    start_peer_tunnel_manager
  fi

  # Check rust-router
  if [ -n "${RUST_ROUTER_PID}" ] && ! kill -0 "${RUST_ROUTER_PID}" 2>/dev/null; then
    wait "${RUST_ROUTER_PID}" 2>/dev/null || true
    EXIT_CODE=$?
    echo "[entrypoint] rust-router exited with code ${EXIT_CODE}"

    if start_rust_router; then
      echo "[entrypoint] rust-router restarted successfully"
      sync_rust_router || echo "[entrypoint] WARNING: sync after restart failed"
    else
      echo "[entrypoint] FATAL: rust-router restart failed" >&2
      exit 1
    fi
  fi

  sleep 1
done

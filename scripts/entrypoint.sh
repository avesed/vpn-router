#!/usr/bin/env bash
set -euo pipefail

# Phase 11-Fix.Y: Unified iptables backend selection
# Problem: iptables-nft and iptables-legacy can coexist with separate rule sets
# causing TPROXY rules to be invisible to the kernel if set on wrong backend.
# Solution: Detect and use the backend that the kernel is actually using.
select_iptables_backend() {
  # Check which backend the kernel is using by looking at existing rules
  # If nft has rules with packet counts > 0, kernel is using nft
  local nft_pkts legacy_pkts
  nft_pkts=$(iptables-nft -t mangle -L -v -n 2>/dev/null | grep -E "^[[:space:]]*[0-9]+" | awk '{sum+=$1} END {print sum+0}')
  legacy_pkts=$(iptables-legacy -t mangle -L -v -n 2>/dev/null | grep -E "^[[:space:]]*[0-9]+" | awk '{sum+=$1} END {print sum+0}')

  if [ "$nft_pkts" -gt "$legacy_pkts" ] 2>/dev/null; then
    echo "iptables-nft"
  elif [ "$legacy_pkts" -gt 0 ] 2>/dev/null; then
    echo "iptables-legacy"
  else
    # Default to nft as it's the modern default
    echo "iptables-nft"
  fi
}

# Select and export iptables backend
IPTABLES_BACKEND=$(select_iptables_backend)
IPTABLES="${IPTABLES_BACKEND}"
IP6TABLES="${IPTABLES_BACKEND/iptables/ip6tables}"
echo "[entrypoint] Using iptables backend: ${IPTABLES_BACKEND}"

# Helper function to run iptables with correct backend
run_iptables() {
  ${IPTABLES} "$@"
}

cleanup() {
  echo "[entrypoint] cleanup: stopping all managed processes..."

  # Stop rust-router if running (Phase 6)
  if [ -n "${RUST_ROUTER_PID:-}" ] && kill -0 "${RUST_ROUTER_PID}" >/dev/null 2>&1; then
    echo "[entrypoint] stopping rust-router (PID ${RUST_ROUTER_PID})"
    kill "${RUST_ROUTER_PID}" >/dev/null 2>&1 || true
  fi

  # Stop health checker first (depends on other services)
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

  # Cleanup DSCP rules (chain routes)
  echo "[entrypoint] cleaning up DSCP rules..."
  python3 /usr/local/bin/dscp_manager.py cleanup 2>/dev/null || true

  # Cleanup rust-router socket (Phase 6)
  rm -f "${RUST_ROUTER_SOCKET}" 2>/dev/null || true

  # Cleanup WireGuard interfaces created by this container
  cleanup_wireguard_interfaces

  echo "[entrypoint] cleanup complete"
}
trap cleanup EXIT
API_PID=""
NGINX_PID=""
OPENVPN_MGR_PID=""
XRAY_MGR_PID=""
XRAY_EGRESS_MGR_PID=""
WARP_MGR_PID=""
HEALTH_CHECKER_PID=""
PEER_TUNNEL_MGR_PID=""
RUST_ROUTER_PID=""

# Cleanup WireGuard interfaces created by this container
# This is important for network_mode: host to prevent stale interfaces
# Note: In Phase 6 userspace mode, kernel WireGuard interfaces are not created,
# but this function is safe to call anyway (operations are idempotent with || true)
cleanup_wireguard_interfaces() {
  echo "[entrypoint] cleaning up WireGuard interfaces..."

  # Cleanup ingress interface (not present in userspace mode)
  if ip link show wg-ingress >/dev/null 2>&1; then
    echo "[entrypoint] removing wg-ingress interface"
    ip link delete wg-ingress 2>/dev/null || true
  fi

  # Cleanup egress interfaces (wg-pia-*, wg-eg-*, wg-warp-*, wg-peer-*)
  for iface in $(ip -br link show type wireguard 2>/dev/null | awk '{print $1}' | grep -E '^wg-(pia|eg|warp|peer)-'); do
    echo "[entrypoint] removing interface: ${iface}"
    ip link delete "${iface}" 2>/dev/null || true
  done

  # Cleanup Xray TUN interface
  if ip link show xray-tun0 >/dev/null 2>&1; then
    echo "[entrypoint] removing xray-tun0 interface"
    ip link delete xray-tun0 2>/dev/null || true
  fi

  # Cleanup iptables rules (TPROXY and NAT)
  echo "[entrypoint] cleaning up iptables rules..."
  ${IPTABLES} -t mangle -F PREROUTING 2>/dev/null || true
  # Phase 11-Fix.X: Cleanup DIVERT chain
  ${IPTABLES} -t mangle -F DIVERT 2>/dev/null || true
  ${IPTABLES} -t mangle -X DIVERT 2>/dev/null || true
  ${IPTABLES} -t nat -D POSTROUTING -s "10.25.0.0/24" ! -o "wg-ingress" -j MASQUERADE 2>/dev/null || true
  ${IPTABLES} -t nat -D POSTROUTING -s "10.24.0.0/24" ! -o "xray-tun0" -j MASQUERADE 2>/dev/null || true

  # Phase 11-Fix.W: Cleanup route_localnet security rules (raw table)
  # Phase 11-Fix.X: Fixed syntax to match the updated setup rules
  ${IPTABLES} -t raw -D PREROUTING -d 127.0.0.0/8 -i lo -j ACCEPT 2>/dev/null || true
  ${IPTABLES} -t raw -D PREROUTING -d 127.0.0.0/8 -i wg-ingress -j ACCEPT 2>/dev/null || true
  ${IPTABLES} -t raw -D PREROUTING -d 127.0.0.0/8 -j DROP 2>/dev/null || true
  ${IPTABLES} -t raw -D PREROUTING -i xray-tun0 -d 127.0.0.0/8 -j ACCEPT 2>/dev/null || true
  # Note: Do NOT reset route_localnet sysctl - it's a host setting with network_mode: host
  # Resetting could break other services on the host

  # Phase 7.7: Clean up DNS redirect rules
  ${IPTABLES} -t nat -D PREROUTING -i wg-ingress -p udp --dport 53 -j REDIRECT --to-port "${RUST_ROUTER_DNS_PORT:-7853}" 2>/dev/null || true
  ${IPTABLES} -t nat -D PREROUTING -i wg-ingress -p tcp --dport 53 -j REDIRECT --to-port "${RUST_ROUTER_DNS_PORT:-7853}" 2>/dev/null || true
  ${IPTABLES} -t nat -D PREROUTING -i xray-tun0 -p udp --dport 53 -j REDIRECT --to-port "${RUST_ROUTER_DNS_PORT:-7853}" 2>/dev/null || true
  ${IPTABLES} -t nat -D PREROUTING -i xray-tun0 -p tcp --dport 53 -j REDIRECT --to-port "${RUST_ROUTER_DNS_PORT:-7853}" 2>/dev/null || true

  # Phase 6 Fix: Cleanup peer tunnel subnet route
  ip route del local 10.200.200.0/24 dev lo 2>/dev/null || true

  # Cleanup ip rules
  ip rule del fwmark 1 lookup 100 2>/dev/null || true
}

# Cleanup any stale interfaces from previous runs before starting
cleanup_stale_interfaces() {
  echo "[entrypoint] checking for stale interfaces from previous runs..."

  # Only cleanup if interface exists but process is not running
  if ip link show wg-ingress >/dev/null 2>&1; then
    # Check if sing-box is running (it manages the ingress)
    if ! pgrep -x sing-box >/dev/null 2>&1; then
      echo "[entrypoint] found stale wg-ingress, cleaning up"
      ip link delete wg-ingress 2>/dev/null || true
    fi
  fi
}

BASE_CONFIG_PATH="${SING_BOX_CONFIG:-/etc/sing-box/sing-box.json}"
GENERATED_CONFIG_PATH="${SING_BOX_GENERATED_CONFIG:-/etc/sing-box/sing-box.generated.json}"
WG_CONFIG_PATH="${WG_CONFIG_PATH:-/etc/sing-box/wireguard/server.json}"
RULESET_DIR="${RULESET_DIR:-/etc/sing-box}"
GEO_DATA_READY_FLAG="${RULESET_DIR}/.geodata-ready"
USER_DB_PATH="${USER_DB_PATH:-/etc/sing-box/user-config.db}"
DEFAULT_CONFIG_DIR="/opt/default-config"

# Port configuration
export WEB_PORT="${WEB_PORT:-36000}"
export WG_LISTEN_PORT="${WG_LISTEN_PORT:-36100}"

# Rust Router configuration
# rust-router is the primary data plane (9.01/10 final score)
# Fallback to sing-box only if rust-router binary is missing
RUST_ROUTER_BIN="${RUST_ROUTER_BIN:-/usr/local/bin/rust-router}"
RUST_ROUTER_CONFIG="${RUST_ROUTER_CONFIG:-/etc/rust-router/config.json}"
RUST_ROUTER_SOCKET="${RUST_ROUTER_SOCKET:-/var/run/rust-router.sock}"
RUST_ROUTER_LOG="${RUST_ROUTER_LOG:-/var/log/rust-router.log}"

# Phase 6: Userspace WireGuard mode (default)
# rust-router handles WireGuard in userspace via boringtun
# Set USERSPACE_WG=false to use kernel WireGuard (requires wireguard kernel module)
USERSPACE_WG="${USERSPACE_WG:-true}"

# Phase 7: DNS engine port (always enabled, no separate flag needed)
# The DNS engine listens on 127.0.0.1:7853 by default and provides:
# - Ad blocking (DomainMatcher integration)
# - DNS caching (moka LRU, per-entry TTL)
# - DNS splitting (per-domain upstream routing)
# - Query logging (async writer, 7-day rotation)
RUST_ROUTER_DNS_PORT="${RUST_ROUTER_DNS_PORT:-7853}"

# Track which router is active (rust-router or sing-box)
ACTIVE_ROUTER="rust-router"

# Check for port conflicts before starting services
check_port_conflicts() {
  local port="$1"
  local service="$2"
  local protocol="${3:-tcp}"

  if [ "${protocol}" = "udp" ]; then
    # Check UDP port
    if ss -uln "sport = :${port}" 2>/dev/null | grep -q ":${port}"; then
      echo "[entrypoint] ERROR: Port ${port}/udp is already in use (required for ${service})" >&2
      return 1
    fi
  else
    # Check TCP port
    if ss -tln "sport = :${port}" 2>/dev/null | grep -q ":${port}"; then
      echo "[entrypoint] ERROR: Port ${port}/tcp is already in use (required for ${service})" >&2
      return 1
    fi
  fi
  return 0
}

# Verify critical ports are available
verify_required_ports() {
  local has_conflict=0

  echo "[entrypoint] checking for port conflicts..."

  # Check web port
  if ! check_port_conflicts "${WEB_PORT}" "nginx/web UI" "tcp"; then
    has_conflict=1
  fi

  # Check API port
  if ! check_port_conflicts "${API_PORT:-8000}" "API server" "tcp"; then
    has_conflict=1
  fi

  # Check WireGuard port
  if ! check_port_conflicts "${WG_LISTEN_PORT}" "WireGuard ingress" "udp"; then
    has_conflict=1
  fi

  if [ ${has_conflict} -eq 1 ]; then
    echo "[entrypoint] FATAL: Port conflicts detected. Resolve conflicts or change port configuration." >&2
    echo "[entrypoint] Hint: Set WEB_PORT, API_PORT, or WG_LISTEN_PORT environment variables" >&2
    exit 1
  fi

  echo "[entrypoint] no port conflicts detected"
}

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

# 初始化 GeoIP catalog 和 IP 数据文件 (JSON 格式，替代 49MB SQLite 数据库)
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

# === SQLCipher 密钥管理 ===
# 获取或创建数据库加密密钥
echo "[entrypoint] initializing encryption key"
export SQLCIPHER_KEY=$(python3 -c "from key_manager import KeyManager; print(KeyManager.get_or_create_key())")
if [ -z "${SQLCIPHER_KEY}" ]; then
  echo "[entrypoint] warning: failed to get encryption key, database will be unencrypted"
fi

# 检测并迁移未加密数据库
if [ -f "${USER_DB_PATH}" ]; then
  # Create automatic backup before any database operations
  BACKUP_DIR="${RULESET_DIR}/backups"
  mkdir -p "${BACKUP_DIR}"
  BACKUP_FILE="${BACKUP_DIR}/user-config.db.$(date +%Y%m%d_%H%M%S).bak"
  cp "${USER_DB_PATH}" "${BACKUP_FILE}" 2>/dev/null || true
  echo "[entrypoint] created database backup: ${BACKUP_FILE}"

  # Keep only last 5 backups to prevent disk fill
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

# 初始化/升级用户数据库（使用 CREATE TABLE IF NOT EXISTS，安全运行）
echo "[entrypoint] initializing user database: ${USER_DB_PATH}"
python3 /usr/local/bin/init_user_db.py /etc/sing-box
if [ $? -ne 0 ]; then
  echo "[entrypoint] failed to initialize user database" >&2
  exit 1
fi

# Cleanup stale interfaces from previous container runs (important for network_mode: host)
cleanup_stale_interfaces

# Verify ports are available before proceeding
verify_required_ports

sysctl -w net.ipv4.ip_forward=1 >/dev/null 2>&1 || true
sysctl -w net.ipv4.conf.all.rp_filter=0 >/dev/null 2>&1 || true
sysctl -w net.ipv4.conf.default.rp_filter=0 >/dev/null 2>&1 || true

# Phase 11-Fix.W: CRITICAL - Enable route_localnet for TPROXY
# TPROXY uses --on-ip 127.0.0.1 to redirect traffic to sing-box on loopback
# Without this, kernel treats 127.0.0.0/8 as "martian" and silently drops packets
# This was the root cause of the "TPROXY black hole" bug where iptables counters
# increased but sing-box never received the traffic
sysctl -w net.ipv4.conf.all.route_localnet=1 >/dev/null 2>&1 || true
sysctl -w net.ipv4.conf.default.route_localnet=1 >/dev/null 2>&1 || true
sysctl -w net.ipv4.conf.lo.route_localnet=1 >/dev/null 2>&1 || true

if [ "${DISABLE_IPV6:-1}" = "1" ]; then
  sysctl -w net.ipv6.conf.all.disable_ipv6=1 >/dev/null || true
  sysctl -w net.ipv6.conf.default.disable_ipv6=1 >/dev/null || true
fi

/usr/local/bin/fetch-geodata.sh "${RULESET_DIR}" "${GEO_DATA_READY_FLAG}"

# === Kernel WireGuard Setup ===
# Creates wg-ingress interface and configures TPROXY to router

WG_INTERFACE="${WG_INTERFACE:-wg-ingress}"
WG_SUBNET="${WG_SUBNET:-10.25.0.0/24}"

# Set TPROXY port for rust-router (7894)
# sing-box uses 7893 as fallback
TPROXY_PORT="${TPROXY_PORT:-7894}"
TPROXY_MARK="1"
TPROXY_TABLE="100"

setup_kernel_wireguard() {
  # Phase 6: Skip kernel WireGuard if userspace mode is enabled
  if [ "${USERSPACE_WG}" = "true" ]; then
    echo "[entrypoint] USERSPACE_WG=true, skipping kernel WireGuard setup (rust-router handles this)"
    return 0
  fi

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
    addr = server.get('address', '10.25.0.1/24')
    # Convert address to subnet (e.g., 10.25.0.1/24 -> 10.25.0.0/24)
    import ipaddress
    net = ipaddress.ip_network(addr, strict=False)
    print(str(net))
else:
    print('10.25.0.0/24')
" 2>/dev/null || echo "10.25.0.0/24")

  echo "[entrypoint] WireGuard subnet: ${WG_SUBNET}"

  # Phase 11-Fix.W: Set interface-specific sysctl after interface creation
  # These settings are critical for TPROXY to work correctly on this interface
  sysctl -w net.ipv4.conf.${WG_INTERFACE}.rp_filter=0 >/dev/null 2>&1 || true
  sysctl -w net.ipv4.conf.${WG_INTERFACE}.route_localnet=1 >/dev/null 2>&1 || true
  echo "[entrypoint] interface sysctl configured for ${WG_INTERFACE}"

  echo "[entrypoint] kernel WireGuard interface ready"
}

# Phase 11-Fix.W: Check TPROXY kernel prerequisites
check_tproxy_prerequisites() {
  echo "[entrypoint] checking TPROXY prerequisites..."

  local modules=("xt_TPROXY" "nf_tproxy_ipv4")
  local all_ok=true

  for module in "${modules[@]}"; do
    # Check if module is already loaded
    if lsmod | grep -q "^${module}\b" 2>/dev/null; then
      continue
    fi

    # Try to load module
    if modprobe "${module}" 2>/dev/null; then
      echo "[entrypoint] loaded module ${module}"
      continue
    fi

    # Module might be built-in, test TPROXY functionality
    if ! ${IPTABLES} -t mangle -m TPROXY -h >/dev/null 2>&1; then
      echo "[entrypoint] WARNING: ${module} not available, TPROXY may not work" >&2
      all_ok=false
    fi
  done

  if [ "$all_ok" = true ]; then
    echo "[entrypoint] TPROXY prerequisites check passed"
  else
    echo "[entrypoint] WARNING: Some TPROXY modules missing, functionality may be degraded" >&2
  fi
}

setup_tproxy_routing() {
  # Setup TPROXY for transparent proxying of WireGuard traffic to sing-box
  echo "[entrypoint] setting up TPROXY routing for WireGuard traffic"

  # Enable ip_nonlocal_bind for TPROXY to work correctly
  # This allows sing-box to send responses with non-local source IPs
  sysctl -w net.ipv4.ip_nonlocal_bind=1 >/dev/null 2>&1 || true
  sysctl -w net.ipv6.ip_nonlocal_bind=1 >/dev/null 2>&1 || true

  # Phase 11-Fix.W: Security protection for route_localnet
  # Block external traffic to loopback (prevent route_localnet abuse)
  # Only allow traffic from lo or WireGuard interface to reach 127.0.0.0/8
  # Use raw table for earliest interception with minimal overhead
  # Phase 11-Fix.X: Fixed syntax - iptables doesn't support multiple -i conditions
  # Use ACCEPT rules for allowed interfaces, then DROP the rest
  ${IPTABLES} -t raw -D PREROUTING -d 127.0.0.0/8 -i lo -j ACCEPT 2>/dev/null || true
  ${IPTABLES} -t raw -D PREROUTING -d 127.0.0.0/8 -i ${WG_INTERFACE} -j ACCEPT 2>/dev/null || true
  ${IPTABLES} -t raw -D PREROUTING -d 127.0.0.0/8 -j DROP 2>/dev/null || true
  ${IPTABLES} -t raw -A PREROUTING -d 127.0.0.0/8 -i lo -j ACCEPT
  ${IPTABLES} -t raw -A PREROUTING -d 127.0.0.0/8 -i ${WG_INTERFACE} -j ACCEPT
  ${IPTABLES} -t raw -A PREROUTING -d 127.0.0.0/8 -j DROP
  echo "[entrypoint] route_localnet security rules configured (raw table)"

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

  # Phase 11-Fix.X: DIVERT chain for established connections
  # This is CRITICAL for TPROXY to work correctly!
  # Without this, return traffic from established connections cannot find
  # its way back to the transparent proxy socket, causing a "black hole".
  # Reference: https://www.kernel.org/doc/Documentation/networking/tproxy.txt
  ${IPTABLES} -t mangle -N DIVERT 2>/dev/null || true
  ${IPTABLES} -t mangle -F DIVERT
  ${IPTABLES} -t mangle -A DIVERT -j MARK --set-mark ${TPROXY_MARK}
  ${IPTABLES} -t mangle -A DIVERT -j ACCEPT
  echo "[entrypoint] DIVERT chain created for TPROXY established connections"

  # M12: 幂等的 iptables 规则设置 - 先删除再添加，避免重复
  # Skip traffic to WireGuard server itself (local subnet)
  ${IPTABLES} -t mangle -D PREROUTING -i "${WG_INTERFACE}" -d "${WG_SUBNET}" -j RETURN 2>/dev/null || true
  ${IPTABLES} -t mangle -A PREROUTING -i "${WG_INTERFACE}" -d "${WG_SUBNET}" -j RETURN

  # Phase 11-Fix.X: Socket match for established connections (MUST be before TPROXY!)
  # This catches return packets for established transparent proxy connections.
  # The -m socket module checks if the packet belongs to an existing socket.
  # IMPORTANT: --transparent flag is required to match sockets with IP_TRANSPARENT option
  ${IPTABLES} -t mangle -D PREROUTING -i "${WG_INTERFACE}" -p tcp -m socket --transparent -j DIVERT 2>/dev/null || true
  ${IPTABLES} -t mangle -D PREROUTING -i "${WG_INTERFACE}" -p udp -m socket --transparent -j DIVERT 2>/dev/null || true
  ${IPTABLES} -t mangle -A PREROUTING -i "${WG_INTERFACE}" -p tcp -m socket --transparent -j DIVERT
  ${IPTABLES} -t mangle -A PREROUTING -i "${WG_INTERFACE}" -p udp -m socket --transparent -j DIVERT
  echo "[entrypoint] Socket match rules added (before TPROXY)"

  # TPROXY TCP traffic from WireGuard interface to sing-box
  ${IPTABLES} -t mangle -D PREROUTING -i "${WG_INTERFACE}" -p tcp \
    -j TPROXY --on-port ${TPROXY_PORT} --on-ip 127.0.0.1 --tproxy-mark ${TPROXY_MARK} 2>/dev/null || true
  ${IPTABLES} -t mangle -A PREROUTING -i "${WG_INTERFACE}" -p tcp \
    -j TPROXY --on-port ${TPROXY_PORT} --on-ip 127.0.0.1 --tproxy-mark ${TPROXY_MARK}

  # TPROXY UDP traffic from WireGuard interface to sing-box
  ${IPTABLES} -t mangle -D PREROUTING -i "${WG_INTERFACE}" -p udp \
    -j TPROXY --on-port ${TPROXY_PORT} --on-ip 127.0.0.1 --tproxy-mark ${TPROXY_MARK} 2>/dev/null || true
  ${IPTABLES} -t mangle -A PREROUTING -i "${WG_INTERFACE}" -p udp \
    -j TPROXY --on-port ${TPROXY_PORT} --on-ip 127.0.0.1 --tproxy-mark ${TPROXY_MARK}

  echo "[entrypoint] TPROXY configured: ${WG_INTERFACE} -> 127.0.0.1:${TPROXY_PORT}"

  # NAT/MASQUERADE for WireGuard ingress traffic going to internet
  # Without this, responses from internet can't route back to private WG IPs
  ${IPTABLES} -t nat -D POSTROUTING -s "${WG_SUBNET}" ! -o "${WG_INTERFACE}" -j MASQUERADE 2>/dev/null || true
  ${IPTABLES} -t nat -A POSTROUTING -s "${WG_SUBNET}" ! -o "${WG_INTERFACE}" -j MASQUERADE
  echo "[entrypoint] NAT configured: ${WG_SUBNET} -> MASQUERADE (for internet access)"

  # Phase 11-Fix.W: Verify TPROXY routing is correctly configured
  local route_check
  route_check=$(ip route show table ${TPROXY_TABLE} 2>/dev/null)
  if ! echo "${route_check}" | grep -q "local"; then
    echo "[entrypoint] ERROR: TPROXY routing table ${TPROXY_TABLE} not configured correctly" >&2
    echo "[entrypoint] Expected 'local 0.0.0.0/0 dev lo' in table ${TPROXY_TABLE}" >&2
    return 1
  fi

  # Verify ip rule exists
  # Note: ip rule show outputs:
  #   - fwmark as hex (0x1) or decimal (1)
  #   - table as number (100) or name (tproxy) depending on /etc/iproute2/rt_tables
  if ! ip rule show | grep -qE "fwmark.*(0x)?${TPROXY_MARK}.*lookup.*(${TPROXY_TABLE}|tproxy)"; then
    echo "[entrypoint] ERROR: TPROXY ip rule not configured (fwmark ${TPROXY_MARK} -> table ${TPROXY_TABLE})" >&2
    return 1
  fi

  echo "[entrypoint] TPROXY routing verified: table ${TPROXY_TABLE} OK, ip rule OK"
}

# ============================================================================
# Phase 7.7: DNS Engine Rules
# ============================================================================
# Redirects DNS traffic (port 53) from ingress interfaces to rust-router DNS engine
# This enables ad blocking, caching, and DNS splitting without modifying client DNS settings
# DNS engine is always enabled in rust-router (Phase 7)
setup_dns_redirect_rules() {
  echo "[entrypoint] setting up DNS redirect rules (port 53 -> ${RUST_ROUTER_DNS_PORT})"

  # Remove existing DNS redirect rules (idempotent)
  ${IPTABLES} -t nat -D PREROUTING -i "${WG_INTERFACE}" -p udp --dport 53 -j REDIRECT --to-port "${RUST_ROUTER_DNS_PORT}" 2>/dev/null || true
  ${IPTABLES} -t nat -D PREROUTING -i "${WG_INTERFACE}" -p tcp --dport 53 -j REDIRECT --to-port "${RUST_ROUTER_DNS_PORT}" 2>/dev/null || true

  # Add DNS redirect rules for WireGuard interface
  # UDP DNS (most common)
  ${IPTABLES} -t nat -A PREROUTING -i "${WG_INTERFACE}" -p udp --dport 53 -j REDIRECT --to-port "${RUST_ROUTER_DNS_PORT}"
  # TCP DNS (for large responses, zone transfers)
  ${IPTABLES} -t nat -A PREROUTING -i "${WG_INTERFACE}" -p tcp --dport 53 -j REDIRECT --to-port "${RUST_ROUTER_DNS_PORT}"

  echo "[entrypoint] DNS redirect added for ${WG_INTERFACE}"

  # Also add for Xray interface if it exists
  if ip link show "${XRAY_INTERFACE}" >/dev/null 2>&1; then
    ${IPTABLES} -t nat -D PREROUTING -i "${XRAY_INTERFACE}" -p udp --dport 53 -j REDIRECT --to-port "${RUST_ROUTER_DNS_PORT}" 2>/dev/null || true
    ${IPTABLES} -t nat -D PREROUTING -i "${XRAY_INTERFACE}" -p tcp --dport 53 -j REDIRECT --to-port "${RUST_ROUTER_DNS_PORT}" 2>/dev/null || true
    ${IPTABLES} -t nat -A PREROUTING -i "${XRAY_INTERFACE}" -p udp --dport 53 -j REDIRECT --to-port "${RUST_ROUTER_DNS_PORT}"
    ${IPTABLES} -t nat -A PREROUTING -i "${XRAY_INTERFACE}" -p tcp --dport 53 -j REDIRECT --to-port "${RUST_ROUTER_DNS_PORT}"
    echo "[entrypoint] DNS redirect added for ${XRAY_INTERFACE}"
  fi

  echo "[entrypoint] DNS redirect rules applied successfully"
  return 0
}

# Setup kernel WireGuard ingress before other services
setup_kernel_wireguard

# === Kernel WireGuard Egress Setup ===
# Creates wg-pia-* and wg-eg-* interfaces for outbound traffic

setup_kernel_wireguard_egress() {
  # Phase 6: Skip kernel WireGuard egress if userspace mode is enabled
  if [ "${USERSPACE_WG}" = "true" ]; then
    echo "[entrypoint] USERSPACE_WG=true, skipping kernel WireGuard egress setup"
    return 0
  fi

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

# === ECMP Routes Setup for Outbound Groups ===
sync_ecmp_routes() {
  echo "[entrypoint] syncing ECMP routes for outbound groups"
  if python3 /usr/local/bin/ecmp_manager.py --sync-all 2>/dev/null; then
    echo "[entrypoint] ECMP routes synced successfully"
  else
    echo "[entrypoint] warning: ECMP route sync failed or no groups configured"
  fi
}

# Sync ECMP routes for outbound groups (after egress interfaces are ready)
sync_ecmp_routes

# === Chain Routes Setup for Multi-hop Chains ===
sync_chain_routes() {
  echo "[entrypoint] syncing chain routes for multi-hop chains"
  if python3 /usr/local/bin/chain_route_manager.py sync 2>/dev/null; then
    echo "[entrypoint] chain routes synced successfully"
  else
    echo "[entrypoint] warning: chain route sync failed or no chains configured"
  fi
}

# === DSCP Rules Restoration (Phase 11-Fix.P) ===
# Restore entry node DSCP rules from persisted state
restore_dscp_rules() {
  echo "[entrypoint] restoring DSCP rules from persisted state"
  # Note: Don't suppress stderr (2>/dev/null) - errors are logged to /var/log/dscp-restore.log for debugging
  if python3 /usr/local/bin/dscp_manager.py restore 2>>/var/log/dscp-restore.log; then
    echo "[entrypoint] DSCP rules restored successfully"
  else
    echo "[entrypoint] warning: DSCP rule restore failed or no persisted state (check /var/log/dscp-restore.log)"
  fi
}

# Sync chain routes (for terminal node DSCP routing)
sync_chain_routes

# Restore entry node DSCP rules (Phase 11-Fix.P)
restore_dscp_rules

# Phase 6: Sync configuration to rust-router via IPC
# This function syncs database configuration (rules, outbounds, peers) to rust-router
# via its Unix socket IPC interface
sync_rust_router() {
  # Wait for rust-router socket to be available
  local max_wait=30
  local waited=0
  while [ ! -S "${RUST_ROUTER_SOCKET}" ] && [ $waited -lt $max_wait ]; do
    sleep 1
    waited=$((waited + 1))
    # Log progress every 5 seconds for debugging
    if [ $((waited % 5)) -eq 0 ]; then
      echo "[entrypoint] waiting for rust-router socket... (${waited}/${max_wait}s)"
    fi
  done

  if [ ! -S "${RUST_ROUTER_SOCKET}" ]; then
    echo "[entrypoint] WARNING: rust-router socket not available after ${max_wait}s, skipping sync"
    return 1
  fi

  echo "[entrypoint] syncing configuration to rust-router via IPC"
  # Use head -50 to capture more output while still preventing runaway logs
  if python3 /usr/local/bin/rust_router_manager.py sync 2>&1 | head -50; then
    echo "[entrypoint] rust-router sync completed"
  else
    echo "[entrypoint] WARNING: rust-router sync failed"
    return 1
  fi
}

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

  # Phase 11-Fix.W: Set interface-specific sysctl for Xray TUN interface
  # Same settings as WireGuard interface for TPROXY compatibility
  sysctl -w net.ipv4.conf.${XRAY_INTERFACE}.rp_filter=0 >/dev/null 2>&1 || true
  sysctl -w net.ipv4.conf.${XRAY_INTERFACE}.route_localnet=1 >/dev/null 2>&1 || true
  echo "[entrypoint] interface sysctl configured for ${XRAY_INTERFACE}"

  # Phase 11-Fix.W: Add Xray interface to route_localnet security whitelist
  # Insert ACCEPT rule before the DROP rule to allow Xray TUN traffic to 127.0.0.0/8
  ${IPTABLES} -t raw -D PREROUTING -i ${XRAY_INTERFACE} -d 127.0.0.0/8 -j ACCEPT 2>/dev/null || true
  ${IPTABLES} -t raw -I PREROUTING -i ${XRAY_INTERFACE} -d 127.0.0.0/8 -j ACCEPT
  echo "[entrypoint] route_localnet security whitelist updated for ${XRAY_INTERFACE}"

  # M12: 幂等的 iptables 规则设置 - 先删除再添加，避免重复
  # Skip traffic to Xray server subnet (local subnet)
  ${IPTABLES} -t mangle -D PREROUTING -i "${XRAY_INTERFACE}" -d "${XRAY_SUBNET}" -j RETURN 2>/dev/null || true
  ${IPTABLES} -t mangle -A PREROUTING -i "${XRAY_INTERFACE}" -d "${XRAY_SUBNET}" -j RETURN

  # TPROXY TCP traffic from Xray TUN interface to sing-box
  ${IPTABLES} -t mangle -D PREROUTING -i "${XRAY_INTERFACE}" -p tcp \
    -j TPROXY --on-port ${TPROXY_PORT} --on-ip 127.0.0.1 --tproxy-mark ${TPROXY_MARK} 2>/dev/null || true
  ${IPTABLES} -t mangle -A PREROUTING -i "${XRAY_INTERFACE}" -p tcp \
    -j TPROXY --on-port ${TPROXY_PORT} --on-ip 127.0.0.1 --tproxy-mark ${TPROXY_MARK}

  # TPROXY UDP traffic from Xray TUN interface to sing-box
  ${IPTABLES} -t mangle -D PREROUTING -i "${XRAY_INTERFACE}" -p udp \
    -j TPROXY --on-port ${TPROXY_PORT} --on-ip 127.0.0.1 --tproxy-mark ${TPROXY_MARK} 2>/dev/null || true
  ${IPTABLES} -t mangle -A PREROUTING -i "${XRAY_INTERFACE}" -p udp \
    -j TPROXY --on-port ${TPROXY_PORT} --on-ip 127.0.0.1 --tproxy-mark ${TPROXY_MARK}

  echo "[entrypoint] Xray TPROXY configured: ${XRAY_INTERFACE} -> 127.0.0.1:${TPROXY_PORT}"

  # NAT/MASQUERADE for Xray V2Ray ingress traffic going to internet
  ${IPTABLES} -t nat -D POSTROUTING -s "${XRAY_SUBNET}" ! -o "${XRAY_INTERFACE}" -j MASQUERADE 2>/dev/null || true
  ${IPTABLES} -t nat -A POSTROUTING -s "${XRAY_SUBNET}" ! -o "${XRAY_INTERFACE}" -j MASQUERADE
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

start_warp_manager() {
  # 检查是否有启用的 WARP 出口
  local warp_count
  warp_count=$(python3 -c "
import sys
sys.path.insert(0, '/usr/local/bin')
from db_helper import get_db
db = get_db('/etc/sing-box/geoip-geodata.db', '/etc/sing-box/user-config.db')
egress_list = db.get_warp_egress_list(enabled_only=True)
print(len(egress_list))
" 2>/dev/null || echo "0")

  if [ "${warp_count}" -gt "0" ]; then
    echo "[entrypoint] starting WARP manager for ${warp_count} WARP egress"
    python3 /usr/local/bin/warp_manager.py daemon >/var/log/warp-manager.log 2>&1 &
    WARP_MGR_PID=$!
    echo "[entrypoint] WARP manager started with PID ${WARP_MGR_PID}"
  else
    echo "[entrypoint] No WARP egress configured, skipping WARP manager"
  fi
}

# === Health Checker Daemon ===
start_health_checker() {
  # 检查是否有启用的出口组
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
    echo "[entrypoint] health checker started with PID ${HEALTH_CHECKER_PID}"
  else
    echo "[entrypoint] No outbound groups configured, skipping health checker"
  fi
}

# === Peer Tunnel Manager Daemon ===
start_peer_tunnel_manager() {
  # 检查是否有启用自动重连的对等节点
  local peer_count
  peer_count=$(python3 -c "
import sys
sys.path.insert(0, '/usr/local/bin')
from db_helper import get_db
db = get_db('/etc/sing-box/geoip-geodata.db', '/etc/sing-box/user-config.db')
peers = db.get_peer_nodes()
# 统计启用自动重连的节点数
count = sum(1 for p in peers if p.get('auto_reconnect', False))
print(count)
" 2>/dev/null || echo "0")

  if [ "${peer_count}" -gt "0" ]; then
    echo "[entrypoint] starting peer tunnel manager for ${peer_count} auto-reconnect peers"
    python3 /usr/local/bin/peer_tunnel_manager.py daemon >/var/log/peer-tunnel-manager.log 2>&1 &
    PEER_TUNNEL_MGR_PID=$!
    echo "[entrypoint] peer tunnel manager started with PID ${PEER_TUNNEL_MGR_PID}"
  else
    echo "[entrypoint] No auto-reconnect peers configured, skipping peer tunnel manager"
  fi
}

start_nginx() {
  echo "[entrypoint] starting nginx on port ${WEB_PORT}"

  # Ensure nginx log directory exists (may be missing if volume mounted)
  mkdir -p /var/log/nginx
  chown www-data:www-data /var/log/nginx 2>/dev/null || true

  # Generate nginx.conf from template with environment variables
  NGINX_TEMPLATE="/etc/nginx/nginx.conf.template"
  NGINX_CONF="/etc/nginx/conf.d/default.conf"
  if [ -f "${NGINX_TEMPLATE}" ]; then
    envsubst '${WEB_PORT} ${API_PORT}' < "${NGINX_TEMPLATE}" > "${NGINX_CONF}"
    echo "[entrypoint] generated nginx config with WEB_PORT=${WEB_PORT}, API_PORT=${API_PORT}"
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

# Generate rust-router config from database
# Fallback to sing-box if config generation fails
echo "[entrypoint] rendering rust-router config"
mkdir -p "$(dirname "${RUST_ROUTER_CONFIG}")"
# Export RUST_ROUTER_PORT so render_routing_config.py uses the correct port
export RUST_ROUTER_PORT="${TPROXY_PORT}"
# Phase 11-Fix.AB: Export USERSPACE_WG so render_routing_config.py can skip WireGuard outbounds
export USERSPACE_WG="${USERSPACE_WG}"
if python3 /usr/local/bin/render_routing_config.py \
    --format=rust-router \
    --output="${RUST_ROUTER_CONFIG}"; then
  echo "[entrypoint] rust-router config generated: ${RUST_ROUTER_CONFIG}"
else
  echo "[entrypoint] rust-router config generation failed, will use sing-box" >&2
  ACTIVE_ROUTER="sing-box"
fi

start_api_server
start_nginx
start_openvpn_manager
start_xray_manager
start_xray_egress_manager
start_warp_manager
start_health_checker
start_peer_tunnel_manager

# Router startup logic - supports both sing-box and rust-router
# rust-router provides high-performance Rust implementation with fallback to sing-box
SINGBOX_PID=""
# Note: RUST_ROUTER_PID is initialized in the PID block at script start

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
  ACTIVE_ROUTER="sing-box"
}

start_rust_router() {
  # Check if rust-router binary exists
  if [ ! -x "${RUST_ROUTER_BIN}" ]; then
    echo "[entrypoint] rust-router binary not found at ${RUST_ROUTER_BIN}" >&2
    return 1
  fi

  # Check if config exists
  if [ ! -f "${RUST_ROUTER_CONFIG}" ]; then
    echo "[entrypoint] rust-router config not found at ${RUST_ROUTER_CONFIG}" >&2
    return 1
  fi

  echo "[entrypoint] starting rust-router with ${RUST_ROUTER_CONFIG}"

  # Set environment variables for rust-router
  export RUST_ROUTER_LISTEN="0.0.0.0:${TPROXY_PORT}"
  export RUST_ROUTER_CONFIG="${RUST_ROUTER_CONFIG}"
  export RUST_ROUTER_SOCKET="${RUST_ROUTER_SOCKET}"
  export RUST_LOG="${RUST_LOG:-info}"

  # Phase 6: Configure userspace WireGuard mode
  if [ "${USERSPACE_WG}" = "true" ]; then
    export RUST_ROUTER_USERSPACE_WG="true"
    export RUST_ROUTER_WG_LISTEN_PORT="${WG_LISTEN_PORT}"

    # Phase 11-Fix.Z: Retrieve WireGuard private key from database for userspace WG
    # Fix: Read encryption key from file if SQLCIPHER_KEY env var is not set
    RUST_ROUTER_WG_PRIVATE_KEY=$(python3 -c "
import sys
sys.path.insert(0, '/usr/local/bin')
from db_helper import get_db
import os
from pathlib import Path

# Get encryption key from env var or file
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
      echo "[entrypoint] rust-router userspace WireGuard enabled (port ${WG_LISTEN_PORT}, private key loaded)"
    else
      echo "[entrypoint] WARNING: USERSPACE_WG=true but no private key found in database" >&2
      echo "[entrypoint] rust-router will fail to start userspace WireGuard ingress" >&2
    fi
  fi

  # Start rust-router
  "${RUST_ROUTER_BIN}" >> "${RUST_ROUTER_LOG}" 2>&1 &
  RUST_ROUTER_PID=$!

  # Wait briefly to check if it started successfully
  sleep 1
  if ! kill -0 "${RUST_ROUTER_PID}" 2>/dev/null; then
    echo "[entrypoint] rust-router failed to start, check ${RUST_ROUTER_LOG}" >&2
    RUST_ROUTER_PID=""
    return 1
  fi

  echo "[entrypoint] rust-router started (PID: ${RUST_ROUTER_PID})"
  ACTIVE_ROUTER="rust-router"
  return 0
}

fallback_to_singbox() {
  echo "[entrypoint] falling back to sing-box"

  # Update TPROXY port for sing-box
  TPROXY_PORT="${TPROXY_PORT:-7893}"
  export TPROXY_PORT

  # Remove DNS redirect rules (sing-box doesn't have rust-router's DNS engine)
  echo "[entrypoint] removing DNS redirect rules (sing-box fallback)"
  ${IPTABLES} -t nat -D PREROUTING -i "${WG_INTERFACE}" -p udp --dport 53 -j REDIRECT --to-port "${RUST_ROUTER_DNS_PORT}" 2>/dev/null || true
  ${IPTABLES} -t nat -D PREROUTING -i "${WG_INTERFACE}" -p tcp --dport 53 -j REDIRECT --to-port "${RUST_ROUTER_DNS_PORT}" 2>/dev/null || true
  ${IPTABLES} -t nat -D PREROUTING -i "${XRAY_INTERFACE}" -p udp --dport 53 -j REDIRECT --to-port "${RUST_ROUTER_DNS_PORT}" 2>/dev/null || true
  ${IPTABLES} -t nat -D PREROUTING -i "${XRAY_INTERFACE}" -p tcp --dport 53 -j REDIRECT --to-port "${RUST_ROUTER_DNS_PORT}" 2>/dev/null || true

  # Start sing-box
  start_singbox "${CONFIG_PATH}"

  # Re-setup TPROXY routing with new port if already configured
  if [ "${TPROXY_CONFIGURED:-false}" = "true" ] && [ "${SKIP_TPROXY_SETUP:-false}" != "true" ]; then
    echo "[entrypoint] reconfiguring TPROXY for sing-box port ${TPROXY_PORT}"
    setup_tproxy_routing
    setup_xray_tproxy
  fi
}

handle_signals() {
  echo "[entrypoint] received signal, shutting down..."

  # Stop rust-router if running
  if [ -n "${RUST_ROUTER_PID:-}" ] && kill -0 "${RUST_ROUTER_PID}" 2>/dev/null; then
    echo "[entrypoint] stopping rust-router"
    kill "${RUST_ROUTER_PID}" 2>/dev/null || true
    wait "${RUST_ROUTER_PID}" 2>/dev/null || true
  fi

  # Stop sing-box if running
  if [ -n "${SINGBOX_PID:-}" ] && kill -0 "${SINGBOX_PID}" 2>/dev/null; then
    echo "[entrypoint] stopping sing-box"
    kill "${SINGBOX_PID}" 2>/dev/null || true
    wait "${SINGBOX_PID}" 2>/dev/null || true
  fi

  cleanup
  exit 0
}

trap handle_signals SIGTERM SIGINT

# Start rust-router (default router)
echo "[entrypoint] starting rust-router (default router)"
if [ "${USERSPACE_WG}" = "true" ]; then
  echo "[entrypoint] userspace WireGuard mode enabled"
fi
if start_rust_router; then
  echo "[entrypoint] rust-router started successfully"

  # Phase 6: Sync configuration to rust-router
  sync_rust_router || echo "[entrypoint] WARNING: initial sync failed, will retry later"
else
  echo "[entrypoint] rust-router failed to start, falling back to sing-box" >&2
  ACTIVE_ROUTER="sing-box"
  # Reset TPROXY port for sing-box fallback
  TPROXY_PORT="7893"
  # Also disable userspace mode since we're falling back to sing-box
  USERSPACE_WG="false"
  start_singbox "${CONFIG_PATH}"
fi

# Phase 11-Fix.W: Check TPROXY kernel prerequisites before setting up routing
# SKIP_TPROXY_SETUP=true to disable automatic TPROXY rules (for manual debugging)
if [ "${SKIP_TPROXY_SETUP:-false}" = "true" ]; then
  echo "[entrypoint] SKIP_TPROXY_SETUP=true, skipping automatic TPROXY setup"
elif [ "${USERSPACE_WG}" = "true" ]; then
  # Phase 6: Full userspace mode - rust-router handles all routing internally
  # No iptables TPROXY rules needed as traffic goes directly to rust-router's WireGuard listener
  echo "[entrypoint] Full userspace mode: rust-router handles all routing internally"
  echo "[entrypoint] Skipping iptables TPROXY setup (not needed for userspace WireGuard)"

  # Phase 6 Fix: Configure peer tunnel subnet routing (10.200.200.0/24)
  # This allows remote nodes to reach this node's API via tunnel IP
  echo "[entrypoint] Configuring peer tunnel subnet routing (10.200.200.0/24)"
  if ip route add local 10.200.200.0/24 dev lo 2>/dev/null; then
    echo "[entrypoint] Added local route for peer tunnel subnet"
  else
    # Route may already exist, verify it
    if ip route show table local | grep -q "local 10.200.200.0/24"; then
      echo "[entrypoint] Peer tunnel subnet route already exists"
    else
      echo "[entrypoint] WARNING: Failed to add peer tunnel subnet route" >&2
    fi
  fi

  # DNS is handled internally by rust-router in userspace mode
  echo "[entrypoint] DNS engine handled internally by rust-router"
else
  check_tproxy_prerequisites

  # Setup TPROXY routing for WireGuard traffic (no need to wait for sing-box)
  setup_tproxy_routing

  # Setup TPROXY routing for Xray V2Ray ingress traffic
  setup_xray_tproxy

  # Phase 7.7: Setup DNS redirect rules (port 53 -> rust-router DNS engine)
  setup_dns_redirect_rules
fi

# Phase 7.7: Log DNS engine status (always enabled with rust-router)
echo "[entrypoint] DNS engine: enabled (port ${RUST_ROUTER_DNS_PORT})"

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

# Phase 6: Counter for periodic rust-router sync check (every 5 minutes = 300 seconds)
SYNC_CHECK_COUNT=0

# 主循环：监控 nginx, API 和 sing-box 进程
while true; do
  rotate_logs

  # Phase 6: Periodic rust-router sync check (every 5 minutes)
  SYNC_CHECK_COUNT=$((SYNC_CHECK_COUNT + 1))
  if [ "${ACTIVE_ROUTER}" = "rust-router" ] && [ $((SYNC_CHECK_COUNT % 300)) -eq 0 ]; then
    if [ -S "${RUST_ROUTER_SOCKET}" ]; then
      # Re-sync if rust-router is running
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

  # Check WARP manager
  if [ -n "${WARP_MGR_PID}" ] && ! kill -0 "${WARP_MGR_PID}" 2>/dev/null; then
    echo "[entrypoint] WARNING: WARP manager died, restarting..." >&2
    start_warp_manager
  fi

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

  # Check router (rust-router or sing-box depending on which is active)
  if [ "${ACTIVE_ROUTER}" = "rust-router" ]; then
    # Check rust-router
    if [ -n "${RUST_ROUTER_PID}" ] && ! kill -0 "${RUST_ROUTER_PID}" 2>/dev/null; then
      wait "${RUST_ROUTER_PID}" 2>/dev/null || true
      EXIT_CODE=$?
      echo "[entrypoint] rust-router exited with code ${EXIT_CODE}"

      # Try to restart rust-router
      if start_rust_router; then
        echo "[entrypoint] rust-router restarted successfully"
        # Phase 6: Re-sync configuration after restart
        sync_rust_router || echo "[entrypoint] WARNING: sync after restart failed"
      else
        echo "[entrypoint] rust-router restart failed, falling back to sing-box" >&2
        # Fall back to sing-box
        TPROXY_PORT="7893"
        # H1 fix: Reset USERSPACE_WG since sing-box requires kernel WireGuard
        USERSPACE_WG="false"
        start_singbox "${GENERATED_CONFIG_PATH:-${BASE_CONFIG_PATH}}"
        # Reconfigure TPROXY for new port (now needed since we're back to kernel WG mode)
        if [ "${SKIP_TPROXY_SETUP:-false}" != "true" ]; then
          setup_tproxy_routing
          setup_xray_tproxy
        fi
        # Note: Kernel WireGuard interfaces should already exist from initial setup
        # If they don't, a container restart will be needed
      fi
    fi
  else
    # Check sing-box
    if [ -n "${SINGBOX_PID}" ] && ! kill -0 "${SINGBOX_PID}" 2>/dev/null; then
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
  fi
  sleep 1
done

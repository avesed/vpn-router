#!/bin/bash
#
# Phase 0 Day 4: Kernel Configuration Check
#
# This script verifies that all required kernel parameters and modules
# are available for TPROXY operation.
#
# Required sysctls:
#   - net.ipv4.conf.all.route_localnet = 1
#   - net.ipv4.conf.lo.route_localnet = 1
#   - net.ipv4.ip_nonlocal_bind = 1
#   - net.ipv4.conf.all.rp_filter = 0 (or 2)
#   - net.ipv4.conf.*.rp_filter = 0 (for ingress interfaces)
#
# Required kernel modules:
#   - xt_TPROXY
#   - xt_socket
#   - xt_mark
#   - xt_DSCP (for multi-hop chains)
#   - xt_dscp
#   - nf_tproxy_ipv4
#
# Usage: ./kernel_check.sh [--fix]
#   --fix: Attempt to fix issues (requires root)

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Counters
PASS=0
FAIL=0
WARN=0

log_pass() {
    echo -e "${GREEN}[PASS]${NC} $1"
    ((PASS++))
}

log_fail() {
    echo -e "${RED}[FAIL]${NC} $1"
    ((FAIL++))
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
    ((WARN++))
}

log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

# Check a sysctl value
check_sysctl() {
    local name=$1
    local expected=$2
    local actual

    if ! actual=$(sysctl -n "$name" 2>/dev/null); then
        log_fail "$name: not found"
        return 1
    fi

    if [[ "$actual" == "$expected" ]]; then
        log_pass "$name = $actual"
        return 0
    else
        log_fail "$name = $actual (expected: $expected)"
        return 1
    fi
}

# Check a sysctl value with alternatives
check_sysctl_alt() {
    local name=$1
    shift
    local expected=("$@")
    local actual

    if ! actual=$(sysctl -n "$name" 2>/dev/null); then
        log_fail "$name: not found"
        return 1
    fi

    for exp in "${expected[@]}"; do
        if [[ "$actual" == "$exp" ]]; then
            log_pass "$name = $actual"
            return 0
        fi
    done

    log_fail "$name = $actual (expected: ${expected[*]})"
    return 1
}

# Check if a kernel module is loaded or built-in
check_module() {
    local name=$1
    local description=$2

    # Check if loaded
    if lsmod | grep -q "^$name"; then
        log_pass "Module $name: loaded ($description)"
        return 0
    fi

    # Check if built-in (in /sys/module without refcnt)
    if [[ -d "/sys/module/$name" ]]; then
        log_pass "Module $name: built-in ($description)"
        return 0
    fi

    # Try to load it
    if modprobe "$name" 2>/dev/null; then
        log_pass "Module $name: loaded on demand ($description)"
        return 0
    fi

    # Check if iptables can use it (some modules are auto-loaded)
    if iptables -t mangle -C OUTPUT -j MARK --set-mark 0x1 2>/dev/null || \
       iptables -t mangle -A OUTPUT -j MARK --set-mark 0x1 2>/dev/null; then
        iptables -t mangle -D OUTPUT -j MARK --set-mark 0x1 2>/dev/null || true
        log_pass "Module $name: available via iptables ($description)"
        return 0
    fi

    log_fail "Module $name: not available ($description)"
    return 1
}

# Check TPROXY-specific module
check_tproxy_module() {
    local name=$1
    local description=$2

    # Check if loaded or built-in
    if lsmod | grep -q "^$name" || [[ -d "/sys/module/$name" ]]; then
        log_pass "Module $name: available ($description)"
        return 0
    fi

    # Try loading
    if modprobe "$name" 2>/dev/null; then
        log_pass "Module $name: loaded on demand ($description)"
        return 0
    fi

    # Some modules have alternative names
    case "$name" in
        nf_tproxy_ipv4)
            if [[ -d "/sys/module/nf_tproxy_core" ]] || modprobe nf_tproxy_core 2>/dev/null; then
                log_pass "Module $name: available via nf_tproxy_core ($description)"
                return 0
            fi
            ;;
    esac

    log_warn "Module $name: may not be available ($description)"
    return 1
}

# Check interface-specific sysctl
check_interface_sysctl() {
    local interface=$1
    local param=$2
    local expected=$3

    local name="net.ipv4.conf.${interface}.${param}"

    if ! ip link show "$interface" &>/dev/null; then
        log_info "Interface $interface not present (skipping $param check)"
        return 0
    fi

    check_sysctl "$name" "$expected"
}

# Fix sysctl value
fix_sysctl() {
    local name=$1
    local value=$2

    if sysctl -w "${name}=${value}" &>/dev/null; then
        log_info "Fixed: $name = $value"
        return 0
    else
        log_fail "Could not fix: $name"
        return 1
    fi
}

# Check capabilities
check_capabilities() {
    echo ""
    echo "=============================================="
    echo "          Capability Check"
    echo "=============================================="
    echo ""

    if [[ $EUID -eq 0 ]]; then
        log_pass "Running as root"
    else
        log_warn "Not running as root (some checks may fail)"
    fi

    # Check if we can create raw sockets
    if python3 -c "import socket; socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)" 2>/dev/null; then
        log_pass "Can create raw sockets"
    else
        log_warn "Cannot create raw sockets (may need CAP_NET_RAW)"
    fi
}

# Main sysctl checks
check_sysctls() {
    echo ""
    echo "=============================================="
    echo "          Sysctl Parameters"
    echo "=============================================="
    echo ""

    log_info "Checking required sysctls for TPROXY..."
    echo ""

    # Global settings
    echo "--- Global Settings ---"
    check_sysctl "net.ipv4.ip_forward" "1"
    check_sysctl "net.ipv4.ip_nonlocal_bind" "1"

    echo ""
    echo "--- Route Localnet (TPROXY requirement) ---"
    check_sysctl "net.ipv4.conf.all.route_localnet" "1"
    check_sysctl "net.ipv4.conf.lo.route_localnet" "1"
    check_sysctl "net.ipv4.conf.default.route_localnet" "1"

    echo ""
    echo "--- Reverse Path Filtering ---"
    # rp_filter: 0 = disabled, 1 = strict, 2 = loose
    # TPROXY needs 0 or 2
    check_sysctl_alt "net.ipv4.conf.all.rp_filter" "0" "2"
    check_sysctl_alt "net.ipv4.conf.lo.rp_filter" "0" "2"

    # Check interface-specific settings
    echo ""
    echo "--- Interface-Specific Settings ---"

    # Check common ingress interfaces
    for iface in wg-ingress xray-tun0 wg0 eth0; do
        if ip link show "$iface" &>/dev/null; then
            check_interface_sysctl "$iface" "route_localnet" "1"
            check_sysctl_alt "net.ipv4.conf.${iface}.rp_filter" "0" "2"
        fi
    done
}

# Kernel module checks
check_modules() {
    echo ""
    echo "=============================================="
    echo "          Kernel Modules"
    echo "=============================================="
    echo ""

    log_info "Checking required kernel modules..."
    echo ""

    echo "--- TPROXY Core ---"
    check_tproxy_module "xt_TPROXY" "TPROXY target"
    check_tproxy_module "xt_socket" "Socket match"
    check_tproxy_module "nf_tproxy_ipv4" "TPROXY IPv4 support"

    echo ""
    echo "--- Packet Marking ---"
    check_module "xt_mark" "Mark match"
    check_module "xt_MARK" "Mark target"

    echo ""
    echo "--- DSCP (for multi-hop chains) ---"
    check_module "xt_DSCP" "DSCP set target"
    check_module "xt_dscp" "DSCP match"

    echo ""
    echo "--- WireGuard ---"
    check_module "wireguard" "WireGuard VPN"
}

# Check routing table availability
check_routing_tables() {
    echo ""
    echo "=============================================="
    echo "          Routing Tables"
    echo "=============================================="
    echo ""

    log_info "Checking routing table configuration..."
    echo ""

    # Check rt_tables file
    local rt_tables="/etc/iproute2/rt_tables"
    if [[ -f "$rt_tables" ]]; then
        log_pass "rt_tables file exists: $rt_tables"

        # Check for tproxy table
        if grep -q "^100.*tproxy" "$rt_tables"; then
            log_pass "TPROXY table (100) is named"
        else
            log_info "TPROXY table (100) not named (optional)"
        fi
    else
        log_warn "rt_tables file not found (tables work but unnamed)"
    fi

    # Verify we can create routing rules
    echo ""
    log_info "Testing routing rule creation..."

    local test_table=999
    local test_mark=0x999

    if ip rule add fwmark $test_mark lookup $test_table priority 32000 2>/dev/null; then
        ip rule del fwmark $test_mark lookup $test_table 2>/dev/null
        log_pass "Can create ip rules with fwmark"
    else
        log_warn "Cannot create ip rules (may need root)"
    fi

    if ip route add local 192.0.2.0/24 dev lo table $test_table 2>/dev/null; then
        ip route del local 192.0.2.0/24 dev lo table $test_table 2>/dev/null
        log_pass "Can add local routes"
    else
        log_warn "Cannot add local routes (may need root)"
    fi
}

# Check iptables availability
check_iptables() {
    echo ""
    echo "=============================================="
    echo "          iptables Configuration"
    echo "=============================================="
    echo ""

    # Detect backend
    local nft_pkts=$(iptables-nft -t mangle -L -v -n 2>/dev/null | awk '{sum+=$1} END {print sum+0}')
    local legacy_pkts=$(iptables-legacy -t mangle -L -v -n 2>/dev/null | awk '{sum+=$1} END {print sum+0}')

    if [[ "$nft_pkts" -gt "$legacy_pkts" ]]; then
        log_info "Active backend: iptables-nft (nftables compatibility)"
    else
        log_info "Active backend: iptables-legacy"
    fi

    # Check TPROXY target availability
    echo ""
    log_info "Testing TPROXY target..."

    # Create a test rule
    local iptables="iptables"
    if iptables -t mangle -A PREROUTING -p tcp --dport 65535 -j TPROXY --on-port 1 --tproxy-mark 0x1 2>/dev/null; then
        iptables -t mangle -D PREROUTING -p tcp --dport 65535 -j TPROXY --on-port 1 --tproxy-mark 0x1 2>/dev/null
        log_pass "TPROXY target is available"
    else
        log_fail "TPROXY target not available"
    fi

    # Check socket match
    log_info "Testing socket match..."
    if iptables -t mangle -A PREROUTING -p tcp -m socket --transparent -j ACCEPT 2>/dev/null; then
        iptables -t mangle -D PREROUTING -p tcp -m socket --transparent -j ACCEPT 2>/dev/null
        log_pass "Socket match with --transparent is available"
    else
        log_fail "Socket match with --transparent not available"
    fi

    # Check DSCP target
    log_info "Testing DSCP target..."
    if iptables -t mangle -A OUTPUT -j DSCP --set-dscp 10 2>/dev/null; then
        iptables -t mangle -D OUTPUT -j DSCP --set-dscp 10 2>/dev/null
        log_pass "DSCP target is available"
    else
        log_warn "DSCP target not available (multi-hop chains may not work)"
    fi
}

# Generate fix commands
generate_fixes() {
    echo ""
    echo "=============================================="
    echo "          Fix Commands"
    echo "=============================================="
    echo ""

    cat << 'EOF'
# Required sysctl settings (add to /etc/sysctl.conf or run with sysctl -w):

# Enable IP forwarding
net.ipv4.ip_forward = 1

# Allow binding to non-local addresses
net.ipv4.ip_nonlocal_bind = 1

# Enable route_localnet for TPROXY
net.ipv4.conf.all.route_localnet = 1
net.ipv4.conf.lo.route_localnet = 1
net.ipv4.conf.default.route_localnet = 1

# Disable strict reverse path filtering
net.ipv4.conf.all.rp_filter = 0
net.ipv4.conf.default.rp_filter = 0

# For WireGuard ingress interface:
# net.ipv4.conf.wg-ingress.route_localnet = 1
# net.ipv4.conf.wg-ingress.rp_filter = 0

# Load required kernel modules:
modprobe xt_TPROXY
modprobe xt_socket
modprobe xt_mark
modprobe xt_MARK
modprobe xt_DSCP
modprobe xt_dscp
modprobe nf_tproxy_ipv4 || modprobe nf_tproxy_core

# Add TPROXY routing table name:
echo "100 tproxy" >> /etc/iproute2/rt_tables
EOF
}

# Apply fixes
apply_fixes() {
    if [[ $EUID -ne 0 ]]; then
        log_fail "Must be root to apply fixes"
        return 1
    fi

    log_info "Applying fixes..."

    # Sysctls
    sysctl -w net.ipv4.ip_forward=1
    sysctl -w net.ipv4.ip_nonlocal_bind=1
    sysctl -w net.ipv4.conf.all.route_localnet=1
    sysctl -w net.ipv4.conf.lo.route_localnet=1
    sysctl -w net.ipv4.conf.default.route_localnet=1
    sysctl -w net.ipv4.conf.all.rp_filter=0
    sysctl -w net.ipv4.conf.default.rp_filter=0

    # Modules
    modprobe xt_TPROXY 2>/dev/null || true
    modprobe xt_socket 2>/dev/null || true
    modprobe xt_mark 2>/dev/null || true
    modprobe xt_MARK 2>/dev/null || true
    modprobe xt_DSCP 2>/dev/null || true
    modprobe xt_dscp 2>/dev/null || true
    modprobe nf_tproxy_ipv4 2>/dev/null || modprobe nf_tproxy_core 2>/dev/null || true

    log_info "Fixes applied"
}

# Print summary
print_summary() {
    echo ""
    echo "=============================================="
    echo "          Summary"
    echo "=============================================="
    echo ""
    echo -e "  ${GREEN}PASS${NC}: $PASS"
    echo -e "  ${RED}FAIL${NC}: $FAIL"
    echo -e "  ${YELLOW}WARN${NC}: $WARN"
    echo ""

    if [[ $FAIL -eq 0 ]]; then
        echo -e "${GREEN}All critical checks passed!${NC}"
        echo "The system is ready for TPROXY operation."
    else
        echo -e "${RED}Some checks failed.${NC}"
        echo "Run with --fix to attempt automatic fixes, or see above for manual commands."
    fi
}

# Main
main() {
    local do_fix=false

    for arg in "$@"; do
        case $arg in
            --fix)
                do_fix=true
                ;;
            --help|-h)
                echo "Usage: $0 [--fix]"
                echo "  --fix: Attempt to automatically fix issues (requires root)"
                exit 0
                ;;
        esac
    done

    echo ""
    echo "=============================================="
    echo "   Phase 0 Day 4: Kernel Configuration Check"
    echo "=============================================="

    check_capabilities
    check_sysctls
    check_modules
    check_routing_tables
    check_iptables

    if [[ "$do_fix" == "true" ]]; then
        apply_fixes
        echo ""
        log_info "Re-running checks after fixes..."
        PASS=0
        FAIL=0
        WARN=0
        check_sysctls
        check_modules
        check_routing_tables
        check_iptables
    fi

    generate_fixes
    print_summary

    if [[ $FAIL -gt 0 ]]; then
        exit 1
    fi
}

main "$@"

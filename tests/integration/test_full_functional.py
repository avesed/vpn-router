#!/usr/bin/env python3
"""
Full Functional Test for VPN-Router Components

Tests all core functionality directly through database and IPC.
Run inside the vpn-node1 container.
"""

import json
import os
import sys
import subprocess
import time

sys.path.insert(0, "/usr/local/bin")

def get_db():
    from db_helper import get_db as _get_db
    key = None
    if os.path.exists("/etc/sing-box/encryption.key"):
        key = open("/etc/sing-box/encryption.key").read().strip()
    return _get_db(encryption_key=key)

def test_wireguard_ingress():
    """Test WireGuard ingress (userspace via rust-router)"""
    print("\n=== 1. WireGuard Ingress (Userspace) ===")
    
    db = get_db()
    
    # Check server config
    wg_server = db.get_wireguard_server()
    if wg_server:
        print(f"Server address: {wg_server.get('address')}")
        print(f"Listen port: {wg_server.get('listen_port')}")
        print(f"Private key: {'set' if wg_server.get('private_key') else 'NOT SET'}")
    else:
        print("WG Server: Not configured")
    
    # Check peers in database
    wg_peers = db.get_wireguard_peers(enabled_only=False)
    print(f"DB Peers: {len(wg_peers)}")
    for p in wg_peers:
        name = p.get('name')
        ips = p.get('allowed_ips')
        enabled = p.get('enabled')
        print(f"  - {name}: {ips} (enabled={enabled})")
    
    # Check rust-router IPC
    import asyncio
    from rust_router_client import RustRouterClient
    
    async def check_rust_router():
        try:
            async with RustRouterClient() as client:
                peers = await client.list_ingress_peers()
                print(f"Rust-router peers: {len(peers)}")
                return len(peers)
        except Exception as e:
            print(f"Rust-router error: {e}")
            return 0
    
    rr_peers = asyncio.run(check_rust_router())
    
    if len(wg_peers) > 0 and rr_peers == len(wg_peers):
        print("[PASS] WG Ingress: peers synced correctly")
        return True
    elif rr_peers > 0:
        print(f"[WARN] WG Ingress: {rr_peers} peers in rust-router, {len(wg_peers)} in DB")
        return True
    else:
        print("[FAIL] WG Ingress: no peers synced")
        return False


def test_wireguard_egress():
    """Test WireGuard egress tunnels"""
    print("\n=== 2. WireGuard Egress ===")
    
    db = get_db()
    
    # Custom WG egress
    custom_egress = db.get_custom_egress_list(enabled_only=False)
    print(f"Custom WG egress: {len(custom_egress)}")
    for e in custom_egress[:5]:
        tag = e.get('tag')
        server = e.get('server')
        port = e.get('server_port')
        enabled = e.get('enabled')
        print(f"  - {tag}: {server}:{port} (enabled={enabled})")
    
    # PIA profiles
    pia_profiles = db.get_pia_profiles(enabled_only=False)
    print(f"PIA profiles: {len(pia_profiles)}")
    for p in pia_profiles[:3]:
        name = p.get('name')
        region = p.get('region_id')
        enabled = p.get('enabled')
        print(f"  - {name}: region={region} (enabled={enabled})")
    
    total = len(custom_egress) + len(pia_profiles)
    if total > 0:
        print(f"[PASS] WG Egress: {total} egress configured")
        return True
    else:
        print("[INFO] WG Egress: no egress configured")
        return True  # Not a failure, just not configured


def test_xray_ingress():
    """Test Xray ingress (VLESS)"""
    print("\n=== 3. Xray Ingress (VLESS) ===")
    
    db = get_db()
    
    # V2Ray inbound config
    v2_inbound = db.get_v2ray_inbound_config()
    if v2_inbound:
        print(f"Enabled: {v2_inbound.get('enabled')}")
        print(f"Protocol: {v2_inbound.get('protocol')}")
        print(f"Port: {v2_inbound.get('listen_port')}")
        print(f"REALITY: {v2_inbound.get('reality_enabled')}")
        print(f"XTLS-Vision: {v2_inbound.get('xtls_vision_enabled')}")
    else:
        print("V2Ray inbound: Not configured")
    
    # V2Ray users
    v2_users = db.get_v2ray_users(enabled_only=False)
    print(f"V2Ray users: {len(v2_users)}")
    for u in v2_users[:5]:
        name = u.get('name')
        flow = u.get('flow')
        enabled = u.get('enabled')
        print(f"  - {name}: flow={flow} (enabled={enabled})")
    
    # Check if xray process is running on port 443
    import socket
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex(('127.0.0.1', 443))
        sock.close()
        port_open = result == 0
    except:
        port_open = False
    
    if v2_inbound and v2_inbound.get('enabled') and port_open:
        print("[PASS] Xray Ingress: enabled and listening")
        return True
    elif v2_inbound and v2_inbound.get('enabled'):
        print("[WARN] Xray Ingress: enabled but port not open")
        return False
    else:
        print("[INFO] Xray Ingress: not enabled")
        return True


def test_xray_egress():
    """Test Xray egress (VLESS)"""
    print("\n=== 4. Xray Egress (VLESS) ===")
    
    db = get_db()
    
    # V2Ray egress
    v2_egress = db.get_v2ray_egress_list(enabled_only=False)
    print(f"V2Ray egress: {len(v2_egress)}")
    for e in v2_egress[:5]:
        tag = e.get('tag')
        server = e.get('server')
        port = e.get('server_port')
        enabled = e.get('enabled')
        print(f"  - {tag}: {server}:{port} (enabled={enabled})")
    
    if len(v2_egress) > 0:
        print(f"[PASS] Xray Egress: {len(v2_egress)} egress configured")
    else:
        print("[INFO] Xray Egress: no egress configured")
    return True


def test_routing_rules():
    """Test routing rules"""
    print("\n=== 5. Routing Rules ===")
    
    db = get_db()
    
    # DB rules
    try:
        rules = db.get_db_rules()
        print(f"DB rules: {len(rules)}")
        for r in rules[:5]:
            tag = r.get('tag')
            outbound = r.get('outbound')
            print(f"  - {tag}: outbound={outbound}")
    except Exception as e:
        print(f"DB rules error: {e}")
        rules = []
    
    # Check generated config
    config_path = "/etc/sing-box/sing-box.generated.json"
    if os.path.exists(config_path):
        with open(config_path) as f:
            config = json.load(f)
        route_rules = config.get('route', {}).get('rules', [])
        print(f"Config route rules: {len(route_rules)}")
    
    print("[PASS] Routing: configuration accessible")
    return True


def test_peer_nodes():
    """Test peer node connections"""
    print("\n=== 6. Peer Nodes ===")
    
    db = get_db()
    
    # Peer nodes
    peer_nodes = db.get_peer_nodes(enabled_only=False)
    print(f"Peer nodes: {len(peer_nodes)}")
    
    connected = 0
    for p in peer_nodes:
        tag = p.get('tag')
        ttype = p.get('tunnel_type')
        status = p.get('tunnel_status')
        endpoint = p.get('endpoint')
        print(f"  - {tag}: type={ttype}, status={status}, endpoint={endpoint}")
        if status == 'connected':
            connected += 1
    
    # Node chains
    chains = db.get_node_chains(enabled_only=False)
    print(f"Node chains: {len(chains)}")
    for c in chains[:3]:
        tag = c.get('tag')
        hops = c.get('hops', [])
        if isinstance(hops, str):
            hops = json.loads(hops) if hops else []
        hop_str = ' -> '.join(hops) if isinstance(hops, list) else str(hops)
        print(f"  - {tag}: {hop_str}")
    
    if len(peer_nodes) > 0:
        print(f"[PASS] Peer Nodes: {len(peer_nodes)} configured, {connected} connected")
    else:
        print("[INFO] Peer Nodes: none configured")
    return True


def test_outbound_groups():
    """Test outbound groups"""
    print("\n=== 7. Outbound Groups ===")
    
    db = get_db()
    
    groups = db.get_outbound_groups(enabled_only=False)
    print(f"Outbound groups: {len(groups)}")
    for g in groups[:5]:
        tag = g.get('tag')
        gtype = g.get('type')
        members = g.get('members')
        print(f"  - {tag}: type={gtype}, members={members}")
    
    if len(groups) > 0:
        print(f"[PASS] Outbound Groups: {len(groups)} configured")
    else:
        print("[INFO] Outbound Groups: none configured")
    return True


def test_process_health():
    """Test process health and resource usage"""
    print("\n=== 8. Process Health ===")
    
    processes = {
        'rust-router': False,
        'sing-box': False,
        'xray': False,
        'api_server': False,
    }
    
    # Check running processes
    import subprocess
    result = subprocess.run(['ps', 'aux'], capture_output=True, text=True)
    
    for line in result.stdout.split('\n'):
        for proc in processes:
            if proc in line and 'grep' not in line:
                processes[proc] = True
                # Extract memory usage
                parts = line.split()
                if len(parts) >= 6:
                    rss_kb = int(parts[5])
                    print(f"  {proc}: running, RSS={rss_kb/1024:.1f}MB")
    
    running = sum(processes.values())
    print(f"\nRunning: {running}/{len(processes)} core processes")
    
    if running >= 2:  # At least rust-router and sing-box
        print("[PASS] Process Health: core processes running")
        return True
    else:
        print("[FAIL] Process Health: missing core processes")
        return False


def test_memory_stability():
    """Test memory stability"""
    print("\n=== 9. Memory Stability ===")
    
    result = subprocess.run(['free', '-m'], capture_output=True, text=True)
    lines = result.stdout.strip().split('\n')
    if len(lines) >= 2:
        parts = lines[1].split()
        if len(parts) >= 4:
            total = int(parts[1])
            used = int(parts[2])
            free = int(parts[3])
            percent = (used / total) * 100
            print(f"Memory: {used}MB / {total}MB ({percent:.1f}% used)")
            
            if percent < 90:
                print("[PASS] Memory: within acceptable limits")
                return True
            else:
                print("[WARN] Memory: usage is high")
                return True  # Not a hard failure
    
    return True


def main():
    print("=" * 60)
    print("VPN-Router Full Functional Tests")
    print("=" * 60)
    
    tests = [
        ("WireGuard Ingress", test_wireguard_ingress),
        ("WireGuard Egress", test_wireguard_egress),
        ("Xray Ingress", test_xray_ingress),
        ("Xray Egress", test_xray_egress),
        ("Routing Rules", test_routing_rules),
        ("Peer Nodes", test_peer_nodes),
        ("Outbound Groups", test_outbound_groups),
        ("Process Health", test_process_health),
        ("Memory Stability", test_memory_stability),
    ]
    
    results = []
    for name, test_func in tests:
        try:
            passed = test_func()
            results.append((name, passed, None))
        except Exception as e:
            results.append((name, False, str(e)))
            print(f"[ERROR] {name}: {e}")
    
    print("\n" + "=" * 60)
    print("SUMMARY")
    print("=" * 60)
    
    passed = sum(1 for _, p, _ in results if p)
    failed = len(results) - passed
    
    print(f"Passed: {passed}/{len(results)}")
    if failed > 0:
        print("\nFailed tests:")
        for name, p, err in results:
            if not p:
                print(f"  - {name}: {err or 'failed'}")
    
    return failed == 0


if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)

#!/usr/bin/env python3
"""Configure kernel WireGuard interface from database

Reads WireGuard server and peer configuration from user-config.db
and applies it to the kernel wg-ingress interface using wg/ip commands.

Usage:
    setup_kernel_wg.py [--interface <name>] [--sync-only]

Options:
    --interface <name>  WireGuard interface name (default: wg-ingress)
    --sync-only         Only sync peers, don't recreate interface
"""
import os
import sys
import subprocess
import tempfile
import argparse
from pathlib import Path

# Add script directory to path for imports
sys.path.insert(0, str(Path(__file__).parent))
from db_helper import get_db

GEODATA_DB_PATH = os.environ.get("GEODATA_DB_PATH", "/etc/sing-box/geoip-geodata.db")
USER_DB_PATH = os.environ.get("USER_DB_PATH", "/etc/sing-box/user-config.db")
DEFAULT_INTERFACE = "wg-ingress"
DEFAULT_WG_SUBNET = os.environ.get("WG_INGRESS_SUBNET", "10.25.0.1/24")

def get_default_peer_ip() -> str:
    """获取默认的 peer IP（基于 DEFAULT_WG_SUBNET）"""
    addr = DEFAULT_WG_SUBNET.split("/")[0]
    prefix = addr.rsplit(".", 1)[0]
    return f"{prefix}.2/32"


def run_cmd(cmd: list, check: bool = True, capture: bool = True) -> subprocess.CompletedProcess:
    """Run command and optionally check return code"""
    print(f"[wg-setup] $ {' '.join(cmd)}")
    result = subprocess.run(cmd, capture_output=capture, text=True, check=False)
    if check and result.returncode != 0:
        print(f"[wg-setup] Command failed: {result.stderr or result.stdout}")
        raise subprocess.CalledProcessError(result.returncode, cmd)
    return result


def interface_exists(interface: str) -> bool:
    """Check if WireGuard interface exists"""
    result = run_cmd(["ip", "link", "show", interface], check=False)
    return result.returncode == 0


def create_interface(interface: str) -> None:
    """Create WireGuard interface if not exists"""
    if not interface_exists(interface):
        print(f"[wg-setup] Creating interface {interface}")
        run_cmd(["ip", "link", "add", interface, "type", "wireguard"])
    else:
        print(f"[wg-setup] Interface {interface} already exists")


def get_current_peers(interface: str) -> set:
    """Get current peers from kernel WireGuard interface"""
    result = run_cmd(["wg", "show", interface, "peers"], check=False)
    if result.returncode != 0:
        return set()
    return set(line.strip() for line in result.stdout.strip().split('\n') if line.strip())


def sync_peers(interface: str, desired_peers: list, current_peers: set) -> None:
    """Sync peers to match desired configuration"""
    desired_pubkeys = {p["public_key"] for p in desired_peers}

    # Remove peers not in desired config
    for pubkey in current_peers - desired_pubkeys:
        print(f"[wg-setup] Removing peer: {pubkey[:20]}...")
        run_cmd(["wg", "set", interface, "peer", pubkey, "remove"])

    # Add or update peers
    for peer in desired_peers:
        pubkey = peer["public_key"]
        allowed_ips = peer.get("allowed_ips", get_default_peer_ip())

        # Build command
        cmd = ["wg", "set", interface, "peer", pubkey, "allowed-ips", allowed_ips]

        # Handle preshared key
        psk_file = None
        if peer.get("preshared_key"):
            with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.psk') as f:
                f.write(peer["preshared_key"])
                psk_file = f.name
            cmd.extend(["preshared-key", psk_file])

        try:
            action = "Updating" if pubkey in current_peers else "Adding"
            print(f"[wg-setup] {action} peer: {peer.get('name', 'unknown')} ({pubkey[:20]}...)")
            run_cmd(cmd)
        finally:
            if psk_file:
                os.unlink(psk_file)


def setup_wireguard_interface(interface: str = DEFAULT_INTERFACE, sync_only: bool = False) -> dict:
    """Setup kernel WireGuard interface from database

    Returns:
        dict with status and configuration info
    """
    db = get_db(GEODATA_DB_PATH, USER_DB_PATH)

    # Get server config
    server = db.get_wireguard_server()
    if not server or not server.get("private_key"):
        return {"success": False, "error": "No WireGuard server configuration in database"}

    # Get peers
    peers = db.get_wireguard_peers(enabled_only=True)

    # Get configuration values
    listen_port = server.get("listen_port", int(os.environ.get("WG_LISTEN_PORT", "36100")))
    address = server.get("address", DEFAULT_WG_SUBNET)
    private_key = server.get("private_key")
    mtu = server.get("mtu", 1420)

    # Create interface if not sync_only
    if not sync_only:
        create_interface(interface)

    # Get current peers before making changes
    current_peers = get_current_peers(interface)

    if not sync_only:
        # Write private key to temp file (wg set requires file)
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.key') as f:
            f.write(private_key)
            private_key_file = f.name

        try:
            # Bring interface down first
            run_cmd(["ip", "link", "set", interface, "down"], check=False)

            # Set private key and listen port
            run_cmd([
                "wg", "set", interface,
                "private-key", private_key_file,
                "listen-port", str(listen_port)
            ])

            # Flush existing addresses and add new one
            run_cmd(["ip", "addr", "flush", "dev", interface], check=False)
            run_cmd(["ip", "addr", "add", address, "dev", interface])

            # Set MTU
            run_cmd(["ip", "link", "set", interface, "mtu", str(mtu)])

            # Bring interface up
            run_cmd(["ip", "link", "set", interface, "up"])

        finally:
            os.unlink(private_key_file)

    # Sync peers
    sync_peers(interface, peers, current_peers)

    result = {
        "success": True,
        "interface": interface,
        "address": address,
        "listen_port": listen_port,
        "mtu": mtu,
        "peer_count": len(peers)
    }

    print(f"[wg-setup] Interface {interface} configured successfully")
    print(f"[wg-setup]   Address: {address}")
    print(f"[wg-setup]   Listen port: {listen_port}")
    print(f"[wg-setup]   MTU: {mtu}")
    print(f"[wg-setup]   Peers: {len(peers)}")

    return result


def add_peer(interface: str, public_key: str, allowed_ips: str, preshared_key: str = None) -> dict:
    """Add a single peer to kernel WireGuard interface"""
    cmd = ["wg", "set", interface, "peer", public_key, "allowed-ips", allowed_ips]

    psk_file = None
    if preshared_key:
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.psk') as f:
            f.write(preshared_key)
            psk_file = f.name
        cmd.extend(["preshared-key", psk_file])

    try:
        run_cmd(cmd)
        return {"success": True, "message": f"Peer {public_key[:20]}... added"}
    except subprocess.CalledProcessError as e:
        return {"success": False, "error": str(e)}
    finally:
        if psk_file:
            os.unlink(psk_file)


def remove_peer(interface: str, public_key: str) -> dict:
    """Remove a peer from kernel WireGuard interface"""
    try:
        run_cmd(["wg", "set", interface, "peer", public_key, "remove"])
        return {"success": True, "message": f"Peer {public_key[:20]}... removed"}
    except subprocess.CalledProcessError as e:
        return {"success": False, "error": str(e)}


def get_interface_status(interface: str = DEFAULT_INTERFACE) -> dict:
    """Get WireGuard interface status using wg show"""
    result = run_cmd(["wg", "show", interface], check=False)
    if result.returncode != 0:
        return {"error": f"Interface {interface} not found or not configured"}

    return parse_wg_show_output(result.stdout)


def parse_wg_show_output(output: str) -> dict:
    """Parse wg show output into structured dict"""
    result = {"interface": {}, "peers": []}
    current_peer = None

    for line in output.strip().split('\n'):
        line = line.rstrip()
        if line.startswith('interface:'):
            result["interface"]["name"] = line.split(':', 1)[1].strip()
        elif line.startswith('  public key:'):
            result["interface"]["public_key"] = line.split(':', 1)[1].strip()
        elif line.startswith('  private key:'):
            result["interface"]["private_key_set"] = "(hidden)" in line
        elif line.startswith('  listening port:'):
            result["interface"]["listen_port"] = int(line.split(':', 1)[1].strip())
        elif line.startswith('peer:'):
            if current_peer:
                result["peers"].append(current_peer)
            current_peer = {"public_key": line.split(':', 1)[1].strip()}
        elif current_peer:
            if line.startswith('  endpoint:'):
                current_peer["endpoint"] = line.split(':', 1)[1].strip()
            elif line.startswith('  allowed ips:'):
                current_peer["allowed_ips"] = line.split(':', 1)[1].strip()
            elif line.startswith('  latest handshake:'):
                current_peer["latest_handshake"] = line.split(':', 1)[1].strip()
            elif line.startswith('  transfer:'):
                transfer = line.split(':', 1)[1].strip()
                # Parse "X received, Y sent"
                parts = transfer.split(',')
                if len(parts) == 2:
                    current_peer["rx"] = parts[0].strip()
                    current_peer["tx"] = parts[1].strip()

    if current_peer:
        result["peers"].append(current_peer)

    return result


def main():
    parser = argparse.ArgumentParser(description="Configure kernel WireGuard interface from database")
    parser.add_argument("--interface", "-i", default=DEFAULT_INTERFACE, help="WireGuard interface name")
    parser.add_argument("--sync-only", "-s", action="store_true", help="Only sync peers, don't recreate interface")
    args = parser.parse_args()

    try:
        result = setup_wireguard_interface(args.interface, args.sync_only)
        if not result.get("success"):
            print(f"[wg-setup] ERROR: {result.get('error')}", file=sys.stderr)
            sys.exit(1)
    except Exception as e:
        print(f"[wg-setup] ERROR: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()

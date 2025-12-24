#!/usr/bin/env python3
"""Configure kernel WireGuard egress interfaces from database

Creates kernel WireGuard interfaces for each enabled PIA profile and custom egress,
replacing the previous sing-box userspace WireGuard endpoints approach.

Benefits:
- Better performance (kernel vs userspace)
- wg show works for debugging
- Standard WireGuard tooling support
- Consistent with ingress architecture

Usage:
    setup_kernel_wg_egress.py [--sync-only] [--cleanup]

Options:
    --sync-only  Only sync existing interfaces, don't create new ones
    --cleanup    Remove all egress interfaces and exit
"""
import os
import sys
import subprocess
import tempfile
import argparse
from pathlib import Path
from typing import Dict, List, Optional, Tuple

# Add script directory to path for imports
sys.path.insert(0, str(Path(__file__).parent))
from db_helper import get_db

GEODATA_DB_PATH = os.environ.get("GEODATA_DB_PATH", "/etc/sing-box/geoip-geodata.db")
USER_DB_PATH = os.environ.get("USER_DB_PATH", "/etc/sing-box/user-config.db")

# Interface naming prefixes
PIA_PREFIX = "wg-pia-"     # 8 chars, leaves 7 for tag
CUSTOM_PREFIX = "wg-eg-"   # 6 chars, leaves 9 for tag
MAX_IFACE_LEN = 15         # Linux interface name limit


def get_egress_interface_name(tag: str, is_pia: bool) -> str:
    """Generate kernel WireGuard interface name for egress

    H12 修复: 使用 hash 确保唯一性，避免长标签截断冲突

    Naming convention:
    - PIA profiles: wg-pia-{tag}
    - Custom egress: wg-eg-{tag}

    Examples:
    - wg-pia-new_york (PIA New York exit)
    - wg-eg-cn2-la (custom CN2 LA exit)
    - wg-pia-ab12c34 (hash of long tag)
    """
    import hashlib
    prefix = PIA_PREFIX if is_pia else CUSTOM_PREFIX
    max_tag_len = MAX_IFACE_LEN - len(prefix)

    if len(tag) <= max_tag_len:
        return f"{prefix}{tag}"
    else:
        # H12: 使用 hash 确保唯一性
        tag_hash = hashlib.md5(tag.encode('utf-8')).hexdigest()[:max_tag_len]
        return f"{prefix}{tag_hash}"


def run_cmd(cmd: list, check: bool = True, capture: bool = True) -> subprocess.CompletedProcess:
    """Run command and optionally check return code"""
    print(f"[wg-egress] $ {' '.join(cmd)}")
    result = subprocess.run(cmd, capture_output=capture, text=True, check=False)
    if check and result.returncode != 0:
        print(f"[wg-egress] Command failed: {result.stderr or result.stdout}")
        raise subprocess.CalledProcessError(result.returncode, cmd)
    return result


def interface_exists(interface: str) -> bool:
    """Check if WireGuard interface exists"""
    result = run_cmd(["ip", "link", "show", interface], check=False)
    return result.returncode == 0


def get_existing_egress_interfaces() -> List[str]:
    """Get list of existing egress WireGuard interfaces"""
    result = run_cmd(["ip", "-br", "link", "show", "type", "wireguard"], check=False)
    if result.returncode != 0:
        return []

    interfaces = []
    for line in result.stdout.strip().split('\n'):
        if not line.strip():
            continue
        iface = line.split()[0]
        if iface.startswith(PIA_PREFIX) or iface.startswith(CUSTOM_PREFIX):
            interfaces.append(iface)
    return interfaces


def create_egress_interface(
    interface: str,
    private_key: str,
    peer_ip: str,
    server: str,
    server_port: int,
    public_key: str,
    mtu: int = 1420,
    preshared_key: Optional[str] = None,
    reserved: Optional[List[int]] = None
) -> bool:
    """Create and configure a kernel WireGuard egress interface

    Args:
        interface: Interface name (e.g., wg-pia-new_york)
        private_key: Client's private key
        peer_ip: Client's IP in VPN (e.g., 10.1.165.62/32)
        server: Server address (IP or hostname)
        server_port: Server WireGuard port
        public_key: Server's public key
        mtu: MTU value (default 1420)
        preshared_key: Optional preshared key
        reserved: Optional reserved bytes for WARP (e.g., [0, 0, 0])

    Returns:
        True if successful
    """
    # Normalize peer_ip
    if peer_ip and "/" not in peer_ip:
        peer_ip = f"{peer_ip}/32"

    # Create interface if not exists
    if not interface_exists(interface):
        print(f"[wg-egress] Creating interface {interface}")
        run_cmd(["ip", "link", "add", interface, "type", "wireguard"])
    else:
        print(f"[wg-egress] Interface {interface} already exists, updating...")

    # Write private key to temp file
    with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.key') as f:
        f.write(private_key)
        private_key_file = f.name

    psk_file = None
    if preshared_key:
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.psk') as f:
            f.write(preshared_key)
            psk_file = f.name

    try:
        # Bring interface down first
        run_cmd(["ip", "link", "set", interface, "down"], check=False)

        # Set private key
        run_cmd(["wg", "set", interface, "private-key", private_key_file])

        # Build peer command
        peer_cmd = [
            "wg", "set", interface, "peer", public_key,
            "endpoint", f"{server}:{server_port}",
            "allowed-ips", "0.0.0.0/0,::/0",
            "persistent-keepalive", "25"
        ]

        if psk_file:
            peer_cmd.extend(["preshared-key", psk_file])

        run_cmd(peer_cmd)

        # Flush existing addresses and add new one
        run_cmd(["ip", "addr", "flush", "dev", interface], check=False)
        if peer_ip:
            run_cmd(["ip", "addr", "add", peer_ip, "dev", interface])

        # Set MTU
        run_cmd(["ip", "link", "set", interface, "mtu", str(mtu)])

        # Bring interface up
        run_cmd(["ip", "link", "set", interface, "up"])

        # Add default route via this interface (using table = interface name hash)
        # We use policy routing later if needed

        return True

    except subprocess.CalledProcessError as e:
        print(f"[wg-egress] Failed to configure {interface}: {e}")
        return False

    finally:
        os.unlink(private_key_file)
        if psk_file:
            os.unlink(psk_file)


def remove_egress_interface(interface: str) -> bool:
    """Remove a kernel WireGuard egress interface"""
    if not interface_exists(interface):
        return True

    try:
        print(f"[wg-egress] Removing interface {interface}")
        run_cmd(["ip", "link", "del", interface])
        return True
    except subprocess.CalledProcessError:
        return False


def get_pia_egress_list(db) -> List[Dict]:
    """Get enabled PIA profiles with WireGuard credentials"""
    profiles = db.get_pia_profiles(enabled_only=True)
    # Filter to only profiles with complete WireGuard credentials
    return [
        p for p in profiles
        if p.get("private_key") and p.get("server_public_key") and p.get("server_ip")
    ]


def get_custom_egress_list(db) -> List[Dict]:
    """Get enabled custom WireGuard egress"""
    return db.get_custom_egress_list(enabled_only=True)


def setup_all_egress_interfaces(sync_only: bool = False) -> Dict:
    """Setup all kernel WireGuard egress interfaces from database

    Returns:
        dict with status and interface info
    """
    db = get_db(GEODATA_DB_PATH, USER_DB_PATH)

    # Get egress configurations from database
    pia_profiles = get_pia_egress_list(db)
    custom_egress = get_custom_egress_list(db)

    print(f"[wg-egress] Found {len(pia_profiles)} PIA profiles, {len(custom_egress)} custom egress")

    if not pia_profiles and not custom_egress:
        print("[wg-egress] No egress configurations found in database")
        return {"success": True, "interfaces": [], "message": "No egress to configure"}

    # Get existing interfaces
    existing_interfaces = set(get_existing_egress_interfaces())

    # Track expected interfaces
    expected_interfaces = set()
    created = 0
    updated = 0
    failed = 0

    # Setup PIA egress interfaces
    for profile in pia_profiles:
        tag = profile.get("name")
        interface = get_egress_interface_name(tag, is_pia=True)
        expected_interfaces.add(interface)

        if sync_only and interface not in existing_interfaces:
            continue

        # Extract WireGuard config from PIA profile
        success = create_egress_interface(
            interface=interface,
            private_key=profile.get("private_key"),
            peer_ip=profile.get("peer_ip"),
            server=profile.get("server_ip"),
            server_port=profile.get("server_port", 1337),
            public_key=profile.get("server_public_key"),
            mtu=1300  # PIA default MTU
        )

        if success:
            if interface in existing_interfaces:
                updated += 1
            else:
                created += 1
        else:
            failed += 1

    # Setup custom egress interfaces
    for egress in custom_egress:
        tag = egress.get("tag")
        interface = get_egress_interface_name(tag, is_pia=False)
        expected_interfaces.add(interface)

        if sync_only and interface not in existing_interfaces:
            continue

        # Parse reserved bytes if present
        reserved = None
        if egress.get("reserved"):
            try:
                import json
                reserved = json.loads(egress["reserved"])
            except (json.JSONDecodeError, TypeError):
                pass

        success = create_egress_interface(
            interface=interface,
            private_key=egress.get("private_key"),
            peer_ip=egress.get("address"),
            server=egress.get("server"),
            server_port=egress.get("port", 51820),
            public_key=egress.get("public_key"),
            mtu=egress.get("mtu", 1420),
            preshared_key=egress.get("pre_shared_key"),
            reserved=reserved
        )

        if success:
            if interface in existing_interfaces:
                updated += 1
            else:
                created += 1
        else:
            failed += 1

    # Cleanup stale interfaces (interfaces not in database)
    stale_interfaces = existing_interfaces - expected_interfaces
    removed = 0
    for interface in stale_interfaces:
        print(f"[wg-egress] Removing stale interface: {interface}")
        if remove_egress_interface(interface):
            removed += 1

    result = {
        "success": failed == 0,
        "interfaces": list(expected_interfaces),
        "created": created,
        "updated": updated,
        "removed": removed,
        "failed": failed
    }

    print(f"[wg-egress] Setup complete: {created} created, {updated} updated, "
          f"{removed} removed, {failed} failed")

    return result


def cleanup_all_egress_interfaces() -> Dict:
    """Remove all kernel WireGuard egress interfaces"""
    existing = get_existing_egress_interfaces()
    removed = 0

    for interface in existing:
        if remove_egress_interface(interface):
            removed += 1

    return {"success": True, "removed": removed}


def get_interface_status(interface: str) -> Optional[Dict]:
    """Get WireGuard interface status using wg show"""
    result = run_cmd(["wg", "show", interface], check=False)
    if result.returncode != 0:
        return None

    return parse_wg_show_output(result.stdout)


def parse_wg_show_output(output: str) -> Dict:
    """Parse wg show output into structured dict"""
    result = {"interface": {}, "peers": []}
    current_peer = None

    for line in output.strip().split('\n'):
        line = line.rstrip()
        if line.startswith('interface:'):
            result["interface"]["name"] = line.split(':', 1)[1].strip()
        elif line.startswith('  public key:'):
            if current_peer is None:
                result["interface"]["public_key"] = line.split(':', 1)[1].strip()
            else:
                current_peer["public_key"] = line.split(':', 1)[1].strip()
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
                parts = transfer.split(',')
                if len(parts) == 2:
                    current_peer["rx"] = parts[0].strip()
                    current_peer["tx"] = parts[1].strip()

    if current_peer:
        result["peers"].append(current_peer)

    return result


def get_all_egress_status() -> Dict:
    """Get status of all egress WireGuard interfaces"""
    interfaces = get_existing_egress_interfaces()
    statuses = {}

    for interface in interfaces:
        status = get_interface_status(interface)
        if status:
            statuses[interface] = status

    return statuses


def main():
    parser = argparse.ArgumentParser(description="Configure kernel WireGuard egress interfaces")
    parser.add_argument("--sync-only", "-s", action="store_true",
                        help="Only sync existing interfaces, don't create new ones")
    parser.add_argument("--cleanup", "-c", action="store_true",
                        help="Remove all egress interfaces and exit")
    parser.add_argument("--status", action="store_true",
                        help="Show status of all egress interfaces")
    args = parser.parse_args()

    try:
        if args.cleanup:
            result = cleanup_all_egress_interfaces()
            print(f"[wg-egress] Cleanup complete: {result['removed']} interfaces removed")
        elif args.status:
            statuses = get_all_egress_status()
            if not statuses:
                print("[wg-egress] No egress interfaces found")
            else:
                import json
                print(json.dumps(statuses, indent=2))
        else:
            result = setup_all_egress_interfaces(args.sync_only)
            if not result.get("success"):
                sys.exit(1)
    except Exception as e:
        print(f"[wg-egress] ERROR: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()

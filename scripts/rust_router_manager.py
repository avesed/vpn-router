#!/usr/bin/env python3
"""
Rust Router Manager (Phase 3.4)

Manager class that syncs database configuration to rust-router.
Handles outbound lifecycle, routing rule sync, and configuration updates.

Features:
- Full sync of all egress types (PIA, Custom WG, WARP, V2Ray, Direct, OpenVPN)
- Incremental sync on egress add/remove/update
- Routing rule sync from database
- Graceful degradation when rust-router unavailable
- Lock protection for concurrent sync operations

Usage:
    manager = RustRouterManager()

    # Full sync on startup
    result = await manager.full_sync()

    # Incremental sync on egress change
    await manager.notify_egress_added("us-east", "pia")
    await manager.notify_egress_removed("old-proxy", "custom")
    await manager.notify_egress_updated("warp-main", "warp")
"""

import asyncio
import json
import ipaddress
import logging
import os
import socket
import sys
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

# Add script directory to path for imports
sys.path.insert(0, str(Path(__file__).parent))

from rust_router_client import (
    RustRouterClient,
    RuleConfig,
    IpcResponse,
    UpdateRoutingResult,
    is_available,
    # Phase 6 types
    PeerInfo,
    EcmpGroupInfo,
    EcmpMemberInfo,
    ChainInfo,
    ChainRoleInfo,
)

logger = logging.getLogger(__name__)

# Environment variables for paths
USER_DB_PATH = os.environ.get("USER_DB_PATH", "/etc/sing-box/user-config.db")
GEODATA_DB_PATH = os.environ.get("GEODATA_DB_PATH", "/etc/sing-box/geoip-geodata.db")

# Egress type to rust-router outbound type mapping
EGRESS_TYPE_MAP = {
    "pia": "wireguard",
    "custom": "wireguard",
    "warp": "wireguard",  # WARP WireGuard mode
    "warp-masque": "socks5",  # WARP MASQUE mode
    "v2ray": "socks5",
    "direct": "direct",
    "openvpn": "direct",  # OpenVPN uses tun device binding
}


@dataclass
class SyncResult:
    """Result of a sync operation"""
    success: bool
    outbounds_added: int = 0
    outbounds_removed: int = 0
    outbounds_updated: int = 0
    rules_synced: int = 0
    # Phase 6 fields
    peers_synced: int = 0
    ecmp_groups_synced: int = 0
    chains_synced: int = 0
    wg_tunnels_synced: int = 0  # Phase 11-Fix.AB
    wg_tunnels_removed: int = 0  # Phase 11-Fix.AB
    wg_ingress_peers_synced: int = 0  # Phase 11-Fix.AD: WireGuard ingress client peers
    dns_blocklist_synced: bool = False  # Phase 3-Fix: DNS adblock rules
    errors: List[str] = field(default_factory=list)


def _get_db():
    """Lazy import and get database instance.

    Phase 11-Fix.AB: Ensures SQLCIPHER_KEY is available from multiple sources:
    1. Environment variable (preferred)
    2. Key file (/etc/sing-box/encryption.key or .db-key)
    3. KeyManager fallback

    This fixes Issue #10 where SQLCIPHER_KEY was not available to RustRouterManager.
    """
    from db_helper import get_db

    # Check if SQLCIPHER_KEY is already set
    encryption_key = os.environ.get("SQLCIPHER_KEY")

    if not encryption_key:
        # Try to read from key files
        key_files = [
            "/etc/sing-box/encryption.key",
            "/etc/sing-box/.db-key",
        ]
        for key_file in key_files:
            try:
                if os.path.exists(key_file):
                    with open(key_file, "r") as f:
                        encryption_key = f.read().strip()
                    if encryption_key:
                        logger.debug(f"Read SQLCIPHER_KEY from {key_file}")
                        break
            except Exception as e:
                logger.warning(f"Failed to read key from {key_file}: {e}")

        # Try KeyManager as last resort
        if not encryption_key:
            try:
                from key_manager import KeyManager
                encryption_key = KeyManager.get_or_create_key()
                if encryption_key:
                    logger.debug("Got SQLCIPHER_KEY from KeyManager")
            except Exception as e:
                logger.warning(f"KeyManager fallback failed: {e}")

        # Set environment variable for future calls
        if encryption_key:
            os.environ["SQLCIPHER_KEY"] = encryption_key
        else:
            logger.error(
                "SQLCIPHER_KEY not found in environment, key files, or KeyManager. "
                "Database operations may fail. Set SQLCIPHER_KEY environment variable "
                "or ensure /etc/sing-box/encryption.key exists."
            )

    return get_db(encryption_key=encryption_key)


def _get_egress_interface_name(tag: str, is_pia: bool = False, egress_type: str = None) -> str:
    """Get WireGuard interface name for an egress"""
    from db_helper import get_egress_interface_name
    return get_egress_interface_name(tag, is_pia=is_pia, egress_type=egress_type)


def _is_ip_address(host: str) -> bool:
    """Check if host is already an IP address (IPv4 or IPv6)."""
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def _parse_wg_config_file(config_path: str) -> Optional[Dict[str, str]]:
    """Parse a WireGuard config file and extract key fields.

    Phase 6-Fix.AG: WARP WireGuard config is stored in wg.conf format.
    This helper extracts the fields needed for rust-router's CreateWgTunnel.

    Args:
        config_path: Path to the wg.conf file

    Returns:
        Dict with private_key, peer_public_key, endpoint, local_ip, or None if failed
    """
    try:
        if not os.path.exists(config_path):
            logger.warning(f"WireGuard config file not found: {config_path}")
            return None

        with open(config_path, "r") as f:
            content = f.read()

        result = {
            "private_key": None,
            "peer_public_key": None,
            "endpoint": None,
            "local_ip": None,
        }

        current_section = None
        for line in content.split("\n"):
            line = line.strip()
            if not line or line.startswith("#"):
                continue

            # Section headers
            if line.startswith("[") and line.endswith("]"):
                current_section = line[1:-1].lower()
                continue

            # Key-value pairs
            if "=" in line:
                key, _, value = line.partition("=")
                key = key.strip().lower()
                value = value.strip()

                if current_section == "interface":
                    if key == "privatekey":
                        result["private_key"] = value
                    elif key == "address":
                        # Take first address (IPv4 preferred)
                        addresses = [a.strip() for a in value.split(",")]
                        for addr in addresses:
                            if "/" in addr and ":" not in addr:  # IPv4 with CIDR
                                result["local_ip"] = addr
                                break
                        if not result["local_ip"] and addresses:
                            result["local_ip"] = addresses[0]

                elif current_section == "peer":
                    if key == "publickey":
                        result["peer_public_key"] = value
                    elif key == "endpoint":
                        result["endpoint"] = value

        # Validate required fields
        if not all([result["private_key"], result["peer_public_key"], result["endpoint"]]):
            logger.warning(f"WireGuard config missing required fields: {config_path}")
            return None

        # Default local_ip if not found
        if not result["local_ip"]:
            result["local_ip"] = "10.0.0.2/32"

        return result

    except Exception as e:
        logger.error(f"Failed to parse WireGuard config {config_path}: {e}")
        return None


async def _resolve_hostname_async(
    hostname: str,
    port: int = 0,
    dns_cache: Optional[Dict[str, str]] = None,
) -> Optional[str]:
    """Resolve hostname to IP address asynchronously.

    Phase 11-Fix.AC: Async DNS resolution for WireGuard egress endpoints.
    Hostnames in Custom WG or WARP egress are resolved to IP addresses
    since rust-router's WgEgressConfig requires IP:port format.

    Args:
        hostname: The hostname or IP address to resolve
        port: Port number for getaddrinfo (default 0)
        dns_cache: Optional cache dict to store/retrieve resolved IPs

    Returns:
        IP address string if resolution successful, None if failed.
        Returns hostname unchanged if it's already an IP address.
    """
    # Return unchanged if already an IP address
    if _is_ip_address(hostname):
        return hostname

    # Check cache first
    if dns_cache is not None and hostname in dns_cache:
        logger.debug(f"DNS cache hit for {hostname}: {dns_cache[hostname]}")
        return dns_cache[hostname]

    # Resolve hostname using getaddrinfo in executor (non-blocking)
    # Phase 11-Fix.AC: Use get_running_loop() for Python 3.10+ compatibility
    loop = asyncio.get_running_loop()
    try:
        # Use run_in_executor to avoid blocking the event loop
        # socket.getaddrinfo is a blocking call
        result = await loop.run_in_executor(
            None,  # Use default ThreadPoolExecutor
            lambda: socket.getaddrinfo(
                hostname,
                port,
                socket.AF_INET,  # Prefer IPv4
                socket.SOCK_DGRAM,  # UDP (WireGuard uses UDP)
                socket.IPPROTO_UDP,
            )
        )

        if result:
            # result format: [(family, type, proto, canonname, sockaddr), ...]
            # sockaddr for AF_INET: (host, port)
            ip_address = result[0][4][0]
            logger.info(f"Resolved hostname {hostname} to {ip_address}")

            # Cache the result
            if dns_cache is not None:
                dns_cache[hostname] = ip_address

            return ip_address
        else:
            logger.warning(f"DNS resolution returned empty result for {hostname}")
            return None

    except socket.gaierror as e:
        logger.warning(f"DNS resolution failed for {hostname}: {e}")
        return None
    except Exception as e:
        logger.warning(f"Unexpected error resolving {hostname}: {e}")
        return None


class RustRouterManager:
    """
    Manages rust-router configuration and lifecycle.

    This manager synchronizes the database configuration with rust-router,
    handling all egress types and routing rules.

    Thread Safety:
        Uses asyncio.Lock to prevent concurrent sync operations.
        Safe to call from multiple coroutines.

    Graceful Degradation:
        If rust-router is not available, all operations return success=False
        but do not raise exceptions. The application can continue to use
        the fallback routing mechanism (e.g., sing-box).
    """

    def __init__(
        self,
        socket_path: Optional[str] = None,
        connect_timeout: float = 5.0,
        request_timeout: float = 10.0,
    ):
        """Initialize the manager.

        Args:
            socket_path: Path to rust-router Unix socket
            connect_timeout: Connection timeout in seconds
            request_timeout: Request timeout in seconds
        """
        self._socket_path = socket_path
        self._connect_timeout = connect_timeout
        self._request_timeout = request_timeout
        self._sync_lock = asyncio.Lock()
        self._db = None  # Lazy loaded
        # Userspace WireGuard is now the only mode (kernel WG deprecated)
        self._peer_repair_attempted_tags: Set[str] = set()

    def _get_db(self):
        """Get database instance (lazy load)"""
        if self._db is None:
            self._db = _get_db()
        return self._db

    def _get_local_node_tag(self) -> str:
        """Match rust-router's local node tag resolution."""
        return os.environ.get("RUST_ROUTER_NODE_TAG") or socket.gethostname()

    def _parse_chain_hops(self, hops: Any) -> List[str]:
        """Parse hops from DB (list or JSON string)."""
        if isinstance(hops, list):
            return [str(h) for h in hops]
        if isinstance(hops, str):
            if not hops.strip():
                return []
            try:
                parsed = json.loads(hops)
            except json.JSONDecodeError:
                return []
            if isinstance(parsed, list):
                return [str(h) for h in parsed]
        return []

    def _build_chain_config(self, chain: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Build IPC v3.2 ChainConfig payload."""
        tag = chain.get("tag", "")
        if not tag:
            return None

        hops = self._parse_chain_hops(chain.get("hops", []))
        if not hops:
            return None

        local_tag = self._get_local_node_tag()
        if local_tag in hops:
            full_hops = hops
        else:
            full_hops = [local_tag] + hops

        if len(full_hops) < 2:
            return None

        hop_configs = []
        for idx, hop_tag in enumerate(full_hops):
            if idx == 0:
                role = "entry"
            elif idx == len(full_hops) - 1:
                role = "terminal"
            else:
                role = "relay"

            tunnel_type = "wireguard"
            if hop_tag != local_tag:
                peer = self._get_db().get_peer_node(hop_tag)
                if peer:
                    tunnel_type = (peer.get("tunnel_type") or "wireguard").lower()
            if tunnel_type not in ("wireguard", "xray"):
                tunnel_type = "wireguard"

            hop_configs.append({
                "node_tag": hop_tag,
                "role": role,
                "tunnel_type": tunnel_type,
            })

        dscp_value = chain.get("dscp_value")
        try:
            dscp_value = int(dscp_value) if dscp_value is not None else 0
        except (TypeError, ValueError):
            dscp_value = 0

        return {
            "tag": tag,
            "description": chain.get("description") or "",
            "dscp_value": dscp_value,
            "hops": hop_configs,
            "rules": [],
            "exit_egress": chain.get("exit_egress") or "",
            "allow_transitive": bool(chain.get("allow_transitive", False)),
        }

    def _extract_host(self, endpoint: str) -> Optional[str]:
        if not endpoint:
            return None
        if endpoint.startswith("["):
            end_idx = endpoint.find("]")
            if end_idx != -1:
                return endpoint[1:end_idx]
        if ":" in endpoint:
            return endpoint.rsplit(":", 1)[0]
        return endpoint

    def _get_local_tag_for_pairing(self) -> str:
        return (
            os.environ.get("VPN_ROUTER_NODE_ID")
            or os.environ.get("RUST_ROUTER_NODE_TAG")
            or socket.gethostname()
        )

    def _get_local_api_port(self) -> int:
        return int(os.environ.get("WEB_PORT", "36000"))

    def _get_json(self, url: str, timeout: int = 5) -> Optional[Dict[str, Any]]:
        try:
            req = urllib.request.Request(url, method="GET")
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                return json.loads(resp.read().decode("utf-8"))
        except Exception as exc:
            logger.debug(f"Failed to GET {url}: {exc}")
            return None

    def _post_json(self, url: str, payload: Dict[str, Any], timeout: int = 10) -> Optional[Dict[str, Any]]:
        try:
            data = json.dumps(payload).encode("utf-8")
            req = urllib.request.Request(
                url,
                data=data,
                method="POST",
                headers={"Content-Type": "application/json"},
            )
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                return json.loads(resp.read().decode("utf-8"))
        except Exception as exc:
            logger.warning(f"Failed to POST {url}: {exc}")
            return None

    async def _get_json_async(self, url: str, timeout: int = 5) -> Optional[Dict[str, Any]]:
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(None, lambda: self._get_json(url, timeout))

    async def _post_json_async(self, url: str, payload: Dict[str, Any], timeout: int = 10) -> Optional[Dict[str, Any]]:
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(None, lambda: self._post_json(url, payload, timeout))

    async def _discover_local_endpoint(self, peer: Dict[str, Any], local_tag: str) -> Optional[str]:
        peer_endpoint = peer.get("endpoint", "")
        peer_host = self._extract_host(peer_endpoint)
        if not peer_host:
            return None
        url = f"http://{peer_host}:8000/api/peers/{urllib.parse.quote(local_tag)}"
        data = await self._get_json_async(url)
        if not data:
            return None
        return data.get("endpoint")

    async def _repair_userspace_peer_via_api(self, peer: Dict[str, Any]) -> bool:
        """Recreate userspace WG peer via pairing APIs when rust-router lost state."""
        local_tag = self._get_local_tag_for_pairing()
        local_endpoint = None
        for _ in range(5):
            local_endpoint = await self._discover_local_endpoint(peer, local_tag)
            if local_endpoint:
                break
            await asyncio.sleep(3)
        if not local_endpoint:
            logger.warning(f"Cannot discover local endpoint for pairing with {peer.get('tag')}")
            return False

        local_api_port = self._get_local_api_port()
        gen_payload = {
            "node_tag": local_tag,
            "node_description": local_tag,
            "endpoint": local_endpoint,
            "api_port": local_api_port,
            "bidirectional": True,
            "tunnel_type": "wireguard",
        }
        gen_resp = await self._post_json_async(
            "http://127.0.0.1:8000/api/peer/generate-pair-request",
            gen_payload,
        )
        if not gen_resp or not gen_resp.get("code"):
            logger.warning(f"Failed to generate pairing request for {peer.get('tag')}")
            return False

        peer_endpoint = peer.get("endpoint", "")
        peer_host = self._extract_host(peer_endpoint)
        if not peer_host:
            logger.warning(f"Missing endpoint for peer {peer.get('tag')}")
            return False

        import_payload = {
            "code": gen_resp["code"],
            "local_node_tag": peer.get("tag"),
            "local_node_description": peer.get("tag"),
            "local_endpoint": peer_endpoint,
            "api_port": peer.get("api_port") or 36000,
        }
        import_resp = None
        for _ in range(5):
            import_resp = await self._post_json_async(
                f"http://{peer_host}:8000/api/peer/import-pair-request",
                import_payload,
            )
            if import_resp and import_resp.get("success"):
                break
            await asyncio.sleep(3)
        if not import_resp or not import_resp.get("success"):
            logger.warning(f"Failed to import pairing request on {peer.get('tag')}")
            return False

        response_code = import_resp.get("response_code")
        if response_code:
            pending_request = gen_resp.get("pending_request") or {}
            pending_request.setdefault("code", gen_resp["code"])
            pending_request.setdefault("node_tag", local_tag)
            pending_request.setdefault("tunnel_type", "wireguard")
            complete_payload = {
                "code": response_code,
                "pending_request": pending_request,
            }
            complete_resp = None
            for _ in range(3):
                complete_resp = await self._post_json_async(
                    "http://127.0.0.1:8000/api/peer/complete-pairing",
                    complete_payload,
                )
                if complete_resp and complete_resp.get("success"):
                    break
                await asyncio.sleep(2)
            if not complete_resp or not complete_resp.get("success"):
                logger.warning(f"Failed to complete pairing with {peer.get('tag')}")
                return False

        return True

    async def _get_client(self) -> RustRouterClient:
        """Create a new client instance"""
        return RustRouterClient(
            socket_path=self._socket_path,
            connect_timeout=self._connect_timeout,
            request_timeout=self._request_timeout,
        )

    async def is_available(self) -> bool:
        """Check if rust-router is available"""
        return await is_available(self._socket_path)

    # =========================================================================
    # Outbound Sync
    # =========================================================================

    async def sync_outbounds(self) -> SyncResult:
        """Sync all outbounds from database to rust-router.

        This method:
        1. Gets all enabled egress from database (PIA, Custom, WARP, V2Ray, Direct, OpenVPN)
        2. Gets current outbounds from rust-router
        3. Adds missing outbounds, removes stale outbounds

        Returns:
            SyncResult with statistics and errors
        """
        result = SyncResult(success=True)

        async with self._sync_lock:
            try:
                db = self._get_db()

                # Collect all egress from database
                db_outbounds: Dict[str, Dict[str, Any]] = {}

                # NOTE: PIA/Custom/WARP WireGuard egress are handled by sync_wg_egress_tunnels()
                # using CreateWgTunnel IPC command (userspace WireGuard via boringtun).
                # Kernel WireGuard mode has been deprecated.

                # WARP MASQUE uses SOCKS5
                for egress in db.get_warp_egress_list(enabled_only=True):
                    tag = egress.get("tag", "")
                    protocol = egress.get("protocol", "wireguard")
                    if tag and protocol != "wireguard":
                        socks_port = egress.get("socks_port")
                        if socks_port:
                            db_outbounds[tag] = {
                                "type": "socks5",
                                "server_addr": f"127.0.0.1:{socks_port}",
                                "egress_type": "warp-masque",
                            }

                # V2Ray egress (SOCKS5)
                for egress in db.get_v2ray_egress_list(enabled_only=True):
                    tag = egress.get("tag", "")
                    socks_port = egress.get("socks_port")
                    if tag and socks_port:
                        db_outbounds[tag] = {
                            "type": "socks5",
                            "server_addr": f"127.0.0.1:{socks_port}",
                            "egress_type": "v2ray",
                        }

                # Direct egress
                for egress in db.get_direct_egress_list(enabled_only=True):
                    tag = egress.get("tag", "")
                    if tag:
                        db_outbounds[tag] = {
                            "type": "direct",
                            "bind_interface": egress.get("bind_interface"),
                            "bind_address": egress.get("bind_address"),
                            "egress_type": "direct",
                        }

                # OpenVPN egress (uses tun device)
                for egress in db.get_openvpn_egress_list(enabled_only=True):
                    tag = egress.get("tag", "")
                    tun_device = egress.get("tun_device")
                    if tag and tun_device:
                        db_outbounds[tag] = {
                            "type": "direct",
                            "bind_interface": tun_device,
                            "egress_type": "openvpn",
                        }

                # Always add direct and block outbounds
                db_outbounds["direct"] = {"type": "direct", "egress_type": "direct"}
                db_outbounds["block"] = {"type": "block", "egress_type": "block"}

                # Get current outbounds from rust-router
                async with await self._get_client() as client:
                    current_outbounds = await client.list_outbounds()
                    current_tags = {o.tag for o in current_outbounds}

                    # Always get WireGuard tunnel tags to exclude from removal
                    # WG tunnels are managed by wg_egress_manager, not outbound_manager,
                    # so remove_outbound() would fail for them
                    wg_tunnel_tags: set = set()
                    try:
                        wg_tunnels = await client.list_wg_tunnels()
                        wg_tunnel_tags = {t.tag for t in wg_tunnels}
                    except Exception as e:
                        logger.debug(f"Failed to get WG tunnel tags: {e}")

                    # Add missing outbounds
                    for tag, config in db_outbounds.items():
                        if tag not in current_tags:
                            add_result = await self._add_outbound(client, tag, config)
                            if add_result.success:
                                result.outbounds_added += 1
                            else:
                                result.errors.append(f"Failed to add {tag}: {add_result.error}")

                    # Remove stale outbounds (except built-in ones and WireGuard tunnels)
                    builtin_tags = {"direct", "block"}
                    for current_tag in current_tags:
                        # Skip built-in tags, WireGuard tunnels, and tags in db_outbounds
                        if current_tag in builtin_tags:
                            continue
                        if current_tag in wg_tunnel_tags:
                            continue
                        if current_tag in db_outbounds:
                            continue
                        remove_result = await client.remove_outbound(current_tag)
                        if remove_result.success:
                            result.outbounds_removed += 1
                        else:
                            result.errors.append(f"Failed to remove {current_tag}: {remove_result.error}")

                if result.errors:
                    result.success = False

                logger.info(
                    f"Outbound sync complete: added={result.outbounds_added}, "
                    f"removed={result.outbounds_removed}, errors={len(result.errors)}"
                )

            except Exception as e:
                result.success = False
                result.errors.append(f"Sync failed: {e}")
                logger.error(f"Outbound sync failed: {e}")

        return result

    async def _add_outbound(
        self,
        client: RustRouterClient,
        tag: str,
        config: Dict[str, Any],
    ) -> IpcResponse:
        """Add a single outbound based on config type"""
        outbound_type = config.get("type", "direct")

        if outbound_type == "wireguard":
            interface = config.get("interface", "")
            routing_mark = config.get("routing_mark")
            return await client.add_wireguard_outbound(
                tag=tag,
                interface=interface,
                routing_mark=routing_mark,
            )

        elif outbound_type == "socks5":
            server_addr = config.get("server_addr", "")
            username = config.get("username")
            password = config.get("password")
            return await client.add_socks5_outbound(
                tag=tag,
                server_addr=server_addr,
                username=username,
                password=password,
            )

        elif outbound_type == "direct":
            # For direct outbounds, we use the basic add mechanism
            # (bind_interface/bind_address handled by rust-router config)
            return IpcResponse(success=True, response_type="success")

        elif outbound_type == "block":
            # Block outbound is built-in
            return IpcResponse(success=True, response_type="success")

        else:
            return IpcResponse(
                success=False,
                response_type="error",
                error=f"Unknown outbound type: {outbound_type}",
            )

    # =========================================================================
    # Userspace WireGuard Egress Sync (Phase 11-Fix.AB)
    # =========================================================================

    async def sync_wg_egress_tunnels(self) -> SyncResult:
        """Sync WireGuard egress tunnels for userspace WG mode.

        Phase 11-Fix.AB: In userspace WG mode, WireGuard egress types
        (PIA, Custom, WARP WG) use rust-router's CreateWgTunnel command
        instead of kernel WireGuard interfaces.

        Returns:
            SyncResult with tunnel sync statistics
        """
        result = SyncResult(success=True)

        # Userspace WireGuard is now the only mode (kernel WG deprecated)
        async with self._sync_lock:
            try:
                db = self._get_db()

                # Phase 11-Fix.AC: DNS resolution cache for this sync cycle
                dns_cache: Dict[str, str] = {}

                # Collect WG-based egress from database
                wg_egress: Dict[str, Dict[str, Any]] = {}

                # PIA profiles
                for profile in db.get_pia_profiles(enabled_only=True):
                    tag = profile.get("name", "")
                    private_key = profile.get("private_key")
                    peer_public_key = profile.get("server_public_key")  # Fix: use server's public key
                    server_ip = profile.get("server_ip")  # Fix: use server IP, not peer_ip
                    server_port = profile.get("server_port", 1337)  # Fix: use actual port (PIA uses 1337)
                    local_ip = profile.get("peer_ip")  # peer_ip is the client's tunnel IP

                    if tag and private_key and peer_public_key and server_ip:
                        wg_egress[tag] = {
                            "private_key": private_key,
                            "peer_public_key": peer_public_key,
                            "endpoint": f"{server_ip}:{server_port}",
                            "local_ip": local_ip or "10.0.0.2/32",
                            "type": "pia",
                        }

                # Custom WG egress
                for egress in db.get_custom_egress_list(enabled_only=True):
                    tag = egress.get("tag", "")
                    private_key = egress.get("private_key")
                    peer_public_key = egress.get("public_key")
                    server = egress.get("server")
                    port = egress.get("port", 51820)
                    address = egress.get("address")

                    if tag and private_key and peer_public_key and server:
                        # Phase 11-Fix.AC: Resolve hostname to IP if needed
                        resolved_server = await _resolve_hostname_async(server, port, dns_cache)
                        if resolved_server is None:
                            logger.warning(
                                f"Skipping Custom WG egress {tag}: failed to resolve server hostname '{server}'"
                            )
                            continue

                        wg_egress[tag] = {
                            "private_key": private_key,
                            "peer_public_key": peer_public_key,
                            "endpoint": f"{resolved_server}:{port}",
                            "local_ip": address or "10.0.0.2/32",
                            "type": "custom",
                        }

                # WARP WireGuard egress (not MASQUE)
                # Phase 3-Fix.B: Read WireGuard config from database (preferred)
                # Fall back to wg.conf file for backward compatibility
                for egress in db.get_warp_egress_list(enabled_only=True):
                    tag = egress.get("tag", "")
                    if not tag:
                        continue

                    # Phase 3-Fix.B: Read WireGuard config from database fields first
                    private_key = egress.get("private_key")
                    peer_public_key = egress.get("peer_public_key")
                    endpoint = egress.get("endpoint")
                    local_ip = egress.get("local_ip")

                    # Check if database has all required fields
                    if not all([private_key, peer_public_key, endpoint, local_ip]):
                        # Fallback: try reading from wg.conf file (backward compatibility)
                        config_path = egress.get("config_path", "")
                        if config_path:
                            wg_config = _parse_wg_config_file(config_path)
                        else:
                            default_path = f"/etc/sing-box/warp/{tag}/wg.conf"
                            wg_config = _parse_wg_config_file(default_path)

                        if not wg_config:
                            logger.warning(f"Skipping WARP egress {tag}: no WireGuard config in database or file")
                            continue

                        private_key = wg_config["private_key"]
                        peer_public_key = wg_config["peer_public_key"]
                        endpoint = wg_config["endpoint"]
                        local_ip = wg_config["local_ip"]

                    # Resolve hostname in endpoint if needed
                    resolved_endpoint = endpoint
                    if ":" in endpoint:
                        last_colon = endpoint.rfind(":")
                        host_part = endpoint[:last_colon]
                        port_part = endpoint[last_colon + 1:]

                        # Handle IPv6 addresses in brackets [::1]:port
                        if host_part.startswith("[") and host_part.endswith("]"):
                            host_part = host_part[1:-1]

                        try:
                            port_num = int(port_part)
                        except ValueError:
                            logger.warning(f"Skipping WARP egress {tag}: invalid port in endpoint '{endpoint}'")
                            continue

                        resolved_host = await _resolve_hostname_async(host_part, port_num, dns_cache)
                        if resolved_host is None:
                            logger.warning(f"Skipping WARP egress {tag}: failed to resolve '{host_part}'")
                            continue

                        if ":" in resolved_host:  # IPv6 address
                            resolved_endpoint = f"[{resolved_host}]:{port_num}"
                        else:
                            resolved_endpoint = f"{resolved_host}:{port_num}"

                    wg_egress[tag] = {
                        "private_key": private_key,
                        "peer_public_key": peer_public_key,
                        "endpoint": resolved_endpoint,
                        "local_ip": local_ip,
                        "type": "warp",
                    }
                    logger.info(f"Found WARP WG egress {tag}: endpoint={resolved_endpoint}, local_ip={local_ip}")

                # Get current tunnels from rust-router
                # Note: list_wg_tunnels() returns List[WgTunnelInfo], not IpcResponse
                async with await self._get_client() as client:
                    current_tunnels = await client.list_wg_tunnels()
                    current_tags = {t.tag for t in current_tunnels if t.tag}

                    # Create missing tunnels
                    for tag, config in wg_egress.items():
                        if tag in current_tags:
                            logger.debug(f"Tunnel {tag} already exists, skipping")
                            continue

                        logger.info(f"Creating userspace WG tunnel: {tag} ({config['type']})")
                        resp = await client.create_wg_tunnel(
                            tag=tag,
                            private_key=config["private_key"],
                            peer_public_key=config["peer_public_key"],
                            endpoint=config["endpoint"],
                            local_ip=config["local_ip"],
                        )

                        if resp.success:
                            result.wg_tunnels_synced += 1
                            logger.info(f"Created userspace WG tunnel: {tag}")
                        else:
                            error_msg = f"Failed to create tunnel {tag}: {resp.error}"
                            result.errors.append(error_msg)
                            logger.error(error_msg)

                    # Remove stale tunnels (in DB but disabled, or not in DB)
                    # Skip peer tunnels (peer-*) as they are managed separately by PeerManager
                    db_enabled_tags = set(wg_egress.keys())
                    for tag in current_tags:
                        # Skip peer tunnels - they are managed by ConnectPeer/DisconnectPeer IPC
                        if tag.startswith("peer-"):
                            logger.debug(f"Skipping peer tunnel in cleanup: {tag}")
                            continue
                        if tag not in db_enabled_tags:
                            logger.info(f"Removing stale WG tunnel: {tag}")
                            resp = await client.remove_wg_tunnel(tag)
                            if resp.success:
                                result.wg_tunnels_removed += 1
                            else:
                                logger.warning(f"Failed to remove stale tunnel {tag}: {resp.error}")

            except Exception as e:
                result.success = False
                error_msg = f"WG tunnel sync failed: {e}"
                result.errors.append(error_msg)
                logger.error(error_msg)

        return result

    # =========================================================================
    # WireGuard Ingress Peer Sync (Phase 11-Fix.AD)
    # =========================================================================

    async def sync_wg_ingress_peers(self) -> SyncResult:
        """Sync WireGuard ingress client peers from database to rust-router.

        Phase 11-Fix.AD: This method syncs WireGuard client peers (from the
        wireguard_peers table) to rust-router's ingress WireGuard interface.

        This method:
        1. Gets all enabled WireGuard peers from database (db.get_wireguard_peers())
        2. Gets current ingress peers from rust-router (client.list_ingress_peers())
        3. Adds missing peers, removes stale peers

        Returns:
            SyncResult with wg_ingress_peers_synced count and errors
        """
        result = SyncResult(success=True)

        async with self._sync_lock:
            try:
                if not await self.is_available():
                    result.success = False
                    result.errors.append("rust-router is not available")
                    return result

                db = self._get_db()

                # Get enabled WireGuard peers from database
                db_peers = db.get_wireguard_peers(enabled_only=True)
                logger.debug(f"Found {len(db_peers)} enabled WG ingress peers in database")

                # Build a map of public_key -> peer info for database peers
                db_peers_by_pubkey: Dict[str, Dict[str, Any]] = {}
                for peer in db_peers:
                    pubkey = peer.get("public_key")
                    if pubkey:
                        db_peers_by_pubkey[pubkey] = peer

                async with await self._get_client() as client:
                    # Get current ingress peers from rust-router
                    current_peers = await client.list_ingress_peers()
                    current_pubkeys = {p.get("public_key") for p in current_peers if p.get("public_key")}

                    logger.debug(f"Found {len(current_pubkeys)} ingress peers in rust-router")

                    added = 0
                    removed = 0

                    # Add missing peers
                    for pubkey, peer in db_peers_by_pubkey.items():
                        if pubkey in current_pubkeys:
                            logger.debug(f"WG ingress peer {peer.get('name', pubkey[:8])} already exists")
                            continue

                        # Add the peer to rust-router
                        name = peer.get("name", "")
                        allowed_ips = peer.get("allowed_ips", "")
                        preshared_key = peer.get("preshared_key")

                        logger.info(f"Adding WG ingress peer: {name} ({pubkey[:8]}...) allowed_ips={allowed_ips}")

                        resp = await client.add_ingress_peer(
                            public_key=pubkey,
                            allowed_ips=allowed_ips,
                            name=name,
                            preshared_key=preshared_key,
                        )

                        if resp.success:
                            added += 1
                            logger.info(f"Added WG ingress peer: {name}")
                        else:
                            error_msg = f"Failed to add WG ingress peer {name}: {resp.error}"
                            result.errors.append(error_msg)
                            logger.error(error_msg)

                    # Remove stale peers (in rust-router but not in database or disabled)
                    for peer in current_peers:
                        pubkey = peer.get("public_key")
                        if not pubkey:
                            continue

                        if pubkey not in db_peers_by_pubkey:
                            peer_name = peer.get("name", pubkey[:8])
                            logger.info(f"Removing stale WG ingress peer: {peer_name}")

                            resp = await client.remove_ingress_peer(pubkey)
                            if resp.success:
                                removed += 1
                            else:
                                logger.warning(f"Failed to remove stale peer {peer_name}: {resp.error}")

                    result.wg_ingress_peers_synced = added

                if result.errors:
                    result.success = False

                logger.info(
                    f"WG ingress peer sync complete: added={added}, removed={removed}, "
                    f"errors={len(result.errors)}"
                )

            except Exception as e:
                result.success = False
                error_msg = f"WG ingress peer sync failed: {e}"
                result.errors.append(error_msg)
                logger.error(error_msg)

        return result

    # =========================================================================
    # DNS Blocklist Sync
    # =========================================================================

    async def sync_dns_blocklist(self) -> SyncResult:
        """Sync DNS adblock rules to rust-router.

        Phase 3-Fix: This method triggers rust-router to reload the DNS blocklist
        from /etc/sing-box/rulesets/__adblock_combined__.json.

        The blocklist file is generated by api_server.py from the adblock_rulesets
        table in the database. This method simply tells rust-router to reload it.

        Returns:
            SyncResult with dns_blocklist_synced flag and errors
        """
        result = SyncResult(success=True)

        try:
            if not await self.is_available():
                result.success = False
                result.errors.append("rust-router is not available")
                return result

            async with await self._get_client() as client:
                resp = await client.reload_dns_blocklist()

                if resp.success:
                    result.dns_blocklist_synced = True
                    logger.info(f"DNS blocklist synced: {resp.message}")
                else:
                    result.success = False
                    error_msg = f"Failed to sync DNS blocklist: {resp.error or resp.message}"
                    result.errors.append(error_msg)
                    logger.error(error_msg)

        except Exception as e:
            result.success = False
            error_msg = f"DNS blocklist sync failed: {e}"
            result.errors.append(error_msg)
            logger.error(error_msg)

        return result

    # =========================================================================
    # Routing Rules Sync
    # =========================================================================

    async def sync_routing_rules(self) -> SyncResult:
        """Sync routing rules from database to rust-router.

        This method:
        1. Gets all enabled routing rules from database
        2. Validates outbounds and skips invalid rules (Phase 11-Fix)
        3. Converts them to RuleConfig format
        4. Sends UpdateRouting command to rust-router

        Returns:
            SyncResult with statistics and errors
        """
        result = SyncResult(success=True)

        async with self._sync_lock:
            try:
                db = self._get_db()
                rules = db.get_routing_rules(enabled_only=True)

                # Get default outbound from settings or use "direct"
                # Phase 11-Fix.Z: 使用正确的方法名 get_setting() (不是 get_settings())
                default_outbound = db.get_setting("default_outbound", "direct") or "direct"

                # Phase 11-Fix: Get valid outbounds from rust-router to pre-validate rules
                # This prevents the entire sync from failing due to one invalid rule
                valid_outbounds: Set[str] = {"block", "adblock", "direct"}
                async with await self._get_client() as client:
                    # Get regular outbounds
                    try:
                        outbounds = await client.list_outbounds()
                        valid_outbounds.update(o.tag for o in outbounds)
                    except Exception as e:
                        logger.warning(f"Failed to get outbounds list: {e}")

                    # Get WG tunnels
                    try:
                        tunnels = await client.list_wg_tunnels()
                        valid_outbounds.update(t.tag for t in tunnels)
                    except Exception as e:
                        logger.warning(f"Failed to get WG tunnels list: {e}")

                    # Get ECMP groups
                    try:
                        groups = await client.list_ecmp_groups()
                        valid_outbounds.update(g.tag for g in groups)
                    except Exception as e:
                        logger.warning(f"Failed to get ECMP groups list: {e}")

                    # Get active chains
                    try:
                        chains = await client.list_chains()
                        # Only add ACTIVE chains as valid outbounds
                        valid_outbounds.update(
                            c.tag for c in chains if c.chain_state == "active"
                        )
                    except Exception as e:
                        logger.warning(f"Failed to get chains list: {e}")

                    # Also allow WireGuard-prefixed tags (may be added later)
                    # These are checked by rust-router's is_valid_outbound_tag

                # Convert to RuleConfig list, skipping invalid outbounds
                rule_configs: List[RuleConfig] = []
                skipped_rules: List[str] = []

                for rule in rules:
                    rule_type = rule.get("rule_type", "")
                    target = rule.get("target", "")
                    outbound = rule.get("outbound", "direct")
                    priority = rule.get("priority", 0)

                    # Skip invalid rules
                    if not rule_type or not target:
                        continue

                    # Phase 11-Fix: Skip rules with invalid outbounds
                    # Allow WireGuard-prefixed tags as they may be added later
                    is_wg_prefixed = (
                        outbound.startswith("wg-") or
                        outbound.startswith("pia-") or
                        outbound.startswith("peer-")
                    )
                    if outbound not in valid_outbounds and not is_wg_prefixed:
                        skipped_rules.append(f"{rule_type}:{target}->{outbound}")
                        logger.warning(
                            f"Skipping rule with invalid outbound: "
                            f"{rule_type}:{target} -> {outbound}"
                        )
                        continue

                    # Phase 11-Fix.AF: Use domain_suffix for domain rules to match all subdomains
                    # e.g., "example.com" matches "www.example.com", "api.example.com", etc.
                    if rule_type == "domain":
                        rule_type = "domain_suffix"
                    # Phase 11-Fix.AG: Map 'ip' to 'ip_cidr' for rust-router compatibility
                    elif rule_type == "ip":
                        rule_type = "ip_cidr"

                    rule_configs.append(RuleConfig(
                        rule_type=rule_type,
                        target=target,
                        outbound=outbound,
                        priority=priority,
                        enabled=True,
                    ))

                # Log skipped rules summary
                if skipped_rules:
                    result.errors.append(
                        f"Skipped {len(skipped_rules)} rules with invalid outbounds: "
                        f"{', '.join(skipped_rules[:5])}"
                        + (f" and {len(skipped_rules) - 5} more" if len(skipped_rules) > 5 else "")
                    )

                # Send valid rules to rust-router
                async with await self._get_client() as client:
                    update_result = await client.update_routing(rule_configs, default_outbound)

                    if update_result.success:
                        result.rules_synced = update_result.rule_count
                        logger.info(
                            f"Routing rules synced: {result.rules_synced} rules "
                            f"(skipped {len(skipped_rules)} invalid), "
                            f"version={update_result.version}, default={update_result.default_outbound}"
                        )
                    else:
                        result.success = False
                        result.errors.append("Failed to update routing rules")

            except Exception as e:
                result.success = False
                result.errors.append(f"Routing sync failed: {e}")
                logger.error(f"Routing rules sync failed: {e}")

        return result

    # =========================================================================
    # Peer Node Sync (Phase 6)
    # =========================================================================

    async def sync_peers(self) -> SyncResult:
        """Sync peer nodes from database to rust-router.

        This method:
        1. Gets all peer nodes from database
        2. Gets current peers from rust-router
        3. Adds missing peers, connects peers that should be connected

        Returns:
            SyncResult with statistics and errors
        """
        result = SyncResult(success=True)

        async with self._sync_lock:
            try:
                if not await self.is_available():
                    result.success = False
                    result.errors.append("rust-router is not available")
                    return result

                db = self._get_db()
                peers = db.get_peer_nodes(enabled_only=False)

                async with await self._get_client() as client:
                    # Get current peers from rust-router
                    current_peers = await client.list_peers()
                    current_tags = {p.tag for p in current_peers}

                    # Track synced peers
                    synced = 0

                    # Userspace WireGuard peer repair (kernel WG deprecated)
                    if peers:
                        local_tag = self._get_local_tag_for_pairing()
                        missing = [
                            p for p in peers
                            if p.get("enabled", False)
                            and p.get("tunnel_type", "wireguard") == "wireguard"
                            and p.get("tag") not in current_tags
                            and local_tag < (p.get("tag") or "")
                        ]
                        for peer in missing:
                            tag = peer.get("tag")
                            if not tag or tag in self._peer_repair_attempted_tags:
                                continue
                            repaired = await self._repair_userspace_peer_via_api(peer)
                            if repaired:
                                self._peer_repair_attempted_tags.add(tag)
                                logger.info(f"Repaired userspace peer via pairing: {tag}")
                                synced += 1

                        if missing:
                            current_peers = await client.list_peers()
                            current_tags = {p.tag for p in current_peers}

                    for peer in peers:
                        tag = peer.get("tag", "")
                        if not tag:
                            continue

                        enabled = peer.get("enabled", False)
                        tunnel_status = peer.get("tunnel_status", "disconnected")
                        auto_connect = peer.get("auto_connect", True)

                        # Skip if peer already exists and no action needed
                        if tag in current_tags:
                            # Check if we need to connect
                            if enabled and auto_connect and tunnel_status == "disconnected":
                                connect_response = await client.connect_peer(tag)
                                if connect_response.success:
                                    logger.debug(f"Connected peer {tag}")
                            synced += 1
                            continue

                        # Peer doesn't exist in rust-router - add it from database
                        # This handles restart recovery when peers were created via pairing
                        if not enabled:
                            logger.debug(f"Skipping disabled peer {tag}")
                            continue

                        tunnel_type = (peer.get("tunnel_type") or "wireguard").lower()
                        endpoint = peer.get("endpoint", "")
                        if not endpoint:
                            logger.warning(f"Peer {tag} missing endpoint, skipping")
                            continue

                        logger.info(f"Adding peer {tag} from database to rust-router")

                        # Build add_peer call with all available fields
                        # Note: wg_peer_public_key is the remote peer's public key
                        # wg_public_key is our own public key (derived from wg_private_key)
                        add_response = await client.add_peer(
                            tag=tag,
                            endpoint=endpoint,
                            tunnel_type=tunnel_type,
                            description=peer.get("description", ""),
                            api_port=peer.get("api_port") or 36000,
                            wg_public_key=peer.get("wg_peer_public_key"),  # Use peer's public key!
                            wg_local_private_key=peer.get("wg_private_key"),  # DB uses wg_private_key
                            tunnel_local_ip=peer.get("tunnel_local_ip"),
                            tunnel_remote_ip=peer.get("tunnel_remote_ip"),
                            tunnel_port=peer.get("tunnel_port"),
                            persistent_keepalive=peer.get("persistent_keepalive"),
                            xray_uuid=peer.get("xray_uuid"),
                            xray_server_name=peer.get("xray_server_name"),
                            xray_public_key=peer.get("xray_public_key"),
                            xray_short_id=peer.get("xray_short_id"),
                            xray_local_socks_port=peer.get("xray_local_socks_port"),
                        )

                        if not add_response.success:
                            logger.warning(f"Failed to add peer {tag}: {add_response.error}")
                            continue

                        logger.info(f"Added peer {tag} to rust-router")
                        synced += 1

                        # Connect the peer if auto_connect is enabled
                        if auto_connect:
                            connect_response = await client.connect_peer(tag)
                            if connect_response.success:
                                logger.info(f"Connected peer {tag}")
                            else:
                                logger.warning(f"Failed to connect peer {tag}: {connect_response.error}")

                    result.peers_synced = synced

                logger.info(f"Peer sync complete: peers_synced={result.peers_synced}")

            except Exception as e:
                result.success = False
                result.errors.append(f"Peer sync failed: {e}")
                logger.error(f"Peer sync failed: {e}")

        return result

    async def notify_peer_added(self, peer_tag: str) -> bool:
        """Notify rust-router that a peer was added.

        Note: Peer addition is handled via the pairing flow in rust-router.
        This method is primarily for logging and future extensions.

        Args:
            peer_tag: The peer tag that was added

        Returns:
            True if notification was processed (rust-router available)
        """
        if not await self.is_available():
            logger.debug(f"Skipping peer added notification: rust-router not available")
            return False

        # Peers are created via pairing flow, not via notification
        # This is a no-op but kept for API consistency
        logger.debug(f"Peer {peer_tag} added (pairing handled by rust-router)")
        return True

    async def notify_peer_removed(self, peer_tag: str) -> bool:
        """Notify rust-router that a peer was removed.

        Args:
            peer_tag: The peer tag to remove

        Returns:
            True if notification was successful
        """
        if not await self.is_available():
            logger.debug(f"Skipping peer removed notification: rust-router not available")
            return False

        try:
            async with await self._get_client() as client:
                response = await client.remove_peer(peer_tag)
                if not response.success:
                    logger.warning(f"Failed to remove peer {peer_tag}: {response.error}")
                return response.success

        except Exception as e:
            logger.error(f"Failed to notify peer removed: {e}")
            return False

    async def notify_peer_updated(self, peer_tag: str) -> bool:
        """Notify rust-router that a peer configuration was updated.

        Args:
            peer_tag: The peer tag that was updated

        Returns:
            True if notification was successful
        """
        if not await self.is_available():
            logger.debug(f"Skipping peer updated notification: rust-router not available")
            return False

        try:
            db = self._get_db()
            peer = db.get_peer_node(peer_tag)
            if not peer:
                logger.warning(f"Peer {peer_tag} not found in database")
                return False

            async with await self._get_client() as client:
                enabled = peer.get("enabled", False)
                auto_connect = peer.get("auto_connect", True)
                tunnel_status = peer.get("tunnel_status", "disconnected")

                # If peer should be connected but isn't, connect
                if enabled and auto_connect and tunnel_status == "disconnected":
                    connect_response = await client.connect_peer(peer_tag)
                    if not connect_response.success:
                        logger.warning(f"Failed to connect peer {peer_tag}: {connect_response.error}")
                        return False
                # If peer should be disconnected, disconnect
                elif not enabled or not auto_connect:
                    # Check current status from rust-router
                    status_response = await client.get_peer_status(peer_tag)
                    if status_response.success and status_response.data:
                        current_status = status_response.data.get("tunnel_status", "disconnected")
                        if current_status == "connected":
                            disconnect_response = await client.disconnect_peer(peer_tag)
                            if not disconnect_response.success:
                                logger.warning(f"Failed to disconnect peer {peer_tag}: {disconnect_response.error}")
                                return False

                return True

        except Exception as e:
            logger.error(f"Failed to notify peer updated: {e}")
            return False

    # =========================================================================
    # ECMP Group Sync (Phase 6)
    # =========================================================================

    async def sync_ecmp_groups(self) -> SyncResult:
        """Sync ECMP groups from database to rust-router.

        This method:
        1. Gets all ECMP groups from database (db.get_outbound_groups())
        2. Gets current groups from rust-router
        3. Creates missing groups, updates existing groups

        Returns:
            SyncResult with statistics and errors
        """
        result = SyncResult(success=True)

        async with self._sync_lock:
            try:
                if not await self.is_available():
                    result.success = False
                    result.errors.append("rust-router is not available")
                    return result

                db = self._get_db()
                groups = db.get_outbound_groups(enabled_only=False)

                async with await self._get_client() as client:
                    # Get current groups from rust-router
                    current_groups = await client.list_ecmp_groups()
                    current_tags = {g.tag for g in current_groups}

                    synced = 0

                    for group in groups:
                        tag = group.get("tag", "")
                        if not tag:
                            continue

                        enabled = group.get("enabled", False)
                        if not enabled:
                            # If group is disabled and exists, remove it
                            if tag in current_tags:
                                await client.remove_ecmp_group(tag)
                            continue

                        # Prepare group configuration
                        algorithm = group.get("algorithm", "five_tuple_hash")
                        description = group.get("description", "")
                        routing_table = group.get("routing_table")

                        # Get members from the group dict (already parsed JSON)
                        members_list = group.get("members", [])
                        weights_dict = group.get("weights") or {}

                        # Build member dicts
                        # Phase 6-Fix.AI: Use 'outbound' key to match Rust EcmpMemberConfig struct
                        # Weights is a dict: {"member-tag": weight, ...}
                        members = []
                        for member_tag in members_list:
                            weight = weights_dict.get(member_tag, 1) if isinstance(weights_dict, dict) else 1
                            members.append({"outbound": member_tag, "weight": weight})

                        if tag in current_tags:
                            # Update existing group's members
                            update_response = await client.update_ecmp_group_members(tag, members)
                            if not update_response.success:
                                result.errors.append(f"Failed to update ECMP group {tag}: {update_response.error}")
                        else:
                            # Create new group
                            create_response = await client.create_ecmp_group(
                                tag=tag,
                                members=members,
                                algorithm=algorithm,
                                description=description,
                                routing_table=routing_table,
                                health_check=True,
                            )
                            if not create_response.success:
                                result.errors.append(f"Failed to create ECMP group {tag}: {create_response.error}")
                            else:
                                synced += 1

                    # Remove groups that exist in rust-router but not in database
                    db_tags = {g.get("tag", "") for g in groups if g.get("enabled", False)}
                    for current_tag in current_tags:
                        if current_tag not in db_tags:
                            await client.remove_ecmp_group(current_tag)

                    result.ecmp_groups_synced = synced

                if result.errors:
                    result.success = False

                logger.info(f"ECMP group sync complete: groups_synced={result.ecmp_groups_synced}")

            except Exception as e:
                result.success = False
                result.errors.append(f"ECMP group sync failed: {e}")
                logger.error(f"ECMP group sync failed: {e}")

        return result

    async def notify_ecmp_group_changed(self, group_tag: str, action: str = "updated") -> bool:
        """Notify rust-router that an ECMP group was changed.

        Args:
            group_tag: The ECMP group tag
            action: One of "added", "removed", "updated"

        Returns:
            True if notification was successful
        """
        if not await self.is_available():
            logger.debug(f"Skipping ECMP group {action} notification: rust-router not available")
            return False

        try:
            async with await self._get_client() as client:
                if action == "removed":
                    response = await client.remove_ecmp_group(group_tag)
                    return response.success

                # For added/updated, get group from database and sync
                db = self._get_db()
                group = db.get_outbound_group(group_tag)
                if not group:
                    logger.warning(f"ECMP group {group_tag} not found in database")
                    return False

                enabled = group.get("enabled", False)
                if not enabled:
                    # Remove disabled group from rust-router
                    response = await client.remove_ecmp_group(group_tag)
                    return response.success

                # Prepare group configuration
                algorithm = group.get("algorithm", "five_tuple_hash")
                description = group.get("description", "")
                routing_table = group.get("routing_table")
                members_list = group.get("members", [])
                weights_list = group.get("weights") or []

                members = []
                for i, member_tag in enumerate(members_list):
                    weight = weights_list[i] if i < len(weights_list) else 1
                    members.append({"tag": member_tag, "weight": weight})

                # Check if group exists
                current_groups = await client.list_ecmp_groups()
                exists = any(g.tag == group_tag for g in current_groups)

                if action == "added" or not exists:
                    response = await client.create_ecmp_group(
                        tag=group_tag,
                        members=members,
                        algorithm=algorithm,
                        description=description,
                        routing_table=routing_table,
                        health_check=True,
                    )
                else:
                    # Update members
                    response = await client.update_ecmp_group_members(group_tag, members)

                if not response.success:
                    logger.warning(f"Failed to {action} ECMP group {group_tag}: {response.error}")
                return response.success

        except Exception as e:
            logger.error(f"Failed to notify ECMP group {action}: {e}")
            return False

    # =========================================================================
    # Chain Sync (Phase 6)
    # =========================================================================

    async def sync_chains(self) -> SyncResult:
        """Sync multi-hop chains from database to rust-router.

        This method:
        1. Gets all chains from database (db.get_node_chains())
        2. Gets current chains from rust-router
        3. Creates chains in rust-router
        4. Activates chains that should be active

        Returns:
            SyncResult with statistics and errors
        """
        result = SyncResult(success=True)

        async with self._sync_lock:
            try:
                if not await self.is_available():
                    result.success = False
                    result.errors.append("rust-router is not available")
                    return result

                db = self._get_db()
                chains = db.get_node_chains(enabled_only=False)

                async with await self._get_client() as client:
                    # Get current chains from rust-router
                    current_chains = await client.list_chains()
                    current_tags = {c.tag for c in current_chains}

                    synced = 0

                    for chain in chains:
                        tag = chain.get("tag", "")
                        if not tag:
                            continue

                        enabled = chain.get("enabled", False)
                        chain_state = chain.get("chain_state", "inactive")
                        chain_config = self._build_chain_config(chain)
                        if not chain_config or not chain_config.get("exit_egress"):
                            result.errors.append(f"Invalid chain config for {tag}")
                            continue

                        if not enabled:
                            # If chain is disabled and exists, delete it
                            if tag in current_tags:
                                # First deactivate if active
                                for cc in current_chains:
                                    if cc.tag == tag and cc.chain_state == "active":
                                        await client.deactivate_chain(tag)
                                        break
                                await client.delete_chain(tag)
                            continue

                        if tag not in current_tags:
                            # Create new chain
                            create_response = await client.create_chain(
                                tag=tag,
                                config=chain_config,
                            )
                            if not create_response.success:
                                result.errors.append(f"Failed to create chain {tag}: {create_response.error}")
                                continue
                            synced += 1

                        # Activate chain if it should be active
                        if chain_state == "active":
                            # Check current state in rust-router
                            # Note: Rust ChainStatus uses "state", not "chain_state"
                            status_response = await client.get_chain_status(tag)
                            if status_response.success and status_response.data:
                                rr_state = status_response.data.get("state", status_response.data.get("chain_state", "inactive"))
                                if rr_state != "active":
                                    activate_response = await client.activate_chain(tag)
                                    if not activate_response.success:
                                        result.errors.append(f"Failed to activate chain {tag}: {activate_response.error}")

                    # Remove chains that exist in rust-router but not in database
                    db_tags = {c.get("tag", "") for c in chains if c.get("enabled", False)}
                    for current_tag in current_tags:
                        if current_tag not in db_tags:
                            # Deactivate before deleting
                            for cc in current_chains:
                                if cc.tag == current_tag and cc.chain_state == "active":
                                    await client.deactivate_chain(current_tag)
                                    break
                            await client.delete_chain(current_tag)

                    result.chains_synced = synced

                if result.errors:
                    result.success = False

                logger.info(f"Chain sync complete: chains_synced={result.chains_synced}")

            except Exception as e:
                result.success = False
                result.errors.append(f"Chain sync failed: {e}")
                logger.error(f"Chain sync failed: {e}")

        return result

    async def notify_chain_changed(self, chain_tag: str, action: str = "updated") -> bool:
        """Notify rust-router that a chain was changed.

        Args:
            chain_tag: The chain tag
            action: One of "created", "deleted", "activated", "deactivated", "updated"

        Returns:
            True if notification was successful
        """
        if not await self.is_available():
            logger.debug(f"Skipping chain {action} notification: rust-router not available")
            return False

        try:
            async with await self._get_client() as client:
                if action == "deleted":
                    # Deactivate first if needed
                    status_response = await client.get_chain_status(chain_tag)
                    if status_response.success and status_response.data:
                        if status_response.data.get("chain_state") == "active":
                            await client.deactivate_chain(chain_tag)
                    response = await client.delete_chain(chain_tag)
                    return response.success

                if action == "activated":
                    response = await client.activate_chain(chain_tag)
                    return response.success

                if action == "deactivated":
                    response = await client.deactivate_chain(chain_tag)
                    return response.success

                # For created/updated, get chain from database
                db = self._get_db()
                chain = db.get_node_chain(chain_tag)
                if not chain:
                    logger.warning(f"Chain {chain_tag} not found in database")
                    return False

                enabled = chain.get("enabled", False)
                if not enabled:
                    # Remove disabled chain from rust-router
                    await client.deactivate_chain(chain_tag)
                    response = await client.delete_chain(chain_tag)
                    return response.success

                chain_config = self._build_chain_config(chain)
                if not chain_config or not chain_config.get("exit_egress"):
                    logger.warning(f"Invalid chain config for {chain_tag}")
                    return False
                chain_state = chain.get("chain_state", "inactive")

                # Check if chain exists in rust-router
                current_chains = await client.list_chains()
                exists = any(c.tag == chain_tag for c in current_chains)

                if action == "created" or not exists:
                    response = await client.create_chain(
                        tag=chain_tag,
                        config=chain_config,
                    )
                    if not response.success:
                        logger.warning(f"Failed to create chain {chain_tag}: {response.error}")
                        return False

                    # Activate if should be active
                    if chain_state == "active":
                        activate_response = await client.activate_chain(chain_tag)
                        return activate_response.success
                    return True
                else:
                    # Update chain (must be inactive to update)
                    for cc in current_chains:
                        if cc.tag == chain_tag and cc.chain_state == "active":
                            await client.deactivate_chain(chain_tag)
                            break

                    response = await client.update_chain(
                        tag=chain_tag,
                        hops=chain_config["hops"],
                        exit_egress=chain_config["exit_egress"],
                        description=chain_config["description"],
                        allow_transitive=chain_config["allow_transitive"],
                    )
                    if not response.success:
                        logger.warning(f"Failed to update chain {chain_tag}: {response.error}")
                        return False

                    # Reactivate if should be active
                    if chain_state == "active":
                        activate_response = await client.activate_chain(chain_tag)
                        return activate_response.success
                    return True

        except Exception as e:
            logger.error(f"Failed to notify chain {action}: {e}")
            return False

    # =========================================================================
    # Full Sync
    # =========================================================================

    async def full_sync(self) -> SyncResult:
        """Full sync: outbounds + rules + peers + ecmp groups + chains + wg ingress peers.

        This should be called on startup to ensure rust-router
        is in sync with the database.

        Returns:
            Combined SyncResult from all sync operations
        """
        result = SyncResult(success=True)

        # Check if rust-router is available
        if not await self.is_available():
            result.success = False
            result.errors.append("rust-router is not available")
            logger.warning("Skipping full sync: rust-router not available")
            return result

        # Sync outbounds first
        outbound_result = await self.sync_outbounds()
        result.outbounds_added = outbound_result.outbounds_added
        result.outbounds_removed = outbound_result.outbounds_removed
        result.errors.extend(outbound_result.errors)

        # Sync userspace WG tunnels (after outbounds sync)
        # Kernel WG mode has been deprecated, always use userspace
        wg_tunnel_result = await self.sync_wg_egress_tunnels()
        result.wg_tunnels_synced = wg_tunnel_result.wg_tunnels_synced
        result.wg_tunnels_removed = wg_tunnel_result.wg_tunnels_removed
        result.errors.extend(wg_tunnel_result.errors)

        # Sync ECMP groups BEFORE routing rules (Phase 6)
        # Default outbound may be an ECMP group tag, so it must exist first
        ecmp_result = await self.sync_ecmp_groups()
        result.ecmp_groups_synced = ecmp_result.ecmp_groups_synced
        result.errors.extend(ecmp_result.errors)

        # Sync peers (Phase 6) - before chains since chains may reference peer tunnels
        peers_result = await self.sync_peers()
        result.peers_synced = peers_result.peers_synced
        result.errors.extend(peers_result.errors)

        # Sync chains BEFORE routing rules (Phase 11-Fix)
        # Routing rules may reference chain tags as outbounds, so chains must exist first
        chains_result = await self.sync_chains()
        result.chains_synced = chains_result.chains_synced
        result.errors.extend(chains_result.errors)

        # Then sync routing rules (after ECMP groups and chains so outbounds exist)
        rules_result = await self.sync_routing_rules()
        result.rules_synced = rules_result.rules_synced
        result.errors.extend(rules_result.errors)

        # Phase 11-Fix.AD: Sync WireGuard ingress client peers
        wg_ingress_result = await self.sync_wg_ingress_peers()
        result.wg_ingress_peers_synced = wg_ingress_result.wg_ingress_peers_synced
        result.errors.extend(wg_ingress_result.errors)

        # Phase 3-Fix: Sync DNS adblock rules
        dns_blocklist_result = await self.sync_dns_blocklist()
        result.dns_blocklist_synced = dns_blocklist_result.dns_blocklist_synced
        result.errors.extend(dns_blocklist_result.errors)

        # Overall success (includes wg_tunnel_result for userspace WG mode)
        result.success = (
            outbound_result.success and
            wg_tunnel_result.success and
            rules_result.success and
            peers_result.success and
            ecmp_result.success and
            chains_result.success and
            wg_ingress_result.success and
            dns_blocklist_result.success
        )

        logger.info(
            f"Full sync complete: outbounds_added={result.outbounds_added}, "
            f"outbounds_removed={result.outbounds_removed}, "
            f"wg_tunnels_synced={result.wg_tunnels_synced}, "
            f"wg_tunnels_removed={result.wg_tunnels_removed}, "
            f"rules_synced={result.rules_synced}, "
            f"peers_synced={result.peers_synced}, "
            f"ecmp_groups_synced={result.ecmp_groups_synced}, "
            f"chains_synced={result.chains_synced}, "
            f"wg_ingress_peers_synced={result.wg_ingress_peers_synced}, "
            f"dns_blocklist_synced={result.dns_blocklist_synced}, "
            f"success={result.success}"
        )

        return result

    # =========================================================================
    # Incremental Sync (Egress Change Notifications)
    # =========================================================================

    async def notify_egress_added(self, tag: str, egress_type: str) -> bool:
        """Notify rust-router that an egress was added.

        Args:
            tag: Egress tag
            egress_type: Egress type (pia, custom, warp, v2ray, direct, openvpn)

        Returns:
            True if notification was successful
        """
        if not await self.is_available():
            logger.debug(f"Skipping egress added notification: rust-router not available")
            return False

        try:
            async with await self._get_client() as client:
                # First, add the outbound to rust-router
                config = self._get_egress_config(tag, egress_type)
                if config:
                    add_result = await self._add_outbound(client, tag, config)
                    if not add_result.success:
                        logger.warning(f"Failed to add outbound {tag}: {add_result.error}")

                # Then notify about the change
                response = await client.notify_egress_change("added", tag, egress_type)
                return response.success

        except Exception as e:
            logger.error(f"Failed to notify egress added: {e}")
            return False

    async def notify_egress_removed(self, tag: str, egress_type: str) -> bool:
        """Notify rust-router that an egress was removed.

        Args:
            tag: Egress tag
            egress_type: Egress type

        Returns:
            True if notification was successful
        """
        if not await self.is_available():
            logger.debug(f"Skipping egress removed notification: rust-router not available")
            return False

        try:
            async with await self._get_client() as client:
                # Drain the outbound first for graceful removal
                drain_result = await client.drain_outbound(tag, timeout_secs=5)
                if not drain_result.success:
                    # Try direct removal if drain fails
                    await client.remove_outbound(tag)

                # Notify about the change
                response = await client.notify_egress_change("removed", tag, egress_type)
                return response.success

        except Exception as e:
            logger.error(f"Failed to notify egress removed: {e}")
            return False

    async def notify_egress_updated(self, tag: str, egress_type: str) -> bool:
        """Notify rust-router that an egress was updated.

        This removes and re-adds the outbound with new configuration.

        Args:
            tag: Egress tag
            egress_type: Egress type

        Returns:
            True if notification was successful
        """
        if not await self.is_available():
            logger.debug(f"Skipping egress updated notification: rust-router not available")
            return False

        try:
            async with await self._get_client() as client:
                # Remove old outbound
                await client.drain_outbound(tag, timeout_secs=5)

                # Add new outbound with updated config
                config = self._get_egress_config(tag, egress_type)
                if config:
                    add_result = await self._add_outbound(client, tag, config)
                    if not add_result.success:
                        logger.warning(f"Failed to re-add outbound {tag}: {add_result.error}")

                # Notify about the change
                response = await client.notify_egress_change("updated", tag, egress_type)
                return response.success

        except Exception as e:
            logger.error(f"Failed to notify egress updated: {e}")
            return False

    def _get_egress_config(self, tag: str, egress_type: str) -> Optional[Dict[str, Any]]:
        """Get egress configuration from database.

        Args:
            tag: Egress tag
            egress_type: Egress type

        Returns:
            Configuration dict or None if not found
        """
        db = self._get_db()

        if egress_type == "pia":
            profile = db.get_pia_profile_by_name(tag)
            if profile:
                interface = _get_egress_interface_name(tag, is_pia=True)
                return {"type": "wireguard", "interface": interface, "egress_type": "pia"}

        elif egress_type == "custom":
            egress = db.get_custom_egress(tag)
            if egress:
                interface = _get_egress_interface_name(tag, is_pia=False)
                return {"type": "wireguard", "interface": interface, "egress_type": "custom"}

        elif egress_type == "warp":
            egress = db.get_warp_egress(tag)
            if egress:
                protocol = egress.get("protocol", "wireguard")
                if protocol == "wireguard":
                    interface = _get_egress_interface_name(tag, egress_type="warp")
                    return {"type": "wireguard", "interface": interface, "egress_type": "warp"}
                else:
                    socks_port = egress.get("socks_port")
                    if socks_port:
                        return {
                            "type": "socks5",
                            "server_addr": f"127.0.0.1:{socks_port}",
                            "egress_type": "warp-masque",
                        }

        elif egress_type == "v2ray":
            egress = db.get_v2ray_egress(tag)
            if egress:
                socks_port = egress.get("socks_port")
                if socks_port:
                    return {
                        "type": "socks5",
                        "server_addr": f"127.0.0.1:{socks_port}",
                        "egress_type": "v2ray",
                    }

        elif egress_type == "direct":
            egress = db.get_direct_egress(tag)
            if egress:
                return {
                    "type": "direct",
                    "bind_interface": egress.get("bind_interface"),
                    "bind_address": egress.get("bind_address"),
                    "egress_type": "direct",
                }

        elif egress_type == "openvpn":
            egress = db.get_openvpn_egress(tag)
            if egress:
                tun_device = egress.get("tun_device")
                if tun_device:
                    return {
                        "type": "direct",
                        "bind_interface": tun_device,
                        "egress_type": "openvpn",
                    }

        return None

    # =========================================================================
    # Default Outbound Management
    # =========================================================================

    async def set_default_outbound(self, tag: str) -> bool:
        """Set the default outbound in rust-router.

        Args:
            tag: Outbound tag to set as default

        Returns:
            True if successful
        """
        if not await self.is_available():
            return False

        try:
            async with await self._get_client() as client:
                response = await client.set_default_outbound(tag)
                return response.success
        except Exception as e:
            logger.error(f"Failed to set default outbound: {e}")
            return False

    # =========================================================================
    # Health and Status
    # =========================================================================

    async def get_health(self) -> Optional[List[Dict[str, Any]]]:
        """Get health status for all outbounds.

        Returns:
            List of health info dicts or None if unavailable
        """
        if not await self.is_available():
            return None

        try:
            async with await self._get_client() as client:
                health = await client.get_outbound_health()
                return [
                    {
                        "tag": h.tag,
                        "type": h.outbound_type,
                        "health": h.health,
                        "enabled": h.enabled,
                        "active_connections": h.active_connections,
                        "error": h.error,
                    }
                    for h in health
                ]
        except Exception as e:
            logger.error(f"Failed to get health: {e}")
            return None

    async def get_status(self) -> Optional[Dict[str, Any]]:
        """Get rust-router status.

        Returns:
            Status dict or None if unavailable
        """
        if not await self.is_available():
            return None

        try:
            async with await self._get_client() as client:
                response = await client.status()
                return response.data if response.success else None
        except Exception as e:
            logger.error(f"Failed to get status: {e}")
            return None


# =============================================================================
# Singleton instance for shared use
# =============================================================================

_manager_instance: Optional[RustRouterManager] = None
_manager_lock = asyncio.Lock()


async def get_manager() -> RustRouterManager:
    """Get the shared RustRouterManager instance.

    Returns:
        RustRouterManager singleton
    """
    global _manager_instance
    async with _manager_lock:
        if _manager_instance is None:
            _manager_instance = RustRouterManager()
        return _manager_instance


# =============================================================================
# Unit tests
# =============================================================================

if __name__ == "__main__":
    import argparse
    import json
    import unittest
    from unittest.mock import AsyncMock, MagicMock, patch, PropertyMock

    class TestSyncResult(unittest.TestCase):
        """Test SyncResult dataclass"""

        def test_default_values(self):
            """Test default values"""
            result = SyncResult(success=True)
            self.assertTrue(result.success)
            self.assertEqual(result.outbounds_added, 0)
            self.assertEqual(result.outbounds_removed, 0)
            self.assertEqual(result.outbounds_updated, 0)
            self.assertEqual(result.rules_synced, 0)
            self.assertEqual(result.errors, [])

        def test_with_values(self):
            """Test with custom values"""
            result = SyncResult(
                success=False,
                outbounds_added=5,
                outbounds_removed=2,
                errors=["error1", "error2"]
            )
            self.assertFalse(result.success)
            self.assertEqual(result.outbounds_added, 5)
            self.assertEqual(result.outbounds_removed, 2)
            self.assertEqual(len(result.errors), 2)

        def test_errors_default_factory(self):
            """Test that errors uses default_factory (not mutable default)"""
            r1 = SyncResult(success=True)
            r2 = SyncResult(success=True)
            r1.errors.append("error")
            # r2.errors should NOT have the error (not shared)
            self.assertEqual(len(r1.errors), 1)
            self.assertEqual(len(r2.errors), 0)

        def test_errors_is_list(self):
            """Test errors is always a list"""
            result = SyncResult(success=True)
            self.assertIsInstance(result.errors, list)

    class TestSyncResultPhase6(unittest.TestCase):
        """Test SyncResult Phase 6 fields"""

        def test_phase6_default_values(self):
            """Test Phase 6 default values"""
            result = SyncResult(success=True)
            self.assertEqual(result.peers_synced, 0)
            self.assertEqual(result.ecmp_groups_synced, 0)
            self.assertEqual(result.chains_synced, 0)

        def test_phase6_with_values(self):
            """Test Phase 6 with custom values"""
            result = SyncResult(
                success=True,
                peers_synced=3,
                ecmp_groups_synced=2,
                chains_synced=1,
            )
            self.assertEqual(result.peers_synced, 3)
            self.assertEqual(result.ecmp_groups_synced, 2)
            self.assertEqual(result.chains_synced, 1)

        def test_all_fields_together(self):
            """Test all fields together"""
            result = SyncResult(
                success=True,
                outbounds_added=5,
                outbounds_removed=2,
                outbounds_updated=1,
                rules_synced=10,
                peers_synced=3,
                ecmp_groups_synced=2,
                chains_synced=1,
                errors=["warning1"],
            )
            self.assertEqual(result.outbounds_added, 5)
            self.assertEqual(result.outbounds_removed, 2)
            self.assertEqual(result.outbounds_updated, 1)
            self.assertEqual(result.rules_synced, 10)
            self.assertEqual(result.peers_synced, 3)
            self.assertEqual(result.ecmp_groups_synced, 2)
            self.assertEqual(result.chains_synced, 1)
            self.assertEqual(len(result.errors), 1)

    class TestEgressTypeMap(unittest.TestCase):
        """Test EGRESS_TYPE_MAP constant"""

        def test_pia_is_wireguard(self):
            """PIA should map to wireguard"""
            self.assertEqual(EGRESS_TYPE_MAP["pia"], "wireguard")

        def test_custom_is_wireguard(self):
            """Custom WG should map to wireguard"""
            self.assertEqual(EGRESS_TYPE_MAP["custom"], "wireguard")

        def test_warp_is_wireguard(self):
            """WARP WG should map to wireguard"""
            self.assertEqual(EGRESS_TYPE_MAP["warp"], "wireguard")

        def test_warp_masque_is_socks5(self):
            """WARP MASQUE should map to socks5"""
            self.assertEqual(EGRESS_TYPE_MAP["warp-masque"], "socks5")

        def test_v2ray_is_socks5(self):
            """V2Ray should map to socks5"""
            self.assertEqual(EGRESS_TYPE_MAP["v2ray"], "socks5")

        def test_direct_is_direct(self):
            """Direct should map to direct"""
            self.assertEqual(EGRESS_TYPE_MAP["direct"], "direct")

        def test_openvpn_is_direct(self):
            """OpenVPN should map to direct (tun binding)"""
            self.assertEqual(EGRESS_TYPE_MAP["openvpn"], "direct")

    class TestRustRouterManagerInit(unittest.TestCase):
        """Test RustRouterManager initialization"""

        def test_default_values(self):
            """Test default initialization"""
            manager = RustRouterManager()
            self.assertIsNone(manager._socket_path)
            self.assertEqual(manager._connect_timeout, 5.0)
            self.assertEqual(manager._request_timeout, 10.0)
            self.assertIsNone(manager._db)

        def test_custom_values(self):
            """Test custom initialization"""
            manager = RustRouterManager(
                socket_path="/custom/socket.sock",
                connect_timeout=3.0,
                request_timeout=15.0
            )
            self.assertEqual(manager._socket_path, "/custom/socket.sock")
            self.assertEqual(manager._connect_timeout, 3.0)
            self.assertEqual(manager._request_timeout, 15.0)

        def test_sync_lock_created(self):
            """Test sync lock is created"""
            manager = RustRouterManager()
            self.assertIsNotNone(manager._sync_lock)
            self.assertIsInstance(manager._sync_lock, asyncio.Lock)

    class TestRustRouterManagerSingleton(unittest.IsolatedAsyncioTestCase):
        """Test get_manager singleton"""

        async def test_returns_same_instance(self):
            """Should return same instance"""
            global _manager_instance
            _manager_instance = None  # Reset singleton

            m1 = await get_manager()
            m2 = await get_manager()
            self.assertIs(m1, m2)

        async def test_creates_rust_router_manager(self):
            """Should create RustRouterManager instance"""
            global _manager_instance
            _manager_instance = None  # Reset singleton

            m = await get_manager()
            self.assertIsInstance(m, RustRouterManager)

    class TestManagerAvailability(unittest.IsolatedAsyncioTestCase):
        """Test manager availability checks"""

        async def test_is_available_when_unavailable(self):
            """Test is_available when rust-router unavailable"""
            manager = RustRouterManager(socket_path="/nonexistent/socket.sock")
            result = await manager.is_available()
            self.assertFalse(result)

    class TestManagerSync(unittest.IsolatedAsyncioTestCase):
        """Test manager sync operations with mocks"""

        def setUp(self):
            self.manager = RustRouterManager()
            # Create mock database
            self.mock_db = MagicMock()
            self.manager._db = self.mock_db

        async def test_sync_outbounds_when_unavailable(self):
            """Test sync_outbounds when rust-router unavailable"""
            # Mock database methods to return empty lists
            self.mock_db.get_pia_profiles.return_value = []
            self.mock_db.get_custom_egress_list.return_value = []
            self.mock_db.get_warp_egress_list.return_value = []
            self.mock_db.get_v2ray_egress_list.return_value = []
            self.mock_db.get_direct_egress_list.return_value = []
            self.mock_db.get_openvpn_egress_list.return_value = []

            # Mock client to fail connection
            with patch.object(self.manager, '_get_client') as mock_get_client:
                mock_client = AsyncMock()
                mock_client.__aenter__ = AsyncMock(return_value=mock_client)
                mock_client.__aexit__ = AsyncMock()
                mock_client.list_outbounds = AsyncMock(return_value=[])
                mock_get_client.return_value = mock_client

                result = await self.manager.sync_outbounds()
                # Should succeed with empty sync
                self.assertTrue(result.success)

        async def test_sync_outbounds_with_pia(self):
            """Test sync_outbounds with PIA profiles"""
            self.mock_db.get_pia_profiles.return_value = [
                {"name": "us-east", "enabled": True}
            ]
            self.mock_db.get_custom_egress_list.return_value = []
            self.mock_db.get_warp_egress_list.return_value = []
            self.mock_db.get_v2ray_egress_list.return_value = []
            self.mock_db.get_direct_egress_list.return_value = []
            self.mock_db.get_openvpn_egress_list.return_value = []

            with patch.object(self.manager, '_get_client') as mock_get_client:
                mock_client = AsyncMock()
                mock_client.__aenter__ = AsyncMock(return_value=mock_client)
                mock_client.__aexit__ = AsyncMock()
                mock_client.list_outbounds = AsyncMock(return_value=[])
                mock_client.add_wireguard_outbound = AsyncMock(
                    return_value=MagicMock(success=True)
                )
                mock_get_client.return_value = mock_client

                with patch('rust_router_manager._get_egress_interface_name', return_value='wg-pia-us-eas'):
                    result = await self.manager.sync_outbounds()

                # Should have added the PIA outbound + direct + block
                self.assertGreater(result.outbounds_added, 0)

        async def test_sync_outbounds_with_v2ray(self):
            """Test sync_outbounds with V2Ray egress"""
            self.mock_db.get_pia_profiles.return_value = []
            self.mock_db.get_custom_egress_list.return_value = []
            self.mock_db.get_warp_egress_list.return_value = []
            self.mock_db.get_v2ray_egress_list.return_value = [
                {"tag": "v2ray-proxy", "socks_port": 37101, "enabled": True}
            ]
            self.mock_db.get_direct_egress_list.return_value = []
            self.mock_db.get_openvpn_egress_list.return_value = []

            with patch.object(self.manager, '_get_client') as mock_get_client:
                mock_client = AsyncMock()
                mock_client.__aenter__ = AsyncMock(return_value=mock_client)
                mock_client.__aexit__ = AsyncMock()
                mock_client.list_outbounds = AsyncMock(return_value=[])
                mock_client.add_socks5_outbound = AsyncMock(
                    return_value=MagicMock(success=True)
                )
                mock_get_client.return_value = mock_client

                result = await self.manager.sync_outbounds()
                self.assertTrue(result.success)

        async def test_sync_routing_rules_empty(self):
            """Test sync_routing_rules with no rules"""
            self.mock_db.get_routing_rules.return_value = []
            self.mock_db.get_settings.return_value = {"default_outbound": "direct"}

            with patch.object(self.manager, '_get_client') as mock_get_client:
                mock_client = AsyncMock()
                mock_client.__aenter__ = AsyncMock(return_value=mock_client)
                mock_client.__aexit__ = AsyncMock()
                mock_client.update_routing = AsyncMock(
                    return_value=MagicMock(success=True, rule_count=0, version=1, default_outbound="direct")
                )
                mock_get_client.return_value = mock_client

                result = await self.manager.sync_routing_rules()
                self.assertTrue(result.success)
                self.assertEqual(result.rules_synced, 0)

        async def test_sync_routing_rules_with_rules(self):
            """Test sync_routing_rules with rules"""
            self.mock_db.get_routing_rules.return_value = [
                {"rule_type": "domain_suffix", "target": "google.com", "outbound": "proxy", "priority": 0},
                {"rule_type": "geoip", "target": "CN", "outbound": "direct", "priority": 1}
            ]
            self.mock_db.get_settings.return_value = {"default_outbound": "proxy"}

            with patch.object(self.manager, '_get_client') as mock_get_client:
                mock_client = AsyncMock()
                mock_client.__aenter__ = AsyncMock(return_value=mock_client)
                mock_client.__aexit__ = AsyncMock()
                mock_client.update_routing = AsyncMock(
                    return_value=MagicMock(success=True, rule_count=2, version=1, default_outbound="proxy")
                )
                mock_get_client.return_value = mock_client

                result = await self.manager.sync_routing_rules()
                self.assertTrue(result.success)
                self.assertEqual(result.rules_synced, 2)

        async def test_full_sync_when_unavailable(self):
            """Test full_sync when rust-router unavailable"""
            with patch.object(self.manager, 'is_available', return_value=False):
                result = await self.manager.full_sync()
                self.assertFalse(result.success)
                self.assertIn("not available", result.errors[0])

    class TestManagerNotifications(unittest.IsolatedAsyncioTestCase):
        """Test manager notification methods"""

        def setUp(self):
            self.manager = RustRouterManager()
            self.mock_db = MagicMock()
            self.manager._db = self.mock_db

        async def test_notify_added_when_unavailable(self):
            """Test notify_egress_added when unavailable"""
            with patch.object(self.manager, 'is_available', return_value=False):
                result = await self.manager.notify_egress_added("us-east", "pia")
                self.assertFalse(result)

        async def test_notify_removed_when_unavailable(self):
            """Test notify_egress_removed when unavailable"""
            with patch.object(self.manager, 'is_available', return_value=False):
                result = await self.manager.notify_egress_removed("us-east", "pia")
                self.assertFalse(result)

        async def test_notify_updated_when_unavailable(self):
            """Test notify_egress_updated when unavailable"""
            with patch.object(self.manager, 'is_available', return_value=False):
                result = await self.manager.notify_egress_updated("us-east", "pia")
                self.assertFalse(result)

        async def test_notify_added_success(self):
            """Test notify_egress_added success"""
            self.mock_db.get_pia_profile_by_name.return_value = {"name": "us-east"}

            with patch.object(self.manager, 'is_available', return_value=True):
                with patch.object(self.manager, '_get_client') as mock_get_client:
                    mock_client = AsyncMock()
                    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
                    mock_client.__aexit__ = AsyncMock()
                    mock_client.add_wireguard_outbound = AsyncMock(
                        return_value=MagicMock(success=True)
                    )
                    mock_client.notify_egress_change = AsyncMock(
                        return_value=MagicMock(success=True)
                    )
                    mock_get_client.return_value = mock_client

                    with patch('rust_router_manager._get_egress_interface_name', return_value='wg-pia-us-eas'):
                        result = await self.manager.notify_egress_added("us-east", "pia")

                    self.assertTrue(result)

        async def test_notify_removed_drains_first(self):
            """Test notify_egress_removed drains before removing"""
            with patch.object(self.manager, 'is_available', return_value=True):
                with patch.object(self.manager, '_get_client') as mock_get_client:
                    mock_client = AsyncMock()
                    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
                    mock_client.__aexit__ = AsyncMock()
                    mock_client.drain_outbound = AsyncMock(
                        return_value=MagicMock(success=True)
                    )
                    mock_client.notify_egress_change = AsyncMock(
                        return_value=MagicMock(success=True)
                    )
                    mock_get_client.return_value = mock_client

                    result = await self.manager.notify_egress_removed("us-east", "pia")

                    # Should have called drain
                    mock_client.drain_outbound.assert_called_once_with("us-east", timeout_secs=5)
                    self.assertTrue(result)

    class TestManagerHealth(unittest.IsolatedAsyncioTestCase):
        """Test manager health and status methods"""

        def setUp(self):
            self.manager = RustRouterManager()

        async def test_get_health_when_unavailable(self):
            """Test get_health when unavailable"""
            with patch.object(self.manager, 'is_available', return_value=False):
                result = await self.manager.get_health()
                self.assertIsNone(result)

        async def test_get_status_when_unavailable(self):
            """Test get_status when unavailable"""
            with patch.object(self.manager, 'is_available', return_value=False):
                result = await self.manager.get_status()
                self.assertIsNone(result)

        async def test_get_health_success(self):
            """Test get_health success"""
            with patch.object(self.manager, 'is_available', return_value=True):
                with patch.object(self.manager, '_get_client') as mock_get_client:
                    mock_client = AsyncMock()
                    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
                    mock_client.__aexit__ = AsyncMock()

                    from rust_router_client import OutboundHealthInfo
                    mock_client.get_outbound_health = AsyncMock(return_value=[
                        OutboundHealthInfo(
                            tag="us-east",
                            outbound_type="wireguard",
                            health="healthy",
                            enabled=True
                        )
                    ])
                    mock_get_client.return_value = mock_client

                    result = await self.manager.get_health()

                    self.assertIsNotNone(result)
                    self.assertEqual(len(result), 1)
                    self.assertEqual(result[0]["tag"], "us-east")
                    self.assertEqual(result[0]["health"], "healthy")

        async def test_get_status_success(self):
            """Test get_status success"""
            with patch.object(self.manager, 'is_available', return_value=True):
                with patch.object(self.manager, '_get_client') as mock_get_client:
                    mock_client = AsyncMock()
                    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
                    mock_client.__aexit__ = AsyncMock()

                    from rust_router_client import IpcResponse
                    mock_client.status = AsyncMock(return_value=IpcResponse(
                        success=True,
                        response_type="status",
                        data={"uptime": 3600, "connections": 100}
                    ))
                    mock_get_client.return_value = mock_client

                    result = await self.manager.get_status()

                    self.assertIsNotNone(result)
                    self.assertEqual(result["uptime"], 3600)

    class TestGetEgressConfig(unittest.TestCase):
        """Test _get_egress_config method"""

        def setUp(self):
            self.manager = RustRouterManager()
            self.mock_db = MagicMock()
            self.manager._db = self.mock_db

        def test_get_pia_config(self):
            """Test getting PIA config"""
            self.mock_db.get_pia_profile_by_name.return_value = {"name": "us-east"}

            with patch('rust_router_manager._get_egress_interface_name', return_value='wg-pia-us-eas'):
                config = self.manager._get_egress_config("us-east", "pia")

            self.assertIsNotNone(config)
            self.assertEqual(config["type"], "wireguard")
            self.assertEqual(config["egress_type"], "pia")

        def test_get_custom_config(self):
            """Test getting custom WG config"""
            self.mock_db.get_custom_egress.return_value = {"tag": "my-wg"}

            with patch('rust_router_manager._get_egress_interface_name', return_value='wg-eg-my-wg'):
                config = self.manager._get_egress_config("my-wg", "custom")

            self.assertIsNotNone(config)
            self.assertEqual(config["type"], "wireguard")
            self.assertEqual(config["egress_type"], "custom")

        def test_get_v2ray_config(self):
            """Test getting V2Ray config"""
            self.mock_db.get_v2ray_egress.return_value = {"tag": "v2ray-proxy", "socks_port": 37101}

            config = self.manager._get_egress_config("v2ray-proxy", "v2ray")

            self.assertIsNotNone(config)
            self.assertEqual(config["type"], "socks5")
            self.assertEqual(config["server_addr"], "127.0.0.1:37101")
            self.assertEqual(config["egress_type"], "v2ray")

        def test_get_warp_wg_config(self):
            """Test getting WARP WireGuard config"""
            self.mock_db.get_warp_egress.return_value = {"tag": "warp-main", "protocol": "wireguard"}

            with patch('rust_router_manager._get_egress_interface_name', return_value='wg-warp-warp-mai'):
                config = self.manager._get_egress_config("warp-main", "warp")

            self.assertIsNotNone(config)
            self.assertEqual(config["type"], "wireguard")
            self.assertEqual(config["egress_type"], "warp")

        def test_get_warp_masque_config(self):
            """Test getting WARP MASQUE config"""
            self.mock_db.get_warp_egress.return_value = {"tag": "warp-main", "protocol": "masque", "socks_port": 38001}

            config = self.manager._get_egress_config("warp-main", "warp")

            self.assertIsNotNone(config)
            self.assertEqual(config["type"], "socks5")
            self.assertEqual(config["server_addr"], "127.0.0.1:38001")

        def test_get_direct_config(self):
            """Test getting direct config"""
            self.mock_db.get_direct_egress.return_value = {"tag": "eth0-direct", "bind_interface": "eth0"}

            config = self.manager._get_egress_config("eth0-direct", "direct")

            self.assertIsNotNone(config)
            self.assertEqual(config["type"], "direct")
            self.assertEqual(config["bind_interface"], "eth0")

        def test_get_openvpn_config(self):
            """Test getting OpenVPN config"""
            self.mock_db.get_openvpn_egress.return_value = {"tag": "ovpn-us", "tun_device": "tun10"}

            config = self.manager._get_egress_config("ovpn-us", "openvpn")

            self.assertIsNotNone(config)
            self.assertEqual(config["type"], "direct")
            self.assertEqual(config["bind_interface"], "tun10")

        def test_get_nonexistent_config(self):
            """Test getting config for nonexistent egress"""
            self.mock_db.get_pia_profile_by_name.return_value = None

            config = self.manager._get_egress_config("nonexistent", "pia")

            self.assertIsNone(config)

        def test_get_unknown_type_config(self):
            """Test getting config for unknown type"""
            config = self.manager._get_egress_config("test", "unknown_type")
            self.assertIsNone(config)

    class TestPeerSync(unittest.IsolatedAsyncioTestCase):
        """Test peer sync methods (Phase 6)"""

        def setUp(self):
            self.manager = RustRouterManager()
            self.mock_db = MagicMock()
            self.manager._db = self.mock_db

        async def test_sync_peers_when_unavailable(self):
            """Test sync_peers when rust-router unavailable"""
            with patch.object(self.manager, 'is_available', return_value=False):
                result = await self.manager.sync_peers()
                self.assertFalse(result.success)
                self.assertIn("not available", result.errors[0])

        async def test_sync_peers_empty(self):
            """Test sync_peers with no peers"""
            self.mock_db.get_peer_nodes.return_value = []

            with patch.object(self.manager, 'is_available', return_value=True):
                with patch.object(self.manager, '_get_client') as mock_get_client:
                    mock_client = AsyncMock()
                    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
                    mock_client.__aexit__ = AsyncMock()
                    mock_client.list_peers = AsyncMock(return_value=[])
                    mock_get_client.return_value = mock_client

                    result = await self.manager.sync_peers()
                    self.assertTrue(result.success)
                    self.assertEqual(result.peers_synced, 0)

        async def test_sync_peers_with_existing(self):
            """Test sync_peers with existing peers"""
            self.mock_db.get_peer_nodes.return_value = [
                {"tag": "node-a", "enabled": True, "auto_connect": True, "tunnel_status": "connected"}
            ]

            with patch.object(self.manager, 'is_available', return_value=True):
                with patch.object(self.manager, '_get_client') as mock_get_client:
                    mock_client = AsyncMock()
                    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
                    mock_client.__aexit__ = AsyncMock()
                    mock_client.list_peers = AsyncMock(return_value=[
                        MagicMock(tag="node-a")
                    ])
                    mock_get_client.return_value = mock_client

                    result = await self.manager.sync_peers()
                    self.assertTrue(result.success)
                    self.assertEqual(result.peers_synced, 1)

        async def test_notify_peer_added_when_unavailable(self):
            """Test notify_peer_added when unavailable"""
            with patch.object(self.manager, 'is_available', return_value=False):
                result = await self.manager.notify_peer_added("node-a")
                self.assertFalse(result)

        async def test_notify_peer_removed_success(self):
            """Test notify_peer_removed success"""
            with patch.object(self.manager, 'is_available', return_value=True):
                with patch.object(self.manager, '_get_client') as mock_get_client:
                    mock_client = AsyncMock()
                    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
                    mock_client.__aexit__ = AsyncMock()
                    mock_client.remove_peer = AsyncMock(return_value=MagicMock(success=True))
                    mock_get_client.return_value = mock_client

                    result = await self.manager.notify_peer_removed("node-a")
                    self.assertTrue(result)
                    mock_client.remove_peer.assert_called_once_with("node-a")

        async def test_notify_peer_updated_connect(self):
            """Test notify_peer_updated triggers connect"""
            self.mock_db.get_peer_node.return_value = {
                "tag": "node-a", "enabled": True, "auto_connect": True, "tunnel_status": "disconnected"
            }

            with patch.object(self.manager, 'is_available', return_value=True):
                with patch.object(self.manager, '_get_client') as mock_get_client:
                    mock_client = AsyncMock()
                    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
                    mock_client.__aexit__ = AsyncMock()
                    mock_client.connect_peer = AsyncMock(return_value=MagicMock(success=True))
                    mock_get_client.return_value = mock_client

                    result = await self.manager.notify_peer_updated("node-a")
                    self.assertTrue(result)
                    mock_client.connect_peer.assert_called_once_with("node-a")

    class TestEcmpGroupSync(unittest.IsolatedAsyncioTestCase):
        """Test ECMP group sync methods (Phase 6)"""

        def setUp(self):
            self.manager = RustRouterManager()
            self.mock_db = MagicMock()
            self.manager._db = self.mock_db

        async def test_sync_ecmp_groups_when_unavailable(self):
            """Test sync_ecmp_groups when rust-router unavailable"""
            with patch.object(self.manager, 'is_available', return_value=False):
                result = await self.manager.sync_ecmp_groups()
                self.assertFalse(result.success)
                self.assertIn("not available", result.errors[0])

        async def test_sync_ecmp_groups_empty(self):
            """Test sync_ecmp_groups with no groups"""
            self.mock_db.get_outbound_groups.return_value = []

            with patch.object(self.manager, 'is_available', return_value=True):
                with patch.object(self.manager, '_get_client') as mock_get_client:
                    mock_client = AsyncMock()
                    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
                    mock_client.__aexit__ = AsyncMock()
                    mock_client.list_ecmp_groups = AsyncMock(return_value=[])
                    mock_get_client.return_value = mock_client

                    result = await self.manager.sync_ecmp_groups()
                    self.assertTrue(result.success)
                    self.assertEqual(result.ecmp_groups_synced, 0)

        async def test_sync_ecmp_groups_create_new(self):
            """Test sync_ecmp_groups creates new group"""
            self.mock_db.get_outbound_groups.return_value = [
                {
                    "tag": "group-1",
                    "enabled": True,
                    "algorithm": "round_robin",
                    "description": "Test group",
                    "members": ["us-east", "us-west"],
                    "weights": [1, 2],
                    "routing_table": 200,
                }
            ]

            with patch.object(self.manager, 'is_available', return_value=True):
                with patch.object(self.manager, '_get_client') as mock_get_client:
                    mock_client = AsyncMock()
                    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
                    mock_client.__aexit__ = AsyncMock()
                    mock_client.list_ecmp_groups = AsyncMock(return_value=[])
                    mock_client.create_ecmp_group = AsyncMock(return_value=MagicMock(success=True))
                    mock_get_client.return_value = mock_client

                    result = await self.manager.sync_ecmp_groups()
                    self.assertTrue(result.success)
                    self.assertEqual(result.ecmp_groups_synced, 1)
                    mock_client.create_ecmp_group.assert_called_once()

        async def test_notify_ecmp_group_removed(self):
            """Test notify_ecmp_group_changed with remove action"""
            with patch.object(self.manager, 'is_available', return_value=True):
                with patch.object(self.manager, '_get_client') as mock_get_client:
                    mock_client = AsyncMock()
                    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
                    mock_client.__aexit__ = AsyncMock()
                    mock_client.remove_ecmp_group = AsyncMock(return_value=MagicMock(success=True))
                    mock_get_client.return_value = mock_client

                    result = await self.manager.notify_ecmp_group_changed("group-1", "removed")
                    self.assertTrue(result)
                    mock_client.remove_ecmp_group.assert_called_once_with("group-1")

        async def test_notify_ecmp_group_added(self):
            """Test notify_ecmp_group_changed with add action"""
            self.mock_db.get_outbound_group.return_value = {
                "tag": "group-1",
                "enabled": True,
                "algorithm": "five_tuple_hash",
                "description": "Test",
                "members": ["us-east"],
                "weights": [1],
                "routing_table": 201,
            }

            with patch.object(self.manager, 'is_available', return_value=True):
                with patch.object(self.manager, '_get_client') as mock_get_client:
                    mock_client = AsyncMock()
                    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
                    mock_client.__aexit__ = AsyncMock()
                    mock_client.list_ecmp_groups = AsyncMock(return_value=[])
                    mock_client.create_ecmp_group = AsyncMock(return_value=MagicMock(success=True))
                    mock_get_client.return_value = mock_client

                    result = await self.manager.notify_ecmp_group_changed("group-1", "added")
                    self.assertTrue(result)
                    mock_client.create_ecmp_group.assert_called_once()

    class TestChainSync(unittest.IsolatedAsyncioTestCase):
        """Test chain sync methods (Phase 6)"""

        def setUp(self):
            self.manager = RustRouterManager()
            self.mock_db = MagicMock()
            self.manager._db = self.mock_db

        async def test_sync_chains_when_unavailable(self):
            """Test sync_chains when rust-router unavailable"""
            with patch.object(self.manager, 'is_available', return_value=False):
                result = await self.manager.sync_chains()
                self.assertFalse(result.success)
                self.assertIn("not available", result.errors[0])

        async def test_sync_chains_empty(self):
            """Test sync_chains with no chains"""
            self.mock_db.get_node_chains.return_value = []

            with patch.object(self.manager, 'is_available', return_value=True):
                with patch.object(self.manager, '_get_client') as mock_get_client:
                    mock_client = AsyncMock()
                    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
                    mock_client.__aexit__ = AsyncMock()
                    mock_client.list_chains = AsyncMock(return_value=[])
                    mock_get_client.return_value = mock_client

                    result = await self.manager.sync_chains()
                    self.assertTrue(result.success)
                    self.assertEqual(result.chains_synced, 0)

        async def test_sync_chains_create_new(self):
            """Test sync_chains creates new chain"""
            self.mock_db.get_node_chains.return_value = [
                {
                    "tag": "chain-1",
                    "enabled": True,
                    "chain_state": "inactive",
                    "hops": ["node-a", "node-b"],
                    "exit_egress": "us-east",
                    "description": "Test chain",
                    "allow_transitive": False,
                }
            ]

            with patch.object(self.manager, 'is_available', return_value=True):
                with patch.object(self.manager, '_get_client') as mock_get_client:
                    mock_client = AsyncMock()
                    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
                    mock_client.__aexit__ = AsyncMock()
                    mock_client.list_chains = AsyncMock(return_value=[])
                    mock_client.create_chain = AsyncMock(return_value=MagicMock(success=True))
                    mock_get_client.return_value = mock_client

                    result = await self.manager.sync_chains()
                    self.assertTrue(result.success)
                    self.assertEqual(result.chains_synced, 1)
                    mock_client.create_chain.assert_called_once()

        async def test_sync_chains_activate(self):
            """Test sync_chains activates chain that should be active"""
            self.mock_db.get_node_chains.return_value = [
                {
                    "tag": "chain-1",
                    "enabled": True,
                    "chain_state": "active",
                    "hops": ["node-a"],
                    "exit_egress": "us-east",
                    "description": "",
                    "allow_transitive": False,
                }
            ]

            with patch.object(self.manager, 'is_available', return_value=True):
                with patch.object(self.manager, '_get_client') as mock_get_client:
                    mock_client = AsyncMock()
                    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
                    mock_client.__aexit__ = AsyncMock()
                    mock_client.list_chains = AsyncMock(return_value=[])
                    mock_client.create_chain = AsyncMock(return_value=MagicMock(success=True))
                    mock_client.get_chain_status = AsyncMock(return_value=MagicMock(
                        success=True, data={"chain_state": "inactive"}
                    ))
                    mock_client.activate_chain = AsyncMock(return_value=MagicMock(success=True))
                    mock_get_client.return_value = mock_client

                    result = await self.manager.sync_chains()
                    self.assertTrue(result.success)
                    mock_client.activate_chain.assert_called_once_with("chain-1")

        async def test_notify_chain_deleted(self):
            """Test notify_chain_changed with deleted action"""
            with patch.object(self.manager, 'is_available', return_value=True):
                with patch.object(self.manager, '_get_client') as mock_get_client:
                    mock_client = AsyncMock()
                    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
                    mock_client.__aexit__ = AsyncMock()
                    mock_client.get_chain_status = AsyncMock(return_value=MagicMock(
                        success=True, data={"chain_state": "inactive"}
                    ))
                    mock_client.delete_chain = AsyncMock(return_value=MagicMock(success=True))
                    mock_get_client.return_value = mock_client

                    result = await self.manager.notify_chain_changed("chain-1", "deleted")
                    self.assertTrue(result)
                    mock_client.delete_chain.assert_called_once_with("chain-1")

        async def test_notify_chain_activated(self):
            """Test notify_chain_changed with activated action"""
            with patch.object(self.manager, 'is_available', return_value=True):
                with patch.object(self.manager, '_get_client') as mock_get_client:
                    mock_client = AsyncMock()
                    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
                    mock_client.__aexit__ = AsyncMock()
                    mock_client.activate_chain = AsyncMock(return_value=MagicMock(success=True))
                    mock_get_client.return_value = mock_client

                    result = await self.manager.notify_chain_changed("chain-1", "activated")
                    self.assertTrue(result)
                    mock_client.activate_chain.assert_called_once_with("chain-1")

        async def test_notify_chain_deactivated(self):
            """Test notify_chain_changed with deactivated action"""
            with patch.object(self.manager, 'is_available', return_value=True):
                with patch.object(self.manager, '_get_client') as mock_get_client:
                    mock_client = AsyncMock()
                    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
                    mock_client.__aexit__ = AsyncMock()
                    mock_client.deactivate_chain = AsyncMock(return_value=MagicMock(success=True))
                    mock_get_client.return_value = mock_client

                    result = await self.manager.notify_chain_changed("chain-1", "deactivated")
                    self.assertTrue(result)
                    mock_client.deactivate_chain.assert_called_once_with("chain-1")

    class TestSetDefaultOutbound(unittest.IsolatedAsyncioTestCase):
        """Test set_default_outbound method"""

        async def test_set_default_when_unavailable(self):
            """Test set_default_outbound when unavailable"""
            manager = RustRouterManager()
            with patch.object(manager, 'is_available', return_value=False):
                result = await manager.set_default_outbound("proxy")
                self.assertFalse(result)

        async def test_set_default_success(self):
            """Test set_default_outbound success"""
            manager = RustRouterManager()
            with patch.object(manager, 'is_available', return_value=True):
                with patch.object(manager, '_get_client') as mock_get_client:
                    mock_client = AsyncMock()
                    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
                    mock_client.__aexit__ = AsyncMock()
                    mock_client.set_default_outbound = AsyncMock(
                        return_value=MagicMock(success=True)
                    )
                    mock_get_client.return_value = mock_client

                    result = await manager.set_default_outbound("proxy")
                    self.assertTrue(result)

    # CLI entry point
    parser = argparse.ArgumentParser(
        description="Rust Router Manager (Phase 6)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s sync           # Full sync (outbounds + rules + peers + ecmp + chains)
  %(prog)s outbounds      # Sync outbounds only
  %(prog)s rules          # Sync routing rules only
  %(prog)s peers          # Sync peer nodes only (Phase 6)
  %(prog)s ecmp           # Sync ECMP groups only (Phase 6)
  %(prog)s chains         # Sync chains only (Phase 6)
  %(prog)s health         # Get outbound health status
  %(prog)s status         # Get rust-router status
  %(prog)s test           # Run comprehensive unit tests
        """
    )
    parser.add_argument(
        "command",
        choices=["sync", "outbounds", "rules", "peers", "ecmp", "chains", "health", "status", "test"],
        help="Command to execute"
    )

    args = parser.parse_args()

    def run_tests():
        """Run unit tests (synchronous function for proper test runner)"""
        print("Running comprehensive RustRouterManager unit tests...")
        print("=" * 60)

        # Create test suite
        loader = unittest.TestLoader()
        suite = unittest.TestSuite()

        # Add all test classes
        suite.addTests(loader.loadTestsFromTestCase(TestSyncResult))
        suite.addTests(loader.loadTestsFromTestCase(TestSyncResultPhase6))
        suite.addTests(loader.loadTestsFromTestCase(TestEgressTypeMap))
        suite.addTests(loader.loadTestsFromTestCase(TestRustRouterManagerInit))
        suite.addTests(loader.loadTestsFromTestCase(TestRustRouterManagerSingleton))
        suite.addTests(loader.loadTestsFromTestCase(TestManagerAvailability))
        suite.addTests(loader.loadTestsFromTestCase(TestManagerSync))
        suite.addTests(loader.loadTestsFromTestCase(TestManagerNotifications))
        suite.addTests(loader.loadTestsFromTestCase(TestManagerHealth))
        suite.addTests(loader.loadTestsFromTestCase(TestGetEgressConfig))
        # Phase 6 test classes
        suite.addTests(loader.loadTestsFromTestCase(TestPeerSync))
        suite.addTests(loader.loadTestsFromTestCase(TestEcmpGroupSync))
        suite.addTests(loader.loadTestsFromTestCase(TestChainSync))
        suite.addTests(loader.loadTestsFromTestCase(TestSetDefaultOutbound))

        # Run tests
        runner = unittest.TextTestRunner(verbosity=2)
        result = runner.run(suite)

        print("=" * 60)
        print(f"Tests run: {result.testsRun}")
        print(f"Failures: {len(result.failures)}")
        print(f"Errors: {len(result.errors)}")

        return 0 if result.wasSuccessful() else 1

    # Handle test command before entering asyncio.run
    if args.command == "test":
        sys.exit(run_tests())

    async def main():
        manager = await get_manager()

        if args.command == "sync":
            print("Running full sync...")
            result = await manager.full_sync()
            print(f"Success: {result.success}")
            print(f"Outbounds added: {result.outbounds_added}")
            print(f"Outbounds removed: {result.outbounds_removed}")
            print(f"Rules synced: {result.rules_synced}")
            print(f"Peers synced: {result.peers_synced}")
            print(f"ECMP groups synced: {result.ecmp_groups_synced}")
            print(f"Chains synced: {result.chains_synced}")
            print(f"WG tunnels synced: {result.wg_tunnels_synced}")
            print(f"WG tunnels removed: {result.wg_tunnels_removed}")
            if result.errors:
                print(f"Errors: {result.errors}")
            return 0 if result.success else 1

        elif args.command == "outbounds":
            print("Syncing outbounds...")
            result = await manager.sync_outbounds()
            print(f"Success: {result.success}")
            print(f"Added: {result.outbounds_added}, Removed: {result.outbounds_removed}")
            if result.errors:
                print(f"Errors: {result.errors}")
            return 0 if result.success else 1

        elif args.command == "rules":
            print("Syncing routing rules...")
            result = await manager.sync_routing_rules()
            print(f"Success: {result.success}")
            print(f"Rules synced: {result.rules_synced}")
            if result.errors:
                print(f"Errors: {result.errors}")
            return 0 if result.success else 1

        elif args.command == "peers":
            print("Syncing peer nodes...")
            result = await manager.sync_peers()
            print(f"Success: {result.success}")
            print(f"Peers synced: {result.peers_synced}")
            if result.errors:
                print(f"Errors: {result.errors}")
            return 0 if result.success else 1

        elif args.command == "ecmp":
            print("Syncing ECMP groups...")
            result = await manager.sync_ecmp_groups()
            print(f"Success: {result.success}")
            print(f"ECMP groups synced: {result.ecmp_groups_synced}")
            if result.errors:
                print(f"Errors: {result.errors}")
            return 0 if result.success else 1

        elif args.command == "chains":
            print("Syncing chains...")
            result = await manager.sync_chains()
            print(f"Success: {result.success}")
            print(f"Chains synced: {result.chains_synced}")
            if result.errors:
                print(f"Errors: {result.errors}")
            return 0 if result.success else 1

        elif args.command == "health":
            health = await manager.get_health()
            if health is None:
                print("rust-router not available")
                return 1
            if not health:
                print("No outbounds configured")
                return 0
            for h in health:
                status = "enabled" if h["enabled"] else "disabled"
                print(f"{h['tag']} ({h['type']}): {h['health']} [{status}]")
                if h.get("error"):
                    print(f"  error: {h['error']}")
            return 0

        elif args.command == "status":
            status = await manager.get_status()
            if status is None:
                print("rust-router not available")
                return 1
            print(json.dumps(status, indent=2))
            return 0

    sys.exit(asyncio.run(main()))

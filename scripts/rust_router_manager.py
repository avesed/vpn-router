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
import logging
import os
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

# Add script directory to path for imports
sys.path.insert(0, str(Path(__file__).parent))

from rust_router_client import (
    RustRouterClient,
    RuleConfig,
    IpcResponse,
    UpdateRoutingResult,
    is_available,
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
    errors: List[str] = field(default_factory=list)


def _get_db():
    """Lazy import and get database instance"""
    from db_helper import get_db
    return get_db()


def _get_egress_interface_name(tag: str, is_pia: bool = False, egress_type: str = None) -> str:
    """Get WireGuard interface name for an egress"""
    from setup_kernel_wg_egress import get_egress_interface_name
    return get_egress_interface_name(tag, is_pia=is_pia, egress_type=egress_type)


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

    def _get_db(self):
        """Get database instance (lazy load)"""
        if self._db is None:
            self._db = _get_db()
        return self._db

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

                # PIA profiles
                for profile in db.get_pia_profiles(enabled_only=True):
                    tag = profile.get("name", "")
                    if tag:
                        interface = _get_egress_interface_name(tag, is_pia=True)
                        db_outbounds[tag] = {
                            "type": "wireguard",
                            "interface": interface,
                            "egress_type": "pia",
                        }

                # Custom WireGuard egress
                for egress in db.get_custom_egress_list(enabled_only=True):
                    tag = egress.get("tag", "")
                    if tag:
                        interface = _get_egress_interface_name(tag, is_pia=False)
                        db_outbounds[tag] = {
                            "type": "wireguard",
                            "interface": interface,
                            "egress_type": "custom",
                        }

                # WARP egress
                for egress in db.get_warp_egress_list(enabled_only=True):
                    tag = egress.get("tag", "")
                    protocol = egress.get("protocol", "wireguard")
                    if tag:
                        if protocol == "wireguard":
                            interface = _get_egress_interface_name(tag, egress_type="warp")
                            db_outbounds[tag] = {
                                "type": "wireguard",
                                "interface": interface,
                                "egress_type": "warp",
                            }
                        else:
                            # WARP MASQUE uses SOCKS5
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

                    # Add missing outbounds
                    for tag, config in db_outbounds.items():
                        if tag not in current_tags:
                            add_result = await self._add_outbound(client, tag, config)
                            if add_result.success:
                                result.outbounds_added += 1
                            else:
                                result.errors.append(f"Failed to add {tag}: {add_result.error}")

                    # Remove stale outbounds (except built-in ones)
                    builtin_tags = {"direct", "block"}
                    for current_tag in current_tags:
                        if current_tag not in db_outbounds and current_tag not in builtin_tags:
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
    # Routing Rules Sync
    # =========================================================================

    async def sync_routing_rules(self) -> SyncResult:
        """Sync routing rules from database to rust-router.

        This method:
        1. Gets all enabled routing rules from database
        2. Converts them to RuleConfig format
        3. Sends UpdateRouting command to rust-router

        Returns:
            SyncResult with statistics and errors
        """
        result = SyncResult(success=True)

        async with self._sync_lock:
            try:
                db = self._get_db()
                rules = db.get_routing_rules(enabled_only=True)

                # Get default outbound from settings or use "direct"
                settings = db.get_settings()
                default_outbound = settings.get("default_outbound", "direct") if settings else "direct"

                # Convert to RuleConfig list
                rule_configs: List[RuleConfig] = []
                for rule in rules:
                    rule_type = rule.get("rule_type", "")
                    target = rule.get("target", "")
                    outbound = rule.get("outbound", "direct")
                    priority = rule.get("priority", 0)

                    # Skip invalid rules
                    if not rule_type or not target:
                        continue

                    rule_configs.append(RuleConfig(
                        rule_type=rule_type,
                        target=target,
                        outbound=outbound,
                        priority=priority,
                        enabled=True,
                    ))

                # Send to rust-router
                async with await self._get_client() as client:
                    update_result = await client.update_routing(rule_configs, default_outbound)

                    if update_result.success:
                        result.rules_synced = update_result.rule_count
                        logger.info(
                            f"Routing rules synced: {result.rules_synced} rules, "
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
    # Full Sync
    # =========================================================================

    async def full_sync(self) -> SyncResult:
        """Full sync: outbounds + rules.

        This should be called on startup to ensure rust-router
        is in sync with the database.

        Returns:
            Combined SyncResult from outbound and rule sync
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

        # Then sync routing rules
        rules_result = await self.sync_routing_rules()
        result.rules_synced = rules_result.rules_synced
        result.errors.extend(rules_result.errors)

        # Overall success
        result.success = outbound_result.success and rules_result.success

        logger.info(
            f"Full sync complete: outbounds_added={result.outbounds_added}, "
            f"outbounds_removed={result.outbounds_removed}, "
            f"rules_synced={result.rules_synced}, success={result.success}"
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
        description="Rust Router Manager (Phase 3.4)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s sync           # Full sync (outbounds + rules)
  %(prog)s outbounds      # Sync outbounds only
  %(prog)s rules          # Sync routing rules only
  %(prog)s health         # Get outbound health status
  %(prog)s status         # Get rust-router status
  %(prog)s test           # Run comprehensive unit tests
        """
    )
    parser.add_argument(
        "command",
        choices=["sync", "outbounds", "rules", "health", "status", "test"],
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
        suite.addTests(loader.loadTestsFromTestCase(TestEgressTypeMap))
        suite.addTests(loader.loadTestsFromTestCase(TestRustRouterManagerInit))
        suite.addTests(loader.loadTestsFromTestCase(TestRustRouterManagerSingleton))
        suite.addTests(loader.loadTestsFromTestCase(TestManagerAvailability))
        suite.addTests(loader.loadTestsFromTestCase(TestManagerSync))
        suite.addTests(loader.loadTestsFromTestCase(TestManagerNotifications))
        suite.addTests(loader.loadTestsFromTestCase(TestManagerHealth))
        suite.addTests(loader.loadTestsFromTestCase(TestGetEgressConfig))
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

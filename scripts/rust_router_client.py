#!/usr/bin/env python3
"""
Rust Router IPC Client (v3.1 - Phase 3.4 + Prometheus Metrics)

Async client for communicating with rust-router via Unix socket.
Used by api_server.py and RustRouterManager for configuration sync.

Protocol v3.1 Features (Phase 3.4 + Prometheus Metrics):
- Length-prefixed JSON framing (4 bytes BE + JSON) - matches Rust IPC protocol
- WireGuard outbound management (AddWireguardOutbound)
- SOCKS5 outbound management (AddSocks5Outbound)
- Graceful drain before removal (DrainOutbound)
- Routing rule updates (UpdateRouting, SetDefaultOutbound)
- Outbound health monitoring (GetOutboundHealth)
- Egress change notifications (NotifyEgressChange)
- Prometheus metrics retrieval (GetPrometheusMetrics)
- Connection retry with exponential backoff
- Graceful degradation when rust-router unavailable

Wire Protocol:
  [4 bytes: message length (big-endian u32)]
  [N bytes: JSON payload]
"""

import asyncio
import json
import logging
import os
import struct
import random
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

# Default socket path
DEFAULT_SOCKET_PATH = "/var/run/rust-router.sock"

# Protocol constants (must match Rust: src/ipc/protocol.rs)
LENGTH_PREFIX_SIZE = 4
MAX_MESSAGE_SIZE = 1024 * 1024  # 1 MB

# Protocol version
PROTOCOL_VERSION = 3  # Phase 3.4: IPC v2.1 with drain, health, routing updates

# Default timeouts
DEFAULT_CONNECT_TIMEOUT = 5.0  # seconds
DEFAULT_REQUEST_TIMEOUT = 10.0  # seconds

# Retry configuration
MAX_RETRIES = 3
BASE_RETRY_DELAY = 0.5  # seconds
MAX_RETRY_DELAY = 5.0  # seconds
JITTER_FACTOR = 0.25  # +/- 25% random jitter

logger = logging.getLogger(__name__)


@dataclass
class IpcResponse:
    """IPC response from rust-router"""
    success: bool
    response_type: str
    data: Optional[Dict[str, Any]] = None
    error: Optional[str] = None
    error_code: Optional[str] = None


@dataclass
class OutboundStats:
    """Per-outbound traffic statistics"""
    bytes_uploaded: int = 0
    bytes_downloaded: int = 0
    connections_total: int = 0
    connections_active: int = 0
    errors: int = 0
    last_activity_ms: int = 0


@dataclass
class OutboundInfo:
    """Information about a single outbound"""
    tag: str
    outbound_type: str
    enabled: bool
    health: str
    active_connections: int = 0
    total_connections: int = 0
    bind_interface: Optional[str] = None
    routing_mark: Optional[int] = None


@dataclass
class OutboundHealthInfo:
    """Health status for a single outbound"""
    tag: str
    outbound_type: str
    health: str
    enabled: bool
    active_connections: int = 0
    last_check: Optional[str] = None
    error: Optional[str] = None


@dataclass
class DrainResult:
    """Result of draining an outbound"""
    success: bool
    drained_count: int = 0
    force_closed_count: int = 0
    drain_time_ms: int = 0


@dataclass
class UpdateRoutingResult:
    """Result of updating routing rules"""
    success: bool
    version: int = 0
    rule_count: int = 0
    default_outbound: str = ""


@dataclass
class PrometheusMetricsResponse:
    """Prometheus metrics response from rust-router"""
    metrics_text: str
    timestamp_ms: int


@dataclass
class RuleConfig:
    """Rule configuration for UpdateRouting"""
    rule_type: str
    target: str
    outbound: str
    priority: int = 0
    enabled: bool = True

    def to_dict(self) -> Dict[str, Any]:
        return {
            "rule_type": self.rule_type,
            "target": self.target,
            "outbound": self.outbound,
            "priority": self.priority,
            "enabled": self.enabled,
        }


class IpcError(Exception):
    """IPC communication error"""
    pass


class IpcConnectionError(IpcError):
    """Connection-related error (renamed to avoid shadowing built-in ConnectionError)"""
    pass


class ProtocolError(IpcError):
    """Protocol-related error (malformed messages)"""
    pass


class IpcTimeoutError(IpcError):
    """Request timeout error (renamed to avoid shadowing built-in TimeoutError)"""
    pass


def calculate_jittered_backoff(attempt: int, base_delay: float = BASE_RETRY_DELAY) -> float:
    """Calculate retry delay with exponential backoff and jitter.

    Args:
        attempt: Retry attempt number (0-indexed)
        base_delay: Base delay in seconds

    Returns:
        Delay in seconds with jitter applied
    """
    delay = base_delay * (2 ** attempt)
    delay = min(delay, MAX_RETRY_DELAY)
    jitter = delay * JITTER_FACTOR * (2 * random.random() - 1)
    return max(0.1, delay + jitter)


class RustRouterClient:
    """
    Async client for rust-router IPC communication (v3.0).

    Features:
    - Length-prefixed JSON protocol (matches Rust implementation)
    - WireGuard and SOCKS5 outbound management
    - Graceful drain before removal
    - Routing rule updates with atomic swap
    - Health monitoring for all outbounds
    - Egress change notifications from Python
    - Connection retry with exponential backoff
    - Graceful degradation when unavailable

    Note: This client is coroutine-safe when used with async context manager,
    but not thread-safe. Use separate instances for different threads.

    Usage:
        async with RustRouterClient() as client:
            # Check status
            status = await client.status()
            print(f"Active connections: {status.data['active_connections']}")

            # Add WireGuard outbound
            await client.add_wireguard_outbound("us-east", "wg-pia-us-east")

            # Update routing rules
            rules = [RuleConfig("domain_suffix", "google.com", "proxy")]
            await client.update_routing(rules, "direct")

            # Drain and remove outbound
            await client.drain_outbound("old-proxy", timeout_secs=30)
    """

    def __init__(
        self,
        socket_path: Optional[str] = None,
        connect_timeout: float = DEFAULT_CONNECT_TIMEOUT,
        request_timeout: float = DEFAULT_REQUEST_TIMEOUT,
        max_retries: int = MAX_RETRIES,
    ):
        self.socket_path = socket_path or os.environ.get(
            "RUST_ROUTER_SOCKET", DEFAULT_SOCKET_PATH
        )
        self.connect_timeout = connect_timeout
        self.request_timeout = request_timeout
        self.max_retries = max_retries
        self._reader: Optional[asyncio.StreamReader] = None
        self._writer: Optional[asyncio.StreamWriter] = None
        self._connected = False

    async def __aenter__(self) -> "RustRouterClient":
        await self.connect()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self.disconnect()

    async def connect(self) -> bool:
        """Connect to rust-router IPC socket with timeout and retry.

        Returns:
            True if connected successfully, False otherwise
        """
        if self._connected:
            return True

        socket_path = Path(self.socket_path)
        if not socket_path.exists():
            logger.warning(f"Socket not found: {self.socket_path}")
            return False

        last_error = None
        for attempt in range(self.max_retries):
            try:
                self._reader, self._writer = await asyncio.wait_for(
                    asyncio.open_unix_connection(str(socket_path)),
                    timeout=self.connect_timeout,
                )
                self._connected = True
                logger.debug(f"Connected to rust-router at {self.socket_path}")
                return True
            except asyncio.TimeoutError:
                last_error = IpcTimeoutError(f"Connection timeout after {self.connect_timeout}s")
            except OSError as e:
                last_error = IpcConnectionError(f"Connection failed: {e}")
            except Exception as e:
                last_error = IpcError(f"Unexpected error: {e}")

            if attempt < self.max_retries - 1:
                delay = calculate_jittered_backoff(attempt)
                logger.debug(f"Retry {attempt + 1}/{self.max_retries} in {delay:.2f}s")
                await asyncio.sleep(delay)

        logger.warning(f"Failed to connect after {self.max_retries} attempts: {last_error}")
        return False

    async def disconnect(self) -> None:
        """Close the connection"""
        if self._writer:
            try:
                self._writer.close()
                await self._writer.wait_closed()
            except Exception:
                pass  # Ignore errors during close
            finally:
                self._writer = None
                self._reader = None
                self._connected = False
                logger.debug("Disconnected from rust-router")

    @property
    def is_connected(self) -> bool:
        """Check if client is connected"""
        return self._connected and self._writer is not None and not self._writer.is_closing()

    async def _send_command(self, command: Dict[str, Any]) -> IpcResponse:
        """Send a command and receive response with length-prefix framing.

        Protocol: [4 bytes length BE] + [JSON payload]
        """
        if not self._connected or not self._writer or not self._reader:
            # Try to reconnect
            if not await self.connect():
                return IpcResponse(
                    success=False,
                    response_type="error",
                    error="Not connected to rust-router",
                    error_code="NOT_CONNECTED",
                )

        try:
            # Encode command to JSON
            json_data = json.dumps(command).encode('utf-8')

            # Check message size
            if len(json_data) > MAX_MESSAGE_SIZE:
                return IpcResponse(
                    success=False,
                    response_type="error",
                    error=f"Message too large: {len(json_data)} bytes",
                    error_code="MESSAGE_TOO_LARGE",
                )

            # Send length prefix + JSON
            length_prefix = struct.pack('>I', len(json_data))
            self._writer.write(length_prefix + json_data)
            await self._writer.drain()

            # Read response length prefix
            len_data = await asyncio.wait_for(
                self._reader.readexactly(LENGTH_PREFIX_SIZE),
                timeout=self.request_timeout,
            )
            response_len = struct.unpack('>I', len_data)[0]

            # Validate response size
            if response_len > MAX_MESSAGE_SIZE:
                return IpcResponse(
                    success=False,
                    response_type="error",
                    error=f"Response too large: {response_len} bytes",
                    error_code="RESPONSE_TOO_LARGE",
                )

            # Read response body
            response_data = await asyncio.wait_for(
                self._reader.readexactly(response_len),
                timeout=self.request_timeout,
            )

            # Parse response
            response = json.loads(response_data.decode('utf-8'))

            return self._parse_response(response)

        except asyncio.TimeoutError:
            await self.disconnect()
            return IpcResponse(
                success=False,
                response_type="error",
                error=f"Request timeout after {self.request_timeout}s",
                error_code="TIMEOUT",
            )
        except asyncio.IncompleteReadError:
            await self.disconnect()
            return IpcResponse(
                success=False,
                response_type="error",
                error="Connection closed by server",
                error_code="CONNECTION_CLOSED",
            )
        except json.JSONDecodeError as e:
            return IpcResponse(
                success=False,
                response_type="error",
                error=f"Invalid JSON response: {e}",
                error_code="INVALID_JSON",
            )
        except Exception as e:
            await self.disconnect()
            return IpcResponse(
                success=False,
                response_type="error",
                error=str(e),
                error_code="UNKNOWN",
            )

    def _parse_response(self, response: Dict[str, Any]) -> IpcResponse:
        """Parse raw response into IpcResponse"""
        response_type = response.get("type", "unknown")

        # Check for error response
        if response_type == "error":
            error_info = response.get("Error", response)
            return IpcResponse(
                success=False,
                response_type="error",
                error=error_info.get("message", "Unknown error"),
                error_code=error_info.get("code", "UNKNOWN"),
            )

        # Success response
        return IpcResponse(
            success=True,
            response_type=response_type,
            data=response,
        )

    # =========================================================================
    # Basic Commands
    # =========================================================================

    async def ping(self) -> IpcResponse:
        """Ping the server"""
        return await self._send_command({"type": "ping"})

    async def status(self) -> IpcResponse:
        """Get server status"""
        return await self._send_command({"type": "status"})

    async def get_capabilities(self) -> IpcResponse:
        """Get server capabilities"""
        return await self._send_command({"type": "get_capabilities"})

    async def get_stats(self) -> IpcResponse:
        """Get connection statistics"""
        return await self._send_command({"type": "get_stats"})

    async def get_outbound_stats(self) -> Dict[str, OutboundStats]:
        """Get per-outbound traffic statistics.

        Returns:
            Dict mapping outbound tag to OutboundStats
        """
        response = await self._send_command({"type": "get_outbound_stats"})
        if not response.success:
            return {}

        result = {}
        if response.data and "outbounds" in response.data:
            for tag, data in response.data["outbounds"].items():
                result[tag] = OutboundStats(
                    bytes_uploaded=data.get("bytes_uploaded", 0),
                    bytes_downloaded=data.get("bytes_downloaded", 0),
                    connections_total=data.get("connections_total", 0),
                    connections_active=data.get("connections_active", 0),
                    errors=data.get("errors", 0),
                    last_activity_ms=data.get("last_activity_ms", 0),
                )
        return result

    # =========================================================================
    # Outbound Management
    # =========================================================================

    async def list_outbounds(self) -> List[OutboundInfo]:
        """List all outbounds"""
        response = await self._send_command({"type": "list_outbounds"})
        if not response.success:
            return []

        result = []
        if response.data and "outbounds" in response.data:
            for item in response.data["outbounds"]:
                result.append(OutboundInfo(
                    tag=item.get("tag", ""),
                    outbound_type=item.get("outbound_type", ""),
                    enabled=item.get("enabled", False),
                    health=item.get("health", "unknown"),
                    active_connections=item.get("active_connections", 0),
                    total_connections=item.get("total_connections", 0),
                    bind_interface=item.get("bind_interface"),
                    routing_mark=item.get("routing_mark"),
                ))
        return result

    async def get_outbound(self, tag: str) -> Optional[OutboundInfo]:
        """Get info for a specific outbound"""
        response = await self._send_command({"type": "get_outbound", "tag": tag})
        if not response.success or not response.data:
            return None

        item = response.data
        return OutboundInfo(
            tag=item.get("tag", tag),
            outbound_type=item.get("outbound_type", ""),
            enabled=item.get("enabled", False),
            health=item.get("health", "unknown"),
            active_connections=item.get("active_connections", 0),
            total_connections=item.get("total_connections", 0),
            bind_interface=item.get("bind_interface"),
            routing_mark=item.get("routing_mark"),
        )

    async def remove_outbound(self, tag: str) -> IpcResponse:
        """Remove an outbound immediately (use drain_outbound for graceful removal)"""
        return await self._send_command({"type": "remove_outbound", "tag": tag})

    async def enable_outbound(self, tag: str) -> IpcResponse:
        """Enable an outbound"""
        return await self._send_command({"type": "enable_outbound", "tag": tag})

    async def disable_outbound(self, tag: str) -> IpcResponse:
        """Disable an outbound"""
        return await self._send_command({"type": "disable_outbound", "tag": tag})

    # =========================================================================
    # Phase 3.3/3.4: WireGuard and SOCKS5 Outbound Management
    # =========================================================================

    async def add_wireguard_outbound(
        self,
        tag: str,
        interface: str,
        routing_mark: Optional[int] = None,
        routing_table: Optional[int] = None,
    ) -> IpcResponse:
        """Add a WireGuard outbound using DirectOutbound with bind_interface.

        Args:
            tag: Unique tag for this outbound
            interface: WireGuard interface name (e.g., "wg-pia-us-east")
            routing_mark: Optional routing mark for policy routing
            routing_table: Optional routing table for policy routing

        Returns:
            IpcResponse indicating success or failure
        """
        command = {
            "type": "add_wireguard_outbound",
            "tag": tag,
            "interface": interface,
        }
        if routing_mark is not None:
            command["routing_mark"] = routing_mark
        if routing_table is not None:
            command["routing_table"] = routing_table

        return await self._send_command(command)

    async def add_socks5_outbound(
        self,
        tag: str,
        server_addr: str,
        username: Optional[str] = None,
        password: Optional[str] = None,
        connect_timeout_secs: int = 10,
        idle_timeout_secs: int = 300,
        pool_max_size: int = 32,
    ) -> IpcResponse:
        """Add a SOCKS5 outbound with connection pooling.

        Args:
            tag: Unique tag for this outbound
            server_addr: SOCKS5 server address (host:port)
            username: Optional username for authentication
            password: Optional password for authentication
            connect_timeout_secs: Connection timeout in seconds
            idle_timeout_secs: Idle connection timeout in seconds
            pool_max_size: Maximum pool size

        Returns:
            IpcResponse indicating success or failure
        """
        command = {
            "type": "add_socks5_outbound",
            "tag": tag,
            "server_addr": server_addr,
            "connect_timeout_secs": connect_timeout_secs,
            "idle_timeout_secs": idle_timeout_secs,
            "pool_max_size": pool_max_size,
        }
        if username is not None:
            command["username"] = username
        if password is not None:
            command["password"] = password

        return await self._send_command(command)

    async def drain_outbound(self, tag: str, timeout_secs: int = 30) -> DrainResult:
        """Drain an outbound gracefully before removal.

        Waits for existing connections to complete (up to timeout),
        then removes the outbound. New connections are rejected during drain.

        Args:
            tag: Outbound tag to drain
            timeout_secs: Timeout in seconds (connections are forcefully closed after this)

        Returns:
            DrainResult with drain statistics
        """
        response = await self._send_command({
            "type": "drain_outbound",
            "tag": tag,
            "timeout_secs": timeout_secs,
        })

        if not response.success:
            return DrainResult(success=False)

        if response.data:
            return DrainResult(
                success=response.data.get("success", True),
                drained_count=response.data.get("drained_count", 0),
                force_closed_count=response.data.get("force_closed_count", 0),
                drain_time_ms=response.data.get("drain_time_ms", 0),
            )
        return DrainResult(success=True)

    async def get_pool_stats(self, tag: Optional[str] = None) -> IpcResponse:
        """Get connection pool statistics for SOCKS5 outbounds.

        Args:
            tag: Optional outbound tag (returns all if None)

        Returns:
            IpcResponse with pool statistics
        """
        command = {"type": "get_pool_stats"}
        if tag is not None:
            command["tag"] = tag
        return await self._send_command(command)

    # =========================================================================
    # Routing Management
    # =========================================================================

    async def update_routing(
        self,
        rules: List[Union[RuleConfig, Dict[str, Any]]],
        default_outbound: str,
    ) -> UpdateRoutingResult:
        """Update routing rules atomically.

        Replaces the current routing configuration with new rules.
        Uses ArcSwap for lock-free hot-reload.

        Args:
            rules: List of RuleConfig or dict with rule configuration
            default_outbound: Default outbound for unmatched traffic

        Returns:
            UpdateRoutingResult with update statistics
        """
        # Convert RuleConfig to dict if needed
        rule_dicts = []
        for rule in rules:
            if isinstance(rule, RuleConfig):
                rule_dicts.append(rule.to_dict())
            else:
                rule_dicts.append(rule)

        response = await self._send_command({
            "type": "update_routing",
            "rules": rule_dicts,
            "default_outbound": default_outbound,
        })

        if not response.success:
            return UpdateRoutingResult(success=False)

        if response.data:
            return UpdateRoutingResult(
                success=response.data.get("success", True),
                version=response.data.get("version", 0),
                rule_count=response.data.get("rule_count", 0),
                default_outbound=response.data.get("default_outbound", default_outbound),
            )
        return UpdateRoutingResult(success=True)

    async def set_default_outbound(self, tag: str) -> IpcResponse:
        """Set the default outbound for unmatched traffic.

        Changes only the default outbound without modifying rules.

        Args:
            tag: New default outbound tag

        Returns:
            IpcResponse indicating success or failure
        """
        return await self._send_command({
            "type": "set_default_outbound",
            "tag": tag,
        })

    async def get_rule_stats(self) -> IpcResponse:
        """Get rule engine statistics."""
        return await self._send_command({"type": "get_rule_stats"})

    async def test_match(
        self,
        dest_port: int,
        protocol: str = "tcp",
        domain: Optional[str] = None,
        dest_ip: Optional[str] = None,
        sniffed_protocol: Optional[str] = None,
    ) -> IpcResponse:
        """Test rule matching for debugging.

        Args:
            dest_port: Destination port
            protocol: Transport protocol (tcp/udp)
            domain: Domain name (optional)
            dest_ip: Destination IP (optional)
            sniffed_protocol: Sniffed protocol (tls/http/quic, optional)

        Returns:
            IpcResponse with match result
        """
        command = {
            "type": "test_match",
            "dest_port": dest_port,
            "protocol": protocol,
        }
        if domain is not None:
            command["domain"] = domain
        if dest_ip is not None:
            command["dest_ip"] = dest_ip
        if sniffed_protocol is not None:
            command["sniffed_protocol"] = sniffed_protocol

        return await self._send_command(command)

    # =========================================================================
    # Health Monitoring
    # =========================================================================

    async def get_outbound_health(self) -> List[OutboundHealthInfo]:
        """Get health status for all outbounds.

        Returns:
            List of OutboundHealthInfo for each outbound
        """
        response = await self._send_command({"type": "get_outbound_health"})
        if not response.success:
            return []

        result = []
        if response.data and "outbounds" in response.data:
            for item in response.data["outbounds"]:
                result.append(OutboundHealthInfo(
                    tag=item.get("tag", ""),
                    outbound_type=item.get("outbound_type", ""),
                    health=item.get("health", "unknown"),
                    enabled=item.get("enabled", False),
                    active_connections=item.get("active_connections", 0),
                    last_check=item.get("last_check"),
                    error=item.get("error"),
                ))
        return result

    # =========================================================================
    # Prometheus Metrics
    # =========================================================================

    async def get_prometheus_metrics(self) -> Optional[PrometheusMetricsResponse]:
        """Get Prometheus-format metrics from rust-router.

        Returns:
            PrometheusMetricsResponse with metrics_text and timestamp_ms,
            or None if the request fails
        """
        response = await self._send_command({"type": "get_prometheus_metrics"})
        if not response.success:
            return None

        if response.data:
            return PrometheusMetricsResponse(
                metrics_text=response.data.get("metrics_text", ""),
                timestamp_ms=response.data.get("timestamp_ms", 0),
            )
        return None

    # =========================================================================
    # Egress Change Notifications
    # =========================================================================

    async def notify_egress_change(
        self,
        action: str,
        tag: str,
        egress_type: str,
    ) -> IpcResponse:
        """Notify rust-router about egress configuration change from Python.

        Args:
            action: Action type ("added", "removed", "updated")
            tag: Outbound tag affected
            egress_type: Egress type (pia, custom, warp, v2ray, direct, openvpn)

        Returns:
            IpcResponse indicating success or failure
        """
        return await self._send_command({
            "type": "notify_egress_change",
            "action": action,
            "tag": tag,
            "egress_type": egress_type,
        })

    # =========================================================================
    # Lifecycle Commands
    # =========================================================================

    async def reload(self, config_path: str) -> IpcResponse:
        """Reload configuration from file."""
        return await self._send_command({
            "type": "reload",
            "config_path": config_path,
        })

    async def shutdown(self, drain_timeout_secs: Optional[int] = None) -> IpcResponse:
        """Request graceful shutdown.

        Args:
            drain_timeout_secs: Optional drain timeout in seconds

        Returns:
            IpcResponse indicating shutdown initiated
        """
        command = {"type": "shutdown"}
        if drain_timeout_secs is not None:
            command["drain_timeout_secs"] = drain_timeout_secs
        return await self._send_command(command)


# =============================================================================
# Convenience functions for one-off operations
# =============================================================================

async def ping(socket_path: Optional[str] = None) -> bool:
    """Ping rust-router and return True if healthy"""
    try:
        async with RustRouterClient(socket_path) as client:
            response = await client.ping()
            return response.success
    except Exception:
        return False


async def get_status(socket_path: Optional[str] = None) -> Optional[Dict[str, Any]]:
    """Get rust-router status"""
    try:
        async with RustRouterClient(socket_path) as client:
            response = await client.status()
            if response.success and response.data:
                return response.data
            return None
    except Exception:
        return None


async def reload_config(config_path: str, socket_path: Optional[str] = None) -> bool:
    """Reload rust-router configuration"""
    try:
        async with RustRouterClient(socket_path) as client:
            response = await client.reload(config_path)
            return response.success
    except Exception:
        return False


async def is_available(socket_path: Optional[str] = None) -> bool:
    """Check if rust-router is available (socket exists and responds to ping)"""
    socket_path = socket_path or os.environ.get("RUST_ROUTER_SOCKET", DEFAULT_SOCKET_PATH)
    if not Path(socket_path).exists():
        return False
    return await ping(socket_path)


async def get_prometheus_metrics(socket_path: Optional[str] = None) -> Optional[PrometheusMetricsResponse]:
    """Get Prometheus metrics from rust-router"""
    try:
        async with RustRouterClient(socket_path) as client:
            return await client.get_prometheus_metrics()
    except Exception:
        return None


# =============================================================================
# Unit tests
# =============================================================================

if __name__ == "__main__":
    import argparse
    import sys
    import tempfile
    import unittest
    from unittest.mock import AsyncMock, MagicMock, patch

    class TestRuleConfig(unittest.TestCase):
        """Test RuleConfig dataclass"""

        def test_to_dict_basic(self):
            """Test basic to_dict conversion"""
            rule = RuleConfig("domain_suffix", "google.com", "proxy")
            d = rule.to_dict()
            self.assertEqual(d["rule_type"], "domain_suffix")
            self.assertEqual(d["target"], "google.com")
            self.assertEqual(d["outbound"], "proxy")
            self.assertEqual(d["priority"], 0)
            self.assertTrue(d["enabled"])

        def test_to_dict_with_priority(self):
            """Test to_dict with custom priority"""
            rule = RuleConfig("domain_suffix", "google.com", "proxy", priority=10)
            d = rule.to_dict()
            self.assertEqual(d["priority"], 10)

        def test_to_dict_disabled(self):
            """Test to_dict with disabled rule"""
            rule = RuleConfig("geoip", "CN", "block", enabled=False)
            d = rule.to_dict()
            self.assertFalse(d["enabled"])

    class TestJitteredBackoff(unittest.TestCase):
        """Test calculate_jittered_backoff function"""

        def test_positive_delays(self):
            """All delays should be positive"""
            for i in range(10):
                delay = calculate_jittered_backoff(i)
                self.assertGreater(delay, 0)

        def test_max_delay_bounded(self):
            """Max delay should be bounded"""
            delay = calculate_jittered_backoff(100)
            self.assertLessEqual(delay, MAX_RETRY_DELAY * (1 + JITTER_FACTOR))

        def test_exponential_growth(self):
            """Earlier attempts should have shorter base delay"""
            # Run multiple times to reduce jitter effects
            delay0_avg = sum(calculate_jittered_backoff(0) for _ in range(100)) / 100
            delay2_avg = sum(calculate_jittered_backoff(2) for _ in range(100)) / 100
            self.assertLess(delay0_avg, delay2_avg)

        def test_jitter_bounds(self):
            """Jitter should be within expected bounds"""
            for _ in range(100):
                delay = calculate_jittered_backoff(0)
                min_expected = BASE_RETRY_DELAY * (1 - JITTER_FACTOR)
                max_expected = BASE_RETRY_DELAY * (1 + JITTER_FACTOR)
                self.assertGreaterEqual(delay, max(0.1, min_expected))
                self.assertLessEqual(delay, max_expected)

        def test_minimum_delay(self):
            """Delay should never be below 0.1s"""
            for i in range(10):
                delay = calculate_jittered_backoff(i, base_delay=0.01)
                self.assertGreaterEqual(delay, 0.1)

    class TestIpcResponse(unittest.TestCase):
        """Test IpcResponse dataclass"""

        def test_success_response(self):
            """Test successful response"""
            resp = IpcResponse(success=True, response_type="pong")
            self.assertTrue(resp.success)
            self.assertEqual(resp.response_type, "pong")
            self.assertIsNone(resp.error)

        def test_error_response(self):
            """Test error response"""
            resp = IpcResponse(
                success=False,
                response_type="error",
                error="Not found",
                error_code="NOT_FOUND"
            )
            self.assertFalse(resp.success)
            self.assertEqual(resp.error, "Not found")
            self.assertEqual(resp.error_code, "NOT_FOUND")

        def test_response_with_data(self):
            """Test response with data"""
            resp = IpcResponse(success=True, response_type="status", data={"uptime": 3600})
            self.assertEqual(resp.data["uptime"], 3600)

    class TestDataclasses(unittest.TestCase):
        """Test other dataclasses"""

        def test_outbound_stats_defaults(self):
            """Test OutboundStats defaults"""
            stats = OutboundStats()
            self.assertEqual(stats.bytes_uploaded, 0)
            self.assertEqual(stats.bytes_downloaded, 0)
            self.assertEqual(stats.connections_total, 0)

        def test_outbound_info(self):
            """Test OutboundInfo"""
            info = OutboundInfo(
                tag="us-east",
                outbound_type="wireguard",
                enabled=True,
                health="healthy",
                active_connections=5
            )
            self.assertEqual(info.tag, "us-east")
            self.assertEqual(info.active_connections, 5)

        def test_drain_result(self):
            """Test DrainResult"""
            result = DrainResult(success=True, drained_count=10, force_closed_count=2)
            self.assertTrue(result.success)
            self.assertEqual(result.drained_count, 10)

        def test_update_routing_result(self):
            """Test UpdateRoutingResult"""
            result = UpdateRoutingResult(success=True, version=5, rule_count=100)
            self.assertTrue(result.success)
            self.assertEqual(result.version, 5)

        def test_prometheus_metrics_response(self):
            """Test PrometheusMetricsResponse"""
            metrics = PrometheusMetricsResponse(
                metrics_text="# HELP test_metric\ntest_metric 42\n",
                timestamp_ms=1704067200000
            )
            self.assertEqual(metrics.metrics_text, "# HELP test_metric\ntest_metric 42\n")
            self.assertEqual(metrics.timestamp_ms, 1704067200000)

        def test_prometheus_metrics_response_empty(self):
            """Test PrometheusMetricsResponse with empty metrics"""
            metrics = PrometheusMetricsResponse(metrics_text="", timestamp_ms=0)
            self.assertEqual(metrics.metrics_text, "")
            self.assertEqual(metrics.timestamp_ms, 0)

    class TestExceptions(unittest.TestCase):
        """Test exception hierarchy"""

        def test_ipc_error_base(self):
            """Test IpcError as base exception"""
            err = IpcError("test error")
            self.assertIsInstance(err, Exception)
            self.assertEqual(str(err), "test error")

        def test_connection_error(self):
            """Test IpcConnectionError inherits from IpcError"""
            err = IpcConnectionError("connection failed")
            self.assertIsInstance(err, IpcError)
            self.assertIsInstance(err, Exception)

        def test_timeout_error(self):
            """Test IpcTimeoutError inherits from IpcError"""
            err = IpcTimeoutError("timeout")
            self.assertIsInstance(err, IpcError)
            self.assertIsInstance(err, Exception)

        def test_protocol_error(self):
            """Test ProtocolError inherits from IpcError"""
            err = ProtocolError("malformed")
            self.assertIsInstance(err, IpcError)

        def test_no_shadow_builtins(self):
            """Ensure custom exceptions don't shadow builtins"""
            # These should be the built-in exceptions
            import builtins
            self.assertIsNot(IpcConnectionError, builtins.ConnectionError)
            self.assertIsNot(IpcTimeoutError, builtins.TimeoutError)

    class TestClientResponseParsing(unittest.TestCase):
        """Test RustRouterClient response parsing"""

        def setUp(self):
            self.client = RustRouterClient()

        def test_parse_success_response(self):
            """Test parsing success response"""
            resp = self.client._parse_response({"type": "pong"})
            self.assertTrue(resp.success)
            self.assertEqual(resp.response_type, "pong")

        def test_parse_error_response(self):
            """Test parsing error response"""
            resp = self.client._parse_response({
                "type": "error",
                "Error": {"code": "NOT_FOUND", "message": "Outbound not found"}
            })
            self.assertFalse(resp.success)
            self.assertEqual(resp.error_code, "NOT_FOUND")
            self.assertEqual(resp.error, "Outbound not found")

        def test_parse_status_response(self):
            """Test parsing status response"""
            resp = self.client._parse_response({
                "type": "status",
                "uptime": 3600,
                "connections": 100
            })
            self.assertTrue(resp.success)
            self.assertEqual(resp.response_type, "status")
            self.assertEqual(resp.data["uptime"], 3600)

        def test_parse_unknown_type(self):
            """Test parsing response with unknown type"""
            resp = self.client._parse_response({})
            self.assertTrue(resp.success)
            self.assertEqual(resp.response_type, "unknown")

        def test_parse_error_without_nested(self):
            """Test parsing error response without nested Error"""
            resp = self.client._parse_response({
                "type": "error",
                "message": "Direct error",
                "code": "DIRECT_ERROR"
            })
            self.assertFalse(resp.success)

    class TestClientProtocol(unittest.TestCase):
        """Test client protocol encoding"""

        def test_encode_command(self):
            """Test command encoding"""
            command = {"type": "ping"}
            json_data = json.dumps(command).encode('utf-8')
            length_prefix = struct.pack('>I', len(json_data))
            # Verify length prefix is 4 bytes
            self.assertEqual(len(length_prefix), 4)
            # Verify we can decode it back
            decoded_len = struct.unpack('>I', length_prefix)[0]
            self.assertEqual(decoded_len, len(json_data))

        def test_message_size_limit(self):
            """Test message size limit detection"""
            # This is tested indirectly - large messages should fail
            large_command = {"type": "test", "data": "x" * (MAX_MESSAGE_SIZE + 1)}
            json_data = json.dumps(large_command).encode('utf-8')
            self.assertGreater(len(json_data), MAX_MESSAGE_SIZE)

    class TestClientConnection(unittest.IsolatedAsyncioTestCase):
        """Test client connection handling"""

        async def test_connect_socket_not_found(self):
            """Test connect when socket doesn't exist"""
            client = RustRouterClient(socket_path="/nonexistent/socket.sock")
            result = await client.connect()
            self.assertFalse(result)

        async def test_connect_timeout(self):
            """Test connection timeout handling"""
            with tempfile.NamedTemporaryFile(suffix=".sock", delete=False) as f:
                socket_path = f.name

            # Create socket file but nothing listening
            from pathlib import Path
            Path(socket_path).touch()

            client = RustRouterClient(
                socket_path=socket_path,
                connect_timeout=0.1,
                max_retries=1
            )
            result = await client.connect()
            self.assertFalse(result)

            # Cleanup
            Path(socket_path).unlink(missing_ok=True)

        async def test_is_connected_property(self):
            """Test is_connected property"""
            client = RustRouterClient()
            self.assertFalse(client.is_connected)

        async def test_disconnect_when_not_connected(self):
            """Test disconnect when not connected"""
            client = RustRouterClient()
            # Should not raise
            await client.disconnect()
            self.assertFalse(client.is_connected)

        async def test_context_manager_without_server(self):
            """Test async context manager when server unavailable"""
            client = RustRouterClient(socket_path="/nonexistent/socket.sock")
            async with client as c:
                self.assertFalse(c.is_connected)

    class TestClientCommands(unittest.IsolatedAsyncioTestCase):
        """Test client command methods with mocked connection"""

        async def asyncSetUp(self):
            self.client = RustRouterClient()
            self.client._connected = False  # Ensure not connected

        async def test_ping_not_connected(self):
            """Test ping when not connected"""
            response = await self.client.ping()
            self.assertFalse(response.success)
            self.assertEqual(response.error_code, "NOT_CONNECTED")

        async def test_status_not_connected(self):
            """Test status when not connected"""
            response = await self.client.status()
            self.assertFalse(response.success)

        async def test_add_wireguard_outbound_command_format(self):
            """Test add_wireguard_outbound command format"""
            # Mock the _send_command method
            self.client._send_command = AsyncMock(
                return_value=IpcResponse(success=True, response_type="success")
            )
            self.client._connected = True

            await self.client.add_wireguard_outbound(
                "us-east", "wg-pia-us-east", routing_mark=200
            )

            # Verify command format
            call_args = self.client._send_command.call_args[0][0]
            self.assertEqual(call_args["type"], "add_wireguard_outbound")
            self.assertEqual(call_args["tag"], "us-east")
            self.assertEqual(call_args["interface"], "wg-pia-us-east")
            self.assertEqual(call_args["routing_mark"], 200)

        async def test_add_socks5_outbound_command_format(self):
            """Test add_socks5_outbound command format"""
            self.client._send_command = AsyncMock(
                return_value=IpcResponse(success=True, response_type="success")
            )
            self.client._connected = True

            await self.client.add_socks5_outbound(
                "v2ray-proxy", "127.0.0.1:37101",
                username="user", password="pass"
            )

            call_args = self.client._send_command.call_args[0][0]
            self.assertEqual(call_args["type"], "add_socks5_outbound")
            self.assertEqual(call_args["server_addr"], "127.0.0.1:37101")
            self.assertEqual(call_args["username"], "user")

        async def test_drain_outbound_success(self):
            """Test drain_outbound with successful response"""
            self.client._send_command = AsyncMock(
                return_value=IpcResponse(
                    success=True,
                    response_type="drain_result",
                    data={"success": True, "drained_count": 5, "force_closed_count": 1}
                )
            )
            self.client._connected = True

            result = await self.client.drain_outbound("old-proxy", timeout_secs=30)
            self.assertTrue(result.success)
            self.assertEqual(result.drained_count, 5)
            self.assertEqual(result.force_closed_count, 1)

        async def test_drain_outbound_failure(self):
            """Test drain_outbound with failed response"""
            self.client._send_command = AsyncMock(
                return_value=IpcResponse(success=False, response_type="error", error="Not found")
            )
            self.client._connected = True

            result = await self.client.drain_outbound("nonexistent")
            self.assertFalse(result.success)

        async def test_update_routing_with_rule_configs(self):
            """Test update_routing with RuleConfig objects"""
            self.client._send_command = AsyncMock(
                return_value=IpcResponse(
                    success=True,
                    response_type="update_routing_result",
                    data={"success": True, "version": 5, "rule_count": 2}
                )
            )
            self.client._connected = True

            rules = [
                RuleConfig("domain_suffix", "google.com", "proxy"),
                RuleConfig("geoip", "CN", "direct")
            ]
            result = await self.client.update_routing(rules, "direct")

            self.assertTrue(result.success)
            self.assertEqual(result.version, 5)
            self.assertEqual(result.rule_count, 2)

        async def test_update_routing_with_dicts(self):
            """Test update_routing with dict objects"""
            self.client._send_command = AsyncMock(
                return_value=IpcResponse(success=True, response_type="success", data={})
            )
            self.client._connected = True

            rules = [
                {"rule_type": "domain_suffix", "target": "google.com", "outbound": "proxy"}
            ]
            result = await self.client.update_routing(rules, "direct")
            self.assertTrue(result.success)

        async def test_notify_egress_change_command(self):
            """Test notify_egress_change command format"""
            self.client._send_command = AsyncMock(
                return_value=IpcResponse(success=True, response_type="success")
            )
            self.client._connected = True

            await self.client.notify_egress_change("added", "us-east", "pia")

            call_args = self.client._send_command.call_args[0][0]
            self.assertEqual(call_args["type"], "notify_egress_change")
            self.assertEqual(call_args["action"], "added")
            self.assertEqual(call_args["tag"], "us-east")
            self.assertEqual(call_args["egress_type"], "pia")

        async def test_get_outbound_health_parsing(self):
            """Test get_outbound_health response parsing"""
            self.client._send_command = AsyncMock(
                return_value=IpcResponse(
                    success=True,
                    response_type="health",
                    data={
                        "outbounds": [
                            {"tag": "us-east", "outbound_type": "wireguard", "health": "healthy", "enabled": True},
                            {"tag": "block", "outbound_type": "block", "health": "healthy", "enabled": True}
                        ]
                    }
                )
            )
            self.client._connected = True

            health = await self.client.get_outbound_health()
            self.assertEqual(len(health), 2)
            self.assertEqual(health[0].tag, "us-east")
            self.assertEqual(health[0].health, "healthy")

        async def test_list_outbounds_parsing(self):
            """Test list_outbounds response parsing"""
            self.client._send_command = AsyncMock(
                return_value=IpcResponse(
                    success=True,
                    response_type="list_outbounds",
                    data={
                        "outbounds": [
                            {"tag": "direct", "outbound_type": "direct", "enabled": True, "health": "healthy"},
                        ]
                    }
                )
            )
            self.client._connected = True

            outbounds = await self.client.list_outbounds()
            self.assertEqual(len(outbounds), 1)
            self.assertEqual(outbounds[0].tag, "direct")

        async def test_test_match_command_format(self):
            """Test test_match command format"""
            self.client._send_command = AsyncMock(
                return_value=IpcResponse(success=True, response_type="test_match")
            )
            self.client._connected = True

            await self.client.test_match(
                dest_port=443,
                protocol="tcp",
                domain="google.com",
                sniffed_protocol="tls"
            )

            call_args = self.client._send_command.call_args[0][0]
            self.assertEqual(call_args["dest_port"], 443)
            self.assertEqual(call_args["domain"], "google.com")
            self.assertEqual(call_args["sniffed_protocol"], "tls")

        async def test_get_prometheus_metrics_success(self):
            """Test get_prometheus_metrics with successful response"""
            self.client._send_command = AsyncMock(
                return_value=IpcResponse(
                    success=True,
                    response_type="prometheus_metrics",
                    data={
                        "metrics_text": "# HELP rust_router_connections_total\nrust_router_connections_total 100\n",
                        "timestamp_ms": 1704067200000
                    }
                )
            )
            self.client._connected = True

            result = await self.client.get_prometheus_metrics()
            self.assertIsNotNone(result)
            self.assertIn("rust_router_connections_total", result.metrics_text)
            self.assertEqual(result.timestamp_ms, 1704067200000)

        async def test_get_prometheus_metrics_failure(self):
            """Test get_prometheus_metrics with failed response"""
            self.client._send_command = AsyncMock(
                return_value=IpcResponse(success=False, response_type="error", error="Connection failed")
            )
            self.client._connected = True

            result = await self.client.get_prometheus_metrics()
            self.assertIsNone(result)

        async def test_get_prometheus_metrics_command_format(self):
            """Test get_prometheus_metrics command format"""
            self.client._send_command = AsyncMock(
                return_value=IpcResponse(
                    success=True,
                    response_type="prometheus_metrics",
                    data={"metrics_text": "", "timestamp_ms": 0}
                )
            )
            self.client._connected = True

            await self.client.get_prometheus_metrics()

            call_args = self.client._send_command.call_args[0][0]
            self.assertEqual(call_args["type"], "get_prometheus_metrics")

        async def test_get_prometheus_metrics_empty_data(self):
            """Test get_prometheus_metrics with empty data field"""
            self.client._send_command = AsyncMock(
                return_value=IpcResponse(
                    success=True,
                    response_type="prometheus_metrics",
                    data=None
                )
            )
            self.client._connected = True

            result = await self.client.get_prometheus_metrics()
            self.assertIsNone(result)

    class TestConvenienceFunctions(unittest.IsolatedAsyncioTestCase):
        """Test convenience functions"""

        async def test_ping_function_unavailable(self):
            """Test ping function when server unavailable"""
            result = await ping("/nonexistent/socket.sock")
            self.assertFalse(result)

        async def test_get_status_unavailable(self):
            """Test get_status when server unavailable"""
            result = await get_status("/nonexistent/socket.sock")
            self.assertIsNone(result)

        async def test_is_available_no_socket(self):
            """Test is_available when socket doesn't exist"""
            result = await is_available("/nonexistent/socket.sock")
            self.assertFalse(result)

        async def test_reload_config_unavailable(self):
            """Test reload_config when server unavailable"""
            result = await reload_config("/etc/config.json", "/nonexistent/socket.sock")
            self.assertFalse(result)

        async def test_get_prometheus_metrics_unavailable(self):
            """Test get_prometheus_metrics when server unavailable"""
            result = await get_prometheus_metrics("/nonexistent/socket.sock")
            self.assertIsNone(result)

    # CLI entry point
    parser = argparse.ArgumentParser(
        description="Rust Router IPC Client (v3.1 - Phase 3.4 + Prometheus Metrics)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s ping                        # Health check
  %(prog)s status                      # Get server status
  %(prog)s stats                       # Get connection statistics
  %(prog)s outbound-stats              # Get per-outbound traffic stats
  %(prog)s list-outbounds              # List all outbounds
  %(prog)s health                      # Get outbound health status
  %(prog)s metrics                     # Get Prometheus metrics
  %(prog)s reload -c /path/to/cfg      # Reload configuration
  %(prog)s shutdown                    # Request graceful shutdown
  %(prog)s test                        # Run comprehensive unit tests
        """
    )
    parser.add_argument(
        "--socket", "-s",
        default=DEFAULT_SOCKET_PATH,
        help="IPC socket path"
    )
    parser.add_argument(
        "command",
        choices=["ping", "status", "stats", "outbound-stats", "list-outbounds",
                 "health", "metrics", "reload", "shutdown", "test"],
        help="Command to execute"
    )
    parser.add_argument(
        "--config", "-c",
        help="Config file path (for reload command)"
    )
    parser.add_argument(
        "--timeout", "-t",
        type=float,
        default=DEFAULT_REQUEST_TIMEOUT,
        help=f"Request timeout in seconds (default: {DEFAULT_REQUEST_TIMEOUT})"
    )

    args = parser.parse_args()

    def error(msg: str) -> None:
        """Print error message to stderr"""
        print(msg, file=sys.stderr)

    def run_tests():
        """Run unit tests (synchronous function for proper test runner)"""
        print("Running comprehensive IPC client unit tests...")
        print("=" * 60)

        # Create test suite
        loader = unittest.TestLoader()
        suite = unittest.TestSuite()

        # Add all test classes
        suite.addTests(loader.loadTestsFromTestCase(TestRuleConfig))
        suite.addTests(loader.loadTestsFromTestCase(TestJitteredBackoff))
        suite.addTests(loader.loadTestsFromTestCase(TestIpcResponse))
        suite.addTests(loader.loadTestsFromTestCase(TestDataclasses))
        suite.addTests(loader.loadTestsFromTestCase(TestExceptions))
        suite.addTests(loader.loadTestsFromTestCase(TestClientResponseParsing))
        suite.addTests(loader.loadTestsFromTestCase(TestClientProtocol))
        suite.addTests(loader.loadTestsFromTestCase(TestClientConnection))
        suite.addTests(loader.loadTestsFromTestCase(TestClientCommands))
        suite.addTests(loader.loadTestsFromTestCase(TestConvenienceFunctions))

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

        try:
            async with RustRouterClient(args.socket, request_timeout=args.timeout) as client:
                if args.command == "ping":
                    response = await client.ping()
                    if response.success:
                        print("pong")
                        return 0
                    else:
                        error(f"Error: {response.error}")
                        return 1

                elif args.command == "status":
                    response = await client.status()
                    if response.success:
                        print(json.dumps(response.data, indent=2))
                        return 0
                    else:
                        error(f"Error: {response.error}")
                        return 1

                elif args.command == "stats":
                    response = await client.get_stats()
                    if response.success:
                        print(json.dumps(response.data, indent=2))
                        return 0
                    else:
                        error(f"Error: {response.error}")
                        return 1

                elif args.command == "outbound-stats":
                    stats = await client.get_outbound_stats()
                    if not stats:
                        print("No outbound statistics available")
                        return 0
                    for tag, s in stats.items():
                        print(f"{tag}:")
                        print(f"  Upload: {s.bytes_uploaded} bytes")
                        print(f"  Download: {s.bytes_downloaded} bytes")
                        print(f"  Total connections: {s.connections_total}")
                        print(f"  Active connections: {s.connections_active}")
                        print(f"  Errors: {s.errors}")
                        print(f"  Last activity: {s.last_activity_ms}ms ago")
                    return 0

                elif args.command == "list-outbounds":
                    outbounds = await client.list_outbounds()
                    if not outbounds:
                        print("No outbounds configured")
                        return 0
                    for o in outbounds:
                        status = "enabled" if o.enabled else "disabled"
                        print(f"{o.tag} ({o.outbound_type}): {o.health} [{status}]")
                        if o.bind_interface:
                            print(f"  interface: {o.bind_interface}")
                        if o.routing_mark:
                            print(f"  routing_mark: {o.routing_mark}")
                        print(f"  connections: {o.active_connections} active, {o.total_connections} total")
                    return 0

                elif args.command == "health":
                    health = await client.get_outbound_health()
                    if not health:
                        print("No health data available")
                        return 0
                    for h in health:
                        status = "enabled" if h.enabled else "disabled"
                        print(f"{h.tag} ({h.outbound_type}): {h.health} [{status}]")
                        if h.error:
                            print(f"  error: {h.error}")
                        if h.last_check:
                            print(f"  last_check: {h.last_check}")
                    return 0

                elif args.command == "metrics":
                    metrics = await client.get_prometheus_metrics()
                    if metrics is None:
                        error("Error: Failed to retrieve Prometheus metrics")
                        return 1
                    print(metrics.metrics_text, end="")
                    return 0

                elif args.command == "reload":
                    if not args.config:
                        error("Error: --config required for reload")
                        return 1
                    response = await client.reload(args.config)
                    if response.success:
                        print("Configuration reloaded")
                        return 0
                    else:
                        error(f"Error: {response.error}")
                        return 1

                elif args.command == "shutdown":
                    response = await client.shutdown()
                    if response.success:
                        print("Shutdown requested")
                        return 0
                    else:
                        error(f"Error: {response.error}")
                        return 1

        except Exception as e:
            error(f"Error: {e}")
            return 1

    sys.exit(asyncio.run(main()))

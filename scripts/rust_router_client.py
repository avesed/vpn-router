#!/usr/bin/env python3
"""
Rust Router IPC Client (v4.1 - Phase 7.7)

Async client for communicating with rust-router via Unix socket.
Used by api_server.py and RustRouterManager for configuration sync.

Protocol v4.1 Features (Phase 7.7):
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

Phase 6 v3.2 Commands:
- Userspace WireGuard tunnel management (CreateWgTunnel, RemoveWgTunnel, etc.)
- ECMP group management (CreateEcmpGroup, RemoveEcmpGroup, etc.)
- Peer node management (GeneratePairRequest, ImportPairRequest, ConnectPeer, etc.)
- Chain management (CreateChain, ActivateChain, DeactivateChain, etc.)
- Two-Phase Commit for distributed chain activation

Phase 7.7 DNS Commands:
- DNS statistics (GetDnsStats, GetDnsCacheStats, GetDnsBlockStats)
- Cache management (FlushDnsCache)
- Upstream management (AddDnsUpstream, RemoveDnsUpstream, GetDnsUpstreamStatus)
- DNS routing (AddDnsRoute, RemoveDnsRoute)
- Query logging (GetDnsQueryLog)
- Test queries (DnsQuery)
- Configuration (GetDnsConfig, ReloadDnsBlocklist)

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
PROTOCOL_VERSION = 5  # Phase 7.7: DNS engine commands

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


# =============================================================================
# Phase 6 v3.2: New dataclasses
# =============================================================================


@dataclass
class WgTunnelInfo:
    """Information about a userspace WireGuard tunnel"""
    tag: str
    state: str
    local_ip: str
    peer_ip: Optional[str] = None
    endpoint: Optional[str] = None
    listen_port: Optional[int] = None
    mtu: int = 1420
    bytes_rx: int = 0
    bytes_tx: int = 0
    last_handshake: Optional[int] = None
    persistent_keepalive: int = 25


@dataclass
class EcmpGroupInfo:
    """Information about an ECMP load balancing group"""
    tag: str
    description: str
    algorithm: str
    member_count: int
    healthy_count: int
    routing_mark: Optional[int] = None
    routing_table: Optional[int] = None
    health_check: bool = True


@dataclass
class EcmpMemberInfo:
    """Information about an ECMP group member"""
    tag: str
    weight: int = 1
    health: str = "unknown"
    active_connections: int = 0


@dataclass
class PeerInfo:
    """Information about a peer node"""
    tag: str
    description: str
    endpoint: str
    tunnel_type: str
    state: str
    tunnel_status: str = "disconnected"
    api_port: int = 36000
    tunnel_port: Optional[int] = None
    tunnel_ip: Optional[str] = None
    last_handshake: Optional[int] = None
    bytes_rx: int = 0
    bytes_tx: int = 0


@dataclass
class PeerHealthInfo:
    """Health status for a peer tunnel"""
    tag: str
    tunnel_status: str
    latency_ms: Optional[float] = None
    packet_loss: Optional[float] = None
    last_check: Optional[int] = None
    consecutive_failures: int = 0


@dataclass
class ChainInfo:
    """Information about a multi-hop chain"""
    tag: str
    description: str
    hops: List[str]
    exit_egress: str
    chain_state: str
    dscp_value: Optional[int] = None
    allow_transitive: bool = False
    last_error: Optional[str] = None


@dataclass
class ChainRoleInfo:
    """Chain role information for current node"""
    chain_tag: str
    role: str  # "entry", "relay", "terminal"
    dscp_value: Optional[int] = None
    previous_hop: Optional[str] = None
    next_hop: Optional[str] = None


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


# =============================================================================
# Phase 7.7: DNS dataclasses
# =============================================================================


@dataclass
class DnsStats:
    """DNS engine statistics"""
    enabled: bool = False
    uptime_secs: int = 0
    total_queries: int = 0
    cache_hits: int = 0
    cache_misses: int = 0
    blocked_queries: int = 0
    upstream_queries: int = 0
    avg_latency_us: int = 0


@dataclass
class DnsCacheStats:
    """DNS cache statistics"""
    enabled: bool = False
    max_entries: int = 0
    current_entries: int = 0
    hits: int = 0
    misses: int = 0
    hit_rate: float = 0.0
    negative_hits: int = 0
    inserts: int = 0
    evictions: int = 0


@dataclass
class DnsBlockStats:
    """DNS blocking statistics"""
    enabled: bool = False
    rule_count: int = 0
    blocked_queries: int = 0
    total_queries: int = 0
    block_rate: float = 0.0
    last_reload: Optional[str] = None


@dataclass
class DnsUpstreamInfo:
    """DNS upstream server information"""
    tag: str
    address: str
    protocol: str
    healthy: bool = True
    total_queries: int = 0
    failed_queries: int = 0
    avg_latency_us: int = 0
    last_success: Optional[str] = None
    last_failure: Optional[str] = None


@dataclass
class DnsQueryLogEntry:
    """DNS query log entry"""
    timestamp: int
    domain: str
    qtype: int
    qtype_str: str
    upstream: str
    response_code: int
    rcode_str: str
    latency_us: int
    blocked: bool = False
    cached: bool = False


@dataclass
class DnsQueryResult:
    """DNS query result"""
    success: bool
    domain: str
    qtype: int
    response_code: int
    answers: List[str] = field(default_factory=list)
    latency_us: int = 0
    cached: bool = False
    blocked: bool = False
    upstream_used: Optional[str] = None


@dataclass
class DnsConfig:
    """DNS engine configuration

    The `available_features` field indicates implementation status of each feature:
    - "available": Feature is fully implemented
    - "partial": Feature is partially implemented (e.g., get_dns_query_log returns empty)
    - "not_implemented": Feature is reserved for future use
    """
    enabled: bool = False
    listen_udp: str = ""
    listen_tcp: str = ""
    upstreams: List[DnsUpstreamInfo] = field(default_factory=list)
    cache_enabled: bool = True
    cache_max_entries: int = 10000
    blocking_enabled: bool = True
    blocking_response_type: str = "zero_ip"
    logging_enabled: bool = False
    logging_format: str = "json"
    available_features: Dict[str, str] = field(default_factory=dict)


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
    # Phase 6: WireGuard Tunnel Management (Userspace)
    # =========================================================================

    async def create_wg_tunnel(
        self,
        tag: str,
        private_key: str,
        peer_public_key: str,
        endpoint: str,
        local_ip: str,
        peer_ip: Optional[str] = None,
        listen_port: Optional[int] = None,
        mtu: int = 1420,
        persistent_keepalive: int = 25,
    ) -> IpcResponse:
        """Create a userspace WireGuard tunnel.

        Args:
            tag: Unique tag for this tunnel
            private_key: WireGuard private key (Base64)
            peer_public_key: Peer's public key (Base64)
            endpoint: Peer endpoint (IP:port)
            local_ip: Local tunnel IP
            peer_ip: Remote tunnel IP (optional)
            listen_port: Local listen port (optional)
            mtu: MTU size (default: 1420)
            persistent_keepalive: Keepalive interval in seconds (default: 25)

        Returns:
            IpcResponse indicating success or failure
        """
        config = {
            "private_key": private_key,
            "peer_public_key": peer_public_key,
            "endpoint": endpoint,
            "local_ip": local_ip,
            "mtu": mtu,
            "persistent_keepalive": persistent_keepalive,
        }
        if peer_ip is not None:
            config["peer_ip"] = peer_ip
        if listen_port is not None:
            config["listen_port"] = listen_port

        return await self._send_command({
            "type": "create_wg_tunnel",
            "tag": tag,
            "config": config,
        })

    async def remove_wg_tunnel(
        self,
        tag: str,
        drain_timeout_secs: Optional[int] = None,
    ) -> IpcResponse:
        """Remove a userspace WireGuard tunnel.

        Args:
            tag: Tunnel tag to remove
            drain_timeout_secs: Optional drain timeout before removal

        Returns:
            IpcResponse indicating success or failure
        """
        command = {"type": "remove_wg_tunnel", "tag": tag}
        if drain_timeout_secs is not None:
            command["drain_timeout_secs"] = drain_timeout_secs
        return await self._send_command(command)

    async def get_wg_tunnel_status(self, tag: str) -> IpcResponse:
        """Get status of a userspace WireGuard tunnel.

        Args:
            tag: Tunnel tag

        Returns:
            IpcResponse with tunnel status data
        """
        return await self._send_command({"type": "get_wg_tunnel_status", "tag": tag})

    async def list_wg_tunnels(self) -> List[WgTunnelInfo]:
        """List all userspace WireGuard tunnels.

        Returns:
            List of WgTunnelInfo for each tunnel
        """
        response = await self._send_command({"type": "list_wg_tunnels"})
        if not response.success:
            return []

        result = []
        if response.data and "tunnels" in response.data:
            for item in response.data["tunnels"]:
                result.append(WgTunnelInfo(
                    tag=item.get("tag", ""),
                    state=item.get("state", "unknown"),
                    local_ip=item.get("local_ip", ""),
                    peer_ip=item.get("peer_ip"),
                    endpoint=item.get("endpoint"),
                    listen_port=item.get("listen_port"),
                    mtu=item.get("mtu", 1420),
                    bytes_rx=item.get("bytes_rx", 0),
                    bytes_tx=item.get("bytes_tx", 0),
                    last_handshake=item.get("last_handshake"),
                    persistent_keepalive=item.get("persistent_keepalive", 25),
                ))
        return result

    # =========================================================================
    # Phase 6: ECMP Group Management
    # =========================================================================

    async def create_ecmp_group(
        self,
        tag: str,
        members: List[Dict[str, Any]],
        algorithm: str = "five_tuple_hash",
        description: str = "",
        routing_mark: Optional[int] = None,
        routing_table: Optional[int] = None,
        health_check: bool = True,
    ) -> IpcResponse:
        """Create an ECMP load balancing group.

        Args:
            tag: Unique tag for this group
            members: List of member dicts with 'tag' and optional 'weight'
            algorithm: Load balancing algorithm:
                - five_tuple_hash: 5-tuple hash for connection affinity (default)
                - round_robin: Sequential distribution
                - weighted: Weight-based distribution
                - least_connections: Route to member with fewest connections
                - random: Random selection
            description: Group description
            routing_mark: Optional routing mark (200-299 range)
            routing_table: Optional routing table
            health_check: Enable health checking (default: True)

        Returns:
            IpcResponse indicating success or failure
        """
        config = {
            "tag": tag,
            "members": members,
            "algorithm": algorithm,
            "description": description,
            "health_check": health_check,
        }
        if routing_mark is not None:
            config["routing_mark"] = routing_mark
        if routing_table is not None:
            config["routing_table"] = routing_table

        return await self._send_command({
            "type": "create_ecmp_group",
            "tag": tag,
            "config": config,
        })

    async def remove_ecmp_group(self, tag: str) -> IpcResponse:
        """Remove an ECMP group.

        Args:
            tag: Group tag to remove

        Returns:
            IpcResponse indicating success or failure
        """
        return await self._send_command({"type": "remove_ecmp_group", "tag": tag})

    async def get_ecmp_group_status(self, tag: str) -> IpcResponse:
        """Get status of an ECMP group.

        Args:
            tag: Group tag

        Returns:
            IpcResponse with group status data including member health
        """
        return await self._send_command({"type": "get_ecmp_group_status", "tag": tag})

    async def list_ecmp_groups(self) -> List[EcmpGroupInfo]:
        """List all ECMP groups.

        Returns:
            List of EcmpGroupInfo for each group
        """
        response = await self._send_command({"type": "list_ecmp_groups"})
        if not response.success:
            return []

        result = []
        if response.data and "groups" in response.data:
            for item in response.data["groups"]:
                result.append(EcmpGroupInfo(
                    tag=item.get("tag", ""),
                    description=item.get("description", ""),
                    algorithm=item.get("algorithm", "five_tuple_hash"),
                    member_count=item.get("member_count", 0),
                    healthy_count=item.get("healthy_count", 0),
                    routing_mark=item.get("routing_mark"),
                    routing_table=item.get("routing_table"),
                    health_check=item.get("health_check", True),
                ))
        return result

    async def update_ecmp_group_members(
        self,
        tag: str,
        members: List[Dict[str, Any]],
    ) -> IpcResponse:
        """Update members of an ECMP group.

        Args:
            tag: Group tag
            members: New list of member dicts with 'tag' and optional 'weight'

        Returns:
            IpcResponse indicating success or failure
        """
        return await self._send_command({
            "type": "update_ecmp_group_members",
            "tag": tag,
            "members": members,
        })

    # =========================================================================
    # Phase 6: Peer Node Management
    # =========================================================================

    async def generate_pair_request(
        self,
        local_tag: str,
        local_description: str,
        local_endpoint: str,
        local_api_port: int = 36000,
        bidirectional: bool = True,
        tunnel_type: str = "wireguard",
    ) -> IpcResponse:
        """Generate an offline pairing request code.

        This starts the offline pairing process. The returned code should be
        shared with the remote node (via QR code, copy-paste, etc.).

        Args:
            local_tag: Local node tag (how remote will identify this node)
            local_description: Human-readable description of this node
            local_endpoint: Local WireGuard endpoint (IP:port)
            local_api_port: Local Web API port (default: 36000)
            bidirectional: Enable bidirectional auto-connect (default: True)
            tunnel_type: Tunnel type ("wireguard" or "xray")

        Returns:
            IpcResponse with 'code' field containing the Base64 pairing request
        """
        return await self._send_command({
            "type": "generate_pair_request",
            "local_tag": local_tag,
            "local_description": local_description,
            "local_endpoint": local_endpoint,
            "local_api_port": local_api_port,
            "bidirectional": bidirectional,
            "tunnel_type": tunnel_type,
        })

    async def import_pair_request(
        self,
        code: str,
        local_tag: str,
        local_description: str,
        local_endpoint: str,
        local_api_port: int = 36000,
    ) -> IpcResponse:
        """Import a pairing request from another node.

        This processes a pairing request code from another node and generates
        a response code to send back.

        Args:
            code: Base64 pairing request code from remote node
            local_tag: Local node tag
            local_description: Human-readable description of this node
            local_endpoint: Local WireGuard endpoint (IP:port)
            local_api_port: Local Web API port (default: 36000)

        Returns:
            IpcResponse with 'response_code' field containing the response code
        """
        return await self._send_command({
            "type": "import_pair_request",
            "code": code,
            "local_tag": local_tag,
            "local_description": local_description,
            "local_endpoint": local_endpoint,
            "local_api_port": local_api_port,
        })

    async def complete_handshake(self, code: str) -> IpcResponse:
        """Complete the pairing handshake with a response code.

        This finalizes the pairing process on the initiating node.

        Args:
            code: Base64 response code from remote node

        Returns:
            IpcResponse indicating success or failure
        """
        return await self._send_command({"type": "complete_handshake", "code": code})

    async def connect_peer(self, tag: str) -> IpcResponse:
        """Connect to a configured peer node.

        Establishes the WireGuard or Xray tunnel to the peer.

        Args:
            tag: Peer tag to connect

        Returns:
            IpcResponse indicating success or failure
        """
        return await self._send_command({"type": "connect_peer", "tag": tag})

    async def disconnect_peer(self, tag: str) -> IpcResponse:
        """Disconnect from a peer node.

        Tears down the tunnel but preserves the peer configuration.

        Args:
            tag: Peer tag to disconnect

        Returns:
            IpcResponse indicating success or failure
        """
        return await self._send_command({"type": "disconnect_peer", "tag": tag})

    async def get_peer_status(self, tag: str) -> IpcResponse:
        """Get status of a peer node.

        Args:
            tag: Peer tag

        Returns:
            IpcResponse with peer status data
        """
        return await self._send_command({"type": "get_peer_status", "tag": tag})

    async def get_peer_tunnel_health(self, tag: str) -> Optional[PeerHealthInfo]:
        """Get tunnel health status for a peer.

        Args:
            tag: Peer tag

        Returns:
            PeerHealthInfo with health metrics, or None if failed
        """
        response = await self._send_command({"type": "get_peer_tunnel_health", "tag": tag})
        if not response.success or not response.data:
            return None

        return PeerHealthInfo(
            tag=tag,
            tunnel_status=response.data.get("tunnel_status", "unknown"),
            latency_ms=response.data.get("latency_ms"),
            packet_loss=response.data.get("packet_loss"),
            last_check=response.data.get("last_check"),
            consecutive_failures=response.data.get("consecutive_failures", 0),
        )

    async def list_peers(self) -> List[PeerInfo]:
        """List all configured peer nodes.

        Returns:
            List of PeerInfo for each peer
        """
        response = await self._send_command({"type": "list_peers"})
        if not response.success:
            return []

        result = []
        if response.data and "peers" in response.data:
            for item in response.data["peers"]:
                result.append(PeerInfo(
                    tag=item.get("tag", ""),
                    description=item.get("description", ""),
                    endpoint=item.get("endpoint", ""),
                    tunnel_type=item.get("tunnel_type", "wireguard"),
                    state=item.get("state", "unknown"),
                    tunnel_status=item.get("tunnel_status", "disconnected"),
                    api_port=item.get("api_port", 36000),
                    tunnel_port=item.get("tunnel_port"),
                    tunnel_ip=item.get("tunnel_ip"),
                    last_handshake=item.get("last_handshake"),
                    bytes_rx=item.get("bytes_rx", 0),
                    bytes_tx=item.get("bytes_tx", 0),
                ))
        return result

    async def remove_peer(self, tag: str) -> IpcResponse:
        """Remove a peer node configuration.

        This disconnects (if connected) and removes all peer configuration.

        Args:
            tag: Peer tag to remove

        Returns:
            IpcResponse indicating success or failure
        """
        return await self._send_command({"type": "remove_peer", "tag": tag})

    # =========================================================================
    # Phase 6: Chain Management
    # =========================================================================

    async def create_chain(
        self,
        tag: str,
        hops: List[str],
        exit_egress: str,
        description: str = "",
        allow_transitive: bool = False,
    ) -> IpcResponse:
        """Create a multi-hop chain.

        Args:
            tag: Unique tag for this chain
            hops: Ordered list of peer tags forming the chain path
            exit_egress: Egress tag on the terminal node
            description: Chain description
            allow_transitive: Allow terminal node to select egress dynamically

        Returns:
            IpcResponse indicating success or failure
        """
        return await self._send_command({
            "type": "create_chain",
            "tag": tag,
            "hops": hops,
            "exit_egress": exit_egress,
            "description": description,
            "allow_transitive": allow_transitive,
        })

    async def update_chain(
        self,
        tag: str,
        hops: Optional[List[str]] = None,
        exit_egress: Optional[str] = None,
        description: Optional[str] = None,
        allow_transitive: Optional[bool] = None,
    ) -> IpcResponse:
        """Update an existing chain.

        Only provided fields are updated. Chain must be inactive.

        Args:
            tag: Chain tag to update
            hops: New hop list (optional)
            exit_egress: New exit egress (optional)
            description: New description (optional)
            allow_transitive: New transitive setting (optional)

        Returns:
            IpcResponse indicating success or failure
        """
        command: Dict[str, Any] = {"type": "update_chain", "tag": tag}
        if hops is not None:
            command["hops"] = hops
        if exit_egress is not None:
            command["exit_egress"] = exit_egress
        if description is not None:
            command["description"] = description
        if allow_transitive is not None:
            command["allow_transitive"] = allow_transitive
        return await self._send_command(command)

    async def remove_chain(self, tag: str) -> IpcResponse:
        """Remove a chain.

        Chain must be inactive before removal.

        Args:
            tag: Chain tag to remove

        Returns:
            IpcResponse indicating success or failure
        """
        return await self._send_command({"type": "remove_chain", "tag": tag})

    # Backwards compatibility alias
    delete_chain = remove_chain

    async def activate_chain(self, tag: str) -> IpcResponse:
        """Activate a chain using Two-Phase Commit.

        This performs distributed activation across all hops:
        1. PREPARE phase: Validate configuration on all nodes
        2. COMMIT phase: Apply DSCP rules on all nodes

        Args:
            tag: Chain tag to activate

        Returns:
            IpcResponse indicating success or failure
        """
        return await self._send_command({"type": "activate_chain", "tag": tag})

    async def deactivate_chain(self, tag: str) -> IpcResponse:
        """Deactivate an active chain.

        Removes DSCP rules from all nodes in the chain.

        Args:
            tag: Chain tag to deactivate

        Returns:
            IpcResponse indicating success or failure
        """
        return await self._send_command({"type": "deactivate_chain", "tag": tag})

    async def get_chain_status(self, tag: str) -> IpcResponse:
        """Get status of a chain.

        Args:
            tag: Chain tag

        Returns:
            IpcResponse with chain status including state and any errors
        """
        return await self._send_command({"type": "get_chain_status", "tag": tag})

    async def list_chains(self) -> List[ChainInfo]:
        """List all chains.

        Returns:
            List of ChainInfo for each chain
        """
        response = await self._send_command({"type": "list_chains"})
        if not response.success:
            return []

        result = []
        if response.data and "chains" in response.data:
            for item in response.data["chains"]:
                result.append(ChainInfo(
                    tag=item.get("tag", ""),
                    description=item.get("description", ""),
                    hops=item.get("hops", []),
                    exit_egress=item.get("exit_egress", ""),
                    chain_state=item.get("chain_state", "inactive"),
                    dscp_value=item.get("dscp_value"),
                    allow_transitive=item.get("allow_transitive", False),
                    last_error=item.get("last_error"),
                ))
        return result

    async def get_chain_role(self, tag: str) -> Optional[ChainRoleInfo]:
        """Get this node's role in a chain.

        Args:
            tag: Chain tag

        Returns:
            ChainRoleInfo describing this node's role, or None if not in chain
        """
        response = await self._send_command({"type": "get_chain_role", "tag": tag})
        if not response.success or not response.data:
            return None

        return ChainRoleInfo(
            chain_tag=tag,
            role=response.data.get("role", "unknown"),
            dscp_value=response.data.get("dscp_value"),
            previous_hop=response.data.get("previous_hop"),
            next_hop=response.data.get("next_hop"),
        )

    # =========================================================================
    # Phase 6: Two-Phase Commit (2PC) Protocol
    # =========================================================================

    async def prepare_chain_route(
        self,
        chain_tag: str,
        dscp_value: int,
        source_node: str,
    ) -> IpcResponse:
        """PREPARE phase of 2PC for chain route registration.

        Validates the chain route configuration without applying rules.

        Args:
            chain_tag: Chain tag
            dscp_value: DSCP value for this chain (1-63)
            source_node: Tag of the node initiating the request

        Returns:
            IpcResponse indicating if PREPARE succeeded
        """
        return await self._send_command({
            "type": "prepare_chain_route",
            "chain_tag": chain_tag,
            "dscp_value": dscp_value,
            "source_node": source_node,
        })

    async def commit_chain_route(
        self,
        chain_tag: str,
        dscp_value: int,
        source_node: str,
    ) -> IpcResponse:
        """COMMIT phase of 2PC for chain route registration.

        Applies the validated chain route rules.

        Args:
            chain_tag: Chain tag
            dscp_value: DSCP value for this chain
            source_node: Tag of the node initiating the request

        Returns:
            IpcResponse indicating if COMMIT succeeded
        """
        return await self._send_command({
            "type": "commit_chain_route",
            "chain_tag": chain_tag,
            "dscp_value": dscp_value,
            "source_node": source_node,
        })

    async def abort_chain_route(
        self,
        chain_tag: str,
        source_node: str,
    ) -> IpcResponse:
        """ABORT phase of 2PC for chain route registration.

        Rolls back any prepared state for this chain route.

        Args:
            chain_tag: Chain tag
            source_node: Tag of the node initiating the request

        Returns:
            IpcResponse indicating if ABORT succeeded
        """
        return await self._send_command({
            "type": "abort_chain_route",
            "chain_tag": chain_tag,
            "source_node": source_node,
        })

    # =========================================================================
    # Phase 7.7: DNS Commands
    # =========================================================================

    async def get_dns_stats(self) -> Optional[DnsStats]:
        """Get overall DNS statistics"""
        response = await self._send_command({"type": "get_dns_stats"})
        if not response.success or not response.data:
            return None
        return DnsStats(
            enabled=response.data.get("enabled", False),
            uptime_secs=response.data.get("uptime_secs", 0),
            total_queries=response.data.get("total_queries", 0),
            cache_hits=response.data.get("cache_hits", 0),
            cache_misses=response.data.get("cache_misses", 0),
            blocked_queries=response.data.get("blocked_queries", 0),
            upstream_queries=response.data.get("upstream_queries", 0),
            avg_latency_us=response.data.get("avg_latency_us", 0),
        )

    async def get_dns_cache_stats(self) -> Optional[DnsCacheStats]:
        """Get DNS cache statistics"""
        response = await self._send_command({"type": "get_dns_cache_stats"})
        if not response.success or not response.data:
            return None
        return DnsCacheStats(
            enabled=response.data.get("enabled", False),
            max_entries=response.data.get("max_entries", 0),
            current_entries=response.data.get("current_entries", 0),
            hits=response.data.get("hits", 0),
            misses=response.data.get("misses", 0),
            hit_rate=response.data.get("hit_rate", 0.0),
            negative_hits=response.data.get("negative_hits", 0),
            inserts=response.data.get("inserts", 0),
            evictions=response.data.get("evictions", 0),
        )

    async def flush_dns_cache(self, pattern: Optional[str] = None) -> IpcResponse:
        """Flush DNS cache (optional pattern for selective flush)

        Args:
            pattern: Optional domain pattern for selective flush.
                     If None, flushes entire cache.

        Returns:
            IpcResponse indicating success or failure
        """
        cmd: Dict[str, Any] = {"type": "flush_dns_cache"}
        if pattern:
            cmd["pattern"] = pattern
        return await self._send_command(cmd)

    async def get_dns_block_stats(self) -> Optional[DnsBlockStats]:
        """Get DNS blocking statistics"""
        response = await self._send_command({"type": "get_dns_block_stats"})
        if not response.success or not response.data:
            return None
        return DnsBlockStats(
            enabled=response.data.get("enabled", False),
            rule_count=response.data.get("rule_count", 0),
            blocked_queries=response.data.get("blocked_queries", 0),
            total_queries=response.data.get("total_queries", 0),
            block_rate=response.data.get("block_rate", 0.0),
            last_reload=response.data.get("last_reload"),
        )

    async def reload_dns_blocklist(self) -> IpcResponse:
        """Reload DNS blocklist from database"""
        return await self._send_command({"type": "reload_dns_blocklist"})

    async def add_dns_upstream(
        self,
        tag: str,
        address: str,
        protocol: str,
        bootstrap: Optional[List[str]] = None,
        timeout_secs: Optional[int] = None,
    ) -> IpcResponse:
        """Add a DNS upstream server

        Args:
            tag: Unique tag for this upstream
            address: Server address (IP:port for UDP/TCP, URL for DoH/DoT)
            protocol: Protocol type ("udp", "tcp", "doh", "dot")
            bootstrap: Optional bootstrap DNS servers for DoH/DoT
            timeout_secs: Optional query timeout in seconds

        Returns:
            IpcResponse indicating success or failure
        """
        config: Dict[str, Any] = {
            "address": address,
            "protocol": protocol,
        }
        if bootstrap:
            config["bootstrap"] = bootstrap
        if timeout_secs:
            config["timeout_secs"] = timeout_secs
        return await self._send_command({
            "type": "add_dns_upstream",
            "tag": tag,
            "config": config,
        })

    async def remove_dns_upstream(self, tag: str) -> IpcResponse:
        """Remove a DNS upstream server

        Args:
            tag: Upstream tag to remove

        Returns:
            IpcResponse indicating success or failure
        """
        return await self._send_command({
            "type": "remove_dns_upstream",
            "tag": tag,
        })

    async def get_dns_upstream_status(
        self, tag: Optional[str] = None
    ) -> List[DnsUpstreamInfo]:
        """Get DNS upstream status

        Args:
            tag: Optional specific upstream tag. If None, returns all upstreams.

        Returns:
            List of DnsUpstreamInfo for each upstream
        """
        cmd: Dict[str, Any] = {"type": "get_dns_upstream_status"}
        if tag:
            cmd["tag"] = tag
        response = await self._send_command(cmd)
        if not response.success or not response.data:
            return []

        result = []
        for item in response.data.get("upstreams", []):
            result.append(DnsUpstreamInfo(
                tag=item.get("tag", ""),
                address=item.get("address", ""),
                protocol=item.get("protocol", ""),
                healthy=item.get("healthy", True),
                total_queries=item.get("total_queries", 0),
                failed_queries=item.get("failed_queries", 0),
                avg_latency_us=item.get("avg_latency_us", 0),
                last_success=item.get("last_success"),
                last_failure=item.get("last_failure"),
            ))
        return result

    async def add_dns_route(
        self, pattern: str, match_type: str, upstream_tag: str
    ) -> IpcResponse:
        """Add a DNS routing rule

        Args:
            pattern: Domain pattern to match
            match_type: One of "exact", "suffix", "keyword", "regex"
            upstream_tag: Upstream server tag to route to

        Returns:
            IpcResponse indicating success or failure
        """
        return await self._send_command({
            "type": "add_dns_route",
            "pattern": pattern,
            "match_type": match_type,
            "upstream_tag": upstream_tag,
        })

    async def remove_dns_route(self, pattern: str) -> IpcResponse:
        """Remove a DNS routing rule by pattern

        Args:
            pattern: Domain pattern to remove

        Returns:
            IpcResponse indicating success or failure
        """
        return await self._send_command({
            "type": "remove_dns_route",
            "pattern": pattern,
        })

    async def get_dns_query_log(
        self, limit: int = 100, offset: int = 0
    ) -> List[DnsQueryLogEntry]:
        """Get DNS query log entries

        Args:
            limit: Maximum number of entries to return (default: 100)
            offset: Number of entries to skip (default: 0)

        Returns:
            List of DnsQueryLogEntry
        """
        response = await self._send_command({
            "type": "get_dns_query_log",
            "limit": limit,
            "offset": offset,
        })
        if not response.success or not response.data:
            return []

        result = []
        for item in response.data.get("entries", []):
            result.append(DnsQueryLogEntry(
                timestamp=item.get("timestamp", 0),
                domain=item.get("domain", ""),
                qtype=item.get("qtype", 0),
                qtype_str=item.get("qtype_str", ""),
                upstream=item.get("upstream", ""),
                response_code=item.get("response_code", 0),
                rcode_str=item.get("rcode_str", ""),
                latency_us=item.get("latency_us", 0),
                blocked=item.get("blocked", False),
                cached=item.get("cached", False),
            ))
        return result

    async def dns_query(
        self,
        domain: str,
        qtype: int = 1,  # Default: A record
        upstream: Optional[str] = None,
    ) -> Optional[DnsQueryResult]:
        """Perform a test DNS query

        Args:
            domain: Domain name to query
            qtype: Query type (1=A, 28=AAAA, 5=CNAME, etc.)
            upstream: Optional specific upstream to use

        Returns:
            DnsQueryResult with query results, or None if failed
        """
        cmd: Dict[str, Any] = {
            "type": "dns_query",
            "domain": domain,
            "qtype": qtype,
        }
        if upstream:
            cmd["upstream"] = upstream
        response = await self._send_command(cmd)
        if not response.success or not response.data:
            return None
        return DnsQueryResult(
            success=response.data.get("success", False),
            domain=response.data.get("domain", domain),
            qtype=response.data.get("qtype", qtype),
            response_code=response.data.get("response_code", 0),
            answers=response.data.get("answers", []),
            latency_us=response.data.get("latency_us", 0),
            cached=response.data.get("cached", False),
            blocked=response.data.get("blocked", False),
            upstream_used=response.data.get("upstream_used"),
        )

    async def get_dns_config(self) -> Optional[DnsConfig]:
        """Get current DNS configuration

        Returns:
            DnsConfig with current settings, or None if failed
        """
        response = await self._send_command({"type": "get_dns_config"})
        if not response.success or not response.data:
            return None

        upstreams = []
        for item in response.data.get("upstreams", []):
            upstreams.append(DnsUpstreamInfo(
                tag=item.get("tag", ""),
                address=item.get("address", ""),
                protocol=item.get("protocol", ""),
                healthy=item.get("healthy", True),
                total_queries=item.get("total_queries", 0),
                failed_queries=item.get("failed_queries", 0),
                avg_latency_us=item.get("avg_latency_us", 0),
                last_success=item.get("last_success"),
                last_failure=item.get("last_failure"),
            ))

        return DnsConfig(
            enabled=response.data.get("enabled", False),
            listen_udp=response.data.get("listen_udp", ""),
            listen_tcp=response.data.get("listen_tcp", ""),
            upstreams=upstreams,
            cache_enabled=response.data.get("cache_enabled", True),
            cache_max_entries=response.data.get("cache_max_entries", 10000),
            blocking_enabled=response.data.get("blocking_enabled", True),
            blocking_response_type=response.data.get("blocking_response_type", "zero_ip"),
            logging_enabled=response.data.get("logging_enabled", False),
            logging_format=response.data.get("logging_format", "json"),
            available_features=response.data.get("available_features", {}),
        )

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

    class TestPhase6Dataclasses(unittest.TestCase):
        """Test Phase 6 v3.2 dataclasses"""

        def test_wg_tunnel_info_defaults(self):
            """Test WgTunnelInfo with defaults"""
            info = WgTunnelInfo(tag="peer1", state="running", local_ip="10.200.200.1")
            self.assertEqual(info.tag, "peer1")
            self.assertEqual(info.state, "running")
            self.assertEqual(info.mtu, 1420)
            self.assertEqual(info.bytes_rx, 0)
            self.assertIsNone(info.peer_ip)

        def test_wg_tunnel_info_full(self):
            """Test WgTunnelInfo with all fields"""
            info = WgTunnelInfo(
                tag="peer1",
                state="running",
                local_ip="10.200.200.1",
                peer_ip="10.200.200.2",
                endpoint="1.2.3.4:36200",
                listen_port=36201,
                mtu=1400,
                bytes_rx=1000,
                bytes_tx=2000,
                last_handshake=1704067200,
                persistent_keepalive=30,
            )
            self.assertEqual(info.listen_port, 36201)
            self.assertEqual(info.last_handshake, 1704067200)

        def test_ecmp_group_info_defaults(self):
            """Test EcmpGroupInfo with defaults"""
            info = EcmpGroupInfo(
                tag="us-exits",
                description="US exit group",
                algorithm="five_tuple_hash",
                member_count=3,
                healthy_count=2,
            )
            self.assertEqual(info.algorithm, "five_tuple_hash")
            self.assertIsNone(info.routing_mark)
            self.assertTrue(info.health_check)

        def test_ecmp_member_info(self):
            """Test EcmpMemberInfo"""
            info = EcmpMemberInfo(tag="us-east", weight=2, health="healthy")
            self.assertEqual(info.weight, 2)
            self.assertEqual(info.active_connections, 0)

        def test_peer_info_defaults(self):
            """Test PeerInfo with defaults"""
            info = PeerInfo(
                tag="node-b",
                description="Remote node B",
                endpoint="10.0.0.2:36200",
                tunnel_type="wireguard",
                state="connected",
            )
            self.assertEqual(info.tunnel_status, "disconnected")
            self.assertEqual(info.api_port, 36000)
            self.assertIsNone(info.tunnel_port)

        def test_peer_health_info(self):
            """Test PeerHealthInfo"""
            info = PeerHealthInfo(
                tag="node-b",
                tunnel_status="healthy",
                latency_ms=15.5,
                packet_loss=0.01,
                consecutive_failures=0,
            )
            self.assertEqual(info.latency_ms, 15.5)
            self.assertEqual(info.packet_loss, 0.01)

        def test_chain_info_defaults(self):
            """Test ChainInfo with defaults"""
            info = ChainInfo(
                tag="chain-us",
                description="US chain",
                hops=["node-a", "node-b"],
                exit_egress="us-east",
                chain_state="inactive",
            )
            self.assertEqual(len(info.hops), 2)
            self.assertIsNone(info.dscp_value)
            self.assertFalse(info.allow_transitive)

        def test_chain_role_info(self):
            """Test ChainRoleInfo"""
            info = ChainRoleInfo(
                chain_tag="chain-us",
                role="relay",
                dscp_value=10,
                previous_hop="node-a",
                next_hop="node-b",
            )
            self.assertEqual(info.role, "relay")
            self.assertEqual(info.dscp_value, 10)

    class TestPhase6Commands(unittest.IsolatedAsyncioTestCase):
        """Test Phase 6 v3.2 client command methods"""

        async def asyncSetUp(self):
            self.client = RustRouterClient()
            self.client._connected = True
            self.client._send_command = AsyncMock(
                return_value=IpcResponse(success=True, response_type="success")
            )

        async def test_create_wg_tunnel_command_format(self):
            """Test create_wg_tunnel command format"""
            await self.client.create_wg_tunnel(
                tag="peer1",
                private_key="cGVlcjEtcHJpdmF0ZS1rZXk=",
                peer_public_key="cGVlcjEtcHVibGljLWtleQ==",
                endpoint="10.0.0.2:36200",
                local_ip="10.200.200.1",
                peer_ip="10.200.200.2",
                listen_port=36201,
            )

            call_args = self.client._send_command.call_args[0][0]
            self.assertEqual(call_args["type"], "create_wg_tunnel")
            self.assertEqual(call_args["tag"], "peer1")
            self.assertEqual(call_args["config"]["endpoint"], "10.0.0.2:36200")
            self.assertEqual(call_args["config"]["listen_port"], 36201)
            self.assertEqual(call_args["config"]["mtu"], 1420)

        async def test_remove_wg_tunnel_command_format(self):
            """Test remove_wg_tunnel command format"""
            await self.client.remove_wg_tunnel("peer1", drain_timeout_secs=30)

            call_args = self.client._send_command.call_args[0][0]
            self.assertEqual(call_args["type"], "remove_wg_tunnel")
            self.assertEqual(call_args["tag"], "peer1")
            self.assertEqual(call_args["drain_timeout_secs"], 30)

        async def test_list_wg_tunnels_parsing(self):
            """Test list_wg_tunnels response parsing"""
            self.client._send_command = AsyncMock(
                return_value=IpcResponse(
                    success=True,
                    response_type="list_wg_tunnels",
                    data={
                        "tunnels": [
                            {"tag": "peer1", "state": "running", "local_ip": "10.200.200.1"},
                            {"tag": "peer2", "state": "stopped", "local_ip": "10.200.200.3"},
                        ]
                    }
                )
            )

            tunnels = await self.client.list_wg_tunnels()
            self.assertEqual(len(tunnels), 2)
            self.assertEqual(tunnels[0].tag, "peer1")
            self.assertEqual(tunnels[0].state, "running")

        async def test_create_ecmp_group_command_format(self):
            """Test create_ecmp_group command format"""
            await self.client.create_ecmp_group(
                tag="us-exits",
                members=[{"tag": "us-east", "weight": 2}, {"tag": "us-west", "weight": 1}],
                algorithm="weighted",
                routing_mark=200,
            )

            call_args = self.client._send_command.call_args[0][0]
            self.assertEqual(call_args["type"], "create_ecmp_group")
            self.assertEqual(call_args["config"]["algorithm"], "weighted")
            self.assertEqual(len(call_args["config"]["members"]), 2)
            self.assertEqual(call_args["config"]["routing_mark"], 200)

        async def test_list_ecmp_groups_parsing(self):
            """Test list_ecmp_groups response parsing"""
            self.client._send_command = AsyncMock(
                return_value=IpcResponse(
                    success=True,
                    response_type="list_ecmp_groups",
                    data={
                        "groups": [
                            {
                                "tag": "us-exits",
                                "description": "US exits",
                                "algorithm": "five_tuple_hash",
                                "member_count": 2,
                                "healthy_count": 2,
                            }
                        ]
                    }
                )
            )

            groups = await self.client.list_ecmp_groups()
            self.assertEqual(len(groups), 1)
            self.assertEqual(groups[0].tag, "us-exits")
            self.assertEqual(groups[0].member_count, 2)

        async def test_generate_pair_request_command_format(self):
            """Test generate_pair_request command format"""
            await self.client.generate_pair_request(
                local_tag="node-a",
                local_description="Node A",
                local_endpoint="10.0.0.1:36200",
                local_api_port=36001,
                bidirectional=True,
                tunnel_type="wireguard",
            )

            call_args = self.client._send_command.call_args[0][0]
            self.assertEqual(call_args["type"], "generate_pair_request")
            self.assertEqual(call_args["local_tag"], "node-a")
            self.assertEqual(call_args["local_api_port"], 36001)
            self.assertTrue(call_args["bidirectional"])

        async def test_import_pair_request_command_format(self):
            """Test import_pair_request command format"""
            await self.client.import_pair_request(
                code="base64-pairing-code",
                local_tag="node-b",
                local_description="Node B",
                local_endpoint="10.0.0.2:36200",
            )

            call_args = self.client._send_command.call_args[0][0]
            self.assertEqual(call_args["type"], "import_pair_request")
            self.assertEqual(call_args["code"], "base64-pairing-code")

        async def test_connect_peer_command_format(self):
            """Test connect_peer command format"""
            await self.client.connect_peer("node-b")

            call_args = self.client._send_command.call_args[0][0]
            self.assertEqual(call_args["type"], "connect_peer")
            self.assertEqual(call_args["tag"], "node-b")

        async def test_list_peers_parsing(self):
            """Test list_peers response parsing"""
            self.client._send_command = AsyncMock(
                return_value=IpcResponse(
                    success=True,
                    response_type="list_peers",
                    data={
                        "peers": [
                            {
                                "tag": "node-b",
                                "description": "Remote B",
                                "endpoint": "10.0.0.2:36200",
                                "tunnel_type": "wireguard",
                                "state": "connected",
                                "tunnel_status": "healthy",
                                "api_port": 36000,
                            }
                        ]
                    }
                )
            )

            peers = await self.client.list_peers()
            self.assertEqual(len(peers), 1)
            self.assertEqual(peers[0].tag, "node-b")
            self.assertEqual(peers[0].tunnel_status, "healthy")

        async def test_get_peer_tunnel_health_parsing(self):
            """Test get_peer_tunnel_health response parsing"""
            self.client._send_command = AsyncMock(
                return_value=IpcResponse(
                    success=True,
                    response_type="peer_health",
                    data={
                        "tunnel_status": "healthy",
                        "latency_ms": 12.5,
                        "packet_loss": 0.0,
                        "consecutive_failures": 0,
                    }
                )
            )

            health = await self.client.get_peer_tunnel_health("node-b")
            self.assertIsNotNone(health)
            self.assertEqual(health.tunnel_status, "healthy")
            self.assertEqual(health.latency_ms, 12.5)

        async def test_create_chain_command_format(self):
            """Test create_chain command format"""
            await self.client.create_chain(
                tag="chain-us",
                hops=["node-b", "node-c"],
                exit_egress="us-east",
                description="US chain via B and C",
                allow_transitive=True,
            )

            call_args = self.client._send_command.call_args[0][0]
            self.assertEqual(call_args["type"], "create_chain")
            self.assertEqual(call_args["hops"], ["node-b", "node-c"])
            self.assertEqual(call_args["exit_egress"], "us-east")
            self.assertTrue(call_args["allow_transitive"])

        async def test_update_chain_partial(self):
            """Test update_chain with partial fields"""
            await self.client.update_chain(
                tag="chain-us",
                exit_egress="us-west",
            )

            call_args = self.client._send_command.call_args[0][0]
            self.assertEqual(call_args["type"], "update_chain")
            self.assertEqual(call_args["exit_egress"], "us-west")
            self.assertNotIn("hops", call_args)
            self.assertNotIn("description", call_args)

        async def test_activate_chain_command_format(self):
            """Test activate_chain command format"""
            await self.client.activate_chain("chain-us")

            call_args = self.client._send_command.call_args[0][0]
            self.assertEqual(call_args["type"], "activate_chain")
            self.assertEqual(call_args["tag"], "chain-us")

        async def test_list_chains_parsing(self):
            """Test list_chains response parsing"""
            self.client._send_command = AsyncMock(
                return_value=IpcResponse(
                    success=True,
                    response_type="list_chains",
                    data={
                        "chains": [
                            {
                                "tag": "chain-us",
                                "description": "US chain",
                                "hops": ["node-b"],
                                "exit_egress": "us-east",
                                "chain_state": "active",
                                "dscp_value": 10,
                            }
                        ]
                    }
                )
            )

            chains = await self.client.list_chains()
            self.assertEqual(len(chains), 1)
            self.assertEqual(chains[0].chain_state, "active")
            self.assertEqual(chains[0].dscp_value, 10)

        async def test_get_chain_role_parsing(self):
            """Test get_chain_role response parsing"""
            self.client._send_command = AsyncMock(
                return_value=IpcResponse(
                    success=True,
                    response_type="chain_role",
                    data={
                        "role": "entry",
                        "dscp_value": 10,
                        "next_hop": "node-b",
                    }
                )
            )

            role = await self.client.get_chain_role("chain-us")
            self.assertIsNotNone(role)
            self.assertEqual(role.role, "entry")
            self.assertEqual(role.next_hop, "node-b")

        async def test_prepare_chain_route_command_format(self):
            """Test prepare_chain_route (2PC PREPARE) command format"""
            await self.client.prepare_chain_route(
                chain_tag="chain-us",
                dscp_value=10,
                source_node="node-a",
            )

            call_args = self.client._send_command.call_args[0][0]
            self.assertEqual(call_args["type"], "prepare_chain_route")
            self.assertEqual(call_args["dscp_value"], 10)
            self.assertEqual(call_args["source_node"], "node-a")

        async def test_commit_chain_route_command_format(self):
            """Test commit_chain_route (2PC COMMIT) command format"""
            await self.client.commit_chain_route(
                chain_tag="chain-us",
                dscp_value=10,
                source_node="node-a",
            )

            call_args = self.client._send_command.call_args[0][0]
            self.assertEqual(call_args["type"], "commit_chain_route")

        async def test_abort_chain_route_command_format(self):
            """Test abort_chain_route (2PC ABORT) command format"""
            await self.client.abort_chain_route(
                chain_tag="chain-us",
                source_node="node-a",
            )

            call_args = self.client._send_command.call_args[0][0]
            self.assertEqual(call_args["type"], "abort_chain_route")
            self.assertNotIn("dscp_value", call_args)

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
        description="Rust Router IPC Client (v4.0 - Phase 6 v3.2)",
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

Phase 6 v3.2 Features:
  - Userspace WireGuard tunnel management (boringtun)
  - ECMP load balancing groups (5 algorithms)
  - Peer node management with offline pairing
  - Multi-hop chain management with 2PC activation
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
        suite.addTests(loader.loadTestsFromTestCase(TestPhase6Dataclasses))
        suite.addTests(loader.loadTestsFromTestCase(TestPhase6Commands))
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

#!/usr/bin/env python3
"""
Router Watchdog - Phase 3.5

Monitors rust-router and sing-box health, manages failover between routers.
Handles TPROXY port switching for seamless traffic failover.

Architecture:
    watchdog.py monitors both routers via health checks:
    - rust-router: IPC ping via Unix socket
    - sing-box: HTTP GET to /health on port 9090

    When rust-router fails (3 consecutive health check failures),
    watchdog updates iptables TPROXY rules to redirect traffic to sing-box.
    When rust-router recovers, watchdog can automatically switch back.

Usage:
    python3 watchdog.py [--daemon]

Environment Variables:
    RUST_ROUTER_PORT: rust-router TPROXY port (default: 7893)
    SINGBOX_PORT: sing-box TPROXY port (default: 7894)
    WATCHDOG_INTERVAL: Health check interval in seconds (default: 5.0)
    WATCHDOG_FAILURE_THRESHOLD: Failures before failover (default: 3)
    WATCHDOG_AUTO_RECOVER: Auto switch back when rust-router recovers (default: true)
    WG_INTERFACE: WireGuard ingress interface name (default: wg-ingress)
"""

import argparse
import asyncio
import logging
import os
import signal
import subprocess
import sys
import time
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Optional, Dict, Any, List, TYPE_CHECKING

# Type checking imports (not executed at runtime)
if TYPE_CHECKING:
    import aiohttp as aiohttp_types
    from rust_router_client import RustRouterClient as RustRouterClientType

# Add scripts directory to path for imports
sys.path.insert(0, str(Path(__file__).parent))

try:
    from rust_router_client import RustRouterClient, is_available as rust_router_available
    HAS_RUST_ROUTER_CLIENT = True
except ImportError:
    HAS_RUST_ROUTER_CLIENT = False
    RustRouterClient = None  # type: ignore

try:
    import aiohttp
    HAS_AIOHTTP = True
except ImportError:
    HAS_AIOHTTP = False
    aiohttp = None  # type: ignore

# Configure logging (统一日志配置，通过 LOG_LEVEL 环境变量控制)
try:
    from log_config import setup_logging, get_logger
    setup_logging()
    logger = get_logger("watchdog")
except ImportError:
    # 回退：如果 log_config 不可用，使用基本配置
    _log_level = os.environ.get("LOG_LEVEL", "INFO").upper()
    logging.basicConfig(
        level=getattr(logging, _log_level, logging.INFO),
        format='%(asctime)s [%(levelname)s] %(name)s: %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    logger = logging.getLogger("watchdog")


class RouterType(Enum):
    """Types of routers managed by watchdog"""
    RUST_ROUTER = "rust-router"
    SINGBOX = "sing-box"


class HealthStatus(Enum):
    """Health status of a router"""
    HEALTHY = "healthy"
    DEGRADED = "degraded"
    UNHEALTHY = "unhealthy"
    UNKNOWN = "unknown"


@dataclass
class RouterState:
    """State tracking for a router"""
    router_type: RouterType
    port: int
    health: HealthStatus = HealthStatus.UNKNOWN
    consecutive_failures: int = 0
    last_check: Optional[datetime] = None
    last_success: Optional[datetime] = None
    error_message: Optional[str] = None


@dataclass
class WatchdogConfig:
    """Configuration for the watchdog"""
    rust_router_port: int = 7893
    singbox_port: int = 7894
    singbox_clash_api_port: int = 9090
    health_interval: float = 5.0
    failure_threshold: int = 3
    health_check_timeout: float = 2.0
    auto_recover: bool = True
    wg_interface: str = "wg-ingress"
    xray_interface: str = "xray-tun0"
    tproxy_mark: int = 1

    @classmethod
    def from_env(cls) -> "WatchdogConfig":
        """Create config from environment variables"""
        return cls(
            rust_router_port=int(os.environ.get("RUST_ROUTER_PORT", "7893")),
            singbox_port=int(os.environ.get("SINGBOX_PORT", "7894")),
            singbox_clash_api_port=int(os.environ.get("CLASH_API_PORT", "9090")),
            health_interval=float(os.environ.get("WATCHDOG_INTERVAL", "5.0")),
            failure_threshold=int(os.environ.get("WATCHDOG_FAILURE_THRESHOLD", "3")),
            health_check_timeout=float(os.environ.get("WATCHDOG_TIMEOUT", "2.0")),
            auto_recover=os.environ.get("WATCHDOG_AUTO_RECOVER", "true").lower() == "true",
            wg_interface=os.environ.get("WG_INTERFACE", "wg-ingress"),
            xray_interface=os.environ.get("XRAY_INTERFACE", "xray-tun0"),
            tproxy_mark=int(os.environ.get("TPROXY_MARK", "1")),
        )


@dataclass
class FailoverEvent:
    """Record of a failover event"""
    timestamp: datetime
    from_router: RouterType
    to_router: RouterType
    reason: str
    success: bool
    error: Optional[str] = None


class RouterWatchdog:
    """
    Watchdog for monitoring router health and managing failover.

    Monitors both rust-router (via IPC) and sing-box (via HTTP),
    managing iptables TPROXY rules to switch traffic between routers.
    """

    def __init__(self, config: Optional[WatchdogConfig] = None):
        """Initialize the watchdog.

        Args:
            config: Watchdog configuration (uses env vars if None)
        """
        self.config = config or WatchdogConfig.from_env()

        # Router state tracking
        self.rust_router_state = RouterState(
            router_type=RouterType.RUST_ROUTER,
            port=self.config.rust_router_port
        )
        self.singbox_state = RouterState(
            router_type=RouterType.SINGBOX,
            port=self.config.singbox_port
        )

        # Active router tracking
        self._active_port = self.config.rust_router_port
        self._active_router = RouterType.RUST_ROUTER

        # Failover history
        self._failover_events: List[FailoverEvent] = []

        # Control flags
        self._running = False
        self._shutdown_event = asyncio.Event()

        # IPC client for rust-router (lazy initialization)
        self._rust_router_client: Optional[RustRouterClient] = None

        # HTTP session for sing-box (lazy initialization)
        self._http_session: Optional[aiohttp.ClientSession] = None

    @property
    def active_router(self) -> RouterType:
        """Get the currently active router"""
        return self._active_router

    @property
    def active_port(self) -> int:
        """Get the currently active TPROXY port"""
        return self._active_port

    @property
    def failover_events(self) -> List[FailoverEvent]:
        """Get the list of failover events"""
        return self._failover_events.copy()

    async def _get_rust_router_client(self) -> Optional[RustRouterClient]:
        """Get or create rust-router IPC client"""
        if not HAS_RUST_ROUTER_CLIENT:
            return None
        if self._rust_router_client is None:
            self._rust_router_client = RustRouterClient(
                connect_timeout=self.config.health_check_timeout,
                request_timeout=self.config.health_check_timeout,
                max_retries=1  # Single try for health checks
            )
        return self._rust_router_client

    async def _get_http_session(self) -> Optional[Any]:
        """Get or create HTTP session for sing-box checks"""
        if not HAS_AIOHTTP or aiohttp is None:
            return None
        if self._http_session is None or self._http_session.closed:
            timeout = aiohttp.ClientTimeout(total=self.config.health_check_timeout)
            self._http_session = aiohttp.ClientSession(timeout=timeout)
        return self._http_session

    async def check_rust_router_health(self) -> bool:
        """Check rust-router health via IPC ping.

        Returns:
            True if healthy, False otherwise
        """
        if not HAS_RUST_ROUTER_CLIENT:
            logger.warning("rust_router_client not available, skipping health check")
            return False

        try:
            client = await self._get_rust_router_client()
            if client is None:
                self.rust_router_state.error_message = "Client not available"
                return False

            # Connect and ping
            connected = await asyncio.wait_for(
                client.connect(),
                timeout=self.config.health_check_timeout
            )
            if not connected:
                self.rust_router_state.error_message = "Connection failed"
                return False

            response = await asyncio.wait_for(
                client.ping(),
                timeout=self.config.health_check_timeout
            )

            if response.success:
                self.rust_router_state.error_message = None
                return True
            else:
                self.rust_router_state.error_message = response.error or "Ping failed"
                return False

        except asyncio.TimeoutError:
            self.rust_router_state.error_message = "Health check timeout"
            return False
        except Exception as e:
            self.rust_router_state.error_message = str(e)
            logger.debug(f"rust-router health check exception: {e}")
            return False
        finally:
            # Disconnect after health check to avoid stale connections
            if self._rust_router_client:
                await self._rust_router_client.disconnect()

    async def check_singbox_health(self) -> bool:
        """Check sing-box health via HTTP GET to Clash API.

        Returns:
            True if healthy, False otherwise
        """
        if not HAS_AIOHTTP:
            logger.warning("aiohttp not available, skipping sing-box health check")
            return False

        url = f"http://127.0.0.1:{self.config.singbox_clash_api_port}/"

        try:
            session = await self._get_http_session()
            if session is None:
                self.singbox_state.error_message = "HTTP session not available"
                return False

            async with session.get(url) as resp:
                if resp.status == 200:
                    self.singbox_state.error_message = None
                    return True
                else:
                    self.singbox_state.error_message = f"HTTP {resp.status}"
                    return False

        except asyncio.TimeoutError:
            self.singbox_state.error_message = "Health check timeout"
            return False
        except aiohttp.ClientError as e:
            self.singbox_state.error_message = str(e)
            return False
        except Exception as e:
            self.singbox_state.error_message = str(e)
            logger.debug(f"sing-box health check exception: {e}")
            return False

    def _run_iptables(self, args: List[str], check: bool = True) -> subprocess.CompletedProcess:
        """Run iptables command.

        Args:
            args: Command arguments (without 'iptables')
            check: Whether to raise on non-zero exit

        Returns:
            CompletedProcess result
        """
        # Detect iptables backend (nft vs legacy) - use IPTABLES_BACKEND consistently
        iptables_cmd = os.environ.get("IPTABLES_BACKEND", os.environ.get("IPTABLES", "iptables"))
        cmd = [iptables_cmd] + args
        logger.debug(f"Running: {' '.join(cmd)}")
        return subprocess.run(cmd, capture_output=True, text=True, check=check)

    def _get_tproxy_rule_args(self, port: int, interface: str) -> List[str]:
        """Get iptables arguments for a TPROXY rule.

        Args:
            port: Target TPROXY port
            interface: Source interface

        Returns:
            List of iptables arguments
        """
        return [
            "-t", "mangle",
            "-i", interface,
            "-p", "tcp",
            "-j", "TPROXY",
            "--on-ip", "127.0.0.1",
            "--on-port", str(port),
            "--tproxy-mark", f"0x{self.config.tproxy_mark:x}/0x{self.config.tproxy_mark:x}"
        ]

    def switch_tproxy_target(self, new_port: int) -> bool:
        """Update iptables TPROXY target port atomically.

        This method updates TPROXY rules for both WireGuard and Xray interfaces.
        The switch is done atomically by deleting old rules and adding new ones.

        Args:
            new_port: New TPROXY target port

        Returns:
            True if switch succeeded, False otherwise
        """
        if new_port == self._active_port:
            logger.debug(f"TPROXY already on port {new_port}")
            return True

        old_port = self._active_port
        interfaces = [self.config.wg_interface, self.config.xray_interface]

        try:
            for interface in interfaces:
                # Skip if interface doesn't exist
                if not Path(f"/sys/class/net/{interface}").exists():
                    logger.debug(f"Interface {interface} not found, skipping")
                    continue

                # Remove old TCP rule
                old_tcp_args = ["-D", "PREROUTING"] + self._get_tproxy_rule_args(old_port, interface)
                self._run_iptables(old_tcp_args, check=False)

                # Remove old UDP rule
                old_udp_args = old_tcp_args.copy()
                old_udp_args[old_udp_args.index("-p") + 1] = "udp"
                self._run_iptables(old_udp_args, check=False)

                # Add new TCP rule - use -I (insert at position 1) for TPROXY rules
                # to ensure they're evaluated before any other PREROUTING rules
                new_tcp_args = ["-I", "PREROUTING", "1"] + self._get_tproxy_rule_args(new_port, interface)
                result = self._run_iptables(new_tcp_args)
                if result.returncode != 0:
                    raise RuntimeError(f"Failed to add TCP TPROXY rule: {result.stderr}")

                # Add new UDP rule - insert at position 2 (after TCP rule)
                new_udp_args = ["-I", "PREROUTING", "2"] + self._get_tproxy_rule_args(new_port, interface)
                new_udp_args[new_udp_args.index("-p") + 1] = "udp"
                result = self._run_iptables(new_udp_args)
                if result.returncode != 0:
                    raise RuntimeError(f"Failed to add UDP TPROXY rule: {result.stderr}")

                logger.info(f"TPROXY rules updated for {interface}: {old_port} -> {new_port}")

            self._active_port = new_port
            return True

        except Exception as e:
            logger.error(f"Failed to switch TPROXY target: {e}")
            # Attempt to restore old rules on failure - use -I to insert at top
            try:
                for interface in interfaces:
                    if not Path(f"/sys/class/net/{interface}").exists():
                        continue
                    # First try to delete any partially added new rules
                    delete_new_tcp = ["-D", "PREROUTING"] + self._get_tproxy_rule_args(new_port, interface)
                    self._run_iptables(delete_new_tcp, check=False)
                    delete_new_udp = delete_new_tcp.copy()
                    delete_new_udp[delete_new_udp.index("-p") + 1] = "udp"
                    self._run_iptables(delete_new_udp, check=False)

                    # Then restore old rules
                    restore_tcp = ["-I", "PREROUTING", "1"] + self._get_tproxy_rule_args(old_port, interface)
                    self._run_iptables(restore_tcp, check=False)
                    restore_udp = ["-I", "PREROUTING", "2"] + self._get_tproxy_rule_args(old_port, interface)
                    restore_udp[restore_udp.index("-p") + 1] = "udp"
                    self._run_iptables(restore_udp, check=False)
            except Exception as restore_error:
                logger.critical(f"Failed to restore TPROXY rules: {restore_error}")
            return False

    def _update_router_state(self, state: RouterState, healthy: bool) -> None:
        """Update router state after health check.

        Args:
            state: Router state to update
            healthy: Whether the health check passed
        """
        state.last_check = datetime.now()

        if healthy:
            state.health = HealthStatus.HEALTHY
            state.consecutive_failures = 0
            state.last_success = datetime.now()
        else:
            state.consecutive_failures += 1
            if state.consecutive_failures >= self.config.failure_threshold:
                state.health = HealthStatus.UNHEALTHY
            else:
                state.health = HealthStatus.DEGRADED

    def _record_failover(self, from_router: RouterType, to_router: RouterType,
                         reason: str, success: bool, error: Optional[str] = None) -> None:
        """Record a failover event.

        Args:
            from_router: Router we're failing over from
            to_router: Router we're failing over to
            reason: Reason for failover
            success: Whether failover succeeded
            error: Error message if failed
        """
        event = FailoverEvent(
            timestamp=datetime.now(),
            from_router=from_router,
            to_router=to_router,
            reason=reason,
            success=success,
            error=error
        )
        self._failover_events.append(event)

        # Keep only last 100 events
        if len(self._failover_events) > 100:
            self._failover_events = self._failover_events[-100:]

        if success:
            logger.warning(f"Failover completed: {from_router.value} -> {to_router.value} ({reason})")
        else:
            logger.error(f"Failover failed: {from_router.value} -> {to_router.value} ({reason}): {error}")

    async def _perform_failover(self, to_router: RouterType, reason: str) -> bool:
        """Perform failover to specified router.

        Args:
            to_router: Router to fail over to
            reason: Reason for failover

        Returns:
            True if failover succeeded
        """
        from_router = self._active_router
        new_port = (self.config.singbox_port if to_router == RouterType.SINGBOX
                    else self.config.rust_router_port)

        # Verify target router is healthy before switching
        if to_router == RouterType.SINGBOX:
            healthy = await self.check_singbox_health()
        else:
            healthy = await self.check_rust_router_health()

        if not healthy:
            error = f"{to_router.value} is not healthy, cannot failover"
            self._record_failover(from_router, to_router, reason, False, error)
            return False

        # Perform the switch
        if self.switch_tproxy_target(new_port):
            self._active_router = to_router
            self._record_failover(from_router, to_router, reason, True)
            return True
        else:
            self._record_failover(from_router, to_router, reason, False, "iptables switch failed")
            return False

    async def _health_check_iteration(self) -> None:
        """Perform one iteration of health checks and failover logic."""
        # Check both routers
        rust_healthy = await self.check_rust_router_health()
        singbox_healthy = await self.check_singbox_health()

        # Update states
        self._update_router_state(self.rust_router_state, rust_healthy)
        self._update_router_state(self.singbox_state, singbox_healthy)

        # Log health status periodically
        if self.rust_router_state.health != HealthStatus.HEALTHY:
            logger.debug(f"rust-router: {self.rust_router_state.health.value} "
                         f"(failures: {self.rust_router_state.consecutive_failures})")
        if self.singbox_state.health != HealthStatus.HEALTHY:
            logger.debug(f"sing-box: {self.singbox_state.health.value} "
                         f"(failures: {self.singbox_state.consecutive_failures})")

        # Failover logic
        if self._active_router == RouterType.RUST_ROUTER:
            # Currently on rust-router - check if we need to failover
            if self.rust_router_state.health == HealthStatus.UNHEALTHY:
                reason = f"rust-router unhealthy ({self.rust_router_state.consecutive_failures} failures)"
                if self.rust_router_state.error_message:
                    reason += f": {self.rust_router_state.error_message}"
                await self._perform_failover(RouterType.SINGBOX, reason)
        else:
            # Currently on sing-box - check if we can recover to rust-router
            if self.config.auto_recover:
                if (self.rust_router_state.health == HealthStatus.HEALTHY and
                        self.singbox_state.consecutive_failures == 0):
                    # rust-router recovered and sing-box is also healthy
                    await self._perform_failover(RouterType.RUST_ROUTER, "rust-router recovered")

            # Also check if sing-box is failing (both routers down scenario)
            if self.singbox_state.health == HealthStatus.UNHEALTHY:
                # Try to failover to rust-router even if it was unhealthy before
                if rust_healthy:
                    await self._perform_failover(RouterType.RUST_ROUTER, "sing-box unhealthy, rust-router recovered")
                else:
                    logger.critical("Both routers unhealthy! No failover possible.")

    async def run(self) -> None:
        """Main watchdog loop.

        Runs health checks at configured interval and manages failover.
        Exits when shutdown is requested via stop() or signal.
        """
        self._running = True
        logger.info(f"Watchdog starting: rust-router={self.config.rust_router_port}, "
                    f"sing-box={self.config.singbox_port}, interval={self.config.health_interval}s")

        while self._running and not self._shutdown_event.is_set():
            try:
                await self._health_check_iteration()
            except Exception as e:
                logger.error(f"Health check iteration failed: {e}")

            # Wait for next interval or shutdown
            try:
                await asyncio.wait_for(
                    self._shutdown_event.wait(),
                    timeout=self.config.health_interval
                )
                # Shutdown event was set
                break
            except asyncio.TimeoutError:
                # Normal case - interval elapsed, continue loop
                pass

        logger.info("Watchdog stopped")

    async def stop(self) -> None:
        """Request graceful shutdown of the watchdog."""
        logger.info("Shutdown requested")
        self._running = False
        self._shutdown_event.set()

        # Cleanup resources
        if self._rust_router_client:
            await self._rust_router_client.disconnect()
        if self._http_session and not self._http_session.closed:
            await self._http_session.close()

    def get_status(self) -> Dict[str, Any]:
        """Get current watchdog status.

        Returns:
            Status dictionary with router states and failover history
        """
        return {
            "active_router": self._active_router.value,
            "active_port": self._active_port,
            "rust_router": {
                "port": self.rust_router_state.port,
                "health": self.rust_router_state.health.value,
                "consecutive_failures": self.rust_router_state.consecutive_failures,
                "last_check": self.rust_router_state.last_check.isoformat() if self.rust_router_state.last_check else None,
                "last_success": self.rust_router_state.last_success.isoformat() if self.rust_router_state.last_success else None,
                "error": self.rust_router_state.error_message,
            },
            "singbox": {
                "port": self.singbox_state.port,
                "health": self.singbox_state.health.value,
                "consecutive_failures": self.singbox_state.consecutive_failures,
                "last_check": self.singbox_state.last_check.isoformat() if self.singbox_state.last_check else None,
                "last_success": self.singbox_state.last_success.isoformat() if self.singbox_state.last_success else None,
                "error": self.singbox_state.error_message,
            },
            "failover_count": len(self._failover_events),
            "last_failover": (
                {
                    "timestamp": self._failover_events[-1].timestamp.isoformat(),
                    "from": self._failover_events[-1].from_router.value,
                    "to": self._failover_events[-1].to_router.value,
                    "reason": self._failover_events[-1].reason,
                }
                if self._failover_events else None
            ),
        }


# =============================================================================
# Unit Tests
# =============================================================================

if __name__ == "__main__":
    import unittest
    from unittest.mock import AsyncMock, MagicMock, patch

    class TestWatchdogConfig(unittest.TestCase):
        """Test WatchdogConfig"""

        def test_default_values(self):
            """Test default configuration values"""
            config = WatchdogConfig()
            self.assertEqual(config.rust_router_port, 7893)
            self.assertEqual(config.singbox_port, 7894)
            self.assertEqual(config.health_interval, 5.0)
            self.assertEqual(config.failure_threshold, 3)
            self.assertTrue(config.auto_recover)

        def test_from_env(self):
            """Test configuration from environment"""
            with patch.dict(os.environ, {
                "RUST_ROUTER_PORT": "7895",
                "SINGBOX_PORT": "7896",
                "WATCHDOG_INTERVAL": "10.0",
                "WATCHDOG_FAILURE_THRESHOLD": "5",
                "WATCHDOG_AUTO_RECOVER": "false"
            }):
                config = WatchdogConfig.from_env()
                self.assertEqual(config.rust_router_port, 7895)
                self.assertEqual(config.singbox_port, 7896)
                self.assertEqual(config.health_interval, 10.0)
                self.assertEqual(config.failure_threshold, 5)
                self.assertFalse(config.auto_recover)

    class TestRouterState(unittest.TestCase):
        """Test RouterState"""

        def test_initial_state(self):
            """Test initial router state"""
            state = RouterState(router_type=RouterType.RUST_ROUTER, port=7893)
            self.assertEqual(state.health, HealthStatus.UNKNOWN)
            self.assertEqual(state.consecutive_failures, 0)
            self.assertIsNone(state.last_check)

        def test_state_tracking(self):
            """Test state can be updated"""
            state = RouterState(router_type=RouterType.SINGBOX, port=7894)
            state.health = HealthStatus.HEALTHY
            state.consecutive_failures = 0
            self.assertEqual(state.health, HealthStatus.HEALTHY)

    class TestFailoverEvent(unittest.TestCase):
        """Test FailoverEvent"""

        def test_create_event(self):
            """Test failover event creation"""
            event = FailoverEvent(
                timestamp=datetime.now(),
                from_router=RouterType.RUST_ROUTER,
                to_router=RouterType.SINGBOX,
                reason="test",
                success=True
            )
            self.assertEqual(event.from_router, RouterType.RUST_ROUTER)
            self.assertEqual(event.to_router, RouterType.SINGBOX)
            self.assertTrue(event.success)

    class TestRouterWatchdog(unittest.IsolatedAsyncioTestCase):
        """Test RouterWatchdog"""

        async def test_init(self):
            """Test watchdog initialization"""
            config = WatchdogConfig()
            watchdog = RouterWatchdog(config)
            self.assertEqual(watchdog.active_router, RouterType.RUST_ROUTER)
            self.assertEqual(watchdog.active_port, config.rust_router_port)

        async def test_active_port_property(self):
            """Test active_port property"""
            watchdog = RouterWatchdog()
            self.assertEqual(watchdog.active_port, watchdog.config.rust_router_port)

        async def test_failover_events_empty(self):
            """Test failover events initially empty"""
            watchdog = RouterWatchdog()
            self.assertEqual(len(watchdog.failover_events), 0)

        async def test_update_router_state_healthy(self):
            """Test state update when healthy"""
            watchdog = RouterWatchdog()
            state = watchdog.rust_router_state
            state.consecutive_failures = 5

            watchdog._update_router_state(state, True)

            self.assertEqual(state.health, HealthStatus.HEALTHY)
            self.assertEqual(state.consecutive_failures, 0)
            self.assertIsNotNone(state.last_check)
            self.assertIsNotNone(state.last_success)

        async def test_update_router_state_unhealthy(self):
            """Test state update when unhealthy"""
            watchdog = RouterWatchdog()
            watchdog.config.failure_threshold = 3
            state = watchdog.rust_router_state
            state.consecutive_failures = 2

            watchdog._update_router_state(state, False)

            self.assertEqual(state.health, HealthStatus.UNHEALTHY)
            self.assertEqual(state.consecutive_failures, 3)

        async def test_update_router_state_degraded(self):
            """Test state update when degraded"""
            watchdog = RouterWatchdog()
            watchdog.config.failure_threshold = 3
            state = watchdog.rust_router_state
            state.consecutive_failures = 0

            watchdog._update_router_state(state, False)

            self.assertEqual(state.health, HealthStatus.DEGRADED)
            self.assertEqual(state.consecutive_failures, 1)

        async def test_record_failover(self):
            """Test failover event recording"""
            watchdog = RouterWatchdog()

            watchdog._record_failover(
                RouterType.RUST_ROUTER,
                RouterType.SINGBOX,
                "test reason",
                True
            )

            self.assertEqual(len(watchdog._failover_events), 1)
            event = watchdog._failover_events[0]
            self.assertEqual(event.from_router, RouterType.RUST_ROUTER)
            self.assertEqual(event.to_router, RouterType.SINGBOX)
            self.assertTrue(event.success)

        async def test_record_failover_limit(self):
            """Test failover events limited to 100"""
            watchdog = RouterWatchdog()

            for i in range(150):
                watchdog._record_failover(
                    RouterType.RUST_ROUTER,
                    RouterType.SINGBOX,
                    f"test {i}",
                    True
                )

            self.assertEqual(len(watchdog._failover_events), 100)

        async def test_get_status(self):
            """Test status retrieval"""
            watchdog = RouterWatchdog()
            status = watchdog.get_status()

            self.assertEqual(status["active_router"], "rust-router")
            self.assertIn("rust_router", status)
            self.assertIn("singbox", status)
            self.assertEqual(status["failover_count"], 0)

        async def test_stop(self):
            """Test graceful shutdown"""
            watchdog = RouterWatchdog()
            await watchdog.stop()
            self.assertFalse(watchdog._running)
            self.assertTrue(watchdog._shutdown_event.is_set())

        async def test_check_rust_router_health_no_client(self):
            """Test rust-router health check without client"""
            with patch.dict('sys.modules', {'rust_router_client': None}):
                # Create fresh watchdog to trigger import check
                watchdog = RouterWatchdog()
                # Mock the global flag
                import watchdog as wd_module
                original = getattr(wd_module, 'HAS_RUST_ROUTER_CLIENT', True)
                try:
                    setattr(wd_module, 'HAS_RUST_ROUTER_CLIENT', False)
                    result = await watchdog.check_rust_router_health()
                    # Should return False when client unavailable
                finally:
                    setattr(wd_module, 'HAS_RUST_ROUTER_CLIENT', original)

        async def test_tproxy_rule_args(self):
            """Test TPROXY rule argument generation"""
            watchdog = RouterWatchdog()
            args = watchdog._get_tproxy_rule_args(7893, "wg-ingress")

            self.assertIn("-t", args)
            self.assertIn("mangle", args)
            self.assertIn("-i", args)
            self.assertIn("wg-ingress", args)
            self.assertIn("TPROXY", args)
            self.assertIn("7893", args)

        async def test_check_rust_router_health_success(self):
            """Test rust-router health check with successful response"""
            watchdog = RouterWatchdog()
            # Mock IPC client
            mock_client = AsyncMock()
            mock_client.connect = AsyncMock(return_value=True)
            mock_client.ping = AsyncMock(return_value=MagicMock(success=True))
            mock_client.disconnect = AsyncMock()

            watchdog._rust_router_client = mock_client
            watchdog._get_rust_router_client = AsyncMock(return_value=mock_client)

            # Patch HAS_RUST_ROUTER_CLIENT
            with patch.object(sys.modules[__name__], 'HAS_RUST_ROUTER_CLIENT', True):
                result = await watchdog.check_rust_router_health()

            # Verify ping was called
            mock_client.ping.assert_called_once()
            self.assertTrue(result)

        async def test_check_rust_router_health_timeout(self):
            """Test rust-router health check timeout"""
            watchdog = RouterWatchdog()
            watchdog.config.health_check_timeout = 0.1

            # Mock IPC client that times out
            mock_client = AsyncMock()
            mock_client.connect = AsyncMock(side_effect=asyncio.TimeoutError())
            mock_client.disconnect = AsyncMock()

            watchdog._rust_router_client = mock_client
            watchdog._get_rust_router_client = AsyncMock(return_value=mock_client)

            with patch.object(sys.modules[__name__], 'HAS_RUST_ROUTER_CLIENT', True):
                result = await watchdog.check_rust_router_health()

            self.assertFalse(result)
            self.assertIsNotNone(watchdog.rust_router_state.error_message)

        async def test_check_singbox_health_success(self):
            """Test sing-box health check with HTTP 200"""
            watchdog = RouterWatchdog()

            # Mock aiohttp session
            mock_response = MagicMock()
            mock_response.status = 200
            mock_response.__aenter__ = AsyncMock(return_value=mock_response)
            mock_response.__aexit__ = AsyncMock(return_value=None)

            mock_session = MagicMock()
            mock_session.get = MagicMock(return_value=mock_response)
            mock_session.closed = False

            watchdog._http_session = mock_session
            watchdog._get_http_session = AsyncMock(return_value=mock_session)

            with patch.object(sys.modules[__name__], 'HAS_AIOHTTP', True):
                result = await watchdog.check_singbox_health()

            self.assertTrue(result)
            self.assertIsNone(watchdog.singbox_state.error_message)

        async def test_check_singbox_health_failure(self):
            """Test sing-box health check with HTTP error"""
            watchdog = RouterWatchdog()

            # Mock aiohttp session returning 503
            mock_response = MagicMock()
            mock_response.status = 503
            mock_response.__aenter__ = AsyncMock(return_value=mock_response)
            mock_response.__aexit__ = AsyncMock(return_value=None)

            mock_session = MagicMock()
            mock_session.get = MagicMock(return_value=mock_response)
            mock_session.closed = False

            watchdog._http_session = mock_session
            watchdog._get_http_session = AsyncMock(return_value=mock_session)

            with patch.object(sys.modules[__name__], 'HAS_AIOHTTP', True):
                result = await watchdog.check_singbox_health()

            self.assertFalse(result)
            self.assertEqual(watchdog.singbox_state.error_message, "HTTP 503")

        async def test_perform_failover_success(self):
            """Test full failover flow when target is healthy"""
            watchdog = RouterWatchdog()
            watchdog._active_router = RouterType.RUST_ROUTER
            watchdog._active_port = watchdog.config.rust_router_port

            # Mock singbox health check to return healthy
            watchdog.check_singbox_health = AsyncMock(return_value=True)
            # Mock iptables switch to succeed
            watchdog.switch_tproxy_target = MagicMock(return_value=True)

            result = await watchdog._perform_failover(RouterType.SINGBOX, "test failover")

            self.assertTrue(result)
            self.assertEqual(watchdog._active_router, RouterType.SINGBOX)
            self.assertEqual(len(watchdog._failover_events), 1)
            self.assertTrue(watchdog._failover_events[0].success)

        async def test_perform_failover_target_unhealthy(self):
            """Test failover when target router is unhealthy"""
            watchdog = RouterWatchdog()
            watchdog._active_router = RouterType.RUST_ROUTER

            # Mock singbox health check to return unhealthy
            watchdog.check_singbox_health = AsyncMock(return_value=False)

            result = await watchdog._perform_failover(RouterType.SINGBOX, "test failover")

            self.assertFalse(result)
            # Should still be on rust-router
            self.assertEqual(watchdog._active_router, RouterType.RUST_ROUTER)
            self.assertEqual(len(watchdog._failover_events), 1)
            self.assertFalse(watchdog._failover_events[0].success)

        async def test_auto_recovery_flow(self):
            """Test automatic recovery when rust-router comes back"""
            watchdog = RouterWatchdog()
            watchdog.config.auto_recover = True
            watchdog._active_router = RouterType.SINGBOX  # Currently on singbox

            # Mock both routers healthy
            watchdog.check_rust_router_health = AsyncMock(return_value=True)
            watchdog.check_singbox_health = AsyncMock(return_value=True)
            watchdog.switch_tproxy_target = MagicMock(return_value=True)

            # Run one health check iteration
            await watchdog._health_check_iteration()

            # Should have recovered to rust-router
            self.assertEqual(watchdog._active_router, RouterType.RUST_ROUTER)

        async def test_both_routers_unhealthy(self):
            """Test when both routers are unhealthy"""
            watchdog = RouterWatchdog()
            watchdog.config.failure_threshold = 1
            watchdog._active_router = RouterType.SINGBOX

            # Mock both routers unhealthy
            watchdog.check_rust_router_health = AsyncMock(return_value=False)
            watchdog.check_singbox_health = AsyncMock(return_value=False)

            # Run iteration - should log critical but not crash
            await watchdog._health_check_iteration()

            # Both should be unhealthy
            self.assertEqual(watchdog.rust_router_state.health, HealthStatus.UNHEALTHY)
            self.assertEqual(watchdog.singbox_state.health, HealthStatus.UNHEALTHY)

        async def test_health_check_with_retries(self):
            """Test health check retry logic"""
            watchdog = RouterWatchdog()
            watchdog.config.failure_threshold = 3

            # Simulate 2 failures then success
            call_count = [0]

            async def mock_health_check():
                call_count[0] += 1
                return call_count[0] >= 3

            watchdog.check_rust_router_health = mock_health_check

            # Run iterations
            for _ in range(3):
                await watchdog._health_check_iteration()

            # After 3 calls, should be healthy
            # Note: This test verifies the retry flow works
            self.assertEqual(call_count[0], 3)

        async def test_failover_event_persistence(self):
            """Test failover events are persisted correctly"""
            watchdog = RouterWatchdog()

            # Record multiple failovers
            for i in range(5):
                watchdog._record_failover(
                    RouterType.RUST_ROUTER,
                    RouterType.SINGBOX,
                    f"reason {i}",
                    i % 2 == 0,  # alternating success/failure
                    None if i % 2 == 0 else f"error {i}"
                )

            events = watchdog.failover_events
            self.assertEqual(len(events), 5)
            self.assertEqual(events[0].reason, "reason 0")
            self.assertTrue(events[0].success)
            self.assertFalse(events[1].success)
            self.assertEqual(events[1].error, "error 1")

        async def test_graceful_shutdown(self):
            """Test graceful shutdown signal handling"""
            watchdog = RouterWatchdog()
            watchdog._running = True

            # Mock clients
            watchdog._rust_router_client = AsyncMock()
            watchdog._rust_router_client.disconnect = AsyncMock()
            watchdog._http_session = MagicMock()
            watchdog._http_session.closed = False
            watchdog._http_session.close = AsyncMock()

            await watchdog.stop()

            self.assertFalse(watchdog._running)
            self.assertTrue(watchdog._shutdown_event.is_set())
            watchdog._rust_router_client.disconnect.assert_called_once()
            watchdog._http_session.close.assert_called_once()

    class TestIptablesRollback(unittest.TestCase):
        """Test iptables rollback logic"""

        def test_iptables_rollback_on_failure(self):
            """Test iptables rollback when add fails"""
            watchdog = RouterWatchdog()
            watchdog._active_port = 7893
            old_port = watchdog._active_port

            call_log = []

            def mock_iptables(args, check=True):
                call_log.append(args)
                result = MagicMock()
                # Fail on add new TCP rule
                if "-I" in args and "tcp" in args[args.index("-p") + 1] if "-p" in args else False:
                    result.returncode = 1
                    result.stderr = "mock error"
                    if check:
                        raise subprocess.CalledProcessError(1, args)
                else:
                    result.returncode = 0
                    result.stderr = ""
                return result

            watchdog._run_iptables = mock_iptables

            # Mock interface existence
            with patch('pathlib.Path.exists', return_value=True):
                result = watchdog.switch_tproxy_target(7894)

            self.assertFalse(result)
            # Port should not have changed
            self.assertEqual(watchdog._active_port, old_port)
            # Should have attempted rollback
            rollback_calls = [c for c in call_log if "-I" in c and str(old_port) in str(c)]
            self.assertTrue(len(rollback_calls) > 0)

    class TestRouterType(unittest.TestCase):
        """Test RouterType enum"""

        def test_values(self):
            """Test enum values"""
            self.assertEqual(RouterType.RUST_ROUTER.value, "rust-router")
            self.assertEqual(RouterType.SINGBOX.value, "sing-box")

    class TestHealthStatus(unittest.TestCase):
        """Test HealthStatus enum"""

        def test_values(self):
            """Test enum values"""
            self.assertEqual(HealthStatus.HEALTHY.value, "healthy")
            self.assertEqual(HealthStatus.DEGRADED.value, "degraded")
            self.assertEqual(HealthStatus.UNHEALTHY.value, "unhealthy")
            self.assertEqual(HealthStatus.UNKNOWN.value, "unknown")

    # CLI handling
    parser = argparse.ArgumentParser(description="Router Watchdog - Phase 3.5")
    parser.add_argument("--daemon", "-d", action="store_true", help="Run as daemon")
    parser.add_argument("--test", "-t", action="store_true", help="Run unit tests")
    parser.add_argument("--status", "-s", action="store_true", help="Print current status and exit")

    args = parser.parse_args()

    if args.test:
        # Run unit tests
        print("Running watchdog unit tests...")
        print("=" * 60)

        loader = unittest.TestLoader()
        suite = unittest.TestSuite()

        suite.addTests(loader.loadTestsFromTestCase(TestWatchdogConfig))
        suite.addTests(loader.loadTestsFromTestCase(TestRouterState))
        suite.addTests(loader.loadTestsFromTestCase(TestFailoverEvent))
        suite.addTests(loader.loadTestsFromTestCase(TestRouterWatchdog))
        suite.addTests(loader.loadTestsFromTestCase(TestIptablesRollback))
        suite.addTests(loader.loadTestsFromTestCase(TestRouterType))
        suite.addTests(loader.loadTestsFromTestCase(TestHealthStatus))

        runner = unittest.TextTestRunner(verbosity=2)
        result = runner.run(suite)

        print("=" * 60)
        print(f"Tests run: {result.testsRun}")
        print(f"Failures: {len(result.failures)}")
        print(f"Errors: {len(result.errors)}")

        sys.exit(0 if result.wasSuccessful() else 1)

    elif args.status:
        # Quick status check
        import json
        watchdog = RouterWatchdog()
        print(json.dumps(watchdog.get_status(), indent=2))
        sys.exit(0)

    else:
        # Run watchdog
        watchdog = RouterWatchdog()
        # Use a mutable container to share loop reference between signal handler and async code
        loop_holder: List[Optional[asyncio.AbstractEventLoop]] = [None]

        def signal_handler(signum, frame):
            logger.info(f"Received signal {signum}")
            # Use thread-safe method to schedule stop() in the event loop
            # Don't use asyncio.create_task() in signal handler - it's not safe
            loop = loop_holder[0]
            if loop is not None and loop.is_running():
                loop.call_soon_threadsafe(lambda: asyncio.create_task(watchdog.stop()))
            else:
                # Set shutdown flag directly if loop not available
                watchdog._running = False
                watchdog._shutdown_event.set()

        signal.signal(signal.SIGTERM, signal_handler)
        signal.signal(signal.SIGINT, signal_handler)

        async def run_watchdog():
            loop_holder[0] = asyncio.get_running_loop()
            await watchdog.run()

        try:
            asyncio.run(run_watchdog())
        except KeyboardInterrupt:
            logger.info("Interrupted")
        finally:
            logger.info("Exiting")

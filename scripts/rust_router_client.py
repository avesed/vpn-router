#!/usr/bin/env python3
"""
Rust Router IPC Client (v2.0)

Async client for communicating with rust-router via Unix socket.
Used by api_server.py for hot-reload and status queries.

Protocol v2.0 Features:
- GetOutboundStats support for per-outbound traffic statistics
- Connection timeout with configurable limits
- Version compatibility checking (accepts v1.0 - v2.0)
"""

import asyncio
import json
import logging
import os
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional

# Default socket path
DEFAULT_SOCKET_PATH = "/var/run/rust-router.sock"

# Protocol version - v2.0 adds capability negotiation and outbound stats
PROTOCOL_VERSION = "2.0"

# Minimum compatible Rust router version
MIN_COMPATIBLE_VERSION = "1.0"

# Default timeouts
DEFAULT_CONNECT_TIMEOUT = 5.0  # seconds
DEFAULT_REQUEST_TIMEOUT = 10.0  # seconds

logger = logging.getLogger(__name__)


@dataclass
class IpcResponse:
    """IPC response from rust-router"""
    success: bool
    id: str
    version: str
    error: Optional[str] = None
    data: Optional[dict] = None


@dataclass
class OutboundStats:
    """Per-outbound traffic statistics"""
    bytes_uploaded: int
    bytes_downloaded: int
    connections_total: int
    connections_active: int
    errors: int
    last_activity_ms: int


class IpcError(Exception):
    """IPC communication error"""
    pass


class VersionMismatchError(IpcError):
    """Protocol version mismatch error"""
    def __init__(self, client_version: str, server_version: str):
        self.client_version = client_version
        self.server_version = server_version
        super().__init__(
            f"Protocol version mismatch: client={client_version}, server={server_version}"
        )


class RustRouterClient:
    """
    Async client for rust-router IPC communication (v2.0).

    Features:
    - Configurable connection and request timeouts
    - Version compatibility checking (v1.0 - v2.0)
    - Per-outbound traffic statistics via GetOutboundStats

    Note: This client is coroutine-safe when used with async context manager,
    but not thread-safe. Use separate instances for different threads.

    Usage:
        async with RustRouterClient() as client:
            status = await client.get_status()
            print(f"Active connections: {status.data['active_connections']}")

            # Get per-outbound stats (new in v2.0)
            outbound_stats = await client.get_outbound_stats()
            for tag, stats in outbound_stats.items():
                print(f"{tag}: {stats.bytes_downloaded} bytes downloaded")
    """

    def __init__(
        self,
        socket_path: Optional[str] = None,
        connect_timeout: float = DEFAULT_CONNECT_TIMEOUT,
        request_timeout: float = DEFAULT_REQUEST_TIMEOUT,
    ):
        self.socket_path = socket_path or os.environ.get(
            "RUST_ROUTER_SOCKET", DEFAULT_SOCKET_PATH
        )
        self.connect_timeout = connect_timeout
        self.request_timeout = request_timeout
        self._reader: Optional[asyncio.StreamReader] = None
        self._writer: Optional[asyncio.StreamWriter] = None
        self._server_version: Optional[str] = None

    async def __aenter__(self) -> "RustRouterClient":
        await self.connect()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self.close()

    async def connect(self) -> None:
        """Connect to rust-router IPC socket with timeout"""
        if not Path(self.socket_path).exists():
            raise FileNotFoundError(f"Socket not found: {self.socket_path}")

        try:
            self._reader, self._writer = await asyncio.wait_for(
                asyncio.open_unix_connection(self.socket_path),
                timeout=self.connect_timeout,
            )
            logger.debug(f"Connected to rust-router at {self.socket_path}")
        except asyncio.TimeoutError:
            raise IpcError(f"Connection timeout after {self.connect_timeout}s")

    async def close(self) -> None:
        """Close the connection"""
        if self._writer:
            self._writer.close()
            try:
                await self._writer.wait_closed()
            except Exception:
                pass  # Ignore errors during close
            self._writer = None
            self._reader = None
            logger.debug("Disconnected from rust-router")

    def _check_version_compatibility(self, server_version: str) -> None:
        """Check if server version is compatible with client"""
        # Parse versions (simple major.minor comparison)
        try:
            server_major, server_minor = map(int, server_version.split(".")[:2])
            min_major, min_minor = map(int, MIN_COMPATIBLE_VERSION.split(".")[:2])

            if server_major < min_major or (
                server_major == min_major and server_minor < min_minor
            ):
                raise VersionMismatchError(PROTOCOL_VERSION, server_version)
        except ValueError:
            logger.warning(f"Could not parse server version: {server_version}")

    async def _send_request(self, command: dict, timeout: Optional[float] = None) -> IpcResponse:
        """Send a request and wait for response with timeout"""
        if not self._writer or not self._reader:
            raise RuntimeError("Not connected")

        timeout = timeout or self.request_timeout
        request_id = str(uuid.uuid4())
        request = {
            "version": PROTOCOL_VERSION,
            "id": request_id,
            "command": command
        }

        try:
            # Send request (newline-delimited JSON)
            data = json.dumps(request) + "\n"
            self._writer.write(data.encode())
            await self._writer.drain()

            # Read response with timeout
            line = await asyncio.wait_for(
                self._reader.readline(),
                timeout=timeout,
            )
            if not line:
                raise ConnectionError("Connection closed by server")

            response = json.loads(line.decode())

            # Check version compatibility on first response
            server_version = response.get("version", "1.0")
            if self._server_version is None:
                self._server_version = server_version
                self._check_version_compatibility(server_version)

            return IpcResponse(
                success=response.get("success", False),
                id=response.get("id", ""),
                version=server_version,
                error=response.get("error"),
                data=response.get("data")
            )
        except asyncio.TimeoutError:
            raise IpcError(f"Request timeout after {timeout}s")

    async def ping(self) -> IpcResponse:
        """Ping the server"""
        return await self._send_request({"type": "ping"})

    async def get_status(self) -> IpcResponse:
        """Get server status"""
        return await self._send_request({"type": "status"})

    async def get_stats(self) -> IpcResponse:
        """Get connection statistics"""
        return await self._send_request({"type": "get_stats"})

    async def get_outbound_stats(self) -> Dict[str, OutboundStats]:
        """
        Get per-outbound traffic statistics (v2.0).

        Returns a dict mapping outbound tag to OutboundStats.

        Example:
            stats = await client.get_outbound_stats()
            for tag, s in stats.items():
                print(f"{tag}: {s.bytes_downloaded} bytes, {s.connections_active} active")
        """
        response = await self._send_request({"type": "get_outbound_stats"})
        if not response.success:
            raise IpcError(response.error or "Failed to get outbound stats")

        result = {}
        if response.data:
            for tag, data in response.data.items():
                result[tag] = OutboundStats(
                    bytes_uploaded=data.get("bytes_uploaded", 0),
                    bytes_downloaded=data.get("bytes_downloaded", 0),
                    connections_total=data.get("connections_total", 0),
                    connections_active=data.get("connections_active", 0),
                    errors=data.get("errors", 0),
                    last_activity_ms=data.get("last_activity_ms", 0),
                )
        return result

    async def get_outbound_stats_raw(self) -> IpcResponse:
        """Get per-outbound traffic statistics as raw IpcResponse"""
        return await self._send_request({"type": "get_outbound_stats"})

    async def reload(self, config_path: str) -> IpcResponse:
        """Reload configuration from file"""
        return await self._send_request({
            "type": "reload",
            "config_path": config_path
        })

    async def shutdown(self) -> IpcResponse:
        """Request graceful shutdown"""
        return await self._send_request({"type": "shutdown"})

    @property
    def server_version(self) -> Optional[str]:
        """Server version (available after first request)"""
        return self._server_version

    @property
    def is_connected(self) -> bool:
        """Check if client is connected"""
        return self._writer is not None and not self._writer.is_closing()


# Convenience functions for one-off operations
async def ping(socket_path: Optional[str] = None) -> bool:
    """Ping rust-router and return True if healthy"""
    try:
        async with RustRouterClient(socket_path) as client:
            response = await client.ping()
            return response.success
    except Exception:
        return False


async def get_status(socket_path: Optional[str] = None) -> Optional[dict]:
    """Get rust-router status"""
    try:
        async with RustRouterClient(socket_path) as client:
            response = await client.get_status()
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


async def get_outbound_stats(socket_path: Optional[str] = None) -> Optional[Dict[str, OutboundStats]]:
    """Get per-outbound traffic statistics"""
    try:
        async with RustRouterClient(socket_path) as client:
            return await client.get_outbound_stats()
    except Exception:
        return None


# CLI interface for testing
if __name__ == "__main__":
    import argparse
    import sys

    parser = argparse.ArgumentParser(
        description="Rust Router IPC Client (v2.0)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s ping                     # Health check
  %(prog)s status                   # Get server status
  %(prog)s stats                    # Get connection statistics
  %(prog)s outbound-stats           # Get per-outbound traffic stats
  %(prog)s reload -c /path/to/cfg   # Reload configuration
  %(prog)s shutdown                 # Request graceful shutdown
        """
    )
    parser.add_argument(
        "--socket", "-s",
        default=DEFAULT_SOCKET_PATH,
        help="IPC socket path"
    )
    parser.add_argument(
        "command",
        choices=["ping", "status", "stats", "outbound-stats", "reload", "shutdown"],
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
                    response = await client.get_status()
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
                    try:
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
                    except IpcError as e:
                        error(f"Error: {e}")
                        return 1

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

        except FileNotFoundError:
            error(f"Error: Socket not found: {args.socket}")
            return 1
        except ConnectionError as e:
            error(f"Error: {e}")
            return 1

    sys.exit(asyncio.run(main()))

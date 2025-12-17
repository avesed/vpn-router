#!/usr/bin/env python3
"""
Lightweight SOCKS5 proxy for OpenVPN tunnels.
Binds to a specific interface to route traffic through OpenVPN.

Usage:
    python3 socks5_proxy.py --port 37001 --bind-interface tun0
    python3 socks5_proxy.py --port 37001 --bind-ip 10.8.0.6
"""

import argparse
import asyncio
import logging
import signal
import socket
import struct
import sys
from typing import Optional

logging.basicConfig(
    level=logging.INFO,
    format='[socks5] %(asctime)s %(levelname)s: %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger(__name__)

# SOCKS5 constants
SOCKS_VERSION = 0x05
AUTH_NONE = 0x00
CMD_CONNECT = 0x01
ATYP_IPV4 = 0x01
ATYP_DOMAIN = 0x03
ATYP_IPV6 = 0x04
REP_SUCCESS = 0x00
REP_GENERAL_FAILURE = 0x01
REP_CONNECTION_NOT_ALLOWED = 0x02
REP_NETWORK_UNREACHABLE = 0x03
REP_HOST_UNREACHABLE = 0x04
REP_CONNECTION_REFUSED = 0x05


class SOCKS5Server:
    """Lightweight SOCKS5 proxy server."""

    def __init__(
        self,
        listen_host: str = '127.0.0.1',
        listen_port: int = 1080,
        bind_interface: Optional[str] = None,
        bind_ip: Optional[str] = None
    ):
        self.listen_host = listen_host
        self.listen_port = listen_port
        self.bind_interface = bind_interface
        self.bind_ip = bind_ip
        self.server: Optional[asyncio.Server] = None
        self.running = False
        self.connections = 0

    async def start(self):
        """Start the SOCKS5 server."""
        self.server = await asyncio.start_server(
            self._handle_client,
            self.listen_host,
            self.listen_port
        )
        self.running = True
        bind_info = f"interface={self.bind_interface}" if self.bind_interface else f"ip={self.bind_ip}"
        logger.info(f"SOCKS5 proxy started on {self.listen_host}:{self.listen_port} ({bind_info})")

        async with self.server:
            await self.server.serve_forever()

    async def stop(self):
        """Stop the SOCKS5 server."""
        self.running = False
        if self.server:
            self.server.close()
            await self.server.wait_closed()
        logger.info("SOCKS5 proxy stopped")

    async def _handle_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        """Handle a single client connection."""
        client_addr = writer.get_extra_info('peername')
        self.connections += 1
        conn_id = self.connections

        try:
            # Step 1: Handshake - receive client greeting
            greeting = await asyncio.wait_for(reader.read(2), timeout=10)
            if len(greeting) < 2 or greeting[0] != SOCKS_VERSION:
                logger.warning(f"[{conn_id}] Invalid SOCKS version from {client_addr}")
                writer.close()
                return

            num_methods = greeting[1]
            methods = await asyncio.wait_for(reader.read(num_methods), timeout=10)

            # Only support no-auth
            if AUTH_NONE not in methods:
                writer.write(bytes([SOCKS_VERSION, 0xFF]))  # No acceptable methods
                await writer.drain()
                writer.close()
                return

            # Accept no-auth
            writer.write(bytes([SOCKS_VERSION, AUTH_NONE]))
            await writer.drain()

            # Step 2: Receive connection request
            request = await asyncio.wait_for(reader.read(4), timeout=10)
            if len(request) < 4:
                writer.close()
                return

            version, cmd, _, atyp = request

            if version != SOCKS_VERSION:
                writer.close()
                return

            if cmd != CMD_CONNECT:
                # Only support CONNECT command
                await self._send_reply(writer, REP_CONNECTION_NOT_ALLOWED, '0.0.0.0', 0)
                writer.close()
                return

            # Parse destination address
            dst_addr, dst_port = await self._parse_address(reader, atyp)
            if dst_addr is None:
                await self._send_reply(writer, REP_GENERAL_FAILURE, '0.0.0.0', 0)
                writer.close()
                return

            logger.debug(f"[{conn_id}] {client_addr} -> {dst_addr}:{dst_port}")

            # Step 3: Connect to destination through bound interface
            try:
                remote_reader, remote_writer = await self._connect_remote(dst_addr, dst_port)
            except OSError as e:
                logger.warning(f"[{conn_id}] Connection to {dst_addr}:{dst_port} failed: {e}")
                if 'refused' in str(e).lower():
                    await self._send_reply(writer, REP_CONNECTION_REFUSED, '0.0.0.0', 0)
                elif 'unreachable' in str(e).lower():
                    await self._send_reply(writer, REP_HOST_UNREACHABLE, '0.0.0.0', 0)
                else:
                    await self._send_reply(writer, REP_GENERAL_FAILURE, '0.0.0.0', 0)
                writer.close()
                return

            # Send success reply
            bind_addr = remote_writer.get_extra_info('sockname')
            await self._send_reply(writer, REP_SUCCESS, bind_addr[0], bind_addr[1])

            # Step 4: Relay data bidirectionally
            await self._relay(reader, writer, remote_reader, remote_writer, conn_id)

        except asyncio.TimeoutError:
            logger.debug(f"[{conn_id}] Timeout from {client_addr}")
        except ConnectionResetError:
            logger.debug(f"[{conn_id}] Connection reset from {client_addr}")
        except Exception as e:
            logger.error(f"[{conn_id}] Error handling {client_addr}: {e}")
        finally:
            try:
                writer.close()
                await writer.wait_closed()
            except:
                pass

    async def _parse_address(self, reader: asyncio.StreamReader, atyp: int):
        """Parse destination address based on address type."""
        try:
            if atyp == ATYP_IPV4:
                addr_data = await asyncio.wait_for(reader.read(4), timeout=10)
                addr = socket.inet_ntoa(addr_data)
            elif atyp == ATYP_DOMAIN:
                domain_len = (await asyncio.wait_for(reader.read(1), timeout=10))[0]
                addr = (await asyncio.wait_for(reader.read(domain_len), timeout=10)).decode('utf-8')
            elif atyp == ATYP_IPV6:
                addr_data = await asyncio.wait_for(reader.read(16), timeout=10)
                addr = socket.inet_ntop(socket.AF_INET6, addr_data)
            else:
                return None, None

            port_data = await asyncio.wait_for(reader.read(2), timeout=10)
            port = struct.unpack('!H', port_data)[0]
            return addr, port
        except:
            return None, None

    async def _connect_remote(self, host: str, port: int):
        """Connect to remote host, optionally binding to interface/IP."""
        loop = asyncio.get_event_loop()

        # Resolve hostname if needed
        if not self._is_ip(host):
            infos = await loop.getaddrinfo(host, port, family=socket.AF_INET, type=socket.SOCK_STREAM)
            if not infos:
                raise OSError(f"Cannot resolve {host}")
            family, socktype, proto, canonname, sockaddr = infos[0]
            host = sockaddr[0]

        # Create socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setblocking(False)

        # Bind to interface or IP if specified
        if self.bind_interface:
            try:
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE,
                               self.bind_interface.encode() + b'\0')
            except Exception as e:
                logger.warning(f"Failed to bind to interface {self.bind_interface}: {e}")
        elif self.bind_ip:
            sock.bind((self.bind_ip, 0))

        # Connect
        await loop.sock_connect(sock, (host, port))

        reader, writer = await asyncio.open_connection(sock=sock)
        return reader, writer

    def _is_ip(self, s: str) -> bool:
        """Check if string is an IP address."""
        try:
            socket.inet_aton(s)
            return True
        except:
            pass
        try:
            socket.inet_pton(socket.AF_INET6, s)
            return True
        except:
            pass
        return False

    async def _send_reply(self, writer: asyncio.StreamWriter, rep: int, addr: str, port: int):
        """Send SOCKS5 reply."""
        try:
            addr_bytes = socket.inet_aton(addr)
            reply = bytes([SOCKS_VERSION, rep, 0x00, ATYP_IPV4]) + addr_bytes + struct.pack('!H', port)
            writer.write(reply)
            await writer.drain()
        except:
            pass

    async def _relay(
        self,
        client_reader: asyncio.StreamReader,
        client_writer: asyncio.StreamWriter,
        remote_reader: asyncio.StreamReader,
        remote_writer: asyncio.StreamWriter,
        conn_id: int
    ):
        """Relay data between client and remote."""
        async def pipe(reader, writer, direction):
            try:
                while True:
                    data = await reader.read(8192)
                    if not data:
                        break
                    writer.write(data)
                    await writer.drain()
            except (ConnectionResetError, BrokenPipeError, asyncio.CancelledError):
                pass
            except Exception as e:
                logger.debug(f"[{conn_id}] {direction} pipe error: {e}")
            finally:
                try:
                    writer.close()
                except:
                    pass

        # Run both directions concurrently
        await asyncio.gather(
            pipe(client_reader, remote_writer, "client->remote"),
            pipe(remote_reader, client_writer, "remote->client"),
            return_exceptions=True
        )


async def main():
    parser = argparse.ArgumentParser(description='SOCKS5 proxy for OpenVPN tunnels')
    parser.add_argument('--host', default='127.0.0.1', help='Listen host (default: 127.0.0.1)')
    parser.add_argument('--port', type=int, required=True, help='Listen port')
    parser.add_argument('--bind-interface', help='Bind outgoing connections to interface (e.g., tun0)')
    parser.add_argument('--bind-ip', help='Bind outgoing connections to IP address')
    parser.add_argument('--verbose', '-v', action='store_true', help='Enable verbose logging')
    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    if not args.bind_interface and not args.bind_ip:
        logger.warning("No --bind-interface or --bind-ip specified, using default routing")

    server = SOCKS5Server(
        listen_host=args.host,
        listen_port=args.port,
        bind_interface=args.bind_interface,
        bind_ip=args.bind_ip
    )

    # Handle signals
    loop = asyncio.get_event_loop()
    for sig in (signal.SIGTERM, signal.SIGINT):
        loop.add_signal_handler(sig, lambda: asyncio.create_task(server.stop()))

    try:
        await server.start()
    except asyncio.CancelledError:
        pass


if __name__ == '__main__':
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass

#!/usr/bin/env python3
"""
Enhanced SOCKS5 proxy for OpenVPN tunnels with UDP ASSOCIATE and tunnel-side DNS.

Features:
- TCP CONNECT command (RFC 1928)
- UDP ASSOCIATE command with relay (RFC 1928)
- DNS resolution through tunnel interface (prevents DNS leakage)
- Interface/IP binding for all connections

Usage:
    python3 socks5_proxy.py --port 37001 --bind-interface tun0
    python3 socks5_proxy.py --port 37001 --bind-ip 10.8.0.6
"""

import argparse
import asyncio
import logging
import os
import random
import signal
import socket
import struct
import sys
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

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
CMD_BIND = 0x02
CMD_UDP_ASSOCIATE = 0x03
ATYP_IPV4 = 0x01
ATYP_DOMAIN = 0x03
ATYP_IPV6 = 0x04
REP_SUCCESS = 0x00
REP_GENERAL_FAILURE = 0x01
REP_CONNECTION_NOT_ALLOWED = 0x02
REP_NETWORK_UNREACHABLE = 0x03
REP_HOST_UNREACHABLE = 0x04
REP_CONNECTION_REFUSED = 0x05
REP_COMMAND_NOT_SUPPORTED = 0x07

# UDP header constants
UDP_RSV = 0x0000
UDP_FRAG_NONE = 0x00

# DNS constants
DNS_PORT = 53
DNS_TIMEOUT = 5.0
DNS_SERVERS = ['8.8.8.8', '1.1.1.1', '8.8.4.4']


class TunnelDNSResolver:
    """DNS resolver that queries through the bound tunnel interface."""

    def __init__(
        self,
        bind_interface: Optional[str] = None,
        bind_ip: Optional[str] = None,
        dns_servers: Optional[List[str]] = None
    ):
        self.bind_interface = bind_interface
        self.bind_ip = bind_ip
        self.dns_servers = dns_servers or DNS_SERVERS
        self._cache: Dict[str, Tuple[List[str], float]] = {}
        self._cache_ttl = 300  # 5 minutes

    async def resolve(self, hostname: str) -> List[str]:
        """
        Resolve hostname to IP addresses through tunnel interface.

        Returns list of IP addresses, empty list if resolution fails.
        """
        # Check cache
        cached = self._cache.get(hostname)
        if cached and time.time() < cached[1]:
            return cached[0]

        loop = asyncio.get_event_loop()
        ips = []

        # Try each DNS server
        for dns_server in self.dns_servers:
            sock = None
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.setblocking(False)

                # Bind to tunnel interface/IP
                if self.bind_interface:
                    try:
                        sock.setsockopt(
                            socket.SOL_SOCKET, socket.SO_BINDTODEVICE,
                            self.bind_interface.encode() + b'\0'
                        )
                    except PermissionError:
                        logger.warning(f"SO_BINDTODEVICE failed for {self.bind_interface}")
                        if self.bind_ip:
                            sock.bind((self.bind_ip, 0))
                elif self.bind_ip:
                    sock.bind((self.bind_ip, 0))

                # Build and send query
                txid = random.randint(0, 65535)
                query = self._build_dns_query(hostname, txid, qtype=1)  # A record

                await asyncio.wait_for(
                    loop.sock_sendto(sock, query, (dns_server, DNS_PORT)),
                    timeout=DNS_TIMEOUT
                )

                # Receive response
                response, _ = await asyncio.wait_for(
                    loop.sock_recvfrom(sock, 512),
                    timeout=DNS_TIMEOUT
                )

                ips = self._parse_dns_response(response, txid)
                if ips:
                    # Cache result
                    self._cache[hostname] = (ips, time.time() + self._cache_ttl)
                    break

            except asyncio.TimeoutError:
                logger.debug(f"DNS timeout querying {dns_server} for {hostname}")
            except Exception as e:
                logger.debug(f"DNS query to {dns_server} failed: {e}")
            finally:
                if sock:
                    sock.close()

        return ips

    def _build_dns_query(self, hostname: str, txid: int, qtype: int = 1) -> bytes:
        """Build DNS query packet for A (1) or AAAA (28) record."""
        # Header
        flags = 0x0100  # Standard query, recursion desired
        header = struct.pack('!HHHHHH', txid, flags, 1, 0, 0, 0)

        # Question section
        question = b''
        for label in hostname.split('.'):
            question += bytes([len(label)]) + label.encode('ascii')
        question += b'\x00'  # Root label
        question += struct.pack('!HH', qtype, 1)  # QTYPE, QCLASS=IN

        return header + question

    def _parse_dns_response(self, data: bytes, expected_txid: int) -> List[str]:
        """Parse DNS response and extract IP addresses."""
        if len(data) < 12:
            return []

        txid = struct.unpack('!H', data[0:2])[0]
        if txid != expected_txid:
            logger.warning(f"DNS txid mismatch: expected {expected_txid}, got {txid}")
            return []

        flags = struct.unpack('!H', data[2:4])[0]
        rcode = flags & 0x0F
        if rcode != 0:
            return []

        qdcount = struct.unpack('!H', data[4:6])[0]
        ancount = struct.unpack('!H', data[6:8])[0]

        if ancount == 0:
            return []

        # Skip header (12 bytes)
        offset = 12

        # Skip question section
        for _ in range(qdcount):
            while offset < len(data) and data[offset] != 0:
                if data[offset] & 0xC0 == 0xC0:
                    offset += 2
                    break
                offset += data[offset] + 1
            else:
                offset += 1
            offset += 4  # QTYPE + QCLASS

        # Parse answers
        ips = []
        for _ in range(ancount):
            if offset >= len(data):
                break

            # Skip name (may be compressed)
            if data[offset] & 0xC0 == 0xC0:
                offset += 2
            else:
                while offset < len(data) and data[offset] != 0:
                    offset += data[offset] + 1
                offset += 1

            if offset + 10 > len(data):
                break

            rtype = struct.unpack('!H', data[offset:offset+2])[0]
            offset += 2
            rclass = struct.unpack('!H', data[offset:offset+2])[0]
            offset += 2
            ttl = struct.unpack('!I', data[offset:offset+4])[0]
            offset += 4
            rdlength = struct.unpack('!H', data[offset:offset+2])[0]
            offset += 2

            if rtype == 1 and rdlength == 4:  # A record
                ip = socket.inet_ntoa(data[offset:offset+4])
                ips.append(ip)
            elif rtype == 28 and rdlength == 16:  # AAAA record
                ip = socket.inet_ntop(socket.AF_INET6, data[offset:offset+16])
                ips.append(ip)

            offset += rdlength

        return ips


@dataclass
class UDPSession:
    """Track state for a UDP ASSOCIATE session."""
    client_addr: Tuple[str, int]
    relay_port: int
    transport: asyncio.DatagramTransport
    protocol: 'UDPRelayProtocol'
    tcp_writer: asyncio.StreamWriter
    created_at: float = field(default_factory=time.time)
    last_activity: float = field(default_factory=time.time)

    def is_expired(self, timeout: float = 300.0) -> bool:
        """Check if session has expired (default 5 minutes)."""
        return time.time() - self.last_activity > timeout


class UDPRelayProtocol(asyncio.DatagramProtocol):
    """UDP relay protocol for SOCKS5 UDP ASSOCIATE."""

    def __init__(
        self,
        session: UDPSession,
        bind_interface: Optional[str],
        bind_ip: Optional[str],
        dns_resolver: TunnelDNSResolver
    ):
        self.session = session
        self.bind_interface = bind_interface
        self.bind_ip = bind_ip
        self.dns_resolver = dns_resolver
        self.transport: Optional[asyncio.DatagramTransport] = None
        # Map remote address to outgoing socket
        self._remote_sockets: Dict[Tuple[str, int], socket.socket] = {}
        self._client_learned = False

    def connection_made(self, transport: asyncio.DatagramTransport):
        self.transport = transport

    def datagram_received(self, data: bytes, addr: Tuple[str, int]):
        """Handle received UDP datagram."""
        self.session.last_activity = time.time()

        # Learn client address from first packet
        if not self._client_learned:
            self.session.client_addr = addr
            self._client_learned = True
            logger.debug(f"UDP session learned client address: {addr}")

        if addr == self.session.client_addr:
            # From client - forward to remote
            asyncio.create_task(self._forward_to_remote(data))
        else:
            # From remote - forward to client
            asyncio.create_task(self._forward_to_client(data, addr))

    async def _forward_to_remote(self, data: bytes):
        """Parse SOCKS5 UDP header and forward to destination."""
        try:
            frag, dst_addr, dst_port, payload = self._parse_udp_header(data)

            if frag != UDP_FRAG_NONE:
                logger.warning(f"UDP fragmentation not supported (frag={frag})")
                return

            # Resolve hostname through tunnel if needed
            if not self._is_ip(dst_addr):
                ips = await self.dns_resolver.resolve(dst_addr)
                if not ips:
                    logger.warning(f"Failed to resolve {dst_addr} through tunnel")
                    return
                dst_addr = ips[0]

            # Get or create socket for this destination
            sock = self._get_remote_socket(dst_addr, dst_port)
            if sock:
                loop = asyncio.get_event_loop()
                await loop.sock_sendto(sock, payload, (dst_addr, dst_port))
                logger.debug(f"UDP forwarded to {dst_addr}:{dst_port} ({len(payload)} bytes)")

        except Exception as e:
            logger.error(f"UDP forward to remote error: {e}")

    async def _forward_to_client(self, data: bytes, remote_addr: Tuple[str, int]):
        """Wrap response with SOCKS5 UDP header and send to client."""
        try:
            header = self._build_udp_header(remote_addr[0], remote_addr[1])
            response = header + data

            if self.transport and self.session.client_addr:
                self.transport.sendto(response, self.session.client_addr)
                logger.debug(f"UDP forwarded to client from {remote_addr} ({len(data)} bytes)")

        except Exception as e:
            logger.error(f"UDP forward to client error: {e}")

    def _parse_udp_header(self, data: bytes) -> Tuple[int, str, int, bytes]:
        """Parse SOCKS5 UDP datagram header."""
        if len(data) < 4:
            raise ValueError("UDP header too short")

        # RSV (2 bytes) + FRAG (1 byte) + ATYP (1 byte)
        rsv = struct.unpack('!H', data[0:2])[0]
        frag = data[2]
        atyp = data[3]

        if atyp == ATYP_IPV4:
            if len(data) < 10:
                raise ValueError("IPv4 address data too short")
            addr = socket.inet_ntoa(data[4:8])
            port = struct.unpack('!H', data[8:10])[0]
            payload = data[10:]
        elif atyp == ATYP_DOMAIN:
            if len(data) < 5:
                raise ValueError("Domain length missing")
            domain_len = data[4]
            if len(data) < 7 + domain_len:
                raise ValueError("Domain data too short")
            addr = data[5:5+domain_len].decode('utf-8')
            port_offset = 5 + domain_len
            port = struct.unpack('!H', data[port_offset:port_offset+2])[0]
            payload = data[port_offset+2:]
        elif atyp == ATYP_IPV6:
            if len(data) < 22:
                raise ValueError("IPv6 address data too short")
            addr = socket.inet_ntop(socket.AF_INET6, data[4:20])
            port = struct.unpack('!H', data[20:22])[0]
            payload = data[22:]
        else:
            raise ValueError(f"Unknown ATYP: {atyp}")

        return frag, addr, port, payload

    def _build_udp_header(self, addr: str, port: int) -> bytes:
        """Build SOCKS5 UDP datagram header."""
        header = struct.pack('!H', 0)  # RSV
        header += bytes([UDP_FRAG_NONE])  # FRAG

        try:
            addr_bytes = socket.inet_aton(addr)
            header += bytes([ATYP_IPV4])
            header += addr_bytes
        except socket.error:
            try:
                addr_bytes = socket.inet_pton(socket.AF_INET6, addr)
                header += bytes([ATYP_IPV6])
                header += addr_bytes
            except socket.error:
                # Domain name (unlikely for responses)
                encoded = addr.encode('utf-8')
                header += bytes([ATYP_DOMAIN, len(encoded)])
                header += encoded

        header += struct.pack('!H', port)
        return header

    def _get_remote_socket(self, addr: str, port: int) -> Optional[socket.socket]:
        """Get or create socket for remote destination."""
        key = (addr, port)
        if key in self._remote_sockets:
            return self._remote_sockets[key]

        try:
            # Determine address family
            if ':' in addr:
                family = socket.AF_INET6
            else:
                family = socket.AF_INET

            sock = socket.socket(family, socket.SOCK_DGRAM)
            sock.setblocking(False)

            # Bind to tunnel interface
            if self.bind_interface:
                try:
                    sock.setsockopt(
                        socket.SOL_SOCKET, socket.SO_BINDTODEVICE,
                        self.bind_interface.encode() + b'\0'
                    )
                except PermissionError:
                    if self.bind_ip:
                        sock.bind((self.bind_ip, 0))
            elif self.bind_ip:
                sock.bind((self.bind_ip, 0))

            self._remote_sockets[key] = sock

            # Start receiving from this socket
            asyncio.create_task(self._receive_from_remote(sock, key))

            return sock

        except Exception as e:
            logger.error(f"Failed to create UDP socket for {addr}:{port}: {e}")
            return None

    async def _receive_from_remote(self, sock: socket.socket, remote_key: Tuple[str, int]):
        """Receive UDP responses from remote and forward to client."""
        loop = asyncio.get_event_loop()
        try:
            while self.transport and not self.transport.is_closing():
                try:
                    data, addr = await asyncio.wait_for(
                        loop.sock_recvfrom(sock, 65535),
                        timeout=1.0
                    )
                    await self._forward_to_client(data, addr)
                except asyncio.TimeoutError:
                    continue
                except Exception as e:
                    if "closed" not in str(e).lower():
                        logger.debug(f"UDP receive error: {e}")
                    break
        finally:
            sock.close()
            self._remote_sockets.pop(remote_key, None)

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

    def error_received(self, exc):
        logger.debug(f"UDP error received: {exc}")

    def connection_lost(self, exc):
        # Clean up remote sockets
        for sock in self._remote_sockets.values():
            try:
                sock.close()
            except:
                pass
        self._remote_sockets.clear()


class SOCKS5Server:
    """Enhanced SOCKS5 proxy server with UDP ASSOCIATE and tunnel DNS."""

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
        self.dns_resolver = TunnelDNSResolver(bind_interface, bind_ip)
        self.udp_sessions: Dict[int, UDPSession] = {}
        self.udp_timeout = 300.0  # 5 minutes

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
        logger.info("Supported: TCP CONNECT, UDP ASSOCIATE, Tunnel DNS")

        # Start UDP session cleanup task
        asyncio.create_task(self._udp_session_cleanup())

        async with self.server:
            await self.server.serve_forever()

    async def stop(self):
        """Stop the SOCKS5 server."""
        self.running = False

        # Close all UDP sessions
        for session in list(self.udp_sessions.values()):
            try:
                session.transport.close()
            except:
                pass
        self.udp_sessions.clear()

        if self.server:
            self.server.close()
            await self.server.wait_closed()
        logger.info("SOCKS5 proxy stopped")

    async def _udp_session_cleanup(self):
        """Periodically clean up expired UDP sessions."""
        while self.running:
            await asyncio.sleep(60)
            expired = [
                port for port, session in self.udp_sessions.items()
                if session.is_expired(self.udp_timeout)
            ]
            for port in expired:
                session = self.udp_sessions.pop(port, None)
                if session:
                    try:
                        session.transport.close()
                    except:
                        pass
                    logger.debug(f"Cleaned up expired UDP session on port {port}")

    async def _handle_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        """Handle a single client connection."""
        client_addr = writer.get_extra_info('peername')
        self.connections += 1
        conn_id = self.connections

        try:
            # Step 1: Handshake
            greeting = await asyncio.wait_for(reader.read(2), timeout=10)
            if len(greeting) < 2 or greeting[0] != SOCKS_VERSION:
                logger.warning(f"[{conn_id}] Invalid SOCKS version from {client_addr}")
                writer.close()
                return

            num_methods = greeting[1]
            methods = await asyncio.wait_for(reader.read(num_methods), timeout=10)

            if AUTH_NONE not in methods:
                writer.write(bytes([SOCKS_VERSION, 0xFF]))
                await writer.drain()
                writer.close()
                return

            writer.write(bytes([SOCKS_VERSION, AUTH_NONE]))
            await writer.drain()

            # Step 2: Receive command
            request = await asyncio.wait_for(reader.read(4), timeout=10)
            if len(request) < 4:
                writer.close()
                return

            version, cmd, _, atyp = request

            if version != SOCKS_VERSION:
                writer.close()
                return

            # Parse destination address
            dst_addr, dst_port = await self._parse_address(reader, atyp)
            if dst_addr is None:
                await self._send_reply(writer, REP_GENERAL_FAILURE, '0.0.0.0', 0)
                writer.close()
                return

            # Dispatch based on command
            if cmd == CMD_CONNECT:
                await self._handle_connect(reader, writer, dst_addr, dst_port, client_addr, conn_id)
            elif cmd == CMD_UDP_ASSOCIATE:
                await self._handle_udp_associate(reader, writer, dst_addr, dst_port, client_addr, conn_id)
            else:
                await self._send_reply(writer, REP_COMMAND_NOT_SUPPORTED, '0.0.0.0', 0)
                writer.close()

        except asyncio.TimeoutError:
            logger.debug(f"[{conn_id}] Timeout from {client_addr}")
        except ConnectionResetError:
            logger.debug(f"[{conn_id}] Connection reset from {client_addr}")
        except Exception as e:
            logger.error(f"[{conn_id}] Error handling {client_addr}: {e}")
        finally:
            try:
                if not writer.is_closing():
                    writer.close()
                    await writer.wait_closed()
            except:
                pass

    async def _handle_connect(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        dst_addr: str,
        dst_port: int,
        client_addr,
        conn_id: int
    ):
        """Handle TCP CONNECT command."""
        logger.debug(f"[{conn_id}] CONNECT {client_addr} -> {dst_addr}:{dst_port}")

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
            return

        # Send success reply
        bind_addr = remote_writer.get_extra_info('sockname')
        await self._send_reply(writer, REP_SUCCESS, bind_addr[0], bind_addr[1])

        # Relay data
        await self._relay(reader, writer, remote_reader, remote_writer, conn_id)

    async def _handle_udp_associate(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        dst_addr: str,
        dst_port: int,
        client_addr,
        conn_id: int
    ):
        """Handle UDP ASSOCIATE command."""
        logger.debug(f"[{conn_id}] UDP ASSOCIATE from {client_addr}")

        try:
            # Create UDP relay socket
            loop = asyncio.get_event_loop()

            # Create session placeholder
            session = UDPSession(
                client_addr=client_addr,
                relay_port=0,
                transport=None,  # type: ignore
                protocol=None,  # type: ignore
                tcp_writer=writer
            )

            # Create protocol
            protocol = UDPRelayProtocol(
                session=session,
                bind_interface=self.bind_interface,
                bind_ip=self.bind_ip,
                dns_resolver=self.dns_resolver
            )

            # Create UDP endpoint - bind to ephemeral port
            transport, _ = await loop.create_datagram_endpoint(
                lambda: protocol,
                local_addr=('0.0.0.0', 0)
            )

            # Get assigned port
            relay_addr = transport.get_extra_info('sockname')
            relay_port = relay_addr[1]

            # Update session
            session.relay_port = relay_port
            session.transport = transport
            session.protocol = protocol

            self.udp_sessions[relay_port] = session

            # Send reply with relay address
            # Use listen host as relay address
            await self._send_reply(writer, REP_SUCCESS, self.listen_host, relay_port)

            logger.info(f"[{conn_id}] UDP relay started on port {relay_port}")

            # Keep TCP connection open - session ends when client closes TCP
            while self.running:
                try:
                    # Check if client disconnected
                    data = await asyncio.wait_for(reader.read(1), timeout=30)
                    if not data:
                        break
                    session.last_activity = time.time()
                except asyncio.TimeoutError:
                    # Check session activity
                    if session.is_expired(self.udp_timeout):
                        logger.debug(f"[{conn_id}] UDP session expired")
                        break
                    # Continue waiting if session is still active
                    continue
                except (ConnectionResetError, BrokenPipeError):
                    break

        except Exception as e:
            logger.error(f"[{conn_id}] UDP ASSOCIATE error: {e}")
            await self._send_reply(writer, REP_GENERAL_FAILURE, '0.0.0.0', 0)
        finally:
            # Clean up UDP session
            if 'relay_port' in dir() and relay_port in self.udp_sessions:
                session = self.udp_sessions.pop(relay_port, None)
                if session and session.transport:
                    session.transport.close()
                logger.debug(f"[{conn_id}] UDP session closed on port {relay_port}")

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
        """Connect to remote host using tunnel DNS and interface binding."""
        loop = asyncio.get_event_loop()

        # Resolve hostname through tunnel if needed
        if not self._is_ip(host):
            ips = await self.dns_resolver.resolve(host)
            if not ips:
                raise OSError(f"Cannot resolve {host} through tunnel DNS")
            host = ips[0]
            logger.debug(f"Resolved {host} via tunnel DNS")

        # Determine address family
        if ':' in host:
            family = socket.AF_INET6
        else:
            family = socket.AF_INET

        # Create socket
        sock = socket.socket(family, socket.SOCK_STREAM)
        sock.setblocking(False)

        # Bind to interface or IP
        if self.bind_interface:
            try:
                sock.setsockopt(
                    socket.SOL_SOCKET, socket.SO_BINDTODEVICE,
                    self.bind_interface.encode() + b'\0'
                )
            except PermissionError as e:
                logger.warning(f"Failed to bind to interface {self.bind_interface}: {e}")
                if self.bind_ip:
                    sock.bind((self.bind_ip, 0))
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
            if ':' in addr:
                addr_bytes = socket.inet_pton(socket.AF_INET6, addr)
                reply = bytes([SOCKS_VERSION, rep, 0x00, ATYP_IPV6]) + addr_bytes
            else:
                addr_bytes = socket.inet_aton(addr)
                reply = bytes([SOCKS_VERSION, rep, 0x00, ATYP_IPV4]) + addr_bytes
            reply += struct.pack('!H', port)
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

        await asyncio.gather(
            pipe(client_reader, remote_writer, "client->remote"),
            pipe(remote_reader, client_writer, "remote->client"),
            return_exceptions=True
        )


async def main():
    parser = argparse.ArgumentParser(description='Enhanced SOCKS5 proxy with UDP and tunnel DNS')
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

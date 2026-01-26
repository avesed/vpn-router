#!/usr/bin/env python3
"""
Throughput test script for VLESS/SOCKS5 proxy
Tests actual download speed through the proxy chain
"""

import socket
import ssl
import time
import argparse
import sys

def create_socks5_connection(proxy_host, proxy_port, target_host, target_port, timeout=30):
    """Create a TCP connection through SOCKS5 proxy"""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    sock.connect((proxy_host, proxy_port))

    # SOCKS5 handshake - no auth
    sock.sendall(b'\x05\x01\x00')  # Version 5, 1 method, no auth
    response = sock.recv(2)
    if response != b'\x05\x00':
        raise Exception(f"SOCKS5 handshake failed: {response.hex()}")

    # SOCKS5 connect request (domain name)
    domain_bytes = target_host.encode()
    request = bytes([
        0x05,  # Version
        0x01,  # CMD: CONNECT
        0x00,  # Reserved
        0x03,  # ATYP: Domain name
        len(domain_bytes),  # Domain length
    ]) + domain_bytes + target_port.to_bytes(2, 'big')

    sock.sendall(request)
    response = sock.recv(10)
    if response[1] != 0x00:
        raise Exception(f"SOCKS5 connect failed: status={response[1]}")

    return sock


def test_download_speed(sock, host, size_bytes):
    """Test download speed using HTTP GET"""
    # Wrap in TLS
    context = ssl.create_default_context()
    tls_sock = context.wrap_socket(sock, server_hostname=host)

    # Send HTTP request
    request = (
        f"GET /__down?bytes={size_bytes} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"User-Agent: throughput-test/1.0\r\n"
        f"Connection: close\r\n"
        f"\r\n"
    )
    tls_sock.sendall(request.encode())

    # Read response
    total_bytes = 0
    start_time = time.perf_counter()

    # Skip HTTP headers
    buffer = b""
    while b"\r\n\r\n" not in buffer:
        chunk = tls_sock.recv(4096)
        if not chunk:
            break
        buffer += chunk

    # Find body start
    header_end = buffer.find(b"\r\n\r\n")
    if header_end != -1:
        body_start = buffer[header_end + 4:]
        total_bytes += len(body_start)

    # Read body
    while True:
        try:
            chunk = tls_sock.recv(65536)
            if not chunk:
                break
            total_bytes += len(chunk)
        except socket.timeout:
            break

    end_time = time.perf_counter()
    duration = end_time - start_time

    tls_sock.close()

    return total_bytes, duration


def test_direct_speed(host, port, size_bytes, timeout=30):
    """Test direct download speed (no proxy)"""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    sock.connect((socket.gethostbyname(host), port))

    return test_download_speed(sock, host, size_bytes)


def test_proxy_speed(proxy_host, proxy_port, target_host, target_port, size_bytes, timeout=60):
    """Test download speed through SOCKS5 proxy"""
    sock = create_socks5_connection(proxy_host, proxy_port, target_host, target_port, timeout)
    return test_download_speed(sock, target_host, size_bytes)


def format_speed(bytes_count, duration):
    """Format speed in Mbps"""
    if duration <= 0:
        return "N/A"
    mbps = (bytes_count * 8) / (duration * 1_000_000)
    return f"{mbps:.1f} Mbps"


def main():
    parser = argparse.ArgumentParser(description="Test throughput through SOCKS5 proxy")
    parser.add_argument("--proxy", default="127.0.0.1:38501", help="SOCKS5 proxy address (host:port)")
    parser.add_argument("--size", type=int, default=10_000_000, help="Download size in bytes")
    parser.add_argument("--runs", type=int, default=3, help="Number of test runs")
    parser.add_argument("--direct", action="store_true", help="Also test direct connection")
    parser.add_argument("--timeout", type=int, default=60, help="Timeout in seconds")
    args = parser.parse_args()

    proxy_host, proxy_port = args.proxy.split(":")
    proxy_port = int(proxy_port)

    target_host = "speed.cloudflare.com"
    target_port = 443

    print(f"=== Throughput Test ===")
    print(f"Proxy: {proxy_host}:{proxy_port}")
    print(f"Target: {target_host}:{target_port}")
    print(f"Size: {args.size / 1_000_000:.1f} MB")
    print(f"Runs: {args.runs}")
    print()

    # Test through proxy
    print("Testing through SOCKS5 proxy...")
    proxy_speeds = []
    for i in range(args.runs):
        try:
            bytes_count, duration = test_proxy_speed(
                proxy_host, proxy_port, target_host, target_port,
                args.size, args.timeout
            )
            speed = format_speed(bytes_count, duration)
            mbps = (bytes_count * 8) / (duration * 1_000_000)
            proxy_speeds.append(mbps)
            print(f"  Run {i+1}: {speed} ({bytes_count} bytes in {duration:.2f}s)")
        except Exception as e:
            print(f"  Run {i+1}: Error - {e}")

    if proxy_speeds:
        avg = sum(proxy_speeds) / len(proxy_speeds)
        print(f"  Average: {avg:.1f} Mbps")
    print()

    # Test direct connection
    if args.direct:
        print("Testing direct connection...")
        direct_speeds = []
        for i in range(args.runs):
            try:
                bytes_count, duration = test_direct_speed(
                    target_host, target_port, args.size, args.timeout
                )
                speed = format_speed(bytes_count, duration)
                mbps = (bytes_count * 8) / (duration * 1_000_000)
                direct_speeds.append(mbps)
                print(f"  Run {i+1}: {speed} ({bytes_count} bytes in {duration:.2f}s)")
            except Exception as e:
                print(f"  Run {i+1}: Error - {e}")

        if direct_speeds:
            avg = sum(direct_speeds) / len(direct_speeds)
            print(f"  Average: {avg:.1f} Mbps")
        print()

    # Summary
    if proxy_speeds and args.direct and direct_speeds:
        proxy_avg = sum(proxy_speeds) / len(proxy_speeds)
        direct_avg = sum(direct_speeds) / len(direct_speeds)
        overhead = ((direct_avg - proxy_avg) / direct_avg) * 100
        print(f"=== Summary ===")
        print(f"Proxy:  {proxy_avg:.1f} Mbps")
        print(f"Direct: {direct_avg:.1f} Mbps")
        print(f"Overhead: {overhead:.1f}%")


if __name__ == "__main__":
    main()

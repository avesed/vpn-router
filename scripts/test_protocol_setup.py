#!/usr/bin/env python3
"""
Protocol Test Setup Script

Configures vpn-client and vpn-server for VLESS/SS protocol testing.

Usage:
    # On vpn-server (first): Configure inbounds + set default to WARP
    python3 test_protocol_setup.py server

    # On vpn-client: Configure outbounds pointing to vpn-server
    python3 test_protocol_setup.py client
"""

import asyncio
import sys
import os

# Add script path
sys.path.insert(0, '/usr/local/bin')

from rust_router_client import RustRouterClient

# Test configuration
TEST_UUID = "b831381d-6324-4d53-ad4f-8cda48b30811"
SERVER_IP = "172.31.0.20"  # vpn-server IP in test network (docker-compose.test.yml)

# Protocol ports on server
PORTS = {
    "vless-tcp": 20080,
    "vless-tls": 20443,
    "vless-ws": 20081,
    "vless-ws-tls": 20444,
    "ss-aead": 21080,
    "ss-2022": 21081,
}


async def setup_server():
    """Configure vpn-server with VLESS/SS inbounds."""
    client = RustRouterClient()

    print("=" * 60)
    print("Configuring vpn-server (VLESS/SS inbounds)")
    print("=" * 60)

    # 1. Set default outbound to direct (or warplb if WARP is configured)
    print("\n[1] Setting default outbound...")
    resp = await client.set_default_outbound("direct")
    print(f"    Default outbound: {'OK' if resp.success else resp.error}")

    # 2. Configure VLESS TCP inbound
    print("\n[2] Configuring VLESS TCP inbound (port 20080)...")
    resp = await client.configure_vless_inbound(
        listen="0.0.0.0:20080",
        users=[{"uuid": TEST_UUID, "email": "test@test.com"}],
        udp_enabled=True,
    )
    print(f"    VLESS TCP: {'OK' if resp.success else resp.error}")

    # 3. Configure Shadowsocks inbound
    print("\n[3] Configuring Shadowsocks AEAD inbound (port 21080)...")
    resp = await client.configure_shadowsocks_inbound(
        listen="0.0.0.0:21080",
        method="aes-256-gcm",
        password="test-password-12345678",
        udp_enabled=True,
    )
    print(f"    SS AEAD: {'OK' if resp.success else resp.error}")

    # 4. Verify status
    print("\n[4] Checking inbound status...")
    resp = await client.get_vless_inbound_status()
    if resp.data:
        print(f"    VLESS: running={resp.data.get('running')}, users={resp.data.get('user_count')}")

    resp = await client.get_shadowsocks_inbound_status()
    if resp.data:
        print(f"    SS: active={resp.data.get('active')}")

    print("\n" + "=" * 60)
    print("Server setup complete!")
    print("=" * 60)


async def setup_client():
    """Configure vpn-client with VLESS/SS outbounds."""
    client = RustRouterClient()

    print("=" * 60)
    print("Configuring vpn-client (VLESS/SS outbounds)")
    print("=" * 60)

    # 1. Add VLESS TCP outbound
    print("\n[1] Adding VLESS TCP outbound...")
    resp = await client.add_vless_outbound(
        tag="vless-tcp",
        server_address=SERVER_IP,
        server_port=PORTS["vless-tcp"],
        uuid=TEST_UUID,
        transport="tcp",
        tls_enabled=False,
    )
    print(f"    vless-tcp: {'OK' if resp.success else resp.error}")

    # 2. Add VLESS TLS outbound
    print("\n[2] Adding VLESS TLS outbound...")
    resp = await client.add_vless_outbound(
        tag="vless-tls",
        server_address=SERVER_IP,
        server_port=PORTS["vless-tls"],
        uuid=TEST_UUID,
        transport="tls",
        tls_enabled=True,
        tls_sni=SERVER_IP,
        tls_skip_verify=True,  # Self-signed cert for testing
    )
    print(f"    vless-tls: {'OK' if resp.success else resp.error}")

    # 3. Add VLESS WebSocket outbound
    print("\n[3] Adding VLESS WebSocket outbound...")
    resp = await client.add_vless_outbound(
        tag="vless-ws",
        server_address=SERVER_IP,
        server_port=PORTS["vless-ws"],
        uuid=TEST_UUID,
        transport="websocket",
        tls_enabled=False,
        ws_path="/ws",
    )
    print(f"    vless-ws: {'OK' if resp.success else resp.error}")

    # 4. Add VLESS WebSocket+TLS outbound
    print("\n[4] Adding VLESS WebSocket+TLS outbound...")
    resp = await client.add_vless_outbound(
        tag="vless-ws-tls",
        server_address=SERVER_IP,
        server_port=PORTS["vless-ws-tls"],
        uuid=TEST_UUID,
        transport="websocket_tls",
        tls_enabled=True,
        tls_sni=SERVER_IP,
        tls_skip_verify=True,
        ws_path="/ws",
    )
    print(f"    vless-ws-tls: {'OK' if resp.success else resp.error}")

    # 5. Add Shadowsocks AEAD outbound
    print("\n[5] Adding Shadowsocks AEAD outbound...")
    resp = await client.add_shadowsocks_outbound(
        tag="ss-aead",
        server=SERVER_IP,
        server_port=PORTS["ss-aead"],
        method="aes-256-gcm",
        password="test-password-12345678",
    )
    print(f"    ss-aead: {'OK' if resp.success else resp.error}")

    # 6. Verify outbounds
    print("\n[6] Checking outbound status...")
    resp = await client.list_vless_outbounds()
    if resp.data and resp.data.get("outbounds"):
        for o in resp.data["outbounds"]:
            print(f"    {o['tag']}: {o['server_address']}:{o['server_port']} ({o['transport']})")

    print("\n" + "=" * 60)
    print("Client setup complete!")
    print("=" * 60)


async def test_protocols():
    """Test each protocol by setting it as default and making a request."""
    client = RustRouterClient()

    print("=" * 60)
    print("Testing protocols")
    print("=" * 60)

    protocols = ["vless-tcp", "ss-aead"]

    for proto in protocols:
        print(f"\n[Testing {proto}]")

        # Set as default
        resp = await client.set_default_outbound(proto)
        if not resp.success:
            print(f"  Failed to set default: {resp.error}")
            continue

        # Verify routing
        resp = await client.test_match(domain="ifconfig.me", dest_port=80)
        if resp.data:
            print(f"  Routing to: {resp.data.get('outbound')}")

        print(f"  Ready for testing - use: curl http://ifconfig.me")


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(1)

    mode = sys.argv[1].lower()

    if mode == "server":
        asyncio.run(setup_server())
    elif mode == "client":
        asyncio.run(setup_client())
    elif mode == "test":
        asyncio.run(test_protocols())
    else:
        print(f"Unknown mode: {mode}")
        print("Use: server, client, or test")
        sys.exit(1)


if __name__ == "__main__":
    main()

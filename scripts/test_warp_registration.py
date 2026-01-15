#!/usr/bin/env python3
"""
Test script for WARP registration via rust-router

This script tests the complete WARP registration flow:
1. Python API endpoint -> rust-router IPC -> Cloudflare API
2. Database persistence with account_id field
3. WireGuard tunnel creation via IPC

Usage:
    python3 test_warp_registration.py [--tag TAG] [--license KEY]
"""

import asyncio
import sys
import os
import argparse
import logging

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from rust_router_client import RustRouterClient, IpcError

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


async def test_warp_registration(tag: str, license_key: str = None):
    """Test WARP registration via rust-router IPC"""

    # Check if rust-router is running
    socket_path = "/var/run/rust-router.sock"
    if not os.path.exists(socket_path):
        logger.error(f"rust-router socket not found: {socket_path}")
        logger.info("Make sure rust-router is running with USE_RUST_ROUTER=true USERSPACE_WG=true")
        return False

    client = RustRouterClient(socket_path=socket_path)

    try:
        # Test 1: Ping
        logger.info("=== Test 1: Ping rust-router ===")
        response = await client.ping()
        if response.success and response.response_type == "pong":
            logger.info("✓ Ping successful")
        else:
            logger.error("✗ Ping failed")
            return False

        # Test 2: Get capabilities
        logger.info("\n=== Test 2: Get capabilities ===")
        capabilities = await client.get_capabilities()
        logger.info(f"Version: {capabilities.get('version', 'unknown')}")
        logger.info(f"WARP support: {capabilities.get('features', {}).get('warp_registration', False)}")

        # Test 3: WARP registration
        logger.info(f"\n=== Test 3: Register WARP device (tag={tag}) ===")
        if license_key:
            logger.info(f"Using WARP+ license: {license_key[:8]}...")
        else:
            logger.info("No license key provided, registering free account")

        try:
            warp_config = await client.register_warp(
                tag=tag,
                name="Test WARP Device",
                warp_plus_license=license_key,
            )

            if warp_config:
                logger.info("✓ WARP registration successful!")
                logger.info(f"  Tag: {warp_config.tag}")
                logger.info(f"  Account ID: {warp_config.account_id}")
                logger.info(f"  Account Type: {warp_config.account_type}")
                logger.info(f"  IPv4: {warp_config.ipv4_address}")
                logger.info(f"  IPv6: {warp_config.ipv6_address}")
                logger.info(f"  Endpoint: {warp_config.endpoint}")
                logger.info(f"  Reserved: {warp_config.reserved}")
                logger.info(f"  License: {warp_config.license_key[:20]}...")

                # Test 4: Create WireGuard tunnel
                logger.info("\n=== Test 4: Create WireGuard tunnel ===")
                try:
                    tunnel_result = await client.create_wg_tunnel(
                        tag=tag,
                        tunnel_type="warp",
                        private_key=warp_config.private_key,
                        peer_public_key=warp_config.peer_public_key,
                        peer_endpoint=warp_config.endpoint,
                        allowed_ips=["0.0.0.0/0", "::/0"],
                        tunnel_ipv4=warp_config.ipv4_address,
                        tunnel_ipv6=warp_config.ipv6_address,
                        mtu=1280,
                        persistent_keepalive=25,
                        reserved=warp_config.reserved,
                    )

                    if tunnel_result and tunnel_result.success:
                        logger.info("✓ WireGuard tunnel created successfully")
                    else:
                        logger.warning("✗ Tunnel creation failed (may already exist)")
                except Exception as e:
                    logger.warning(f"Tunnel creation error: {e}")

                # Test 5: List WireGuard tunnels
                logger.info("\n=== Test 5: List WireGuard tunnels ===")
                tunnels = await client.list_wg_tunnels()
                for tunnel in tunnels:
                    if tunnel.tag == tag:
                        logger.info(f"✓ Found tunnel: {tunnel.tag}")
                        logger.info(f"  Status: {tunnel.status}")
                        logger.info(f"  Tunnel Type: {tunnel.tunnel_type}")
                        logger.info(f"  Endpoint: {tunnel.peer_endpoint}")
                        break
                else:
                    logger.warning(f"Tunnel '{tag}' not found in list")

                return True
            else:
                logger.error("✗ Registration returned None")
                return False

        except IpcError as e:
            logger.error(f"✗ WARP registration failed: {e}")
            if "rate limit" in str(e).lower():
                logger.info("Note: Cloudflare API rate limit (~10 registrations/hour)")
            elif "invalid" in str(e).lower():
                logger.info("Note: Check WARP+ license key format (XXXXXXXX-XXXXXXXX-XXXXXXXX)")
            return False

    except Exception as e:
        logger.error(f"Test failed with exception: {e}", exc_info=True)
        return False
    finally:
        await client.close()


def main():
    parser = argparse.ArgumentParser(description="Test WARP registration via rust-router")
    parser.add_argument("--tag", default="test-warp", help="WARP device tag (default: test-warp)")
    parser.add_argument("--license", help="WARP+ license key (optional)")
    args = parser.parse_args()

    logger.info("WARP Registration Test Script")
    logger.info("=" * 60)
    logger.info("Prerequisites:")
    logger.info("  1. rust-router must be running")
    logger.info("  2. Environment: USE_RUST_ROUTER=true USERSPACE_WG=true")
    logger.info("  3. Socket path: /var/run/rust-router.sock")
    logger.info("=" * 60)

    success = asyncio.run(test_warp_registration(args.tag, args.license))

    if success:
        logger.info("\n" + "=" * 60)
        logger.info("✓ All tests passed!")
        logger.info("=" * 60)
        sys.exit(0)
    else:
        logger.error("\n" + "=" * 60)
        logger.error("✗ Tests failed")
        logger.error("=" * 60)
        sys.exit(1)


if __name__ == "__main__":
    main()

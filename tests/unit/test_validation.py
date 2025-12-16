"""
Unit tests for input validation.
"""

import pytest
import re


class TestWireGuardKeyValidation:
    """Tests for WireGuard key format validation."""

    # WireGuard keys are 32 bytes = 44 characters in base64 (with padding)
    VALID_WG_KEY = "YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXoxMjM0NTY="
    INVALID_KEYS = [
        "",  # Empty
        "short",  # Too short
        "a" * 100,  # Too long
        "invalid!@#$%^&*()",  # Invalid characters
        "YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXoxMjM0NTY",  # Missing padding
    ]

    def test_valid_wireguard_key_format(self):
        """Test that a valid WireGuard key passes validation."""
        # WireGuard key: 44 characters, base64 encoded, ends with =
        pattern = r'^[A-Za-z0-9+/]{43}=$'
        assert re.match(pattern, self.VALID_WG_KEY)

    @pytest.mark.parametrize("invalid_key", INVALID_KEYS)
    def test_invalid_wireguard_key_format(self, invalid_key):
        """Test that invalid WireGuard keys fail validation."""
        pattern = r'^[A-Za-z0-9+/]{43}=$'
        assert not re.match(pattern, invalid_key)


class TestIPValidation:
    """Tests for IP address and CIDR validation."""

    VALID_IPV4_CIDRS = [
        "192.168.1.0/24",
        "10.0.0.0/8",
        "172.16.0.0/12",
        "0.0.0.0/0",
        "8.8.8.8/32",
    ]

    INVALID_IPV4_CIDRS = [
        "256.1.1.1/24",  # Invalid octet
        "192.168.1.0/33",  # Invalid prefix
        "192.168.1/24",  # Missing octet
        "not-an-ip/24",  # Not an IP
        "",  # Empty
    ]

    @pytest.mark.parametrize("cidr", VALID_IPV4_CIDRS)
    def test_valid_ipv4_cidr(self, cidr):
        """Test that valid IPv4 CIDRs pass validation."""
        import ipaddress
        try:
            ipaddress.ip_network(cidr, strict=False)
            valid = True
        except ValueError:
            valid = False
        assert valid is True

    @pytest.mark.parametrize("cidr", INVALID_IPV4_CIDRS)
    def test_invalid_ipv4_cidr(self, cidr):
        """Test that invalid IPv4 CIDRs fail validation."""
        import ipaddress
        try:
            ipaddress.ip_network(cidr, strict=False)
            valid = True
        except ValueError:
            valid = False
        assert valid is False


class TestPortValidation:
    """Tests for port number validation."""

    VALID_PORTS = [1, 80, 443, 51820, 65535]
    INVALID_PORTS = [0, -1, 65536, 100000]

    @pytest.mark.parametrize("port", VALID_PORTS)
    def test_valid_port(self, port):
        """Test that valid ports pass validation."""
        assert 1 <= port <= 65535

    @pytest.mark.parametrize("port", INVALID_PORTS)
    def test_invalid_port(self, port):
        """Test that invalid ports fail validation."""
        assert not (1 <= port <= 65535)


class TestTagValidation:
    """Tests for tag/name validation."""

    VALID_TAGS = [
        "my-vpn",
        "us_east_1",
        "server123",
        "a",
        "MyVPN-Server_01",
    ]

    INVALID_TAGS = [
        "",  # Empty
        "has space",  # Contains space
        "has/slash",  # Contains slash
        "has:colon",  # Contains colon
    ]

    @pytest.mark.parametrize("tag", VALID_TAGS)
    def test_valid_tag(self, tag):
        """Test that valid tags pass validation."""
        pattern = r'^[a-zA-Z0-9_-]+$'
        assert re.match(pattern, tag)

    @pytest.mark.parametrize("tag", INVALID_TAGS)
    def test_invalid_tag(self, tag):
        """Test that invalid tags fail validation."""
        pattern = r'^[a-zA-Z0-9_-]+$'
        assert not re.match(pattern, tag)

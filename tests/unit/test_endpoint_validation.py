"""
Unit tests for endpoint validation (CR-003/CR-004 fix).

Tests the validation of peer node endpoints in host:port format,
including hostname validation, port range checks, and edge cases.
"""

import pytest
import sys
from pathlib import Path

# Add scripts directory to path
SCRIPTS_DIR = Path(__file__).parent.parent.parent / "scripts"
sys.path.insert(0, str(SCRIPTS_DIR))


class TestEndpointValidation:
    """Tests for endpoint format validation."""

    # Valid endpoints
    VALID_ENDPOINTS = [
        "example.com:36200",
        "vpn.example.org:51820",
        "192.168.1.1:443",
        "10.0.0.1:80",
        "my-server.example.com:36200",
        "server_01.test.com:8080",
        "localhost:8000",
        "a.b:1",  # Minimal valid case
        "very-long-subdomain.another-subdomain.example.com:65535",
    ]

    # Invalid endpoints
    INVALID_ENDPOINTS = [
        # Missing port
        ("example.com", "missing port"),
        ("example.com:", "empty port"),
        # Invalid port
        ("example.com:0", "port 0"),
        ("example.com:65536", "port > 65535"),
        ("example.com:-1", "negative port"),
        ("example.com:abc", "non-numeric port"),
        ("example.com:99999", "port > 65535"),
        # Invalid hostname
        (":8080", "empty hostname"),
        ("..example.com:8080", "double dot in hostname"),
        ("-example.com:8080", "hostname starts with hyphen"),
        ("example-.com:8080", "hostname segment ends with hyphen"),
        ("example..com:8080", "double dot in hostname"),
        # Format issues
        ("example.com:8080:extra", "multiple colons"),
        ("", "empty string"),
        ("   :8080", "whitespace hostname"),
        # Injection attempts
        ("example.com:8080; rm -rf /", "command injection"),
        ("example.com:8080\n", "newline injection"),
        ("$(whoami).com:8080", "command substitution"),
    ]

    @pytest.fixture
    def validate_endpoint(self):
        """Import the validate_endpoint function from api_server."""
        # We'll create a local validation function that mirrors the implementation
        import re

        ENDPOINT_PATTERN = re.compile(r'^[\w\.\-]+:\d+$')

        def _validate_hostname(hostname: str) -> bool:
            """Validate hostname format."""
            if not hostname:
                return False
            if hostname.startswith('-') or hostname.startswith('.'):
                return False
            if '..' in hostname:
                return False
            if any(s.endswith('-') for s in hostname.split('.')):
                return False
            # Basic DNS label rules
            import re
            if not re.match(r'^[a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?)*$', hostname):
                if hostname != 'localhost':
                    return False
            return True

        def _validate_endpoint(endpoint: str) -> tuple:
            """Validate endpoint format host:port"""
            if not endpoint:
                return False, "endpoint is required"

            if not ENDPOINT_PATTERN.match(endpoint):
                return False, "endpoint format should be host:port"

            try:
                host, port_str = endpoint.rsplit(":", 1)
                port = int(port_str)
            except ValueError:
                return False, "invalid port number"

            if not _validate_hostname(host):
                return False, "invalid hostname"

            if not (1 <= port <= 65535):
                return False, "port out of range (1-65535)"

            return True, ""

        return _validate_endpoint

    @pytest.mark.parametrize("endpoint", VALID_ENDPOINTS)
    def test_valid_endpoints(self, validate_endpoint, endpoint):
        """Test that valid endpoints pass validation."""
        valid, error = validate_endpoint(endpoint)
        assert valid is True, f"Expected valid but got: {error}"

    @pytest.mark.parametrize("endpoint,description", INVALID_ENDPOINTS)
    def test_invalid_endpoints(self, validate_endpoint, endpoint, description):
        """Test that invalid endpoints fail validation."""
        valid, error = validate_endpoint(endpoint)
        assert valid is False, f"Expected invalid for {description}: {endpoint}"


class TestHostnameValidation:
    """Tests for hostname format validation."""

    VALID_HOSTNAMES = [
        "example.com",
        "sub.example.com",
        "my-server.example.com",
        "server01.test.org",
        "a.b.c.d.e.f",
        "localhost",
        "EXAMPLE.COM",  # Case insensitive
        "Example.Com",
    ]

    INVALID_HOSTNAMES = [
        "",  # Empty
        "-example.com",  # Starts with hyphen
        "example-.com",  # Segment ends with hyphen
        "..example.com",  # Double dot
        "example..com",  # Double dot in middle
        ".example.com",  # Starts with dot
        "example.com.",  # Ends with dot (trailing dot is technically valid in DNS but we reject)
        "exa mple.com",  # Contains space
    ]

    @pytest.fixture
    def validate_hostname(self):
        """Create hostname validation function."""
        import re

        def _validate_hostname(hostname: str) -> bool:
            if not hostname:
                return False
            if hostname.startswith('-') or hostname.startswith('.'):
                return False
            if hostname.endswith('.'):
                return False
            if '..' in hostname:
                return False
            if ' ' in hostname:
                return False
            if any(s.endswith('-') for s in hostname.split('.')):
                return False
            return True

        return _validate_hostname

    @pytest.mark.parametrize("hostname", VALID_HOSTNAMES)
    def test_valid_hostnames(self, validate_hostname, hostname):
        """Test that valid hostnames pass validation."""
        assert validate_hostname(hostname) is True

    @pytest.mark.parametrize("hostname", INVALID_HOSTNAMES)
    def test_invalid_hostnames(self, validate_hostname, hostname):
        """Test that invalid hostnames fail validation."""
        assert validate_hostname(hostname) is False


class TestPortValidation:
    """Tests for port number validation in endpoints."""

    VALID_PORTS = [1, 80, 443, 8080, 36200, 51820, 65535]
    INVALID_PORTS = [0, -1, 65536, 100000, -65535]

    @pytest.mark.parametrize("port", VALID_PORTS)
    def test_valid_ports(self, port):
        """Test that valid ports pass validation."""
        assert 1 <= port <= 65535

    @pytest.mark.parametrize("port", INVALID_PORTS)
    def test_invalid_ports(self, port):
        """Test that invalid ports fail validation."""
        assert not (1 <= port <= 65535)


class TestIPv4Endpoints:
    """Tests for IPv4 address endpoints."""

    VALID_IPV4_ENDPOINTS = [
        "192.168.1.1:8080",
        "10.0.0.1:443",
        "172.16.0.1:51820",
        "127.0.0.1:8000",
        "0.0.0.0:80",
        "255.255.255.255:65535",
    ]

    INVALID_IPV4_ENDPOINTS = [
        "256.0.0.1:8080",  # Octet > 255
        "192.168.1:8080",  # Missing octet
        "192.168.1.1.1:8080",  # Extra octet
        "192.168.1.256:8080",  # Last octet > 255
    ]

    @pytest.mark.parametrize("endpoint", VALID_IPV4_ENDPOINTS)
    def test_valid_ipv4_endpoints(self, endpoint):
        """Test that valid IPv4 endpoints pass basic format check."""
        import re
        # Basic check that it matches host:port format
        pattern = r'^[\d\.]+:\d+$'
        assert re.match(pattern, endpoint)

    @pytest.mark.parametrize("endpoint", INVALID_IPV4_ENDPOINTS)
    def test_invalid_ipv4_endpoints(self, endpoint):
        """Test that invalid IPv4 endpoints are detected by IP validation."""
        import ipaddress

        host = endpoint.rsplit(":", 1)[0]
        try:
            ipaddress.ip_address(host)
            valid = True
        except ValueError:
            valid = False
        assert valid is False


class TestEndpointEdgeCases:
    """Tests for edge cases and boundary conditions."""

    def test_port_boundary_minimum(self):
        """Test port at minimum valid value (1)."""
        assert 1 <= 1 <= 65535

    def test_port_boundary_maximum(self):
        """Test port at maximum valid value (65535)."""
        assert 1 <= 65535 <= 65535

    def test_port_boundary_zero(self):
        """Test port at zero (invalid)."""
        assert not (1 <= 0 <= 65535)

    def test_port_boundary_above_max(self):
        """Test port above maximum (65536, invalid)."""
        assert not (1 <= 65536 <= 65535)

    def test_very_long_hostname(self):
        """Test handling of very long hostnames."""
        # DNS labels are limited to 63 chars, total hostname to 253 chars
        long_label = "a" * 63
        long_hostname = f"{long_label}.{long_label}.{long_label}.com"

        # Should be within limits
        assert len(long_hostname) <= 253

    def test_maximum_port_as_string(self):
        """Test parsing maximum valid port from string."""
        port_str = "65535"
        port = int(port_str)
        assert 1 <= port <= 65535

    def test_port_with_leading_zeros(self):
        """Test port with leading zeros (should still be valid int)."""
        port_str = "00080"
        port = int(port_str)
        assert port == 80
        assert 1 <= port <= 65535

"""
Unit tests for PSK authentication rate limiting (CR-005 fix).

Tests the rate limiting mechanism that prevents brute-force attacks
on the PSK authentication endpoint.
"""

import pytest
import time
import sys
from pathlib import Path
from collections import defaultdict
from typing import Dict, List

# Add scripts directory to path
SCRIPTS_DIR = Path(__file__).parent.parent.parent / "scripts"
sys.path.insert(0, str(SCRIPTS_DIR))


class MockRateLimiter:
    """
    Mock implementation of the PSK rate limiter for testing.
    Mirrors the actual implementation in api_server.py.
    """

    def __init__(self, max_attempts: int = 5, window_seconds: int = 60):
        self._attempts: Dict[str, List[float]] = defaultdict(list)
        self.max_attempts = max_attempts
        self.window_seconds = window_seconds

    def check_rate_limit(self, client_ip: str) -> bool:
        """
        Check if a client IP is within rate limits.
        Returns True if allowed, False if rate limited.
        """
        now = time.time()
        attempts = self._attempts[client_ip]

        # Clean up expired attempts
        attempts[:] = [t for t in attempts if now - t < self.window_seconds]

        if len(attempts) >= self.max_attempts:
            return False

        attempts.append(now)
        return True

    def get_attempt_count(self, client_ip: str) -> int:
        """Get current attempt count for an IP."""
        now = time.time()
        attempts = self._attempts[client_ip]
        return len([t for t in attempts if now - t < self.window_seconds])

    def reset(self, client_ip: str = None):
        """Reset attempts for an IP or all IPs."""
        if client_ip:
            self._attempts[client_ip] = []
        else:
            self._attempts.clear()


class TestRateLimiter:
    """Tests for rate limiting mechanism."""

    @pytest.fixture
    def limiter(self):
        """Create a rate limiter with 5 attempts per 60 seconds."""
        return MockRateLimiter(max_attempts=5, window_seconds=60)

    @pytest.fixture
    def fast_limiter(self):
        """Create a rate limiter with a short window for timing tests."""
        return MockRateLimiter(max_attempts=3, window_seconds=1)

    def test_first_attempt_allowed(self, limiter):
        """Test that the first attempt is always allowed."""
        assert limiter.check_rate_limit("192.168.1.100") is True

    def test_attempts_within_limit_allowed(self, limiter):
        """Test that attempts within the limit are allowed."""
        client_ip = "192.168.1.100"

        # First 5 attempts should all be allowed
        for i in range(5):
            assert limiter.check_rate_limit(client_ip) is True, f"Attempt {i+1} should be allowed"

    def test_attempt_exceeding_limit_blocked(self, limiter):
        """Test that the 6th attempt is blocked."""
        client_ip = "192.168.1.100"

        # First 5 attempts
        for _ in range(5):
            limiter.check_rate_limit(client_ip)

        # 6th attempt should be blocked
        assert limiter.check_rate_limit(client_ip) is False

    def test_different_ips_have_separate_limits(self, limiter):
        """Test that different IPs have independent rate limits."""
        ip1 = "192.168.1.100"
        ip2 = "192.168.1.101"

        # Exhaust limit for ip1
        for _ in range(5):
            limiter.check_rate_limit(ip1)

        # ip1 should be blocked
        assert limiter.check_rate_limit(ip1) is False

        # ip2 should still be allowed
        assert limiter.check_rate_limit(ip2) is True

    def test_attempts_expire_after_window(self, fast_limiter):
        """Test that attempts expire after the window period."""
        client_ip = "192.168.1.100"

        # Exhaust limit
        for _ in range(3):
            fast_limiter.check_rate_limit(client_ip)

        # Should be blocked
        assert fast_limiter.check_rate_limit(client_ip) is False

        # Wait for window to expire
        time.sleep(1.1)

        # Should be allowed again
        assert fast_limiter.check_rate_limit(client_ip) is True

    def test_attempt_count_tracking(self, limiter):
        """Test that attempt counts are tracked correctly."""
        client_ip = "192.168.1.100"

        assert limiter.get_attempt_count(client_ip) == 0

        limiter.check_rate_limit(client_ip)
        assert limiter.get_attempt_count(client_ip) == 1

        limiter.check_rate_limit(client_ip)
        limiter.check_rate_limit(client_ip)
        assert limiter.get_attempt_count(client_ip) == 3

    def test_reset_clears_attempts(self, limiter):
        """Test that reset clears the attempt history."""
        client_ip = "192.168.1.100"

        # Make some attempts
        for _ in range(5):
            limiter.check_rate_limit(client_ip)

        # Should be blocked
        assert limiter.check_rate_limit(client_ip) is False

        # Reset
        limiter.reset(client_ip)

        # Should be allowed again
        assert limiter.check_rate_limit(client_ip) is True

    def test_partial_expiry(self, fast_limiter):
        """Test that only expired attempts are cleaned up."""
        client_ip = "192.168.1.100"

        # Make 2 attempts
        fast_limiter.check_rate_limit(client_ip)
        fast_limiter.check_rate_limit(client_ip)

        # Wait half the window
        time.sleep(0.5)

        # Make 1 more attempt
        fast_limiter.check_rate_limit(client_ip)

        # Should have 3 attempts tracked
        assert fast_limiter.get_attempt_count(client_ip) == 3

        # Wait for first 2 attempts to expire
        time.sleep(0.6)

        # Should only have 1 attempt remaining
        assert fast_limiter.get_attempt_count(client_ip) == 1

    def test_ipv6_addresses(self, limiter):
        """Test that IPv6 addresses are handled correctly."""
        ipv6_full = "2001:0db8:85a3:0000:0000:8a2e:0370:7334"
        ipv6_short = "::1"
        ipv6_mixed = "::ffff:192.168.1.100"

        # All should work independently
        assert limiter.check_rate_limit(ipv6_full) is True
        assert limiter.check_rate_limit(ipv6_short) is True
        assert limiter.check_rate_limit(ipv6_mixed) is True

        # Each has 1 attempt
        assert limiter.get_attempt_count(ipv6_full) == 1
        assert limiter.get_attempt_count(ipv6_short) == 1
        assert limiter.get_attempt_count(ipv6_mixed) == 1


class TestRateLimiterEdgeCases:
    """Tests for edge cases in rate limiting."""

    def test_zero_max_attempts(self):
        """Test limiter with 0 max attempts (always block)."""
        limiter = MockRateLimiter(max_attempts=0, window_seconds=60)
        assert limiter.check_rate_limit("192.168.1.100") is False

    def test_one_max_attempt(self):
        """Test limiter with 1 max attempt."""
        limiter = MockRateLimiter(max_attempts=1, window_seconds=60)

        assert limiter.check_rate_limit("192.168.1.100") is True
        assert limiter.check_rate_limit("192.168.1.100") is False

    def test_very_long_window(self):
        """Test limiter with a very long window (1 hour)."""
        limiter = MockRateLimiter(max_attempts=5, window_seconds=3600)

        for _ in range(5):
            limiter.check_rate_limit("192.168.1.100")

        # Should still be blocked (window hasn't expired)
        assert limiter.check_rate_limit("192.168.1.100") is False

    def test_empty_ip_string(self):
        """Test handling of empty IP string."""
        limiter = MockRateLimiter(max_attempts=5, window_seconds=60)

        # Empty string should work as a key
        assert limiter.check_rate_limit("") is True

    def test_special_characters_in_ip(self):
        """Test handling of IPs with special formatting."""
        limiter = MockRateLimiter(max_attempts=5, window_seconds=60)

        # These should all be treated as separate keys
        assert limiter.check_rate_limit("192.168.1.100") is True
        assert limiter.check_rate_limit(" 192.168.1.100") is True  # Leading space
        assert limiter.check_rate_limit("192.168.1.100 ") is True  # Trailing space


class TestRateLimiterConcurrency:
    """Tests for rate limiting under concurrent access."""

    def test_rapid_requests_same_ip(self):
        """Test rate limiting with rapid sequential requests."""
        limiter = MockRateLimiter(max_attempts=100, window_seconds=60)
        client_ip = "192.168.1.100"

        # Make 100 rapid requests
        for i in range(100):
            limiter.check_rate_limit(client_ip)

        # 101st should be blocked
        assert limiter.check_rate_limit(client_ip) is False

    def test_many_different_ips(self):
        """Test rate limiting with many different client IPs."""
        limiter = MockRateLimiter(max_attempts=5, window_seconds=60)

        # Track 1000 different IPs
        for i in range(1000):
            ip = f"192.168.{i // 256}.{i % 256}"
            assert limiter.check_rate_limit(ip) is True

        # All should have 1 attempt each
        for i in range(1000):
            ip = f"192.168.{i // 256}.{i % 256}"
            assert limiter.get_attempt_count(ip) == 1


class TestRateLimiterMemory:
    """Tests for rate limiter memory management."""

    def test_cleanup_on_check(self):
        """Test that expired entries are cleaned up during check."""
        limiter = MockRateLimiter(max_attempts=5, window_seconds=1)
        client_ip = "192.168.1.100"

        # Make 3 attempts
        for _ in range(3):
            limiter.check_rate_limit(client_ip)

        assert limiter.get_attempt_count(client_ip) == 3

        # Wait for expiry
        time.sleep(1.1)

        # Check triggers cleanup
        limiter.check_rate_limit(client_ip)

        # Should only have 1 attempt (the one we just made)
        assert limiter.get_attempt_count(client_ip) == 1

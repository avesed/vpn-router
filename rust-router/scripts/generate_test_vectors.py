#!/usr/bin/env python3
"""Generate test vectors for Rust rule engine parity testing.

This script generates a comprehensive set of test cases for verifying
that the Rust rule engine implementation matches the expected behavior
of the Python/sing-box reference implementation.

Usage:
    python generate_test_vectors.py [--output FILE]

Output:
    tests/fixtures/rule_test_vectors.json
"""

import json
import argparse
import random
from datetime import datetime
from typing import Any


def generate_domain_exact_tests() -> list[dict[str, Any]]:
    """Generate exact domain match test cases."""
    cases = []

    # Common exact domain matches
    domains = [
        ("google.com", "proxy"),
        ("facebook.com", "social"),
        ("twitter.com", "social"),
        ("github.com", "dev"),
        ("stackoverflow.com", "dev"),
        ("amazon.com", "shopping"),
        ("netflix.com", "streaming"),
        ("spotify.com", "streaming"),
    ]

    for i, (domain, outbound) in enumerate(domains):
        cases.append({
            "id": f"domain_exact_{i+1:03d}",
            "category": "domain_exact",
            "description": f"Exact match for {domain}",
            "input": {
                "domain": domain,
                "dest_ip": None,
                "dest_port": 443,
                "protocol": "tcp"
            },
            "rules": [{"type": "domain", "target": domain, "outbound": outbound}],
            "expected": {"outbound": outbound, "match_type": "domain"}
        })

    # Case insensitivity tests
    case_tests = [
        ("GOOGLE.COM", "google.com"),
        ("Google.Com", "google.com"),
        ("FACEBOOK.COM", "facebook.com"),
        ("FaceBook.Com", "facebook.com"),
    ]

    for i, (input_domain, rule_domain) in enumerate(case_tests):
        cases.append({
            "id": f"domain_exact_case_{i+1:03d}",
            "category": "domain_exact_case",
            "description": f"Case insensitive exact match: {input_domain} vs {rule_domain}",
            "input": {
                "domain": input_domain,
                "dest_ip": None,
                "dest_port": 443,
                "protocol": "tcp"
            },
            "rules": [{"type": "domain", "target": rule_domain, "outbound": "proxy"}],
            "expected": {"outbound": "proxy", "match_type": "domain"}
        })

    # Non-matching tests (subdomain should not match exact)
    non_matches = [
        ("www.google.com", "google.com"),
        ("mail.google.com", "google.com"),
        ("api.github.com", "github.com"),
    ]

    for i, (input_domain, rule_domain) in enumerate(non_matches):
        cases.append({
            "id": f"domain_exact_no_match_{i+1:03d}",
            "category": "domain_exact_no_match",
            "description": f"Subdomain should not match exact: {input_domain}",
            "input": {
                "domain": input_domain,
                "dest_ip": None,
                "dest_port": 443,
                "protocol": "tcp"
            },
            "rules": [{"type": "domain", "target": rule_domain, "outbound": "proxy"}],
            "expected": {"outbound": "direct", "match_type": None}
        })

    return cases


def generate_domain_suffix_tests() -> list[dict[str, Any]]:
    """Generate domain suffix match test cases."""
    cases = []

    # Basic suffix matches
    suffix_tests = [
        ("google.com", "www.google.com", "proxy"),
        ("google.com", "mail.google.com", "proxy"),
        ("google.com", "google.com", "proxy"),  # Exact also matches suffix
        ("google.com", "apis.google.com", "proxy"),
        ("facebook.com", "m.facebook.com", "social"),
        ("github.com", "api.github.com", "dev"),
    ]

    for i, (suffix, input_domain, outbound) in enumerate(suffix_tests):
        cases.append({
            "id": f"domain_suffix_{i+1:03d}",
            "category": "domain_suffix",
            "description": f"Suffix match: {input_domain} matches {suffix}",
            "input": {
                "domain": input_domain,
                "dest_ip": None,
                "dest_port": 443,
                "protocol": "tcp"
            },
            "rules": [{"type": "domain_suffix", "target": suffix, "outbound": outbound}],
            "expected": {"outbound": outbound, "match_type": "domain"}
        })

    # Deep subdomain tests
    deep_subdomains = [
        ("google.com", "very.deep.subdomain.google.com"),
        ("amazonaws.com", "s3.us-west-2.amazonaws.com"),
        ("cloudflare.com", "cdnjs.cloudflare.com"),
    ]

    for i, (suffix, input_domain) in enumerate(deep_subdomains):
        cases.append({
            "id": f"domain_suffix_deep_{i+1:03d}",
            "category": "domain_suffix_deep",
            "description": f"Deep subdomain suffix match: {input_domain}",
            "input": {
                "domain": input_domain,
                "dest_ip": None,
                "dest_port": 443,
                "protocol": "tcp"
            },
            "rules": [{"type": "domain_suffix", "target": suffix, "outbound": "proxy"}],
            "expected": {"outbound": "proxy", "match_type": "domain"}
        })

    # Boundary tests - should NOT match
    boundary_non_matches = [
        ("google.com", "notgoogle.com"),
        ("google.com", "fakegoogle.com"),
        ("facebook.com", "notfacebook.com"),
        ("amazon.com", "famazon.com"),
    ]

    for i, (suffix, input_domain) in enumerate(boundary_non_matches):
        cases.append({
            "id": f"domain_suffix_boundary_{i+1:03d}",
            "category": "domain_suffix_boundary",
            "description": f"Suffix boundary: {input_domain} should NOT match {suffix}",
            "input": {
                "domain": input_domain,
                "dest_ip": None,
                "dest_port": 443,
                "protocol": "tcp"
            },
            "rules": [{"type": "domain_suffix", "target": suffix, "outbound": "proxy"}],
            "expected": {"outbound": "direct", "match_type": None}
        })

    # Leading dot handling
    leading_dot_tests = [
        (".google.com", "www.google.com", True),
        (".google.com", "google.com", True),
        ("google.com", "www.google.com", True),
    ]

    for i, (suffix, input_domain, should_match) in enumerate(leading_dot_tests):
        expected = {"outbound": "proxy", "match_type": "domain"} if should_match else {"outbound": "direct", "match_type": None}
        cases.append({
            "id": f"domain_suffix_leadingdot_{i+1:03d}",
            "category": "domain_suffix_leading_dot",
            "description": f"Leading dot handling: {input_domain} vs {suffix}",
            "input": {
                "domain": input_domain,
                "dest_ip": None,
                "dest_port": 443,
                "protocol": "tcp"
            },
            "rules": [{"type": "domain_suffix", "target": suffix, "outbound": "proxy"}],
            "expected": expected
        })

    return cases


def generate_domain_keyword_tests() -> list[dict[str, Any]]:
    """Generate domain keyword match test cases."""
    cases = []

    # Basic keyword matches
    keyword_tests = [
        ("google", "google.com", "proxy"),
        ("google", "www.google.com", "proxy"),
        ("google", "googleapis.com", "proxy"),
        ("ads", "ads.example.com", "block"),
        ("tracking", "tracking.example.com", "block"),
        ("facebook", "facebook.com", "social"),
        ("facebook", "connect.facebook.net", "social"),
    ]

    for i, (keyword, input_domain, outbound) in enumerate(keyword_tests):
        cases.append({
            "id": f"domain_keyword_{i+1:03d}",
            "category": "domain_keyword",
            "description": f"Keyword match: {keyword} in {input_domain}",
            "input": {
                "domain": input_domain,
                "dest_ip": None,
                "dest_port": 443,
                "protocol": "tcp"
            },
            "rules": [{"type": "domain_keyword", "target": keyword, "outbound": outbound}],
            "expected": {"outbound": outbound, "match_type": "domain"}
        })

    # Keyword in middle of domain
    middle_keyword_tests = [
        ("ads", "example-ads-server.com"),
        ("track", "track-analytics.example.com"),
        ("cdn", "cdn.example.com"),
    ]

    for i, (keyword, input_domain) in enumerate(middle_keyword_tests):
        cases.append({
            "id": f"domain_keyword_middle_{i+1:03d}",
            "category": "domain_keyword_middle",
            "description": f"Keyword in middle: {keyword} in {input_domain}",
            "input": {
                "domain": input_domain,
                "dest_ip": None,
                "dest_port": 443,
                "protocol": "tcp"
            },
            "rules": [{"type": "domain_keyword", "target": keyword, "outbound": "block"}],
            "expected": {"outbound": "block", "match_type": "domain"}
        })

    # No keyword match
    no_keyword_tests = [
        ("facebook", "google.com"),
        ("twitter", "amazon.com"),
        ("youtube", "netflix.com"),
    ]

    for i, (keyword, input_domain) in enumerate(no_keyword_tests):
        cases.append({
            "id": f"domain_keyword_no_match_{i+1:03d}",
            "category": "domain_keyword_no_match",
            "description": f"No keyword match: {keyword} not in {input_domain}",
            "input": {
                "domain": input_domain,
                "dest_ip": None,
                "dest_port": 443,
                "protocol": "tcp"
            },
            "rules": [{"type": "domain_keyword", "target": keyword, "outbound": "proxy"}],
            "expected": {"outbound": "direct", "match_type": None}
        })

    return cases


def generate_domain_regex_tests() -> list[dict[str, Any]]:
    """Generate domain regex match test cases."""
    cases = []

    # Basic regex patterns
    regex_tests = [
        (r".*\.google\.com$", "www.google.com", True),
        (r".*\.google\.com$", "mail.google.com", True),
        (r".*\.google\.com$", "google.com", False),  # No subdomain
        (r"^www\..*\.com$", "www.example.com", True),
        (r"^www\..*\.com$", "api.example.com", False),
        (r".*\.(cn|ru|ir)$", "example.cn", True),
        (r".*\.(cn|ru|ir)$", "example.ru", True),
        (r".*\.(cn|ru|ir)$", "example.ir", True),
        (r".*\.(cn|ru|ir)$", "example.com", False),
    ]

    for i, (pattern, input_domain, should_match) in enumerate(regex_tests):
        expected = {"outbound": "proxy", "match_type": "domain"} if should_match else {"outbound": "direct", "match_type": None}
        cases.append({
            "id": f"domain_regex_{i+1:03d}",
            "category": "domain_regex",
            "description": f"Regex match: {pattern} vs {input_domain}",
            "input": {
                "domain": input_domain,
                "dest_ip": None,
                "dest_port": 443,
                "protocol": "tcp"
            },
            "rules": [{"type": "domain_regex", "target": pattern, "outbound": "proxy"}],
            "expected": expected
        })

    # Complex regex patterns
    complex_regex_tests = [
        (r"^(www|api|cdn)\.example\.com$", "www.example.com", True),
        (r"^(www|api|cdn)\.example\.com$", "api.example.com", True),
        (r"^(www|api|cdn)\.example\.com$", "cdn.example.com", True),
        (r"^(www|api|cdn)\.example\.com$", "mail.example.com", False),
        (r".*-cdn[0-9]+\..*", "static-cdn01.example.com", True),
        (r".*-cdn[0-9]+\..*", "static-cdn123.example.com", True),
        (r".*-cdn[0-9]+\..*", "static-server.example.com", False),
    ]

    for i, (pattern, input_domain, should_match) in enumerate(complex_regex_tests):
        expected = {"outbound": "proxy", "match_type": "domain"} if should_match else {"outbound": "direct", "match_type": None}
        cases.append({
            "id": f"domain_regex_complex_{i+1:03d}",
            "category": "domain_regex_complex",
            "description": f"Complex regex: {pattern} vs {input_domain}",
            "input": {
                "domain": input_domain,
                "dest_ip": None,
                "dest_port": 443,
                "protocol": "tcp"
            },
            "rules": [{"type": "domain_regex", "target": pattern, "outbound": "proxy"}],
            "expected": expected
        })

    return cases


def generate_geoip_cidr_tests() -> list[dict[str, Any]]:
    """Generate GeoIP CIDR match test cases."""
    cases = []

    # Private IPv4 ranges
    private_ipv4_tests = [
        ("10.0.0.0/8", "10.0.0.1", "private"),
        ("10.0.0.0/8", "10.255.255.255", "private"),
        ("10.0.0.0/8", "10.100.50.25", "private"),
        ("172.16.0.0/12", "172.16.0.1", "private"),
        ("172.16.0.0/12", "172.31.255.255", "private"),
        ("172.16.0.0/12", "172.20.100.50", "private"),
        ("192.168.0.0/16", "192.168.0.1", "private"),
        ("192.168.0.0/16", "192.168.255.255", "private"),
        ("192.168.0.0/16", "192.168.1.100", "private"),
    ]

    for i, (cidr, ip, outbound) in enumerate(private_ipv4_tests):
        cases.append({
            "id": f"geoip_cidr_private_{i+1:03d}",
            "category": "geoip_cidr_private",
            "description": f"Private IPv4 CIDR match: {ip} in {cidr}",
            "input": {
                "domain": None,
                "dest_ip": ip,
                "dest_port": 443,
                "protocol": "tcp"
            },
            "rules": [{"type": "ip_cidr", "target": cidr, "outbound": outbound}],
            "expected": {"outbound": outbound, "match_type": "geoip"}
        })

    # CIDR boundary tests (should NOT match)
    boundary_tests = [
        ("10.0.0.0/8", "11.0.0.1"),
        ("10.0.0.0/8", "9.255.255.255"),
        ("172.16.0.0/12", "172.32.0.1"),
        ("172.16.0.0/12", "172.15.255.255"),
        ("192.168.0.0/16", "192.169.0.1"),
        ("192.168.0.0/16", "192.167.255.255"),
    ]

    for i, (cidr, ip) in enumerate(boundary_tests):
        cases.append({
            "id": f"geoip_cidr_boundary_{i+1:03d}",
            "category": "geoip_cidr_boundary",
            "description": f"CIDR boundary: {ip} NOT in {cidr}",
            "input": {
                "domain": None,
                "dest_ip": ip,
                "dest_port": 443,
                "protocol": "tcp"
            },
            "rules": [{"type": "ip_cidr", "target": cidr, "outbound": "private"}],
            "expected": {"outbound": "direct", "match_type": None}
        })

    # Single host /32
    single_host_tests = [
        ("8.8.8.8/32", "8.8.8.8", True),
        ("8.8.8.8/32", "8.8.8.9", False),
        ("1.1.1.1/32", "1.1.1.1", True),
        ("1.1.1.1/32", "1.1.1.2", False),
    ]

    for i, (cidr, ip, should_match) in enumerate(single_host_tests):
        expected = {"outbound": "proxy", "match_type": "geoip"} if should_match else {"outbound": "direct", "match_type": None}
        cases.append({
            "id": f"geoip_cidr_single_{i+1:03d}",
            "category": "geoip_cidr_single",
            "description": f"Single host CIDR: {ip} vs {cidr}",
            "input": {
                "domain": None,
                "dest_ip": ip,
                "dest_port": 443,
                "protocol": "tcp"
            },
            "rules": [{"type": "ip_cidr", "target": cidr, "outbound": "proxy"}],
            "expected": expected
        })

    # Various CIDR prefix lengths
    prefix_tests = [
        ("8.0.0.0/8", "8.1.2.3", True),
        ("8.8.0.0/16", "8.8.1.2", True),
        ("8.8.8.0/24", "8.8.8.1", True),
        ("8.8.8.0/24", "8.8.9.1", False),
    ]

    for i, (cidr, ip, should_match) in enumerate(prefix_tests):
        expected = {"outbound": "proxy", "match_type": "geoip"} if should_match else {"outbound": "direct", "match_type": None}
        cases.append({
            "id": f"geoip_cidr_prefix_{i+1:03d}",
            "category": "geoip_cidr_prefix",
            "description": f"CIDR prefix length: {ip} vs {cidr}",
            "input": {
                "domain": None,
                "dest_ip": ip,
                "dest_port": 443,
                "protocol": "tcp"
            },
            "rules": [{"type": "ip_cidr", "target": cidr, "outbound": "proxy"}],
            "expected": expected
        })

    # IPv6 CIDR tests
    ipv6_tests = [
        ("2001:db8::/32", "2001:db8::1", True),
        ("2001:db8::/32", "2001:db8:ffff:ffff:ffff:ffff:ffff:ffff", True),
        ("2001:db8::/32", "2001:db9::1", False),
        ("fe80::/10", "fe80::1", True),
        ("fe80::/10", "fe81::1", True),
        ("fe80::/10", "fec0::1", False),
        ("::1/128", "::1", True),
        ("::1/128", "::2", False),
    ]

    for i, (cidr, ip, should_match) in enumerate(ipv6_tests):
        expected = {"outbound": "proxy", "match_type": "geoip"} if should_match else {"outbound": "direct", "match_type": None}
        cases.append({
            "id": f"geoip_cidr_ipv6_{i+1:03d}",
            "category": "geoip_cidr_ipv6",
            "description": f"IPv6 CIDR: {ip} vs {cidr}",
            "input": {
                "domain": None,
                "dest_ip": ip,
                "dest_port": 443,
                "protocol": "tcp"
            },
            "rules": [{"type": "ip_cidr", "target": cidr, "outbound": "proxy"}],
            "expected": expected
        })

    # Localhost tests
    localhost_tests = [
        ("127.0.0.0/8", "127.0.0.1", True),
        ("127.0.0.0/8", "127.255.255.255", True),
        ("127.0.0.0/8", "128.0.0.1", False),
        ("::1/128", "::1", True),
    ]

    for i, (cidr, ip, should_match) in enumerate(localhost_tests):
        expected = {"outbound": "localhost", "match_type": "geoip"} if should_match else {"outbound": "direct", "match_type": None}
        cases.append({
            "id": f"geoip_cidr_localhost_{i+1:03d}",
            "category": "geoip_cidr_localhost",
            "description": f"Localhost: {ip} vs {cidr}",
            "input": {
                "domain": None,
                "dest_ip": ip,
                "dest_port": 443,
                "protocol": "tcp"
            },
            "rules": [{"type": "ip_cidr", "target": cidr, "outbound": "localhost"}],
            "expected": expected
        })

    return cases


def generate_port_tests() -> list[dict[str, Any]]:
    """Generate port matching test cases."""
    cases = []

    # Single port matches
    single_ports = [
        (80, 80, True),
        (443, 443, True),
        (8080, 8080, True),
        (22, 22, True),
        (80, 81, False),
        (443, 442, False),
    ]

    for i, (rule_port, input_port, should_match) in enumerate(single_ports):
        expected = {"outbound": "proxy", "match_type": "rule"} if should_match else {"outbound": "direct", "match_type": None}
        cases.append({
            "id": f"port_single_{i+1:03d}",
            "category": "port_single",
            "description": f"Single port: {input_port} vs {rule_port}",
            "input": {
                "domain": None,
                "dest_ip": "8.8.8.8",
                "dest_port": input_port,
                "protocol": "tcp"
            },
            "rules": [{"type": "port", "target": str(rule_port), "outbound": "proxy"}],
            "expected": expected
        })

    # Port range matches
    range_tests = [
        ("80-443", 80, True),
        ("80-443", 443, True),
        ("80-443", 200, True),
        ("80-443", 79, False),
        ("80-443", 444, False),
        ("1-1024", 1, True),
        ("1-1024", 1024, True),
        ("1-1024", 512, True),
        ("1-1024", 0, False),  # Port 0 is invalid but test boundary
        ("1-1024", 1025, False),
        ("8000-9000", 8000, True),
        ("8000-9000", 9000, True),
        ("8000-9000", 8500, True),
        ("8000-9000", 7999, False),
        ("8000-9000", 9001, False),
    ]

    for i, (range_str, input_port, should_match) in enumerate(range_tests):
        if input_port == 0:
            continue  # Skip invalid port 0
        expected = {"outbound": "proxy", "match_type": "rule"} if should_match else {"outbound": "direct", "match_type": None}
        cases.append({
            "id": f"port_range_{i+1:03d}",
            "category": "port_range",
            "description": f"Port range: {input_port} vs {range_str}",
            "input": {
                "domain": None,
                "dest_ip": "8.8.8.8",
                "dest_port": input_port,
                "protocol": "tcp"
            },
            "rules": [{"type": "port", "target": range_str, "outbound": "proxy"}],
            "expected": expected
        })

    # Edge case ports
    edge_ports = [
        (1, "1", True),
        (65535, "65535", True),
        (65534, "65534", True),
    ]

    for i, (input_port, rule_port, should_match) in enumerate(edge_ports):
        expected = {"outbound": "proxy", "match_type": "rule"} if should_match else {"outbound": "direct", "match_type": None}
        cases.append({
            "id": f"port_edge_{i+1:03d}",
            "category": "port_edge",
            "description": f"Edge port: {input_port}",
            "input": {
                "domain": None,
                "dest_ip": "8.8.8.8",
                "dest_port": input_port,
                "protocol": "tcp"
            },
            "rules": [{"type": "port", "target": rule_port, "outbound": "proxy"}],
            "expected": expected
        })

    return cases


def generate_protocol_tests() -> list[dict[str, Any]]:
    """Generate protocol matching test cases."""
    cases = []

    # Basic protocol matches
    protocol_tests = [
        ("tcp", "tcp", True),
        ("udp", "udp", True),
        ("tcp", "udp", False),
        ("udp", "tcp", False),
        ("TCP", "tcp", True),  # Case insensitive
        ("UDP", "udp", True),
    ]

    for i, (rule_proto, input_proto, should_match) in enumerate(protocol_tests):
        expected = {"outbound": "proxy", "match_type": "rule"} if should_match else {"outbound": "direct", "match_type": None}
        cases.append({
            "id": f"protocol_{i+1:03d}",
            "category": "protocol",
            "description": f"Protocol: {input_proto} vs rule {rule_proto}",
            "input": {
                "domain": None,
                "dest_ip": "8.8.8.8",
                "dest_port": 443,
                "protocol": input_proto
            },
            "rules": [{"type": "protocol", "target": rule_proto, "outbound": "proxy"}],
            "expected": expected
        })

    # Sniffed protocol tests
    sniffed_tests = [
        ("tls", "tcp", "tls", True),
        ("http", "tcp", "http", True),
        ("quic", "udp", "quic", True),
        ("tls", "tcp", "http", False),
        ("http", "tcp", "tls", False),
    ]

    for i, (rule_proto, transport, sniffed, should_match) in enumerate(sniffed_tests):
        expected = {"outbound": "proxy", "match_type": "rule"} if should_match else {"outbound": "direct", "match_type": None}
        cases.append({
            "id": f"protocol_sniffed_{i+1:03d}",
            "category": "protocol_sniffed",
            "description": f"Sniffed protocol: {sniffed} vs {rule_proto}",
            "input": {
                "domain": None,
                "dest_ip": "8.8.8.8",
                "dest_port": 443,
                "protocol": transport,
                "sniffed_protocol": sniffed
            },
            "rules": [{"type": "protocol", "target": rule_proto, "outbound": "proxy"}],
            "expected": expected
        })

    return cases


def generate_priority_tests() -> list[dict[str, Any]]:
    """Generate rule priority test cases."""
    cases = []

    # Domain vs GeoIP priority (domain should win)
    cases.append({
        "id": "priority_domain_over_geoip_001",
        "category": "priority",
        "description": "Domain rule takes priority over GeoIP",
        "input": {
            "domain": "example.com",
            "dest_ip": "10.0.0.1",  # Private IP
            "dest_port": 443,
            "protocol": "tcp"
        },
        "rules": [
            {"type": "domain", "target": "example.com", "outbound": "domain-proxy"},
            {"type": "ip_cidr", "target": "10.0.0.0/8", "outbound": "private"}
        ],
        "expected": {"outbound": "domain-proxy", "match_type": "domain"}
    })

    # Multiple domain rules (first match wins by order)
    cases.append({
        "id": "priority_domain_order_001",
        "category": "priority",
        "description": "First matching domain rule wins",
        "input": {
            "domain": "www.example.com",
            "dest_ip": None,
            "dest_port": 443,
            "protocol": "tcp"
        },
        "rules": [
            {"type": "domain_suffix", "target": "example.com", "outbound": "first-proxy"},
            {"type": "domain_keyword", "target": "example", "outbound": "second-proxy"}
        ],
        "expected": {"outbound": "first-proxy", "match_type": "domain"}
    })

    # Exact over suffix
    cases.append({
        "id": "priority_exact_over_suffix_001",
        "category": "priority",
        "description": "Exact domain match over suffix",
        "input": {
            "domain": "example.com",
            "dest_ip": None,
            "dest_port": 443,
            "protocol": "tcp"
        },
        "rules": [
            {"type": "domain", "target": "example.com", "outbound": "exact-proxy"},
            {"type": "domain_suffix", "target": "example.com", "outbound": "suffix-proxy"}
        ],
        "expected": {"outbound": "exact-proxy", "match_type": "domain"}
    })

    # GeoIP over port rules
    cases.append({
        "id": "priority_geoip_over_port_001",
        "category": "priority",
        "description": "GeoIP takes priority over port rules",
        "input": {
            "domain": None,
            "dest_ip": "10.0.0.1",
            "dest_port": 443,
            "protocol": "tcp"
        },
        "rules": [
            {"type": "ip_cidr", "target": "10.0.0.0/8", "outbound": "private"},
            {"type": "port", "target": "443", "outbound": "https-proxy"}
        ],
        "expected": {"outbound": "private", "match_type": "geoip"}
    })

    # Chain routing marks
    cases.append({
        "id": "priority_chain_routing_001",
        "category": "priority_chain",
        "description": "Chain routing with routing mark",
        "input": {
            "domain": "stream.example.com",
            "dest_ip": None,
            "dest_port": 443,
            "protocol": "tcp"
        },
        "rules": [
            {"type": "domain_suffix", "target": "example.com", "outbound": "us-stream"}
        ],
        "chains": ["us-stream"],
        "expected": {"outbound": "us-stream", "match_type": "domain", "has_routing_mark": True}
    })

    # Multiple CIDR rules (more specific first)
    cases.append({
        "id": "priority_cidr_specific_001",
        "category": "priority",
        "description": "More specific CIDR should be added first",
        "input": {
            "domain": None,
            "dest_ip": "192.168.1.100",
            "dest_port": 443,
            "protocol": "tcp"
        },
        "rules": [
            {"type": "ip_cidr", "target": "192.168.1.0/24", "outbound": "subnet"},
            {"type": "ip_cidr", "target": "192.168.0.0/16", "outbound": "network"}
        ],
        "expected": {"outbound": "subnet", "match_type": "geoip"}
    })

    # Default fallback
    cases.append({
        "id": "priority_default_001",
        "category": "priority",
        "description": "No match falls to default",
        "input": {
            "domain": "unknown.org",
            "dest_ip": "100.100.100.100",
            "dest_port": 12345,
            "protocol": "tcp"
        },
        "rules": [
            {"type": "domain_suffix", "target": "example.com", "outbound": "proxy"},
            {"type": "ip_cidr", "target": "10.0.0.0/8", "outbound": "private"},
            {"type": "port", "target": "443", "outbound": "https"}
        ],
        "expected": {"outbound": "direct", "match_type": None}
    })

    return cases


def generate_chain_routing_tests() -> list[dict[str, Any]]:
    """Generate chain routing test cases."""
    cases = []

    # Basic chain routing
    chain_configs = [
        ("us-stream", 1),
        ("jp-gaming", 2),
        ("eu-work", 3),
        ("asia-proxy", 4),
    ]

    for i, (chain_tag, dscp) in enumerate(chain_configs):
        cases.append({
            "id": f"chain_basic_{i+1:03d}",
            "category": "chain_routing",
            "description": f"Chain routing: {chain_tag} with DSCP {dscp}",
            "input": {
                "domain": f"test-{chain_tag}.example.com",
                "dest_ip": None,
                "dest_port": 443,
                "protocol": "tcp"
            },
            "rules": [
                {"type": "domain_suffix", "target": f"test-{chain_tag}.example.com", "outbound": chain_tag}
            ],
            "chains": [{"tag": chain_tag, "dscp": dscp}],
            "expected": {
                "outbound": chain_tag,
                "match_type": "domain",
                "has_routing_mark": True,
                "routing_mark": 768 + dscp  # ENTRY_ROUTING_MARK_BASE + dscp
            }
        })

    # Chain with auto-assigned DSCP
    cases.append({
        "id": "chain_auto_dscp_001",
        "category": "chain_routing",
        "description": "Chain with auto-assigned DSCP",
        "input": {
            "domain": "auto-chain.example.com",
            "dest_ip": None,
            "dest_port": 443,
            "protocol": "tcp"
        },
        "rules": [
            {"type": "domain_suffix", "target": "auto-chain.example.com", "outbound": "auto-chain"}
        ],
        "chains": ["auto-chain"],  # Auto-assign DSCP
        "expected": {
            "outbound": "auto-chain",
            "match_type": "domain",
            "has_routing_mark": True
        }
    })

    # Non-chain outbound (no routing mark)
    cases.append({
        "id": "chain_non_chain_001",
        "category": "chain_routing",
        "description": "Non-chain outbound has no routing mark",
        "input": {
            "domain": "direct.example.com",
            "dest_ip": None,
            "dest_port": 443,
            "protocol": "tcp"
        },
        "rules": [
            {"type": "domain_suffix", "target": "direct.example.com", "outbound": "direct"}
        ],
        "chains": ["other-chain"],
        "expected": {
            "outbound": "direct",
            "match_type": "domain",
            "has_routing_mark": False
        }
    })

    return cases


def generate_edge_cases() -> list[dict[str, Any]]:
    """Generate edge case test cases."""
    cases = []

    # Empty domain
    cases.append({
        "id": "edge_empty_domain_001",
        "category": "edge_case",
        "description": "Empty domain string",
        "input": {
            "domain": "",
            "dest_ip": "8.8.8.8",
            "dest_port": 443,
            "protocol": "tcp"
        },
        "rules": [
            {"type": "domain_suffix", "target": "example.com", "outbound": "proxy"}
        ],
        "expected": {"outbound": "direct", "match_type": None}
    })

    # No domain (IP only)
    cases.append({
        "id": "edge_no_domain_001",
        "category": "edge_case",
        "description": "No domain, IP only",
        "input": {
            "domain": None,
            "dest_ip": "8.8.8.8",
            "dest_port": 443,
            "protocol": "tcp"
        },
        "rules": [
            {"type": "domain_suffix", "target": "example.com", "outbound": "proxy"}
        ],
        "expected": {"outbound": "direct", "match_type": None}
    })

    # Very long domain
    long_subdomain = "a" * 63  # Max label length
    long_domain = f"{long_subdomain}.{long_subdomain}.{long_subdomain}.example.com"
    cases.append({
        "id": "edge_long_domain_001",
        "category": "edge_case",
        "description": "Very long domain name",
        "input": {
            "domain": long_domain,
            "dest_ip": None,
            "dest_port": 443,
            "protocol": "tcp"
        },
        "rules": [
            {"type": "domain_suffix", "target": "example.com", "outbound": "proxy"}
        ],
        "expected": {"outbound": "proxy", "match_type": "domain"}
    })

    # Domain with hyphens
    cases.append({
        "id": "edge_hyphen_domain_001",
        "category": "edge_case",
        "description": "Domain with hyphens",
        "input": {
            "domain": "my-test-domain.example-site.com",
            "dest_ip": None,
            "dest_port": 443,
            "protocol": "tcp"
        },
        "rules": [
            {"type": "domain_suffix", "target": "example-site.com", "outbound": "proxy"}
        ],
        "expected": {"outbound": "proxy", "match_type": "domain"}
    })

    # Numeric domain (IP-like but not IP)
    cases.append({
        "id": "edge_numeric_domain_001",
        "category": "edge_case",
        "description": "Numeric-looking domain",
        "input": {
            "domain": "123.456.789.example.com",
            "dest_ip": None,
            "dest_port": 443,
            "protocol": "tcp"
        },
        "rules": [
            {"type": "domain_suffix", "target": "example.com", "outbound": "proxy"}
        ],
        "expected": {"outbound": "proxy", "match_type": "domain"}
    })

    # Trailing dot in domain (FQDN)
    cases.append({
        "id": "edge_trailing_dot_001",
        "category": "edge_case",
        "description": "Domain with trailing dot (FQDN)",
        "input": {
            "domain": "www.example.com.",  # Note: typically normalized before matching
            "dest_ip": None,
            "dest_port": 443,
            "protocol": "tcp"
        },
        "rules": [
            {"type": "domain_suffix", "target": "example.com", "outbound": "proxy"}
        ],
        "expected": {"outbound": "direct", "match_type": None}  # Trailing dot causes mismatch
    })

    # No rules at all
    cases.append({
        "id": "edge_no_rules_001",
        "category": "edge_case",
        "description": "No rules, default fallback",
        "input": {
            "domain": "any.domain.com",
            "dest_ip": "1.2.3.4",
            "dest_port": 443,
            "protocol": "tcp"
        },
        "rules": [],
        "expected": {"outbound": "direct", "match_type": None}
    })

    # Mixed case domain with suffix
    cases.append({
        "id": "edge_mixed_case_suffix_001",
        "category": "edge_case",
        "description": "Mixed case domain with suffix match",
        "input": {
            "domain": "WWW.EXAMPLE.COM",
            "dest_ip": None,
            "dest_port": 443,
            "protocol": "tcp"
        },
        "rules": [
            {"type": "domain_suffix", "target": "example.com", "outbound": "proxy"}
        ],
        "expected": {"outbound": "proxy", "match_type": "domain"}
    })

    # All zeros IP
    cases.append({
        "id": "edge_zero_ip_001",
        "category": "edge_case",
        "description": "All zeros IP address",
        "input": {
            "domain": None,
            "dest_ip": "0.0.0.0",
            "dest_port": 443,
            "protocol": "tcp"
        },
        "rules": [
            {"type": "ip_cidr", "target": "0.0.0.0/8", "outbound": "block"}
        ],
        "expected": {"outbound": "block", "match_type": "geoip"}
    })

    # Broadcast address
    cases.append({
        "id": "edge_broadcast_001",
        "category": "edge_case",
        "description": "Broadcast IP address",
        "input": {
            "domain": None,
            "dest_ip": "255.255.255.255",
            "dest_port": 443,
            "protocol": "tcp"
        },
        "rules": [
            {"type": "ip_cidr", "target": "255.255.255.255/32", "outbound": "block"}
        ],
        "expected": {"outbound": "block", "match_type": "geoip"}
    })

    return cases


def generate_comprehensive_tests() -> list[dict[str, Any]]:
    """Generate comprehensive real-world-like test cases."""
    cases = []

    # Streaming services
    streaming_domains = [
        ("netflix.com", "netflix"),
        ("hulu.com", "hulu"),
        ("disneyplus.com", "disney"),
        ("hbomax.com", "hbo"),
        ("primevideo.com", "amazon"),
        ("youtube.com", "google"),
        ("twitch.tv", "twitch"),
        ("crunchyroll.com", "crunchyroll"),
        ("peacocktv.com", "peacock"),
        ("paramountplus.com", "paramount"),
    ]

    for i, (domain, service) in enumerate(streaming_domains):
        cases.append({
            "id": f"real_streaming_{i+1:03d}",
            "category": "real_world",
            "description": f"Streaming service: {service}",
            "input": {
                "domain": f"www.{domain}",
                "dest_ip": None,
                "dest_port": 443,
                "protocol": "tcp"
            },
            "rules": [
                {"type": "domain_suffix", "target": domain, "outbound": f"{service}-proxy"}
            ],
            "expected": {"outbound": f"{service}-proxy", "match_type": "domain"}
        })

    # Social media
    social_domains = [
        ("facebook.com", "meta"),
        ("instagram.com", "meta"),
        ("twitter.com", "twitter"),
        ("x.com", "twitter"),
        ("tiktok.com", "tiktok"),
        ("linkedin.com", "linkedin"),
        ("pinterest.com", "pinterest"),
        ("reddit.com", "reddit"),
        ("snapchat.com", "snapchat"),
        ("discord.com", "discord"),
        ("slack.com", "slack"),
        ("telegram.org", "telegram"),
        ("whatsapp.com", "whatsapp"),
    ]

    for i, (domain, platform) in enumerate(social_domains):
        cases.append({
            "id": f"real_social_{i+1:03d}",
            "category": "real_world",
            "description": f"Social media: {platform}",
            "input": {
                "domain": domain,
                "dest_ip": None,
                "dest_port": 443,
                "protocol": "tcp"
            },
            "rules": [
                {"type": "domain_suffix", "target": domain, "outbound": "social-proxy"}
            ],
            "expected": {"outbound": "social-proxy", "match_type": "domain"}
        })

    # Developer tools
    dev_domains = [
        "github.com",
        "gitlab.com",
        "bitbucket.org",
        "stackoverflow.com",
        "npmjs.com",
        "pypi.org",
        "crates.io",
        "docker.com",
        "kubernetes.io",
        "terraform.io",
        "ansible.com",
        "jenkins.io",
        "circleci.com",
        "travis-ci.com",
        "vercel.com",
        "netlify.com",
        "heroku.com",
        "aws.amazon.com",
        "cloud.google.com",
        "azure.microsoft.com",
    ]

    for i, domain in enumerate(dev_domains):
        cases.append({
            "id": f"real_dev_{i+1:03d}",
            "category": "real_world",
            "description": f"Developer tool: {domain}",
            "input": {
                "domain": domain,
                "dest_ip": None,
                "dest_port": 443,
                "protocol": "tcp"
            },
            "rules": [
                {"type": "domain_suffix", "target": domain, "outbound": "dev-proxy"}
            ],
            "expected": {"outbound": "dev-proxy", "match_type": "domain"}
        })

    # Ad blocking keywords
    ad_keywords = ["ads", "tracking", "analytics", "telemetry", "metrics", "beacon", "pixel", "tracker", "adserver", "doubleclick"]

    for i, keyword in enumerate(ad_keywords):
        cases.append({
            "id": f"real_adblock_{i+1:03d}",
            "category": "real_world",
            "description": f"Ad blocking keyword: {keyword}",
            "input": {
                "domain": f"{keyword}.example.com",
                "dest_ip": None,
                "dest_port": 443,
                "protocol": "tcp"
            },
            "rules": [
                {"type": "domain_keyword", "target": keyword, "outbound": "block"}
            ],
            "expected": {"outbound": "block", "match_type": "domain"}
        })

    return cases


def generate_additional_cidr_tests() -> list[dict[str, Any]]:
    """Generate additional CIDR tests to reach 500+ cases."""
    cases = []

    # Cloud provider IP ranges (representative samples)
    cloud_ranges = [
        ("13.0.0.0/8", "13.52.100.50", "aws"),
        ("34.0.0.0/8", "34.102.50.25", "gcp"),
        ("40.0.0.0/8", "40.112.100.50", "azure"),
        ("52.0.0.0/8", "52.95.100.50", "aws"),
        ("54.0.0.0/8", "54.200.100.50", "aws"),
        ("104.0.0.0/8", "104.16.50.25", "cloudflare"),
        ("142.250.0.0/16", "142.250.100.50", "google"),
        ("151.101.0.0/16", "151.101.100.50", "fastly"),
        ("157.240.0.0/16", "157.240.100.50", "facebook"),
        ("172.217.0.0/16", "172.217.100.50", "google"),
    ]

    for i, (cidr, ip, provider) in enumerate(cloud_ranges):
        cases.append({
            "id": f"cidr_cloud_{i+1:03d}",
            "category": "cidr_cloud",
            "description": f"Cloud provider {provider}: {ip}",
            "input": {
                "domain": None,
                "dest_ip": ip,
                "dest_port": 443,
                "protocol": "tcp"
            },
            "rules": [{"type": "ip_cidr", "target": cidr, "outbound": f"{provider}-proxy"}],
            "expected": {"outbound": f"{provider}-proxy", "match_type": "geoip"}
        })

    # Additional IPv6 ranges
    ipv6_ranges = [
        ("2600::/12", "2600::1", "north-america"),
        ("2400::/12", "2400::1", "asia-pacific"),
        ("2800::/12", "2800::1", "latin-america"),
        ("2a00::/12", "2a00::1", "europe"),
        ("2c00::/12", "2c00::1", "africa"),
        ("2001:4860::/32", "2001:4860::1", "google-ipv6"),
        ("2606:4700::/32", "2606:4700::1", "cloudflare-ipv6"),
        ("2620:1ec::/48", "2620:1ec::1", "facebook-ipv6"),
    ]

    for i, (cidr, ip, region) in enumerate(ipv6_ranges):
        cases.append({
            "id": f"cidr_ipv6_region_{i+1:03d}",
            "category": "cidr_ipv6_region",
            "description": f"IPv6 region {region}: {ip}",
            "input": {
                "domain": None,
                "dest_ip": ip,
                "dest_port": 443,
                "protocol": "tcp"
            },
            "rules": [{"type": "ip_cidr", "target": cidr, "outbound": f"{region}-proxy"}],
            "expected": {"outbound": f"{region}-proxy", "match_type": "geoip"}
        })

    # More prefix length variations
    # Note: for /32, we must use the exact IP as the test IP
    for prefix in [8, 12, 16, 20, 24, 28, 30, 32]:
        base_ip = f"203.{prefix}.0.0"
        cidr = f"{base_ip}/{prefix}"
        # For /32, test IP must be the same as the CIDR base IP
        test_ip = base_ip if prefix == 32 else f"203.{prefix}.0.1"
        cases.append({
            "id": f"cidr_prefix_{prefix:02d}",
            "category": "cidr_prefix_variety",
            "description": f"CIDR prefix /{prefix}",
            "input": {
                "domain": None,
                "dest_ip": test_ip,
                "dest_port": 443,
                "protocol": "tcp"
            },
            "rules": [{"type": "ip_cidr", "target": cidr, "outbound": "proxy"}],
            "expected": {"outbound": "proxy", "match_type": "geoip"}
        })

    return cases


def generate_additional_domain_tests() -> list[dict[str, Any]]:
    """Generate additional domain tests to reach 500+ cases."""
    cases = []

    # Top 100 websites (sample)
    top_domains = [
        "google.com", "youtube.com", "facebook.com", "baidu.com", "wikipedia.org",
        "qq.com", "yahoo.com", "amazon.com", "twitter.com", "instagram.com",
        "linkedin.com", "reddit.com", "netflix.com", "microsoft.com", "apple.com",
        "bing.com", "office.com", "zoom.us", "tiktok.com", "pinterest.com",
        "ebay.com", "aliexpress.com", "taobao.com", "jd.com", "weibo.com",
        "sina.com.cn", "163.com", "sohu.com", "zhihu.com", "bilibili.com",
        "medium.com", "quora.com", "tumblr.com", "wordpress.com", "blogger.com",
        "dropbox.com", "icloud.com", "onedrive.com", "drive.google.com", "box.com",
        "zoom.us", "teams.microsoft.com", "meet.google.com", "webex.com", "gotomeeting.com",
        "paypal.com", "stripe.com", "square.com", "venmo.com", "cash.app",
    ]

    for i, domain in enumerate(top_domains):
        cases.append({
            "id": f"domain_top_{i+1:03d}",
            "category": "domain_top_sites",
            "description": f"Top website: {domain}",
            "input": {
                "domain": domain,
                "dest_ip": None,
                "dest_port": 443,
                "protocol": "tcp"
            },
            "rules": [{"type": "domain", "target": domain, "outbound": "proxy"}],
            "expected": {"outbound": "proxy", "match_type": "domain"}
        })

    # Subdomains of top sites
    subdomains = [
        ("www", "google.com"),
        ("mail", "google.com"),
        ("drive", "google.com"),
        ("docs", "google.com"),
        ("calendar", "google.com"),
        ("api", "github.com"),
        ("raw", "githubusercontent.com"),
        ("gist", "github.com"),
        ("cdn", "jsdelivr.net"),
        ("unpkg", "com"),
        ("m", "facebook.com"),
        ("mobile", "twitter.com"),
        ("i", "imgur.com"),
        ("static", "reddit.com"),
        ("v", "redd.it"),
    ]

    for i, (subdomain, domain) in enumerate(subdomains):
        full_domain = f"{subdomain}.{domain}"
        cases.append({
            "id": f"domain_subdomain_{i+1:03d}",
            "category": "domain_subdomains",
            "description": f"Subdomain: {full_domain}",
            "input": {
                "domain": full_domain,
                "dest_ip": None,
                "dest_port": 443,
                "protocol": "tcp"
            },
            "rules": [{"type": "domain_suffix", "target": domain, "outbound": "proxy"}],
            "expected": {"outbound": "proxy", "match_type": "domain"}
        })

    # TLD variations
    tlds = ["com", "org", "net", "io", "co", "app", "dev", "cloud", "ai", "xyz", "tech", "info"]
    for i, tld in enumerate(tlds):
        domain = f"example.{tld}"
        cases.append({
            "id": f"domain_tld_{i+1:03d}",
            "category": "domain_tlds",
            "description": f"TLD variation: .{tld}",
            "input": {
                "domain": domain,
                "dest_ip": None,
                "dest_port": 443,
                "protocol": "tcp"
            },
            "rules": [{"type": "domain_suffix", "target": f".{tld}", "outbound": "proxy"}],
            "expected": {"outbound": "proxy", "match_type": "domain"}
        })

    # Country code TLDs
    cc_tlds = ["cn", "ru", "jp", "kr", "de", "fr", "uk", "au", "br", "in", "mx", "es", "it", "nl", "se"]
    for i, cc in enumerate(cc_tlds):
        domain = f"example.{cc}"
        cases.append({
            "id": f"domain_cctld_{i+1:03d}",
            "category": "domain_cctlds",
            "description": f"Country code TLD: .{cc}",
            "input": {
                "domain": domain,
                "dest_ip": None,
                "dest_port": 443,
                "protocol": "tcp"
            },
            "rules": [{"type": "domain_suffix", "target": f".{cc}", "outbound": f"{cc}-proxy"}],
            "expected": {"outbound": f"{cc}-proxy", "match_type": "domain"}
        })

    return cases


def generate_additional_port_tests() -> list[dict[str, Any]]:
    """Generate additional port tests."""
    cases = []

    # Common service ports
    service_ports = [
        (21, "ftp"),
        (22, "ssh"),
        (23, "telnet"),
        (25, "smtp"),
        (53, "dns"),
        (67, "dhcp"),
        (68, "dhcp-client"),
        (69, "tftp"),
        (80, "http"),
        (110, "pop3"),
        (119, "nntp"),
        (123, "ntp"),
        (143, "imap"),
        (161, "snmp"),
        (162, "snmp-trap"),
        (389, "ldap"),
        (443, "https"),
        (445, "smb"),
        (465, "smtps"),
        (514, "syslog"),
        (587, "submission"),
        (636, "ldaps"),
        (993, "imaps"),
        (995, "pop3s"),
        (1433, "mssql"),
        (1521, "oracle"),
        (3306, "mysql"),
        (3389, "rdp"),
        (5432, "postgresql"),
        (5672, "amqp"),
        (6379, "redis"),
        (8080, "http-alt"),
        (8443, "https-alt"),
        (9000, "php-fpm"),
        (9090, "prometheus"),
        (27017, "mongodb"),
    ]

    for i, (port, service) in enumerate(service_ports):
        cases.append({
            "id": f"port_service_{i+1:03d}",
            "category": "port_services",
            "description": f"Service port: {service} ({port})",
            "input": {
                "domain": None,
                "dest_ip": "8.8.8.8",
                "dest_port": port,
                "protocol": "tcp"
            },
            "rules": [{"type": "port", "target": str(port), "outbound": f"{service}-proxy"}],
            "expected": {"outbound": f"{service}-proxy", "match_type": "rule"}
        })

    return cases


def generate_combined_rule_tests() -> list[dict[str, Any]]:
    """Generate tests with multiple rule types combined."""
    cases = []

    # Domain + Port combination
    cases.append({
        "id": "combined_domain_port_001",
        "category": "combined_rules",
        "description": "Domain suffix + specific port",
        "input": {
            "domain": "api.example.com",
            "dest_ip": None,
            "dest_port": 8443,
            "protocol": "tcp"
        },
        "rules": [
            {"type": "domain_suffix", "target": "example.com", "port": "8443", "outbound": "api-proxy"}
        ],
        "expected": {"outbound": "api-proxy", "match_type": "domain"}
    })

    # Multiple domain rules with different types
    cases.append({
        "id": "combined_multi_domain_001",
        "category": "combined_rules",
        "description": "Multiple domain rule types",
        "input": {
            "domain": "cdn.google.com",
            "dest_ip": None,
            "dest_port": 443,
            "protocol": "tcp"
        },
        "rules": [
            {"type": "domain_keyword", "target": "cdn", "outbound": "cdn-proxy"},
            {"type": "domain_suffix", "target": "google.com", "outbound": "google-proxy"}
        ],
        "expected": {"outbound": "cdn-proxy", "match_type": "domain"}
    })

    # IP + Protocol combination
    cases.append({
        "id": "combined_ip_protocol_001",
        "category": "combined_rules",
        "description": "IP CIDR + UDP protocol",
        "input": {
            "domain": None,
            "dest_ip": "8.8.8.8",
            "dest_port": 53,
            "protocol": "udp"
        },
        "rules": [
            {"type": "ip_cidr", "target": "8.8.8.0/24", "protocol": "udp", "outbound": "dns-proxy"}
        ],
        "expected": {"outbound": "dns-proxy", "match_type": "geoip"}
    })

    # Complex rule chain
    for i in range(20):
        cases.append({
            "id": f"combined_complex_{i+1:03d}",
            "category": "combined_complex",
            "description": f"Complex rule chain #{i+1}",
            "input": {
                "domain": f"service{i}.example.com",
                "dest_ip": f"10.0.{i}.1",
                "dest_port": 443 + i,
                "protocol": "tcp"
            },
            "rules": [
                {"type": "domain_suffix", "target": f"service{i}.example.com", "outbound": f"service{i}-proxy"},
                {"type": "ip_cidr", "target": f"10.0.{i}.0/24", "outbound": "private"},
                {"type": "port", "target": str(443 + i), "outbound": "default"}
            ],
            "expected": {"outbound": f"service{i}-proxy", "match_type": "domain"}
        })

    return cases


def generate_negative_tests() -> list[dict[str, Any]]:
    """Generate negative test cases (things that should NOT match)."""
    cases = []

    # Domain suffix boundary (should not match partial)
    boundary_tests = [
        ("google.com", "notagoogle.com"),
        ("facebook.com", "notfacebook.com"),
        ("amazon.com", "mamazon.com"),
        ("apple.com", "mapple.com"),
        ("microsoft.com", "notmicrosoft.com"),
    ]

    for i, (suffix, input_domain) in enumerate(boundary_tests):
        cases.append({
            "id": f"negative_suffix_{i+1:03d}",
            "category": "negative_suffix",
            "description": f"Should NOT match suffix: {input_domain} vs {suffix}",
            "input": {
                "domain": input_domain,
                "dest_ip": None,
                "dest_port": 443,
                "protocol": "tcp"
            },
            "rules": [{"type": "domain_suffix", "target": suffix, "outbound": "proxy"}],
            "expected": {"outbound": "direct", "match_type": None}
        })

    # CIDR outside range
    cidr_outside_tests = [
        ("10.0.0.0/8", "11.0.0.1"),
        ("172.16.0.0/12", "172.32.0.1"),
        ("192.168.0.0/16", "192.169.0.1"),
        ("8.8.8.0/24", "8.8.9.1"),
        ("1.1.1.0/24", "1.1.2.1"),
    ]

    for i, (cidr, ip) in enumerate(cidr_outside_tests):
        cases.append({
            "id": f"negative_cidr_{i+1:03d}",
            "category": "negative_cidr",
            "description": f"Should NOT match CIDR: {ip} vs {cidr}",
            "input": {
                "domain": None,
                "dest_ip": ip,
                "dest_port": 443,
                "protocol": "tcp"
            },
            "rules": [{"type": "ip_cidr", "target": cidr, "outbound": "proxy"}],
            "expected": {"outbound": "direct", "match_type": None}
        })

    # Port outside range
    port_outside_tests = [
        ("80-443", 79),
        ("80-443", 444),
        ("1000-2000", 999),
        ("1000-2000", 2001),
        ("8000-9000", 7999),
        ("8000-9000", 9001),
    ]

    for i, (port_range, port) in enumerate(port_outside_tests):
        cases.append({
            "id": f"negative_port_{i+1:03d}",
            "category": "negative_port",
            "description": f"Should NOT match port: {port} vs {port_range}",
            "input": {
                "domain": None,
                "dest_ip": "8.8.8.8",
                "dest_port": port,
                "protocol": "tcp"
            },
            "rules": [{"type": "port", "target": port_range, "outbound": "proxy"}],
            "expected": {"outbound": "direct", "match_type": None}
        })

    # Protocol mismatch
    protocol_mismatch_tests = [
        ("tcp", "udp"),
        ("udp", "tcp"),
    ]

    for i, (rule_proto, input_proto) in enumerate(protocol_mismatch_tests):
        cases.append({
            "id": f"negative_protocol_{i+1:03d}",
            "category": "negative_protocol",
            "description": f"Should NOT match protocol: {input_proto} vs {rule_proto}",
            "input": {
                "domain": None,
                "dest_ip": "8.8.8.8",
                "dest_port": 443,
                "protocol": input_proto
            },
            "rules": [{"type": "protocol", "target": rule_proto, "outbound": "proxy"}],
            "expected": {"outbound": "direct", "match_type": None}
        })

    return cases


def generate_stress_tests() -> list[dict[str, Any]]:
    """Generate stress test cases with many rules."""
    cases = []

    # Many rules, first match
    many_rules = []
    for j in range(50):
        many_rules.append({"type": "domain_suffix", "target": f"example{j}.com", "outbound": f"proxy{j}"})

    cases.append({
        "id": "stress_many_rules_first_001",
        "category": "stress_test",
        "description": "50 rules, match first",
        "input": {
            "domain": "www.example0.com",
            "dest_ip": None,
            "dest_port": 443,
            "protocol": "tcp"
        },
        "rules": many_rules,
        "expected": {"outbound": "proxy0", "match_type": "domain"}
    })

    # Many rules, match last
    cases.append({
        "id": "stress_many_rules_last_001",
        "category": "stress_test",
        "description": "50 rules, match last",
        "input": {
            "domain": "www.example49.com",
            "dest_ip": None,
            "dest_port": 443,
            "protocol": "tcp"
        },
        "rules": many_rules,
        "expected": {"outbound": "proxy49", "match_type": "domain"}
    })

    # Many rules, no match
    cases.append({
        "id": "stress_many_rules_none_001",
        "category": "stress_test",
        "description": "50 rules, no match",
        "input": {
            "domain": "www.notmatched.com",
            "dest_ip": None,
            "dest_port": 443,
            "protocol": "tcp"
        },
        "rules": many_rules,
        "expected": {"outbound": "direct", "match_type": None}
    })

    return cases


def generate_international_domain_tests() -> list[dict[str, Any]]:
    """Generate international domain test cases."""
    cases = []

    # Chinese domains
    chinese_domains = [
        "baidu.com", "qq.com", "taobao.com", "jd.com", "weibo.com",
        "163.com", "sohu.com", "sina.com.cn", "tmall.com", "alipay.com",
        "youku.com", "iqiyi.com", "douyin.com", "bilibili.com", "zhihu.com",
        "douban.com", "csdn.net", "huawei.com", "xiaomi.com", "tencent.com",
    ]

    for i, domain in enumerate(chinese_domains):
        cases.append({
            "id": f"intl_china_{i+1:03d}",
            "category": "international_china",
            "description": f"Chinese domain: {domain}",
            "input": {
                "domain": domain,
                "dest_ip": None,
                "dest_port": 443,
                "protocol": "tcp"
            },
            "rules": [{"type": "domain_suffix", "target": domain, "outbound": "cn-proxy"}],
            "expected": {"outbound": "cn-proxy", "match_type": "domain"}
        })

    # Russian domains
    russian_domains = [
        "yandex.ru", "vk.com", "mail.ru", "ok.ru", "avito.ru",
        "wildberries.ru", "ozon.ru", "tinkoff.ru", "sberbank.ru", "gazeta.ru",
    ]

    for i, domain in enumerate(russian_domains):
        cases.append({
            "id": f"intl_russia_{i+1:03d}",
            "category": "international_russia",
            "description": f"Russian domain: {domain}",
            "input": {
                "domain": domain,
                "dest_ip": None,
                "dest_port": 443,
                "protocol": "tcp"
            },
            "rules": [{"type": "domain_suffix", "target": domain, "outbound": "ru-proxy"}],
            "expected": {"outbound": "ru-proxy", "match_type": "domain"}
        })

    # Japanese domains
    japanese_domains = [
        "yahoo.co.jp", "google.co.jp", "amazon.co.jp", "rakuten.co.jp",
        "livedoor.jp", "nicovideo.jp", "pixiv.net", "dmm.com", "mercari.com",
        "line.me", "cookpad.com", "tabelog.com", "hatenablog.com", "fc2.com",
    ]

    for i, domain in enumerate(japanese_domains):
        cases.append({
            "id": f"intl_japan_{i+1:03d}",
            "category": "international_japan",
            "description": f"Japanese domain: {domain}",
            "input": {
                "domain": domain,
                "dest_ip": None,
                "dest_port": 443,
                "protocol": "tcp"
            },
            "rules": [{"type": "domain_suffix", "target": domain, "outbound": "jp-proxy"}],
            "expected": {"outbound": "jp-proxy", "match_type": "domain"}
        })

    # European domains
    european_domains = [
        "bbc.co.uk", "guardian.co.uk", "amazon.co.uk", "ebay.co.uk",
        "spiegel.de", "amazon.de", "otto.de", "bild.de", "web.de",
        "lemonde.fr", "amazon.fr", "orange.fr", "leboncoin.fr",
        "elpais.com", "elmundo.es", "amazon.es",
        "corriere.it", "amazon.it", "mediaset.it",
    ]

    for i, domain in enumerate(european_domains):
        cases.append({
            "id": f"intl_europe_{i+1:03d}",
            "category": "international_europe",
            "description": f"European domain: {domain}",
            "input": {
                "domain": domain,
                "dest_ip": None,
                "dest_port": 443,
                "protocol": "tcp"
            },
            "rules": [{"type": "domain_suffix", "target": domain, "outbound": "eu-proxy"}],
            "expected": {"outbound": "eu-proxy", "match_type": "domain"}
        })

    return cases


def generate_cdn_domain_tests() -> list[dict[str, Any]]:
    """Generate CDN domain test cases."""
    cases = []

    cdn_domains = [
        ("cloudflare.com", "cloudflare"),
        ("cloudflare-dns.com", "cloudflare"),
        ("cdnjs.cloudflare.com", "cloudflare"),
        ("akamai.net", "akamai"),
        ("akamaiedge.net", "akamai"),
        ("akamaihd.net", "akamai"),
        ("fastly.net", "fastly"),
        ("fastlylb.net", "fastly"),
        ("cloudfront.net", "cloudfront"),
        ("d1.awsstatic.com", "aws"),
        ("s3.amazonaws.com", "aws"),
        ("azureedge.net", "azure"),
        ("azurefd.net", "azure"),
        ("googleusercontent.com", "google"),
        ("ggpht.com", "google"),
        ("gstatic.com", "google"),
        ("fbcdn.net", "facebook"),
        ("fbsbx.com", "facebook"),
        ("twimg.com", "twitter"),
        ("redd.it", "reddit"),
        ("imgur.com", "imgur"),
        ("jsdelivr.net", "jsdelivr"),
        ("unpkg.com", "unpkg"),
        ("cdninstagram.com", "instagram"),
    ]

    for i, (domain, cdn) in enumerate(cdn_domains):
        cases.append({
            "id": f"cdn_{i+1:03d}",
            "category": "cdn_domains",
            "description": f"CDN domain: {cdn} - {domain}",
            "input": {
                "domain": domain,
                "dest_ip": None,
                "dest_port": 443,
                "protocol": "tcp"
            },
            "rules": [{"type": "domain_suffix", "target": domain, "outbound": f"{cdn}-cdn"}],
            "expected": {"outbound": f"{cdn}-cdn", "match_type": "domain"}
        })

    return cases


def generate_gaming_domain_tests() -> list[dict[str, Any]]:
    """Generate gaming domain test cases."""
    cases = []

    gaming_domains = [
        ("steampowered.com", "steam"),
        ("steamcommunity.com", "steam"),
        ("steamstatic.com", "steam"),
        ("epicgames.com", "epic"),
        ("unrealengine.com", "epic"),
        ("ea.com", "ea"),
        ("origin.com", "ea"),
        ("blizzard.com", "blizzard"),
        ("battle.net", "blizzard"),
        ("riotgames.com", "riot"),
        ("leagueoflegends.com", "riot"),
        ("valorant.com", "riot"),
        ("minecraft.net", "microsoft"),
        ("xbox.com", "microsoft"),
        ("playstation.com", "sony"),
        ("playstation.net", "sony"),
        ("nintendo.com", "nintendo"),
        ("nintendo.net", "nintendo"),
        ("ubisoft.com", "ubisoft"),
        ("rockstargames.com", "rockstar"),
    ]

    for i, (domain, publisher) in enumerate(gaming_domains):
        cases.append({
            "id": f"gaming_{i+1:03d}",
            "category": "gaming_domains",
            "description": f"Gaming domain: {publisher} - {domain}",
            "input": {
                "domain": domain,
                "dest_ip": None,
                "dest_port": 443,
                "protocol": "tcp"
            },
            "rules": [{"type": "domain_suffix", "target": domain, "outbound": "gaming-proxy"}],
            "expected": {"outbound": "gaming-proxy", "match_type": "domain"}
        })

    return cases


def main():
    parser = argparse.ArgumentParser(description="Generate test vectors for Rust rule engine")
    parser.add_argument(
        "--output",
        "-o",
        default="tests/fixtures/rule_test_vectors.json",
        help="Output file path"
    )
    args = parser.parse_args()

    # Generate all test cases
    all_cases = []

    print("Generating test vectors...")

    cases = generate_domain_exact_tests()
    print(f"  Domain exact: {len(cases)} cases")
    all_cases.extend(cases)

    cases = generate_domain_suffix_tests()
    print(f"  Domain suffix: {len(cases)} cases")
    all_cases.extend(cases)

    cases = generate_domain_keyword_tests()
    print(f"  Domain keyword: {len(cases)} cases")
    all_cases.extend(cases)

    cases = generate_domain_regex_tests()
    print(f"  Domain regex: {len(cases)} cases")
    all_cases.extend(cases)

    cases = generate_geoip_cidr_tests()
    print(f"  GeoIP CIDR: {len(cases)} cases")
    all_cases.extend(cases)

    cases = generate_port_tests()
    print(f"  Port: {len(cases)} cases")
    all_cases.extend(cases)

    cases = generate_protocol_tests()
    print(f"  Protocol: {len(cases)} cases")
    all_cases.extend(cases)

    cases = generate_priority_tests()
    print(f"  Priority: {len(cases)} cases")
    all_cases.extend(cases)

    cases = generate_chain_routing_tests()
    print(f"  Chain routing: {len(cases)} cases")
    all_cases.extend(cases)

    cases = generate_edge_cases()
    print(f"  Edge cases: {len(cases)} cases")
    all_cases.extend(cases)

    cases = generate_comprehensive_tests()
    print(f"  Real-world: {len(cases)} cases")
    all_cases.extend(cases)

    # Additional tests to reach 500+
    cases = generate_additional_cidr_tests()
    print(f"  Additional CIDR: {len(cases)} cases")
    all_cases.extend(cases)

    cases = generate_additional_domain_tests()
    print(f"  Additional Domain: {len(cases)} cases")
    all_cases.extend(cases)

    cases = generate_additional_port_tests()
    print(f"  Additional Port: {len(cases)} cases")
    all_cases.extend(cases)

    cases = generate_combined_rule_tests()
    print(f"  Combined rules: {len(cases)} cases")
    all_cases.extend(cases)

    cases = generate_negative_tests()
    print(f"  Negative tests: {len(cases)} cases")
    all_cases.extend(cases)

    cases = generate_stress_tests()
    print(f"  Stress tests: {len(cases)} cases")
    all_cases.extend(cases)

    cases = generate_international_domain_tests()
    print(f"  International domains: {len(cases)} cases")
    all_cases.extend(cases)

    cases = generate_cdn_domain_tests()
    print(f"  CDN domains: {len(cases)} cases")
    all_cases.extend(cases)

    cases = generate_gaming_domain_tests()
    print(f"  Gaming domains: {len(cases)} cases")
    all_cases.extend(cases)

    # Build final structure
    test_vectors = {
        "version": "1.0",
        "description": "Rule matching test vectors for Rust/Python parity testing",
        "generated_at": datetime.now(datetime.UTC).isoformat().replace("+00:00", "Z") if hasattr(datetime, "UTC") else datetime.utcnow().isoformat() + "Z",
        "total_cases": len(all_cases),
        "categories": {
            "domain_exact": sum(1 for c in all_cases if c["category"].startswith("domain_exact")),
            "domain_suffix": sum(1 for c in all_cases if c["category"].startswith("domain_suffix")),
            "domain_keyword": sum(1 for c in all_cases if c["category"].startswith("domain_keyword")),
            "domain_regex": sum(1 for c in all_cases if c["category"].startswith("domain_regex")),
            "geoip": sum(1 for c in all_cases if c["category"].startswith("geoip") or c["category"].startswith("cidr")),
            "port": sum(1 for c in all_cases if c["category"].startswith("port")),
            "protocol": sum(1 for c in all_cases if c["category"].startswith("protocol")),
            "priority": sum(1 for c in all_cases if c["category"].startswith("priority")),
            "chain_routing": sum(1 for c in all_cases if c["category"].startswith("chain")),
            "edge_case": sum(1 for c in all_cases if c["category"].startswith("edge")),
            "real_world": sum(1 for c in all_cases if c["category"].startswith("real")),
            "combined": sum(1 for c in all_cases if c["category"].startswith("combined")),
            "negative": sum(1 for c in all_cases if c["category"].startswith("negative")),
            "stress": sum(1 for c in all_cases if c["category"].startswith("stress")),
            "additional": sum(1 for c in all_cases if c["category"].startswith("domain_top") or c["category"].startswith("domain_sub") or c["category"].startswith("domain_tld") or c["category"].startswith("domain_cc")),
        },
        "test_cases": all_cases
    }

    # Write output
    with open(args.output, "w") as f:
        json.dump(test_vectors, f, indent=2)

    print(f"\nGenerated {len(all_cases)} test cases")
    print(f"Output: {args.output}")
    print("\nCategories:")
    for cat, count in test_vectors["categories"].items():
        if count > 0:
            print(f"  {cat}: {count}")


if __name__ == "__main__":
    main()

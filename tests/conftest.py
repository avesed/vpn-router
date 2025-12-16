"""
Pytest configuration and fixtures for vpn-router tests.
"""

import os
import sys
import tempfile
import sqlite3
from pathlib import Path
from typing import Generator

import pytest

# Add scripts directory to path for imports
SCRIPTS_DIR = Path(__file__).parent.parent / "scripts"
sys.path.insert(0, str(SCRIPTS_DIR))


@pytest.fixture
def temp_dir() -> Generator[Path, None, None]:
    """Create a temporary directory for test files."""
    with tempfile.TemporaryDirectory() as tmpdir:
        yield Path(tmpdir)


@pytest.fixture
def user_db_path(temp_dir: Path) -> Path:
    """Create a path for temporary user database."""
    return temp_dir / "user-config.db"


@pytest.fixture
def geodata_db_path(temp_dir: Path) -> Path:
    """Create a path for temporary geodata database."""
    return temp_dir / "geoip-geodata.db"


@pytest.fixture
def initialized_user_db(user_db_path: Path) -> Path:
    """Create and initialize a user database with schema."""
    from init_user_db import USER_DB_SCHEMA

    conn = sqlite3.connect(str(user_db_path))
    conn.executescript(USER_DB_SCHEMA)
    conn.commit()
    conn.close()
    return user_db_path


@pytest.fixture
def mock_geodata_db(geodata_db_path: Path) -> Path:
    """Create a minimal geodata database for testing."""
    conn = sqlite3.connect(str(geodata_db_path))
    cursor = conn.cursor()

    # Create minimal schema
    cursor.executescript("""
        CREATE TABLE IF NOT EXISTS countries (
            code TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            display_name TEXT,
            ipv4_count INTEGER DEFAULT 0,
            ipv6_count INTEGER DEFAULT 0,
            recommended_exit TEXT
        );

        CREATE TABLE IF NOT EXISTS ip_ranges (
            id INTEGER PRIMARY KEY,
            country_code TEXT NOT NULL,
            cidr TEXT NOT NULL,
            ip_version INTEGER NOT NULL
        );

        CREATE TABLE IF NOT EXISTS domain_categories (
            id INTEGER PRIMARY KEY,
            name TEXT NOT NULL,
            description TEXT,
            group_type TEXT,
            recommended_exit TEXT
        );

        CREATE TABLE IF NOT EXISTS domain_lists (
            id TEXT PRIMARY KEY,
            domain_count INTEGER DEFAULT 0
        );

        CREATE TABLE IF NOT EXISTS domains (
            id INTEGER PRIMARY KEY,
            list_id TEXT NOT NULL,
            domain TEXT NOT NULL,
            domain_type TEXT DEFAULT 'domain'
        );

        CREATE TABLE IF NOT EXISTS domain_list_categories (
            list_id TEXT NOT NULL,
            category_id INTEGER NOT NULL,
            PRIMARY KEY (list_id, category_id)
        );

        -- Insert test data
        INSERT INTO countries (code, name, display_name, ipv4_count, ipv6_count)
        VALUES ('us', 'United States', 'United States', 100, 10);

        INSERT INTO countries (code, name, display_name, ipv4_count, ipv6_count)
        VALUES ('cn', 'China', 'China', 50, 5);

        INSERT INTO ip_ranges (country_code, cidr, ip_version)
        VALUES ('us', '8.8.8.0/24', 4);

        INSERT INTO domain_categories (id, name, description, group_type)
        VALUES (1, 'streaming', 'Streaming services', 'media');

        INSERT INTO domain_lists (id, domain_count)
        VALUES ('netflix', 5);

        INSERT INTO domains (list_id, domain, domain_type)
        VALUES ('netflix', 'netflix.com', 'domain_suffix');
    """)

    conn.commit()
    conn.close()
    return geodata_db_path


@pytest.fixture
def sample_wireguard_config() -> dict:
    """Sample WireGuard server configuration."""
    return {
        "interface_name": "wg-test",
        "address": "10.23.0.1/24",
        "listen_port": 51820,
        "mtu": 1420,
        "private_key": "WEoxMjM0NTY3ODkwYWJjZGVmZ2hpamtsbW5vcHFycw=="
    }


@pytest.fixture
def sample_routing_rule() -> dict:
    """Sample routing rule."""
    return {
        "rule_type": "domain_suffix",
        "target": "example.com",
        "outbound": "direct",
        "tag": "test-rule",
        "priority": 100
    }


@pytest.fixture
def sample_pia_profile() -> dict:
    """Sample PIA profile."""
    return {
        "name": "us-east",
        "description": "US East Coast",
        "region_id": "us_east",
        "dns_strategy": "prefer_ipv4"
    }

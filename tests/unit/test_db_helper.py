"""
Unit tests for db_helper.py - Database operations.
"""

import pytest
from pathlib import Path


class TestUserDatabase:
    """Tests for UserDatabase class."""

    def test_get_user_stats_empty_db(self, initialized_user_db, mock_geodata_db):
        """Test getting stats from an empty database."""
        from db_helper import get_db

        db = get_db(str(mock_geodata_db), str(initialized_user_db))
        stats = db.get_user_stats()

        assert stats["routing_rules_count"] == 0
        assert stats["outbounds_count"] >= 0  # May have defaults
        assert stats["wireguard_peers_count"] == 0

    def test_add_routing_rule(self, initialized_user_db, mock_geodata_db, sample_routing_rule):
        """Test adding a routing rule."""
        from db_helper import get_db

        db = get_db(str(mock_geodata_db), str(initialized_user_db))
        rule_id = db.add_routing_rule(**sample_routing_rule)

        assert rule_id is not None
        assert rule_id > 0

        # Verify rule was added
        rules = db.get_routing_rules(enabled_only=False)
        assert len(rules) == 1
        assert rules[0]["target"] == "example.com"
        assert rules[0]["outbound"] == "direct"

    def test_add_routing_rules_batch(self, initialized_user_db, mock_geodata_db):
        """Test batch adding routing rules."""
        from db_helper import get_db

        db = get_db(str(mock_geodata_db), str(initialized_user_db))
        rules = [
            {"rule_type": "domain_suffix", "target": "google.com", "outbound": "direct", "tag": "test1", "priority": 100},
            {"rule_type": "domain_suffix", "target": "facebook.com", "outbound": "direct", "tag": "test2", "priority": 101},
            {"rule_type": "ip_cidr", "target": "8.8.8.0/24", "outbound": "direct", "tag": "test3", "priority": 102},
        ]

        count = db.add_routing_rules_batch(rules)
        assert count == 3

        all_rules = db.get_routing_rules(enabled_only=False)
        assert len(all_rules) == 3

    def test_delete_routing_rule(self, initialized_user_db, mock_geodata_db, sample_routing_rule):
        """Test deleting a routing rule."""
        from db_helper import get_db

        db = get_db(str(mock_geodata_db), str(initialized_user_db))
        rule_id = db.add_routing_rule(**sample_routing_rule)

        # Delete the rule
        result = db.delete_routing_rule(rule_id)
        assert result is True

        # Verify rule was deleted
        rules = db.get_routing_rules(enabled_only=False)
        assert len(rules) == 0

    def test_delete_nonexistent_rule(self, initialized_user_db, mock_geodata_db):
        """Test deleting a rule that doesn't exist."""
        from db_helper import get_db

        db = get_db(str(mock_geodata_db), str(initialized_user_db))
        result = db.delete_routing_rule(99999)
        assert result is False

    def test_update_routing_rule(self, initialized_user_db, mock_geodata_db, sample_routing_rule):
        """Test updating a routing rule."""
        from db_helper import get_db

        db = get_db(str(mock_geodata_db), str(initialized_user_db))
        rule_id = db.add_routing_rule(**sample_routing_rule)

        # Update the rule
        result = db.update_routing_rule(rule_id, outbound="block", priority=200)
        assert result is True

        # Verify update
        rules = db.get_routing_rules(enabled_only=False)
        assert rules[0]["outbound"] == "block"
        assert rules[0]["priority"] == 200

    def test_delete_all_routing_rules_preserve_adblock(self, initialized_user_db, mock_geodata_db):
        """Test deleting all rules while preserving adblock rules."""
        from db_helper import get_db

        db = get_db(str(mock_geodata_db), str(initialized_user_db))

        # Add regular and adblock rules
        db.add_routing_rule("domain_suffix", "example.com", "direct", "normal-rule", 100)
        db.add_routing_rule("domain_suffix", "ads.com", "block", "__adblock__test123", 101)

        # Delete all but preserve adblock
        deleted = db.delete_all_routing_rules(preserve_adblock=True)
        assert deleted == 1

        # Verify only adblock rule remains
        rules = db.get_routing_rules(enabled_only=False)
        assert len(rules) == 1
        assert rules[0]["tag"].startswith("__adblock__")


class TestGeodataDatabase:
    """Tests for GeodataDatabase class."""

    def test_get_countries(self, initialized_user_db, mock_geodata_db):
        """Test getting countries from geodata database."""
        from db_helper import get_db

        db = get_db(str(mock_geodata_db), str(initialized_user_db))
        countries = db.get_countries()

        assert len(countries) == 2
        country_codes = [c["code"] for c in countries]
        assert "us" in country_codes
        assert "cn" in country_codes

    def test_get_country(self, initialized_user_db, mock_geodata_db):
        """Test getting a specific country."""
        from db_helper import get_db

        db = get_db(str(mock_geodata_db), str(initialized_user_db))
        country = db.get_country("us")

        assert country is not None
        assert country["code"] == "us"
        assert country["name"] == "United States"

    def test_get_country_not_found(self, initialized_user_db, mock_geodata_db):
        """Test getting a country that doesn't exist."""
        from db_helper import get_db

        db = get_db(str(mock_geodata_db), str(initialized_user_db))
        country = db.get_country("xyz")

        assert country is None

    def test_get_ip_ranges(self, initialized_user_db, mock_geodata_db):
        """Test getting IP ranges for a country."""
        from db_helper import get_db

        db = get_db(str(mock_geodata_db), str(initialized_user_db))
        ranges = db.get_ip_ranges("us")

        assert len(ranges) == 1
        assert ranges[0] == "8.8.8.0/24"

    def test_get_geodata_stats(self, initialized_user_db, mock_geodata_db):
        """Test getting geodata statistics."""
        from db_helper import get_db

        db = get_db(str(mock_geodata_db), str(initialized_user_db))
        stats = db.get_geodata_stats()

        assert stats["countries_count"] == 2
        assert stats["ip_ranges_count"] == 1


class TestWireGuardOperations:
    """Tests for WireGuard server and peer operations."""

    def test_set_and_get_wireguard_server(self, initialized_user_db, mock_geodata_db, sample_wireguard_config):
        """Test setting and getting WireGuard server config."""
        from db_helper import get_db

        db = get_db(str(mock_geodata_db), str(initialized_user_db))
        db.set_wireguard_server(**sample_wireguard_config)

        server = db.get_wireguard_server()
        assert server is not None
        assert server["interface_name"] == "wg-test"
        assert server["listen_port"] == 51820

    def test_add_wireguard_peer(self, initialized_user_db, mock_geodata_db):
        """Test adding a WireGuard peer."""
        from db_helper import get_db

        db = get_db(str(mock_geodata_db), str(initialized_user_db))
        peer_id = db.add_wireguard_peer(
            name="test-client",
            public_key="dGVzdHB1YmxpY2tleWJhc2U2NGVuY29kZWQ=",
            allowed_ips="10.23.0.2/32"
        )

        assert peer_id is not None
        peers = db.get_wireguard_peers()
        assert len(peers) == 1
        assert peers[0]["name"] == "test-client"

    def test_add_wireguard_peer_with_lan_access(self, initialized_user_db, mock_geodata_db):
        """Test adding a WireGuard peer with LAN access enabled."""
        from db_helper import get_db

        db = get_db(str(mock_geodata_db), str(initialized_user_db))
        peer_id = db.add_wireguard_peer(
            name="lan-client",
            public_key="dGVzdHB1YmxpY2tleWJhc2U2NGVuY29kZWQ=",
            allowed_ips="10.23.0.3/32",
            allow_lan=True,
            lan_subnet="192.168.1.0/24"
        )

        peers = db.get_wireguard_peers()
        lan_peer = next(p for p in peers if p["name"] == "lan-client")
        assert lan_peer["allow_lan"] == 1
        assert lan_peer["lan_subnet"] == "192.168.1.0/24"

    def test_delete_wireguard_peer(self, initialized_user_db, mock_geodata_db):
        """Test deleting a WireGuard peer."""
        from db_helper import get_db

        db = get_db(str(mock_geodata_db), str(initialized_user_db))
        peer_id = db.add_wireguard_peer(
            name="to-delete",
            public_key="dGVzdHB1YmxpY2tleWJhc2U2NGVuY29kZWQ=",
            allowed_ips="10.23.0.4/32"
        )

        result = db.delete_wireguard_peer(peer_id)
        assert result is True

        peers = db.get_wireguard_peers()
        assert len(peers) == 0


class TestPIAProfiles:
    """Tests for PIA profile operations."""

    def test_add_pia_profile(self, initialized_user_db, mock_geodata_db, sample_pia_profile):
        """Test adding a PIA profile."""
        from db_helper import get_db

        db = get_db(str(mock_geodata_db), str(initialized_user_db))
        profile_id = db.add_pia_profile(**sample_pia_profile)

        assert profile_id is not None
        profiles = db.get_pia_profiles()
        assert len(profiles) >= 1

    def test_update_pia_profile_credentials(self, initialized_user_db, mock_geodata_db, sample_pia_profile):
        """Test updating PIA profile with WireGuard credentials."""
        from db_helper import get_db

        db = get_db(str(mock_geodata_db), str(initialized_user_db))
        profile_id = db.add_pia_profile(**sample_pia_profile)

        # Update with credentials
        result = db.update_pia_profile(
            profile_id,
            server_ip="10.0.0.1",
            server_port=1337,
            private_key="dGVzdHByaXZhdGVrZXk=",
            public_key="dGVzdHB1YmxpY2tleQ==",
            address="10.1.0.2/32"
        )
        assert result is True

        profiles = db.get_pia_profiles()
        updated = next(p for p in profiles if p["id"] == profile_id)
        assert updated["server_ip"] == "10.0.0.1"


class TestCustomEgress:
    """Tests for custom egress operations."""

    def test_add_custom_egress(self, initialized_user_db, mock_geodata_db):
        """Test adding a custom WireGuard egress."""
        from db_helper import get_db

        db = get_db(str(mock_geodata_db), str(initialized_user_db))
        egress_id = db.add_custom_egress(
            tag="my-vpn",
            description="My Custom VPN",
            server="vpn.example.com",
            port=51820,
            private_key="dGVzdHByaXZhdGVrZXk=",
            public_key="dGVzdHB1YmxpY2tleQ==",
            address="10.0.0.2/32"
        )

        assert egress_id is not None
        egress_list = db.get_custom_egress_list()
        assert len(egress_list) == 1
        assert egress_list[0]["tag"] == "my-vpn"

    def test_delete_custom_egress(self, initialized_user_db, mock_geodata_db):
        """Test deleting a custom egress."""
        from db_helper import get_db

        db = get_db(str(mock_geodata_db), str(initialized_user_db))
        db.add_custom_egress(
            tag="to-delete",
            description="Delete me",
            server="vpn.example.com",
            port=51820,
            private_key="dGVzdHByaXZhdGVrZXk=",
            public_key="dGVzdHB1YmxpY2tleQ==",
            address="10.0.0.3/32"
        )

        result = db.delete_custom_egress("to-delete")
        assert result is True

        egress_list = db.get_custom_egress_list()
        assert len(egress_list) == 0


class TestDirectEgress:
    """Tests for direct egress operations."""

    def test_add_direct_egress_with_interface(self, initialized_user_db, mock_geodata_db):
        """Test adding a direct egress with interface binding."""
        from db_helper import get_db

        db = get_db(str(mock_geodata_db), str(initialized_user_db))
        egress_id = db.add_direct_egress(
            tag="direct-eth1",
            description="WAN1 exit",
            bind_interface="eth1"
        )

        assert egress_id is not None
        egress_list = db.get_direct_egress_list()
        assert len(egress_list) == 1
        assert egress_list[0]["bind_interface"] == "eth1"

    def test_add_direct_egress_with_ip(self, initialized_user_db, mock_geodata_db):
        """Test adding a direct egress with IP binding."""
        from db_helper import get_db

        db = get_db(str(mock_geodata_db), str(initialized_user_db))
        egress_id = db.add_direct_egress(
            tag="direct-wan2",
            description="Secondary WAN",
            inet4_bind_address="192.168.2.100"
        )

        assert egress_id is not None
        egress_list = db.get_direct_egress_list()
        assert len(egress_list) == 1
        assert egress_list[0]["inet4_bind_address"] == "192.168.2.100"

    def test_delete_direct_egress(self, initialized_user_db, mock_geodata_db):
        """Test deleting a direct egress."""
        from db_helper import get_db

        db = get_db(str(mock_geodata_db), str(initialized_user_db))
        db.add_direct_egress(tag="to-delete", bind_interface="eth2")

        result = db.delete_direct_egress("to-delete")
        assert result is True

        egress_list = db.get_direct_egress_list()
        assert len(egress_list) == 0


class TestSettings:
    """Tests for settings operations."""

    def test_get_setting_default(self, initialized_user_db, mock_geodata_db):
        """Test getting a setting with default value."""
        from db_helper import get_db

        db = get_db(str(mock_geodata_db), str(initialized_user_db))
        value = db.get_setting("nonexistent", "default_value")
        assert value == "default_value"

    def test_set_and_get_setting(self, initialized_user_db, mock_geodata_db):
        """Test setting and getting a setting."""
        from db_helper import get_db

        db = get_db(str(mock_geodata_db), str(initialized_user_db))
        db.set_setting("test_key", "test_value")

        value = db.get_setting("test_key")
        assert value == "test_value"

    def test_update_setting(self, initialized_user_db, mock_geodata_db):
        """Test updating an existing setting."""
        from db_helper import get_db

        db = get_db(str(mock_geodata_db), str(initialized_user_db))
        db.set_setting("update_key", "old_value")
        db.set_setting("update_key", "new_value")

        value = db.get_setting("update_key")
        assert value == "new_value"

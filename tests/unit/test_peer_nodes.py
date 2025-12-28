"""
Unit tests for Peer Node Management (Phase 1) - Database and API layer.
"""

import json
import pytest
import sqlite3
from pathlib import Path
from typing import Generator


@pytest.fixture(autouse=True)
def reset_db_singleton():
    """Reset the db_helper singleton between tests."""
    import db_helper
    db_helper._db_manager = None
    yield
    db_helper._db_manager = None


@pytest.fixture
def initialized_user_db_with_peer_tables(temp_dir: Path) -> Path:
    """Create and initialize a user database with peer_nodes and node_chains tables."""
    from init_user_db import USER_DB_SCHEMA

    db_path = temp_dir / "user-config.db"
    conn = sqlite3.connect(str(db_path))
    conn.executescript(USER_DB_SCHEMA)
    conn.commit()
    conn.close()
    return db_path


@pytest.fixture
def sample_peer_node() -> dict:
    """Sample peer node configuration."""
    return {
        "tag": "node-tokyo",
        "name": "Tokyo Node",
        "description": "Tokyo relay server",
        "endpoint": "tokyo.example.com:36200",
        "psk_hash": "$2b$12$examplehashexamplehashexamplehashexamplehash",
        "tunnel_type": "wireguard",
        "auto_reconnect": True,
        "enabled": True,
    }


@pytest.fixture
def sample_node_chain() -> dict:
    """Sample node chain configuration."""
    return {
        "tag": "us-via-tokyo",
        "name": "US via Tokyo",
        "description": "Route to US through Tokyo",
        "hops": ["node-tokyo", "node-us"],
        "priority": 100,
        "enabled": True,
    }


class TestPeerNodesDatabaseSchema:
    """Tests for peer_nodes and node_chains table schema."""

    def test_peer_nodes_table_exists(self, initialized_user_db_with_peer_tables):
        """Verify peer_nodes table is created with correct columns."""
        conn = sqlite3.connect(str(initialized_user_db_with_peer_tables))
        cursor = conn.cursor()

        cursor.execute("PRAGMA table_info(peer_nodes)")
        columns = {row[1]: row[2] for row in cursor.fetchall()}

        # Check required columns exist
        expected_columns = [
            "id", "tag", "name", "description", "endpoint", "psk_hash",
            "tunnel_type", "tunnel_status", "tunnel_interface",
            "tunnel_local_ip", "tunnel_remote_ip", "tunnel_port",
            "wg_private_key", "wg_public_key", "wg_peer_public_key",
            "xray_protocol", "xray_uuid", "xray_socks_port",
            "default_outbound", "last_seen", "last_error",
            "auto_reconnect", "enabled", "created_at", "updated_at"
        ]

        for col in expected_columns:
            assert col in columns, f"Column '{col}' missing from peer_nodes table"

        conn.close()

    def test_node_chains_table_exists(self, initialized_user_db_with_peer_tables):
        """Verify node_chains table is created with correct columns."""
        conn = sqlite3.connect(str(initialized_user_db_with_peer_tables))
        cursor = conn.cursor()

        cursor.execute("PRAGMA table_info(node_chains)")
        columns = {row[1]: row[2] for row in cursor.fetchall()}

        expected_columns = [
            "id", "tag", "name", "description", "hops", "hop_protocols",
            "entry_rules", "relay_rules", "health_status", "last_health_check",
            "enabled", "priority", "created_at", "updated_at"
        ]

        for col in expected_columns:
            assert col in columns, f"Column '{col}' missing from node_chains table"

        conn.close()

    def test_peer_nodes_unique_constraints(self, initialized_user_db_with_peer_tables):
        """Verify UNIQUE constraints on peer_nodes table."""
        conn = sqlite3.connect(str(initialized_user_db_with_peer_tables))
        cursor = conn.cursor()

        # Check for unique indexes
        cursor.execute("SELECT name, sql FROM sqlite_master WHERE type='index' AND tbl_name='peer_nodes'")
        indexes = cursor.fetchall()
        index_names = [idx[0] for idx in indexes if idx[0]]

        # Should have unique index on tunnel_local_ip
        assert "idx_peer_nodes_tunnel_local_ip" in index_names
        # Should have unique index on tunnel_port
        assert "idx_peer_nodes_tunnel_port" in index_names
        # Should have unique index on xray_socks_port
        assert "idx_peer_nodes_xray_socks_port" in index_names

        conn.close()

    def test_tag_uniqueness_enforced(self, initialized_user_db_with_peer_tables):
        """Test that duplicate tags are rejected."""
        conn = sqlite3.connect(str(initialized_user_db_with_peer_tables))
        cursor = conn.cursor()

        # Insert first node
        cursor.execute("""
            INSERT INTO peer_nodes (tag, name, endpoint, psk_hash)
            VALUES ('node-test', 'Test Node', 'test.example.com:36200', 'hash123')
        """)
        conn.commit()

        # Try to insert duplicate tag
        with pytest.raises(sqlite3.IntegrityError):
            cursor.execute("""
                INSERT INTO peer_nodes (tag, name, endpoint, psk_hash)
                VALUES ('node-test', 'Duplicate Node', 'test2.example.com:36200', 'hash456')
            """)

        conn.close()


class TestPeerNodeCRUD:
    """Tests for peer node CRUD operations via db_helper."""

    def test_add_peer_node(self, initialized_user_db_with_peer_tables, mock_geodata_db):
        """Test adding a peer node."""
        from db_helper import get_db

        db = get_db(str(mock_geodata_db), str(initialized_user_db_with_peer_tables))

        node_id = db.add_peer_node(
            tag="node-tokyo",
            name="Tokyo Node",
            endpoint="tokyo.example.com:36200",
            psk_hash="$2b$12$examplehash",
            tunnel_type="wireguard",
        )

        assert node_id is not None
        assert node_id > 0

    def test_get_peer_node(self, initialized_user_db_with_peer_tables, mock_geodata_db):
        """Test getting a peer node by tag."""
        from db_helper import get_db

        db = get_db(str(mock_geodata_db), str(initialized_user_db_with_peer_tables))

        db.add_peer_node(
            tag="node-tokyo",
            name="Tokyo Node",
            endpoint="tokyo.example.com:36200",
            psk_hash="$2b$12$examplehash",
        )

        node = db.get_peer_node("node-tokyo")
        assert node is not None
        assert node["tag"] == "node-tokyo"
        assert node["name"] == "Tokyo Node"
        assert node["endpoint"] == "tokyo.example.com:36200"

    def test_get_peer_node_not_found(self, initialized_user_db_with_peer_tables, mock_geodata_db):
        """Test getting a non-existent peer node."""
        from db_helper import get_db

        db = get_db(str(mock_geodata_db), str(initialized_user_db_with_peer_tables))

        node = db.get_peer_node("nonexistent")
        assert node is None

    def test_get_peer_nodes(self, initialized_user_db_with_peer_tables, mock_geodata_db):
        """Test getting all peer nodes."""
        from db_helper import get_db

        db = get_db(str(mock_geodata_db), str(initialized_user_db_with_peer_tables))

        # Add multiple nodes
        db.add_peer_node(
            tag="node-tokyo",
            name="Tokyo Node",
            endpoint="tokyo.example.com:36200",
            psk_hash="hash1",
            enabled=True,
        )
        db.add_peer_node(
            tag="node-us",
            name="US Node",
            endpoint="us.example.com:36201",
            psk_hash="hash2",
            enabled=False,
        )

        # Get all nodes
        all_nodes = db.get_peer_nodes()
        assert len(all_nodes) == 2

        # Get only enabled nodes
        enabled_nodes = db.get_peer_nodes(enabled_only=True)
        assert len(enabled_nodes) == 1
        assert enabled_nodes[0]["tag"] == "node-tokyo"

    def test_update_peer_node(self, initialized_user_db_with_peer_tables, mock_geodata_db):
        """Test updating a peer node."""
        from db_helper import get_db

        db = get_db(str(mock_geodata_db), str(initialized_user_db_with_peer_tables))

        db.add_peer_node(
            tag="node-tokyo",
            name="Tokyo Node",
            endpoint="tokyo.example.com:36200",
            psk_hash="hash1",
        )

        # Update the node
        success = db.update_peer_node(
            "node-tokyo",
            name="Tokyo Server (Updated)",
            tunnel_status="connected",
            tunnel_local_ip="10.200.200.1",
            tunnel_remote_ip="10.200.200.2",
        )

        assert success is True

        # Verify update
        node = db.get_peer_node("node-tokyo")
        assert node["name"] == "Tokyo Server (Updated)"
        assert node["tunnel_status"] == "connected"
        assert node["tunnel_local_ip"] == "10.200.200.1"

    def test_update_peer_node_not_found(self, initialized_user_db_with_peer_tables, mock_geodata_db):
        """Test updating a non-existent peer node."""
        from db_helper import get_db

        db = get_db(str(mock_geodata_db), str(initialized_user_db_with_peer_tables))

        success = db.update_peer_node("nonexistent", name="New Name")
        assert success is False

    def test_delete_peer_node(self, initialized_user_db_with_peer_tables, mock_geodata_db):
        """Test deleting a peer node."""
        from db_helper import get_db

        db = get_db(str(mock_geodata_db), str(initialized_user_db_with_peer_tables))

        db.add_peer_node(
            tag="node-delete",
            name="Delete Me",
            endpoint="delete.example.com:36200",
            psk_hash="hash1",
        )

        success = db.delete_peer_node("node-delete")
        assert success is True

        # Verify deletion
        node = db.get_peer_node("node-delete")
        assert node is None

    def test_delete_peer_node_not_found(self, initialized_user_db_with_peer_tables, mock_geodata_db):
        """Test deleting a non-existent peer node."""
        from db_helper import get_db

        db = get_db(str(mock_geodata_db), str(initialized_user_db_with_peer_tables))

        success = db.delete_peer_node("nonexistent")
        assert success is False

    def test_get_connected_peer_nodes(self, initialized_user_db_with_peer_tables, mock_geodata_db):
        """Test getting connected peer nodes."""
        from db_helper import get_db

        db = get_db(str(mock_geodata_db), str(initialized_user_db_with_peer_tables))

        # Add nodes with different statuses
        db.add_peer_node(
            tag="node-connected",
            name="Connected Node",
            endpoint="connected.example.com:36200",
            psk_hash="hash1",
        )
        db.update_peer_node("node-connected", tunnel_status="connected")

        db.add_peer_node(
            tag="node-disconnected",
            name="Disconnected Node",
            endpoint="disconnected.example.com:36201",
            psk_hash="hash2",
        )

        connected = db.get_connected_peer_nodes()
        assert len(connected) == 1
        assert connected[0]["tag"] == "node-connected"


class TestPeerNodePortAllocation:
    """Tests for port allocation methods."""

    def test_get_next_peer_tunnel_port_initial(self, initialized_user_db_with_peer_tables, mock_geodata_db):
        """Test initial tunnel port allocation starts at 36200."""
        from db_helper import get_db

        db = get_db(str(mock_geodata_db), str(initialized_user_db_with_peer_tables))

        port = db.get_next_peer_tunnel_port()
        assert port == 36200

    def test_get_next_peer_tunnel_port_increments(self, initialized_user_db_with_peer_tables, mock_geodata_db):
        """Test tunnel port allocation increments correctly."""
        from db_helper import get_db

        db = get_db(str(mock_geodata_db), str(initialized_user_db_with_peer_tables))

        # Add a node with port 36200
        db.add_peer_node(
            tag="node-1",
            name="Node 1",
            endpoint="node1.example.com:36200",
            psk_hash="hash1",
            tunnel_port=36200,
        )

        # Next port should be 36201
        port = db.get_next_peer_tunnel_port()
        assert port == 36201

    def test_get_next_peer_xray_socks_port_initial(self, initialized_user_db_with_peer_tables, mock_geodata_db):
        """Test initial SOCKS port allocation starts at 37201."""
        from db_helper import get_db

        db = get_db(str(mock_geodata_db), str(initialized_user_db_with_peer_tables))

        port = db.get_next_peer_xray_socks_port()
        assert port == 37201

    def test_get_next_peer_xray_socks_port_increments(self, initialized_user_db_with_peer_tables, mock_geodata_db):
        """Test SOCKS port allocation increments correctly."""
        from db_helper import get_db

        db = get_db(str(mock_geodata_db), str(initialized_user_db_with_peer_tables))

        # Add a node with SOCKS port 37201
        node_id = db.add_peer_node(
            tag="node-1",
            name="Node 1",
            endpoint="node1.example.com:36200",
            psk_hash="hash1",
        )
        db.update_peer_node("node-1", xray_socks_port=37201)

        # Next port should be 37202
        port = db.get_next_peer_xray_socks_port()
        assert port == 37202


class TestNodeChainCRUD:
    """Tests for node chain CRUD operations via db_helper."""

    def test_add_node_chain(self, initialized_user_db_with_peer_tables, mock_geodata_db):
        """Test adding a node chain."""
        from db_helper import get_db

        db = get_db(str(mock_geodata_db), str(initialized_user_db_with_peer_tables))

        # First add the peer nodes that will be in the chain
        db.add_peer_node(
            tag="node-tokyo",
            name="Tokyo Node",
            endpoint="tokyo.example.com:36200",
            psk_hash="hash1",
        )
        db.add_peer_node(
            tag="node-us",
            name="US Node",
            endpoint="us.example.com:36201",
            psk_hash="hash2",
        )

        chain_id = db.add_node_chain(
            tag="us-via-tokyo",
            name="US via Tokyo",
            hops=["node-tokyo", "node-us"],
            description="Route to US through Tokyo",
            priority=100,
        )

        assert chain_id is not None
        assert chain_id > 0

    def test_get_node_chain(self, initialized_user_db_with_peer_tables, mock_geodata_db):
        """Test getting a node chain by tag."""
        from db_helper import get_db

        db = get_db(str(mock_geodata_db), str(initialized_user_db_with_peer_tables))

        db.add_node_chain(
            tag="chain-test",
            name="Test Chain",
            hops=["node-a", "node-b"],
        )

        chain = db.get_node_chain("chain-test")
        assert chain is not None
        assert chain["tag"] == "chain-test"
        assert chain["name"] == "Test Chain"
        assert chain["hops"] == ["node-a", "node-b"]

    def test_get_node_chain_not_found(self, initialized_user_db_with_peer_tables, mock_geodata_db):
        """Test getting a non-existent node chain."""
        from db_helper import get_db

        db = get_db(str(mock_geodata_db), str(initialized_user_db_with_peer_tables))

        chain = db.get_node_chain("nonexistent")
        assert chain is None

    def test_get_node_chains(self, initialized_user_db_with_peer_tables, mock_geodata_db):
        """Test getting all node chains."""
        from db_helper import get_db

        db = get_db(str(mock_geodata_db), str(initialized_user_db_with_peer_tables))

        db.add_node_chain(
            tag="chain-1",
            name="Chain 1",
            hops=["node-a"],
            enabled=True,
        )
        db.add_node_chain(
            tag="chain-2",
            name="Chain 2",
            hops=["node-b"],
            enabled=False,
        )

        # Get all chains
        all_chains = db.get_node_chains()
        assert len(all_chains) == 2

        # Get only enabled chains
        enabled_chains = db.get_node_chains(enabled_only=True)
        assert len(enabled_chains) == 1
        assert enabled_chains[0]["tag"] == "chain-1"

    def test_update_node_chain(self, initialized_user_db_with_peer_tables, mock_geodata_db):
        """Test updating a node chain."""
        from db_helper import get_db

        db = get_db(str(mock_geodata_db), str(initialized_user_db_with_peer_tables))

        db.add_node_chain(
            tag="chain-update",
            name="Original Name",
            hops=["node-a"],
        )

        success = db.update_node_chain(
            "chain-update",
            name="Updated Name",
            hops=["node-a", "node-b", "node-c"],
            health_status="healthy",
        )

        assert success is True

        chain = db.get_node_chain("chain-update")
        assert chain["name"] == "Updated Name"
        assert chain["hops"] == ["node-a", "node-b", "node-c"]
        assert chain["health_status"] == "healthy"

    def test_delete_node_chain(self, initialized_user_db_with_peer_tables, mock_geodata_db):
        """Test deleting a node chain."""
        from db_helper import get_db

        db = get_db(str(mock_geodata_db), str(initialized_user_db_with_peer_tables))

        db.add_node_chain(
            tag="chain-delete",
            name="Delete Me",
            hops=["node-a"],
        )

        success = db.delete_node_chain("chain-delete")
        assert success is True

        chain = db.get_node_chain("chain-delete")
        assert chain is None

    def test_validate_chain_hops_valid(self, initialized_user_db_with_peer_tables, mock_geodata_db):
        """Test validating chain hops with existing nodes."""
        from db_helper import get_db

        db = get_db(str(mock_geodata_db), str(initialized_user_db_with_peer_tables))

        # Add the nodes first
        db.add_peer_node(
            tag="node-a",
            name="Node A",
            endpoint="a.example.com:36200",
            psk_hash="hash1",
        )
        db.add_peer_node(
            tag="node-b",
            name="Node B",
            endpoint="b.example.com:36201",
            psk_hash="hash2",
        )

        is_valid, missing = db.validate_chain_hops(["node-a", "node-b"])
        assert is_valid is True
        assert len(missing) == 0

    def test_validate_chain_hops_invalid(self, initialized_user_db_with_peer_tables, mock_geodata_db):
        """Test validating chain hops with missing nodes."""
        from db_helper import get_db

        db = get_db(str(mock_geodata_db), str(initialized_user_db_with_peer_tables))

        # Only add one node
        db.add_peer_node(
            tag="node-a",
            name="Node A",
            endpoint="a.example.com:36200",
            psk_hash="hash1",
        )

        is_valid, missing = db.validate_chain_hops(["node-a", "node-b", "node-c"])
        assert is_valid is False
        assert "node-b" in missing
        assert "node-c" in missing

    def test_validate_chain_hops_empty(self, initialized_user_db_with_peer_tables, mock_geodata_db):
        """Test validating empty chain hops."""
        from db_helper import get_db

        db = get_db(str(mock_geodata_db), str(initialized_user_db_with_peer_tables))

        is_valid, missing = db.validate_chain_hops([])
        assert is_valid is False


class TestPeerNodeWithXrayConfig:
    """Tests for peer nodes with Xray configuration."""

    def test_add_peer_node_with_xray(self, initialized_user_db_with_peer_tables, mock_geodata_db):
        """Test adding a peer node with Xray tunnel type."""
        from db_helper import get_db

        db = get_db(str(mock_geodata_db), str(initialized_user_db_with_peer_tables))

        node_id = db.add_peer_node(
            tag="node-xray",
            name="Xray Node",
            endpoint="xray.example.com:443",
            psk_hash="hash1",
            tunnel_type="xray",
            xray_protocol="vless",
        )

        assert node_id is not None

        node = db.get_peer_node("node-xray")
        assert node["tunnel_type"] == "xray"
        assert node["xray_protocol"] == "vless"

    def test_update_peer_node_xray_config(self, initialized_user_db_with_peer_tables, mock_geodata_db):
        """Test updating Xray configuration on a peer node."""
        from db_helper import get_db

        db = get_db(str(mock_geodata_db), str(initialized_user_db_with_peer_tables))

        db.add_peer_node(
            tag="node-xray",
            name="Xray Node",
            endpoint="xray.example.com:443",
            psk_hash="hash1",
            tunnel_type="xray",
        )

        success = db.update_peer_node(
            "node-xray",
            xray_uuid="test-uuid-12345",
            xray_socks_port=37201,
        )

        assert success is True

        node = db.get_peer_node("node-xray")
        assert node["xray_uuid"] == "test-uuid-12345"
        assert node["xray_socks_port"] == 37201


class TestPeerNodeWithWireGuardConfig:
    """Tests for peer nodes with WireGuard configuration."""

    def test_add_peer_node_with_wireguard(self, initialized_user_db_with_peer_tables, mock_geodata_db):
        """Test adding a peer node with WireGuard configuration."""
        from db_helper import get_db

        db = get_db(str(mock_geodata_db), str(initialized_user_db_with_peer_tables))

        node_id = db.add_peer_node(
            tag="node-wg",
            name="WireGuard Node",
            endpoint="wg.example.com:36200",
            psk_hash="hash1",
            tunnel_type="wireguard",
            wg_private_key="test-private-key",
            wg_public_key="test-public-key",
        )

        assert node_id is not None

        node = db.get_peer_node("node-wg")
        assert node["tunnel_type"] == "wireguard"
        assert node["wg_private_key"] == "test-private-key"
        assert node["wg_public_key"] == "test-public-key"

    def test_update_peer_node_wireguard_keys(self, initialized_user_db_with_peer_tables, mock_geodata_db):
        """Test updating WireGuard keys on a peer node."""
        from db_helper import get_db

        db = get_db(str(mock_geodata_db), str(initialized_user_db_with_peer_tables))

        db.add_peer_node(
            tag="node-wg",
            name="WireGuard Node",
            endpoint="wg.example.com:36200",
            psk_hash="hash1",
            tunnel_type="wireguard",
        )

        success = db.update_peer_node(
            "node-wg",
            wg_private_key="new-private-key",
            wg_public_key="new-public-key",
            wg_peer_public_key="peer-public-key",
            tunnel_port=36200,
            tunnel_local_ip="10.200.200.1",
            tunnel_remote_ip="10.200.200.2",
        )

        assert success is True

        node = db.get_peer_node("node-wg")
        assert node["wg_private_key"] == "new-private-key"
        assert node["wg_peer_public_key"] == "peer-public-key"
        assert node["tunnel_port"] == 36200


class TestNodeChainWithHopProtocols:
    """Tests for node chains with hop protocols configuration."""

    def test_add_node_chain_with_hop_protocols(self, initialized_user_db_with_peer_tables, mock_geodata_db):
        """Test adding a node chain with hop protocols."""
        from db_helper import get_db

        db = get_db(str(mock_geodata_db), str(initialized_user_db_with_peer_tables))

        chain_id = db.add_node_chain(
            tag="chain-mixed",
            name="Mixed Protocol Chain",
            hops=["node-tokyo", "node-us"],
            hop_protocols={
                "node-tokyo": "wireguard",
                "node-us": "xray",
            },
        )

        assert chain_id is not None

        chain = db.get_node_chain("chain-mixed")
        assert chain["hop_protocols"]["node-tokyo"] == "wireguard"
        assert chain["hop_protocols"]["node-us"] == "xray"

    def test_add_node_chain_with_entry_rules(self, initialized_user_db_with_peer_tables, mock_geodata_db):
        """Test adding a node chain with entry rules."""
        from db_helper import get_db

        db = get_db(str(mock_geodata_db), str(initialized_user_db_with_peer_tables))

        entry_rules = {
            "domain_suffix": ["google.com", "youtube.com"],
            "geoip": ["us"],
        }

        chain_id = db.add_node_chain(
            tag="chain-rules",
            name="Chain with Rules",
            hops=["node-us"],
            entry_rules=entry_rules,
        )

        assert chain_id is not None

        chain = db.get_node_chain("chain-rules")
        assert chain["entry_rules"]["domain_suffix"] == ["google.com", "youtube.com"]
        assert chain["entry_rules"]["geoip"] == ["us"]

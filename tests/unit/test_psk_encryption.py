"""
Unit tests for PSK encryption/decryption (CR-001 fix).

Tests the secure storage and retrieval of Pre-Shared Keys using
Fernet symmetric encryption with the deployment key.
"""

import pytest
import sys
from pathlib import Path

# Add scripts directory to path
SCRIPTS_DIR = Path(__file__).parent.parent.parent / "scripts"
sys.path.insert(0, str(SCRIPTS_DIR))


class TestPSKEncryption:
    """Tests for PSK encryption functionality."""

    @pytest.fixture
    def key_manager(self, temp_dir):
        """Create a KeyManager with a temporary key file."""
        from key_manager import KeyManager

        key_path = temp_dir / ".test-key"
        km = KeyManager(key_path=str(key_path))
        return km

    def test_encrypt_decrypt_roundtrip(self, key_manager):
        """Test that encrypting then decrypting returns the original value."""
        original_psk = "my-super-secret-psk-12345"

        key = key_manager.get_or_create_key()
        encrypted = key_manager.encrypt_with_key(original_psk, key)
        decrypted = key_manager.decrypt_with_key(encrypted, key)

        assert decrypted == original_psk

    def test_encrypted_format_is_base64(self, key_manager):
        """Test that encrypted value is valid base64 format."""
        import base64

        key = key_manager.get_or_create_key()
        encrypted = key_manager.encrypt_with_key("test-psk", key)

        # Should be valid base64
        try:
            decoded = base64.urlsafe_b64decode(encrypted)
            is_valid_base64 = True
        except Exception:
            is_valid_base64 = False

        assert is_valid_base64

    def test_encrypted_value_differs_from_original(self, key_manager):
        """Test that encrypted value is different from the plaintext."""
        psk = "test-psk-value"

        key = key_manager.get_or_create_key()
        encrypted = key_manager.encrypt_with_key(psk, key)

        # Encrypted should not be the same as original
        assert encrypted != psk
        # Encrypted should be longer (due to Fernet overhead)
        assert len(encrypted) > len(psk)

    def test_different_encryptions_produce_different_ciphertexts(self, key_manager):
        """Test that same plaintext produces different ciphertexts (IV randomness)."""
        psk = "same-psk-value"

        key = key_manager.get_or_create_key()
        encrypted1 = key_manager.encrypt_with_key(psk, key)
        encrypted2 = key_manager.encrypt_with_key(psk, key)

        # Fernet includes random IV, so encryptions should differ
        assert encrypted1 != encrypted2

    def test_decrypt_with_wrong_key_fails(self, temp_dir):
        """Test that decrypting with wrong key fails."""
        from key_manager import KeyManager
        from cryptography.fernet import InvalidToken

        # Create two separate key managers with different keys
        km1 = KeyManager(key_path=str(temp_dir / ".key1"))
        km2 = KeyManager(key_path=str(temp_dir / ".key2"))

        key1 = km1.get_or_create_key()
        key2 = km2.get_or_create_key()

        # Encrypt with key1
        encrypted = km1.encrypt_with_key("secret-psk", key1)

        # Decrypting with key2 should fail
        with pytest.raises(InvalidToken):
            km2.decrypt_with_key(encrypted, key2)

    def test_decrypt_invalid_data_fails(self, key_manager):
        """Test that decrypting invalid data fails gracefully."""
        from cryptography.fernet import InvalidToken

        key = key_manager.get_or_create_key()

        with pytest.raises(InvalidToken):
            key_manager.decrypt_with_key("not-valid-encrypted-data", key)

    def test_key_persistence(self, temp_dir):
        """Test that the key persists across KeyManager instances."""
        from key_manager import KeyManager

        key_path = temp_dir / ".persistent-key"

        # Create first instance and get/create key
        km1 = KeyManager(key_path=str(key_path))
        key1 = km1.get_or_create_key()

        # Create second instance - should get the same key
        km2 = KeyManager(key_path=str(key_path))
        key2 = km2.get_or_create_key()

        assert key1 == key2

    def test_encrypt_empty_string(self, key_manager):
        """Test that empty strings can be encrypted and decrypted."""
        key = key_manager.get_or_create_key()

        encrypted = key_manager.encrypt_with_key("", key)
        decrypted = key_manager.decrypt_with_key(encrypted, key)

        assert decrypted == ""

    def test_encrypt_unicode_characters(self, key_manager):
        """Test that unicode PSKs can be encrypted and decrypted."""
        # PSK with unicode characters
        unicode_psk = "秘密密钥-🔐-secret"

        key = key_manager.get_or_create_key()
        encrypted = key_manager.encrypt_with_key(unicode_psk, key)
        decrypted = key_manager.decrypt_with_key(encrypted, key)

        assert decrypted == unicode_psk

    def test_encrypt_long_psk(self, key_manager):
        """Test that long PSKs can be encrypted and decrypted."""
        long_psk = "x" * 1000  # 1000 character PSK

        key = key_manager.get_or_create_key()
        encrypted = key_manager.encrypt_with_key(long_psk, key)
        decrypted = key_manager.decrypt_with_key(encrypted, key)

        assert decrypted == long_psk


class TestPSKIntegration:
    """Integration tests for PSK encryption with database operations."""

    @pytest.fixture
    def mock_geodata_path(self, temp_dir):
        """Create a mock geodata catalog file."""
        geodata_path = temp_dir / "geoip-catalog.json"
        geodata_path.write_text('{"countries": []}')
        return str(geodata_path)

    @pytest.fixture
    def initialized_db_with_encryption(self, temp_dir, mock_geodata_path):
        """Create an initialized database for testing."""
        import sqlite3
        from init_user_db import USER_DB_SCHEMA

        db_path = temp_dir / "user-config.db"
        conn = sqlite3.connect(str(db_path))
        conn.executescript(USER_DB_SCHEMA)
        conn.commit()
        conn.close()
        return str(db_path)

    @pytest.fixture(autouse=True)
    def reset_db_singleton(self):
        """Reset the db_helper singleton between tests."""
        import db_helper
        db_helper._db_manager = None
        yield
        db_helper._db_manager = None

    def test_psk_stored_encrypted_in_database(
        self, initialized_db_with_encryption, mock_geodata_path, temp_dir
    ):
        """Test that PSK is stored encrypted in the database, not in plaintext."""
        import sqlite3
        import os
        from db_helper import get_db
        from key_manager import KeyManager

        # Set up encryption key
        key_path = temp_dir / ".db-key"
        km = KeyManager(key_path=str(key_path))
        key = km.get_or_create_key()
        os.environ['SQLCIPHER_KEY'] = key

        db = get_db(mock_geodata_path, initialized_db_with_encryption)

        original_psk = "my-secret-psk-12345"
        psk_encrypted = km.encrypt_with_key(original_psk, key)

        # Add peer node with encrypted PSK
        db.add_peer_node(
            tag="test-node",
            name="Test Node",
            endpoint="test.example.com:36200",
            psk_hash="$2b$12$hashhash",
            psk_encrypted=psk_encrypted,
        )

        # Read directly from database to verify encrypted storage
        conn = sqlite3.connect(initialized_db_with_encryption)
        cursor = conn.cursor()
        cursor.execute("SELECT psk_encrypted FROM peer_nodes WHERE tag = ?", ("test-node",))
        row = cursor.fetchone()
        conn.close()

        stored_psk = row[0]

        # Stored value should not be plaintext
        assert stored_psk != original_psk
        # Stored value should be the encrypted version
        assert stored_psk == psk_encrypted
        # Should be able to decrypt back to original
        decrypted = km.decrypt_with_key(stored_psk, key)
        assert decrypted == original_psk

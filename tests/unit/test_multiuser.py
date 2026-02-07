"""
Unit tests for multi-user system - User management and resource isolation.

Tests cover:
- User CRUD operations
- Resource ownership filtering (rules, peers, v2ray users)
- Cascade delete when user is deleted
- Token management (version, blacklist)
- Account lockout
- Last admin protection
"""

import pytest
import bcrypt
from pathlib import Path


@pytest.fixture(autouse=True)
def reset_db_singleton():
    """Reset the db_helper singleton between tests."""
    import db_helper
    db_helper._db_manager = None
    yield
    db_helper._db_manager = None


@pytest.fixture
def multiuser_db(initialized_user_db, mock_geodata_db):
    """Create a database with multi-user schema ready for testing.

    The USER_DB_SCHEMA already includes all multi-user tables:
    - users: User accounts with role, token_version, lockout fields
    - audit_log: Security event logging
    - token_blacklist: JWT revocation
    - user_quotas: Per-user resource limits
    """
    from db_helper import get_db
    import sqlite3

    # Enable foreign keys (must be done on each connection)
    conn = sqlite3.connect(str(initialized_user_db))
    conn.execute("PRAGMA foreign_keys = ON")
    conn.commit()
    conn.close()

    db = get_db(str(mock_geodata_db), str(initialized_user_db))
    return db


@pytest.fixture
def admin_user(multiuser_db):
    """Create an admin user and return (user_id, username)."""
    password_hash = bcrypt.hashpw(b"Admin123!", bcrypt.gensalt()).decode()
    user_id = multiuser_db.add_user(
        username="admin",
        password_hash=password_hash,
        email="admin@example.com",
        role="admin"
    )
    return user_id, "admin"


@pytest.fixture
def regular_user(multiuser_db, admin_user):
    """Create a regular user and return (user_id, username)."""
    admin_id, _ = admin_user
    password_hash = bcrypt.hashpw(b"User1234!", bcrypt.gensalt()).decode()
    user_id = multiuser_db.add_user(
        username="testuser",
        password_hash=password_hash,
        email="user@example.com",
        role="user",
        created_by=admin_id
    )
    return user_id, "testuser"


@pytest.fixture
def second_user(multiuser_db, admin_user):
    """Create a second regular user for isolation tests."""
    admin_id, _ = admin_user
    password_hash = bcrypt.hashpw(b"User5678!", bcrypt.gensalt()).decode()
    user_id = multiuser_db.add_user(
        username="otheruser",
        password_hash=password_hash,
        role="user",
        created_by=admin_id
    )
    return user_id, "otheruser"


class TestUserCRUD:
    """Tests for user management operations."""

    def test_create_user(self, multiuser_db):
        """Test creating a new user."""
        password_hash = bcrypt.hashpw(b"Test1234!", bcrypt.gensalt()).decode()
        user_id = multiuser_db.add_user(
            username="newuser",
            password_hash=password_hash,
            email="new@example.com",
            role="user"
        )

        assert user_id is not None
        assert user_id > 0

        user = multiuser_db.get_user(user_id)
        assert user["username"] == "newuser"
        assert user["email"] == "new@example.com"
        assert user["role"] == "user"
        assert user["enabled"] == 1

    def test_get_user_by_username(self, multiuser_db, admin_user):
        """Test fetching user by username."""
        admin_id, username = admin_user

        user = multiuser_db.get_user_by_username(username)
        assert user is not None
        assert user["id"] == admin_id
        assert user["role"] == "admin"

    def test_get_nonexistent_user(self, multiuser_db):
        """Test fetching a user that doesn't exist."""
        user = multiuser_db.get_user(99999)
        assert user is None

        user = multiuser_db.get_user_by_username("nonexistent")
        assert user is None

    def test_update_user_role(self, multiuser_db, admin_user, regular_user):
        """Test updating user role."""
        user_id, _ = regular_user

        result = multiuser_db.update_user(user_id, role="admin")
        assert result is True

        user = multiuser_db.get_user(user_id)
        assert user["role"] == "admin"

    def test_disable_user(self, multiuser_db, regular_user):
        """Test disabling a user account."""
        user_id, _ = regular_user

        result = multiuser_db.update_user(user_id, enabled=0)
        assert result is True

        user = multiuser_db.get_user(user_id)
        assert user["enabled"] == 0

    def test_delete_user(self, multiuser_db, regular_user):
        """Test deleting a user."""
        user_id, _ = regular_user

        result = multiuser_db.delete_user(user_id)
        assert result is True

        user = multiuser_db.get_user(user_id)
        assert user is None

    def test_list_users(self, multiuser_db, admin_user, regular_user):
        """Test listing all users."""
        users = multiuser_db.get_users()

        assert len(users) >= 2
        usernames = [u["username"] for u in users]
        assert "admin" in usernames
        assert "testuser" in usernames

    def test_count_users_by_role(self, multiuser_db, admin_user, regular_user, second_user):
        """Test counting users by role."""
        admin_count = multiuser_db.count_users_by_role("admin")
        user_count = multiuser_db.count_users_by_role("user")

        assert admin_count == 1
        assert user_count == 2


class TestResourceOwnership:
    """Tests for resource ownership filtering."""

    def test_rule_owned_by_user(self, multiuser_db, regular_user):
        """Test that rules can be owned by a user."""
        user_id, _ = regular_user

        rule_id = multiuser_db.add_routing_rule(
            rule_type="domain_suffix",
            target="example.com",
            outbound="direct",
            tag="user-rule",
            priority=100,
            owner_id=user_id
        )

        assert rule_id is not None

        # User can see their own rules
        rules = multiuser_db.get_routing_rules(owner_id=user_id)
        assert len(rules) == 1
        assert rules[0]["owner_id"] == user_id

    def test_rule_isolation_between_users(self, multiuser_db, regular_user, second_user):
        """Test that users cannot see each other's rules."""
        user1_id, _ = regular_user
        user2_id, _ = second_user

        # User 1 creates a rule
        multiuser_db.add_routing_rule(
            rule_type="domain_suffix",
            target="user1.com",
            outbound="direct",
            tag="user1-rule",
            owner_id=user1_id
        )

        # User 2 creates a rule
        multiuser_db.add_routing_rule(
            rule_type="domain_suffix",
            target="user2.com",
            outbound="direct",
            tag="user2-rule",
            owner_id=user2_id
        )

        # User 1 can only see their own rule
        user1_rules = multiuser_db.get_routing_rules(owner_id=user1_id)
        assert len(user1_rules) == 1
        assert user1_rules[0]["target"] == "user1.com"

        # User 2 can only see their own rule
        user2_rules = multiuser_db.get_routing_rules(owner_id=user2_id)
        assert len(user2_rules) == 1
        assert user2_rules[0]["target"] == "user2.com"

    def test_admin_sees_all_rules(self, multiuser_db, admin_user, regular_user, second_user):
        """Test that admin can see all rules (owner_id=None)."""
        user1_id, _ = regular_user
        user2_id, _ = second_user

        multiuser_db.add_routing_rule(
            rule_type="domain_suffix",
            target="user1.com",
            outbound="direct",
            owner_id=user1_id
        )
        multiuser_db.add_routing_rule(
            rule_type="domain_suffix",
            target="user2.com",
            outbound="direct",
            owner_id=user2_id
        )

        # Admin sees all rules (owner_id=None means no filter)
        all_rules = multiuser_db.get_routing_rules(owner_id=None)
        assert len(all_rules) >= 2

    def test_peer_ownership(self, multiuser_db, regular_user):
        """Test WireGuard peer ownership."""
        user_id, _ = regular_user

        peer_id = multiuser_db.add_wireguard_peer(
            name="user-peer",
            public_key="dGVzdHB1YmxpY2tleQ==",
            allowed_ips="10.25.0.10/32",
            owner_id=user_id
        )

        assert peer_id is not None

        peers = multiuser_db.get_wireguard_peers(owner_id=user_id)
        assert len(peers) == 1
        assert peers[0]["owner_id"] == user_id

    def test_peer_isolation(self, multiuser_db, regular_user, second_user):
        """Test peer isolation between users."""
        user1_id, _ = regular_user
        user2_id, _ = second_user

        multiuser_db.add_wireguard_peer(
            name="user1-peer",
            public_key="dXNlcjFwdWJrZXk=",
            allowed_ips="10.25.0.10/32",
            owner_id=user1_id
        )
        multiuser_db.add_wireguard_peer(
            name="user2-peer",
            public_key="dXNlcjJwdWJrZXk=",
            allowed_ips="10.25.0.11/32",
            owner_id=user2_id
        )

        user1_peers = multiuser_db.get_wireguard_peers(owner_id=user1_id)
        user2_peers = multiuser_db.get_wireguard_peers(owner_id=user2_id)

        assert len(user1_peers) == 1
        assert user1_peers[0]["name"] == "user1-peer"
        assert len(user2_peers) == 1
        assert user2_peers[0]["name"] == "user2-peer"

    def test_v2ray_user_ownership(self, multiuser_db, regular_user):
        """Test V2Ray user ownership."""
        user_id, _ = regular_user

        v2ray_id = multiuser_db.add_v2ray_user(
            name="vless-client",
            uuid="550e8400-e29b-41d4-a716-446655440000",
            owner_id=user_id
        )

        assert v2ray_id is not None

        v2ray_users = multiuser_db.get_v2ray_users(owner_id=user_id)
        assert len(v2ray_users) == 1
        assert v2ray_users[0]["owner_id"] == user_id


class TestCascadeDelete:
    """Tests for cascade delete when user is deleted."""

    def test_cascade_delete_rules(self, multiuser_db, regular_user):
        """Test that deleting a user cascades to their rules."""
        user_id, _ = regular_user

        # Create rules for user
        multiuser_db.add_routing_rule(
            rule_type="domain_suffix",
            target="cascade1.com",
            outbound="direct",
            owner_id=user_id
        )
        multiuser_db.add_routing_rule(
            rule_type="domain_suffix",
            target="cascade2.com",
            outbound="direct",
            owner_id=user_id
        )

        # Verify rules exist
        rules = multiuser_db.get_routing_rules(owner_id=user_id)
        assert len(rules) == 2

        # Delete user
        multiuser_db.delete_user(user_id)

        # Rules should be cascade deleted
        rules_after = multiuser_db.get_routing_rules(owner_id=None)
        user_rules = [r for r in rules_after if r.get("owner_id") == user_id]
        assert len(user_rules) == 0

    def test_cascade_delete_peers(self, multiuser_db, regular_user):
        """Test that deleting a user cascades to their peers."""
        user_id, _ = regular_user

        multiuser_db.add_wireguard_peer(
            name="cascade-peer",
            public_key="Y2FzY2FkZXBlZXJrZXk=",
            allowed_ips="10.25.0.20/32",
            owner_id=user_id
        )

        peers_before = multiuser_db.get_wireguard_peers(owner_id=user_id)
        assert len(peers_before) == 1

        multiuser_db.delete_user(user_id)

        # Peer should be cascade deleted
        all_peers = multiuser_db.get_wireguard_peers(owner_id=None)
        user_peers = [p for p in all_peers if p.get("owner_id") == user_id]
        assert len(user_peers) == 0

    def test_cascade_delete_quotas(self, multiuser_db, regular_user):
        """Test that deleting a user cascades to their quotas."""
        user_id, _ = regular_user

        # Set quota for user
        multiuser_db.set_user_quota(user_id, max_peers=5, max_rules=50)

        quota = multiuser_db.get_user_quota(user_id)
        assert quota is not None

        multiuser_db.delete_user(user_id)

        # Quota should be cascade deleted
        quota_after = multiuser_db.get_user_quota(user_id)
        assert quota_after is None


class TestTokenManagement:
    """Tests for token version and blacklist."""

    def test_token_version_increment(self, multiuser_db, regular_user):
        """Test that token version increments on password change."""
        user_id, _ = regular_user

        user_before = multiuser_db.get_user(user_id)
        version_before = user_before["token_version"]

        # Increment token version (password change)
        result = multiuser_db.increment_token_version(user_id)
        assert result is True

        user_after = multiuser_db.get_user(user_id)
        assert user_after["token_version"] == version_before + 1

    def test_token_blacklist(self, multiuser_db, regular_user):
        """Test adding and checking token blacklist."""
        user_id, _ = regular_user
        jti = "test-token-id-12345"
        expires_at = "2099-12-31T23:59:59Z"

        # Add token to blacklist
        result = multiuser_db.add_revoked_token(
            jti=jti,
            user_id=user_id,
            expires_at=expires_at,
            reason="logout"
        )
        assert result is True

        # Check if token is revoked
        is_revoked = multiuser_db.is_token_revoked(jti)
        assert is_revoked is True

        # Non-revoked token
        is_valid = multiuser_db.is_token_revoked("non-existent-jti")
        assert is_valid is False


class TestAccountLockout:
    """Tests for account lockout functionality."""

    def test_record_failed_login(self, multiuser_db, regular_user):
        """Test recording failed login attempts."""
        user_id, _ = regular_user

        # Record failed logins
        count1 = multiuser_db.record_failed_login(user_id)
        count2 = multiuser_db.record_failed_login(user_id)
        count3 = multiuser_db.record_failed_login(user_id)

        assert count1 == 1
        assert count2 == 2
        assert count3 == 3

    def test_account_lockout(self, multiuser_db, regular_user):
        """Test locking account after failed attempts."""
        user_id, _ = regular_user

        # Account should not be locked initially
        assert multiuser_db.is_account_locked(user_id) is False

        # Lock account
        result = multiuser_db.lock_account(user_id, lock_minutes=30)
        assert result is True

        # Account should be locked
        assert multiuser_db.is_account_locked(user_id) is True

    def test_reset_failed_login(self, multiuser_db, regular_user):
        """Test resetting failed login count after successful login."""
        user_id, _ = regular_user

        # Record some failed attempts
        multiuser_db.record_failed_login(user_id)
        multiuser_db.record_failed_login(user_id)

        user = multiuser_db.get_user(user_id)
        assert user["failed_login_count"] == 2

        # Reset on successful login
        result = multiuser_db.reset_failed_login(user_id)
        assert result is True

        user_after = multiuser_db.get_user(user_id)
        assert user_after["failed_login_count"] == 0


class TestLastAdminProtection:
    """Tests for preventing deletion/demotion of last admin."""

    def test_count_admins(self, multiuser_db, admin_user):
        """Test counting admin users."""
        admin_count = multiuser_db.count_users_by_role("admin")
        assert admin_count == 1

    def test_second_admin_can_be_demoted(self, multiuser_db, admin_user, regular_user):
        """Test that a second admin can be demoted."""
        user_id, _ = regular_user

        # Promote to admin
        multiuser_db.update_user(user_id, role="admin")
        assert multiuser_db.count_users_by_role("admin") == 2

        # Can demote back to user
        result = multiuser_db.update_user(user_id, role="user")
        assert result is True
        assert multiuser_db.count_users_by_role("admin") == 1


class TestAuditLog:
    """Tests for audit logging."""

    def test_add_audit_log(self, multiuser_db, admin_user):
        """Test adding audit log entries."""
        user_id, _ = admin_user

        log_id = multiuser_db.add_audit_log(
            action="login",
            user_id=user_id,
            ip_address="192.168.1.100"
        )

        assert log_id is not None
        assert log_id > 0

    def test_get_audit_logs(self, multiuser_db, admin_user):
        """Test retrieving audit logs."""
        user_id, _ = admin_user

        # Add some logs
        multiuser_db.add_audit_log(action="login", user_id=user_id)
        multiuser_db.add_audit_log(action="create_rule", user_id=user_id)
        multiuser_db.add_audit_log(action="logout", user_id=user_id)

        # Get all logs for user
        logs = multiuser_db.get_audit_logs(user_id=user_id)
        assert len(logs) >= 3

        # Get logs by action
        login_logs = multiuser_db.get_audit_logs(action="login")
        assert len(login_logs) >= 1


class TestUserQuotas:
    """Tests for user resource quotas."""

    def test_set_and_get_quota(self, multiuser_db, regular_user):
        """Test setting and getting user quota."""
        user_id, _ = regular_user

        result = multiuser_db.set_user_quota(
            user_id,
            max_peers=20,
            max_rules=200,
            max_rule_sets=15
        )
        assert result is True

        quota = multiuser_db.get_user_quota(user_id)
        assert quota["max_peers"] == 20
        assert quota["max_rules"] == 200
        assert quota["max_rule_sets"] == 15

    def test_default_quota(self, multiuser_db, regular_user):
        """Test that users without explicit quota return None."""
        user_id, _ = regular_user

        # New user has no quota set
        quota = multiuser_db.get_user_quota(user_id)
        # Should be None until explicitly set
        assert quota is None

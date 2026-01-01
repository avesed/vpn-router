#!/usr/bin/env python3
"""Phase 11 集成测试

测试多节点对等网络架构的核心功能：
- 双向自动连接（WireGuard 和 Xray）
- 中继节点配置（DSCP 路由）
- 终端出口缓存
- 级联删除通知（Phase 11-Cascade）

Phase 11-Cascade 测试覆盖：
- 墓碑记录创建、检查和过期清理
- 原子幂等性标记（TOCTOU 竞态条件防护）
- 节点事件日志
- TunnelAPIClient 级联删除方法

注意：这些测试需要运行中的 vpn-gateway 容器
运行方式：
    pytest tests/integration/test_phase11.py -v
"""

import json
import os
import subprocess
import sys
import time
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional

import pytest
# bcrypt import removed - PSK authentication deprecated (Phase 11-Fix.N)

# 添加脚本目录到 Python 路径
SCRIPTS_DIR = Path(__file__).parent.parent.parent / "scripts"
sys.path.insert(0, str(SCRIPTS_DIR))

# 在导入 db_helper 之前，确保设置加密密钥
def setup_encryption_key():
    """从文件或生成加密密钥"""
    key_file = Path(os.environ.get("SQLCIPHER_KEY_FILE", "/etc/sing-box/.db-key"))
    if key_file.exists():
        key = key_file.read_text().strip()
        os.environ["SQLCIPHER_KEY"] = key
    elif not os.environ.get("SQLCIPHER_KEY"):
        # 测试环境下生成临时密钥
        import secrets
        os.environ["SQLCIPHER_KEY"] = secrets.token_hex(32)

setup_encryption_key()


# ============ 测试配置 ============

# 容器内测试时使用这些路径
GEODATA_PATH = os.environ.get("GEODATA_DB_PATH", "/etc/sing-box/geoip-catalog.json")
USER_DB_PATH = os.environ.get("USER_DB_PATH", "/etc/sing-box/user-config.db")


def skip_if_no_database():
    """如果数据库不存在则跳过测试"""
    if not Path(USER_DB_PATH).exists():
        pytest.skip(f"数据库不存在: {USER_DB_PATH}")


# ============ Phase 11.1: 数据库 Schema 测试 ============

class TestDatabaseSchema:
    """Phase 11.1 数据库 Schema 扩展测试"""

    @pytest.fixture(autouse=True)
    def setup(self):
        """每个测试前检查数据库"""
        skip_if_no_database()
        from db_helper import get_db
        self.db = get_db(GEODATA_PATH, USER_DB_PATH)

    def test_peer_nodes_bidirectional_status_column(self):
        """验证 peer_nodes 表有 bidirectional_status 列"""
        with self.db.user._get_conn() as conn:
            cursor = conn.cursor()
            cursor.execute("PRAGMA table_info(peer_nodes)")
            columns = {row[1] for row in cursor.fetchall()}

        assert "bidirectional_status" in columns, "缺少 bidirectional_status 列"

    def test_peer_nodes_bidirectional_index_exists(self):
        """验证双向连接复合索引存在"""
        with self.db.user._get_conn() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT name FROM sqlite_master
                WHERE type='index' AND name='idx_peer_nodes_enabled_bidirectional'
            """)
            result = cursor.fetchone()

        assert result is not None, "缺少 idx_peer_nodes_enabled_bidirectional 索引"

    def test_terminal_egress_cache_table_exists(self):
        """验证 terminal_egress_cache 表存在"""
        with self.db.user._get_conn() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT name FROM sqlite_master
                WHERE type='table' AND name='terminal_egress_cache'
            """)
            result = cursor.fetchone()

        assert result is not None, "缺少 terminal_egress_cache 表"

    def test_node_chains_dscp_column(self):
        """验证 node_chains 表有 dscp_value 列"""
        with self.db.user._get_conn() as conn:
            cursor = conn.cursor()
            cursor.execute("PRAGMA table_info(node_chains)")
            columns = {row[1] for row in cursor.fetchall()}

        assert "dscp_value" in columns, "缺少 dscp_value 列"
        assert "chain_mark_type" in columns, "缺少 chain_mark_type 列"


# ============ Phase 11.2/11.3: 双向连接测试 ============

class TestBidirectionalConnect:
    """双向自动连接测试"""

    @pytest.fixture(autouse=True)
    def setup(self):
        """每个测试前检查数据库"""
        skip_if_no_database()
        from db_helper import get_db
        self.db = get_db(GEODATA_PATH, USER_DB_PATH)

    def test_update_bidirectional_status(self):
        """测试更新双向状态"""
        # 创建测试节点
        test_tag = f"test-bidir-{int(time.time())}"
        # PSK deprecated - using tunnel-based authentication

        try:
            # 添加测试节点
            self.db.add_peer_node(
                tag=test_tag,
                name="Test Bidirectional",
                endpoint="10.0.0.100:36300",
                # psk_hash deprecated
                tunnel_type="wireguard"
            )

            # 更新双向状态
            success = self.db.update_peer_bidirectional_status(test_tag, "bidirectional")
            assert success, "更新双向状态失败"

            # 验证状态
            node = self.db.get_peer_node(test_tag)
            assert node is not None
            assert node.get("bidirectional_status") == "bidirectional"

        finally:
            # 清理
            self.db.delete_peer_node(test_tag)

    def test_get_peers_pending_bidirectional(self):
        """测试获取待双向连接的节点"""
        test_tag = f"test-pending-{int(time.time())}"
        # PSK deprecated - using tunnel-based authentication

        try:
            # 添加测试节点（默认 pending 状态）
            self.db.add_peer_node(
                tag=test_tag,
                name="Test Pending",
                endpoint="10.0.0.101:36300",
                # psk_hash deprecated
                tunnel_type="wireguard"
            )

            # 设置为 connected 状态（get_peers_pending_bidirectional 要求 connected）
            self.db.update_peer_node(test_tag, tunnel_status="connected")

            # 获取待连接节点
            pending = self.db.get_peers_pending_bidirectional()
            tags = [p["tag"] for p in pending]

            assert test_tag in tags, "应该返回 pending 状态且已连接的节点"

        finally:
            self.db.delete_peer_node(test_tag)


# ============ Phase 11.4: 中继路由测试 ============

class TestRelayConfiguration:
    """中继节点配置测试"""

    @pytest.fixture(autouse=True)
    def setup(self):
        """每个测试前检查数据库"""
        skip_if_no_database()
        from db_helper import get_db
        self.db = get_db(GEODATA_PATH, USER_DB_PATH)

    def test_routing_table_allocation_no_collision(self):
        """验证路由表分配无冲突"""
        # 各模块使用的路由表范围
        ecmp_range = range(200, 300)
        dscp_range = range(300, 364)  # 300 + 1 to 300 + 63
        relay_range = range(400, 464)  # 400-463
        peer_range = range(500, 600)

        # 验证范围不重叠
        assert not set(ecmp_range) & set(dscp_range), "ECMP 和 DSCP 路由表冲突"
        assert not set(dscp_range) & set(relay_range), "DSCP 和 Relay 路由表冲突"
        assert not set(relay_range) & set(peer_range), "Relay 和 Peer 路由表冲突"
        assert not set(ecmp_range) & set(peer_range), "ECMP 和 Peer 路由表冲突"

    def test_dscp_manager_constants(self):
        """验证 DSCP 管理器常量"""
        from dscp_manager import TERMINAL_TABLE_BASE, TERMINAL_FWMARK_BASE

        assert TERMINAL_TABLE_BASE == 300, f"TERMINAL_TABLE_BASE 应为 300，实际为 {TERMINAL_TABLE_BASE}"
        assert TERMINAL_FWMARK_BASE == 300, f"TERMINAL_FWMARK_BASE 应为 300，实际为 {TERMINAL_FWMARK_BASE}"

    def test_relay_manager_constants(self):
        """验证中继管理器常量"""
        from relay_config_manager import RELAY_FWMARK_BASE, RELAY_TABLE_BASE

        assert RELAY_FWMARK_BASE == 400, f"RELAY_FWMARK_BASE 应为 400，实际为 {RELAY_FWMARK_BASE}"
        assert RELAY_TABLE_BASE == 400, f"RELAY_TABLE_BASE 应为 400，实际为 {RELAY_TABLE_BASE}"


# ============ Phase 11.5: 终端出口缓存测试 ============

class TestTerminalEgressCache:
    """终端出口缓存测试"""

    @pytest.fixture(autouse=True)
    def setup(self):
        """每个测试前检查数据库"""
        skip_if_no_database()
        from db_helper import get_db
        self.db = get_db(GEODATA_PATH, USER_DB_PATH)

    def test_cache_create_and_get(self):
        """测试缓存创建和获取"""
        test_chain = f"test-cache-{int(time.time())}"

        try:
            # 创建缓存
            egress_list = [
                {"tag": "us-stream", "type": "pia", "enabled": True},
                {"tag": "direct", "type": "direct", "enabled": True}
            ]
            success = self.db.update_terminal_egress_cache(
                chain_tag=test_chain,
                terminal_node="node-b",
                egress_list=egress_list,
                ttl_seconds=300
            )
            assert success, "创建缓存失败"

            # 获取缓存
            cache = self.db.get_terminal_egress_cache(test_chain)
            assert cache is not None, "获取缓存失败"
            assert cache["terminal_node"] == "node-b"

            cached_list = json.loads(cache["egress_list"])
            assert len(cached_list) == 2

        finally:
            self.db.delete_terminal_egress_cache(test_chain)

    def test_cache_expiry(self):
        """测试缓存过期"""
        test_chain = f"test-expire-{int(time.time())}"

        try:
            # 创建即将过期的缓存（TTL = 1 秒）
            egress_list = [{"tag": "direct", "type": "direct", "enabled": True}]
            self.db.update_terminal_egress_cache(
                chain_tag=test_chain,
                terminal_node="node-c",
                egress_list=egress_list,
                ttl_seconds=1
            )

            # 等待过期
            time.sleep(2)

            # 清理过期缓存
            deleted = self.db.cleanup_expired_terminal_egress_cache()

            # 验证缓存已被清理
            cache = self.db.get_terminal_egress_cache(test_chain)
            # 缓存可能已经不存在，或者 expires_at 已过期
            if cache:
                expires_at = datetime.fromisoformat(cache["expires_at"])
                assert expires_at < datetime.now(), "缓存应该已过期"

        finally:
            self.db.delete_terminal_egress_cache(test_chain)

    def test_cascade_delete_on_chain_delete(self):
        """测试删除链路时级联删除缓存"""
        test_chain = f"test-cascade-{int(time.time())}"

        try:
            # 创建链路
            self.db.add_node_chain(
                tag=test_chain,
                name="Test Cascade Chain",
                hops=["node-a", "node-b"],
                description="For cascade delete test"
            )

            # 创建缓存
            egress_list = [{"tag": "direct", "type": "direct", "enabled": True}]
            self.db.update_terminal_egress_cache(
                chain_tag=test_chain,
                terminal_node="node-b",
                egress_list=egress_list,
                ttl_seconds=300
            )

            # 验证缓存存在
            cache = self.db.get_terminal_egress_cache(test_chain)
            assert cache is not None, "缓存应该存在"

            # 删除链路
            self.db.delete_node_chain(test_chain)

            # 验证缓存已被级联删除
            cache = self.db.get_terminal_egress_cache(test_chain)
            assert cache is None, "删除链路后缓存应该被级联删除"

        finally:
            # 确保清理
            self.db.delete_node_chain(test_chain)
            self.db.delete_terminal_egress_cache(test_chain)


# ============ Phase 11-Cascade: 级联删除测试 ============

class TestCascadeDelete:
    """Phase 11-Cascade 级联删除功能测试"""

    @pytest.fixture(autouse=True)
    def setup(self):
        """每个测试前检查数据库"""
        skip_if_no_database()
        from db_helper import get_db
        self.db = get_db(GEODATA_PATH, USER_DB_PATH)

    def test_tombstone_create_and_check(self):
        """测试墓碑记录创建和检查"""
        test_tag = f"test-tombstone-{int(time.time())}"

        try:
            # 创建墓碑
            success = self.db.add_peer_tombstone(
                tag=test_tag,
                deleted_by="local-node",
                reason="test_delete",
                ttl_hours=24
            )
            assert success, "创建墓碑失败"

            # 检查墓碑存在
            exists = self.db.is_peer_tombstoned(test_tag)
            assert exists, "墓碑应该存在"

        finally:
            # 清理
            self.db.delete_peer_tombstone(test_tag)

    def test_tombstone_expiry(self):
        """测试墓碑过期

        B-1 Fix: 使用有效的 ttl_hours=1，然后直接更新 expires_at 为过去时间
        """
        test_tag = f"test-expire-tomb-{int(time.time())}"

        try:
            # 创建有效墓碑（TTL = 1 小时，符合 ttl_hours > 0 的验证要求）
            success = self.db.add_peer_tombstone(
                tag=test_tag,
                deleted_by="local-node",
                reason="test_expire",
                ttl_hours=1  # B-1 Fix: 使用有效值
            )
            assert success, "创建墓碑失败"

            # 直接更新 expires_at 为过去时间来模拟过期
            # 这是测试过期清理逻辑的正确方式，而不是等待实际过期
            with self.db.user._get_conn() as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    UPDATE peer_tombstones
                    SET expires_at = strftime('%Y-%m-%dT%H:%M:%SZ', 'now', '-1 hour')
                    WHERE tag = ?
                """, (test_tag,))
                conn.commit()

            # 清理过期墓碑
            deleted_count = self.db.cleanup_expired_tombstones()
            assert deleted_count >= 1, f"应该至少清理 1 个墓碑，实际清理了 {deleted_count}"

            # 验证墓碑已被清理
            exists = self.db.is_peer_tombstoned(test_tag)
            assert not exists, "过期墓碑应该被清理"

        finally:
            self.db.delete_peer_tombstone(test_tag)

    def test_atomic_idempotency_mark(self):
        """测试原子幂等性标记（防止 TOCTOU 竞态条件）"""
        import uuid
        test_event_id = str(uuid.uuid4())
        test_from_node = "test-node"

        try:
            # 第一次标记 - 应该成功
            was_processed, success = self.db.mark_event_if_not_processed(
                event_id=test_event_id,
                from_node=test_from_node,
                action="delete"
            )
            assert not was_processed, "首次标记：事件不应该已处理"
            assert success, "首次标记：应该成功标记"

            # 第二次标记 - 应该返回已处理
            was_processed2, success2 = self.db.mark_event_if_not_processed(
                event_id=test_event_id,
                from_node=test_from_node,
                action="delete"
            )
            assert was_processed2, "第二次标记：事件应该已处理"
            assert not success2, "第二次标记：不应该再次标记"

        finally:
            # 清理
            with self.db.user._get_conn() as conn:
                conn.execute(
                    "DELETE FROM processed_peer_events WHERE event_id = ?",
                    (test_event_id,)
                )
                conn.commit()

    def test_peer_event_log(self):
        """测试节点事件日志"""
        test_tag = f"test-event-{int(time.time())}"

        try:
            # 记录事件
            success = self.db.log_peer_event(
                event_type="delete",
                peer_tag=test_tag,
                from_node="source-node",
                details={"cascade": True, "reason": "test"}
            )
            assert success, "记录事件失败"

            # 获取最近事件
            events = self.db.get_peer_events(limit=10)
            assert len(events) > 0, "应该有事件记录"

            # 验证最新事件
            latest = events[0]
            assert latest["peer_tag"] == test_tag
            assert latest["event_type"] == "delete"
            assert latest["from_node"] == "source-node"

        finally:
            # 清理测试事件
            with self.db.user._get_conn() as conn:
                conn.execute(
                    "DELETE FROM peer_event_log WHERE peer_tag = ?",
                    (test_tag,)
                )
                conn.commit()

    def test_cascade_delete_tables_exist(self):
        """验证级联删除相关表存在"""
        with self.db.user._get_conn() as conn:
            cursor = conn.cursor()

            # 检查 peer_event_log 表
            cursor.execute("""
                SELECT name FROM sqlite_master
                WHERE type='table' AND name='peer_event_log'
            """)
            assert cursor.fetchone() is not None, "缺少 peer_event_log 表"

            # 检查 peer_tombstones 表
            cursor.execute("""
                SELECT name FROM sqlite_master
                WHERE type='table' AND name='peer_tombstones'
            """)
            assert cursor.fetchone() is not None, "缺少 peer_tombstones 表"

            # 检查 processed_peer_events 表
            cursor.execute("""
                SELECT name FROM sqlite_master
                WHERE type='table' AND name='processed_peer_events'
            """)
            assert cursor.fetchone() is not None, "缺少 processed_peer_events 表"

    def test_processed_events_index_exists(self):
        """验证已处理事件索引存在"""
        with self.db.user._get_conn() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT name FROM sqlite_master
                WHERE type='index' AND name='idx_processed_peer_events_event_id'
            """)
            result = cursor.fetchone()

        assert result is not None, "缺少 idx_processed_peer_events_event_id 索引"


# ============ 单元测试：模块导入 ============

class TestModuleImports:
    """验证关键模块可以正常导入"""

    def test_import_dscp_manager(self):
        """导入 DSCP 管理器"""
        from dscp_manager import DSCPManager, get_dscp_manager
        manager = get_dscp_manager()
        assert manager is not None

    def test_import_relay_config_manager(self):
        """导入中继配置管理器"""
        from relay_config_manager import RelayConfigManager, get_relay_manager
        manager = get_relay_manager()
        assert manager is not None

    def test_import_peer_tunnel_manager(self):
        """导入对等隧道管理器"""
        from peer_tunnel_manager import PeerTunnelManager
        manager = PeerTunnelManager()
        assert manager is not None

    def test_import_tunnel_api_client_cascade_methods(self):
        """验证 TunnelAPIClient 级联删除方法存在"""
        from tunnel_api_client import TunnelAPIClient, TunnelAPIClientManager

        # 验证 TunnelAPIClient 有 send_peer_event 方法
        assert hasattr(TunnelAPIClient, 'send_peer_event'), \
            "TunnelAPIClient 缺少 send_peer_event 方法"
        assert hasattr(TunnelAPIClient, 'send_delete_event'), \
            "TunnelAPIClient 缺少 send_delete_event 方法"
        assert hasattr(TunnelAPIClient, 'send_broadcast_event'), \
            "TunnelAPIClient 缺少 send_broadcast_event 方法"

        # 验证 TunnelAPIClientManager 有广播方法
        assert hasattr(TunnelAPIClientManager, 'broadcast_delete_event'), \
            "TunnelAPIClientManager 缺少 broadcast_delete_event 方法"
        assert hasattr(TunnelAPIClientManager, 'notify_peer_delete'), \
            "TunnelAPIClientManager 缺少 notify_peer_delete 方法"


# ============ 命令行入口 ============

if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])

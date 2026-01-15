#!/usr/bin/env python3
"""
数据库访问辅助模块 - 分离版本

将系统数据和用户数据分离到两个数据库：
- geoip-geodata.db: 只读的地理位置和域名数据（系统数据）
- user-config.db: 用户的路由规则和出口配置（用户数据）
"""
import hashlib
import json
import logging
import os
import threading
from pathlib import Path
from typing import List, Dict, Optional, Any
from contextlib import contextmanager

# SQLCipher 加密数据库支持
try:
    from pysqlcipher3 import dbapi2 as sqlite3
    HAS_SQLCIPHER = True
except ImportError:
    import sqlite3
    HAS_SQLCIPHER = False

# C3 修复: 添加日志记录器
logger = logging.getLogger(__name__)


# ============ M13 修复: JSON Schema 验证辅助函数 ============

def validate_reserved_bytes(data: Any) -> Optional[List[int]]:
    """验证 WireGuard reserved bytes (3 个 0-255 整数)

    Args:
        data: 解析后的 JSON 数据

    Returns:
        验证通过返回原数据，否则返回 None
    """
    if data is None:
        return None
    if not isinstance(data, list):
        logger.warning(f"reserved bytes should be a list, got {type(data).__name__}")
        return None
    if len(data) != 3:
        logger.warning(f"reserved bytes should have 3 elements, got {len(data)}")
        return None
    for i, val in enumerate(data):
        if not isinstance(val, int) or val < 0 or val > 255:
            logger.warning(f"reserved byte[{i}] should be 0-255 integer, got {val}")
            return None
    return data


def validate_string_list(data: Any, field_name: str = "field") -> Optional[List[str]]:
    """验证字符串列表

    Args:
        data: 解析后的 JSON 数据
        field_name: 字段名（用于日志）

    Returns:
        验证通过返回原数据，否则返回 None
    """
    if data is None:
        return None
    if not isinstance(data, list):
        logger.warning(f"{field_name} should be a list, got {type(data).__name__}")
        return None
    for i, val in enumerate(data):
        if not isinstance(val, str):
            logger.warning(f"{field_name}[{i}] should be string, got {type(val).__name__}")
            return None
    return data


def validate_dict(data: Any, field_name: str = "field") -> Optional[Dict]:
    """验证 JSON 对象/字典

    Args:
        data: 解析后的 JSON 数据
        field_name: 字段名（用于日志）

    Returns:
        验证通过返回原数据，否则返回 None
    """
    if data is None:
        return None
    if not isinstance(data, dict):
        logger.warning(f"{field_name} should be a dict, got {type(data).__name__}")
        return None
    return data


# WireGuard egress interface naming constants
WG_PIA_PREFIX = "wg-pia-"     # 8 chars, leaves 7 for tag
WG_CUSTOM_PREFIX = "wg-eg-"   # 6 chars, leaves 9 for tag
WG_WARP_PREFIX = "wg-warp-"   # 8 chars, leaves 7 for tag
WG_MAX_IFACE_LEN = 15         # Linux interface name limit


def get_egress_interface_name(tag: str, is_pia: bool = False, egress_type: str = None) -> str:
    """Generate kernel WireGuard interface name for egress

    H12 修复: 使用 hash 确保唯一性，避免长标签截断冲突

    Naming convention:
    - PIA profiles: wg-pia-{tag} (e.g., wg-pia-new_york)
    - Custom egress: wg-eg-{tag} (e.g., wg-eg-cn2-la)
    - WARP egress: wg-warp-{tag} (e.g., wg-warp-cf)

    For tags that would be truncated, we use a hash-based suffix to ensure uniqueness:
    - If tag fits: wg-pia-hk (full tag)
    - If tag would truncate: wg-pia-ab12c34 (hash of full tag)

    Args:
        tag: The egress profile tag/name
        is_pia: True for PIA profiles, False for custom egress (legacy parameter)
        egress_type: One of "pia", "custom", "warp" (takes precedence over is_pia)

    Returns:
        Interface name, max 15 characters (Linux limit), guaranteed unique per tag
    """
    # Determine prefix based on egress_type or is_pia fallback
    if egress_type == "warp":
        prefix = WG_WARP_PREFIX
    elif egress_type == "pia" or (egress_type is None and is_pia):
        prefix = WG_PIA_PREFIX
    else:
        prefix = WG_CUSTOM_PREFIX

    max_tag_len = WG_MAX_IFACE_LEN - len(prefix)

    if len(tag) <= max_tag_len:
        # 标签足够短，直接使用
        return f"{prefix}{tag}"
    else:
        # H12: 标签过长，使用 hash 确保唯一性
        # 使用 MD5 hash 的前 max_tag_len 个字符
        tag_hash = hashlib.md5(tag.encode('utf-8')).hexdigest()[:max_tag_len]
        return f"{prefix}{tag_hash}"


class GeodataDatabase:
    """地理位置和域名数据库（只读）"""

    def __init__(self, db_path: str):
        self.db_path = db_path

    @contextmanager
    def _get_conn(self):
        """获取数据库连接（上下文管理器）"""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
        finally:
            conn.close()

    def get_statistics(self) -> Dict[str, int]:
        """获取数据库统计信息"""
        with self._get_conn() as conn:
            cursor = conn.cursor()
            return {
                "countries_count": cursor.execute("SELECT COUNT(*) FROM countries").fetchone()[0],
                "ip_ranges_count": cursor.execute("SELECT COUNT(*) FROM ip_ranges").fetchone()[0],
                "ipv4_count": cursor.execute("SELECT COUNT(*) FROM ip_ranges WHERE ip_version = 4").fetchone()[0],
                "ipv6_count": cursor.execute("SELECT COUNT(*) FROM ip_ranges WHERE ip_version = 6").fetchone()[0],
                "categories_count": cursor.execute("SELECT COUNT(*) FROM domain_categories").fetchone()[0],
                "domain_lists_count": cursor.execute("SELECT COUNT(*) FROM domain_lists").fetchone()[0],
                "domains_count": cursor.execute("SELECT COUNT(*) FROM domains").fetchone()[0],
            }

    def get_countries(self, limit: int = 100) -> List[Dict]:
        """获取国家列表"""
        with self._get_conn() as conn:
            cursor = conn.cursor()
            rows = cursor.execute("""
                SELECT code, name, display_name, ipv4_count, ipv6_count, recommended_exit
                FROM countries
                ORDER BY display_name
                LIMIT ?
            """, (limit,)).fetchall()
            return [dict(row) for row in rows]

    def get_country(self, country_code: str) -> Optional[Dict]:
        """获取单个国家信息"""
        with self._get_conn() as conn:
            cursor = conn.cursor()
            row = cursor.execute("""
                SELECT code, name, display_name, ipv4_count, ipv6_count, recommended_exit
                FROM countries
                WHERE code = ?
            """, (country_code.lower(),)).fetchone()
            return dict(row) if row else None

    def get_country_ips(self, country_code: str, ip_version: Optional[int] = None, limit: int = 10000) -> List[str]:
        """获取国家的 IP 范围"""
        with self._get_conn() as conn:
            cursor = conn.cursor()
            if ip_version:
                rows = cursor.execute("""
                    SELECT cidr FROM ip_ranges
                    WHERE country_code = ? AND ip_version = ?
                    LIMIT ?
                """, (country_code.lower(), ip_version, limit)).fetchall()
            else:
                rows = cursor.execute("""
                    SELECT cidr FROM ip_ranges
                    WHERE country_code = ?
                    LIMIT ?
                """, (country_code.lower(), limit)).fetchall()
            return [row[0] for row in rows]

    def search_countries(self, query: str, limit: int = 20) -> List[Dict]:
        """搜索国家"""
        with self._get_conn() as conn:
            cursor = conn.cursor()
            pattern = f"%{query}%"
            rows = cursor.execute("""
                SELECT code, name, display_name, ipv4_count, ipv6_count
                FROM countries
                WHERE code LIKE ? OR name LIKE ? OR display_name LIKE ?
                ORDER BY display_name
                LIMIT ?
            """, (pattern, pattern, pattern, limit)).fetchall()
            return [dict(row) for row in rows]

    def get_domain_categories(self, group_type: Optional[str] = None) -> List[Dict]:
        """获取域名分类"""
        with self._get_conn() as conn:
            cursor = conn.cursor()
            if group_type:
                rows = cursor.execute("""
                    SELECT id, name, description, group_type, recommended_exit
                    FROM domain_categories
                    WHERE group_type = ?
                    ORDER BY name
                """, (group_type,)).fetchall()
            else:
                rows = cursor.execute("""
                    SELECT id, name, description, group_type, recommended_exit
                    FROM domain_categories
                    ORDER BY name
                """).fetchall()
            return [dict(row) for row in rows]

    def get_domain_list(self, list_id: str) -> Optional[Dict]:
        """获取域名列表信息（不包含域名）"""
        with self._get_conn() as conn:
            cursor = conn.cursor()
            row = cursor.execute("""
                SELECT id, domain_count
                FROM domain_lists
                WHERE id = ?
            """, (list_id,)).fetchone()
            return dict(row) if row else None

    def get_domain_list_with_domains(self, list_id: str, limit: int = 1000) -> Optional[Dict]:
        """获取域名列表及其域名"""
        list_info = self.get_domain_list(list_id)
        if not list_info:
            return None

        with self._get_conn() as conn:
            cursor = conn.cursor()
            rows = cursor.execute("""
                SELECT domain, domain_type
                FROM domains
                WHERE list_id = ?
                LIMIT ?
            """, (list_id, limit)).fetchall()

            domains_by_type = {"suffix": [], "keyword": [], "regex": [], "full": []}
            for row in rows:
                domain_type = row[1] if row[1] else "suffix"
                domains_by_type[domain_type].append(row[0])

            list_info["domains"] = domains_by_type
            return list_info

    def search_domain_lists(self, query: str, limit: int = 20) -> List[Dict]:
        """搜索域名列表"""
        with self._get_conn() as conn:
            cursor = conn.cursor()
            pattern = f"%{query}%"
            rows = cursor.execute("""
                SELECT id, domain_count
                FROM domain_lists
                WHERE id LIKE ?
                ORDER BY id
                LIMIT ?
            """, (pattern, limit)).fetchall()
            return [dict(row) for row in rows]

    def get_domain_lists(self, limit: int = 1000) -> List[Dict]:
        """获取所有域名列表"""
        with self._get_conn() as conn:
            cursor = conn.cursor()
            rows = cursor.execute("""
                SELECT id, domain_count
                FROM domain_lists
                ORDER BY id
                LIMIT ?
            """, (limit,)).fetchall()
            return [dict(row) for row in rows]

    def get_domains_by_list(self, list_id: str, limit: int = 10) -> List[str]:
        """获取列表的域名（仅域名字符串）"""
        with self._get_conn() as conn:
            cursor = conn.cursor()
            rows = cursor.execute("""
                SELECT domain
                FROM domains
                WHERE list_id = ?
                LIMIT ?
            """, (list_id, limit)).fetchall()
            return [row[0] for row in rows]

    def get_list_categories(self, list_id: str) -> List[str]:
        """获取列表所属的分类ID列表"""
        with self._get_conn() as conn:
            cursor = conn.cursor()
            rows = cursor.execute("""
                SELECT category_id
                FROM domain_list_categories
                WHERE list_id = ?
            """, (list_id,)).fetchall()
            return [row[0] for row in rows]


class UserDatabase:
    """用户配置数据库（读写，支持 SQLCipher 加密）

    性能优化：使用线程本地存储 (Thread-Local Storage) 缓存数据库连接，
    避免每次操作都创建新连接并执行 PRAGMA key（SQLCipher 密钥派生约 30-50ms）。
    """

    def __init__(self, db_path: str, encryption_key: Optional[str] = None):
        """
        初始化用户数据库

        Args:
            db_path: 数据库文件路径
            encryption_key: SQLCipher 加密密钥（64 字符 hex）
        """
        self.db_path = db_path
        self.encryption_key = encryption_key
        # 线程本地存储：每个线程独立的连接缓存
        self._local = threading.local()

    def _apply_encryption(self, conn) -> None:
        """[DB-003] 应用 SQLCipher 加密密钥和性能调优 PRAGMA

        性能调优说明：
        - cipher_memory_security = OFF: 减少内存安全检查开销（生产环境可接受）
        - cache_size = -2000: 使用 2MB 页面缓存（负值表示 KB）
        - temp_store = MEMORY: 临时表存储在内存中
        - journal_mode = WAL: 写前日志模式，提升并发性能
        - synchronous = NORMAL: 平衡安全性和速度
        """
        if self.encryption_key and HAS_SQLCIPHER:
            conn.execute(f"PRAGMA key = '{self.encryption_key}'")
            # [DB-003] 性能调优 PRAGMA
            conn.execute("PRAGMA cipher_memory_security = OFF")
            conn.execute("PRAGMA cache_size = -2000")  # 2MB
            conn.execute("PRAGMA temp_store = MEMORY")
            conn.execute("PRAGMA journal_mode = WAL")
            conn.execute("PRAGMA synchronous = NORMAL")

    def _get_cached_conn(self):
        """获取当前线程的缓存连接

        性能优化：连接复用避免每次创建新连接的开销（SQLCipher PRAGMA key 约 30-50ms）
        使用线程本地存储确保每个线程有独立的连接，避免多线程冲突。

        Returns:
            sqlite3.Connection: 数据库连接
        """
        if not hasattr(self._local, 'conn') or self._local.conn is None:
            conn = sqlite3.connect(
                str(self.db_path),
                check_same_thread=False,  # 允许跨线程（但 TLS 保证每个线程用自己的连接）
                timeout=30.0
            )
            self._apply_encryption(conn)
            conn.row_factory = sqlite3.Row
            self._local.conn = conn
            logger.debug(f"Created new database connection for thread {threading.current_thread().name}")
        return self._local.conn

    @contextmanager
    def _get_conn(self):
        """获取数据库连接（上下文管理器，兼容现有代码）

        使用线程本地缓存连接，不在退出时关闭连接以支持复用。
        """
        yield self._get_cached_conn()
        # 不关闭连接，保持复用

    def close_connection(self):
        """关闭当前线程的缓存连接（用于清理）"""
        if hasattr(self._local, 'conn') and self._local.conn is not None:
            try:
                self._local.conn.close()
                logger.debug(f"Closed database connection for thread {threading.current_thread().name}")
            except Exception as e:
                logger.warning(f"Error closing connection: {e}")
            finally:
                self._local.conn = None

    @contextmanager
    def _transaction(self):
        """
        M4 修复: 事务上下文管理器，支持自动回滚

        在发生异常时自动回滚未提交的更改，防止数据不一致。
        成功完成时自动提交。

        性能优化：使用线程本地缓存连接，不在退出时关闭连接。

        Usage:
            with db._transaction() as (conn, cursor):
                cursor.execute("INSERT ...")
                cursor.execute("UPDATE ...")
                # 自动提交
            # 如果发生异常，自动回滚
        """
        conn = self._get_cached_conn()
        cursor = conn.cursor()
        try:
            yield conn, cursor
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        # 不关闭连接，保持复用

    def get_statistics(self) -> Dict[str, int]:
        """获取用户数据库统计信息"""
        with self._get_conn() as conn:
            cursor = conn.cursor()
            return {
                "routing_rules_count": cursor.execute("SELECT COUNT(*) FROM routing_rules").fetchone()[0],
                "active_rules_count": cursor.execute("SELECT COUNT(*) FROM routing_rules WHERE enabled = 1").fetchone()[0],
                "outbounds_count": cursor.execute("SELECT COUNT(*) FROM outbounds").fetchone()[0],
                "active_outbounds_count": cursor.execute("SELECT COUNT(*) FROM outbounds WHERE enabled = 1").fetchone()[0],
                "wireguard_peers_count": cursor.execute("SELECT COUNT(*) FROM wireguard_peers").fetchone()[0],
                "active_peers_count": cursor.execute("SELECT COUNT(*) FROM wireguard_peers WHERE enabled = 1").fetchone()[0],
                "pia_profiles_count": cursor.execute("SELECT COUNT(*) FROM pia_profiles").fetchone()[0],
                "active_profiles_count": cursor.execute("SELECT COUNT(*) FROM pia_profiles WHERE enabled = 1").fetchone()[0],
                "custom_category_items_count": cursor.execute("SELECT COUNT(*) FROM custom_category_items").fetchone()[0],
            }

    # ============ 路由规则管理 ============

    def get_routing_rules(self, enabled_only: bool = True) -> List[Dict]:
        """获取路由规则"""
        with self._get_conn() as conn:
            cursor = conn.cursor()
            if enabled_only:
                rows = cursor.execute("""
                    SELECT id, rule_type, target, outbound, tag, priority, enabled, created_at, updated_at
                    FROM routing_rules
                    WHERE enabled = 1
                    ORDER BY priority DESC, id ASC
                """).fetchall()
            else:
                rows = cursor.execute("""
                    SELECT id, rule_type, target, outbound, tag, priority, enabled, created_at, updated_at
                    FROM routing_rules
                    ORDER BY priority DESC, id ASC
                """).fetchall()
            return [dict(row) for row in rows]

    def add_routing_rule(self, rule_type: str, target: str, outbound: str, priority: int = 0, tag: Optional[str] = None) -> int:
        """添加路由规则"""
        with self._get_conn() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO routing_rules (rule_type, target, outbound, tag, priority)
                VALUES (?, ?, ?, ?, ?)
            """, (rule_type, target, outbound, tag, priority))
            conn.commit()
            return cursor.lastrowid

    def add_routing_rules_batch(self, rules: List[tuple]) -> int:
        """批量添加路由规则（使用事务确保原子性）

        Args:
            rules: [(rule_type, target, outbound, tag, priority), ...]

        Returns:
            成功插入的数量

        Raises:
            Exception: 如果插入失败，所有更改都会被回滚
        """
        if not rules:
            return 0
        # M4 修复: 使用事务确保批量操作的原子性
        with self._transaction() as (conn, cursor):
            cursor.executemany("""
                INSERT OR IGNORE INTO routing_rules (rule_type, target, outbound, tag, priority)
                VALUES (?, ?, ?, ?, ?)
            """, rules)
            return cursor.rowcount

    def update_routing_rule(
        self,
        rule_id: int,
        outbound: Optional[str] = None,
        priority: Optional[int] = None,
        enabled: Optional[bool] = None
    ) -> bool:
        """更新路由规则"""
        updates = []
        params = []

        if outbound is not None:
            updates.append("outbound = ?")
            params.append(outbound)
        if priority is not None:
            updates.append("priority = ?")
            params.append(priority)
        if enabled is not None:
            updates.append("enabled = ?")
            params.append(1 if enabled else 0)

        if not updates:
            return False

        updates.append("updated_at = CURRENT_TIMESTAMP")
        params.append(rule_id)

        with self._get_conn() as conn:
            cursor = conn.cursor()
            cursor.execute(f"""
                UPDATE routing_rules
                SET {', '.join(updates)}
                WHERE id = ?
            """, params)
            conn.commit()
            return cursor.rowcount > 0

    def delete_routing_rule(self, rule_id: int) -> bool:
        """删除路由规则"""
        with self._get_conn() as conn:
            cursor = conn.cursor()
            cursor.execute("DELETE FROM routing_rules WHERE id = ?", (rule_id,))
            conn.commit()
            return cursor.rowcount > 0

    def delete_all_routing_rules(self, preserve_adblock: bool = False) -> int:
        """删除所有路由规则（用于备份恢复的替换模式）

        Args:
            preserve_adblock: 如果为 True，保留以 __adblock__ 开头的规则
        """
        with self._get_conn() as conn:
            cursor = conn.cursor()
            if preserve_adblock:
                cursor.execute("DELETE FROM routing_rules WHERE tag NOT LIKE '__adblock__%'")
            else:
                cursor.execute("DELETE FROM routing_rules")
            conn.commit()
            return cursor.rowcount

    # ============ 出口管理 ============

    def get_outbounds(self, enabled_only: bool = True) -> List[Dict]:
        """获取出口列表"""
        with self._get_conn() as conn:
            cursor = conn.cursor()
            if enabled_only:
                rows = cursor.execute("""
                    SELECT tag, type, description, config, enabled, created_at, updated_at
                    FROM outbounds
                    WHERE enabled = 1
                    ORDER BY tag
                """).fetchall()
            else:
                rows = cursor.execute("""
                    SELECT tag, type, description, config, enabled, created_at, updated_at
                    FROM outbounds
                    ORDER BY tag
                """).fetchall()
            return [dict(row) for row in rows]

    def get_outbound(self, tag: str) -> Optional[Dict]:
        """获取单个出口"""
        with self._get_conn() as conn:
            cursor = conn.cursor()
            row = cursor.execute("""
                SELECT tag, type, description, config, enabled, created_at, updated_at
                FROM outbounds
                WHERE tag = ?
            """, (tag,)).fetchone()
            return dict(row) if row else None

    def add_outbound(self, tag: str, type_: str, description: str = "", config: Optional[str] = None) -> bool:
        """添加出口"""
        with self._get_conn() as conn:
            cursor = conn.cursor()
            try:
                cursor.execute("""
                    INSERT INTO outbounds (tag, type, description, config)
                    VALUES (?, ?, ?, ?)
                """, (tag, type_, description, config))
                conn.commit()
                return True
            except sqlite3.IntegrityError:
                return False

    # ============ WireGuard 服务器管理 ============

    def get_wireguard_server(self) -> Optional[Dict]:
        """获取 WireGuard 服务器配置（仅一行）"""
        with self._get_conn() as conn:
            cursor = conn.cursor()
            row = cursor.execute("""
                SELECT id, interface_name, address, listen_port, mtu, private_key,
                       default_outbound, created_at, updated_at
                FROM wireguard_server
                WHERE id = 1
            """).fetchone()
            return dict(row) if row else None

    def set_wireguard_server(self, interface_name: str, address: str, listen_port: int,
                            mtu: int, private_key: str,
                            default_outbound: Optional[str] = None) -> bool:
        """设置 WireGuard 服务器配置（插入或更新）"""
        with self._get_conn() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT OR REPLACE INTO wireguard_server
                (id, interface_name, address, listen_port, mtu, private_key, default_outbound, updated_at)
                VALUES (1, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
            """, (interface_name, address, listen_port, mtu, private_key, default_outbound))
            conn.commit()
            return True

    # ============ WireGuard 对等点（客户端）管理 ============

    def get_wireguard_peers(self, enabled_only: bool = True) -> List[Dict]:
        """获取 WireGuard 对等点列表"""
        with self._get_conn() as conn:
            cursor = conn.cursor()
            if enabled_only:
                rows = cursor.execute("""
                    SELECT id, name, public_key, allowed_ips, preshared_key, allow_lan, lan_subnet, default_outbound, enabled, created_at, updated_at
                    FROM wireguard_peers
                    WHERE enabled = 1
                    ORDER BY name
                """).fetchall()
            else:
                rows = cursor.execute("""
                    SELECT id, name, public_key, allowed_ips, preshared_key, allow_lan, lan_subnet, default_outbound, enabled, created_at, updated_at
                    FROM wireguard_peers
                    ORDER BY name
                """).fetchall()
            return [dict(row) for row in rows]

    def get_wireguard_peer(self, peer_id: int) -> Optional[Dict]:
        """获取单个 WireGuard 对等点"""
        with self._get_conn() as conn:
            cursor = conn.cursor()
            row = cursor.execute("""
                SELECT id, name, public_key, allowed_ips, preshared_key, allow_lan, lan_subnet, default_outbound, enabled, created_at, updated_at
                FROM wireguard_peers
                WHERE id = ?
            """, (peer_id,)).fetchone()
            return dict(row) if row else None

    def get_wireguard_peer_by_name(self, name: str) -> Optional[Dict]:
        """根据名称获取单个 WireGuard 对等点"""
        with self._get_conn() as conn:
            cursor = conn.cursor()
            row = cursor.execute("""
                SELECT id, name, public_key, allowed_ips, preshared_key, allow_lan, lan_subnet, default_outbound, enabled, created_at, updated_at
                FROM wireguard_peers
                WHERE name = ?
            """, (name,)).fetchone()
            return dict(row) if row else None

    def add_wireguard_peer(self, name: str, public_key: str, allowed_ips: str,
                          preshared_key: Optional[str] = None,
                          allow_lan: bool = False,
                          lan_subnet: Optional[str] = None,
                          default_outbound: Optional[str] = None) -> int:
        """添加 WireGuard 对等点

        Args:
            default_outbound: 此客户端的默认出口（None=使用入口默认或全局默认）
        """
        with self._get_conn() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO wireguard_peers (name, public_key, allowed_ips, preshared_key, allow_lan, lan_subnet, default_outbound)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (name, public_key, allowed_ips, preshared_key, 1 if allow_lan else 0, lan_subnet, default_outbound))
            conn.commit()
            return cursor.lastrowid

    def update_wireguard_peer(self, peer_id: int, name: Optional[str] = None,
                             allowed_ips: Optional[str] = None, enabled: Optional[bool] = None,
                             allow_lan: Optional[bool] = None,
                             lan_subnet: Optional[str] = None,
                             default_outbound: Optional[str] = ...) -> bool:
        """更新 WireGuard 对等点

        Args:
            default_outbound: 使用 ... 表示不更新，None 表示清空，字符串表示设置新值
        """
        updates = []
        params = []

        if name is not None:
            updates.append("name = ?")
            params.append(name)
        if allowed_ips is not None:
            updates.append("allowed_ips = ?")
            params.append(allowed_ips)
        if enabled is not None:
            updates.append("enabled = ?")
            params.append(1 if enabled else 0)
        if allow_lan is not None:
            updates.append("allow_lan = ?")
            params.append(1 if allow_lan else 0)
        if lan_subnet is not None:
            updates.append("lan_subnet = ?")
            params.append(lan_subnet)
        if default_outbound is not ...:
            updates.append("default_outbound = ?")
            params.append(default_outbound)

        if not updates:
            return False

        updates.append("updated_at = CURRENT_TIMESTAMP")
        params.append(peer_id)

        with self._get_conn() as conn:
            cursor = conn.cursor()
            cursor.execute(f"""
                UPDATE wireguard_peers
                SET {', '.join(updates)}
                WHERE id = ?
            """, params)
            conn.commit()
            return cursor.rowcount > 0

    def delete_wireguard_peer(self, peer_id: int) -> bool:
        """删除 WireGuard 对等点"""
        with self._get_conn() as conn:
            cursor = conn.cursor()
            cursor.execute("DELETE FROM wireguard_peers WHERE id = ?", (peer_id,))
            conn.commit()
            return cursor.rowcount > 0

    # ============ PIA Profiles 管理 ============

    def get_pia_profiles(self, enabled_only: bool = True) -> List[Dict]:
        """获取 PIA profiles 列表（包含凭证信息）"""
        with self._get_conn() as conn:
            cursor = conn.cursor()
            if enabled_only:
                rows = cursor.execute("""
                    SELECT *
                    FROM pia_profiles
                    WHERE enabled = 1
                    ORDER BY name
                """).fetchall()
            else:
                rows = cursor.execute("""
                    SELECT *
                    FROM pia_profiles
                    ORDER BY name
                """).fetchall()
            return [dict(row) for row in rows]

    def get_pia_profile(self, profile_id: int) -> Optional[Dict]:
        """获取单个 PIA profile"""
        with self._get_conn() as conn:
            cursor = conn.cursor()
            row = cursor.execute("""
                SELECT id, name, description, region_id, custom_dns, enabled, created_at, updated_at
                FROM pia_profiles
                WHERE id = ?
            """, (profile_id,)).fetchone()
            return dict(row) if row else None

    def get_pia_profile_by_name(self, name: str) -> Optional[Dict]:
        """根据名称获取 PIA profile"""
        with self._get_conn() as conn:
            cursor = conn.cursor()
            row = cursor.execute("""
                SELECT id, name, description, region_id, custom_dns, enabled, created_at, updated_at
                FROM pia_profiles
                WHERE name = ?
            """, (name,)).fetchone()
            return dict(row) if row else None

    def add_pia_profile(self, name: str, region_id: str, description: str = "",
                       custom_dns: str = None) -> int:
        """添加 PIA profile

        Args:
            name: profile 名称
            region_id: PIA 地区 ID
            description: 描述
            custom_dns: 自定义 DNS（空=使用 PIA DNS 10.0.0.241，或如 1.1.1.1, tls://dns.google）
        """
        with self._get_conn() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO pia_profiles (name, description, region_id, custom_dns)
                VALUES (?, ?, ?, ?)
            """, (name, description, region_id, custom_dns))
            conn.commit()
            return cursor.lastrowid

    def update_pia_profile(self, profile_id: int, description: Optional[str] = None,
                          region_id: Optional[str] = None, custom_dns: Optional[str] = None,
                          enabled: Optional[bool] = None) -> bool:
        """更新 PIA profile

        Args:
            profile_id: profile ID
            description: 描述
            region_id: PIA 地区 ID
            custom_dns: 自定义 DNS（空字符串=使用 PIA DNS，或如 1.1.1.1, tls://dns.google）
            enabled: 是否启用
        """
        updates = []
        params = []

        if description is not None:
            updates.append("description = ?")
            params.append(description)
        if region_id is not None:
            updates.append("region_id = ?")
            params.append(region_id)
        if custom_dns is not None:
            updates.append("custom_dns = ?")
            # 空字符串转为 NULL（使用默认 PIA DNS）
            params.append(custom_dns if custom_dns else None)
        if enabled is not None:
            updates.append("enabled = ?")
            params.append(1 if enabled else 0)

        if not updates:
            return False

        updates.append("updated_at = CURRENT_TIMESTAMP")
        params.append(profile_id)

        with self._get_conn() as conn:
            cursor = conn.cursor()
            cursor.execute(f"""
                UPDATE pia_profiles
                SET {', '.join(updates)}
                WHERE id = ?
            """, params)
            conn.commit()
            return cursor.rowcount > 0

    def delete_pia_profile(self, profile_id: int) -> bool:
        """删除 PIA profile"""
        with self._get_conn() as conn:
            cursor = conn.cursor()
            cursor.execute("DELETE FROM pia_profiles WHERE id = ?", (profile_id,))
            conn.commit()
            return cursor.rowcount > 0

    def update_pia_credentials(self, name: str, credentials: Dict[str, Any]) -> bool:
        """更新 PIA profile 的 WireGuard 凭证"""
        with self._get_conn() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                UPDATE pia_profiles
                SET server_cn = ?,
                    server_ip = ?,
                    server_port = ?,
                    server_public_key = ?,
                    peer_ip = ?,
                    server_virtual_ip = ?,
                    private_key = ?,
                    public_key = ?,
                    updated_at = CURRENT_TIMESTAMP
                WHERE name = ?
            """, (
                credentials.get("server_cn"),
                credentials.get("server_ip"),
                credentials.get("server_port"),
                credentials.get("server_public_key"),
                credentials.get("peer_ip"),
                credentials.get("server_virtual_ip"),
                credentials.get("private_key"),
                credentials.get("public_key"),
                name
            ))
            conn.commit()
            return cursor.rowcount > 0

    # ============ PIA 账户凭据管理 ============

    def get_pia_credentials(self) -> Optional[Dict[str, str]]:
        """获取 PIA 账户凭据

        Returns:
            {"username": "...", "password": "..."} 或 None（不存在）
        """
        with self._get_conn() as conn:
            cursor = conn.cursor()
            row = cursor.execute("""
                SELECT username, password FROM pia_credentials WHERE id = 1
            """).fetchone()
            if row:
                return {"username": row[0], "password": row[1]}
            return None

    def set_pia_credentials(self, username: str, password: str) -> bool:
        """设置 PIA 账户凭据（插入或更新）

        Args:
            username: PIA 用户名
            password: PIA 密码

        Returns:
            是否成功
        """
        with self._get_conn() as conn:
            cursor = conn.cursor()
            # 使用 INSERT OR REPLACE 兼容 SQLCipher
            cursor.execute("""
                INSERT OR REPLACE INTO pia_credentials (id, username, password, updated_at)
                VALUES (1, ?, ?, CURRENT_TIMESTAMP)
            """, (username, password))
            conn.commit()
            return True

    def delete_pia_credentials(self) -> bool:
        """删除 PIA 账户凭据

        Returns:
            是否成功删除（凭据存在并被删除返回 True）
        """
        with self._get_conn() as conn:
            cursor = conn.cursor()
            cursor.execute("DELETE FROM pia_credentials WHERE id = 1")
            conn.commit()
            return cursor.rowcount > 0

    def has_pia_credentials(self) -> bool:
        """检查是否存在 PIA 凭据

        Returns:
            True 如果凭据存在
        """
        with self._get_conn() as conn:
            cursor = conn.cursor()
            row = cursor.execute("""
                SELECT 1 FROM pia_credentials WHERE id = 1
            """).fetchone()
            return row is not None

    # ============ 自定义分类项目管理 ============

    def get_custom_category_items(self, category_id: Optional[str] = None) -> Dict[str, List[Dict]]:
        """获取自定义分类项目（按分类分组）"""
        with self._get_conn() as conn:
            cursor = conn.cursor()
            if category_id:
                rows = cursor.execute("""
                    SELECT id, category_id, item_id, name, domains, domain_count, created_at
                    FROM custom_category_items
                    WHERE category_id = ?
                    ORDER BY created_at DESC
                """, (category_id,)).fetchall()
            else:
                rows = cursor.execute("""
                    SELECT id, category_id, item_id, name, domains, domain_count, created_at
                    FROM custom_category_items
                    ORDER BY category_id, created_at DESC
                """).fetchall()

            # 按分类分组
            import json
            items_by_category = {}
            for row in rows:
                row_dict = dict(row)
                cat_id = row_dict['category_id']
                # 解析 JSON 域名列表 - M13 修复: 添加 schema 验证
                try:
                    parsed = json.loads(row_dict['domains'])
                    row_dict['domains'] = validate_string_list(parsed, "domains") or []
                except (json.JSONDecodeError, TypeError) as e:
                    logger.warning(f"Failed to parse domains JSON for {row_dict.get('item_id', 'unknown')}: {e}")
                    row_dict['domains'] = []
                row_dict['sample_domains'] = row_dict['domains'][:5]

                if cat_id not in items_by_category:
                    items_by_category[cat_id] = []
                items_by_category[cat_id].append(row_dict)

            return items_by_category

    def add_custom_category_item(self, category_id: str, item_id: str, name: str,
                                  domains: List[str]) -> int:
        """添加自定义分类项目"""
        import json
        domain_count = len(domains)
        domains_json = json.dumps(domains)

        with self._get_conn() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO custom_category_items (category_id, item_id, name, domains, domain_count)
                VALUES (?, ?, ?, ?, ?)
            """, (category_id, item_id, name, domains_json, domain_count))
            conn.commit()
            return cursor.lastrowid

    def delete_custom_category_item(self, item_id: str) -> bool:
        """删除自定义分类项目"""
        with self._get_conn() as conn:
            cursor = conn.cursor()
            cursor.execute("DELETE FROM custom_category_items WHERE item_id = ?", (item_id,))
            conn.commit()
            return cursor.rowcount > 0

    def get_custom_category_item(self, item_id: str) -> Optional[Dict]:
        """获取单个自定义分类项目"""
        with self._get_conn() as conn:
            cursor = conn.cursor()
            row = cursor.execute("""
                SELECT id, category_id, item_id, name, domains, domain_count, created_at
                FROM custom_category_items
                WHERE item_id = ?
            """, (item_id,)).fetchone()

            if row:
                import json
                row_dict = dict(row)
                # M13 修复: 添加 schema 验证
                try:
                    parsed = json.loads(row_dict['domains'])
                    row_dict['domains'] = validate_string_list(parsed, "domains") or []
                except (json.JSONDecodeError, TypeError) as e:
                    logger.warning(f"Failed to parse domains JSON for {row_dict.get('item_id', 'unknown')}: {e}")
                    row_dict['domains'] = []
                return row_dict
            return None

    # ============ 设置管理 ============

    def get_setting(self, key: str, default: str = None) -> Optional[str]:
        """获取设置值"""
        with self._get_conn() as conn:
            cursor = conn.cursor()
            row = cursor.execute(
                "SELECT value FROM settings WHERE key = ?", (key,)
            ).fetchone()
            return row[0] if row else default

    def set_setting(self, key: str, value: str) -> bool:
        """设置或更新设置值"""
        with self._get_conn() as conn:
            cursor = conn.cursor()
            # 使用 INSERT OR REPLACE 兼容 SQLCipher
            cursor.execute("""
                INSERT OR REPLACE INTO settings (key, value, updated_at)
                VALUES (?, ?, CURRENT_TIMESTAMP)
            """, (key, value))
            conn.commit()
            return True

    def get_all_settings(self) -> Dict[str, str]:
        """获取所有设置"""
        with self._get_conn() as conn:
            cursor = conn.cursor()
            rows = cursor.execute("SELECT key, value FROM settings").fetchall()
            return {row[0]: row[1] for row in rows}

    # ============ 管理员认证 ============

    def is_admin_setup(self) -> bool:
        """检查管理员密码是否已设置"""
        with self._get_conn() as conn:
            cursor = conn.cursor()
            row = cursor.execute(
                "SELECT id FROM admin_auth WHERE id = 1"
            ).fetchone()
            return row is not None

    def set_admin_password(self, password_hash: str) -> bool:
        """设置或更新管理员密码哈希"""
        with self._get_conn() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT OR REPLACE INTO admin_auth
                (id, password_hash, updated_at)
                VALUES (1, ?, CURRENT_TIMESTAMP)
            """, (password_hash,))
            conn.commit()
            return True

    def get_admin_password_hash(self) -> Optional[str]:
        """获取管理员密码哈希"""
        with self._get_conn() as conn:
            cursor = conn.cursor()
            row = cursor.execute(
                "SELECT password_hash FROM admin_auth WHERE id = 1"
            ).fetchone()
            return row[0] if row else None

    def get_or_create_jwt_secret(self) -> str:
        """获取 JWT 密钥，不存在则创建

        M16 修复: 优先使用环境变量 JWT_SECRET_KEY，回退到数据库存储
        """
        import secrets as sec
        # 优先使用环境变量（更安全，不存储在数据库）
        env_secret = os.environ.get("JWT_SECRET_KEY")
        if env_secret:
            return env_secret
        # 回退到数据库存储
        secret = self.get_setting("jwt_secret_key")
        if not secret:
            secret = sec.token_urlsafe(32)
            self.set_setting("jwt_secret_key", secret)
        return secret

    # ============ Custom Egress 方法 ============

    def get_custom_egress_list(self, enabled_only: bool = False) -> List[Dict]:
        """获取所有自定义出口"""
        with self._get_conn() as conn:
            cursor = conn.cursor()
            if enabled_only:
                rows = cursor.execute(
                    "SELECT * FROM custom_egress WHERE enabled = 1 ORDER BY tag"
                ).fetchall()
            else:
                rows = cursor.execute(
                    "SELECT * FROM custom_egress ORDER BY tag"
                ).fetchall()
            columns = [desc[0] for desc in cursor.description]
            result = []
            for row in rows:
                item = dict(zip(columns, row))
                # 解析 reserved JSON - C3 修复: 使用具体异常类型
                # M13 修复: 添加 schema 验证
                if item.get("reserved"):
                    try:
                        parsed = json.loads(item["reserved"])
                        item["reserved"] = validate_reserved_bytes(parsed)
                    except (json.JSONDecodeError, TypeError) as e:
                        logger.warning(f"Failed to parse reserved JSON for {item.get('tag', 'unknown')}: {e}")
                        item["reserved"] = None
                result.append(item)
            return result

    def get_custom_egress(self, tag: str) -> Optional[Dict]:
        """根据 tag 获取自定义出口"""
        with self._get_conn() as conn:
            cursor = conn.cursor()
            row = cursor.execute(
                "SELECT * FROM custom_egress WHERE tag = ?", (tag,)
            ).fetchone()
            if not row:
                return None
            columns = [desc[0] for desc in cursor.description]
            item = dict(zip(columns, row))
            # C3 修复: 使用具体异常类型
            # M13 修复: 添加 schema 验证
            if item.get("reserved"):
                try:
                    parsed = json.loads(item["reserved"])
                    item["reserved"] = validate_reserved_bytes(parsed)
                except (json.JSONDecodeError, TypeError) as e:
                    logger.warning(f"Failed to parse reserved JSON for {tag}: {e}")
                    item["reserved"] = None
            return item

    def add_custom_egress(self, tag: str, server: str, private_key: str,
                          public_key: str, address: str, description: str = "",
                          port: int = 51820, mtu: int = 1420, dns: str = "1.1.1.1",
                          pre_shared_key: Optional[str] = None,
                          reserved: Optional[List[int]] = None) -> int:
        """添加自定义出口"""
        with self._get_conn() as conn:
            cursor = conn.cursor()
            reserved_json = json.dumps(reserved) if reserved else None
            cursor.execute("""
                INSERT INTO custom_egress
                (tag, description, server, port, private_key, public_key, address, mtu, dns, pre_shared_key, reserved)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (tag, description, server, port, private_key, public_key, address, mtu, dns, pre_shared_key, reserved_json))
            conn.commit()
            return cursor.lastrowid

    def update_custom_egress(self, tag: str, **kwargs) -> bool:
        """更新自定义出口"""
        allowed_fields = {"description", "server", "port", "private_key", "public_key",
                          "address", "mtu", "dns", "pre_shared_key", "reserved", "enabled"}
        updates = []
        values = []
        for key, value in kwargs.items():
            if key in allowed_fields and value is not None:
                if key == "reserved":
                    value = json.dumps(value) if value else None
                updates.append(f"{key} = ?")
                values.append(value)
        if not updates:
            return False
        updates.append("updated_at = CURRENT_TIMESTAMP")
        values.append(tag)
        with self._get_conn() as conn:
            cursor = conn.cursor()
            cursor.execute(f"""
                UPDATE custom_egress SET {", ".join(updates)} WHERE tag = ?
            """, values)
            conn.commit()
            return cursor.rowcount > 0

    def delete_custom_egress(self, tag: str) -> bool:
        """删除自定义出口"""
        with self._get_conn() as conn:
            cursor = conn.cursor()
            cursor.execute("DELETE FROM custom_egress WHERE tag = ?", (tag,))
            conn.commit()
            return cursor.rowcount > 0

    # ============ Remote Rule Sets 管理 ============

    def get_remote_rule_sets(self, enabled_only: bool = False, category: Optional[str] = None) -> List[Dict]:
        """获取远程规则集列表"""
        with self._get_conn() as conn:
            cursor = conn.cursor()
            query = "SELECT * FROM remote_rule_sets"
            conditions = []
            params = []

            if enabled_only:
                conditions.append("enabled = 1")
            if category:
                conditions.append("category = ?")
                params.append(category)

            if conditions:
                query += " WHERE " + " AND ".join(conditions)
            query += " ORDER BY priority DESC, name"

            rows = cursor.execute(query, params).fetchall()
            columns = [desc[0] for desc in cursor.description]
            return [dict(zip(columns, row)) for row in rows]

    def get_remote_rule_set(self, tag: str) -> Optional[Dict]:
        """获取单个远程规则集"""
        with self._get_conn() as conn:
            cursor = conn.cursor()
            row = cursor.execute(
                "SELECT * FROM remote_rule_sets WHERE tag = ?", (tag,)
            ).fetchone()
            if not row:
                return None
            columns = [desc[0] for desc in cursor.description]
            return dict(zip(columns, row))

    def toggle_remote_rule_set(self, tag: str) -> bool:
        """切换远程规则集启用状态"""
        with self._get_conn() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                UPDATE remote_rule_sets
                SET enabled = 1 - enabled, updated_at = CURRENT_TIMESTAMP
                WHERE tag = ?
            """, (tag,))
            conn.commit()
            return cursor.rowcount > 0

    def update_remote_rule_set(self, tag: str, **kwargs) -> bool:
        """更新远程规则集"""
        allowed_fields = {"name", "description", "url", "format", "outbound",
                          "enabled", "priority", "category", "region",
                          "last_updated", "domain_count"}
        updates = []
        values = []
        for key, value in kwargs.items():
            if key in allowed_fields and value is not None:
                updates.append(f"{key} = ?")
                values.append(value)
        if not updates:
            return False
        updates.append("updated_at = CURRENT_TIMESTAMP")
        values.append(tag)
        with self._get_conn() as conn:
            cursor = conn.cursor()
            cursor.execute(f"""
                UPDATE remote_rule_sets SET {", ".join(updates)} WHERE tag = ?
            """, values)
            conn.commit()
            return cursor.rowcount > 0

    def add_remote_rule_set(self, tag: str, name: str, url: str,
                            description: str = "", format: str = "adblock",
                            outbound: str = "block", category: str = "general",
                            region: Optional[str] = None, priority: int = 0) -> int:
        """添加远程规则集"""
        with self._get_conn() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO remote_rule_sets
                (tag, name, description, url, format, outbound, category, region, priority)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (tag, name, description, url, format, outbound, category, region, priority))
            conn.commit()
            return cursor.lastrowid

    def delete_remote_rule_set(self, tag: str) -> bool:
        """删除远程规则集"""
        with self._get_conn() as conn:
            cursor = conn.cursor()
            cursor.execute("DELETE FROM remote_rule_sets WHERE tag = ?", (tag,))
            conn.commit()
            return cursor.rowcount > 0

    # ============ Direct Egress 管理（多 direct 出口）============

    def get_direct_egress_list(self, enabled_only: bool = False) -> List[Dict]:
        """获取所有 direct 出口"""
        with self._get_conn() as conn:
            cursor = conn.cursor()
            if enabled_only:
                rows = cursor.execute(
                    "SELECT * FROM direct_egress WHERE enabled = 1 ORDER BY tag"
                ).fetchall()
            else:
                rows = cursor.execute(
                    "SELECT * FROM direct_egress ORDER BY tag"
                ).fetchall()
            columns = [desc[0] for desc in cursor.description]
            return [dict(zip(columns, row)) for row in rows]

    def get_direct_egress(self, tag: str) -> Optional[Dict]:
        """根据 tag 获取 direct 出口"""
        with self._get_conn() as conn:
            cursor = conn.cursor()
            row = cursor.execute(
                "SELECT * FROM direct_egress WHERE tag = ?", (tag,)
            ).fetchone()
            if not row:
                return None
            columns = [desc[0] for desc in cursor.description]
            return dict(zip(columns, row))

    def add_direct_egress(self, tag: str, description: str = "",
                          bind_interface: Optional[str] = None,
                          inet4_bind_address: Optional[str] = None,
                          inet6_bind_address: Optional[str] = None) -> int:
        """添加 direct 出口"""
        with self._get_conn() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO direct_egress
                (tag, description, bind_interface, inet4_bind_address, inet6_bind_address)
                VALUES (?, ?, ?, ?, ?)
            """, (tag, description, bind_interface, inet4_bind_address, inet6_bind_address))
            conn.commit()
            return cursor.lastrowid

    def update_direct_egress(self, tag: str, **kwargs) -> bool:
        """更新 direct 出口"""
        allowed_fields = {"description", "bind_interface", "inet4_bind_address",
                          "inet6_bind_address", "enabled"}
        updates = []
        values = []
        for key, value in kwargs.items():
            if key in allowed_fields:
                updates.append(f"{key} = ?")
                values.append(value)
        if not updates:
            return False
        updates.append("updated_at = CURRENT_TIMESTAMP")
        values.append(tag)
        with self._get_conn() as conn:
            cursor = conn.cursor()
            cursor.execute(f"""
                UPDATE direct_egress SET {", ".join(updates)} WHERE tag = ?
            """, values)
            conn.commit()
            return cursor.rowcount > 0

    def delete_direct_egress(self, tag: str) -> bool:
        """删除 direct 出口"""
        with self._get_conn() as conn:
            cursor = conn.cursor()
            cursor.execute("DELETE FROM direct_egress WHERE tag = ?", (tag,))
            conn.commit()
            return cursor.rowcount > 0

    # ============ OpenVPN Egress 管理（直接接口绑定）============

    OPENVPN_TUN_DEVICE_START = 10  # TUN 设备编号起始值 (tun10, tun11, ...)

    def get_openvpn_egress_list(self, enabled_only: bool = False) -> List[Dict]:
        """获取所有 OpenVPN 出口"""
        with self._get_conn() as conn:
            cursor = conn.cursor()
            if enabled_only:
                rows = cursor.execute(
                    "SELECT * FROM openvpn_egress WHERE enabled = 1 ORDER BY tag"
                ).fetchall()
            else:
                rows = cursor.execute(
                    "SELECT * FROM openvpn_egress ORDER BY tag"
                ).fetchall()
            columns = [desc[0] for desc in cursor.description]
            result = []
            for row in rows:
                item = dict(zip(columns, row))
                # 解析 extra_options JSON - C3 修复: 使用具体异常类型
                # M13 修复: 添加 schema 验证
                if item.get("extra_options"):
                    try:
                        parsed = json.loads(item["extra_options"])
                        item["extra_options"] = validate_string_list(parsed, "extra_options")
                    except (json.JSONDecodeError, TypeError) as e:
                        logger.warning(f"Failed to parse extra_options JSON for {item.get('tag', 'unknown')}: {e}")
                        item["extra_options"] = None
                result.append(item)
            return result

    def get_openvpn_egress(self, tag: str) -> Optional[Dict]:
        """根据 tag 获取 OpenVPN 出口"""
        with self._get_conn() as conn:
            cursor = conn.cursor()
            row = cursor.execute(
                "SELECT * FROM openvpn_egress WHERE tag = ?", (tag,)
            ).fetchone()
            if not row:
                return None
            columns = [desc[0] for desc in cursor.description]
            item = dict(zip(columns, row))
            # C3 修复: 使用具体异常类型
            # M13 修复: 添加 schema 验证
            if item.get("extra_options"):
                try:
                    parsed = json.loads(item["extra_options"])
                    item["extra_options"] = validate_string_list(parsed, "extra_options")
                except (json.JSONDecodeError, TypeError) as e:
                    logger.warning(f"Failed to parse extra_options JSON for {tag}: {e}")
                    item["extra_options"] = None
            return item

    def get_next_openvpn_tun_device(self) -> str:
        """获取下一个可用的 TUN 设备名（从 tun10 开始）

        Returns:
            TUN 设备名，如 "tun10", "tun11", ...
        """
        with self._get_conn() as conn:
            cursor = conn.cursor()
            # 获取所有现有的 tun_device
            rows = cursor.execute(
                "SELECT tun_device FROM openvpn_egress WHERE tun_device IS NOT NULL"
            ).fetchall()

            if not rows:
                return f"tun{self.OPENVPN_TUN_DEVICE_START}"

            # 提取所有使用中的设备编号
            used_numbers = set()
            for row in rows:
                tun_device = row[0]
                if tun_device and tun_device.startswith("tun"):
                    try:
                        num = int(tun_device[3:])
                        used_numbers.add(num)
                    except ValueError:
                        continue

            # 从起始值开始找第一个未使用的编号
            next_num = self.OPENVPN_TUN_DEVICE_START
            while next_num in used_numbers:
                next_num += 1
                # 安全上限检查
                if next_num > 255:
                    raise ValueError("No available TUN devices (exceeded tun255)")

            return f"tun{next_num}"

    def add_openvpn_egress(
        self,
        tag: str,
        remote_host: str,
        ca_cert: str,
        description: str = "",
        protocol: str = "udp",
        remote_port: int = 1194,
        client_cert: Optional[str] = None,
        client_key: Optional[str] = None,
        tls_auth: Optional[str] = None,
        tls_crypt: Optional[str] = None,
        crl_verify: Optional[str] = None,
        auth_user: Optional[str] = None,
        auth_pass: Optional[str] = None,
        cipher: str = "AES-256-GCM",
        auth: str = "SHA256",
        compress: Optional[str] = None,
        extra_options: Optional[List[str]] = None
    ) -> int:
        """添加 OpenVPN 出口

        Returns:
            新创建记录的 ID
        """
        tun_device = self.get_next_openvpn_tun_device()
        extra_options_json = json.dumps(extra_options) if extra_options else None

        with self._get_conn() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO openvpn_egress
                (tag, description, protocol, remote_host, remote_port,
                 ca_cert, client_cert, client_key, tls_auth, tls_crypt, crl_verify,
                 auth_user, auth_pass, cipher, auth, compress, extra_options, tun_device)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (tag, description, protocol, remote_host, remote_port,
                  ca_cert, client_cert, client_key, tls_auth, tls_crypt, crl_verify,
                  auth_user, auth_pass, cipher, auth, compress, extra_options_json, tun_device))
            conn.commit()
            return cursor.lastrowid

    def update_openvpn_egress(self, tag: str, **kwargs) -> bool:
        """更新 OpenVPN 出口"""
        allowed_fields = {
            "description", "protocol", "remote_host", "remote_port",
            "ca_cert", "client_cert", "client_key", "tls_auth", "tls_crypt", "crl_verify",
            "auth_user", "auth_pass", "cipher", "auth", "compress",
            "extra_options", "enabled"
        }
        updates = []
        values = []
        for key, value in kwargs.items():
            if key in allowed_fields:
                if key == "extra_options":
                    value = json.dumps(value) if value else None
                updates.append(f"{key} = ?")
                values.append(value)
        if not updates:
            return False
        updates.append("updated_at = CURRENT_TIMESTAMP")
        values.append(tag)
        with self._get_conn() as conn:
            cursor = conn.cursor()
            cursor.execute(f"""
                UPDATE openvpn_egress SET {", ".join(updates)} WHERE tag = ?
            """, values)
            conn.commit()
            return cursor.rowcount > 0

    def delete_openvpn_egress(self, tag: str) -> bool:
        """删除 OpenVPN 出口"""
        with self._get_conn() as conn:
            cursor = conn.cursor()
            cursor.execute("DELETE FROM openvpn_egress WHERE tag = ?", (tag,))
            conn.commit()
            return cursor.rowcount > 0

    # ============ V2Ray Egress 管理 (VLESS only - Xray-lite) ============

    # SOCKS 端口起始值（可通过环境变量配置，与 OpenVPN 37001 错开）
    V2RAY_EGRESS_SOCKS_PORT_START = int(os.environ.get("V2RAY_SOCKS_PORT_BASE", "37101"))

    def get_next_v2ray_egress_socks_port(self) -> int:
        """获取下一个可用的 SOCKS 端口（从 V2RAY_EGRESS_SOCKS_PORT_START 开始）"""
        with self._get_conn() as conn:
            cursor = conn.cursor()
            row = cursor.execute(
                "SELECT MAX(socks_port) FROM v2ray_egress"
            ).fetchone()
            max_port = row[0] if row and row[0] else None
            if max_port is None:
                return self.V2RAY_EGRESS_SOCKS_PORT_START
            next_port = max_port + 1
            # H10: 端口边界检查
            if next_port > 65535:
                raise ValueError("No available SOCKS ports (exceeded 65535)")
            return next_port

    def get_v2ray_egress_list(self, enabled_only: bool = False, protocol: Optional[str] = None) -> List[Dict]:
        """获取所有 V2Ray 出口

        Args:
            enabled_only: 只返回启用的出口
            protocol: 过滤协议类型 (vmess, vless, trojan)
        """
        with self._get_conn() as conn:
            cursor = conn.cursor()
            query = "SELECT * FROM v2ray_egress"
            conditions = []
            params = []

            if enabled_only:
                conditions.append("enabled = 1")
            if protocol:
                conditions.append("protocol = ?")
                params.append(protocol)

            if conditions:
                query += " WHERE " + " AND ".join(conditions)
            query += " ORDER BY tag"

            rows = cursor.execute(query, params).fetchall()
            columns = [desc[0] for desc in cursor.description]
            result = []
            for row in rows:
                item = dict(zip(columns, row))
                # 解析 JSON 字段 - C3 修复: 使用具体异常类型
                # M13 修复: 添加 schema 验证
                for json_field in ["tls_alpn", "transport_config"]:
                    if item.get(json_field):
                        try:
                            parsed = json.loads(item[json_field])
                            if json_field == "tls_alpn":
                                item[json_field] = validate_string_list(parsed, "tls_alpn")
                            elif json_field == "transport_config":
                                item[json_field] = validate_dict(parsed, "transport_config")
                        except (json.JSONDecodeError, TypeError) as e:
                            # 降级为 debug（避免日志刷屏，这些解析错误通常不影响功能）
                            logger.debug(f"Failed to parse {json_field} JSON for {item.get('tag', 'unknown')}: {e}")
                result.append(item)
            return result

    def get_v2ray_egress(self, tag: str) -> Optional[Dict]:
        """根据 tag 获取 V2Ray 出口"""
        with self._get_conn() as conn:
            cursor = conn.cursor()
            row = cursor.execute(
                "SELECT * FROM v2ray_egress WHERE tag = ?", (tag,)
            ).fetchone()
            if not row:
                return None
            columns = [desc[0] for desc in cursor.description]
            item = dict(zip(columns, row))
            # 解析 JSON 字段 - C3 修复: 使用具体异常类型
            # M13 修复: 添加 schema 验证
            for json_field in ["tls_alpn", "transport_config"]:
                if item.get(json_field):
                    try:
                        parsed = json.loads(item[json_field])
                        if json_field == "tls_alpn":
                            item[json_field] = validate_string_list(parsed, "tls_alpn")
                        elif json_field == "transport_config":
                            item[json_field] = validate_dict(parsed, "transport_config")
                    except (json.JSONDecodeError, TypeError) as e:
                        # 降级为 debug（避免日志刷屏）
                        logger.debug(f"Failed to parse {json_field} JSON for {tag}: {e}")
            return item

    def add_v2ray_egress(
        self,
        tag: str,
        protocol: str,
        server: str,
        server_port: int = 443,
        description: str = "",
        # Auth
        uuid: Optional[str] = None,
        password: Optional[str] = None,
        # VMess specific
        security: str = "auto",
        alter_id: int = 0,
        # VLESS specific
        flow: Optional[str] = None,
        # TLS
        tls_enabled: bool = True,
        tls_sni: Optional[str] = None,
        tls_alpn: Optional[List[str]] = None,
        tls_allow_insecure: bool = False,
        tls_fingerprint: Optional[str] = None,
        # REALITY
        reality_enabled: bool = False,
        reality_public_key: Optional[str] = None,
        reality_short_id: Optional[str] = None,
        # Transport
        transport_type: str = "tcp",
        transport_config: Optional[Dict] = None,
        # Multiplex
        multiplex_enabled: bool = False,
        multiplex_protocol: Optional[str] = None,
        multiplex_max_connections: Optional[int] = None,
        multiplex_min_streams: Optional[int] = None,
        multiplex_max_streams: Optional[int] = None
    ) -> int:
        """添加 V2Ray 出口

        Returns:
            新创建记录的 ID
        """
        # [Xray-lite] 仅支持 VLESS 协议
        if protocol != "vless":
            raise ValueError(
                f"Only 'vless' protocol is supported in Xray-lite. Got: '{protocol}'. "
                "VMess and Trojan have been removed. See docs/VMESS_TROJAN_MIGRATION.md"
            )

        # 自动分配 SOCKS 端口
        socks_port = self.get_next_v2ray_egress_socks_port()
        tls_alpn_json = json.dumps(tls_alpn) if tls_alpn else None
        transport_config_json = json.dumps(transport_config) if transport_config else None

        with self._get_conn() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO v2ray_egress
                (tag, description, protocol, server, server_port,
                 uuid, password, security, alter_id, flow,
                 tls_enabled, tls_sni, tls_alpn, tls_allow_insecure, tls_fingerprint,
                 reality_enabled, reality_public_key, reality_short_id,
                 transport_type, transport_config,
                 multiplex_enabled, multiplex_protocol, multiplex_max_connections,
                 multiplex_min_streams, multiplex_max_streams, socks_port)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (tag, description, protocol, server, server_port,
                  uuid, password, security, alter_id, flow,
                  1 if tls_enabled else 0, tls_sni, tls_alpn_json,
                  1 if tls_allow_insecure else 0, tls_fingerprint,
                  1 if reality_enabled else 0, reality_public_key, reality_short_id,
                  transport_type, transport_config_json,
                  1 if multiplex_enabled else 0, multiplex_protocol, multiplex_max_connections,
                  multiplex_min_streams, multiplex_max_streams, socks_port))
            conn.commit()
            return cursor.lastrowid

    def update_v2ray_egress(self, tag: str, **kwargs) -> bool:
        """更新 V2Ray 出口"""
        allowed_fields = {
            "description", "protocol", "server", "server_port",
            "uuid", "password", "security", "alter_id", "flow",
            "tls_enabled", "tls_sni", "tls_alpn", "tls_allow_insecure", "tls_fingerprint",
            "reality_enabled", "reality_public_key", "reality_short_id",
            "transport_type", "transport_config",
            "multiplex_enabled", "multiplex_protocol", "multiplex_max_connections",
            "multiplex_min_streams", "multiplex_max_streams", "socks_port", "enabled"
        }
        updates = []
        values = []
        for key, value in kwargs.items():
            if key in allowed_fields:
                if key in ["tls_alpn", "transport_config"]:
                    value = json.dumps(value) if value else None
                updates.append(f"{key} = ?")
                values.append(value)
        if not updates:
            return False
        updates.append("updated_at = CURRENT_TIMESTAMP")
        values.append(tag)
        with self._get_conn() as conn:
            cursor = conn.cursor()
            cursor.execute(f"""
                UPDATE v2ray_egress SET {", ".join(updates)} WHERE tag = ?
            """, values)
            conn.commit()
            return cursor.rowcount > 0

    def delete_v2ray_egress(self, tag: str) -> bool:
        """删除 V2Ray 出口"""
        with self._get_conn() as conn:
            cursor = conn.cursor()
            cursor.execute("DELETE FROM v2ray_egress WHERE tag = ?", (tag,))
            conn.commit()
            return cursor.rowcount > 0

    # ============ WARP 出口 ============

    def get_warp_egress_list(self, enabled_only: bool = False) -> List[Dict]:
        """获取所有 WARP 出口"""
        with self._get_conn() as conn:
            cursor = conn.cursor()
            if enabled_only:
                rows = cursor.execute(
                    "SELECT * FROM warp_egress WHERE enabled = 1 ORDER BY tag"
                ).fetchall()
            else:
                rows = cursor.execute(
                    "SELECT * FROM warp_egress ORDER BY tag"
                ).fetchall()
            columns = [desc[0] for desc in cursor.description]
            return [dict(zip(columns, row)) for row in rows]

    def get_warp_egress(self, tag: str) -> Optional[Dict]:
        """根据 tag 获取 WARP 出口"""
        with self._get_conn() as conn:
            cursor = conn.cursor()
            row = cursor.execute(
                "SELECT * FROM warp_egress WHERE tag = ?", (tag,)
            ).fetchone()
            if not row:
                return None
            columns = [desc[0] for desc in cursor.description]
            return dict(zip(columns, row))

    def get_next_warp_socks_port(self) -> int:
        """获取下一个可用的 WARP SOCKS 端口（可通过环境变量配置起始端口）"""
        # WARP SOCKS port start (configurable via environment)
        WARP_SOCKS_PORT_START = int(os.environ.get("WARP_MASQUE_PORT_BASE", "38001"))
        with self._get_conn() as conn:
            cursor = conn.cursor()
            row = cursor.execute(
                "SELECT MAX(socks_port) FROM warp_egress"
            ).fetchone()
            max_port = row[0] if row and row[0] else None
            if max_port is None:
                return WARP_SOCKS_PORT_START
            next_port = max_port + 1
            # H10 修复: 检查端口溢出
            if next_port > 65535:
                raise ValueError(f"WARP SOCKS port overflow: {next_port} > 65535")
            return next_port

    def add_warp_egress(
        self,
        tag: str,
        description: str = "",
        config_path: Optional[str] = None,
        license_key: Optional[str] = None,
        account_type: str = "free",
        endpoint_v4: Optional[str] = None,
        endpoint_v6: Optional[str] = None,
        enabled: bool = True,
        account_id: Optional[str] = None
    ) -> int:
        """添加 WARP 出口 (Phase 3: WireGuard only, protocol/mode/socks_port removed)"""
        with self._get_conn() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO warp_egress
                (tag, description, config_path, license_key, account_type,
                 endpoint_v4, endpoint_v6, enabled, account_id)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                tag, description, config_path, license_key, account_type,
                endpoint_v4, endpoint_v6,
                1 if enabled else 0,
                account_id
            ))
            conn.commit()
            return cursor.lastrowid

    def update_warp_egress(self, tag: str, **kwargs) -> bool:
        """更新 WARP 出口 (Phase 3: WireGuard only)"""
        allowed_fields = {
            "description", "config_path", "license_key", "account_type",
            "endpoint_v4", "endpoint_v6", "enabled", "account_id"
            # Phase 3: Removed protocol, mode, socks_port
        }
        updates = {k: v for k, v in kwargs.items() if k in allowed_fields}
        if not updates:
            return False

        # 处理 enabled 布尔值
        if "enabled" in updates:
            updates["enabled"] = 1 if updates["enabled"] else 0

        set_clause = ", ".join([f"{k} = ?" for k in updates.keys()])
        values = list(updates.values()) + [tag]

        with self._get_conn() as conn:
            cursor = conn.cursor()
            cursor.execute(
                f"UPDATE warp_egress SET {set_clause}, updated_at = CURRENT_TIMESTAMP WHERE tag = ?",
                values
            )
            conn.commit()
            return cursor.rowcount > 0

    def delete_warp_egress(self, tag: str) -> bool:
        """删除 WARP 出口"""
        with self._get_conn() as conn:
            cursor = conn.cursor()
            cursor.execute("DELETE FROM warp_egress WHERE tag = ?", (tag,))
            conn.commit()
            return cursor.rowcount > 0

    # ============ 出口组（负载均衡/故障转移） ============

    def get_outbound_groups(self, enabled_only: bool = False) -> List[Dict]:
        """获取所有出口组"""
        with self._get_conn() as conn:
            cursor = conn.cursor()
            if enabled_only:
                rows = cursor.execute(
                    "SELECT * FROM outbound_groups WHERE enabled = 1 ORDER BY tag"
                ).fetchall()
            else:
                rows = cursor.execute(
                    "SELECT * FROM outbound_groups ORDER BY tag"
                ).fetchall()
            columns = [desc[0] for desc in cursor.description]
            result = []
            for row in rows:
                item = dict(zip(columns, row))
                # 解析 JSON 字段
                if item.get("members"):
                    try:
                        item["members"] = json.loads(item["members"])
                    except (json.JSONDecodeError, TypeError):
                        item["members"] = []
                if item.get("weights"):
                    try:
                        item["weights"] = json.loads(item["weights"])
                    except (json.JSONDecodeError, TypeError):
                        item["weights"] = None
                result.append(item)
            return result

    def get_outbound_group(self, tag: str) -> Optional[Dict]:
        """根据 tag 获取单个出口组"""
        with self._get_conn() as conn:
            cursor = conn.cursor()
            row = cursor.execute(
                "SELECT * FROM outbound_groups WHERE tag = ?", (tag,)
            ).fetchone()
            if not row:
                return None
            columns = [desc[0] for desc in cursor.description]
            item = dict(zip(columns, row))
            # 解析 JSON 字段
            if item.get("members"):
                try:
                    item["members"] = json.loads(item["members"])
                except (json.JSONDecodeError, TypeError):
                    item["members"] = []
            if item.get("weights"):
                try:
                    item["weights"] = json.loads(item["weights"])
                except (json.JSONDecodeError, TypeError):
                    item["weights"] = None
            return item

    def get_next_routing_table(self) -> Optional[int]:
        """获取下一个可用的 ECMP 路由表号（200-299 范围）

        Phase 8 Fix: 添加上限验证，防止表号超出 ECMP 范围并与 DSCP/Relay/Peer 表冲突。

        Returns:
            可用的表号 (200-299)，如果范围已耗尽则返回 None

        Table Ranges:
            200-299: ECMP outbound groups
            300-363: DSCP terminal routing
            400-463: Relay node forwarding
            500-599: Peer node tunnels
        """
        ECMP_TABLE_MIN = 200
        ECMP_TABLE_MAX = 299

        with self._get_conn() as conn:
            cursor = conn.cursor()
            # 获取所有已使用的 ECMP 表号
            rows = cursor.execute(
                "SELECT routing_table FROM outbound_groups WHERE routing_table IS NOT NULL"
            ).fetchall()
            used_tables = {row[0] for row in rows}

            # 查找第一个可用的表号（支持表号复用）
            for table in range(ECMP_TABLE_MIN, ECMP_TABLE_MAX + 1):
                if table not in used_tables:
                    return table

            # Phase 8: 范围耗尽，返回 None
            return None

    def get_all_egress_tags(self) -> set:
        """[PERF-001] 获取所有有效的出口 tag（用于验证成员）

        使用 UNION ALL 单次查询优化（替代 N+1 查询模式）。
        包括：PIA profiles, custom egress, direct egress, OpenVPN, V2Ray, WARP, 已有的出口组
        """
        with self._get_conn() as conn:
            cursor = conn.cursor()
            # 使用 UNION ALL 单次查询获取所有出口 tag
            rows = cursor.execute("""
                SELECT name as tag FROM pia_profiles WHERE enabled = 1
                UNION ALL SELECT tag FROM custom_egress WHERE enabled = 1
                UNION ALL SELECT tag FROM direct_egress WHERE enabled = 1
                UNION ALL SELECT tag FROM openvpn_egress WHERE enabled = 1
                UNION ALL SELECT tag FROM v2ray_egress WHERE enabled = 1
                UNION ALL SELECT tag FROM warp_egress WHERE enabled = 1
                UNION ALL SELECT tag FROM outbound_groups WHERE enabled = 1
            """).fetchall()
            # 转换为 set 并添加内置出口
            tags = {row[0] for row in rows if row[0]}
            tags.add("direct")
            tags.add("block")
            return tags

    def tag_exists_in_any_egress(self, tag: str) -> bool:
        """检查 tag 是否已被任何出口类型使用"""
        with self._get_conn() as conn:
            cursor = conn.cursor()
            # 检查所有出口表
            tables = [
                ("pia_profiles", "name"),
                ("custom_egress", "tag"),
                ("direct_egress", "tag"),
                ("openvpn_egress", "tag"),
                ("v2ray_egress", "tag"),
                ("warp_egress", "tag"),
                ("outbound_groups", "tag"),
            ]
            for table, column in tables:
                row = cursor.execute(
                    f"SELECT 1 FROM {table} WHERE {column} = ?", (tag,)
                ).fetchone()
                if row:
                    return True
            # 检查内置出口
            if tag in ("direct", "block", "adblock"):
                return True
            return False

    def validate_group_members(
        self,
        members: List[str],
        exclude_tag: Optional[str] = None
    ) -> tuple:
        """验证成员有效性

        Args:
            members: 成员 tag 列表
            exclude_tag: 排除的 tag（用于编辑时排除自己）

        Returns:
            (valid: bool, error_msg: str, invalid_members: List[str])
        """
        valid_tags = self.get_all_egress_tags()
        if exclude_tag:
            valid_tags.discard(exclude_tag)

        invalid = []
        for member in members:
            if member not in valid_tags:
                invalid.append(member)

        if invalid:
            return False, f"无效的成员: {', '.join(invalid)}", invalid
        return True, "", []

    def check_circular_reference(
        self,
        tag: str,
        members: List[str],
        visited: Optional[set] = None
    ) -> tuple:
        """检测循环引用

        使用 DFS 检测是否存在 A -> B -> C -> A 的循环依赖。

        Args:
            tag: 当前组的 tag
            members: 当前组的成员列表
            visited: 已访问的节点（用于 DFS）

        Returns:
            (has_cycle: bool, cycle_path: List[str])
        """
        if visited is None:
            visited = set()

        # 检查自引用
        if tag in members:
            return True, [tag, tag]

        visited.add(tag)

        for member in members:
            # 检查成员是否是已访问的节点（形成环）
            if member in visited:
                return True, [tag, member]

            # 如果成员是出口组，递归检查
            group = self.get_outbound_group(member)
            if group:
                # 递归检查
                has_cycle, path = self.check_circular_reference(
                    member, group["members"], visited.copy()
                )
                if has_cycle:
                    return True, [tag] + path

        return False, []

    def add_outbound_group(
        self,
        tag: str,
        group_type: str,
        members: List[str],
        description: str = "",
        weights: Optional[Dict[str, int]] = None,
        health_check_url: str = "http://www.gstatic.com/generate_204",
        health_check_interval: int = 60,
        health_check_timeout: int = 5,
        enabled: bool = True
    ) -> int:
        """添加出口组

        Args:
            tag: 组标识（唯一）
            group_type: 组类型 ('loadbalance' 或 'failover')
            members: 成员出口 tag 列表
            description: 描述
            weights: 权重配置（仅 loadbalance 使用）
            health_check_url: 健康检查 URL
            health_check_interval: 健康检查间隔（秒）
            health_check_timeout: 健康检查超时（秒）
            enabled: 是否启用

        Returns:
            新创建的组 ID
        """
        # 自动分配路由表号
        routing_table = self.get_next_routing_table()

        # Phase 8 Fix: 检查表号分配是否成功
        if routing_table is None:
            raise ValueError(
                "无法分配路由表号：ECMP 表范围 (200-299) 已耗尽。"
                "请删除不再使用的出口组以释放表号。"
            )

        members_json = json.dumps(members)
        weights_json = json.dumps(weights) if weights else None

        with self._get_conn() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO outbound_groups
                (tag, description, type, members, weights,
                 health_check_url, health_check_interval, health_check_timeout,
                 routing_table, enabled)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                tag, description, group_type, members_json, weights_json,
                health_check_url, health_check_interval, health_check_timeout,
                routing_table, 1 if enabled else 0
            ))
            conn.commit()
            return cursor.lastrowid

    def update_outbound_group(self, tag: str, **kwargs) -> bool:
        """更新出口组

        支持的字段：description, members, weights,
        health_check_url, health_check_interval, health_check_timeout, enabled
        """
        allowed_fields = {
            "description", "members", "weights",
            "health_check_url", "health_check_interval", "health_check_timeout",
            "enabled"
        }
        updates = {k: v for k, v in kwargs.items() if k in allowed_fields}
        if not updates:
            return False

        # 处理特殊字段
        if "members" in updates:
            updates["members"] = json.dumps(updates["members"])
        if "weights" in updates:
            updates["weights"] = json.dumps(updates["weights"]) if updates["weights"] else None
        if "enabled" in updates:
            updates["enabled"] = 1 if updates["enabled"] else 0

        set_clause = ", ".join([f"{k} = ?" for k in updates.keys()])
        values = list(updates.values()) + [tag]

        with self._get_conn() as conn:
            cursor = conn.cursor()
            cursor.execute(
                f"UPDATE outbound_groups SET {set_clause}, updated_at = CURRENT_TIMESTAMP WHERE tag = ?",
                values
            )
            conn.commit()
            return cursor.rowcount > 0

    def delete_outbound_group(self, tag: str) -> bool:
        """删除出口组"""
        with self._get_conn() as conn:
            cursor = conn.cursor()
            cursor.execute("DELETE FROM outbound_groups WHERE tag = ?", (tag,))
            conn.commit()
            return cursor.rowcount > 0

    # ============ V2Ray Inbound 配置 ============

    def get_v2ray_inbound_config(self) -> Optional[Dict]:
        """获取 V2Ray 入口配置"""
        with self._get_conn() as conn:
            cursor = conn.cursor()
            row = cursor.execute(
                "SELECT * FROM v2ray_inbound_config WHERE id = 1"
            ).fetchone()
            if not row:
                return None
            columns = [desc[0] for desc in cursor.description]
            item = dict(zip(columns, row))
            # 解析 JSON 字段
            # M13 修复: 添加 schema 验证
            if item.get("transport_config"):
                try:
                    parsed = json.loads(item["transport_config"])
                    item["transport_config"] = validate_dict(parsed, "transport_config")
                except (json.JSONDecodeError, TypeError) as e:
                    # 降级为 debug（避免日志刷屏）
                    logger.debug(f"Failed to parse transport_config JSON: {e}")
            return item

    def set_v2ray_inbound_config(
        self,
        protocol: str,
        listen_port: int = 443,
        listen_address: str = "0.0.0.0",
        tls_enabled: bool = True,
        tls_cert_path: Optional[str] = None,
        tls_key_path: Optional[str] = None,
        tls_cert_content: Optional[str] = None,
        tls_key_content: Optional[str] = None,
        xtls_vision_enabled: int = 0,
        reality_enabled: int = 0,
        reality_private_key: Optional[str] = None,
        reality_public_key: Optional[str] = None,
        reality_short_ids: Optional[str] = None,
        reality_dest: Optional[str] = None,
        reality_server_names: Optional[str] = None,
        transport_type: str = "tcp",
        transport_config: Optional[Dict] = None,
        fallback_server: Optional[str] = None,
        fallback_port: Optional[int] = None,
        tun_device: str = "xray-tun0",
        tun_subnet: str = "10.24.0.0/24",
        enabled: bool = False,
        default_outbound: Optional[str] = None
    ) -> bool:
        """设置 V2Ray 入口配置（使用 Xray + TUN + TPROXY 架构）"""
        transport_config_json = json.dumps(transport_config) if transport_config else None

        with self._get_conn() as conn:
            cursor = conn.cursor()
            # 使用 UPSERT (INSERT OR REPLACE)
            cursor.execute("""
                INSERT OR REPLACE INTO v2ray_inbound_config
                (id, protocol, listen_address, listen_port,
                 tls_enabled, tls_cert_path, tls_key_path, tls_cert_content, tls_key_content,
                 xtls_vision_enabled, reality_enabled, reality_private_key, reality_public_key,
                 reality_short_ids, reality_dest, reality_server_names,
                 transport_type, transport_config, fallback_server, fallback_port,
                 tun_device, tun_subnet, enabled, default_outbound,
                 updated_at)
                VALUES (1, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
            """, (protocol, listen_address, listen_port,
                  1 if tls_enabled else 0, tls_cert_path, tls_key_path,
                  tls_cert_content, tls_key_content,
                  xtls_vision_enabled, reality_enabled, reality_private_key, reality_public_key,
                  reality_short_ids, reality_dest, reality_server_names,
                  transport_type, transport_config_json,
                  fallback_server, fallback_port,
                  tun_device, tun_subnet, 1 if enabled else 0, default_outbound))
            conn.commit()
            return True

    def update_v2ray_inbound_config(self, **kwargs) -> bool:
        """更新 V2Ray 入口配置的特定字段"""
        allowed_fields = {
            "protocol", "listen_address", "listen_port",
            "tls_enabled", "tls_cert_path", "tls_key_path",
            "tls_cert_content", "tls_key_content",
            "xtls_vision_enabled", "reality_enabled",
            "reality_private_key", "reality_public_key",
            "reality_short_ids", "reality_dest", "reality_server_names",
            "transport_type", "transport_config",
            "fallback_server", "fallback_port",
            "tun_device", "tun_subnet", "enabled",
            "default_outbound"
        }
        updates = []
        values = []
        for key, value in kwargs.items():
            if key in allowed_fields:
                if key == "transport_config":
                    value = json.dumps(value) if value else None
                updates.append(f"{key} = ?")
                values.append(value)
        if not updates:
            return False
        updates.append("updated_at = CURRENT_TIMESTAMP")
        with self._get_conn() as conn:
            cursor = conn.cursor()
            cursor.execute(f"""
                UPDATE v2ray_inbound_config SET {", ".join(updates)} WHERE id = 1
            """, values)
            conn.commit()
            return cursor.rowcount > 0

    # ============ V2Ray 用户管理 ============

    def get_v2ray_users(self, enabled_only: bool = True) -> List[Dict]:
        """获取所有 V2Ray 用户"""
        with self._get_conn() as conn:
            cursor = conn.cursor()
            if enabled_only:
                rows = cursor.execute(
                    "SELECT * FROM v2ray_users WHERE enabled = 1 ORDER BY name"
                ).fetchall()
            else:
                rows = cursor.execute(
                    "SELECT * FROM v2ray_users ORDER BY name"
                ).fetchall()
            columns = [desc[0] for desc in cursor.description]
            return [dict(zip(columns, row)) for row in rows]

    def get_v2ray_user(self, user_id: int) -> Optional[Dict]:
        """根据 ID 获取 V2Ray 用户"""
        with self._get_conn() as conn:
            cursor = conn.cursor()
            row = cursor.execute(
                "SELECT * FROM v2ray_users WHERE id = ?", (user_id,)
            ).fetchone()
            if not row:
                return None
            columns = [desc[0] for desc in cursor.description]
            return dict(zip(columns, row))

    def get_v2ray_user_by_name(self, name: str) -> Optional[Dict]:
        """根据名称获取 V2Ray 用户"""
        with self._get_conn() as conn:
            cursor = conn.cursor()
            row = cursor.execute(
                "SELECT * FROM v2ray_users WHERE name = ?", (name,)
            ).fetchone()
            if not row:
                return None
            columns = [desc[0] for desc in cursor.description]
            return dict(zip(columns, row))

    def add_v2ray_user(
        self,
        name: str,
        uuid: Optional[str] = None,
        password: Optional[str] = None,
        email: Optional[str] = None,
        alter_id: int = 0,
        flow: Optional[str] = None
    ) -> int:
        """添加 V2Ray 用户

        Returns:
            新创建记录的 ID
        """
        with self._get_conn() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO v2ray_users (name, uuid, password, email, alter_id, flow)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (name, uuid, password, email, alter_id, flow))
            conn.commit()
            return cursor.lastrowid

    def update_v2ray_user(self, user_id: int, **kwargs) -> bool:
        """更新 V2Ray 用户"""
        allowed_fields = {"name", "uuid", "password", "email", "alter_id", "flow", "enabled"}
        updates = []
        values = []
        for key, value in kwargs.items():
            if key in allowed_fields:
                updates.append(f"{key} = ?")
                values.append(value)
        if not updates:
            return False
        updates.append("updated_at = CURRENT_TIMESTAMP")
        values.append(user_id)
        with self._get_conn() as conn:
            cursor = conn.cursor()
            cursor.execute(f"""
                UPDATE v2ray_users SET {", ".join(updates)} WHERE id = ?
            """, values)
            conn.commit()
            return cursor.rowcount > 0

    def delete_v2ray_user(self, user_id: int) -> bool:
        """删除 V2Ray 用户"""
        with self._get_conn() as conn:
            cursor = conn.cursor()
            cursor.execute("DELETE FROM v2ray_users WHERE id = ?", (user_id,))
            conn.commit()
            return cursor.rowcount > 0

    # ============ Peer Nodes 管理 ============

    def get_peer_nodes(self, enabled_only: bool = False) -> List[Dict]:
        """获取所有对等节点"""
        with self._get_conn() as conn:
            cursor = conn.cursor()
            if enabled_only:
                rows = cursor.execute(
                    "SELECT * FROM peer_nodes WHERE enabled = 1 ORDER BY tag"
                ).fetchall()
            else:
                rows = cursor.execute(
                    "SELECT * FROM peer_nodes ORDER BY tag"
                ).fetchall()
            columns = [desc[0] for desc in cursor.description]
            return [dict(zip(columns, row)) for row in rows]

    def get_peer_node(self, tag: str) -> Optional[Dict]:
        """根据 tag 获取单个对等节点"""
        with self._get_conn() as conn:
            cursor = conn.cursor()
            row = cursor.execute(
                "SELECT * FROM peer_nodes WHERE tag = ?", (tag,)
            ).fetchone()
            if not row:
                return None
            columns = [desc[0] for desc in cursor.description]
            return dict(zip(columns, row))

    def get_peer_node_by_id(self, node_id: int) -> Optional[Dict]:
        """根据 ID 获取单个对等节点"""
        with self._get_conn() as conn:
            cursor = conn.cursor()
            row = cursor.execute(
                "SELECT * FROM peer_nodes WHERE id = ?", (node_id,)
            ).fetchone()
            if not row:
                return None
            columns = [desc[0] for desc in cursor.description]
            return dict(zip(columns, row))

    def add_peer_node(
        self,
        tag: str,
        name: str,
        endpoint: str,
        psk_hash: str = "",  # 已废弃，保留参数兼容
        psk_encrypted: Optional[str] = None,  # 已废弃
        description: str = "",
        api_port: Optional[int] = None,
        tunnel_type: str = "wireguard",
        # 隧道状态和 IP 参数（Phase 2 配对系统需要）
        tunnel_status: str = "disconnected",
        tunnel_interface: Optional[str] = None,  # Phase 11-Tunnel: WireGuard 接口名
        tunnel_local_ip: Optional[str] = None,
        tunnel_remote_ip: Optional[str] = None,
        tunnel_port: Optional[int] = None,
        tunnel_api_endpoint: Optional[str] = None,
        # WireGuard 参数
        wg_private_key: Optional[str] = None,
        wg_public_key: Optional[str] = None,
        wg_peer_public_key: Optional[str] = None,
        # Xray 参数
        xray_protocol: str = "vless",
        xray_uuid: Optional[str] = None,
        # REALITY 配置（本节点作为服务端）
        xray_reality_private_key: Optional[str] = None,
        xray_reality_public_key: Optional[str] = None,
        xray_reality_short_id: Optional[str] = None,
        xray_reality_dest: str = "www.microsoft.com:443",
        xray_reality_server_names: str = '["www.microsoft.com"]',
        # 对端 REALITY 配置（本节点作为客户端连接对端时使用）
        xray_peer_reality_public_key: Optional[str] = None,
        xray_peer_reality_short_id: Optional[str] = None,
        # XHTTP 传输配置
        xray_xhttp_path: str = "/",
        xray_xhttp_mode: str = "auto",
        xray_xhttp_host: Optional[str] = None,
        # 连接模式
        connection_mode: str = "outbound",  # 'outbound' or 'inbound'
        default_outbound: Optional[str] = None,
        auto_reconnect: bool = True,
        enabled: bool = True,
        # Phase 11: 双向连接状态
        bidirectional_status: str = "pending",
    ) -> int:
        """添加对等节点

        Args:
            tag: 唯一标识
            name: 显示名称
            endpoint: 远程端点 IP:port 或 域名:port
            psk_hash: [已废弃] 保留兼容，不再使用
            psk_encrypted: [已废弃] 保留兼容，不再使用
            description: 描述
            tunnel_type: 隧道类型 (wireguard/xray)
            tunnel_status: 隧道状态 (disconnected/connecting/connected/error)
            tunnel_local_ip: 本端隧道 IP (如 10.200.200.1)
            tunnel_remote_ip: 对端隧道 IP (如 10.200.200.2)
            tunnel_port: 本地监听端口
            tunnel_api_endpoint: 隧道内 API 地址 (如 10.200.200.2:36000)
            wg_private_key: WireGuard 私钥
            wg_public_key: WireGuard 公钥
            wg_peer_public_key: 对端 WireGuard 公钥
            xray_protocol: Xray 协议 (固定为 vless)
            xray_uuid: Xray UUID
            xray_reality_private_key: REALITY 私钥（x25519）
            xray_reality_public_key: REALITY 公钥
            xray_reality_short_id: REALITY Short ID
            xray_reality_dest: REALITY Dest Server（伪装目标）
            xray_reality_server_names: REALITY Server Names（JSON 数组）
            xray_peer_reality_public_key: 对端 REALITY 公钥
            xray_peer_reality_short_id: 对端 REALITY Short ID
            xray_xhttp_path: XHTTP 路径
            xray_xhttp_mode: XHTTP 模式 (auto/packet-up/stream-up/stream-one)
            xray_xhttp_host: XHTTP Host
            connection_mode: 连接模式 ('outbound' 或 'inbound')
            default_outbound: 默认出口
            auto_reconnect: 自动重连
            enabled: 是否启用

        Raises:
            sqlite3.IntegrityError: 如果 tunnel_local_ip 或 tunnel_port 冲突（竞态条件检测）
            ValueError: 如果 tunnel_port 超出有效范围 (36200-36299)
        """
        # Phase 6 Fix: 验证 tunnel_port 在有效范围内（支持环境变量配置）
        TUNNEL_PORT_MIN = int(os.environ.get("PEER_TUNNEL_PORT_MIN", "36200"))
        TUNNEL_PORT_MAX = int(os.environ.get("PEER_TUNNEL_PORT_MAX", "36299"))
        if tunnel_port is not None:
            if not (TUNNEL_PORT_MIN <= tunnel_port <= TUNNEL_PORT_MAX):
                raise ValueError(
                    f"tunnel_port {tunnel_port} 超出有效范围 ({TUNNEL_PORT_MIN}-{TUNNEL_PORT_MAX})"
                )

        with self._get_conn() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO peer_nodes (
                    tag, name, description, endpoint, api_port, psk_hash, psk_encrypted,
                    tunnel_type, tunnel_status, tunnel_interface,
                    tunnel_local_ip, tunnel_remote_ip, tunnel_port, tunnel_api_endpoint,
                    wg_private_key, wg_public_key, wg_peer_public_key,
                    xray_protocol, xray_uuid,
                    xray_reality_private_key, xray_reality_public_key, xray_reality_short_id,
                    xray_reality_dest, xray_reality_server_names,
                    xray_peer_reality_public_key, xray_peer_reality_short_id,
                    xray_xhttp_path, xray_xhttp_mode, xray_xhttp_host,
                    connection_mode, default_outbound, auto_reconnect, enabled,
                    bidirectional_status
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                tag, name, description, endpoint, api_port, psk_hash, psk_encrypted,
                tunnel_type, tunnel_status, tunnel_interface,
                tunnel_local_ip, tunnel_remote_ip, tunnel_port, tunnel_api_endpoint,
                wg_private_key, wg_public_key, wg_peer_public_key,
                xray_protocol, xray_uuid,
                xray_reality_private_key, xray_reality_public_key, xray_reality_short_id,
                xray_reality_dest, xray_reality_server_names,
                xray_peer_reality_public_key, xray_peer_reality_short_id,
                xray_xhttp_path, xray_xhttp_mode, xray_xhttp_host,
                connection_mode, default_outbound, 1 if auto_reconnect else 0, 1 if enabled else 0,
                bidirectional_status
            ))
            conn.commit()
            return cursor.lastrowid

    def update_peer_node(self, tag: str, **kwargs) -> bool:
        """更新对等节点"""
        allowed_fields = {
            "name", "description", "endpoint", "api_port", "psk_hash", "psk_encrypted",
            "tunnel_type", "tunnel_status", "tunnel_interface",
            "tunnel_local_ip", "tunnel_remote_ip", "tunnel_port", "tunnel_api_endpoint",
            "wg_private_key", "wg_public_key", "wg_peer_public_key",
            "xray_protocol", "xray_uuid", "xray_socks_port",
            # REALITY 配置（本节点作为服务端）
            "xray_reality_private_key", "xray_reality_public_key", "xray_reality_short_id",
            "xray_reality_dest", "xray_reality_server_names",
            # 对端 REALITY 配置（本节点作为客户端）
            "xray_peer_reality_public_key", "xray_peer_reality_short_id",
            "xray_peer_reality_dest", "xray_peer_reality_server_names",
            # XHTTP 传输配置
            "xray_xhttp_path", "xray_xhttp_mode", "xray_xhttp_host",
            # 入站监听配置（本节点作为服务端接收对方连接）
            "inbound_enabled", "inbound_port", "inbound_uuid", "inbound_socks_port",
            # 对方入站信息（用于连接到对方的入站）
            "peer_inbound_enabled", "peer_inbound_port", "peer_inbound_uuid",
            "peer_inbound_reality_public_key", "peer_inbound_reality_short_id",
            # Phase 11.1: 双向自动连接参数
            "bidirectional_status", "remote_wg_private_key", "remote_wg_public_key",
            # 连接模式
            "connection_mode",  # 'outbound' or 'inbound'
            "default_outbound", "last_seen", "last_error",
            "auto_reconnect", "enabled"
        }
        updates = []
        values = []
        for key, value in kwargs.items():
            if key in allowed_fields:
                updates.append(f"{key} = ?")
                values.append(value)
        if not updates:
            return False
        updates.append("updated_at = CURRENT_TIMESTAMP")
        values.append(tag)
        with self._get_conn() as conn:
            cursor = conn.cursor()
            cursor.execute(f"""
                UPDATE peer_nodes SET {", ".join(updates)} WHERE tag = ?
            """, values)
            conn.commit()
            return cursor.rowcount > 0

    def delete_peer_node(self, tag: str) -> bool:
        """删除对等节点"""
        with self._get_conn() as conn:
            cursor = conn.cursor()
            cursor.execute("DELETE FROM peer_nodes WHERE tag = ?", (tag,))
            conn.commit()
            return cursor.rowcount > 0

    def get_connected_peer_nodes(self) -> List[Dict]:
        """获取所有已连接的对等节点"""
        with self._get_conn() as conn:
            cursor = conn.cursor()
            rows = cursor.execute(
                "SELECT * FROM peer_nodes WHERE tunnel_status = 'connected' AND enabled = 1 ORDER BY tag"
            ).fetchall()
            columns = [desc[0] for desc in cursor.description]
            return [dict(zip(columns, row)) for row in rows]

    def get_next_peer_tunnel_port(self) -> Optional[int]:
        """获取下一个可用的对等节点隧道端口

        Issue 10/13 Fix: 使用正确的端口范围 (36200-36299) 并正确处理耗尽情况。
        此范围与 CLAUDE.md 和 peer_pairing.py 中的文档保持一致。

        Returns:
            可用的端口号，如果端口范围已耗尽则返回 None

        Raises:
            ValueError: 端口超出配置的范围
        """
        # Peer tunnel port range (configurable via environment)
        TUNNEL_PORT_MIN = int(os.environ.get("PEER_TUNNEL_PORT_MIN", "36200"))
        TUNNEL_PORT_MAX = int(os.environ.get("PEER_TUNNEL_PORT_MAX", "36299"))

        with self._get_conn() as conn:
            cursor = conn.cursor()
            # 获取所有已使用的端口
            rows = cursor.execute(
                "SELECT tunnel_port FROM peer_nodes WHERE tunnel_port IS NOT NULL"
            ).fetchall()
            used_ports = set(row[0] for row in rows)

            # 从最小端口开始查找可用端口（支持端口复用）
            for port in range(TUNNEL_PORT_MIN, TUNNEL_PORT_MAX + 1):
                if port not in used_ports:
                    return port

            # Issue 10 Fix: 端口范围耗尽，返回 None 而非抛出异常
            # 让调用者可以提供更友好的错误消息
            return None

    def get_next_peer_xray_socks_port(self) -> int:
        """获取下一个可用的 Xray SOCKS 端口（可通过环境变量配置起始端口）

        Raises:
            ValueError: 端口超出 65535 限制
        """
        # Peer Xray SOCKS port start (configurable via environment)
        PEER_XRAY_SOCKS_PORT_START = int(os.environ.get("PEER_XRAY_SOCKS_PORT_START", "37201"))
        with self._get_conn() as conn:
            cursor = conn.cursor()
            row = cursor.execute(
                "SELECT MAX(xray_socks_port) FROM peer_nodes WHERE xray_socks_port IS NOT NULL"
            ).fetchone()
            max_port = row[0] if row and row[0] else (PEER_XRAY_SOCKS_PORT_START - 1)
            next_port = max(max_port + 1, PEER_XRAY_SOCKS_PORT_START)
            if next_port > 65535:
                raise ValueError(f"Peer Xray SOCKS port overflow: {next_port} > 65535")
            return next_port

    def get_next_peer_inbound_port(self) -> int:
        """获取下一个可用的对等节点入站端口（可通过环境变量配置起始端口）

        Raises:
            ValueError: 端口超出 65535 限制
        """
        # Peer inbound port start (configurable via environment)
        PEER_INBOUND_PORT_START = int(os.environ.get("PEER_INBOUND_PORT_START", "36500"))
        with self._get_conn() as conn:
            cursor = conn.cursor()
            row = cursor.execute(
                "SELECT MAX(inbound_port) FROM peer_nodes WHERE inbound_port IS NOT NULL"
            ).fetchone()
            max_port = row[0] if row and row[0] else (PEER_INBOUND_PORT_START - 1)
            next_port = max(max_port + 1, PEER_INBOUND_PORT_START)
            if next_port > 65535:
                raise ValueError(f"Peer inbound port overflow: {next_port} > 65535")
            return next_port

    def get_peer_nodes_with_inbound(self) -> List[Dict]:
        """获取所有启用入站监听的对等节点"""
        with self._get_conn() as conn:
            cursor = conn.cursor()
            rows = cursor.execute(
                "SELECT * FROM peer_nodes WHERE inbound_enabled = 1 AND enabled = 1 ORDER BY tag"
            ).fetchall()
            columns = [desc[0] for desc in cursor.description]
            return [dict(zip(columns, row)) for row in rows]

    # ============ 双向连接管理 (Phase 11.1) ============

    def update_peer_bidirectional_status(self, tag: str, status: str) -> bool:
        """更新对等节点的双向连接状态

        Args:
            tag: 节点标识
            status: 状态值 ('pending', 'outbound_only', 'bidirectional')

        Returns:
            是否更新成功
        """
        valid_statuses = {'pending', 'outbound_only', 'bidirectional'}
        if status not in valid_statuses:
            logger.warning(f"Invalid bidirectional_status: {status}")
            return False

        with self._get_conn() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "UPDATE peer_nodes SET bidirectional_status = ?, updated_at = CURRENT_TIMESTAMP WHERE tag = ?",
                (status, tag)
            )
            conn.commit()
            return cursor.rowcount > 0

    def get_peers_pending_bidirectional(self) -> List[Dict]:
        """获取等待双向连接的对等节点列表

        Returns:
            bidirectional_status='pending' 且已连接的节点列表
        """
        with self._get_conn() as conn:
            cursor = conn.cursor()
            rows = cursor.execute("""
                SELECT * FROM peer_nodes
                WHERE bidirectional_status = 'pending'
                  AND tunnel_status = 'connected'
                  AND enabled = 1
                ORDER BY tag
            """).fetchall()
            columns = [desc[0] for desc in cursor.description]
            return [dict(zip(columns, row)) for row in rows]

    def get_peers_by_bidirectional_status(self, status: str) -> List[Dict]:
        """按双向连接状态获取对等节点列表

        Args:
            status: 状态值 ('pending', 'outbound_only', 'bidirectional')

        Returns:
            符合条件的节点列表
        """
        # 输入验证 (Phase 11.1)
        valid_statuses = {'pending', 'outbound_only', 'bidirectional'}
        if status not in valid_statuses:
            logger.warning(f"Invalid bidirectional_status query: {status}")
            return []

        with self._get_conn() as conn:
            cursor = conn.cursor()
            rows = cursor.execute("""
                SELECT * FROM peer_nodes
                WHERE bidirectional_status = ?
                  AND enabled = 1
                ORDER BY tag
            """, (status,)).fetchall()
            columns = [desc[0] for desc in cursor.description]
            return [dict(zip(columns, row)) for row in rows]

    # ============ Pending Pairings 管理 (Phase 11-Tunnel) ============

    def add_pending_pairing(
        self,
        pairing_id: str,
        local_tag: str,
        local_endpoint: str,
        tunnel_type: str = "wireguard",
        tunnel_local_ip: str = None,
        tunnel_remote_ip: str = None,
        tunnel_port: int = None,
        wg_private_key: str = None,
        wg_public_key: str = None,
        remote_wg_private_key: str = None,
        remote_wg_public_key: str = None,
        interface_name: str = None,
        expires_days: int = 7
    ) -> int:
        """添加待处理配对记录

        当节点 A 生成配对码时，同时创建 WireGuard 接口并保存配对信息。
        当节点 B 通过隧道调用 complete-handshake 后，此记录将被删除。

        Args:
            pairing_id: 配对标识（base64 hash，用于匹配请求）
            local_tag: 本节点标识
            local_endpoint: 本节点端点 (IP:port)
            tunnel_type: 隧道类型 (wireguard/xray)
            tunnel_local_ip: 本端隧道 IP
            tunnel_remote_ip: 对端隧道 IP
            tunnel_port: WireGuard 监听端口
            wg_private_key: 本节点私钥
            wg_public_key: 本节点公钥
            remote_wg_private_key: 预生成的对端私钥（将包含在配对码中）
            remote_wg_public_key: 预生成的对端公钥
            interface_name: WireGuard 接口名 (wg-pending-xxx)
            expires_days: 过期天数（默认 7 天）

        Returns:
            新记录的 ID
        """
        with self._get_conn() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO pending_pairings (
                    pairing_id, local_tag, local_endpoint, tunnel_type,
                    tunnel_local_ip, tunnel_remote_ip, tunnel_port,
                    wg_private_key, wg_public_key,
                    remote_wg_private_key, remote_wg_public_key,
                    interface_name, expires_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
                    datetime('now', '+' || ? || ' days'))
            """, (
                pairing_id, local_tag, local_endpoint, tunnel_type,
                tunnel_local_ip, tunnel_remote_ip, tunnel_port,
                wg_private_key, wg_public_key,
                remote_wg_private_key, remote_wg_public_key,
                interface_name, expires_days
            ))
            conn.commit()
            return cursor.lastrowid

    def get_pending_pairing(self, pairing_id: str) -> Optional[Dict]:
        """根据配对标识获取待处理配对记录

        Args:
            pairing_id: 配对标识

        Returns:
            配对记录字典，不存在返回 None
        """
        with self._get_conn() as conn:
            cursor = conn.cursor()
            row = cursor.execute(
                "SELECT * FROM pending_pairings WHERE pairing_id = ?",
                (pairing_id,)
            ).fetchone()
            if row:
                columns = [desc[0] for desc in cursor.description]
                return dict(zip(columns, row))
            return None

    def get_pending_pairing_by_interface(self, interface_name: str) -> Optional[Dict]:
        """根据接口名获取待处理配对记录

        Args:
            interface_name: WireGuard 接口名

        Returns:
            配对记录字典，不存在返回 None
        """
        with self._get_conn() as conn:
            cursor = conn.cursor()
            row = cursor.execute(
                "SELECT * FROM pending_pairings WHERE interface_name = ?",
                (interface_name,)
            ).fetchone()
            if row:
                columns = [desc[0] for desc in cursor.description]
                return dict(zip(columns, row))
            return None

    def delete_pending_pairing(self, pairing_id: str) -> bool:
        """删除待处理配对记录

        当配对成功完成后，应删除此记录。

        Args:
            pairing_id: 配对标识

        Returns:
            是否删除成功
        """
        with self._get_conn() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "DELETE FROM pending_pairings WHERE pairing_id = ?",
                (pairing_id,)
            )
            conn.commit()
            return cursor.rowcount > 0

    def cleanup_expired_pairings(self) -> int:
        """清理过期的待处理配对记录

        Returns:
            删除的记录数量
        """
        with self._get_conn() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "DELETE FROM pending_pairings WHERE expires_at < datetime('now')"
            )
            conn.commit()
            return cursor.rowcount

    def get_all_pending_pairings(self) -> List[Dict]:
        """获取所有未过期的待处理配对记录

        Returns:
            配对记录列表
        """
        with self._get_conn() as conn:
            cursor = conn.cursor()
            rows = cursor.execute("""
                SELECT * FROM pending_pairings
                WHERE expires_at > datetime('now')
                ORDER BY created_at DESC
            """).fetchall()
            columns = [desc[0] for desc in cursor.description]
            return [dict(zip(columns, row)) for row in rows]

    # ============ Phase 11-Cascade: 级联删除通知支持 ============

    # 有效的事件类型 (必须与数据库 CHECK 约束保持一致)
    # Phase B: 添加 port_change 事件类型支持端口变更通知
    VALID_PEER_EVENT_TYPES = frozenset({'delete', 'disconnect', 'broadcast', 'received', 'port_change'})

    def log_peer_event(
        self,
        event_type: str,
        peer_tag: str,
        event_id: Optional[str] = None,
        from_node: Optional[str] = None,
        details: Optional[Dict] = None,
        source_ip: Optional[str] = None
    ) -> int:
        """记录对等节点事件到审计日志

        Args:
            event_type: 事件类型 (delete, disconnect, broadcast, received)
            peer_tag: 相关节点 tag
            event_id: 事件唯一 ID
            from_node: 事件来源节点
            details: 额外信息 (Dict, 将转为 JSON)
            source_ip: 请求来源 IP

        Returns:
            新记录的 ID

        Raises:
            ValueError: 如果 event_type 无效
        """
        # 输入验证
        if event_type not in self.VALID_PEER_EVENT_TYPES:
            raise ValueError(f"Invalid event_type: {event_type}. Must be one of: {', '.join(sorted(self.VALID_PEER_EVENT_TYPES))}")

        details_json = json.dumps(details) if details else None

        with self._get_conn() as conn:
            cursor = conn.cursor()
            # 使用 SQLite 的 strftime 生成 ISO 8601 格式时间戳 (与 schema 默认值一致)
            cursor.execute("""
                INSERT INTO peer_event_log
                    (event_type, peer_tag, event_id, from_node, details, source_ip, created_at)
                VALUES (?, ?, ?, ?, ?, ?, strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
            """, (event_type, peer_tag, event_id, from_node, details_json, source_ip))
            conn.commit()
            return cursor.lastrowid

    def get_peer_events(
        self,
        peer_tag: Optional[str] = None,
        event_type: Optional[str] = None,
        limit: int = 100
    ) -> List[Dict]:
        """查询对等节点事件日志

        Args:
            peer_tag: 按节点过滤
            event_type: 按事件类型过滤
            limit: 返回记录数量上限

        Returns:
            事件记录列表 (按时间倒序)

        Raises:
            ValueError: 如果 event_type 无效
        """
        # 输入验证
        if event_type is not None and event_type not in self.VALID_PEER_EVENT_TYPES:
            raise ValueError(f"Invalid event_type: {event_type}. Must be one of: {', '.join(sorted(self.VALID_PEER_EVENT_TYPES))}")

        with self._get_conn() as conn:
            cursor = conn.cursor()
            sql = "SELECT * FROM peer_event_log WHERE 1=1"
            params = []
            if peer_tag:
                sql += " AND peer_tag = ?"
                params.append(peer_tag)
            if event_type:
                sql += " AND event_type = ?"
                params.append(event_type)
            sql += " ORDER BY created_at DESC LIMIT ?"
            params.append(limit)
            rows = cursor.execute(sql, params).fetchall()
            columns = [desc[0] for desc in cursor.description]
            # 解析 JSON 格式的 details 字段
            result = []
            for row in rows:
                row_dict = dict(zip(columns, row))
                if row_dict.get('details'):
                    try:
                        row_dict['details'] = json.loads(row_dict['details'])
                    except (json.JSONDecodeError, TypeError):
                        pass  # 保持原始字符串
                result.append(row_dict)
            return result

    # 默认墓碑 TTL (小时) - 防止删除后节点在此期间重新连接
    DEFAULT_TOMBSTONE_TTL_HOURS = 24

    def add_peer_tombstone(
        self,
        tag: str,
        deleted_by: str = "local",
        reason: str = "deleted",
        ttl_hours: int = DEFAULT_TOMBSTONE_TTL_HOURS
    ) -> bool:
        """添加节点墓碑记录

        Args:
            tag: 节点 tag
            deleted_by: 删除来源 ('local' 或远程节点 tag)
            reason: 删除原因
            ttl_hours: 墓碑有效期 (小时)

        Returns:
            是否成功

        Raises:
            ValueError: 如果 ttl_hours <= 0
        """
        # 输入验证
        if not isinstance(ttl_hours, int) or ttl_hours <= 0:
            raise ValueError(f"ttl_hours must be a positive integer, got: {ttl_hours}")

        with self._get_conn() as conn:
            cursor = conn.cursor()
            # 使用 SQLite 的 datetime 函数计算时间，确保格式一致
            # 注意: pysqlcipher3 使用 SQLite 3.15.2，不支持 ON CONFLICT 语法
            # 因此使用 INSERT OR REPLACE (SQLite 3.15+ 兼容)
            cursor.execute("""
                INSERT OR REPLACE INTO peer_tombstones (tag, deleted_at, expires_at, deleted_by, reason)
                VALUES (?, strftime('%Y-%m-%dT%H:%M:%SZ', 'now'),
                        strftime('%Y-%m-%dT%H:%M:%SZ', 'now', '+' || ? || ' hours'),
                        ?, ?)
            """, (tag, ttl_hours, deleted_by, reason))
            conn.commit()
            return True

    def get_peer_tombstone(self, tag: str) -> Optional[Dict]:
        """查询节点墓碑记录

        Args:
            tag: 节点 tag

        Returns:
            墓碑记录 (如果存在且未过期)，否则 None
        """
        with self._get_conn() as conn:
            cursor = conn.cursor()
            # 使用 strftime 确保与存储格式一致 (ISO 8601)
            row = cursor.execute("""
                SELECT * FROM peer_tombstones
                WHERE tag = ? AND expires_at > strftime('%Y-%m-%dT%H:%M:%SZ', 'now')
            """, (tag,)).fetchone()
            if row:
                columns = [desc[0] for desc in cursor.description]
                return dict(zip(columns, row))
            return None

    def is_peer_tombstoned(self, tag: str) -> bool:
        """检查节点是否在墓碑期内

        Args:
            tag: 节点 tag

        Returns:
            是否在墓碑期
        """
        return self.get_peer_tombstone(tag) is not None

    def cleanup_expired_tombstones(self) -> int:
        """清理过期的墓碑记录

        Returns:
            删除的记录数
        """
        with self._get_conn() as conn:
            cursor = conn.cursor()
            # 使用 strftime 确保与存储格式一致 (ISO 8601)
            cursor.execute("""
                DELETE FROM peer_tombstones
                WHERE expires_at <= strftime('%Y-%m-%dT%H:%M:%SZ', 'now')
            """)
            deleted = cursor.rowcount
            conn.commit()
            return deleted

    def get_all_tombstones(self, include_expired: bool = False) -> List[Dict]:
        """获取所有墓碑记录

        Args:
            include_expired: 是否包含已过期的记录

        Returns:
            墓碑记录列表
        """
        with self._get_conn() as conn:
            cursor = conn.cursor()
            if include_expired:
                sql = "SELECT * FROM peer_tombstones ORDER BY deleted_at DESC"
            else:
                sql = """
                    SELECT * FROM peer_tombstones
                    WHERE expires_at > strftime('%Y-%m-%dT%H:%M:%SZ', 'now')
                    ORDER BY deleted_at DESC
                """
            rows = cursor.execute(sql).fetchall()
            columns = [desc[0] for desc in cursor.description]
            return [dict(zip(columns, row)) for row in rows]

    def delete_peer_tombstone(self, tag: str) -> bool:
        """手动删除墓碑记录 (允许节点重新连接)

        Args:
            tag: 节点 tag

        Returns:
            是否成功删除
        """
        with self._get_conn() as conn:
            cursor = conn.cursor()
            cursor.execute("DELETE FROM peer_tombstones WHERE tag = ?", (tag,))
            deleted = cursor.rowcount > 0
            conn.commit()
            return deleted

    # 默认审计日志保留时间 (小时)
    DEFAULT_PEER_EVENT_RETENTION_HOURS = 168  # 7 天

    def cleanup_old_peer_events(self, hours: int = DEFAULT_PEER_EVENT_RETENTION_HOURS) -> int:
        """清理旧的审计日志记录

        Args:
            hours: 保留时间 (小时)，默认 7 天

        Returns:
            删除的记录数

        Raises:
            ValueError: 如果 hours <= 0
        """
        if not isinstance(hours, int) or hours <= 0:
            raise ValueError(f"hours must be a positive integer, got: {hours}")

        with self._get_conn() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                DELETE FROM peer_event_log
                WHERE created_at < strftime('%Y-%m-%dT%H:%M:%SZ', 'now', '-' || ? || ' hours')
            """, (hours,))
            deleted = cursor.rowcount
            conn.commit()
            return deleted

    def is_event_processed(self, event_id: str) -> bool:
        """检查事件是否已处理 (幂等性检查)

        Args:
            event_id: 事件唯一 ID

        Returns:
            是否已处理
        """
        with self._get_conn() as conn:
            cursor = conn.cursor()
            row = cursor.execute("""
                SELECT 1 FROM processed_peer_events WHERE event_id = ?
            """, (event_id,)).fetchone()
            return row is not None

    def mark_event_processed(
        self,
        event_id: str,
        from_node: str,
        action: Optional[str] = None
    ) -> bool:
        """标记事件为已处理

        Args:
            event_id: 事件唯一 ID
            from_node: 事件来源节点
            action: 事件动作类型

        Returns:
            是否成功
        """
        with self._get_conn() as conn:
            cursor = conn.cursor()
            try:
                # 使用 SQLite 的 strftime 生成 ISO 8601 格式时间戳
                cursor.execute("""
                    INSERT INTO processed_peer_events
                        (event_id, processed_at, from_node, action)
                    VALUES (?, strftime('%Y-%m-%dT%H:%M:%SZ', 'now'), ?, ?)
                """, (event_id, from_node, action))
                conn.commit()
                return True
            except sqlite3.IntegrityError:
                # 已存在，返回 True (幂等)
                return True

    def mark_event_if_not_processed(
        self,
        event_id: str,
        from_node: str,
        action: Optional[str] = None
    ) -> tuple:
        """原子操作：检查并标记事件为已处理（防止 TOCTOU 竞态条件）

        在单个事务中执行检查和标记，避免并发请求重复处理同一事件。

        Args:
            event_id: 事件唯一 ID
            from_node: 事件来源节点
            action: 事件动作类型

        Returns:
            元组 (was_processed, now_marked):
            - was_processed: True 表示之前已处理（幂等返回）
            - now_marked: True 表示本次成功标记
        """
        with self._get_conn() as conn:
            cursor = conn.cursor()
            try:
                # 使用 INSERT OR IGNORE + 检查 rowcount 实现原子操作
                cursor.execute("""
                    INSERT OR IGNORE INTO processed_peer_events
                        (event_id, processed_at, from_node, action)
                    VALUES (?, strftime('%Y-%m-%dT%H:%M:%SZ', 'now'), ?, ?)
                """, (event_id, from_node, action))
                conn.commit()

                if cursor.rowcount > 0:
                    # 成功插入，这是第一次处理
                    return (False, True)
                else:
                    # 插入被忽略，说明之前已存在
                    return (True, False)
            except Exception as e:
                logging.error(f"mark_event_if_not_processed 失败: {e}")
                conn.rollback()
                raise

    # 默认已处理事件保留时间 (小时) - 用于幂等性去重
    DEFAULT_PROCESSED_EVENT_RETENTION_HOURS = 24

    def cleanup_old_processed_events(self, hours: int = DEFAULT_PROCESSED_EVENT_RETENTION_HOURS) -> int:
        """清理旧的已处理事件记录

        Args:
            hours: 保留时间 (小时)

        Returns:
            删除的记录数

        Raises:
            ValueError: 如果 hours <= 0
        """
        # 输入验证 (防止 SQL 注入和无效值)
        if not isinstance(hours, int) or hours <= 0:
            raise ValueError(f"hours must be a positive integer, got: {hours}")

        with self._get_conn() as conn:
            cursor = conn.cursor()
            # 使用参数化查询避免 SQL 注入
            # strftime 格式与存储格式一致 (ISO 8601)
            cursor.execute("""
                DELETE FROM processed_peer_events
                WHERE processed_at < strftime('%Y-%m-%dT%H:%M:%SZ', 'now', '-' || ? || ' hours')
            """, (hours,))
            deleted = cursor.rowcount
            conn.commit()
            return deleted

    # ============ Relay Routes 管理 ============

    def get_relay_routes(self, chain_tag: Optional[str] = None, enabled_only: bool = False) -> List[Dict]:
        """获取中继路由列表

        Args:
            chain_tag: 可选，按链路过滤
            enabled_only: 是否只返回启用的路由
        """
        with self._get_conn() as conn:
            cursor = conn.cursor()
            sql = "SELECT * FROM relay_routes WHERE 1=1"
            params = []
            if chain_tag:
                sql += " AND chain_tag = ?"
                params.append(chain_tag)
            if enabled_only:
                sql += " AND enabled = 1"
            sql += " ORDER BY id"
            rows = cursor.execute(sql, params).fetchall()
            columns = [desc[0] for desc in cursor.description]
            return [dict(zip(columns, row)) for row in rows]

    def add_relay_route(
        self,
        chain_tag: str,
        source_peer_tag: str,
        target_peer_tag: str,
        enabled: bool = True
    ) -> int:
        """添加中继路由

        Args:
            chain_tag: 所属链路标识
            source_peer_tag: 流量来源节点标识
            target_peer_tag: 转发目标节点标识
            enabled: 是否启用
        """
        with self._get_conn() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO relay_routes (chain_tag, source_peer_tag, target_peer_tag, enabled)
                VALUES (?, ?, ?, ?)
            """, (chain_tag, source_peer_tag, target_peer_tag, 1 if enabled else 0))
            conn.commit()
            return cursor.lastrowid

    def delete_relay_route(self, route_id: int) -> bool:
        """删除中继路由"""
        with self._get_conn() as conn:
            cursor = conn.cursor()
            cursor.execute("DELETE FROM relay_routes WHERE id = ?", (route_id,))
            conn.commit()
            return cursor.rowcount > 0

    def delete_relay_routes_by_chain(self, chain_tag: str) -> int:
        """删除指定链路的所有中继路由"""
        with self._get_conn() as conn:
            cursor = conn.cursor()
            cursor.execute("DELETE FROM relay_routes WHERE chain_tag = ?", (chain_tag,))
            conn.commit()
            return cursor.rowcount

    def update_relay_route(self, route_id: int, **kwargs) -> bool:
        """更新中继路由"""
        allowed_fields = {"enabled"}
        updates = []
        values = []
        for key, value in kwargs.items():
            if key in allowed_fields:
                updates.append(f"{key} = ?")
                values.append(value)
        if not updates:
            return False
        values.append(route_id)
        with self._get_conn() as conn:
            cursor = conn.cursor()
            cursor.execute(f"""
                UPDATE relay_routes SET {", ".join(updates)} WHERE id = ?
            """, values)
            conn.commit()
            return cursor.rowcount > 0

    # ============ Node Chains 管理 ============

    def get_node_chains(self, enabled_only: bool = False) -> List[Dict]:
        """获取所有多跳链路"""
        with self._get_conn() as conn:
            cursor = conn.cursor()
            if enabled_only:
                rows = cursor.execute(
                    "SELECT * FROM node_chains WHERE enabled = 1 ORDER BY priority, tag"
                ).fetchall()
            else:
                rows = cursor.execute(
                    "SELECT * FROM node_chains ORDER BY priority, tag"
                ).fetchall()
            columns = [desc[0] for desc in cursor.description]
            result = []
            for row in rows:
                item = dict(zip(columns, row))
                # 解析 JSON 字段
                for json_field in ["hops", "hop_protocols", "entry_rules", "relay_rules"]:
                    if item.get(json_field):
                        try:
                            item[json_field] = json.loads(item[json_field])
                        except (json.JSONDecodeError, TypeError):
                            if json_field == "hops":
                                item[json_field] = []
                            else:
                                item[json_field] = None
                result.append(item)
            return result

    def get_node_chain(self, tag: str) -> Optional[Dict]:
        """根据 tag 获取单个多跳链路"""
        with self._get_conn() as conn:
            cursor = conn.cursor()
            row = cursor.execute(
                "SELECT * FROM node_chains WHERE tag = ?", (tag,)
            ).fetchone()
            if not row:
                return None
            columns = [desc[0] for desc in cursor.description]
            item = dict(zip(columns, row))
            # 解析 JSON 字段
            for json_field in ["hops", "hop_protocols", "entry_rules", "relay_rules"]:
                if item.get(json_field):
                    try:
                        item[json_field] = json.loads(item[json_field])
                    except (json.JSONDecodeError, TypeError):
                        if json_field == "hops":
                            item[json_field] = []
                        else:
                            item[json_field] = None
            return item

    def add_node_chain(
        self,
        tag: str,
        name: str,
        hops: List[str],
        description: str = "",
        hop_protocols: Optional[Dict[str, str]] = None,
        entry_rules: Optional[Dict] = None,
        relay_rules: Optional[Dict] = None,
        priority: int = 0,
        enabled: bool = True,
        # 多跳链路架构 v2 新增字段
        exit_egress: Optional[str] = None,
        dscp_value: Optional[int] = None,
        chain_mark_type: str = "dscp",
        chain_state: str = "inactive",
        allow_transitive: bool = False  # Phase 11-Fix.Q: 传递模式验证
    ) -> int:
        """添加多跳链路

        Args:
            tag: 链路唯一标识
            name: 显示名称
            hops: 跳点节点列表 ["node-tokyo", "node-us"]
            description: 描述
            hop_protocols: 每跳协议 {"node-tokyo": "wireguard", "node-us": "xray"}
            entry_rules: 入口分流规则
            relay_rules: 中继分流规则
            priority: 优先级
            enabled: 是否启用
            exit_egress: 终端节点的本地出口 tag（多跳链路架构 v2）
            dscp_value: DSCP 标记值 1-63（多跳链路架构 v2）
            chain_mark_type: 标记类型 'dscp' 或 'xray_email'
            chain_state: 链路状态 'inactive'/'activating'/'active'/'error'
            allow_transitive: 是否允许传递验证（只验证第一跳）
        """
        with self._get_conn() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO node_chains (
                    tag, name, description, hops, hop_protocols,
                    entry_rules, relay_rules, priority, enabled,
                    exit_egress, dscp_value, chain_mark_type, chain_state,
                    allow_transitive
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                tag, name, description,
                json.dumps(hops),
                json.dumps(hop_protocols) if hop_protocols else None,
                json.dumps(entry_rules) if entry_rules else None,
                json.dumps(relay_rules) if relay_rules else None,
                priority, 1 if enabled else 0,
                exit_egress, dscp_value, chain_mark_type, chain_state,
                1 if allow_transitive else 0
            ))
            conn.commit()
            return cursor.lastrowid

    def update_node_chain(self, tag: str, **kwargs) -> bool:
        """更新多跳链路"""
        allowed_fields = {
            "name", "description", "hops", "hop_protocols",
            "entry_rules", "relay_rules", "health_status",
            "last_health_check", "priority", "enabled",
            "downstream_status", "disconnected_node",  # 级联通知字段
            # 多跳链路架构 v2 字段
            "exit_egress", "dscp_value", "chain_mark_type", "chain_state",
            "allow_transitive",  # Phase 11-Fix.Q: 传递模式验证
            "last_error"  # Phase 5: 错误原因记录
        }
        updates = []
        values = []
        for key, value in kwargs.items():
            if key in allowed_fields:
                # JSON 字段需要序列化
                if key in {"hops", "hop_protocols", "entry_rules", "relay_rules"}:
                    if value is not None:
                        value = json.dumps(value)
                updates.append(f"{key} = ?")
                values.append(value)
        if not updates:
            return False
        updates.append("updated_at = CURRENT_TIMESTAMP")
        values.append(tag)
        with self._get_conn() as conn:
            cursor = conn.cursor()
            cursor.execute(f"""
                UPDATE node_chains SET {", ".join(updates)} WHERE tag = ?
            """, values)
            conn.commit()
            return cursor.rowcount > 0

    def atomic_chain_state_transition(
        self,
        tag: str,
        expected_state: str,
        new_state: str,
        timeout_ms: int = 30000,
        last_error: Optional[str] = None
    ) -> tuple:
        """Phase 11-Fix.T/U: 原子性链路状态转换

        使用 BEGIN EXCLUSIVE 事务确保并发安全。解决两个并发请求同时
        读取 'inactive' 状态然后都尝试写入 'activating' 的竞态条件。

        Phase 11-Fix.U 修改:
        - 使用专用连接避免 TLS 连接池隐式事务状态冲突
        - 添加 last_error 参数支持在同一事务中设置错误消息

        Args:
            tag: 链路标签
            expected_state: 期望的当前状态
            new_state: 要转换到的新状态
            timeout_ms: 获取锁的超时时间（毫秒）
            last_error: 可选的错误消息，将在同一事务中原子设置

        Returns:
            (success: bool, error_message: Optional[str])
            - (True, None): 转换成功
            - (False, "Chain not found"): 链路不存在
            - (False, "Expected state 'X', found 'Y'"): 状态不匹配
            - (False, "Database error: ..."): 数据库错误
        """
        # Phase 11-Fix.U: 使用专用连接避免 TLS 连接池冲突
        # TLS 缓存连接可能有待处理的隐式事务，导致 BEGIN EXCLUSIVE 或 COMMIT 失败
        conn = sqlite3.connect(
            str(self.db_path),
            timeout=timeout_ms / 1000.0,  # SQLite timeout 是秒
            check_same_thread=False
        )
        try:
            # 应用 SQLCipher 加密和性能 PRAGMA
            self._apply_encryption(conn)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()

            # 设置锁等待超时
            cursor.execute(f"PRAGMA busy_timeout = {timeout_ms}")

            # 开始排他事务 - 阻止其他写操作
            cursor.execute("BEGIN EXCLUSIVE")

            # 检查当前状态
            cursor.execute(
                "SELECT chain_state FROM node_chains WHERE tag = ?",
                (tag,)
            )
            row = cursor.fetchone()

            if not row:
                # Phase 11-Fix.V.2: 使用 conn.rollback() 统一事务管理
                conn.rollback()
                return False, f"Chain '{tag}' not found"

            current_state = row[0] or "inactive"

            if current_state != expected_state:
                # Phase 11-Fix.V.2: 使用 conn.rollback() 统一事务管理
                conn.rollback()
                return False, f"Expected state '{expected_state}', found '{current_state}'"

            # Phase 11-Fix.U: 原子更新状态和 last_error（如果提供）
            if last_error is not None:
                cursor.execute(
                    """UPDATE node_chains
                       SET chain_state = ?, last_error = ?, updated_at = CURRENT_TIMESTAMP
                       WHERE tag = ?""",
                    (new_state, last_error, tag)
                )
            else:
                cursor.execute(
                    """UPDATE node_chains
                       SET chain_state = ?, updated_at = CURRENT_TIMESTAMP
                       WHERE tag = ?""",
                    (new_state, tag)
                )
            # Phase 11-Fix.V.2: 使用 conn.commit() 统一事务管理
            conn.commit()

            logger.info(
                f"[db] Chain '{tag}' state transition: {expected_state} -> {new_state}"
                + (f" (last_error: {last_error[:50]}...)" if last_error and len(last_error) > 50
                   else (f" (last_error: {last_error})" if last_error else ""))
            )
            return True, None

        except Exception as e:
            try:
                conn.rollback()
            except Exception as rollback_err:
                # Phase 11-Fix.V.2: 记录 rollback 失败（连接将在 finally 中关闭）
                logger.warning(f"[db] Rollback failed during error recovery: {rollback_err}")
            logger.error(f"[db] atomic_chain_state_transition failed: {e}")
            return False, f"Database error: {str(e)}"
        finally:
            # Phase 11-Fix.U: 专用连接在使用后关闭，不污染 TLS 连接池
            try:
                conn.close()
            except Exception:
                pass

    def delete_node_chain(self, tag: str) -> bool:
        """删除多跳链路

        级联删除关联数据：
        - terminal_egress_cache (入口节点缓存的终端出口列表)
        - chain_routing (链路路由规则)
        - relay_routes (中继路由)
        """
        with self._get_conn() as conn:
            cursor = conn.cursor()

            # 级联删除关联的缓存和路由数据
            cursor.execute("DELETE FROM terminal_egress_cache WHERE chain_tag = ?", (tag,))
            cursor.execute("DELETE FROM chain_routing WHERE chain_tag = ?", (tag,))
            cursor.execute("DELETE FROM relay_routes WHERE chain_tag = ?", (tag,))

            # 删除链路本身
            cursor.execute("DELETE FROM node_chains WHERE tag = ?", (tag,))
            conn.commit()
            return cursor.rowcount > 0

    def validate_chain_hops(self, hops: List[str], allow_transitive: bool = False) -> tuple:
        """Phase 11-Fix.C: 验证链路的跳点节点，支持传递模式

        验证内容：
        1. hops 不能为空
        2. 检测重复节点（循环链路防护）
        3. 验证节点存在性：
           - 严格模式 (allow_transitive=False): 所有节点必须存在于本地 peer_nodes 表
           - 传递模式 (allow_transitive=True): 只验证第一跳存在于本地 peer_nodes，
             后续跳通过隧道向下游节点查询（用于线性拓扑 A→B→C，A 只知道 B）

        Args:
            hops: 跳点列表（不包含本地节点）
            allow_transitive: 是否允许传递模式（只验证第一跳）

        Returns:
            (is_valid, error_message_or_missing_nodes)
        """
        if not hops:
            return False, ["hops cannot be empty"]

        # 检测重复节点（循环链路防护）
        # 同一链路中不应出现重复节点，如 A→B→A 或 A→B→C→B
        seen = set()
        duplicates = []
        for hop in hops:
            if hop in seen:
                duplicates.append(hop)
            seen.add(hop)

        if duplicates:
            return False, [f"circular chain detected: duplicate node(s) {duplicates}"]

        if allow_transitive:
            # 传递模式：只验证第一跳是本地 peer
            first_hop = hops[0]
            with self._get_conn() as conn:
                cursor = conn.cursor()
                row = cursor.execute(
                    "SELECT tag, tunnel_status FROM peer_nodes WHERE tag = ?",
                    (first_hop,)
                ).fetchone()

                if not row:
                    return False, [f"first hop '{first_hop}' not found in local peer_nodes"]

                # 可选：检查第一跳是否已连接
                tunnel_status = row[1]
                if tunnel_status != "connected":
                    return False, [f"first hop '{first_hop}' is not connected (status: {tunnel_status})"]

                return True, []
        else:
            # 严格模式：所有节点必须在本地 peer_nodes 表
            with self._get_conn() as conn:
                cursor = conn.cursor()
                # 使用单一 IN 查询代替 N+1 循环
                placeholders = ",".join("?" * len(hops))
                rows = cursor.execute(
                    f"SELECT tag FROM peer_nodes WHERE tag IN ({placeholders})",
                    hops
                ).fetchall()

                existing_tags = {row[0] for row in rows}
                missing = [hop for hop in hops if hop not in existing_tags]
                return len(missing) == 0, missing

    # ============ Chain Registrations 管理（级联通知用）============

    def get_chain_registrations(self) -> List[Dict]:
        """获取所有链路注册"""
        with self._get_conn() as conn:
            cursor = conn.cursor()
            rows = cursor.execute(
                "SELECT * FROM chain_registrations ORDER BY registered_at DESC"
            ).fetchall()
            columns = [desc[0] for desc in cursor.description]
            return [dict(zip(columns, row)) for row in rows]

    def get_chain_registrations_by_downstream(self, downstream_node_tag: str) -> List[Dict]:
        """获取经过指定下游节点的所有链路注册（用于断连时通知上游）

        Args:
            downstream_node_tag: 下游节点标签

        Returns:
            包含上游端点信息的注册列表，用于发送断连通知
        """
        with self._get_conn() as conn:
            cursor = conn.cursor()
            rows = cursor.execute(
                "SELECT * FROM chain_registrations WHERE downstream_node_tag = ?",
                (downstream_node_tag,)
            ).fetchall()
            columns = [desc[0] for desc in cursor.description]
            return [dict(zip(columns, row)) for row in rows]

    def get_chain_upstream_registration(self, chain_id: str) -> Optional[Dict]:
        """获取链路的上游注册（用于级联转发通知）

        当收到下游断连通知时，检查自己是否也需要向更上游转发

        Args:
            chain_id: 链路标识

        Returns:
            上游注册信息，如果本节点是链路起点则返回 None
        """
        with self._get_conn() as conn:
            cursor = conn.cursor()
            row = cursor.execute(
                "SELECT * FROM chain_registrations WHERE chain_id = ?",
                (chain_id,)
            ).fetchone()
            if not row:
                return None
            columns = [desc[0] for desc in cursor.description]
            return dict(zip(columns, row))

    def add_chain_registration(
        self,
        chain_id: str,
        upstream_node_tag: str,
        upstream_endpoint: str,
        upstream_psk: str,
        downstream_node_tag: str
    ) -> int:
        """添加链路注册

        当上游节点启用链路时，向中间节点注册，以便断连时能收到通知

        Args:
            chain_id: 链路标识
            upstream_node_tag: 上游节点标签
            upstream_endpoint: 上游节点端点（IP:port）
            upstream_psk: 上游节点 PSK（用于向上游发送通知时的认证）
            downstream_node_tag: 下游节点标签

        Returns:
            新记录 ID
        """
        with self._get_conn() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT OR REPLACE INTO chain_registrations
                (chain_id, upstream_node_tag, upstream_endpoint, upstream_psk, downstream_node_tag)
                VALUES (?, ?, ?, ?, ?)
            """, (chain_id, upstream_node_tag, upstream_endpoint, upstream_psk, downstream_node_tag))
            conn.commit()
            return cursor.lastrowid

    def delete_chain_registration(self, chain_id: str, upstream_node_tag: str = None) -> bool:
        """删除链路注册

        Args:
            chain_id: 链路标识
            upstream_node_tag: 上游节点标签（可选，不指定则删除该链路的所有注册）

        Returns:
            是否删除成功
        """
        with self._get_conn() as conn:
            cursor = conn.cursor()
            if upstream_node_tag:
                cursor.execute(
                    "DELETE FROM chain_registrations WHERE chain_id = ? AND upstream_node_tag = ?",
                    (chain_id, upstream_node_tag)
                )
            else:
                cursor.execute(
                    "DELETE FROM chain_registrations WHERE chain_id = ?",
                    (chain_id,)
                )
            conn.commit()
            return cursor.rowcount > 0

    def delete_chain_registrations_by_downstream(self, downstream_node_tag: str) -> int:
        """删除指定下游节点的所有注册

        当节点被删除时，清理相关注册

        Args:
            downstream_node_tag: 下游节点标签

        Returns:
            删除的记录数
        """
        with self._get_conn() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "DELETE FROM chain_registrations WHERE downstream_node_tag = ?",
                (downstream_node_tag,)
            )
            conn.commit()
            return cursor.rowcount

    def update_chain_downstream_status(
        self,
        chain_tag: str,
        status: str,
        disconnected_node: str = None
    ) -> bool:
        """更新链路的下游状态

        Args:
            chain_tag: 链路标签
            status: 状态 ('unknown', 'connected', 'disconnected')
            disconnected_node: 断开的节点标签

        Returns:
            是否更新成功
        """
        with self._get_conn() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                UPDATE node_chains
                SET downstream_status = ?,
                    disconnected_node = ?,
                    updated_at = CURRENT_TIMESTAMP
                WHERE tag = ?
            """, (status, disconnected_node, chain_tag))
            conn.commit()
            return cursor.rowcount > 0

    def get_chains_with_downstream_node(self, node_tag: str) -> List[Dict]:
        """获取包含指定节点作为下游的所有链路

        用于当节点断开时，找到需要更新状态的链路

        Args:
            node_tag: 节点标签

        Returns:
            链路列表
        """
        chains = self.get_node_chains()
        result = []
        for chain in chains:
            hops = chain.get("hops", [])
            # 检查节点是否在链路中（不是第一个节点，因为第一个是直连）
            if node_tag in hops[1:]:
                result.append(chain)
        return result

    # ============ Chain Routing 管理（终端节点 DSCP/email 到出口映射）============

    def get_chain_routing_list(self, mark_type: Optional[str] = None) -> List[Dict]:
        """获取链路路由列表

        Args:
            mark_type: 过滤标记类型 ('dscp' 或 'xray_email')，None 返回全部

        Returns:
            链路路由列表
        """
        with self._get_conn() as conn:
            cursor = conn.cursor()
            if mark_type:
                rows = cursor.execute(
                    "SELECT * FROM chain_routing WHERE mark_type = ? ORDER BY mark_value",
                    (mark_type,)
                ).fetchall()
            else:
                rows = cursor.execute(
                    "SELECT * FROM chain_routing ORDER BY mark_type, mark_value"
                ).fetchall()
            columns = [desc[0] for desc in cursor.description]
            return [dict(zip(columns, row)) for row in rows]

    def get_chain_routing(self, chain_tag: str, mark_value: int, mark_type: str = "dscp") -> Optional[Dict]:
        """获取单个链路路由

        Args:
            chain_tag: 链路标识
            mark_value: 标记值
            mark_type: 标记类型

        Returns:
            链路路由字典或 None
        """
        with self._get_conn() as conn:
            cursor = conn.cursor()
            row = cursor.execute(
                "SELECT * FROM chain_routing WHERE chain_tag = ? AND mark_value = ? AND mark_type = ?",
                (chain_tag, mark_value, mark_type)
            ).fetchone()
            if row:
                columns = [desc[0] for desc in cursor.description]
                return dict(zip(columns, row))
            return None

    def get_chain_routing_by_mark(self, mark_value: int, mark_type: str = "dscp") -> Optional[Dict]:
        """根据标记值查找链路路由

        用于终端节点根据 DSCP/email 标记查找应该使用的出口

        Args:
            mark_value: 标记值
            mark_type: 标记类型

        Returns:
            链路路由字典或 None
        """
        with self._get_conn() as conn:
            cursor = conn.cursor()
            row = cursor.execute(
                "SELECT * FROM chain_routing WHERE mark_value = ? AND mark_type = ?",
                (mark_value, mark_type)
            ).fetchone()
            if row:
                columns = [desc[0] for desc in cursor.description]
                return dict(zip(columns, row))
            return None

    # 常量定义：保留的 DSCP 值（QoS 常用值）
    RESERVED_DSCP_VALUES = frozenset({0, 10, 12, 14, 18, 20, 22, 26, 28, 30, 34, 36, 38, 46})
    VALID_MARK_TYPES = frozenset({"dscp", "xray_email"})

    def add_chain_routing(
        self,
        chain_tag: str,
        mark_value: int,
        egress_tag: str,
        mark_type: str = "dscp",
        source_node: Optional[str] = None
    ) -> int:
        """添加链路路由

        Args:
            chain_tag: 链路标识
            mark_value: 标记值 (DSCP: 1-63)
            egress_tag: 本地出口 tag
            mark_type: 标记类型 ('dscp' 或 'xray_email')
            source_node: 注册来源节点

        Returns:
            新记录的 ID

        Raises:
            ValueError: 如果 mark_type 无效，或 DSCP 值超出范围/被保留
        """
        # 验证 mark_type
        if mark_type not in self.VALID_MARK_TYPES:
            raise ValueError(f"Invalid mark_type: {mark_type}. Must be one of {self.VALID_MARK_TYPES}")

        # 验证 DSCP 值范围和保留值
        if mark_type == "dscp":
            if not (1 <= mark_value <= 63):
                raise ValueError(f"DSCP value must be 1-63, got {mark_value}")
            if mark_value in self.RESERVED_DSCP_VALUES:
                raise ValueError(f"DSCP value {mark_value} is reserved for QoS")

        with self._get_conn() as conn:
            cursor = conn.cursor()
            existing = cursor.execute(
                "SELECT chain_tag FROM chain_routing WHERE mark_value = ? AND mark_type = ?",
                (mark_value, mark_type),
            ).fetchone()
            if existing and existing[0] != chain_tag:
                raise ValueError(
                    f"Mark value {mark_value} ({mark_type}) already registered to chain '{existing[0]}'"
                )

            cursor.execute("""
                INSERT INTO chain_routing (chain_tag, mark_value, mark_type, egress_tag, source_node)
                VALUES (?, ?, ?, ?, ?)
            """, (chain_tag, mark_value, mark_type, egress_tag, source_node))
            conn.commit()
            return cursor.lastrowid

    def add_or_update_chain_routing(
        self,
        chain_tag: str,
        mark_value: int,
        egress_tag: str,
        mark_type: str = "dscp",
        source_node: Optional[str] = None
    ) -> int:
        """添加或更新链路路由 (原子操作)

        使用显式 UPDATE/INSERT 更新同一链路记录，避免覆盖其他链路。
        如果路由已存在（相同 chain_tag + mark_value + mark_type），则更新。

        Args:
            chain_tag: 链路标识
            mark_value: 标记值 (DSCP: 1-63)
            egress_tag: 本地出口 tag
            mark_type: 标记类型 ('dscp' 或 'xray_email')
            source_node: 注册来源节点

        Returns:
            记录的 ID

        Raises:
            ValueError: 如果 mark_type 无效，或 DSCP 值超出范围/被保留
        """
        # 验证 mark_type
        if mark_type not in self.VALID_MARK_TYPES:
            raise ValueError(f"Invalid mark_type: {mark_type}. Must be one of {self.VALID_MARK_TYPES}")

        # 验证 DSCP 值范围和保留值
        if mark_type == "dscp":
            if not (1 <= mark_value <= 63):
                raise ValueError(f"DSCP value must be 1-63, got {mark_value}")
            if mark_value in self.RESERVED_DSCP_VALUES:
                raise ValueError(f"DSCP value {mark_value} is reserved for QoS")

        with self._get_conn() as conn:
            cursor = conn.cursor()
            existing = cursor.execute(
                "SELECT chain_tag FROM chain_routing WHERE mark_value = ? AND mark_type = ?",
                (mark_value, mark_type),
            ).fetchone()
            if existing and existing[0] != chain_tag:
                raise ValueError(
                    f"Mark value {mark_value} ({mark_type}) already registered to chain '{existing[0]}'"
                )

            existing_row = cursor.execute(
                "SELECT id FROM chain_routing WHERE chain_tag = ? AND mark_value = ? AND mark_type = ?",
                (chain_tag, mark_value, mark_type),
            ).fetchone()

            if existing_row:
                cursor.execute(
                    """
                    UPDATE chain_routing
                    SET egress_tag = ?, source_node = ?, updated_at = CURRENT_TIMESTAMP
                    WHERE id = ?
                    """,
                    (egress_tag, source_node, existing_row[0]),
                )
                conn.commit()
                return existing_row[0]

            cursor.execute(
                """
                INSERT INTO chain_routing
                    (chain_tag, mark_value, mark_type, egress_tag, source_node, updated_at)
                VALUES (?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
                """,
                (chain_tag, mark_value, mark_type, egress_tag, source_node),
            )
            conn.commit()
            return cursor.lastrowid

    def update_chain_routing(
        self,
        chain_tag: str,
        mark_value: int,
        mark_type: str = "dscp",
        **kwargs
    ) -> bool:
        """更新链路路由

        Args:
            chain_tag: 链路标识
            mark_value: 标记值
            mark_type: 标记类型
            **kwargs: 要更新的字段 (egress_tag, source_node)

        Returns:
            是否成功更新
        """
        allowed_fields = {"egress_tag", "source_node"}
        updates = []
        values = []
        for key, value in kwargs.items():
            if key in allowed_fields:
                updates.append(f"{key} = ?")
                values.append(value)
        if not updates:
            return False
        updates.append("updated_at = CURRENT_TIMESTAMP")
        values.extend([chain_tag, mark_value, mark_type])
        with self._get_conn() as conn:
            cursor = conn.cursor()
            cursor.execute(f"""
                UPDATE chain_routing
                SET {", ".join(updates)}
                WHERE chain_tag = ? AND mark_value = ? AND mark_type = ?
            """, values)
            conn.commit()
            return cursor.rowcount > 0

    def delete_chain_routing(self, chain_tag: str, mark_value: int, mark_type: str = "dscp") -> bool:
        """删除链路路由

        Args:
            chain_tag: 链路标识
            mark_value: 标记值
            mark_type: 标记类型

        Returns:
            是否成功删除
        """
        with self._get_conn() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "DELETE FROM chain_routing WHERE chain_tag = ? AND mark_value = ? AND mark_type = ?",
                (chain_tag, mark_value, mark_type)
            )
            conn.commit()
            return cursor.rowcount > 0

    def delete_chain_routing_by_chain(self, chain_tag: str) -> int:
        """删除指定链路的所有路由

        Args:
            chain_tag: 链路标识

        Returns:
            删除的记录数
        """
        with self._get_conn() as conn:
            cursor = conn.cursor()
            cursor.execute("DELETE FROM chain_routing WHERE chain_tag = ?", (chain_tag,))
            conn.commit()
            return cursor.rowcount

    def delete_chain_routing_by_source(self, source_node: str) -> int:
        """删除指定来源节点注册的所有路由

        用于节点断开时清理其注册的路由

        Args:
            source_node: 来源节点 tag

        Returns:
            删除的记录数
        """
        with self._get_conn() as conn:
            cursor = conn.cursor()
            cursor.execute("DELETE FROM chain_routing WHERE source_node = ?", (source_node,))
            conn.commit()
            return cursor.rowcount

    # ============ 终端出口缓存 (Phase 11.1) ============

    def get_terminal_egress_cache(self, chain_tag: str) -> Optional[Dict]:
        """获取终端出口缓存

        Args:
            chain_tag: 链路标识

        Returns:
            缓存记录（包含 egress_list, terminal_node, cached_at, expires_at）或 None
        """
        with self._get_conn() as conn:
            cursor = conn.cursor()
            row = cursor.execute("""
                SELECT id, chain_tag, terminal_node, egress_list, cached_at, expires_at
                FROM terminal_egress_cache
                WHERE chain_tag = ?
            """, (chain_tag,)).fetchone()

            if not row:
                return None

            columns = [desc[0] for desc in cursor.description]
            return dict(zip(columns, row))

    def update_terminal_egress_cache(
        self,
        chain_tag: str,
        terminal_node: str,
        egress_list: List[Dict],
        ttl_seconds: int = 300
    ) -> bool:
        """更新或创建终端出口缓存

        Args:
            chain_tag: 链路标识
            terminal_node: 终端节点 tag
            egress_list: 出口列表 (JSON 可序列化的列表)
            ttl_seconds: 缓存过期时间（秒），默认 5 分钟，最大 86400 (24h)

        Returns:
            是否成功
        """
        # TTL 边界验证 (Phase 11.1)
        if not isinstance(ttl_seconds, int) or ttl_seconds < 0 or ttl_seconds > 86400:
            logger.warning(f"Invalid ttl_seconds: {ttl_seconds}, using default 300")
            ttl_seconds = 300

        egress_json = json.dumps(egress_list, ensure_ascii=False)

        with self._get_conn() as conn:
            cursor = conn.cursor()
            # 使用 INSERT OR REPLACE 以兼容旧版 SQLite/pysqlcipher3
            # 先删除旧记录（如果存在）
            cursor.execute("DELETE FROM terminal_egress_cache WHERE chain_tag = ?", (chain_tag,))
            # 插入新记录
            cursor.execute("""
                INSERT INTO terminal_egress_cache (chain_tag, terminal_node, egress_list, cached_at, expires_at)
                VALUES (?, ?, ?, CURRENT_TIMESTAMP, datetime(CURRENT_TIMESTAMP, ? || ' seconds'))
            """, (chain_tag, terminal_node, egress_json, f"+{ttl_seconds}"))
            conn.commit()
            return True

    def delete_terminal_egress_cache(self, chain_tag: str) -> bool:
        """删除终端出口缓存

        Args:
            chain_tag: 链路标识

        Returns:
            是否成功删除
        """
        with self._get_conn() as conn:
            cursor = conn.cursor()
            cursor.execute("DELETE FROM terminal_egress_cache WHERE chain_tag = ?", (chain_tag,))
            conn.commit()
            return cursor.rowcount > 0

    def cleanup_expired_terminal_egress_cache(self) -> int:
        """清理过期的终端出口缓存

        Returns:
            清理的记录数
        """
        with self._get_conn() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                DELETE FROM terminal_egress_cache
                WHERE expires_at < CURRENT_TIMESTAMP
            """)
            conn.commit()
            return cursor.rowcount

    def get_all_terminal_egress_cache(self) -> List[Dict]:
        """获取所有终端出口缓存记录

        Returns:
            所有缓存记录列表
        """
        with self._get_conn() as conn:
            cursor = conn.cursor()
            rows = cursor.execute("""
                SELECT id, chain_tag, terminal_node, egress_list, cached_at, expires_at
                FROM terminal_egress_cache
                ORDER BY chain_tag
            """).fetchall()

            columns = [desc[0] for desc in cursor.description]
            return [dict(zip(columns, row)) for row in rows]

    def get_next_available_dscp_value(self) -> Optional[int]:
        """获取下一个可用的 DSCP 值

        DSCP 范围: 1-63 (6 bits)
        保留值: 0 (默认), 46 (EF), 10/12/14 (AF11-13), 18/20/22 (AF21-23),
                26/28/30 (AF31-33), 34/36/38 (AF41-43)

        使用单一 UNION 查询优化性能（从 2 次查询减少到 1 次）

        Returns:
            可用的 DSCP 值，或 None 如果已用完
        """
        # 使用类常量代替内联定义
        available_range = set(range(1, 64)) - self.RESERVED_DSCP_VALUES

        with self._get_conn() as conn:
            cursor = conn.cursor()
            # 使用单一 UNION 查询代替两次独立查询
            rows = cursor.execute("""
                SELECT mark_value AS dscp FROM chain_routing WHERE mark_type = 'dscp'
                UNION
                SELECT dscp_value FROM node_chains WHERE dscp_value IS NOT NULL
            """).fetchall()

            used_values = {row[0] for row in rows}

            # 找到第一个可用值
            available = available_range - used_values
            if available:
                return min(available)
            return None

    def update_peer_node_tunnel_api_endpoint(self, tag: str, tunnel_api_endpoint: Optional[str]) -> bool:
        """更新对等节点的隧道 API 端点

        Args:
            tag: 节点标识
            tunnel_api_endpoint: 隧道内 API 地址 (如 10.200.200.2:36000)

        Returns:
            是否成功更新
        """
        with self._get_conn() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                UPDATE peer_nodes
                SET tunnel_api_endpoint = ?, updated_at = CURRENT_TIMESTAMP
                WHERE tag = ?
            """, (tunnel_api_endpoint, tag))
            conn.commit()
            return cursor.rowcount > 0


class DatabaseManager:
    """统一的数据库管理器，协调系统数据和用户数据"""

    def __init__(self, geodata_path: str, user_path: str, encryption_key: Optional[str] = None):
        """
        初始化数据库管理器

        Args:
            geodata_path: GeoIP 数据目录路径
            user_path: 用户数据库文件路径
            encryption_key: SQLCipher 加密密钥（用于 user 数据库）
        """
        self.geodata_path = geodata_path
        self.user_path = user_path
        self.encryption_key = encryption_key
        self.geodata = GeodataDatabase(geodata_path)
        self.user = UserDatabase(user_path, encryption_key)

    def get_statistics(self) -> Dict[str, int]:
        """获取完整统计信息"""
        geodata_stats = self.geodata.get_statistics()
        user_stats = self.user.get_statistics()
        return {**geodata_stats, **user_stats}

    # 系统数据（只读）
    def get_countries(self, limit: int = 100) -> List[Dict]:
        return self.geodata.get_countries(limit)

    def get_country(self, country_code: str) -> Optional[Dict]:
        return self.geodata.get_country(country_code)

    def get_country_ips(self, country_code: str, ip_version: Optional[int] = None, limit: int = 10000) -> List[str]:
        return self.geodata.get_country_ips(country_code, ip_version, limit)

    def search_countries(self, query: str, limit: int = 20) -> List[Dict]:
        return self.geodata.search_countries(query, limit)

    def get_domain_categories(self, group_type: Optional[str] = None) -> List[Dict]:
        return self.geodata.get_domain_categories(group_type)

    def get_domain_list(self, list_id: str) -> Optional[Dict]:
        return self.geodata.get_domain_list(list_id)

    def get_domain_list_with_domains(self, list_id: str, limit: int = 1000) -> Optional[Dict]:
        return self.geodata.get_domain_list_with_domains(list_id, limit)

    def search_domain_lists(self, query: str, limit: int = 20) -> List[Dict]:
        return self.geodata.search_domain_lists(query, limit)

    # 用户数据（读写）
    def get_routing_rules(self, enabled_only: bool = True) -> List[Dict]:
        return self.user.get_routing_rules(enabled_only)

    def add_routing_rule(self, rule_type: str, target: str, outbound: str, priority: int = 0, tag: Optional[str] = None) -> int:
        return self.user.add_routing_rule(rule_type, target, outbound, priority, tag)

    def add_routing_rules_batch(self, rules: List[tuple]) -> int:
        return self.user.add_routing_rules_batch(rules)

    def update_routing_rule(self, rule_id: int, outbound: Optional[str] = None,
                          priority: Optional[int] = None, enabled: Optional[bool] = None) -> bool:
        return self.user.update_routing_rule(rule_id, outbound, priority, enabled)

    def delete_routing_rule(self, rule_id: int) -> bool:
        return self.user.delete_routing_rule(rule_id)

    def delete_all_routing_rules(self, preserve_adblock: bool = False) -> int:
        return self.user.delete_all_routing_rules(preserve_adblock)

    def get_outbounds(self, enabled_only: bool = True) -> List[Dict]:
        return self.user.get_outbounds(enabled_only)

    def get_outbound(self, tag: str) -> Optional[Dict]:
        return self.user.get_outbound(tag)

    def add_outbound(self, tag: str, type_: str, description: str = "", config: Optional[str] = None) -> bool:
        return self.user.add_outbound(tag, type_, description, config)

    # WireGuard 服务器
    def get_wireguard_server(self) -> Optional[Dict]:
        return self.user.get_wireguard_server()

    def set_wireguard_server(self, interface_name: str, address: str, listen_port: int,
                            mtu: int, private_key: str,
                            default_outbound: Optional[str] = None) -> bool:
        return self.user.set_wireguard_server(interface_name, address, listen_port, mtu, private_key, default_outbound)

    # WireGuard 对等点
    def get_wireguard_peers(self, enabled_only: bool = True) -> List[Dict]:
        return self.user.get_wireguard_peers(enabled_only)

    def get_wireguard_peer(self, peer_id: int) -> Optional[Dict]:
        return self.user.get_wireguard_peer(peer_id)

    def get_wireguard_peer_by_name(self, name: str) -> Optional[Dict]:
        return self.user.get_wireguard_peer_by_name(name)

    def add_wireguard_peer(self, name: str, public_key: str, allowed_ips: str,
                          preshared_key: Optional[str] = None,
                          allow_lan: bool = False,
                          lan_subnet: Optional[str] = None,
                          default_outbound: Optional[str] = None) -> int:
        return self.user.add_wireguard_peer(name, public_key, allowed_ips, preshared_key, allow_lan, lan_subnet, default_outbound)

    def update_wireguard_peer(self, peer_id: int, name: Optional[str] = None,
                             allowed_ips: Optional[str] = None, enabled: Optional[bool] = None,
                             allow_lan: Optional[bool] = None,
                             lan_subnet: Optional[str] = None,
                             default_outbound: Optional[str] = ...) -> bool:
        return self.user.update_wireguard_peer(peer_id, name, allowed_ips, enabled, allow_lan, lan_subnet, default_outbound)

    def delete_wireguard_peer(self, peer_id: int) -> bool:
        return self.user.delete_wireguard_peer(peer_id)

    # PIA Profiles
    def get_pia_profiles(self, enabled_only: bool = True) -> List[Dict]:
        return self.user.get_pia_profiles(enabled_only)

    def get_pia_profile(self, profile_id: int) -> Optional[Dict]:
        return self.user.get_pia_profile(profile_id)

    def get_pia_profile_by_name(self, name: str) -> Optional[Dict]:
        return self.user.get_pia_profile_by_name(name)

    def add_pia_profile(self, name: str, region_id: str, description: str = "",
                       custom_dns: str = None) -> int:
        return self.user.add_pia_profile(name, region_id, description, custom_dns)

    def update_pia_profile(self, profile_id: int, description: Optional[str] = None,
                          region_id: Optional[str] = None, custom_dns: Optional[str] = None,
                          enabled: Optional[bool] = None) -> bool:
        return self.user.update_pia_profile(profile_id, description, region_id, custom_dns, enabled)

    def delete_pia_profile(self, profile_id: int) -> bool:
        return self.user.delete_pia_profile(profile_id)

    def update_pia_credentials(self, name: str, credentials: Dict[str, Any]) -> bool:
        return self.user.update_pia_credentials(name, credentials)

    # PIA Account Credentials (for database persistence)
    def get_pia_credentials(self) -> Optional[Dict[str, str]]:
        return self.user.get_pia_credentials()

    def set_pia_credentials(self, username: str, password: str) -> bool:
        return self.user.set_pia_credentials(username, password)

    def delete_pia_credentials(self) -> bool:
        return self.user.delete_pia_credentials()

    def has_pia_credentials(self) -> bool:
        return self.user.has_pia_credentials()

    # Custom Category Items
    def get_custom_category_items(self, category_id: Optional[str] = None) -> Dict[str, List[Dict]]:
        return self.user.get_custom_category_items(category_id)

    def add_custom_category_item(self, category_id: str, item_id: str, name: str,
                                  domains: List[str]) -> int:
        return self.user.add_custom_category_item(category_id, item_id, name, domains)

    def delete_custom_category_item(self, item_id: str) -> bool:
        return self.user.delete_custom_category_item(item_id)

    def get_custom_category_item(self, item_id: str) -> Optional[Dict]:
        return self.user.get_custom_category_item(item_id)

    # Settings
    def get_setting(self, key: str, default: str = None) -> Optional[str]:
        return self.user.get_setting(key, default)

    def set_setting(self, key: str, value: str) -> bool:
        return self.user.set_setting(key, value)

    def get_all_settings(self) -> Dict[str, str]:
        return self.user.get_all_settings()

    # Admin Authentication
    def is_admin_setup(self) -> bool:
        """检查管理员密码是否已设置"""
        return self.user.is_admin_setup()

    def set_admin_password(self, password_hash: str) -> bool:
        """设置或更新管理员密码哈希"""
        return self.user.set_admin_password(password_hash)

    def get_admin_password_hash(self) -> Optional[str]:
        """获取管理员密码哈希"""
        return self.user.get_admin_password_hash()

    def get_or_create_jwt_secret(self) -> str:
        """获取 JWT 密钥，不存在则创建"""
        return self.user.get_or_create_jwt_secret()

    # Custom Egress
    def get_custom_egress_list(self, enabled_only: bool = False) -> List[Dict]:
        return self.user.get_custom_egress_list(enabled_only)

    def get_custom_egress(self, tag: str) -> Optional[Dict]:
        return self.user.get_custom_egress(tag)

    def add_custom_egress(self, tag: str, server: str, private_key: str,
                          public_key: str, address: str, description: str = "",
                          port: int = 51820, mtu: int = 1420, dns: str = "1.1.1.1",
                          pre_shared_key: Optional[str] = None,
                          reserved: Optional[List[int]] = None) -> int:
        return self.user.add_custom_egress(tag, server, private_key, public_key,
                                           address, description, port, mtu, dns,
                                           pre_shared_key, reserved)

    def update_custom_egress(self, tag: str, **kwargs) -> bool:
        return self.user.update_custom_egress(tag, **kwargs)

    def delete_custom_egress(self, tag: str) -> bool:
        return self.user.delete_custom_egress(tag)

    # Remote Rule Sets
    def get_remote_rule_sets(self, enabled_only: bool = False, category: Optional[str] = None) -> List[Dict]:
        return self.user.get_remote_rule_sets(enabled_only, category)

    def get_remote_rule_set(self, tag: str) -> Optional[Dict]:
        return self.user.get_remote_rule_set(tag)

    def toggle_remote_rule_set(self, tag: str) -> bool:
        return self.user.toggle_remote_rule_set(tag)

    def update_remote_rule_set(self, tag: str, **kwargs) -> bool:
        return self.user.update_remote_rule_set(tag, **kwargs)

    def add_remote_rule_set(self, tag: str, name: str, url: str,
                            description: str = "", format: str = "adblock",
                            outbound: str = "block", category: str = "general",
                            region: Optional[str] = None, priority: int = 0) -> int:
        return self.user.add_remote_rule_set(tag, name, url, description, format,
                                             outbound, category, region, priority)

    def delete_remote_rule_set(self, tag: str) -> bool:
        return self.user.delete_remote_rule_set(tag)

    # Direct Egress
    def get_direct_egress_list(self, enabled_only: bool = False) -> List[Dict]:
        return self.user.get_direct_egress_list(enabled_only)

    def get_direct_egress(self, tag: str) -> Optional[Dict]:
        return self.user.get_direct_egress(tag)

    def add_direct_egress(self, tag: str, description: str = "",
                          bind_interface: Optional[str] = None,
                          inet4_bind_address: Optional[str] = None,
                          inet6_bind_address: Optional[str] = None) -> int:
        return self.user.add_direct_egress(tag, description, bind_interface,
                                           inet4_bind_address, inet6_bind_address)

    def update_direct_egress(self, tag: str, **kwargs) -> bool:
        return self.user.update_direct_egress(tag, **kwargs)

    def delete_direct_egress(self, tag: str) -> bool:
        return self.user.delete_direct_egress(tag)

    # OpenVPN Egress
    def get_openvpn_egress_list(self, enabled_only: bool = False) -> List[Dict]:
        return self.user.get_openvpn_egress_list(enabled_only)

    def get_openvpn_egress(self, tag: str) -> Optional[Dict]:
        return self.user.get_openvpn_egress(tag)

    def get_next_openvpn_tun_device(self) -> str:
        return self.user.get_next_openvpn_tun_device()

    def add_openvpn_egress(
        self,
        tag: str,
        remote_host: str,
        ca_cert: str,
        description: str = "",
        protocol: str = "udp",
        remote_port: int = 1194,
        client_cert: Optional[str] = None,
        client_key: Optional[str] = None,
        tls_auth: Optional[str] = None,
        tls_crypt: Optional[str] = None,
        crl_verify: Optional[str] = None,
        auth_user: Optional[str] = None,
        auth_pass: Optional[str] = None,
        cipher: str = "AES-256-GCM",
        auth: str = "SHA256",
        compress: Optional[str] = None,
        extra_options: Optional[List[str]] = None
    ) -> int:
        return self.user.add_openvpn_egress(
            tag, remote_host, ca_cert, description, protocol, remote_port,
            client_cert, client_key, tls_auth, tls_crypt, crl_verify, auth_user, auth_pass,
            cipher, auth, compress, extra_options
        )

    def update_openvpn_egress(self, tag: str, **kwargs) -> bool:
        return self.user.update_openvpn_egress(tag, **kwargs)

    def delete_openvpn_egress(self, tag: str) -> bool:
        return self.user.delete_openvpn_egress(tag)

    # V2Ray Egress
    def get_v2ray_egress_list(self, enabled_only: bool = False, protocol: Optional[str] = None) -> List[Dict]:
        return self.user.get_v2ray_egress_list(enabled_only, protocol)

    def get_v2ray_egress(self, tag: str) -> Optional[Dict]:
        return self.user.get_v2ray_egress(tag)

    def get_next_v2ray_egress_socks_port(self) -> int:
        return self.user.get_next_v2ray_egress_socks_port()

    def add_v2ray_egress(
        self,
        tag: str,
        protocol: str,
        server: str,
        server_port: int = 443,
        description: str = "",
        uuid: Optional[str] = None,
        password: Optional[str] = None,
        security: str = "auto",
        alter_id: int = 0,
        flow: Optional[str] = None,
        tls_enabled: bool = True,
        tls_sni: Optional[str] = None,
        tls_alpn: Optional[List[str]] = None,
        tls_allow_insecure: bool = False,
        tls_fingerprint: Optional[str] = None,
        reality_enabled: bool = False,
        reality_public_key: Optional[str] = None,
        reality_short_id: Optional[str] = None,
        transport_type: str = "tcp",
        transport_config: Optional[Dict] = None,
        multiplex_enabled: bool = False,
        multiplex_protocol: Optional[str] = None,
        multiplex_max_connections: Optional[int] = None,
        multiplex_min_streams: Optional[int] = None,
        multiplex_max_streams: Optional[int] = None
    ) -> int:
        return self.user.add_v2ray_egress(
            tag, protocol, server, server_port, description,
            uuid, password, security, alter_id, flow,
            tls_enabled, tls_sni, tls_alpn, tls_allow_insecure, tls_fingerprint,
            reality_enabled, reality_public_key, reality_short_id,
            transport_type, transport_config,
            multiplex_enabled, multiplex_protocol, multiplex_max_connections,
            multiplex_min_streams, multiplex_max_streams
        )

    def update_v2ray_egress(self, tag: str, **kwargs) -> bool:
        return self.user.update_v2ray_egress(tag, **kwargs)

    def delete_v2ray_egress(self, tag: str) -> bool:
        return self.user.delete_v2ray_egress(tag)

    # WARP Egress
    def get_warp_egress_list(self, enabled_only: bool = False) -> List[Dict]:
        return self.user.get_warp_egress_list(enabled_only)

    def get_warp_egress(self, tag: str) -> Optional[Dict]:
        return self.user.get_warp_egress(tag)

    def get_next_warp_socks_port(self) -> int:
        return self.user.get_next_warp_socks_port()

    def add_warp_egress(
        self,
        tag: str,
        description: str = "",
        config_path: Optional[str] = None,
        license_key: Optional[str] = None,
        account_type: str = "free",
        endpoint_v4: Optional[str] = None,
        endpoint_v6: Optional[str] = None,
        enabled: bool = True,
        account_id: Optional[str] = None
    ) -> int:
        """Phase 3: WireGuard only, protocol/mode/socks_port removed"""
        return self.user.add_warp_egress(
            tag, description, config_path, license_key, account_type,
            endpoint_v4, endpoint_v6, enabled, account_id
        )

    def update_warp_egress(self, tag: str, **kwargs) -> bool:
        return self.user.update_warp_egress(tag, **kwargs)

    def delete_warp_egress(self, tag: str) -> bool:
        return self.user.delete_warp_egress(tag)

    # Outbound Groups (负载均衡/故障转移)
    def get_outbound_groups(self, enabled_only: bool = False) -> List[Dict]:
        return self.user.get_outbound_groups(enabled_only)

    def get_outbound_group(self, tag: str) -> Optional[Dict]:
        return self.user.get_outbound_group(tag)

    def get_next_routing_table(self) -> Optional[int]:
        return self.user.get_next_routing_table()

    def get_all_egress_tags(self) -> set:
        return self.user.get_all_egress_tags()

    def tag_exists_in_any_egress(self, tag: str) -> bool:
        return self.user.tag_exists_in_any_egress(tag)

    def validate_group_members(
        self,
        members: List[str],
        exclude_tag: Optional[str] = None
    ) -> tuple:
        return self.user.validate_group_members(members, exclude_tag)

    def check_circular_reference(
        self,
        tag: str,
        members: List[str],
        visited: Optional[set] = None
    ) -> tuple:
        return self.user.check_circular_reference(tag, members, visited)

    def add_outbound_group(
        self,
        tag: str,
        group_type: str,
        members: List[str],
        description: str = "",
        weights: Optional[Dict[str, int]] = None,
        health_check_url: str = "http://www.gstatic.com/generate_204",
        health_check_interval: int = 60,
        health_check_timeout: int = 5,
        enabled: bool = True
    ) -> int:
        return self.user.add_outbound_group(
            tag, group_type, members, description, weights,
            health_check_url, health_check_interval, health_check_timeout, enabled
        )

    def update_outbound_group(self, tag: str, **kwargs) -> bool:
        return self.user.update_outbound_group(tag, **kwargs)

    def delete_outbound_group(self, tag: str) -> bool:
        return self.user.delete_outbound_group(tag)

    # V2Ray Inbound
    def get_v2ray_inbound_config(self) -> Optional[Dict]:
        return self.user.get_v2ray_inbound_config()

    def set_v2ray_inbound_config(
        self,
        protocol: str,
        listen_port: int = 443,
        listen_address: str = "0.0.0.0",
        tls_enabled: bool = True,
        tls_cert_path: Optional[str] = None,
        tls_key_path: Optional[str] = None,
        tls_cert_content: Optional[str] = None,
        tls_key_content: Optional[str] = None,
        xtls_vision_enabled: int = 0,
        reality_enabled: int = 0,
        reality_private_key: Optional[str] = None,
        reality_public_key: Optional[str] = None,
        reality_short_ids: Optional[str] = None,
        reality_dest: Optional[str] = None,
        reality_server_names: Optional[str] = None,
        transport_type: str = "tcp",
        transport_config: Optional[Dict] = None,
        fallback_server: Optional[str] = None,
        fallback_port: Optional[int] = None,
        tun_device: str = "xray-tun0",
        tun_subnet: str = "10.24.0.0/24",
        enabled: bool = False,
        default_outbound: Optional[str] = None
    ) -> bool:
        return self.user.set_v2ray_inbound_config(
            protocol, listen_port, listen_address,
            tls_enabled, tls_cert_path, tls_key_path, tls_cert_content, tls_key_content,
            xtls_vision_enabled, reality_enabled, reality_private_key, reality_public_key,
            reality_short_ids, reality_dest, reality_server_names,
            transport_type, transport_config, fallback_server, fallback_port,
            tun_device, tun_subnet, enabled, default_outbound
        )

    # Alias for API compatibility
    save_v2ray_inbound_config = set_v2ray_inbound_config

    def update_v2ray_inbound_config(self, **kwargs) -> bool:
        return self.user.update_v2ray_inbound_config(**kwargs)

    # V2Ray Users
    def get_v2ray_users(self, enabled_only: bool = True) -> List[Dict]:
        return self.user.get_v2ray_users(enabled_only)

    def get_v2ray_user(self, user_id: int) -> Optional[Dict]:
        return self.user.get_v2ray_user(user_id)

    def get_v2ray_user_by_name(self, name: str) -> Optional[Dict]:
        return self.user.get_v2ray_user_by_name(name)

    def add_v2ray_user(
        self,
        name: str,
        uuid: Optional[str] = None,
        password: Optional[str] = None,
        email: Optional[str] = None,
        alter_id: int = 0,
        flow: Optional[str] = None
    ) -> int:
        return self.user.add_v2ray_user(name, uuid, password, email, alter_id, flow)

    def update_v2ray_user(self, user_id: int, **kwargs) -> bool:
        return self.user.update_v2ray_user(user_id, **kwargs)

    def delete_v2ray_user(self, user_id: int) -> bool:
        return self.user.delete_v2ray_user(user_id)

    # Peer Nodes (对等节点管理)
    def get_peer_nodes(self, enabled_only: bool = False) -> List[Dict]:
        return self.user.get_peer_nodes(enabled_only)

    def get_peer_node(self, tag: str) -> Optional[Dict]:
        return self.user.get_peer_node(tag)

    def get_peer_node_by_id(self, node_id: int) -> Optional[Dict]:
        return self.user.get_peer_node_by_id(node_id)

    def add_peer_node(
        self,
        tag: str,
        name: str,
        endpoint: str,
        psk_hash: str = "",  # 已废弃，保留参数兼容
        psk_encrypted: Optional[str] = None,  # 已废弃
        description: str = "",
        api_port: Optional[int] = None,
        tunnel_type: str = "wireguard",
        # 隧道状态和 IP 参数（Phase 2 配对系统需要）
        tunnel_status: str = "disconnected",
        tunnel_interface: Optional[str] = None,  # Phase 11-Tunnel: WireGuard 接口名
        tunnel_local_ip: Optional[str] = None,
        tunnel_remote_ip: Optional[str] = None,
        tunnel_port: Optional[int] = None,
        tunnel_api_endpoint: Optional[str] = None,
        # WireGuard 参数
        wg_private_key: Optional[str] = None,
        wg_public_key: Optional[str] = None,
        wg_peer_public_key: Optional[str] = None,
        # Xray 参数
        xray_protocol: str = "vless",
        xray_uuid: Optional[str] = None,
        # REALITY 配置（本节点作为服务端）
        xray_reality_private_key: Optional[str] = None,
        xray_reality_public_key: Optional[str] = None,
        xray_reality_short_id: Optional[str] = None,
        xray_reality_dest: str = "www.microsoft.com:443",
        xray_reality_server_names: str = '["www.microsoft.com"]',
        # 对端 REALITY 配置
        xray_peer_reality_public_key: Optional[str] = None,
        xray_peer_reality_short_id: Optional[str] = None,
        # XHTTP 传输配置
        xray_xhttp_path: str = "/",
        xray_xhttp_mode: str = "auto",
        xray_xhttp_host: Optional[str] = None,
        # 连接模式
        connection_mode: str = "outbound",
        default_outbound: Optional[str] = None,
        auto_reconnect: bool = True,
        enabled: bool = True,
        # Phase 11: 双向连接状态
        bidirectional_status: str = "pending",
    ) -> int:
        return self.user.add_peer_node(
            tag, name, endpoint, psk_hash, psk_encrypted, description, api_port,
            tunnel_type, tunnel_status, tunnel_interface,
            tunnel_local_ip, tunnel_remote_ip, tunnel_port, tunnel_api_endpoint,
            wg_private_key, wg_public_key, wg_peer_public_key,
            xray_protocol, xray_uuid,
            xray_reality_private_key, xray_reality_public_key, xray_reality_short_id,
            xray_reality_dest, xray_reality_server_names,
            xray_peer_reality_public_key, xray_peer_reality_short_id,
            xray_xhttp_path, xray_xhttp_mode, xray_xhttp_host,
            connection_mode, default_outbound, auto_reconnect, enabled,
            bidirectional_status
        )

    def update_peer_node(self, tag: str, **kwargs) -> bool:
        return self.user.update_peer_node(tag, **kwargs)

    def delete_peer_node(self, tag: str) -> bool:
        return self.user.delete_peer_node(tag)

    def get_connected_peer_nodes(self) -> List[Dict]:
        return self.user.get_connected_peer_nodes()

    def get_next_peer_tunnel_port(self) -> Optional[int]:
        return self.user.get_next_peer_tunnel_port()

    def get_next_peer_xray_socks_port(self) -> int:
        return self.user.get_next_peer_xray_socks_port()

    def get_next_peer_inbound_port(self) -> int:
        return self.user.get_next_peer_inbound_port()

    def get_peer_nodes_with_inbound(self) -> List[Dict]:
        return self.user.get_peer_nodes_with_inbound()

    # 双向连接管理 (Phase 11.1)
    def update_peer_bidirectional_status(self, tag: str, status: str) -> bool:
        return self.user.update_peer_bidirectional_status(tag, status)

    def get_peers_pending_bidirectional(self) -> List[Dict]:
        return self.user.get_peers_pending_bidirectional()

    def get_peers_by_bidirectional_status(self, status: str) -> List[Dict]:
        return self.user.get_peers_by_bidirectional_status(status)

    # Pending Pairings (待处理配对管理, Phase 11-Tunnel)
    def add_pending_pairing(
        self,
        pairing_id: str,
        local_tag: str,
        local_endpoint: str,
        tunnel_type: str = "wireguard",
        tunnel_local_ip: str = None,
        tunnel_remote_ip: str = None,
        tunnel_port: int = None,
        wg_private_key: str = None,
        wg_public_key: str = None,
        remote_wg_private_key: str = None,
        remote_wg_public_key: str = None,
        interface_name: str = None,
        expires_days: int = 7
    ) -> int:
        return self.user.add_pending_pairing(
            pairing_id, local_tag, local_endpoint, tunnel_type,
            tunnel_local_ip, tunnel_remote_ip, tunnel_port,
            wg_private_key, wg_public_key,
            remote_wg_private_key, remote_wg_public_key,
            interface_name, expires_days
        )

    def get_pending_pairing(self, pairing_id: str) -> Optional[Dict]:
        return self.user.get_pending_pairing(pairing_id)

    def get_pending_pairing_by_interface(self, interface_name: str) -> Optional[Dict]:
        return self.user.get_pending_pairing_by_interface(interface_name)

    def delete_pending_pairing(self, pairing_id: str) -> bool:
        return self.user.delete_pending_pairing(pairing_id)

    def cleanup_expired_pairings(self) -> int:
        return self.user.cleanup_expired_pairings()

    def get_all_pending_pairings(self) -> List[Dict]:
        return self.user.get_all_pending_pairings()

    # Phase 11-Cascade: 级联删除通知支持
    def log_peer_event(
        self,
        event_type: str,
        peer_tag: str,
        event_id: Optional[str] = None,
        from_node: Optional[str] = None,
        details: Optional[Dict] = None,
        source_ip: Optional[str] = None
    ) -> int:
        return self.user.log_peer_event(event_type, peer_tag, event_id, from_node, details, source_ip)

    def get_peer_events(
        self,
        peer_tag: Optional[str] = None,
        event_type: Optional[str] = None,
        limit: int = 100
    ) -> List[Dict]:
        return self.user.get_peer_events(peer_tag, event_type, limit)

    def add_peer_tombstone(
        self,
        tag: str,
        deleted_by: str = "local",
        reason: str = "deleted",
        ttl_hours: int = 24
    ) -> bool:
        return self.user.add_peer_tombstone(tag, deleted_by, reason, ttl_hours)

    def get_peer_tombstone(self, tag: str) -> Optional[Dict]:
        return self.user.get_peer_tombstone(tag)

    def is_peer_tombstoned(self, tag: str) -> bool:
        return self.user.is_peer_tombstoned(tag)

    def cleanup_expired_tombstones(self) -> int:
        return self.user.cleanup_expired_tombstones()

    def get_all_tombstones(self, include_expired: bool = False) -> List[Dict]:
        return self.user.get_all_tombstones(include_expired)

    def delete_peer_tombstone(self, tag: str) -> bool:
        return self.user.delete_peer_tombstone(tag)

    def cleanup_old_peer_events(self, hours: int = 168) -> int:
        return self.user.cleanup_old_peer_events(hours)

    def is_event_processed(self, event_id: str) -> bool:
        return self.user.is_event_processed(event_id)

    def mark_event_processed(
        self,
        event_id: str,
        from_node: str,
        action: Optional[str] = None
    ) -> bool:
        return self.user.mark_event_processed(event_id, from_node, action)

    def mark_event_if_not_processed(
        self,
        event_id: str,
        from_node: str,
        action: Optional[str] = None
    ) -> tuple:
        return self.user.mark_event_if_not_processed(event_id, from_node, action)

    def cleanup_old_processed_events(self, hours: int = 24) -> int:
        return self.user.cleanup_old_processed_events(hours)

    # Relay Routes (中继路由管理)
    def get_relay_routes(self, chain_tag: Optional[str] = None, enabled_only: bool = False) -> List[Dict]:
        return self.user.get_relay_routes(chain_tag, enabled_only)

    def add_relay_route(
        self,
        chain_tag: str,
        source_peer_tag: str,
        target_peer_tag: str,
        enabled: bool = True
    ) -> int:
        return self.user.add_relay_route(chain_tag, source_peer_tag, target_peer_tag, enabled)

    def delete_relay_route(self, route_id: int) -> bool:
        return self.user.delete_relay_route(route_id)

    def delete_relay_routes_by_chain(self, chain_tag: str) -> int:
        return self.user.delete_relay_routes_by_chain(chain_tag)

    def update_relay_route(self, route_id: int, **kwargs) -> bool:
        return self.user.update_relay_route(route_id, **kwargs)

    # Node Chains (多跳链路管理)
    def get_node_chains(self, enabled_only: bool = False) -> List[Dict]:
        return self.user.get_node_chains(enabled_only)

    def get_node_chain(self, tag: str) -> Optional[Dict]:
        return self.user.get_node_chain(tag)

    def add_node_chain(
        self,
        tag: str,
        name: str,
        hops: List[str],
        description: str = "",
        hop_protocols: Optional[Dict[str, str]] = None,
        entry_rules: Optional[Dict] = None,
        relay_rules: Optional[Dict] = None,
        priority: int = 0,
        enabled: bool = True,
        # 多跳链路架构 v2 新增字段
        exit_egress: Optional[str] = None,
        dscp_value: Optional[int] = None,
        chain_mark_type: str = "dscp",
        chain_state: str = "inactive",
        allow_transitive: bool = False  # Phase 11-Fix.Q: 传递模式验证
    ) -> int:
        return self.user.add_node_chain(
            tag, name, hops, description, hop_protocols,
            entry_rules, relay_rules, priority, enabled,
            exit_egress=exit_egress,
            dscp_value=dscp_value,
            chain_mark_type=chain_mark_type,
            chain_state=chain_state,
            allow_transitive=allow_transitive
        )

    def update_node_chain(self, tag: str, **kwargs) -> bool:
        return self.user.update_node_chain(tag, **kwargs)

    def atomic_chain_state_transition(
        self,
        tag: str,
        expected_state: str,
        new_state: str,
        timeout_ms: int = 30000,
        last_error: Optional[str] = None
    ) -> tuple:
        """Phase 11-Fix.T/U: 原子性链路状态转换（代理方法）"""
        return self.user.atomic_chain_state_transition(
            tag, expected_state, new_state, timeout_ms, last_error
        )

    def delete_node_chain(self, tag: str) -> bool:
        return self.user.delete_node_chain(tag)

    def validate_chain_hops(self, hops: List[str], allow_transitive: bool = False) -> tuple:
        return self.user.validate_chain_hops(hops, allow_transitive)

    # Chain Registrations (级联通知用)
    def get_chain_registrations(self) -> List[Dict]:
        return self.user.get_chain_registrations()

    def get_chain_registrations_by_downstream(self, downstream_node_tag: str) -> List[Dict]:
        return self.user.get_chain_registrations_by_downstream(downstream_node_tag)

    def get_chain_upstream_registration(self, chain_id: str) -> Optional[Dict]:
        return self.user.get_chain_upstream_registration(chain_id)

    def add_chain_registration(
        self,
        chain_id: str,
        upstream_node_tag: str,
        upstream_endpoint: str,
        upstream_psk: str,
        downstream_node_tag: str
    ) -> int:
        return self.user.add_chain_registration(
            chain_id, upstream_node_tag, upstream_endpoint, upstream_psk, downstream_node_tag
        )

    def delete_chain_registration(self, chain_id: str, upstream_node_tag: str = None) -> bool:
        return self.user.delete_chain_registration(chain_id, upstream_node_tag)

    def delete_chain_registrations_by_downstream(self, downstream_node_tag: str) -> int:
        return self.user.delete_chain_registrations_by_downstream(downstream_node_tag)

    def update_chain_downstream_status(
        self,
        chain_tag: str,
        status: str,
        disconnected_node: str = None
    ) -> bool:
        return self.user.update_chain_downstream_status(chain_tag, status, disconnected_node)

    def get_chains_with_downstream_node(self, node_tag: str) -> List[Dict]:
        return self.user.get_chains_with_downstream_node(node_tag)

    # Chain Routing 管理（多跳链路架构 v2）
    def get_chain_routing_list(self, mark_type: Optional[str] = None) -> List[Dict]:
        return self.user.get_chain_routing_list(mark_type)

    def get_chain_routing(self, chain_tag: str, mark_value: int, mark_type: str = "dscp") -> Optional[Dict]:
        return self.user.get_chain_routing(chain_tag, mark_value, mark_type)

    def get_chain_routing_by_mark(self, mark_value: int, mark_type: str = "dscp") -> Optional[Dict]:
        return self.user.get_chain_routing_by_mark(mark_value, mark_type)

    def add_chain_routing(
        self,
        chain_tag: str,
        mark_value: int,
        egress_tag: str,
        mark_type: str = "dscp",
        source_node: Optional[str] = None
    ) -> int:
        return self.user.add_chain_routing(chain_tag, mark_value, egress_tag, mark_type, source_node)

    def add_or_update_chain_routing(
        self,
        chain_tag: str,
        mark_value: int,
        egress_tag: str,
        mark_type: str = "dscp",
        source_node: Optional[str] = None
    ) -> int:
        return self.user.add_or_update_chain_routing(chain_tag, mark_value, egress_tag, mark_type, source_node)

    def update_chain_routing(
        self,
        chain_tag: str,
        mark_value: int,
        mark_type: str = "dscp",
        **kwargs
    ) -> bool:
        return self.user.update_chain_routing(chain_tag, mark_value, mark_type, **kwargs)

    def delete_chain_routing(self, chain_tag: str, mark_value: int, mark_type: str = "dscp") -> bool:
        return self.user.delete_chain_routing(chain_tag, mark_value, mark_type)

    def delete_chain_routing_by_chain(self, chain_tag: str) -> int:
        return self.user.delete_chain_routing_by_chain(chain_tag)

    def delete_chain_routing_by_source(self, source_node: str) -> int:
        return self.user.delete_chain_routing_by_source(source_node)

    def get_next_available_dscp_value(self) -> Optional[int]:
        return self.user.get_next_available_dscp_value()

    def update_peer_node_tunnel_api_endpoint(self, tag: str, tunnel_api_endpoint: Optional[str]) -> bool:
        return self.user.update_peer_node_tunnel_api_endpoint(tag, tunnel_api_endpoint)

    # 终端出口缓存 (Phase 11.1)
    def get_terminal_egress_cache(self, chain_tag: str) -> Optional[Dict]:
        return self.user.get_terminal_egress_cache(chain_tag)

    def update_terminal_egress_cache(
        self,
        chain_tag: str,
        terminal_node: str,
        egress_list: List[Dict],
        ttl_seconds: int = 300
    ) -> bool:
        return self.user.update_terminal_egress_cache(chain_tag, terminal_node, egress_list, ttl_seconds)

    def delete_terminal_egress_cache(self, chain_tag: str) -> bool:
        return self.user.delete_terminal_egress_cache(chain_tag)

    def cleanup_expired_terminal_egress_cache(self) -> int:
        return self.user.cleanup_expired_terminal_egress_cache()

    def get_all_terminal_egress_cache(self) -> List[Dict]:
        return self.user.get_all_terminal_egress_cache()


# 全局缓存
_db_manager: Optional[DatabaseManager] = None


def get_db(geodata_path: str = "/etc/sing-box/geoip-geodata.db",
           user_path: str = "/etc/sing-box/user-config.db",
           encryption_key: Optional[str] = None) -> DatabaseManager:
    """获取数据库管理器（单例模式）

    Args:
        geodata_path: GeoIP 数据目录路径
        user_path: 用户数据库文件路径
        encryption_key: SQLCipher 加密密钥（用于 user 数据库）
                       如果未提供，会尝试从 SQLCIPHER_KEY 环境变量获取

    注意: 首次调用的参数会被缓存，后续调用如果使用不同参数会打印警告。
    """
    global _db_manager
    if _db_manager is None:
        # 如果未提供加密密钥，尝试从环境变量获取
        if encryption_key is None:
            encryption_key = os.environ.get("SQLCIPHER_KEY")
        _db_manager = DatabaseManager(geodata_path, user_path, encryption_key)
    else:
        # 检查路径是否与缓存的一致
        if _db_manager.geodata_path != geodata_path or _db_manager.user_path != user_path:
            print(f"[db] Warning: get_db called with different paths, using cached manager. "
                  f"Requested: geodata={geodata_path}, user={user_path}. "
                  f"Cached: geodata={_db_manager.geodata_path}, user={_db_manager.user_path}")
    return _db_manager


# 测试代码
if __name__ == "__main__":
    import sys

    geodata_path = sys.argv[1] if len(sys.argv) > 1 else "/etc/sing-box/geoip-geodata.db"
    user_path = sys.argv[2] if len(sys.argv) > 2 else "/etc/sing-box/user-config.db"

    print("=== 测试分离数据库功能 ===\n")

    db = get_db(geodata_path, user_path)

    # 测试统计
    print("1. 完整统计:")
    stats = db.get_statistics()
    for key, value in stats.items():
        print(f"   {key}: {value:,}")

    # 测试国家查询
    print("\n2. 搜索国家 'china':")
    results = db.search_countries("china", limit=3)
    for country in results:
        print(f"   {country['code']}: {country['display_name']}")

    # 测试路由规则
    print("\n3. 添加测试规则:")
    rule_id = db.add_routing_rule("domain", "example.com", "direct", priority=10)
    print(f"   规则 ID: {rule_id}")

    print("\n4. 获取所有规则:")
    rules = db.get_routing_rules()
    for rule in rules:
        print(f"   [{rule['id']}] {rule['rule_type']}: {rule['target']} -> {rule['outbound']}")

    print("\n✅ 所有测试通过！")

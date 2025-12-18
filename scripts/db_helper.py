#!/usr/bin/env python3
"""
数据库访问辅助模块 - 分离版本

将系统数据和用户数据分离到两个数据库：
- geoip-geodata.db: 只读的地理位置和域名数据（系统数据）
- user-config.db: 用户的路由规则和出口配置（用户数据）
"""
import json
import sqlite3
from pathlib import Path
from typing import List, Dict, Optional, Any
from contextlib import contextmanager


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
    """用户配置数据库（读写）"""

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
        """批量添加路由规则

        Args:
            rules: [(rule_type, target, outbound, tag, priority), ...]

        Returns:
            成功插入的数量
        """
        if not rules:
            return 0
        with self._get_conn() as conn:
            cursor = conn.cursor()
            cursor.executemany("""
                INSERT OR IGNORE INTO routing_rules (rule_type, target, outbound, tag, priority)
                VALUES (?, ?, ?, ?, ?)
            """, rules)
            conn.commit()
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
                SELECT id, interface_name, address, listen_port, mtu, private_key, created_at, updated_at
                FROM wireguard_server
                WHERE id = 1
            """).fetchone()
            return dict(row) if row else None

    def set_wireguard_server(self, interface_name: str, address: str, listen_port: int,
                            mtu: int, private_key: str) -> bool:
        """设置 WireGuard 服务器配置（插入或更新）"""
        with self._get_conn() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT OR REPLACE INTO wireguard_server
                (id, interface_name, address, listen_port, mtu, private_key, updated_at)
                VALUES (1, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
            """, (interface_name, address, listen_port, mtu, private_key))
            conn.commit()
            return True

    # ============ WireGuard 对等点（客户端）管理 ============

    def get_wireguard_peers(self, enabled_only: bool = True) -> List[Dict]:
        """获取 WireGuard 对等点列表"""
        with self._get_conn() as conn:
            cursor = conn.cursor()
            if enabled_only:
                rows = cursor.execute("""
                    SELECT id, name, public_key, allowed_ips, preshared_key, allow_lan, lan_subnet, enabled, created_at, updated_at
                    FROM wireguard_peers
                    WHERE enabled = 1
                    ORDER BY name
                """).fetchall()
            else:
                rows = cursor.execute("""
                    SELECT id, name, public_key, allowed_ips, preshared_key, allow_lan, lan_subnet, enabled, created_at, updated_at
                    FROM wireguard_peers
                    ORDER BY name
                """).fetchall()
            return [dict(row) for row in rows]

    def get_wireguard_peer(self, peer_id: int) -> Optional[Dict]:
        """获取单个 WireGuard 对等点"""
        with self._get_conn() as conn:
            cursor = conn.cursor()
            row = cursor.execute("""
                SELECT id, name, public_key, allowed_ips, preshared_key, allow_lan, lan_subnet, enabled, created_at, updated_at
                FROM wireguard_peers
                WHERE id = ?
            """, (peer_id,)).fetchone()
            return dict(row) if row else None

    def get_wireguard_peer_by_name(self, name: str) -> Optional[Dict]:
        """根据名称获取单个 WireGuard 对等点"""
        with self._get_conn() as conn:
            cursor = conn.cursor()
            row = cursor.execute("""
                SELECT id, name, public_key, allowed_ips, preshared_key, allow_lan, lan_subnet, enabled, created_at, updated_at
                FROM wireguard_peers
                WHERE name = ?
            """, (name,)).fetchone()
            return dict(row) if row else None

    def add_wireguard_peer(self, name: str, public_key: str, allowed_ips: str,
                          preshared_key: Optional[str] = None,
                          allow_lan: bool = False,
                          lan_subnet: Optional[str] = None) -> int:
        """添加 WireGuard 对等点"""
        with self._get_conn() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO wireguard_peers (name, public_key, allowed_ips, preshared_key, allow_lan, lan_subnet)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (name, public_key, allowed_ips, preshared_key, 1 if allow_lan else 0, lan_subnet))
            conn.commit()
            return cursor.lastrowid

    def update_wireguard_peer(self, peer_id: int, name: Optional[str] = None,
                             allowed_ips: Optional[str] = None, enabled: Optional[bool] = None,
                             allow_lan: Optional[bool] = None,
                             lan_subnet: Optional[str] = None) -> bool:
        """更新 WireGuard 对等点"""
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
                SELECT id, name, description, region_id, dns_strategy, enabled, created_at, updated_at
                FROM pia_profiles
                WHERE id = ?
            """, (profile_id,)).fetchone()
            return dict(row) if row else None

    def get_pia_profile_by_name(self, name: str) -> Optional[Dict]:
        """根据名称获取 PIA profile"""
        with self._get_conn() as conn:
            cursor = conn.cursor()
            row = cursor.execute("""
                SELECT id, name, description, region_id, dns_strategy, enabled, created_at, updated_at
                FROM pia_profiles
                WHERE name = ?
            """, (name,)).fetchone()
            return dict(row) if row else None

    def add_pia_profile(self, name: str, region_id: str, description: str = "",
                       dns_strategy: str = "direct-dns") -> int:
        """添加 PIA profile"""
        with self._get_conn() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO pia_profiles (name, description, region_id, dns_strategy)
                VALUES (?, ?, ?, ?)
            """, (name, description, region_id, dns_strategy))
            conn.commit()
            return cursor.lastrowid

    def update_pia_profile(self, profile_id: int, description: Optional[str] = None,
                          region_id: Optional[str] = None, dns_strategy: Optional[str] = None,
                          enabled: Optional[bool] = None) -> bool:
        """更新 PIA profile"""
        updates = []
        params = []

        if description is not None:
            updates.append("description = ?")
            params.append(description)
        if region_id is not None:
            updates.append("region_id = ?")
            params.append(region_id)
        if dns_strategy is not None:
            updates.append("dns_strategy = ?")
            params.append(dns_strategy)
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
                # 解析 JSON 域名列表
                row_dict['domains'] = json.loads(row_dict['domains'])
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
                row_dict['domains'] = json.loads(row_dict['domains'])
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
            cursor.execute("""
                INSERT INTO settings (key, value, updated_at)
                VALUES (?, ?, CURRENT_TIMESTAMP)
                ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = CURRENT_TIMESTAMP
            """, (key, value))
            conn.commit()
            return True

    def get_all_settings(self) -> Dict[str, str]:
        """获取所有设置"""
        with self._get_conn() as conn:
            cursor = conn.cursor()
            rows = cursor.execute("SELECT key, value FROM settings").fetchall()
            return {row[0]: row[1] for row in rows}

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
                # 解析 reserved JSON
                if item.get("reserved"):
                    try:
                        item["reserved"] = json.loads(item["reserved"])
                    except:
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
            if item.get("reserved"):
                try:
                    item["reserved"] = json.loads(item["reserved"])
                except:
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

    # ============ OpenVPN Egress 管理（通过 SOCKS5 桥接）============

    OPENVPN_SOCKS_PORT_START = 37001  # SOCKS 端口起始值

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
                # 解析 extra_options JSON
                if item.get("extra_options"):
                    try:
                        item["extra_options"] = json.loads(item["extra_options"])
                    except:
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
            if item.get("extra_options"):
                try:
                    item["extra_options"] = json.loads(item["extra_options"])
                except:
                    item["extra_options"] = None
            return item

    def get_next_openvpn_socks_port(self) -> int:
        """获取下一个可用的 SOCKS 端口（从 37001 开始）"""
        with self._get_conn() as conn:
            cursor = conn.cursor()
            row = cursor.execute(
                "SELECT MAX(socks_port) FROM openvpn_egress"
            ).fetchone()
            max_port = row[0] if row and row[0] else None
            if max_port is None:
                return self.OPENVPN_SOCKS_PORT_START
            return max_port + 1

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
        socks_port = self.get_next_openvpn_socks_port()
        extra_options_json = json.dumps(extra_options) if extra_options else None

        with self._get_conn() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO openvpn_egress
                (tag, description, protocol, remote_host, remote_port,
                 ca_cert, client_cert, client_key, tls_auth, tls_crypt, crl_verify,
                 auth_user, auth_pass, cipher, auth, compress, extra_options, socks_port)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (tag, description, protocol, remote_host, remote_port,
                  ca_cert, client_cert, client_key, tls_auth, tls_crypt, crl_verify,
                  auth_user, auth_pass, cipher, auth, compress, extra_options_json, socks_port))
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


class DatabaseManager:
    """统一的数据库管理器，协调系统数据和用户数据"""

    def __init__(self, geodata_path: str, user_path: str):
        self.geodata = GeodataDatabase(geodata_path)
        self.user = UserDatabase(user_path)

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
                            mtu: int, private_key: str) -> bool:
        return self.user.set_wireguard_server(interface_name, address, listen_port, mtu, private_key)

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
                          lan_subnet: Optional[str] = None) -> int:
        return self.user.add_wireguard_peer(name, public_key, allowed_ips, preshared_key, allow_lan, lan_subnet)

    def update_wireguard_peer(self, peer_id: int, name: Optional[str] = None,
                             allowed_ips: Optional[str] = None, enabled: Optional[bool] = None,
                             allow_lan: Optional[bool] = None,
                             lan_subnet: Optional[str] = None) -> bool:
        return self.user.update_wireguard_peer(peer_id, name, allowed_ips, enabled, allow_lan, lan_subnet)

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
                       dns_strategy: str = "direct-dns") -> int:
        return self.user.add_pia_profile(name, region_id, description, dns_strategy)

    def update_pia_profile(self, profile_id: int, description: Optional[str] = None,
                          region_id: Optional[str] = None, dns_strategy: Optional[str] = None,
                          enabled: Optional[bool] = None) -> bool:
        return self.user.update_pia_profile(profile_id, description, region_id, dns_strategy, enabled)

    def delete_pia_profile(self, profile_id: int) -> bool:
        return self.user.delete_pia_profile(profile_id)

    def update_pia_credentials(self, name: str, credentials: Dict[str, Any]) -> bool:
        return self.user.update_pia_credentials(name, credentials)

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

    def get_next_openvpn_socks_port(self) -> int:
        return self.user.get_next_openvpn_socks_port()

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


# 全局缓存
_db_manager: Optional[DatabaseManager] = None


def get_db(geodata_path: str = "/etc/sing-box/geoip-geodata.db",
           user_path: str = "/etc/sing-box/user-config.db") -> DatabaseManager:
    """获取数据库管理器（单例模式）"""
    global _db_manager
    if _db_manager is None:
        _db_manager = DatabaseManager(geodata_path, user_path)
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

#!/usr/bin/env python3
"""链路路由管理器

在终端节点管理 DSCP/email 到本地出口的路由映射。

当远程入口节点激活链路时，通过隧道 API 注册路由映射到本终端节点。
此模块读取 chain_routing 表，应用 iptables 和策略路由规则。

使用示例：
    manager = ChainRouteManager(db)

    # 从数据库同步所有路由规则
    manager.sync_routes()

    # 添加单条路由
    manager.add_route("us-stream", dscp_value=3, egress_tag="pia-us")

    # 删除路由
    manager.remove_route("us-stream", dscp_value=3)
"""

import logging
import threading
from dataclasses import dataclass
from typing import Dict, List, Optional, Set

from dscp_manager import DSCPManager, get_dscp_manager, TERMINAL_FWMARK_BASE, TERMINAL_TABLE_BASE


@dataclass
class ChainRoute:
    """链路路由信息"""
    chain_tag: str
    mark_value: int
    mark_type: str  # "dscp" 或 "xray_email"
    egress_tag: str
    egress_interface: Optional[str] = None
    source_node: Optional[str] = None


class ChainRouteManager:
    """链路路由管理器

    管理终端节点的链路路由规则，将 DSCP/email 标记映射到本地出口。
    """

    def __init__(self, db):
        """初始化管理器

        Args:
            db: DatabaseManager 实例
        """
        self.db = db
        self.dscp_manager = get_dscp_manager()
        self._active_routes: Dict[str, ChainRoute] = {}  # key: f"{chain_tag}:{mark_value}:{mark_type}"
        self._lock = threading.Lock()  # 线程安全锁，保护 _active_routes 的并发访问
        self._logger = logging.getLogger("chain-route-mgr")

    def _get_route_key(self, chain_tag: str, mark_value: int, mark_type: str) -> str:
        """生成路由键"""
        return f"{chain_tag}:{mark_value}:{mark_type}"

    def _get_egress_interface(self, egress_tag: str) -> Optional[str]:
        """获取出口对应的网络接口

        不同类型的出口对应不同的接口命名规则：
        - PIA profiles: wg-pia-{tag}
        - Custom WireGuard: wg-eg-{tag}
        - WARP WireGuard: wg-warp-{tag}
        - OpenVPN: tun10, tun11, etc. (从数据库获取)
        - Direct: bind_interface 或无接口（使用 IP 绑定）
        - V2Ray/WARP MASQUE: 无接口（SOCKS 代理）

        Args:
            egress_tag: 出口标识

        Returns:
            网络接口名，或 None（不适用于 DSCP 路由）
        """
        # 特殊情况：direct 出口不需要接口
        if egress_tag == "direct":
            return None

        # 检查 PIA profiles
        profiles = self.db.get_pia_profiles(enabled_only=True)
        for p in profiles:
            if p["name"] == egress_tag:
                # 使用与 setup_kernel_wg_egress.py 相同的命名逻辑
                from db_helper import get_egress_interface_name
                return get_egress_interface_name(egress_tag, is_pia=True)

        # 检查 Custom WireGuard
        custom_list = self.db.get_custom_egress_list(enabled_only=True)
        for e in custom_list:
            if e["tag"] == egress_tag:
                from db_helper import get_egress_interface_name
                return get_egress_interface_name(egress_tag, is_pia=False)

        # 检查 WARP WireGuard
        warp_list = self.db.get_warp_egress_list(enabled_only=True)
        for e in warp_list:
            if e["tag"] == egress_tag and e.get("protocol") == "wireguard":
                # Phase 11-Fix.I: 使用统一的接口命名函数，确保与 setup_kernel_wg_egress.py 一致
                from setup_kernel_wg_egress import get_egress_interface_name as get_wg_egress_iface
                return get_wg_egress_iface(egress_tag, egress_type="warp")

        # 检查 OpenVPN（有 tun 设备）
        openvpn_list = self.db.get_openvpn_egress_list(enabled_only=True)
        for e in openvpn_list:
            if e["tag"] == egress_tag:
                return e.get("tun_device")  # 如 tun10

        # 检查 Direct egress（有 bind_interface）
        direct_list = self.db.get_direct_egress_list(enabled_only=True)
        for e in direct_list:
            if e["tag"] == egress_tag:
                return e.get("bind_interface")

        # V2Ray 和 WARP MASQUE 使用 SOCKS，不适用于 DSCP 路由
        self._logger.warning(f"Cannot determine interface for egress: {egress_tag}")
        return None

    def add_route(
        self,
        chain_tag: str,
        mark_value: int,
        egress_tag: str,
        mark_type: str = "dscp",
        source_node: Optional[str] = None,
    ) -> bool:
        """添加链路路由

        Args:
            chain_tag: 链路标识
            mark_value: 标记值（DSCP 1-63 或其他标记）
            egress_tag: 本地出口标识
            mark_type: 标记类型
            source_node: 来源节点

        Returns:
            是否成功
        """
        route_key = self._get_route_key(chain_tag, mark_value, mark_type)

        self._logger.info(
            f"Adding route: chain={chain_tag}, mark={mark_value}, "
            f"type={mark_type}, egress={egress_tag}"
        )

        if mark_type == "dscp":
            # DSCP 路由需要网络接口
            interface = self._get_egress_interface(egress_tag)
            if not interface:
                self._logger.error(f"Cannot find interface for egress: {egress_tag}")
                return False

            # 设置 DSCP 路由规则
            if not self.dscp_manager.setup_terminal_rules(mark_value, interface):
                return False

            # 记录活动路由（线程安全）
            with self._lock:
                self._active_routes[route_key] = ChainRoute(
                    chain_tag=chain_tag,
                    mark_value=mark_value,
                    mark_type=mark_type,
                    egress_tag=egress_tag,
                    egress_interface=interface,
                    source_node=source_node,
                )

            self._logger.info(f"Route added: {route_key} -> {interface}")
            return True

        elif mark_type == "xray_email":
            # Xray email 标记不需要 iptables 规则，由 Xray routing 处理
            # 但仍然记录以便跟踪（线程安全）
            with self._lock:
                self._active_routes[route_key] = ChainRoute(
                    chain_tag=chain_tag,
                    mark_value=mark_value,
                    mark_type=mark_type,
                    egress_tag=egress_tag,
                    source_node=source_node,
                )
            self._logger.info(f"Xray email route recorded: {route_key} -> {egress_tag}")
            return True

        else:
            self._logger.error(f"Unknown mark type: {mark_type}")
            return False

    def remove_route(
        self,
        chain_tag: str,
        mark_value: int,
        mark_type: str = "dscp",
    ) -> bool:
        """删除链路路由

        Args:
            chain_tag: 链路标识
            mark_value: 标记值
            mark_type: 标记类型

        Returns:
            是否成功
        """
        route_key = self._get_route_key(chain_tag, mark_value, mark_type)

        self._logger.info(f"Removing route: {route_key}")

        # 线程安全地检查和获取路由
        with self._lock:
            if route_key not in self._active_routes:
                self._logger.warning(f"Route not found: {route_key}")
                return False
            route = self._active_routes[route_key]

        if mark_type == "dscp":
            # 清理 DSCP 路由规则（在锁外执行，避免阻塞）
            self.dscp_manager.cleanup_terminal_rules(mark_value)

        # 移除记录（线程安全）
        with self._lock:
            if route_key in self._active_routes:
                del self._active_routes[route_key]

        self._logger.info(f"Route removed: {route_key}")
        return True

    def sync_routes(self) -> int:
        """从数据库同步所有链路路由

        读取 chain_routing 表，应用/更新路由规则。

        Returns:
            成功应用的路由数量
        """
        self._logger.info("Syncing routes from database")

        # 获取数据库中的路由
        db_routes = self.db.get_chain_routing_list()
        db_route_keys: Set[str] = set()

        success_count = 0

        # 添加/更新路由
        for r in db_routes:
            chain_tag = r["chain_tag"]
            mark_value = r["mark_value"]
            mark_type = r.get("mark_type", "dscp")
            egress_tag = r["egress_tag"]
            source_node = r.get("source_node")

            route_key = self._get_route_key(chain_tag, mark_value, mark_type)
            db_route_keys.add(route_key)

            # 检查是否需要更新（线程安全读取）
            with self._lock:
                existing = self._active_routes.get(route_key)
            if existing and existing.egress_tag == egress_tag:
                # 路由未变，跳过
                continue

            # 如果存在旧路由，先删除
            if existing:
                self.remove_route(chain_tag, mark_value, mark_type)

            # 添加新路由
            if self.add_route(chain_tag, mark_value, egress_tag, mark_type, source_node):
                success_count += 1

        # 删除数据库中不存在的路由（线程安全读取）
        with self._lock:
            stale_keys = set(self._active_routes.keys()) - db_route_keys
            stale_routes = [(self._active_routes[key].chain_tag,
                            self._active_routes[key].mark_value,
                            self._active_routes[key].mark_type) for key in stale_keys]
        for chain_tag, mark_value, mark_type in stale_routes:
            self.remove_route(chain_tag, mark_value, mark_type)

        self._logger.info(f"Sync complete: {success_count} routes applied, {len(stale_keys)} removed")
        return success_count

    def cleanup_all(self) -> bool:
        """清理所有链路路由

        Returns:
            是否成功
        """
        self._logger.info("Cleaning up all chain routes")

        # 清理 DSCP 规则
        self.dscp_manager.cleanup_all_rules()

        # 清空记录（线程安全）
        with self._lock:
            self._active_routes.clear()

        self._logger.info("All chain routes cleaned up")
        return True

    def get_active_routes(self) -> List[ChainRoute]:
        """获取所有活动路由（线程安全）"""
        with self._lock:
            return list(self._active_routes.values())

    def get_route(self, chain_tag: str, mark_value: int, mark_type: str = "dscp") -> Optional[ChainRoute]:
        """获取指定路由（线程安全）"""
        route_key = self._get_route_key(chain_tag, mark_value, mark_type)
        with self._lock:
            return self._active_routes.get(route_key)


# 全局实例和线程安全锁
_chain_route_manager: Optional[ChainRouteManager] = None
_chain_route_manager_lock = threading.Lock()


def get_chain_route_manager(db) -> ChainRouteManager:
    """获取全局链路路由管理器实例（线程安全）

    使用双重检查锁定模式确保线程安全的单例创建。

    Args:
        db: DatabaseManager 实例

    Returns:
        ChainRouteManager 实例
    """
    global _chain_route_manager
    if _chain_route_manager is None:
        with _chain_route_manager_lock:
            if _chain_route_manager is None:
                _chain_route_manager = ChainRouteManager(db)
    return _chain_route_manager


if __name__ == "__main__":
    import sys
    import os

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    )

    # 简单的命令行测试
    if len(sys.argv) < 2:
        print("Usage: chain_route_manager.py <command> [args]")
        print("Commands:")
        print("  sync     - Sync routes from database")
        print("  cleanup  - Clean up all routes")
        print("  list     - List active routes")
        sys.exit(1)

    command = sys.argv[1]

    if command in ["sync", "cleanup", "list"]:
        # 需要数据库连接
        sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
        from db_helper import get_db

        geodata_path = os.environ.get("GEODATA_PATH", "/etc/sing-box/geoip-catalog.json")
        user_db_path = os.environ.get("USER_DB_PATH", "/etc/sing-box/user-config.db")

        db = get_db(geodata_path, user_db_path)
        manager = get_chain_route_manager(db)

        if command == "sync":
            count = manager.sync_routes()
            print(f"Synced {count} routes")

        elif command == "cleanup":
            manager.cleanup_all()
            print("All routes cleaned up")

        elif command == "list":
            routes = manager.get_active_routes()
            if routes:
                for r in routes:
                    print(
                        f"Chain: {r.chain_tag}, Mark: {r.mark_value}, "
                        f"Type: {r.mark_type}, Egress: {r.egress_tag}, "
                        f"Interface: {r.egress_interface}"
                    )
            else:
                print("No active routes")

    else:
        print(f"Unknown command: {command}")
        sys.exit(1)

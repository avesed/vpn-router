#!/usr/bin/env python3
"""中继节点配置管理器

Phase 11.4: 对于 WireGuard 多跳链路，中间节点需要 iptables 规则来转发流量。

架构：
    入口(A) -> wg-peer-B [DSCP 标记] -> 中继(B) -> wg-peer-C -> 终端(C)

中继规则（在节点 B 上）：
    iptables -t mangle -A PREROUTING -i wg-peer-A -m dscp --dscp X -j MARK --set-mark Y
    ip rule add fwmark Y table 400
    ip route add default dev wg-peer-C table 400

设计决策：
    - 中继节点仅透传流量到下一跳，不在本地出口（简化实现）
    - 使用独立的 fwmark 范围 (400-463) 避免与终端 (300) 和 ECMP (200) 冲突
    - 仅支持 WireGuard 隧道（Xray 使用 SOCKS5，无法保留 DSCP 标记）
"""

import logging
import subprocess
import threading
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)

# 中继路由使用的 fwmark 和路由表范围
RELAY_FWMARK_BASE = 400
RELAY_TABLE_BASE = 400
MAX_RELAY_RULES = 64  # 支持最多 64 条中继规则 (400-463)


@dataclass
class RelayRule:
    """中继规则配置"""
    chain_tag: str              # 所属链路标识
    source_interface: str       # 流量来源接口 (如 wg-peer-node-a)
    target_interface: str       # 流量目标接口 (如 wg-peer-node-c)
    dscp_value: int             # DSCP 标记值
    mark_type: str = "dscp"     # 标记类型（仅支持 'dscp'，Xray 隧道不支持中继）
    fwmark: int = 0             # 分配的 fwmark 值
    table_id: int = 0           # 分配的路由表 ID
    active: bool = False        # 是否已激活


class RelayConfigManager:
    """中继节点配置管理器

    管理多跳链路中间节点的转发规则，包括：
    - iptables DSCP 匹配和标记
    - 策略路由（ip rule + ip route）

    注意：仅支持 WireGuard 隧道，Xray 隧道使用 SOCKS5 代理，无法保留 DSCP 标记。
    """

    def __init__(self, db=None):
        """初始化中继配置管理器

        Args:
            db: 数据库实例（可选，用于持久化规则状态）
        """
        self.db = db
        self._rules: Dict[str, RelayRule] = {}
        self._lock = threading.Lock()
        self._next_fwmark = RELAY_FWMARK_BASE

    def setup_relay_route(
        self,
        chain_tag: str,
        source_interface: str,
        target_interface: str,
        dscp_value: int,
        mark_type: str = "dscp"
    ) -> bool:
        """配置链路跳的中继转发

        对于 WireGuard：设置 iptables DSCP 匹配 + 策略路由
        对于 Xray：通过 xray_manager 添加 email 路由规则

        Args:
            chain_tag: 链路标识
            source_interface: 流量来源接口
            target_interface: 流量目标接口
            dscp_value: DSCP 标记值
            mark_type: 标记类型（仅支持 'dscp'，Xray 隧道不支持中继）

        Returns:
            是否成功配置
        """
        with self._lock:
            # 检查是否已存在相同链路的规则
            if chain_tag in self._rules:
                logger.warning(f"[relay] 链路 '{chain_tag}' 的中继规则已存在")
                return True

            if any(
                rule.dscp_value == dscp_value and rule.mark_type == mark_type
                for rule in self._rules.values()
            ):
                conflict = next(
                    rule
                    for rule in self._rules.values()
                    if rule.dscp_value == dscp_value and rule.mark_type == mark_type
                )
                logger.error(
                    f"[relay] DSCP={dscp_value} 已被链路 '{conflict.chain_tag}' 使用，拒绝重复注册"
                )
                return False

            # 分配 fwmark 和路由表
            fwmark = self._allocate_fwmark()
            if fwmark < 0:
                logger.error(f"[relay] 无法分配 fwmark，已达到最大规则数 {MAX_RELAY_RULES}")
                return False

            table_id = fwmark  # 使用相同的值作为路由表 ID

            rule = RelayRule(
                chain_tag=chain_tag,
                source_interface=source_interface,
                target_interface=target_interface,
                dscp_value=dscp_value,
                mark_type=mark_type,
                fwmark=fwmark,
                table_id=table_id,
            )

            # 根据类型配置规则
            if mark_type == "dscp":
                success = self._setup_dscp_relay(rule)
            else:
                success = self._setup_xray_relay(rule)

            if success:
                rule.active = True
                self._rules[chain_tag] = rule
                logger.info(f"[relay] 链路 '{chain_tag}' 中继规则已配置: "
                           f"{source_interface} -> {target_interface} (DSCP={dscp_value}, fwmark={fwmark})")

                # 持久化到数据库（如果可用）
                if self.db:
                    self._save_rule_to_db(rule)
            else:
                # 释放 fwmark
                self._release_fwmark(fwmark)

            return success

    def cleanup_relay_route(self, chain_tag: str) -> bool:
        """移除链路的中继配置

        Args:
            chain_tag: 链路标识

        Returns:
            是否成功清理
        """
        with self._lock:
            rule = self._rules.get(chain_tag)
            if not rule:
                logger.warning(f"[relay] 链路 '{chain_tag}' 的中继规则不存在")
                return True  # 不存在也算成功

            if rule.mark_type == "dscp":
                success = self._cleanup_dscp_relay(rule)
            else:
                success = self._cleanup_xray_relay(rule)

            if success:
                self._release_fwmark(rule.fwmark)
                del self._rules[chain_tag]
                logger.info(f"[relay] 链路 '{chain_tag}' 中继规则已清理")

                # 从数据库删除（如果可用）
                if self.db:
                    self._delete_rule_from_db(chain_tag)

            return success

    def sync_relay_routes(self) -> int:
        """从数据库同步所有中继路由

        Returns:
            同步的规则数量
        """
        if not self.db:
            logger.warning("[relay] 数据库不可用，无法同步规则")
            return 0

        try:
            routes = self.db.get_relay_routes(enabled_only=True)
            synced = 0

            for route in routes:
                chain_tag = route.get("chain_tag")
                source_peer = route.get("source_peer_tag")
                target_peer = route.get("target_peer_tag")

                if not all([chain_tag, source_peer, target_peer]):
                    continue

                # 从节点获取接口名
                source_node = self.db.get_peer_node(source_peer)
                target_node = self.db.get_peer_node(target_peer)

                if not source_node or not target_node:
                    logger.warning(f"[relay] 链路 '{chain_tag}' 的节点不存在")
                    continue

                # Phase 11-Fix.P: 验证节点使用 WireGuard 隧道（非 Xray）
                source_tunnel_type = source_node.get("tunnel_type", "wireguard")
                target_tunnel_type = target_node.get("tunnel_type", "wireguard")
                if source_tunnel_type == "xray" or target_tunnel_type == "xray":
                    logger.warning(
                        f"[relay] 链路 '{chain_tag}' 包含 Xray 节点，跳过中继路由同步 "
                        f"(source={source_peer}:{source_tunnel_type}, target={target_peer}:{target_tunnel_type})"
                    )
                    continue

                source_interface = source_node.get("tunnel_interface", f"wg-peer-{source_peer}")
                target_interface = target_node.get("tunnel_interface", f"wg-peer-{target_peer}")

                # 从链路配置获取 DSCP 值
                chain = self.db.get_node_chain(chain_tag)
                if chain and chain.get("dscp_value"):
                    dscp_value = chain["dscp_value"]
                else:
                    logger.warning(f"[relay] 链路 '{chain_tag}' 没有配置 DSCP 值，跳过")
                    continue

                if self.setup_relay_route(chain_tag, source_interface, target_interface, dscp_value):
                    synced += 1

            logger.info(f"[relay] 已同步 {synced} 条中继路由")
            return synced

        except Exception as e:
            logger.error(f"[relay] 同步中继路由失败: {e}")
            return 0

    def get_active_rules(self) -> List[Dict]:
        """获取当前活跃的中继规则列表"""
        with self._lock:
            return [
                {
                    "chain_tag": rule.chain_tag,
                    "source_interface": rule.source_interface,
                    "target_interface": rule.target_interface,
                    "dscp_value": rule.dscp_value,
                    "mark_type": rule.mark_type,
                    "fwmark": rule.fwmark,
                    "table_id": rule.table_id,
                    "active": rule.active,
                }
                for rule in self._rules.values()
            ]

    def cleanup_all(self) -> int:
        """清理所有中继规则

        Returns:
            清理的规则数量
        """
        with self._lock:
            count = 0
            for chain_tag in list(self._rules.keys()):
                if self.cleanup_relay_route(chain_tag):
                    count += 1
            return count

    # ========================================
    # 私有方法
    # ========================================

    def _allocate_fwmark(self) -> int:
        """分配下一个可用的 fwmark 值"""
        # 查找第一个未使用的 fwmark
        used_marks = {rule.fwmark for rule in self._rules.values()}
        for mark in range(RELAY_FWMARK_BASE, RELAY_FWMARK_BASE + MAX_RELAY_RULES):
            if mark not in used_marks:
                return mark
        return -1  # 没有可用的 fwmark

    def _release_fwmark(self, fwmark: int):
        """释放 fwmark（当前实现中不需要特别处理，只是记录日志）"""
        logger.debug(f"[relay] 释放 fwmark={fwmark}")

    def _setup_dscp_relay(self, rule: RelayRule) -> bool:
        """设置 DSCP 匹配的中继转发

        1. iptables -t mangle -A PREROUTING -i {source} -m dscp --dscp {value} -j MARK --set-mark {fwmark}
        2. ip rule add fwmark {fwmark} table {table}
        3. ip route add default dev {target} table {table}
        """
        try:
            # 1. 添加 iptables 规则 - DSCP 匹配并设置 fwmark
            iptables_cmd = [
                "iptables", "-t", "mangle", "-A", "PREROUTING",
                "-i", rule.source_interface,
                "-m", "dscp", "--dscp", str(rule.dscp_value),
                "-j", "MARK", "--set-mark", str(rule.fwmark)
            ]
            subprocess.run(iptables_cmd, check=True, capture_output=True, timeout=10)
            logger.debug(f"[relay] 添加 iptables 规则: {' '.join(iptables_cmd)}")

            # 2. 添加策略路由规则
            rule_cmd = ["ip", "rule", "add", "fwmark", str(rule.fwmark), "table", str(rule.table_id)]
            subprocess.run(rule_cmd, check=True, capture_output=True, timeout=10)
            logger.debug(f"[relay] 添加 ip rule: {' '.join(rule_cmd)}")

            # 3. 添加默认路由到目标接口
            route_cmd = ["ip", "route", "add", "default", "dev", rule.target_interface, "table", str(rule.table_id)]
            result = subprocess.run(route_cmd, capture_output=True, timeout=10)
            if result.returncode != 0:
                # 如果路由已存在，尝试替换
                route_cmd = ["ip", "route", "replace", "default", "dev", rule.target_interface, "table", str(rule.table_id)]
                subprocess.run(route_cmd, check=True, capture_output=True, timeout=10)
            logger.debug(f"[relay] 添加 ip route: {' '.join(route_cmd)}")

            return True

        except subprocess.CalledProcessError as e:
            logger.error(f"[relay] 设置 DSCP 中继失败: {e.stderr.decode() if e.stderr else e}")
            # 尝试回滚已添加的规则
            self._cleanup_dscp_relay(rule)
            return False
        except subprocess.TimeoutExpired:
            logger.error("[relay] 设置 DSCP 中继超时")
            return False
        except Exception as e:
            logger.error(f"[relay] 设置 DSCP 中继异常: {e}")
            return False

    def _cleanup_dscp_relay(self, rule: RelayRule) -> bool:
        """清理 DSCP 中继规则"""
        success = True

        # 1. 删除路由
        try:
            route_cmd = ["ip", "route", "del", "default", "table", str(rule.table_id)]
            subprocess.run(route_cmd, capture_output=True, timeout=10)
        except Exception as e:
            logger.warning(f"[relay] 删除路由失败: {e}")

        # 2. 删除策略路由规则
        try:
            rule_cmd = ["ip", "rule", "del", "fwmark", str(rule.fwmark), "table", str(rule.table_id)]
            subprocess.run(rule_cmd, capture_output=True, timeout=10)
        except Exception as e:
            logger.warning(f"[relay] 删除 ip rule 失败: {e}")

        # 3. 删除 iptables 规则
        try:
            iptables_cmd = [
                "iptables", "-t", "mangle", "-D", "PREROUTING",
                "-i", rule.source_interface,
                "-m", "dscp", "--dscp", str(rule.dscp_value),
                "-j", "MARK", "--set-mark", str(rule.fwmark)
            ]
            subprocess.run(iptables_cmd, capture_output=True, timeout=10)
        except Exception as e:
            logger.warning(f"[relay] 删除 iptables 规则失败: {e}")
            success = False

        return success

    def _setup_xray_relay(self, rule: RelayRule) -> bool:
        """Xray 中继路由不支持 (Phase 11-Fix.P)

        设计决策：多跳链路应使用 WireGuard 隧道，而非 Xray。
        Xray 隧道用于入口/出口，不用于中继。

        WireGuard 中继优势：
        - 内核级转发，性能更高
        - DSCP 标记保留，路由更简单
        - 无需复杂的 email 路由规则

        Returns:
            False - Xray 中继不支持
        """
        logger.error(
            f"[relay] Xray relay not supported for multi-hop chains. "
            f"Use WireGuard tunnels instead. chain={rule.chain_tag}"
        )
        return False

    def _cleanup_xray_relay(self, rule: RelayRule) -> bool:
        """清理 Xray 中继规则 (Phase 11-Fix.P)

        由于 Xray 中继不支持，此方法仅记录日志。
        """
        logger.debug(f"[relay] Xray relay cleanup (no-op): chain={rule.chain_tag}")
        return True

    def _save_rule_to_db(self, rule: RelayRule):
        """将规则保存到数据库"""
        if not self.db:
            return
        try:
            # 使用现有的 add_relay_route 方法
            # 需要从接口名推断节点 tag
            source_tag = rule.source_interface.replace("wg-peer-", "")
            target_tag = rule.target_interface.replace("wg-peer-", "")
            self.db.add_relay_route(
                chain_tag=rule.chain_tag,
                source_peer_tag=source_tag,
                target_peer_tag=target_tag,
                enabled=True
            )
        except Exception as e:
            logger.warning(f"[relay] 保存规则到数据库失败: {e}")

    def _delete_rule_from_db(self, chain_tag: str):
        """从数据库删除规则"""
        if not self.db:
            return
        try:
            self.db.delete_relay_routes_by_chain(chain_tag)
        except Exception as e:
            logger.warning(f"[relay] 从数据库删除规则失败: {e}")


# 全局单例
_relay_manager: Optional[RelayConfigManager] = None


def get_relay_manager(db=None) -> RelayConfigManager:
    """获取中继配置管理器单例"""
    global _relay_manager
    if _relay_manager is None:
        _relay_manager = RelayConfigManager(db)
    elif db and _relay_manager.db is None:
        _relay_manager.db = db
    return _relay_manager


def cleanup_all_relay_routes() -> int:
    """清理所有中继路由（用于容器关闭时）"""
    global _relay_manager
    if _relay_manager:
        return _relay_manager.cleanup_all()
    return 0

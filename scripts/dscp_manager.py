#!/usr/bin/env python3
"""DSCP 标记管理器

管理多跳链路的 DSCP iptables 规则，用于 WireGuard 隧道的流量识别和路由。

架构：
- 入口节点：sing-box routing_mark → iptables DSCP 设置 → WireGuard
- 中继节点：透传（Linux 保留 DSCP）
- 终端节点：iptables DSCP 读取 → fwmark → 策略路由 → 本地出口

使用示例：
    manager = DSCPManager()

    # 入口节点：设置 DSCP 标记规则
    manager.setup_entry_rules("us-stream", routing_mark=101, dscp_value=1)

    # 终端节点：设置 DSCP 路由规则
    manager.setup_terminal_rules(dscp_value=1, egress_interface="wg-pia-us")

    # 清理规则
    manager.cleanup_chain_rules("us-stream")
"""

import logging
import os
import re
import subprocess
import threading
from dataclasses import dataclass
from typing import Dict, List, Optional, Set, Tuple

# DSCP 值范围和保留值
DSCP_MIN = 1
DSCP_MAX = 63

# 保留的 DSCP 值（QoS 常用）
# 注意: 必须与 db_helper.py 中的 RESERVED_DSCP_VALUES 保持一致
# 包含: 0 (BE), 10/12/14 (AF1x), 18/20/22 (AF2x), 26/28/30 (AF3x), 34/36/38 (AF4x), 46 (EF)
RESERVED_DSCP_VALUES: Set[int] = {
    0,                        # Default (BE - Best Effort)
    10, 12, 14,               # AF11, AF12, AF13 (Assured Forwarding Class 1)
    18, 20, 22,               # AF21, AF22, AF23 (Assured Forwarding Class 2)
    26, 28, 30,               # AF31, AF32, AF33 (Assured Forwarding Class 3)
    34, 36, 38,               # AF41, AF42, AF43 (Assured Forwarding Class 4)
    46,                       # EF (Expedited Forwarding)
}

# 可用的 DSCP 值（排除保留值）
AVAILABLE_DSCP_VALUES: Set[int] = set(range(DSCP_MIN, DSCP_MAX + 1)) - RESERVED_DSCP_VALUES

# 标记偏移量（可通过环境变量配置）
# 注意: ECMP 使用 200-299 的 fwmark 和 routing table，DSCP 使用 300-363
ENTRY_ROUTING_MARK_BASE = int(os.environ.get("ENTRY_ROUTING_MARK_BASE", "100"))   # sing-box routing_mark = 100 + dscp (100-163)
TERMINAL_FWMARK_BASE = int(os.environ.get("TERMINAL_FWMARK_BASE", "300"))         # 终端节点 fwmark = 300 + dscp (301-363)
TERMINAL_TABLE_BASE = int(os.environ.get("TERMINAL_TABLE_BASE", "300"))           # 策略路由表 = 300 + dscp (301-363)

# iptables 链名前缀
CHAIN_PREFIX = "CHAIN_DSCP_"

# 接口名验证正则 (Linux 接口名规则：字母数字开头，允许字母数字和连字符，最长15字符)
INTERFACE_NAME_PATTERN = re.compile(r'^[a-zA-Z0-9][a-zA-Z0-9\-]*$')
MAX_INTERFACE_NAME_LEN = 15

# chain_tag 验证正则 (小写字母开头，允许小写字母、数字、连字符)
CHAIN_TAG_PATTERN = re.compile(r'^[a-z][a-z0-9\-]*$')
MAX_CHAIN_TAG_LEN = 64


@dataclass
class DSCPRule:
    """DSCP 规则信息"""
    chain_tag: str
    dscp_value: int
    routing_mark: int  # 入口节点的 routing_mark
    fwmark: int        # 终端节点的 fwmark
    table: int         # 策略路由表
    egress_interface: Optional[str] = None


class DSCPManager:
    """DSCP 标记管理器

    管理入口节点和终端节点的 DSCP 相关 iptables 规则和策略路由。
    """

    def __init__(self):
        self._rules: Dict[str, DSCPRule] = {}  # chain_tag -> rule info
        self._logger = logging.getLogger("dscp-manager")
        self._lock = threading.Lock()  # 保护 _rules 的线程锁

    def _validate_interface_name(self, name: str) -> bool:
        """验证网络接口名称

        Args:
            name: 接口名称

        Returns:
            True 如果有效
        """
        if not name or len(name) > MAX_INTERFACE_NAME_LEN:
            return False
        # 允许 iptables 通配符 + (如 wg-peer-+)
        if name.endswith('+'):
            name = name[:-1]
        return bool(INTERFACE_NAME_PATTERN.match(name))

    def _validate_chain_tag(self, tag: str) -> bool:
        """验证链路标识

        Args:
            tag: 链路标识

        Returns:
            True 如果有效
        """
        if not tag or len(tag) > MAX_CHAIN_TAG_LEN:
            return False
        return bool(CHAIN_TAG_PATTERN.match(tag))

    def _run_command(self, cmd: List[str], check: bool = True) -> Tuple[bool, str]:
        """执行系统命令

        Args:
            cmd: 命令列表
            check: 是否检查返回码

        Returns:
            (success, output/error)
        """
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=30,
            )
            if check and result.returncode != 0:
                return False, result.stderr.strip()
            return True, result.stdout.strip()
        except subprocess.TimeoutExpired:
            return False, "Command timeout"
        except Exception as e:
            return False, str(e)

    def _iptables(self, args: List[str], check: bool = True) -> Tuple[bool, str]:
        """执行 iptables 命令"""
        return self._run_command(["iptables"] + args, check)

    def _ip(self, args: List[str], check: bool = True) -> Tuple[bool, str]:
        """执行 ip 命令"""
        return self._run_command(["ip"] + args, check)

    def _rule_exists(self, table: str, chain: str, rule_spec: List[str]) -> bool:
        """检查 iptables 规则是否存在"""
        success, _ = self._iptables(
            ["-t", table, "-C", chain] + rule_spec,
            check=False
        )
        return success

    def _add_rule_if_not_exists(self, table: str, chain: str, rule_spec: List[str]) -> bool:
        """添加 iptables 规则（如果不存在）"""
        if self._rule_exists(table, chain, rule_spec):
            self._logger.debug(f"Rule already exists: {rule_spec}")
            return True

        success, error = self._iptables(["-t", table, "-A", chain] + rule_spec)
        if not success:
            self._logger.error(f"Failed to add rule: {error}")
            return False
        return True

    def _delete_rule_if_exists(self, table: str, chain: str, rule_spec: List[str]) -> bool:
        """删除 iptables 规则（如果存在）"""
        if not self._rule_exists(table, chain, rule_spec):
            return True

        success, error = self._iptables(["-t", table, "-D", chain] + rule_spec)
        if not success:
            self._logger.error(f"Failed to delete rule: {error}")
            return False
        return True

    def _ip_rule_exists(self, fwmark: int, table: int) -> bool:
        """Check if an ip rule with given fwmark and table exists.

        Supports both hex (0x12d) and decimal (301) fwmark formats
        as different Linux distributions use different output formats.
        """
        success, output = self._ip(["rule", "list"])
        if not success:
            return False

        # Pattern 1: hex format (e.g., "fwmark 0x12d lookup 301")
        hex_pattern = rf"fwmark\s+0x{fwmark:x}\s+.*lookup\s+{table}\b"
        if re.search(hex_pattern, output, re.IGNORECASE):
            return True

        # Pattern 2: decimal format (e.g., "fwmark 301 lookup 301")
        dec_pattern = rf"fwmark\s+{fwmark}\s+.*lookup\s+{table}\b"
        if re.search(dec_pattern, output):
            return True

        return False

    def setup_entry_rules(
        self,
        chain_tag: str,
        routing_mark: int,
        dscp_value: int,
    ) -> bool:
        """设置入口节点的 DSCP 标记规则

        将 sing-box 的 routing_mark 转换为 DSCP 值，用于标记发往隧道的流量。

        Args:
            chain_tag: 链路标识
            routing_mark: sing-box outbound 的 routing_mark 值
            dscp_value: 要设置的 DSCP 值 (1-63)

        Returns:
            是否成功
        """
        # 输入验证
        if not self._validate_chain_tag(chain_tag):
            self._logger.error(f"Invalid chain_tag format: {chain_tag}")
            return False

        if not (DSCP_MIN <= dscp_value <= DSCP_MAX):
            self._logger.error(f"Invalid DSCP value: {dscp_value}, must be {DSCP_MIN}-{DSCP_MAX}")
            return False

        if dscp_value in RESERVED_DSCP_VALUES:
            self._logger.warning(f"DSCP {dscp_value} is reserved, using anyway")

        self._logger.info(
            f"[entry] Setting DSCP rules: chain={chain_tag}, "
            f"routing_mark={routing_mark}, dscp={dscp_value}"
        )

        # 规则 1: routing_mark → DSCP
        # iptables -t mangle -A OUTPUT -m mark --mark <routing_mark> -j DSCP --set-dscp <dscp>
        rule1 = [
            "-m", "mark", "--mark", str(routing_mark),
            "-j", "DSCP", "--set-dscp", str(dscp_value),
        ]

        # 规则 2: 清除 routing_mark（避免干扰后续路由）
        # iptables -t mangle -A OUTPUT -m mark --mark <routing_mark> -j MARK --set-mark 0
        rule2 = [
            "-m", "mark", "--mark", str(routing_mark),
            "-j", "MARK", "--set-mark", "0",
        ]

        # 添加规则（顺序重要：先设 DSCP，再清除 mark）
        if not self._add_rule_if_not_exists("mangle", "OUTPUT", rule1):
            return False
        if not self._add_rule_if_not_exists("mangle", "OUTPUT", rule2):
            # 回滚第一条规则
            self._delete_rule_if_exists("mangle", "OUTPUT", rule1)
            return False

        # 记录规则（线程安全）
        with self._lock:
            self._rules[chain_tag] = DSCPRule(
                chain_tag=chain_tag,
                dscp_value=dscp_value,
                routing_mark=routing_mark,
                fwmark=TERMINAL_FWMARK_BASE + dscp_value,
                table=TERMINAL_TABLE_BASE + dscp_value,
            )

        self._logger.info(f"[entry] DSCP rules set successfully: chain={chain_tag}")
        return True

    def setup_terminal_rules(
        self,
        dscp_value: int,
        egress_interface: str,
        peer_interface_pattern: str = "wg-peer-+",
    ) -> bool:
        """设置终端节点的 DSCP 路由规则

        读取入站流量的 DSCP 值，转换为 fwmark，并设置策略路由到指定出口。

        Args:
            dscp_value: 要匹配的 DSCP 值 (1-63)
            egress_interface: 出口网络接口（如 wg-pia-us-stream）
            peer_interface_pattern: 入站接口模式（默认 wg-peer-+，匹配所有对端隧道）

        Returns:
            是否成功
        """
        # 输入验证
        if not (DSCP_MIN <= dscp_value <= DSCP_MAX):
            self._logger.error(f"Invalid DSCP value: {dscp_value}, must be {DSCP_MIN}-{DSCP_MAX}")
            return False

        if not self._validate_interface_name(egress_interface):
            self._logger.error(f"Invalid egress interface name: {egress_interface}")
            return False

        if not self._validate_interface_name(peer_interface_pattern):
            self._logger.error(f"Invalid peer interface pattern: {peer_interface_pattern}")
            return False

        fwmark = TERMINAL_FWMARK_BASE + dscp_value
        table = TERMINAL_TABLE_BASE + dscp_value

        self._logger.info(
            f"[terminal] Setting DSCP routing: dscp={dscp_value}, "
            f"fwmark={fwmark}, table={table}, egress={egress_interface}"
        )

        # 规则 1: DSCP → fwmark
        # iptables -t mangle -A PREROUTING -i wg-peer-+ -m dscp --dscp <dscp> -j MARK --set-mark <fwmark>
        rule1 = [
            "-i", peer_interface_pattern,
            "-m", "dscp", "--dscp", str(dscp_value),
            "-j", "MARK", "--set-mark", str(fwmark),
        ]

        if not self._add_rule_if_not_exists("mangle", "PREROUTING", rule1):
            return False

        # 记录是否添加了新的 ip rule（用于回滚）
        added_ip_rule = False

        # 策略路由 2: ip rule add fwmark <fwmark> table <table>
        if not self._ip_rule_exists(fwmark, table):
            success, error = self._ip([
                "rule", "add", "fwmark", str(fwmark), "table", str(table)
            ])
            if not success:
                self._logger.error(f"Failed to add ip rule: {error}")
                self._delete_rule_if_exists("mangle", "PREROUTING", rule1)
                return False
            added_ip_rule = True

        # 策略路由 3: ip route add default dev <egress> table <table>
        # 先清除旧路由（只删除 default，不 flush 整个表）
        self._ip(["route", "del", "default", "table", str(table)], check=False)

        success, error = self._ip([
            "route", "add", "default", "dev", egress_interface, "table", str(table)
        ])
        if not success:
            self._logger.error(f"Failed to add route: {error}")
            # 回滚已添加的规则
            if added_ip_rule:
                self._ip(["rule", "del", "fwmark", str(fwmark), "table", str(table)], check=False)
            self._delete_rule_if_exists("mangle", "PREROUTING", rule1)
            return False

        self._logger.info(f"[terminal] DSCP routing set successfully: dscp={dscp_value}")
        return True

    def verify_entry_rules(
        self,
        chain_tag: str,
        routing_mark: int,
        dscp_value: int,
    ) -> bool:
        """验证入口 DSCP 规则是否实际生效

        检查 iptables OUTPUT 链中的两条规则是否存在。

        Args:
            chain_tag: 链路标识
            routing_mark: sing-box 的 routing_mark 值
            dscp_value: DSCP 值 (1-63)

        Returns:
            True 如果两条规则都存在，否则 False
        """
        # 规则 1: mark → DSCP (OUTPUT chain)
        rule1 = [
            "-m", "mark", "--mark", str(routing_mark),
            "-j", "DSCP", "--set-dscp", str(dscp_value),
        ]
        if not self._rule_exists("mangle", "OUTPUT", rule1):
            self._logger.error(f"[{chain_tag}] Entry rule 1 (mark→DSCP) verification failed")
            return False

        # 规则 2: clear mark (OUTPUT chain)
        rule2 = [
            "-m", "mark", "--mark", str(routing_mark),
            "-j", "MARK", "--set-mark", "0",
        ]
        if not self._rule_exists("mangle", "OUTPUT", rule2):
            self._logger.error(f"[{chain_tag}] Entry rule 2 (clear mark) verification failed")
            return False

        self._logger.info(f"[{chain_tag}] Entry DSCP rules verified successfully")
        return True

    def verify_terminal_rules(
        self,
        dscp_value: int,
        egress_interface: str,
        peer_interface_pattern: str = "wg-peer-+",
    ) -> bool:
        """验证终端 DSCP 规则是否实际生效

        检查 iptables 规则、ip rule 和 ip route 是否都存在。

        Args:
            dscp_value: DSCP 值 (1-63)
            egress_interface: 出口网络接口
            peer_interface_pattern: 入站接口模式

        Returns:
            True 如果所有规则都存在，否则 False
        """
        fwmark = TERMINAL_FWMARK_BASE + dscp_value
        table = TERMINAL_TABLE_BASE + dscp_value

        # 检查 iptables 规则 (PREROUTING chain)
        rule = [
            "-i", peer_interface_pattern,
            "-m", "dscp", "--dscp", str(dscp_value),
            "-j", "MARK", "--set-mark", str(fwmark),
        ]
        if not self._rule_exists("mangle", "PREROUTING", rule):
            self._logger.error(f"[dscp={dscp_value}] Terminal iptables rule verification failed")
            return False

        # 检查 ip rule
        if not self._ip_rule_exists(fwmark, table):
            self._logger.error(f"[dscp={dscp_value}] Terminal ip rule verification failed")
            return False

        # 检查 ip route
        success, output = self._ip(["route", "show", "table", str(table)])
        if not success:
            self._logger.error(f"[dscp={dscp_value}] Terminal ip route query failed")
            return False

        # Use regex with word boundaries for exact interface matching
        # Pattern matches "dev wg-pia-us " or "dev wg-pia-us\n" but not "dev wg-pia-us2"
        interface_pattern = rf"\bdev\s+{re.escape(egress_interface)}\b"
        if not re.search(interface_pattern, output):
            self._logger.error(f"[dscp={dscp_value}] Terminal ip route verification failed: interface '{egress_interface}' not found in table {table}")
            return False

        self._logger.info(f"[dscp={dscp_value}] Terminal DSCP rules verified successfully")
        return True

    def cleanup_entry_rules(
        self,
        chain_tag: str,
        routing_mark: int,
        dscp_value: int,
    ) -> bool:
        """清理入口节点的 DSCP 规则

        Args:
            chain_tag: 链路标识
            routing_mark: routing_mark 值
            dscp_value: DSCP 值

        Returns:
            是否成功
        """
        self._logger.info(f"[entry] Cleaning up DSCP rules: chain={chain_tag}")

        # 删除规则（顺序相反：先删 mark 清除，再删 DSCP 设置）
        rule2 = [
            "-m", "mark", "--mark", str(routing_mark),
            "-j", "MARK", "--set-mark", "0",
        ]
        rule1 = [
            "-m", "mark", "--mark", str(routing_mark),
            "-j", "DSCP", "--set-dscp", str(dscp_value),
        ]

        self._delete_rule_if_exists("mangle", "OUTPUT", rule2)
        self._delete_rule_if_exists("mangle", "OUTPUT", rule1)

        # 移除记录（线程安全）
        with self._lock:
            if chain_tag in self._rules:
                del self._rules[chain_tag]

        self._logger.info(f"[entry] DSCP rules cleaned up: chain={chain_tag}")
        return True

    def cleanup_terminal_rules(
        self,
        dscp_value: int,
        peer_interface_pattern: str = "wg-peer-+",
    ) -> bool:
        """清理终端节点的 DSCP 路由规则

        Args:
            dscp_value: DSCP 值
            peer_interface_pattern: 入站接口模式

        Returns:
            是否成功
        """
        fwmark = TERMINAL_FWMARK_BASE + dscp_value
        table = TERMINAL_TABLE_BASE + dscp_value

        self._logger.info(f"[terminal] Cleaning up DSCP routing: dscp={dscp_value}")

        # 清除路由表
        self._ip(["route", "flush", "table", str(table)], check=False)

        # 删除 ip rule
        # 可能有多条相同规则，循环删除
        for _ in range(10):  # 最多尝试 10 次
            if not self._ip_rule_exists(fwmark, table):
                break
            self._ip(["rule", "del", "fwmark", str(fwmark), "table", str(table)], check=False)

        # 删除 iptables 规则
        rule1 = [
            "-i", peer_interface_pattern,
            "-m", "dscp", "--dscp", str(dscp_value),
            "-j", "MARK", "--set-mark", str(fwmark),
        ]
        self._delete_rule_if_exists("mangle", "PREROUTING", rule1)

        self._logger.info(f"[terminal] DSCP routing cleaned up: dscp={dscp_value}")
        return True

    def cleanup_all_rules(self) -> bool:
        """清理所有 DSCP 相关规则

        用于容器关闭或重置时的完整清理。

        Returns:
            是否成功
        """
        self._logger.info("Cleaning up all DSCP rules")

        success = True

        # 清理所有可能的 DSCP 值对应的规则
        for dscp in range(DSCP_MIN, DSCP_MAX + 1):
            fwmark = TERMINAL_FWMARK_BASE + dscp
            table = TERMINAL_TABLE_BASE + dscp
            routing_mark = ENTRY_ROUTING_MARK_BASE + dscp

            # 清理终端节点规则
            self._ip(["route", "flush", "table", str(table)], check=False)
            self._ip(["rule", "del", "fwmark", str(fwmark)], check=False)

            # 清理入口节点规则（通用模式）
            rule1 = [
                "-m", "mark", "--mark", str(routing_mark),
                "-j", "DSCP", "--set-dscp", str(dscp),
            ]
            rule2 = [
                "-m", "mark", "--mark", str(routing_mark),
                "-j", "MARK", "--set-mark", "0",
            ]
            self._delete_rule_if_exists("mangle", "OUTPUT", rule2)
            self._delete_rule_if_exists("mangle", "OUTPUT", rule1)

            # 清理终端节点 iptables 规则
            for pattern in ["wg-peer-+", "wg-peer-*"]:
                terminal_rule = [
                    "-i", pattern,
                    "-m", "dscp", "--dscp", str(dscp),
                    "-j", "MARK", "--set-mark", str(fwmark),
                ]
                self._delete_rule_if_exists("mangle", "PREROUTING", terminal_rule)

        # 清空记录（线程安全）
        with self._lock:
            self._rules.clear()
        self._logger.info("All DSCP rules cleaned up")
        return success

    def cleanup_rules_for_interface(self, interface: str) -> bool:
        """清理与特定接口相关的所有 DSCP 规则

        当 WireGuard 隧道断开时调用，清理该接口相关的 iptables 规则。

        Args:
            interface: WireGuard 接口名称（如 wg-peer-node2）

        Returns:
            是否成功
        """
        self._logger.info(f"Cleaning up DSCP rules for interface: {interface}")
        success = True

        # 清理所有可能的 DSCP 值对应的规则
        for dscp in range(DSCP_MIN, DSCP_MAX + 1):
            fwmark = TERMINAL_FWMARK_BASE + dscp

            # 清理终端节点规则（匹配入站接口）
            terminal_rule = [
                "-i", interface,
                "-m", "dscp", "--dscp", str(dscp),
                "-j", "MARK", "--set-mark", str(fwmark),
            ]
            self._delete_rule_if_exists("mangle", "PREROUTING", terminal_rule)

            # 清理入口节点规则（匹配出站接口）
            routing_mark = ENTRY_ROUTING_MARK_BASE + dscp
            entry_rule1 = [
                "-o", interface,
                "-m", "mark", "--mark", str(routing_mark),
                "-j", "DSCP", "--set-dscp", str(dscp),
            ]
            entry_rule2 = [
                "-o", interface,
                "-m", "mark", "--mark", str(routing_mark),
                "-j", "MARK", "--set-mark", "0",
            ]
            self._delete_rule_if_exists("mangle", "POSTROUTING", entry_rule2)
            self._delete_rule_if_exists("mangle", "POSTROUTING", entry_rule1)

        self._logger.info(f"DSCP rules cleaned up for interface: {interface}")
        return success

    def get_dscp_for_chain(self, chain_tag: str) -> Optional[int]:
        """获取链路的 DSCP 值"""
        with self._lock:
            rule = self._rules.get(chain_tag)
            return rule.dscp_value if rule else None

    def get_routing_mark(self, dscp_value: int) -> int:
        """根据 DSCP 值计算 routing_mark"""
        return ENTRY_ROUTING_MARK_BASE + dscp_value

    def get_fwmark(self, dscp_value: int) -> int:
        """根据 DSCP 值计算 fwmark"""
        return TERMINAL_FWMARK_BASE + dscp_value

    def get_table(self, dscp_value: int) -> int:
        """根据 DSCP 值计算策略路由表号"""
        return TERMINAL_TABLE_BASE + dscp_value

    def list_active_rules(self) -> List[DSCPRule]:
        """列出所有活动的 DSCP 规则"""
        with self._lock:
            return list(self._rules.values())

    def is_dscp_available(self, dscp_value: int) -> bool:
        """检查 DSCP 值是否可用（未被使用且不是保留值）"""
        if dscp_value in RESERVED_DSCP_VALUES:
            return False
        # 检查是否已被其他链路使用（线程安全）
        with self._lock:
            for rule in self._rules.values():
                if rule.dscp_value == dscp_value:
                    return False
        return True


# 全局实例和锁
_dscp_manager: Optional[DSCPManager] = None
_dscp_manager_lock = threading.Lock()


def get_dscp_manager() -> DSCPManager:
    """获取全局 DSCP 管理器实例（线程安全）

    使用双重检查锁定模式确保线程安全的单例初始化。
    """
    global _dscp_manager
    if _dscp_manager is None:
        with _dscp_manager_lock:
            # 双重检查：进入锁后再次检查
            if _dscp_manager is None:
                _dscp_manager = DSCPManager()
    return _dscp_manager


if __name__ == "__main__":
    import sys

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    )

    manager = get_dscp_manager()

    if len(sys.argv) < 2:
        print("Usage: dscp_manager.py <command> [args]")
        print("Commands:")
        print("  cleanup              - Clean up all DSCP rules")
        print("  entry <tag> <mark> <dscp>  - Set entry node rules")
        print("  terminal <dscp> <interface> - Set terminal node rules")
        print("  list                 - List active rules")
        sys.exit(1)

    command = sys.argv[1]

    if command == "cleanup":
        manager.cleanup_all_rules()
        print("All DSCP rules cleaned up")

    elif command == "entry" and len(sys.argv) == 5:
        tag = sys.argv[2]
        mark = int(sys.argv[3])
        dscp = int(sys.argv[4])
        if manager.setup_entry_rules(tag, mark, dscp):
            print(f"Entry rules set: tag={tag}, mark={mark}, dscp={dscp}")
        else:
            print("Failed to set entry rules")
            sys.exit(1)

    elif command == "terminal" and len(sys.argv) == 4:
        dscp = int(sys.argv[2])
        interface = sys.argv[3]
        if manager.setup_terminal_rules(dscp, interface):
            print(f"Terminal rules set: dscp={dscp}, interface={interface}")
        else:
            print("Failed to set terminal rules")
            sys.exit(1)

    elif command == "list":
        rules = manager.list_active_rules()
        if rules:
            for r in rules:
                print(f"Chain: {r.chain_tag}, DSCP: {r.dscp_value}, Mark: {r.routing_mark}")
        else:
            print("No active DSCP rules")

    else:
        print(f"Unknown command: {command}")
        sys.exit(1)

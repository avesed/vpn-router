#!/usr/bin/env python3
"""DSCP 标记管理器

.. deprecated:: Phase 12
    此模块已弃用。rust-router 现在在用户空间处理 DSCP 路由，无需内核 iptables 规则。
    
    - 入口节点 DSCP 标记：rust-router/src/ingress/forwarder.rs
    - 终端节点 DSCP 路由：rust-router/src/ingress/processor.rs
    
    保留此文件仅用于向后兼容和参考。所有 setup/cleanup 函数现在是 no-op。

原始功能说明（已废弃）：
管理多跳链路的 DSCP iptables 规则，用于 WireGuard 隧道的流量识别和路由。

架构（已迁移到 rust-router 用户空间）：
- 入口节点：sing-box routing_mark → iptables DSCP 设置 → WireGuard
- 中继节点：透传（Linux 保留 DSCP）
- 终端节点：iptables DSCP 读取 → fwmark → 策略路由 → 本地出口

使用示例（已废弃）：
    manager = DSCPManager()

    # 入口节点：设置 DSCP 标记规则
    manager.setup_entry_rules("us-stream", routing_mark=101, dscp_value=1)

    # 终端节点：设置 DSCP 路由规则
    manager.setup_terminal_rules(dscp_value=1, egress_interface="wg-pia-us")

    # 清理规则
    manager.cleanup_chain_rules("us-stream")
"""

import json
import logging
import os
import re
import subprocess
import threading
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

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

# 持久化状态文件路径 (Phase 11-Fix.P)
DSCP_STATE_FILE = Path(os.environ.get("DSCP_STATE_FILE", "/etc/sing-box/dscp-state.json"))


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
        self._terminal_rules: Dict[int, Dict[str, Any]] = {}  # dscp_value -> terminal rule info
        self._logger = logging.getLogger("dscp-manager")
        self._lock = threading.Lock()  # 保护 _rules 的线程锁

    def _persist_state(self) -> bool:
        """持久化当前规则状态到 JSON 文件 (Phase 11-Fix.P)

        使用原子写入确保数据一致性。
        注意：锁保护整个操作以避免竞争条件。

        Returns:
            是否成功
        """
        try:
            with self._lock:
                state = {
                    "entry_rules": {
                        tag: asdict(rule) for tag, rule in self._rules.items()
                    },
                    "terminal_rules": self._terminal_rules.copy(),
                }

                # 原子写入：先写临时文件，再重命名（在锁内执行）
                tmp_file = DSCP_STATE_FILE.with_suffix(".tmp")
                DSCP_STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
                tmp_file.write_text(json.dumps(state, indent=2))
                tmp_file.rename(DSCP_STATE_FILE)

                self._logger.debug(f"DSCP state persisted: {len(state['entry_rules'])} entry rules, {len(state['terminal_rules'])} terminal rules")
            return True
        except Exception as e:
            self._logger.error(f"Failed to persist DSCP state: {e}")
            return False

    def load_persisted_state(self) -> int:
        """从持久化文件加载并恢复 DSCP 规则 (Phase 11-Fix.P)

        在容器启动时调用，恢复之前的 DSCP 规则状态。

        Returns:
            恢复的规则数量
        """
        if not DSCP_STATE_FILE.exists():
            self._logger.info("No persisted DSCP state found")
            return 0

        try:
            state = json.loads(DSCP_STATE_FILE.read_text())
            restored_count = 0

            # 恢复入口规则
            entry_rules = state.get("entry_rules", {})
            for chain_tag, rule_data in entry_rules.items():
                routing_mark = rule_data.get("routing_mark")
                dscp_value = rule_data.get("dscp_value")

                if routing_mark is None or dscp_value is None:
                    self._logger.warning(f"Skipping invalid entry rule: {chain_tag}")
                    continue

                # 重新应用规则
                if self.setup_entry_rules(chain_tag, routing_mark, dscp_value, persist=False):
                    # 验证规则确实生效
                    if self.verify_entry_rules(chain_tag, routing_mark, dscp_value):
                        restored_count += 1
                        self._logger.info(f"Restored entry rule: chain={chain_tag}, dscp={dscp_value}")
                    else:
                        # 使用 warning 而非 error：规则可能在链路激活时重新创建
                        self._logger.warning(f"Entry rule restored but verification failed: {chain_tag} (will be re-created on chain activation)")
                else:
                    self._logger.warning(f"Failed to restore entry rule: {chain_tag} (will be re-created on chain activation)")

            # 恢复终端规则
            terminal_rules = state.get("terminal_rules", {})
            for dscp_str, rule_data in terminal_rules.items():
                dscp_value = int(dscp_str)
                egress_interface = rule_data.get("egress_interface")
                peer_interface_pattern = rule_data.get("peer_interface_pattern", "wg-peer-+")

                if not egress_interface:
                    self._logger.warning(f"Skipping invalid terminal rule: dscp={dscp_value}")
                    continue

                # 重新应用规则
                if self.setup_terminal_rules(dscp_value, egress_interface, peer_interface_pattern, persist=False):
                    # 验证规则确实生效
                    if self.verify_terminal_rules(dscp_value, egress_interface, peer_interface_pattern):
                        restored_count += 1
                        self._logger.info(f"Restored terminal rule: dscp={dscp_value}, egress={egress_interface}")
                    else:
                        self._logger.warning(f"Terminal rule restored but verification failed: dscp={dscp_value} (interface may not exist yet)")
                else:
                    self._logger.warning(f"Failed to restore terminal rule: dscp={dscp_value} (interface may not exist yet)")

            self._logger.info(f"DSCP state restoration complete: {restored_count} rules restored")
            return restored_count

        except json.JSONDecodeError as e:
            self._logger.error(f"Failed to parse DSCP state file: {e}")
            return 0
        except Exception as e:
            self._logger.error(f"Failed to load DSCP state: {e}")
            return 0

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

        Phase 11-Fix.V.1: 修复 check=False 时总是返回 True 的问题

        Args:
            cmd: 命令列表
            check: 是否记录错误日志（不影响返回值的正确性）
                   - True: 命令失败时记录警告日志
                   - False: 静默失败，不记录日志（用于探测性检查如 iptables -C）

        Returns:
            (success, output/error)
            - success: 始终反映实际命令执行结果 (returncode == 0)
            - output: 成功时返回 stdout，失败时返回 stderr
        """
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=30,
            )
            # 修复: 始终根据返回码判断成功与否
            success = (result.returncode == 0)
            if not success:
                error_msg = result.stderr.strip() or f"Command failed with exit code {result.returncode}"
                if check:
                    # 仅在 check=True 时记录错误日志
                    self._logger.warning(f"Command failed: {' '.join(cmd)}: {error_msg}")
                return False, error_msg
            return True, (result.stdout or "").strip()
        except subprocess.TimeoutExpired:
            if check:
                self._logger.error(f"Command timeout: {' '.join(cmd)}")
            return False, "Command timeout"
        except Exception as e:
            if check:
                self._logger.error(f"Command exception: {' '.join(cmd)}: {e}")
            return False, str(e)

    def _ensure_kernel_modules(self) -> bool:
        """Phase 11-Fix.T: 确保 DSCP 相关内核模块已加载

        DSCP 操作需要以下内核模块:
        - xt_DSCP: 用于设置 DSCP 值 (-j DSCP --set-dscp)
        - xt_dscp: 用于匹配 DSCP 值 (-m dscp --dscp)
        - xt_mark: 用于设置/匹配 fwmark

        Returns:
            True 如果所有模块可用，False 如果加载失败
        """
        required_modules = ["xt_DSCP", "xt_dscp", "xt_mark"]

        for module in required_modules:
            # 检查模块是否已加载
            check_cmd = ["lsmod"]
            success, output = self._run_command(check_cmd, check=False)
            if success and module.lower() in output.lower():
                continue

            # 尝试加载模块
            self._logger.info(f"Loading kernel module: {module}")
            load_cmd = ["modprobe", module]
            success, error = self._run_command(load_cmd, check=False)
            if not success:
                # 模块可能内置于内核（不需要单独加载）
                # 尝试使用 iptables 命令来验证功能可用性
                test_cmd = ["iptables", "-t", "mangle", "-L", "-n"]
                test_success, _ = self._run_command(test_cmd, check=False)
                if not test_success:
                    self._logger.error(
                        f"Kernel module {module} not available and cannot load: {error}"
                    )
                    return False
                else:
                    self._logger.debug(
                        f"Module {module} may be built-in or alias, iptables works"
                    )

        return True

    def _iptables(self, args: List[str], check: bool = True) -> Tuple[bool, str]:
        """执行 iptables 命令"""
        return self._run_command(["iptables"] + args, check)

    def _ip(self, args: List[str], check: bool = True) -> Tuple[bool, str]:
        """执行 ip 命令"""
        return self._run_command(["ip"] + args, check)

    def _get_interface_gateway(self, interface: str) -> Optional[str]:
        """获取指定接口的默认网关 IP

        Phase 11-Fix.Y: 对于物理接口（如 eth0），需要获取网关才能正确设置路由。
        WireGuard 接口是点对点隧道，不需要网关。

        Args:
            interface: 接口名称（如 eth0, ens192）

        Returns:
            网关 IP 地址，如果无法获取则返回 None
        """
        # WireGuard 接口不需要网关（点对点隧道）
        if interface.startswith("wg-"):
            return None

        # 方法 1: 从 main 路由表获取该接口的默认路由网关
        # 命令: ip route show dev eth0 default
        # 输出示例: default via 10.1.100.2 proto static
        success, output = self._ip(["route", "show", "dev", interface, "default"], check=False)
        if success and output:
            # 解析 "default via X.X.X.X ..."
            match = re.search(r'default\s+via\s+(\d+\.\d+\.\d+\.\d+)', output)
            if match:
                gateway = match.group(1)
                self._logger.debug(f"Found gateway {gateway} for interface {interface}")
                return gateway

        # 方法 2: 从所有默认路由中查找该接口的网关
        # 命令: ip route show default
        # 输出示例: default via 10.1.100.2 dev eth0 proto static
        success, output = self._ip(["route", "show", "default"], check=False)
        if success and output:
            for line in output.split('\n'):
                if f"dev {interface}" in line:
                    match = re.search(r'default\s+via\s+(\d+\.\d+\.\d+\.\d+)', line)
                    if match:
                        gateway = match.group(1)
                        self._logger.debug(f"Found gateway {gateway} for interface {interface} from default routes")
                        return gateway

        self._logger.warning(f"Could not find gateway for interface {interface}")
        return None

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
        verify: bool = False,
        persist: bool = True,
    ) -> bool:
        """设置入口节点的 DSCP 标记规则

        将 sing-box 的 routing_mark 转换为 DSCP 值，用于标记发往隧道的流量。

        Args:
            chain_tag: 链路标识
            routing_mark: sing-box outbound 的 routing_mark 值
            dscp_value: 要设置的 DSCP 值 (1-63)
            verify: 是否在设置后验证规则 (Phase 11-Fix.P)
            persist: 是否持久化状态 (Phase 11-Fix.P)

        Returns:
            是否成功
        """
        # Phase 11-Fix.T: 确保内核模块可用
        if not self._ensure_kernel_modules():
            self._logger.error("DSCP kernel modules not available")
            return False

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

        # Phase 11-Fix.P: 持久化状态
        if persist:
            self._persist_state()

        # Phase 11-Fix.P: 验证规则
        if verify:
            if not self.verify_entry_rules(chain_tag, routing_mark, dscp_value):
                self._logger.error(f"[entry] DSCP rules verification failed: chain={chain_tag}")
                # 回滚规则
                self.cleanup_entry_rules(chain_tag, routing_mark, dscp_value, persist=persist)
                return False

        self._logger.info(f"[entry] DSCP rules set successfully: chain={chain_tag}")
        return True

    def setup_terminal_rules(
        self,
        dscp_value: int,
        egress_interface: str,
        peer_interface_pattern: str = "wg-peer-+",
        verify: bool = False,
        persist: bool = True,
    ) -> bool:
        """设置终端节点的 DSCP 路由规则

        读取入站流量的 DSCP 值，转换为 fwmark，并设置策略路由到指定出口。

        Args:
            dscp_value: 要匹配的 DSCP 值 (1-63)
            egress_interface: 出口网络接口（如 wg-pia-us-stream）
            peer_interface_pattern: 入站接口模式（默认 wg-peer-+，匹配所有对端隧道）
            verify: 是否在设置后验证规则 (Phase 11-Fix.P)
            persist: 是否持久化状态 (Phase 11-Fix.P)

        Returns:
            是否成功
        """
        # Phase 11-Fix.T: 确保内核模块可用
        if not self._ensure_kernel_modules():
            self._logger.error("DSCP kernel modules not available")
            return False

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

        # 策略路由 3: ip route add default [via <gateway>] dev <egress> table <table>
        # Phase 11-Fix.Y: 对于物理接口需要指定网关，否则会创建 scope link 路由导致 "no route to host"
        # 先清除旧路由（只删除 default，不 flush 整个表）
        self._ip(["route", "del", "default", "table", str(table)], check=False)

        # 获取接口网关（物理接口需要，WireGuard 接口不需要）
        gateway = self._get_interface_gateway(egress_interface)

        if gateway:
            # 物理接口：使用网关
            # ip route add default via 10.1.100.2 dev eth0 table 301
            route_cmd = [
                "route", "add", "default", "via", gateway,
                "dev", egress_interface, "table", str(table)
            ]
            self._logger.info(
                f"[terminal] Adding route with gateway: default via {gateway} dev {egress_interface} table {table}"
            )
        else:
            # WireGuard 接口：点对点隧道，不需要网关
            # ip route add default dev wg-pia-us table 301
            route_cmd = [
                "route", "add", "default", "dev", egress_interface, "table", str(table)
            ]
            self._logger.info(
                f"[terminal] Adding route without gateway: default dev {egress_interface} table {table}"
            )

        success, error = self._ip(route_cmd)
        if not success:
            self._logger.error(f"Failed to add route: {error}")
            # 回滚已添加的规则
            if added_ip_rule:
                self._ip(["rule", "del", "fwmark", str(fwmark), "table", str(table)], check=False)
            self._delete_rule_if_exists("mangle", "PREROUTING", rule1)
            return False

        # Phase 11-Fix.P: 记录终端规则用于持久化
        with self._lock:
            self._terminal_rules[dscp_value] = {
                "egress_interface": egress_interface,
                "peer_interface_pattern": peer_interface_pattern,
                "fwmark": fwmark,
                "table": table,
            }

        # Phase 11-Fix.P: 持久化状态
        if persist:
            self._persist_state()

        # Phase 11-Fix.P: 验证规则
        if verify:
            if not self.verify_terminal_rules(dscp_value, egress_interface, peer_interface_pattern):
                self._logger.error(f"[terminal] DSCP routing verification failed: dscp={dscp_value}")
                # 回滚规则
                self.cleanup_terminal_rules(dscp_value, peer_interface_pattern, persist=persist)
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
        persist: bool = True,
    ) -> bool:
        """清理入口节点的 DSCP 规则

        Args:
            chain_tag: 链路标识
            routing_mark: routing_mark 值
            dscp_value: DSCP 值
            persist: 是否持久化状态 (Phase 11-Fix.P)

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

        # Phase 11-Fix.P: 持久化状态
        if persist:
            self._persist_state()

        self._logger.info(f"[entry] DSCP rules cleaned up: chain={chain_tag}")
        return True

    def cleanup_terminal_rules(
        self,
        dscp_value: int,
        peer_interface_pattern: str = "wg-peer-+",
        persist: bool = True,
    ) -> bool:
        """清理终端节点的 DSCP 路由规则

        Args:
            dscp_value: DSCP 值
            peer_interface_pattern: 入站接口模式
            persist: 是否持久化状态 (Phase 11-Fix.P)

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

        # Phase 11-Fix.P: 移除终端规则记录
        with self._lock:
            if dscp_value in self._terminal_rules:
                del self._terminal_rules[dscp_value]

        # Phase 11-Fix.P: 持久化状态
        if persist:
            self._persist_state()

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
            self._terminal_rules.clear()

        # Phase 11-Fix.P: 持久化空状态（删除状态文件）
        if DSCP_STATE_FILE.exists():
            try:
                DSCP_STATE_FILE.unlink()
                self._logger.info("DSCP state file removed")
            except Exception as e:
                self._logger.warning(f"Failed to remove DSCP state file: {e}")

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
        print("  restore              - Restore DSCP rules from persisted state (Phase 11-Fix.P)")
        print("  entry <tag> <mark> <dscp>  - Set entry node rules")
        print("  terminal <dscp> <interface> - Set terminal node rules")
        print("  list                 - List active rules")
        sys.exit(1)

    command = sys.argv[1]

    if command == "cleanup":
        manager.cleanup_all_rules()
        print("All DSCP rules cleaned up")

    elif command == "restore":
        # Phase 11-Fix.P: 从持久化状态恢复 DSCP 规则
        count = manager.load_persisted_state()
        print(f"DSCP rules restored: {count} rules")

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

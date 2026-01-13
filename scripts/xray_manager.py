#!/usr/bin/env python3
"""
Xray 进程管理器

管理 Xray 进程和 TUN 设备，支持：
- 从数据库读取配置
- 生成 Xray JSON 配置
- 创建/配置 TUN 设备
- 启动/停止 Xray 进程
- 监控进程状态

使用方法:
    python3 xray_manager.py start     # 启动 Xray
    python3 xray_manager.py stop      # 停止 Xray
    python3 xray_manager.py reload    # 重载配置
    python3 xray_manager.py status    # 显示状态
    python3 xray_manager.py generate-keys  # 生成 REALITY 密钥对
"""

import argparse
import asyncio
import fcntl
import json
import logging
import os
import re
import secrets
import signal
import subprocess
import sys
import time
import uuid as uuid_module
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Any

# 添加脚本目录到 Python 路径
sys.path.insert(0, str(Path(__file__).parent))

from db_helper import get_db

# 配置 logger（在其他模块级函数使用前定义）
logging.basicConfig(
    level=logging.INFO,
    format='[xray-mgr] %(asctime)s %(levelname)s: %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger(__name__)


def _safe_int_env(name: str, default: int) -> int:
    """Safely read an integer from environment variable with fallback.

    Args:
        name: Environment variable name
        default: Default value if not set or invalid

    Returns:
        Integer value from environment or default
    """
    value = os.environ.get(name)
    if value is None:
        return default
    try:
        return int(value)
    except ValueError:
        logger.warning(f"Invalid integer value '{value}' for {name}, using default {default}")
        return default

# Email 格式验证（用于链路标记）
# 允许以字母或数字开头（兼容数字开头的 chain tag）
EMAIL_PATTERN = re.compile(r'^chain-[a-z0-9][a-z0-9\-]*@[a-z0-9][a-z0-9\-]*$')
MAX_EMAIL_LEN = 128

def validate_chain_email(email: str) -> bool:
    """验证链路 email 格式

    格式: chain-{chain_tag}@{source_node}
    例如: chain-us-stream@node-tokyo
    """
    if not email or len(email) > MAX_EMAIL_LEN:
        return False
    return bool(EMAIL_PATTERN.match(email))


def build_chain_email(chain_tag: str, source_node: str) -> str:
    """构建链路 email 标识

    Args:
        chain_tag: 链路标识
        source_node: 来源节点标识

    Returns:
        格式化的 email 字符串

    Raises:
        ValueError: 如果输入为空或无有效字符
    """
    if not chain_tag or not source_node:
        raise ValueError("chain_tag and source_node must not be empty")

    # 清理 tag 和 node，只保留安全字符
    safe_chain = re.sub(r'[^a-z0-9\-]', '', chain_tag.lower())[:32]
    safe_node = re.sub(r'[^a-z0-9\-]', '', source_node.lower())[:32]

    if not safe_chain or not safe_node:
        raise ValueError("chain_tag and source_node must contain valid characters (a-z, 0-9, -)")

    return f"chain-{safe_chain}@{safe_node}"


# 导入 DSCP 常量用于 fwmark 计算
# 终端节点的 Xray email 路由使用与 DSCP 相同的 fwmark 和策略路由表
try:
    from dscp_manager import TERMINAL_FWMARK_BASE, TERMINAL_TABLE_BASE
except ImportError:
    # 默认值，与 dscp_manager.py 保持一致
    TERMINAL_FWMARK_BASE = 300
    TERMINAL_TABLE_BASE = 300


@dataclass
class ChainEgressInfo:
    """链路出口信息

    用于描述终端节点如何路由链路流量到本地出口。
    """
    egress_tag: str
    egress_type: str  # "interface", "socks", "direct"
    interface: Optional[str] = None  # 网络接口名 (wg-pia-*, tun*, etc.)
    socks_port: Optional[int] = None  # SOCKS 代理端口 (V2Ray/WARP MASQUE)
    fwmark: Optional[int] = None  # 策略路由 fwmark


def get_chain_egress_info(db, egress_tag: str, mark_value: int) -> Optional[ChainEgressInfo]:
    """获取链路出口配置信息

    根据出口类型返回相应的配置信息，用于生成 Xray 出站配置。

    Args:
        db: DatabaseManager 实例
        egress_tag: 出口标识
        mark_value: 标记值（用于计算 fwmark，范围 0-63）

    Returns:
        ChainEgressInfo 实例，或 None 如果出口不存在或参数无效
    """
    # 验证 mark_value 范围（DSCP 值范围是 0-63）
    if not isinstance(mark_value, int) or mark_value < 0 or mark_value > 63:
        logger.error(f"Invalid mark_value: {mark_value} (must be 0-63)")
        return None

    # 计算 fwmark 并验证不超过 65535
    fwmark = TERMINAL_FWMARK_BASE + mark_value
    if fwmark > 65535:
        logger.error(f"Calculated fwmark {fwmark} exceeds 65535")
        return None

    # 特殊情况：direct 使用默认直连
    if egress_tag == "direct":
        return ChainEgressInfo(
            egress_tag="direct",
            egress_type="direct"
        )

    # 检查 PIA profiles
    try:
        profiles = db.get_pia_profiles(enabled_only=True)
        for p in profiles:
            if p.get("name") == egress_tag:
                from db_helper import get_egress_interface_name
                interface = get_egress_interface_name(egress_tag, is_pia=True)
                return ChainEgressInfo(
                    egress_tag=egress_tag,
                    egress_type="interface",
                    interface=interface,
                    fwmark=fwmark
                )
    except Exception as e:
        logger.warning(f"检查 PIA profiles 时出错: {e}")

    # 检查 Custom WireGuard
    try:
        custom_list = db.get_custom_egress_list(enabled_only=True)
        for e in custom_list:
            if e.get("tag") == egress_tag:
                from db_helper import get_egress_interface_name
                interface = get_egress_interface_name(egress_tag, is_pia=False)
                return ChainEgressInfo(
                    egress_tag=egress_tag,
                    egress_type="interface",
                    interface=interface,
                    fwmark=fwmark
                )
    except Exception as e:
        logger.warning(f"检查 Custom WireGuard 时出错: {e}")

    # 检查 WARP WireGuard
    try:
        warp_list = db.get_warp_egress_list(enabled_only=True)
        for e in warp_list:
            if e.get("tag") == egress_tag:
                protocol = e.get("protocol", "masque")
                if protocol == "wireguard":
                    # Phase 11-Fix.I: 使用统一的接口命名函数
                    from setup_kernel_wg_egress import get_egress_interface_name as get_wg_egress_iface
                    interface = get_wg_egress_iface(egress_tag, egress_type="warp")
                    return ChainEgressInfo(
                        egress_tag=egress_tag,
                        egress_type="interface",
                        interface=interface,
                        fwmark=fwmark
                    )
                else:
                    # WARP MASQUE 使用 SOCKS
                    socks_port = e.get("socks_port")
                    if socks_port:
                        return ChainEgressInfo(
                            egress_tag=egress_tag,
                            egress_type="socks",
                            socks_port=socks_port
                        )
    except Exception as e:
        logger.warning(f"检查 WARP egress 时出错: {e}")

    # 检查 OpenVPN（TUN 设备）
    try:
        openvpn_list = db.get_openvpn_egress_list(enabled_only=True)
        for e in openvpn_list:
            if e.get("tag") == egress_tag:
                tun_device = e.get("tun_device")
                if tun_device:
                    return ChainEgressInfo(
                        egress_tag=egress_tag,
                        egress_type="interface",
                        interface=tun_device,
                        fwmark=fwmark
                    )
    except Exception as e:
        logger.warning(f"检查 OpenVPN egress 时出错: {e}")

    # 检查 Direct egress（bind_interface）
    try:
        direct_list = db.get_direct_egress_list(enabled_only=True)
        for e in direct_list:
            if e.get("tag") == egress_tag:
                interface = e.get("bind_interface")
                if interface:
                    return ChainEgressInfo(
                        egress_tag=egress_tag,
                        egress_type="interface",
                        interface=interface,
                        fwmark=fwmark
                    )
                else:
                    # Direct without interface uses default routing
                    return ChainEgressInfo(
                        egress_tag=egress_tag,
                        egress_type="direct"
                    )
    except Exception as e:
        logger.warning(f"检查 Direct egress 时出错: {e}")

    # 检查 V2Ray egress（SOCKS）
    try:
        v2ray_list = db.get_v2ray_egress_list(enabled_only=True)
        for e in v2ray_list:
            if e.get("tag") == egress_tag:
                socks_port = e.get("socks_port")
                if socks_port:
                    return ChainEgressInfo(
                        egress_tag=egress_tag,
                        egress_type="socks",
                        socks_port=socks_port
                    )
    except Exception as e:
        logger.warning(f"检查 V2Ray egress 时出错: {e}")

    logger.warning(f"未找到出口: {egress_tag}")
    return None


def build_chain_routing_outbound(egress_info: ChainEgressInfo, chain_tag: str) -> Optional[Dict]:
    """构建链路路由出站配置

    根据出口类型生成相应的 Xray 出站配置。

    Args:
        egress_info: 出口信息
        chain_tag: 链路标识

    Returns:
        Xray 出站配置字典，或 None 如果无法生成
    """
    safe_chain = re.sub(r'[^a-z0-9\-]', '', chain_tag.lower())[:32]
    outbound_tag = f"chain-egress-{safe_chain}"

    if egress_info.egress_type == "interface":
        # 接口类型：使用 freedom 出站 + sockopt.mark
        # 策略路由会根据 mark 选择正确的接口
        if egress_info.fwmark is None:
            logger.error(f"接口类型出口缺少 fwmark: {egress_info.egress_tag}")
            return None
        return {
            "tag": outbound_tag,
            "protocol": "freedom",
            "settings": {
                "domainStrategy": "AsIs"
            },
            "streamSettings": {
                "sockopt": {
                    "mark": egress_info.fwmark
                }
            }
        }

    elif egress_info.egress_type == "socks":
        # SOCKS 类型：使用 SOCKS 出站
        if egress_info.socks_port is None:
            logger.error(f"SOCKS 类型出口缺少端口: {egress_info.egress_tag}")
            return None
        return {
            "tag": outbound_tag,
            "protocol": "socks",
            "settings": {
                "servers": [{
                    "address": "127.0.0.1",
                    "port": egress_info.socks_port
                }]
            }
        }

    elif egress_info.egress_type == "direct":
        # 直连类型：使用 freedom 出站（无 mark）
        return {
            "tag": outbound_tag,
            "protocol": "freedom",
            "settings": {
                "domainStrategy": "AsIs"
            }
        }

    logger.warning(f"未知的出口类型: {egress_info.egress_type}")
    return None


def build_chain_routing_rule(chain_tag: str, source_node: Optional[str] = None) -> Dict:
    """构建链路路由规则

    生成 Xray 路由规则，匹配链路 email 并路由到对应出站。

    Args:
        chain_tag: 链路标识
        source_node: 来源节点（可选，用于精确匹配）

    Returns:
        Xray 路由规则字典
    """
    safe_chain = re.sub(r'[^a-z0-9\-]', '', chain_tag.lower())[:32]
    outbound_tag = f"chain-egress-{safe_chain}"

    # 构建 user 匹配模式
    if source_node:
        safe_node = re.sub(r'[^a-z0-9\-]', '', source_node.lower())[:32]
        user_pattern = f"chain-{safe_chain}@{safe_node}"
    else:
        # 使用通配符匹配任意来源节点
        user_pattern = f"chain-{safe_chain}@*"

    return {
        "type": "field",
        "user": [user_pattern],
        "outboundTag": outbound_tag
    }


# 确保 SQLCIPHER_KEY 环境变量设置正确
if not os.environ.get("SQLCIPHER_KEY"):
    try:
        from key_manager import KeyManager
        key = KeyManager.get_or_create_key()
        if key:
            os.environ["SQLCIPHER_KEY"] = key
    except Exception:
        pass  # 忽略密钥获取失败，db_helper 会处理

# logging.basicConfig 配置已在模块顶部设置


def is_valid_uuid(value: str) -> bool:
    """验证 UUID 格式是否正确"""
    if not value:
        return False
    try:
        uuid_module.UUID(value, version=4)
        return True
    except (ValueError, AttributeError):
        return False


def sanitize_tag_for_email(tag: str) -> str:
    """清理 tag 用作 Xray email 字段，防止配置注入

    Email 字段用于标识客户端，只允许安全字符
    """
    if not tag:
        return "unknown"
    # 只保留字母、数字、下划线、连字符和点
    sanitized = re.sub(r'[^a-zA-Z0-9_\-.]', '_', tag)
    # 限制长度
    return sanitized[:64] if len(sanitized) > 64 else sanitized


# 配置路径
XRAY_RUN_DIR = Path("/run/xray")
XRAY_LOG_DIR = Path("/var/log")
XRAY_CONFIG_PATH = XRAY_RUN_DIR / "config.json"
XRAY_PID_FILE = XRAY_RUN_DIR / "xray.pid"

# Xray 入站 V2Ray API 端口 (gRPC StatsService)
# 用于查询 per-user 流量统计和在线检测
XRAY_INGRESS_API_PORT = 10087
GEODATA_DB_PATH = os.environ.get("GEODATA_DB_PATH", "/etc/sing-box/geoip-geodata.db")
USER_DB_PATH = os.environ.get("USER_DB_PATH", "/etc/sing-box/user-config.db")

# Peer 节点 SOCKS5 端口范围（用于连接到远程 peer）
# sing-box 通过这些 SOCKS 端口将流量路由到对应的 peer 出站
PEER_SOCKS_PORT_START = _safe_int_env("PEER_SOCKS_PORT_BASE", 37201)

# 入口链路 SOCKS5 端口范围（用于链路流量入口）
# sing-box 将链路流量路由到这些端口，Xray 添加 email 标记后转发到第一跳 peer
CHAIN_ENTRY_SOCKS_PORT_START = _safe_int_env("CHAIN_ENTRY_SOCKS_PORT_BASE", 37301)

# TUN 配置
DEFAULT_TUN_DEVICE = "xray-tun0"
DEFAULT_TUN_SUBNET = "10.24.0.0/24"
DEFAULT_TUN_ADDRESS = "10.24.0.1"

# Xray WireGuard 出站配置
# 注意: 使用不同的子网 (10.23.1.x) 避免与 wg-ingress 的 10.25.0.x 冲突
# 这是因为 Xray 的 WireGuard 会在本地创建一个 TUN 接口，该接口的 IP 会被内核
# 注册为本地地址。如果使用相同子网，响应包会被路由到 loopback 而不是 wg-ingress
XRAY_WG_PEER_NAME = "__xray_internal__"
XRAY_WG_PEER_IP = "10.23.1.200"  # 使用不同子网避免路由冲突
XRAY_WG_SUBNET = "10.23.1.0/24"  # Xray WireGuard 客户端子网
XRAY_WG_KEY_FILE = Path("/etc/sing-box/xray-wg-key.json")


def write_pid_file_atomic(pid_path: Path, pid: int) -> None:
    """
    原子写入 PID 文件，使用文件锁防止竞态条件 (H6)
    """
    pid_path.parent.mkdir(parents=True, exist_ok=True)
    lock_path = pid_path.with_suffix(".lock")

    # 获取独占锁
    with open(lock_path, 'w') as lock_file:
        fcntl.flock(lock_file.fileno(), fcntl.LOCK_EX)
        try:
            # 写入临时文件
            tmp_path = pid_path.with_suffix(".tmp")
            tmp_path.write_text(str(pid))
            # 原子重命名
            tmp_path.rename(pid_path)
        finally:
            fcntl.flock(lock_file.fileno(), fcntl.LOCK_UN)


def cleanup_stale_pid_file(pid_path: Path) -> None:
    """
    清理无效的 PID 文件 (H6: L18 修复)
    """
    if not pid_path.exists():
        return

    try:
        pid_str = pid_path.read_text().strip()
        pid = int(pid_str)
        # 检查进程是否存在
        os.kill(pid, 0)
    except (ValueError, ProcessLookupError, PermissionError):
        # PID 无效或进程不存在，清理文件
        try:
            pid_path.unlink()
            logger.debug(f"已清理无效 PID 文件: {pid_path}")
        except Exception as e:
            logger.warning(f"清理 PID 文件失败: {e}")
    except Exception as e:
        logger.warning(f"检查 PID 文件时出错: {e}")


@dataclass
class XrayProcess:
    """存储 Xray 进程信息"""
    pid: Optional[int] = None
    tun_device: str = DEFAULT_TUN_DEVICE
    tun_subnet: str = DEFAULT_TUN_SUBNET
    listen_port: int = 443
    status: str = "stopped"  # stopped, starting, running, error
    config: Dict[str, Any] = field(default_factory=dict)


class XrayManager:
    """Xray 进程管理器"""

    def __init__(self):
        self.process = XrayProcess()
        self.db = get_db(GEODATA_DB_PATH, USER_DB_PATH)
        self._running = False
        # H6: 清理可能存在的无效 PID 文件
        cleanup_stale_pid_file(XRAY_PID_FILE)

    def _get_v2ray_inbound_config(self) -> Optional[Dict]:
        """从数据库读取 V2Ray 入口配置"""
        try:
            return self.db.get_v2ray_inbound_config()
        except Exception as e:
            logger.error(f"读取 V2Ray 入口配置失败: {e}")
            return None

    def _get_v2ray_users(self) -> List[Dict]:
        """从数据库读取 V2Ray 用户列表"""
        try:
            return self.db.get_v2ray_users(enabled_only=True)
        except Exception as e:
            logger.error(f"读取 V2Ray 用户列表失败: {e}")
            return []

    def _get_peer_nodes_for_inbound(self) -> List[Dict]:
        """获取启用了入站的 peer 节点（它们的 UUID 需要加入入站配置）"""
        try:
            nodes = self.db.get_peer_nodes_with_inbound()
            return [n for n in nodes if n.get("inbound_enabled") and n.get("inbound_uuid")]
        except Exception as e:
            logger.error(f"读取 peer 节点入站配置失败: {e}")
            return []

    def _get_peer_nodes_for_outbound(self) -> List[Dict]:
        """获取需要建立出站连接的 peer 节点

        返回所有启用的 peer 节点，这些节点需要：
        1. SOCKS5 入站（供 sing-box 路由）
        2. VLESS+XHTTP+REALITY 出站（连接到远程 peer）
        """
        try:
            nodes = self.db.get_peer_nodes(enabled_only=True)
            result = []
            for n in nodes:
                # 需要有对端的 REALITY 公钥和 UUID 才能建立出站连接
                if n.get("xray_peer_reality_public_key") and n.get("xray_uuid"):
                    result.append(n)
            return result
        except Exception as e:
            logger.error(f"读取 peer 节点出站配置失败: {e}")
            return []

    def _get_chain_routing_entries(self) -> List[Dict]:
        """获取链路路由条目（用于终端节点）

        返回所有 mark_type='xray_email' 的链路路由条目。
        这些条目用于在终端节点生成 Xray 路由规则，
        将带有特定 email 标记的流量路由到本地出口。

        Returns:
            链路路由条目列表，每个包含:
            - chain_tag: 链路标识
            - mark_value: 标记值（用于计算 fwmark）
            - egress_tag: 本地出口标识
            - source_node: 来源节点（可选）
        """
        try:
            entries = self.db.get_chain_routing_list(mark_type="xray_email")
            logger.debug(f"获取到 {len(entries)} 条 xray_email 链路路由")
            return entries
        except Exception as e:
            logger.error(f"读取链路路由条目失败: {e}")
            return []

    def _get_local_node_id(self) -> str:
        """获取本地节点标识

        用于构建 email 标识的来源节点部分。
        优先使用主机名，回退时使用 machine-id。
        """
        import socket
        # 优先使用主机名
        try:
            hostname = socket.gethostname()
            if hostname and hostname != "localhost":
                # 清理主机名，只保留小写字母数字和连字符
                clean_name = re.sub(r'[^a-z0-9\-]', '', hostname.lower())[:32]
                if clean_name:
                    return clean_name
        except Exception:
            pass

        # 回退：使用 machine-id
        machine_id_path = Path("/etc/machine-id")
        if machine_id_path.exists():
            try:
                machine_id = machine_id_path.read_text().strip()
                if machine_id:
                    return f"node-{machine_id[:8]}"
            except Exception:
                pass

        # 最后回退：返回固定标识
        return "vpn-gateway"

    def _get_entry_chains(self) -> List[Dict]:
        """获取本节点作为入口的链路列表

        返回所有启用的链路，其中本节点是入口（发起方）。
        链路的 hops 数组第一个元素是下一跳节点。

        对于 xray_email 类型的链路，需要在出站配置中添加 email 字段。

        Returns:
            链路列表，每个包含:
            - tag: 链路标识
            - hops: 节点跳列表 (JSON)
            - chain_mark_type: 标记类型 ("dscp" 或 "xray_email")
            - dscp_value: DSCP/标记值
            - exit_egress: 终端节点的本地出口
        """
        try:
            # 获取所有启用的链路
            chains = self.db.get_node_chains(enabled_only=True)
            # 过滤出 xray_email 类型的链路
            xray_chains = [c for c in chains if c.get("chain_mark_type") == "xray_email"]
            logger.debug(f"获取到 {len(xray_chains)} 条 xray_email 入口链路")
            return xray_chains
        except Exception as e:
            logger.error(f"读取入口链路失败: {e}")
            return []

    def get_entry_chain_socks_ports(self) -> Dict[str, int]:
        """获取入口链路的 SOCKS 端口映射

        供 sing-box/render_singbox.py 使用，生成 SOCKS outbound 将链路流量
        路由到 Xray 的入口链路 SOCKS 入站。

        Returns:
            字典，键为链路 tag，值为 SOCKS 端口号
            例如: {"us-via-tokyo": 37301, "jp-gaming": 37302}
        """
        entry_chains = self._get_entry_chains()
        peer_outbound_nodes = self._get_peer_nodes_for_outbound()

        result = {}
        for idx, chain in enumerate(entry_chains):
            chain_tag = chain.get("tag")
            hops = chain.get("hops", [])

            if not chain_tag or not hops:
                continue

            # 验证第一跳 peer 存在
            first_hop_tag = hops[0]
            has_valid_peer = any(
                peer.get("tag") == first_hop_tag and
                peer.get("xray_peer_reality_public_key") and
                peer.get("xray_uuid")
                for peer in peer_outbound_nodes
            )

            if has_valid_peer:
                socks_port = CHAIN_ENTRY_SOCKS_PORT_START + idx
                result[chain_tag] = socks_port

        return result

    def _get_or_create_xray_wg_keypair(self) -> Dict[str, str]:
        """获取或创建 Xray 专用的 WireGuard 密钥对"""
        # 检查是否已有密钥
        if XRAY_WG_KEY_FILE.exists():
            try:
                with open(XRAY_WG_KEY_FILE, 'r') as f:
                    keys = json.load(f)
                    if keys.get("private_key") and keys.get("public_key"):
                        logger.info("使用已存在的 Xray WireGuard 密钥")
                        return keys
            except Exception as e:
                logger.warning(f"读取 Xray WireGuard 密钥失败: {e}")

        # 生成新的密钥对
        logger.info("生成新的 Xray WireGuard 密钥对")
        try:
            # 生成私钥
            result = subprocess.run(
                ["wg", "genkey"],
                capture_output=True, text=True, check=True
            )
            private_key = result.stdout.strip()

            # 从私钥生成公钥
            result = subprocess.run(
                ["wg", "pubkey"],
                input=private_key,
                capture_output=True, text=True, check=True
            )
            public_key = result.stdout.strip()

            keys = {"private_key": private_key, "public_key": public_key}

            # 保存到文件
            XRAY_WG_KEY_FILE.parent.mkdir(parents=True, exist_ok=True)
            with open(XRAY_WG_KEY_FILE, 'w') as f:
                json.dump(keys, f)
            os.chmod(XRAY_WG_KEY_FILE, 0o600)

            return keys
        except subprocess.CalledProcessError as e:
            logger.error(f"生成 WireGuard 密钥对失败: {e}")
            raise

    def _get_wg_server_public_key(self, private_key: str) -> str:
        """从私钥计算公钥"""
        try:
            result = subprocess.run(
                ["wg", "pubkey"],
                input=private_key,
                capture_output=True, text=True, check=True
            )
            return result.stdout.strip()
        except subprocess.CalledProcessError as e:
            logger.error(f"计算 WireGuard 公钥失败: {e}")
            raise

    def _ensure_xray_wg_peer(self, xray_public_key: str) -> bool:
        """确保 wg-ingress 中存在 Xray 的 peer，并配置路由"""
        try:
            # 检查是否已存在
            existing = self.db.get_wireguard_peer_by_name(XRAY_WG_PEER_NAME)
            if existing:
                # 检查公钥是否匹配
                if existing.get("public_key") == xray_public_key:
                    logger.info(f"Xray WireGuard peer 已存在: {XRAY_WG_PEER_IP}")
                else:
                    # 公钥不匹配，更新 peer
                    logger.info("更新 Xray WireGuard peer 公钥")
                    self.db.delete_wireguard_peer(existing["id"])
                    # 添加新的 peer
                    self.db.add_wireguard_peer(
                        name=XRAY_WG_PEER_NAME,
                        public_key=xray_public_key,
                        allowed_ips=f"{XRAY_WG_PEER_IP}/32"
                    )
            else:
                # 添加新的 peer
                logger.info(f"创建 Xray WireGuard peer: {XRAY_WG_PEER_NAME} ({XRAY_WG_PEER_IP})")
                self.db.add_wireguard_peer(
                    name=XRAY_WG_PEER_NAME,
                    public_key=xray_public_key,
                    allowed_ips=f"{XRAY_WG_PEER_IP}/32"
                )

            # 使用 wg set 热添加/更新 peer（无需重启 wg-ingress）
            subprocess.run(
                ["wg", "set", "wg-ingress", "peer", xray_public_key,
                 "allowed-ips", f"{XRAY_WG_PEER_IP}/32"],
                check=True
            )
            logger.info("Xray WireGuard peer 已添加到 wg-ingress")

            # 添加路由使响应包通过 wg-ingress 发送
            # 这是必须的，因为 Xray 的 WireGuard 使用不同子网 (10.23.1.x)
            self._setup_xray_wg_routes()

            return True

        except Exception as e:
            logger.error(f"确保 Xray WireGuard peer 失败: {e}")
            return False

    def _setup_xray_wg_routes(self) -> bool:
        """设置 Xray WireGuard 子网的路由和 iptables 规则"""
        try:
            # 添加路由: 10.23.1.0/24 via wg-ingress (main table)
            result = subprocess.run(
                ["ip", "route", "show", XRAY_WG_SUBNET],
                capture_output=True, text=True
            )
            if "wg-ingress" not in result.stdout:
                logger.info(f"添加路由 {XRAY_WG_SUBNET} dev wg-ingress")
                subprocess.run(
                    ["ip", "route", "add", XRAY_WG_SUBNET, "dev", "wg-ingress"],
                    check=False  # 如果已存在不报错
                )

            # 添加策略路由表 200 用于强制 Xray WireGuard 返回流量走 wg-ingress
            # 这是必要的，因为 Xray 的 WireGuard 接口会创建 local 路由，导致
            # sing-box 的 TPROXY 响应被本地投递而不是通过 wg-ingress 加密发送
            subprocess.run(
                ["ip", "route", "replace", XRAY_WG_SUBNET, "dev", "wg-ingress", "table", "200"],
                check=False
            )

            # 添加策略规则，优先级 0（与 local 表相同，但会在 local 表之后检查）
            result = subprocess.run(
                ["ip", "rule", "show", "to", XRAY_WG_SUBNET],
                capture_output=True, text=True
            )
            if "lookup 200" not in result.stdout:
                logger.info(f"添加策略路由规则: to {XRAY_WG_SUBNET} lookup 200")
                subprocess.run(
                    ["ip", "rule", "add", "to", XRAY_WG_SUBNET, "lookup", "200", "priority", "0"],
                    check=False
                )

            # 添加 iptables RETURN 规则，防止 Xray 子网内部流量被 TPROXY
            # 检查规则是否已存在
            result = subprocess.run(
                ["iptables", "-t", "mangle", "-C", "PREROUTING",
                 "-i", "wg-ingress", "-d", XRAY_WG_SUBNET, "-j", "RETURN"],
                capture_output=True
            )
            if result.returncode != 0:
                logger.info(f"添加 iptables RETURN 规则: {XRAY_WG_SUBNET}")
                subprocess.run(
                    ["iptables", "-t", "mangle", "-I", "PREROUTING", "1",
                     "-i", "wg-ingress", "-d", XRAY_WG_SUBNET, "-j", "RETURN"],
                    check=True
                )

            return True
        except Exception as e:
            logger.error(f"设置 Xray WireGuard 路由失败: {e}")
            return False

    def _fix_local_routes_for_xray_wg(self) -> bool:
        """删除 Xray WireGuard 接口的 local 路由，使响应包走 wg-ingress

        问题: Xray 的 WireGuard 出站会创建接口 (wg0, wg1, wg2) 并分配 IP 10.23.1.200，
        这导致内核在 local 路由表中创建 local 路由。当 sing-box 发送 TPROXY 响应到
        10.23.1.200 时，包会被本地投递而不是通过 wg-ingress WireGuard 加密发送。

        解决方案: 删除 local 表中的这些路由，让包走 table 200 的路由到 wg-ingress。
        """
        try:
            # 查找所有 10.23.1.200 的 local 路由
            result = subprocess.run(
                ["ip", "route", "show", "table", "local"],
                capture_output=True, text=True
            )

            for line in result.stdout.splitlines():
                if XRAY_WG_PEER_IP in line and "local" in line:
                    # 解析接口名 (如 "local 10.23.1.200 dev wg0 proto kernel scope host")
                    parts = line.split()
                    if len(parts) >= 4 and parts[3] == "dev":
                        dev = parts[4]
                        logger.info(f"删除 local 路由: {XRAY_WG_PEER_IP} dev {dev}")
                        subprocess.run(
                            ["ip", "route", "del", "local", XRAY_WG_PEER_IP, "dev", dev, "table", "local"],
                            check=False  # 忽略错误（可能已被删除）
                        )

            # 验证修复结果
            result = subprocess.run(
                ["ip", "route", "get", XRAY_WG_PEER_IP],
                capture_output=True, text=True
            )
            if "wg-ingress" in result.stdout or "table 200" in result.stdout:
                logger.info(f"Local 路由修复成功: {XRAY_WG_PEER_IP} 现在走 wg-ingress")
                return True
            else:
                logger.warning(f"Local 路由修复可能失败: {result.stdout}")
                return False

        except Exception as e:
            logger.error(f"修复 local 路由失败: {e}")
            return False

    def _generate_xray_config(
        self,
        config: Dict,
        users: List[Dict],
        peer_inbound_nodes: List[Dict] = None,
        peer_outbound_nodes: List[Dict] = None,
        chain_routing_entries: List[Dict] = None
    ) -> Dict:
        """生成 Xray 配置

        Args:
            config: V2Ray 入站配置
            users: V2Ray 用户列表
            peer_inbound_nodes: 启用入站的 peer 节点（它们的 UUID 加入 clients）
            peer_outbound_nodes: 需要出站连接的 peer 节点（生成 SOCKS 入站和 VLESS 出站）
            chain_routing_entries: 链路路由条目（终端节点使用，将 email 标记路由到本地出口）
        """
        peer_inbound_nodes = peer_inbound_nodes or []
        peer_outbound_nodes = peer_outbound_nodes or []
        chain_routing_entries = chain_routing_entries or []

        protocol = config.get("protocol", "vless")
        listen_port = config.get("listen_port", 443)
        listen_address = config.get("listen_address", "0.0.0.0")
        tun_device = config.get("tun_device", DEFAULT_TUN_DEVICE)

        # 基础配置
        # 启用 SOCKS5 UDP 转发后，DNS 由 sing-box 统一处理
        xray_config = {
            "log": {
                "loglevel": "debug",
                "access": str(XRAY_LOG_DIR / "xray-access.log"),
                "error": str(XRAY_LOG_DIR / "xray-error.log")
            },
            # 启用统计功能（用于客户端在线检测）
            "stats": {},
            # V2Ray API 用于查询 per-user 统计数据
            # listen 字段直接指定 gRPC 监听地址，无需额外的入站配置
            "api": {
                "tag": "api",
                "listen": f"127.0.0.1:{XRAY_INGRESS_API_PORT}",
                "services": ["StatsService", "HandlerService", "LoggerService"]
            },
            # 策略配置：启用入站/出站统计和 per-user 统计
            "policy": {
                "levels": {
                    "0": {
                        "statsUserUplink": True,
                        "statsUserDownlink": True
                    }
                },
                "system": {
                    "statsInboundUplink": True,
                    "statsInboundDownlink": True,
                    "statsOutboundUplink": True,
                    "statsOutboundDownlink": True
                }
            },
            # DNS 由 sing-box 处理（通过 SOCKS5 UDP 转发）
            # NOTE: API 通过 api.listen 字段直接暴露 gRPC 端口，无需额外入站
            "inbounds": [],
            "outbounds": [],
            "routing": {
                "domainStrategy": "AsIs",
                "rules": []
            }
        }

        # 构建入站配置
        inbound = {
            "tag": "v2ray-in",
            "port": listen_port,
            "listen": listen_address,
            "protocol": protocol,
            "settings": {}
        }

        # 根据协议配置用户
        if protocol == "vless":
            clients = []
            # 添加普通用户
            for user in users:
                # email 用于 V2Ray API 统计和在线检测
                # 优先使用 email，否则用 name，再否则用 "user"
                email = user.get("email") or user.get("name") or "user"
                client = {
                    "id": user.get("uuid"),
                    "email": email,
                    "level": 0  # 关联到 policy.levels.0 以启用 per-user 统计
                }
                # XTLS-Vision flow - 只在 TCP 传输时启用 (不支持 ws/grpc/h2 等)
                # 用户可以单独设置 flow 字段，即使全局 xtls_vision_enabled 未启用
                transport_type = config.get("transport_type", "tcp")
                user_flow = user.get("flow")
                if transport_type == "tcp" and (config.get("xtls_vision_enabled") or user_flow):
                    client["flow"] = user_flow or "xtls-rprx-vision"
                clients.append(client)

            # 添加 Peer 节点的 UUID（允许 peer 连接到本节点）
            for peer in peer_inbound_nodes:
                peer_uuid = peer.get("inbound_uuid")
                peer_tag = peer.get("tag", "unknown")
                # 验证 UUID 格式
                if not is_valid_uuid(peer_uuid):
                    logger.warning(f"跳过无效 peer UUID: {peer_tag}")
                    continue
                # 用 peer:tag 作为 email 标识，便于区分和统计
                sanitized_tag = sanitize_tag_for_email(peer_tag)
                client = {
                    "id": peer_uuid,
                    "email": f"peer:{sanitized_tag}",
                    "level": 0
                }
                clients.append(client)
                logger.info(f"添加 peer 入站 UUID: {peer_tag}")

            inbound["settings"] = {
                "clients": clients,
                "decryption": "none"
            }

        elif protocol == "vmess":
            # [REMOVED in Xray-lite] VMess 协议已从 Xray-lite 中移除
            raise ValueError(
                "VMess protocol is no longer supported in Xray-lite. "
                "Please migrate to VLESS protocol. See docs/VMESS_TROJAN_MIGRATION.md"
            )

        elif protocol == "trojan":
            # [REMOVED in Xray-lite] Trojan 协议已从 Xray-lite 中移除
            raise ValueError(
                "Trojan protocol is no longer supported in Xray-lite. "
                "Please migrate to VLESS protocol. See docs/VMESS_TROJAN_MIGRATION.md"
            )

        # 流设置
        transport_type = config.get("transport_type", "tcp")
        stream_settings = {
            "network": transport_type
        }

        # 传输层配置 (gRPC, WebSocket, etc.)
        transport_config_raw = config.get("transport_config")
        if transport_config_raw:
            try:
                # Handle both dict (already parsed) and string (JSON) formats
                if isinstance(transport_config_raw, dict):
                    transport_config = transport_config_raw
                else:
                    transport_config = json.loads(transport_config_raw)
                if transport_type == "grpc" and transport_config:
                    grpc_settings = {
                        "serviceName": transport_config.get("service_name", "")
                    }
                    if transport_config.get("authority"):
                        grpc_settings["authority"] = transport_config["authority"]
                    stream_settings["grpcSettings"] = grpc_settings
                elif transport_type == "ws" and transport_config:
                    stream_settings["wsSettings"] = {
                        "path": transport_config.get("path", "/"),
                        "headers": transport_config.get("headers", {})
                    }
                elif transport_type == "h2" and transport_config:
                    stream_settings["httpSettings"] = {
                        "path": transport_config.get("path", "/"),
                        "host": transport_config.get("host", [])
                    }
                elif transport_type == "quic" and transport_config:
                    stream_settings["quicSettings"] = {
                        "security": transport_config.get("security", "none"),
                        "key": transport_config.get("key", ""),
                        "header": {
                            "type": transport_config.get("header_type", "none")
                        }
                    }
                elif transport_type == "httpupgrade" and transport_config:
                    stream_settings["httpupgradeSettings"] = {
                        "path": transport_config.get("path", "/"),
                        "host": transport_config.get("host", "")
                    }
                elif transport_type == "xhttp" and transport_config:
                    xhttp_settings = {
                        "path": transport_config.get("path", "/")
                    }
                    # Mode: auto, packet-up, stream-up, stream-one
                    if transport_config.get("mode"):
                        xhttp_settings["mode"] = transport_config["mode"]
                    # Host header (optional)
                    if transport_config.get("host"):
                        xhttp_settings["host"] = transport_config["host"]
                    stream_settings["xhttpSettings"] = xhttp_settings
            except (json.JSONDecodeError, TypeError) as e:
                logger.warning(f"解析传输层配置失败: {e}")

        # REALITY 配置（优先于 TLS）
        if config.get("reality_enabled"):
            stream_settings["security"] = "reality"
            # 处理可能为 None 的 JSON 字段
            server_names_raw = config.get("reality_server_names")
            short_ids_raw = config.get("reality_short_ids")
            server_names = json.loads(server_names_raw) if server_names_raw else ["www.microsoft.com"]
            short_ids = json.loads(short_ids_raw) if short_ids_raw else [""]
            stream_settings["realitySettings"] = {
                "dest": config.get("reality_dest") or "www.microsoft.com:443",
                "serverNames": server_names,
                "privateKey": config.get("reality_private_key") or "",
                "shortIds": short_ids
            }
        elif config.get("tls_enabled"):
            stream_settings["security"] = "tls"
            tls_settings = {}

            # 证书配置
            if config.get("tls_cert_path") and config.get("tls_key_path"):
                tls_settings["certificates"] = [{
                    "certificateFile": config.get("tls_cert_path"),
                    "keyFile": config.get("tls_key_path")
                }]
            elif config.get("tls_cert_content") and config.get("tls_key_content"):
                # 将证书内容写入临时文件
                cert_path = XRAY_RUN_DIR / "server.crt"
                key_path = XRAY_RUN_DIR / "server.key"
                cert_path.write_text(config.get("tls_cert_content"))
                key_path.write_text(config.get("tls_key_content"))
                os.chmod(key_path, 0o600)
                tls_settings["certificates"] = [{
                    "certificateFile": str(cert_path),
                    "keyFile": str(key_path)
                }]

            stream_settings["tlsSettings"] = tls_settings

        inbound["streamSettings"] = stream_settings

        xray_config["inbounds"].append(inbound)

        # 出站配置
        # 检查是否启用 rust-router SOCKS5 入站
        rust_router_socks5_enabled = os.environ.get("RUST_ROUTER_SOCKS5_INBOUND", "").lower() == "true"
        XRAY_SOCKS_PORT = 38501  # rust-router 的 SOCKS5 入站端口
        
        if rust_router_socks5_enabled:
            # rust-router 模式：socks-out 作为第一个 outbound（默认出站）
            # 这样所有未匹配规则的流量都会走 rust-router 进行域名路由
            xray_config["outbounds"].append({
                "tag": "socks-out",
                "protocol": "socks",
                "settings": {
                    "servers": [{
                        "address": "127.0.0.1",
                        "port": XRAY_SOCKS_PORT
                    }]
                }
            })
            logger.info(f"Xray 配置 SOCKS5 出站: 127.0.0.1:{XRAY_SOCKS_PORT} (默认出站，rust-router 域名路由)")
            
            # freedom 作为备用出站
            xray_config["outbounds"].append({
                "tag": "freedom",
                "protocol": "freedom",
                "settings": {}
            })
        else:
            # 直连模式：freedom 作为第一个 outbound（默认出站）
            xray_config["outbounds"].append({
                "tag": "freedom",
                "protocol": "freedom",
                "settings": {}
            })
            
            # SOCKS5 作为备用出站
            xray_config["outbounds"].append({
                "tag": "socks-out",
                "protocol": "socks",
                "settings": {
                    "servers": [{
                        "address": "127.0.0.1",
                        "port": XRAY_SOCKS_PORT
                    }]
                }
            })
            logger.info(f"Xray 配置 SOCKS5 出站: 127.0.0.1:{XRAY_SOCKS_PORT} (备用)")

        # ============ Peer 节点出站配置 ============
        # 为每个需要连接的 peer 节点创建:
        # 1. SOCKS5 入站 - 供 sing-box 路由流量到此 peer
        # 2. VLESS+XHTTP+REALITY 出站 - 连接到远程 peer
        # 3. 路由规则 - 将 SOCKS 入站流量路由到对应出站

        for idx, peer in enumerate(peer_outbound_nodes):
            peer_tag = peer.get("tag")
            if not peer_tag:
                continue

            # 分配 SOCKS 端口 (37201, 37202, ...)
            # 使用数据库中分配的端口，如果没有则按索引分配
            socks_port = peer.get("xray_socks_port") or (PEER_SOCKS_PORT_START + idx)

            # 解析 endpoint 获取服务器地址和端口
            endpoint = peer.get("endpoint", "")
            if ":" in endpoint:
                server_host = endpoint.rsplit(":", 1)[0]
                try:
                    server_port = int(endpoint.rsplit(":", 1)[1])
                except ValueError:
                    server_port = 443
            else:
                server_host = endpoint
                server_port = 443

            # 获取对端的 REALITY 配置
            peer_reality_public_key = peer.get("xray_peer_reality_public_key")
            peer_reality_short_id = peer.get("xray_peer_reality_short_id", "")
            peer_uuid = peer.get("xray_uuid")

            # 解析 server names
            server_names_raw = peer.get("xray_peer_reality_server_names", '["www.microsoft.com"]')
            try:
                server_names = json.loads(server_names_raw) if isinstance(server_names_raw, str) else server_names_raw
            except (json.JSONDecodeError, TypeError):
                server_names = ["www.microsoft.com"]
            reality_server_name = server_names[0] if server_names else "www.microsoft.com"

            # XHTTP 配置
            xhttp_path = peer.get("xray_xhttp_path", "/")
            xhttp_mode = peer.get("xray_xhttp_mode", "auto")

            if not all([server_host, peer_reality_public_key, peer_uuid]):
                logger.warning(f"Peer {peer_tag} 配置不完整，跳过")
                continue

            # 验证 UUID 格式
            if not is_valid_uuid(peer_uuid):
                logger.warning(f"Peer {peer_tag} UUID 格式无效，跳过")
                continue

            # 清理 tag 用于 Xray 配置标识
            sanitized_tag = sanitize_tag_for_email(peer_tag)

            # 1. 添加 SOCKS5 入站（供 sing-box 路由流量）
            socks_inbound = {
                "tag": f"socks-in-{sanitized_tag}",
                "port": socks_port,
                "listen": "127.0.0.1",
                "protocol": "socks",
                "settings": {
                    "auth": "noauth",
                    "udp": True
                }
            }
            xray_config["inbounds"].append(socks_inbound)

            # 2. 添加 VLESS+XHTTP+REALITY 出站（连接到远程 peer）
            xhttp_settings: Dict[str, Any] = {
                "path": xhttp_path,
                "mode": xhttp_mode
            }

            peer_outbound = {
                "tag": f"peer-{sanitized_tag}",
                "protocol": "vless",
                "settings": {
                    "vnext": [{
                        "address": server_host,
                        "port": server_port,
                        "users": [{
                            "id": peer_uuid,
                            "encryption": "none"
                        }]
                    }]
                },
                "streamSettings": {
                    "network": "xhttp",
                    "xhttpSettings": xhttp_settings,
                    "security": "reality",
                    "realitySettings": {
                        "serverName": reality_server_name,
                        "fingerprint": "chrome",
                        "publicKey": peer_reality_public_key,
                        "shortId": peer_reality_short_id
                    }
                }
            }
            xray_config["outbounds"].append(peer_outbound)

            # 3. 添加路由规则（SOCKS 入站 → peer 出站）
            peer_route = {
                "type": "field",
                "inboundTag": [f"socks-in-{sanitized_tag}"],
                "outboundTag": f"peer-{sanitized_tag}"
            }
            xray_config["routing"]["rules"].append(peer_route)

            logger.info(f"添加 peer 出站配置: {peer_tag} -> {server_host}:{server_port} (SOCKS:{socks_port})")

        # ============ 链路路由配置（终端节点） ============
        # 为每个 xray_email 类型的链路路由条目创建:
        # 1. 出站（freedom with mark 或 SOCKS）
        # 2. 路由规则（匹配 email → 对应出站）
        chain_count = 0
        for entry in chain_routing_entries:
            chain_tag = entry.get("chain_tag")
            mark_value = entry.get("mark_value")
            egress_tag = entry.get("egress_tag")
            source_node = entry.get("source_node")

            if not all([chain_tag, mark_value is not None, egress_tag]):
                logger.warning(f"链路路由条目不完整，跳过: {entry}")
                continue

            # 获取出口信息
            egress_info = get_chain_egress_info(self.db, egress_tag, mark_value)
            if not egress_info:
                logger.warning(f"无法获取出口信息: {egress_tag}，跳过链路 {chain_tag}")
                continue

            # 生成出站配置
            outbound = build_chain_routing_outbound(egress_info, chain_tag)
            if not outbound:
                logger.warning(f"无法生成出站配置: {chain_tag} -> {egress_tag}")
                continue

            # 检查是否已存在同名出站
            existing_tags = [o.get("tag") for o in xray_config["outbounds"]]
            if outbound["tag"] not in existing_tags:
                xray_config["outbounds"].append(outbound)
            else:
                logger.debug(f"出站已存在，跳过添加: {outbound['tag']}")

            # 生成路由规则
            rule = build_chain_routing_rule(chain_tag, source_node)
            xray_config["routing"]["rules"].append(rule)

            logger.info(
                f"添加链路路由: {chain_tag} (mark={mark_value}) -> "
                f"{egress_tag} ({egress_info.egress_type})"
            )
            chain_count += 1

        if chain_count > 0:
            logger.info(f"共添加 {chain_count} 条链路路由规则")

        # ============ 入口链路配置（入口节点） ============
        # 当本节点是链路的入口节点时，需要为每个链路创建:
        # 1. SOCKS5 入站 - 供 sing-box 路由流量到此链路
        # 2. VLESS 出站 - 连接到第一跳 peer，带有 email 字段标识链路
        # 3. 路由规则 - 将 SOCKS 入站流量路由到对应出站
        entry_chains = self._get_entry_chains()
        local_node_id = self._get_local_node_id()
        entry_count = 0

        for idx, chain in enumerate(entry_chains):
            chain_tag = chain.get("tag")
            hops = chain.get("hops", [])

            if not chain_tag or not hops:
                logger.warning(f"链路 {chain_tag} 配置不完整，跳过")
                continue

            # 获取第一跳 peer 节点
            first_hop_tag = hops[0]

            # 从 peer 出站节点中查找对应的配置
            first_hop_peer = None
            for peer in peer_outbound_nodes:
                if peer.get("tag") == first_hop_tag:
                    first_hop_peer = peer
                    break

            if not first_hop_peer:
                logger.warning(f"链路 {chain_tag} 的第一跳 {first_hop_tag} 未找到有效的 peer 出站配置")
                continue

            # 获取 peer 连接详情
            endpoint = first_hop_peer.get("endpoint", "")
            if ":" in endpoint:
                server_host = endpoint.rsplit(":", 1)[0]
                try:
                    server_port = int(endpoint.rsplit(":", 1)[1])
                except ValueError:
                    server_port = 443
            else:
                server_host = endpoint
                server_port = 443

            peer_reality_public_key = first_hop_peer.get("xray_peer_reality_public_key")
            peer_reality_short_id = first_hop_peer.get("xray_peer_reality_short_id", "")
            peer_uuid = first_hop_peer.get("xray_uuid")

            # 解析 server names
            server_names_raw = first_hop_peer.get("xray_peer_reality_server_names", '["www.microsoft.com"]')
            try:
                server_names = json.loads(server_names_raw) if isinstance(server_names_raw, str) else server_names_raw
            except (json.JSONDecodeError, TypeError):
                server_names = ["www.microsoft.com"]
            reality_server_name = server_names[0] if server_names else "www.microsoft.com"

            # XHTTP 配置
            xhttp_path = first_hop_peer.get("xray_xhttp_path", "/")
            xhttp_mode = first_hop_peer.get("xray_xhttp_mode", "auto")

            if not all([server_host, peer_reality_public_key, peer_uuid]):
                logger.warning(f"链路 {chain_tag} 的第一跳 {first_hop_tag} 配置不完整")
                continue

            # 验证 UUID 格式
            if not is_valid_uuid(peer_uuid):
                logger.warning(f"链路 {chain_tag} 的第一跳 {first_hop_tag} UUID 格式无效")
                continue

            # 分配 SOCKS 端口 (37301, 37302, ...)
            socks_port = CHAIN_ENTRY_SOCKS_PORT_START + idx

            # 清理标识符
            safe_chain = re.sub(r'[^a-z0-9\-]', '', chain_tag.lower())[:32]

            # 构建 email 标识（用于链路流量识别）
            chain_email = build_chain_email(chain_tag, local_node_id)

            # 1. 添加 SOCKS5 入站（供 sing-box 路由流量）
            socks_inbound = {
                "tag": f"chain-in-{safe_chain}",
                "port": socks_port,
                "listen": "127.0.0.1",
                "protocol": "socks",
                "settings": {
                    "auth": "noauth",
                    "udp": True
                }
            }
            xray_config["inbounds"].append(socks_inbound)

            # 2. 添加 VLESS+XHTTP+REALITY 出站（带 email 标识）
            xhttp_settings: Dict[str, Any] = {
                "path": xhttp_path,
                "mode": xhttp_mode
            }

            chain_outbound = {
                "tag": f"chain-out-{safe_chain}",
                "protocol": "vless",
                "settings": {
                    "vnext": [{
                        "address": server_host,
                        "port": server_port,
                        "users": [{
                            "id": peer_uuid,
                            "encryption": "none",
                            "email": chain_email  # 链路标识
                        }]
                    }]
                },
                "streamSettings": {
                    "network": "xhttp",
                    "xhttpSettings": xhttp_settings,
                    "security": "reality",
                    "realitySettings": {
                        "serverName": reality_server_name,
                        "fingerprint": "chrome",
                        "publicKey": peer_reality_public_key,
                        "shortId": peer_reality_short_id
                    }
                }
            }
            xray_config["outbounds"].append(chain_outbound)

            # 3. 添加路由规则（SOCKS 入站 → 链路出站）
            chain_route = {
                "type": "field",
                "inboundTag": [f"chain-in-{safe_chain}"],
                "outboundTag": f"chain-out-{safe_chain}"
            }
            xray_config["routing"]["rules"].append(chain_route)

            logger.info(
                f"添加入口链路配置: {chain_tag} -> {first_hop_tag} "
                f"(SOCKS:{socks_port}, email:{chain_email})"
            )
            entry_count += 1

        if entry_count > 0:
            logger.info(f"共添加 {entry_count} 条入口链路配置")

        # v2ray-in 的路由通过默认 outbound 处理（第一个 outbound）
        # 如果启用了 rust-router，socks-out 是第一个 outbound
        # 否则 freedom 是第一个 outbound
        # 不需要显式添加 inboundTag 路由规则，因为 Xray 存在 inboundTag 匹配问题

        return xray_config

    def _setup_tun_device(self, tun_device: str, tun_subnet: str) -> bool:
        """创建并配置 TUN 设备"""
        try:
            # 解析子网获取设备地址
            import ipaddress
            network = ipaddress.ip_network(tun_subnet, strict=False)
            tun_address = str(list(network.hosts())[0])  # 使用子网的第一个可用 IP

            # 检查设备是否已存在
            result = subprocess.run(
                ["ip", "link", "show", tun_device],
                capture_output=True, text=True
            )

            if result.returncode != 0:
                # 创建 TUN 设备
                logger.info(f"创建 TUN 设备 {tun_device}")
                subprocess.run(
                    ["ip", "tuntap", "add", "mode", "tun", "dev", tun_device],
                    check=True
                )

            # 配置 IP 地址
            # 先删除现有地址
            subprocess.run(
                ["ip", "addr", "flush", "dev", tun_device],
                capture_output=True
            )

            # 添加地址
            prefix_len = network.prefixlen
            subprocess.run(
                ["ip", "addr", "add", f"{tun_address}/{prefix_len}", "dev", tun_device],
                check=True
            )

            # 启用设备
            subprocess.run(
                ["ip", "link", "set", tun_device, "up"],
                check=True
            )

            logger.info(f"TUN 设备 {tun_device} 已配置: {tun_address}/{prefix_len}")
            return True

        except subprocess.CalledProcessError as e:
            logger.error(f"配置 TUN 设备失败: {e}")
            return False
        except Exception as e:
            logger.error(f"TUN 设备配置错误: {e}")
            return False

    def _cleanup_tun_device(self, tun_device: str):
        """清理 TUN 设备"""
        try:
            subprocess.run(
                ["ip", "link", "del", tun_device],
                capture_output=True
            )
            logger.info(f"已删除 TUN 设备 {tun_device}")
        except Exception as e:
            logger.debug(f"删除 TUN 设备时出错: {e}")

    async def start(self) -> bool:
        """启动 Xray"""
        config = self._get_v2ray_inbound_config()
        if not config:
            logger.error("V2Ray 入口配置不存在")
            return False

        if not config.get("enabled"):
            logger.info("V2Ray 入口已禁用")
            return False

        # 检查是否已有进程在运行
        if self._is_process_alive():
            existing_pid = self.process.pid or self._read_pid_from_file()
            logger.info(f"Xray 已在运行 (PID: {existing_pid})，先停止现有进程")
            await self.stop()

        users = self._get_v2ray_users()
        if not users:
            logger.warning("没有启用的 V2Ray 用户")
            # 继续启动，但警告无用户

        # 加载 peer 节点配置
        peer_inbound_nodes = self._get_peer_nodes_for_inbound()
        peer_outbound_nodes = self._get_peer_nodes_for_outbound()
        chain_routing_entries = self._get_chain_routing_entries()
        logger.info(f"Peer 节点: {len(peer_inbound_nodes)} 入站, {len(peer_outbound_nodes)} 出站")
        if chain_routing_entries:
            logger.info(f"链路路由: {len(chain_routing_entries)} 条 (xray_email)")

        logger.info("启动 Xray...")
        self.process.status = "starting"

        # 创建运行目录
        XRAY_RUN_DIR.mkdir(parents=True, exist_ok=True)

        # 配置 TUN 设备
        tun_device = config.get("tun_device", DEFAULT_TUN_DEVICE)
        tun_subnet = config.get("tun_subnet", DEFAULT_TUN_SUBNET)
        self.process.tun_device = tun_device
        self.process.tun_subnet = tun_subnet
        self.process.listen_port = config.get("listen_port", 443)

        if not self._setup_tun_device(tun_device, tun_subnet):
            self.process.status = "error"
            return False

        # 生成配置（包含客户端用户、peer 节点和链路路由）
        try:
            xray_config = self._generate_xray_config(
                config, users, peer_inbound_nodes, peer_outbound_nodes,
                chain_routing_entries
            )
            XRAY_CONFIG_PATH.write_text(json.dumps(xray_config, indent=2))
            self.process.config = xray_config
            logger.info(f"Xray 配置已生成: {XRAY_CONFIG_PATH}")
        except Exception as e:
            logger.error(f"生成 Xray 配置失败: {e}")
            self.process.status = "error"
            return False

        # 启动 Xray 进程
        try:
            proc = subprocess.Popen(
                ["xray", "run", "-c", str(XRAY_CONFIG_PATH)],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL
            )
            self.process.pid = proc.pid
            logger.info(f"Xray 已启动 (PID: {proc.pid}, 端口: {self.process.listen_port})")
        except Exception as e:
            logger.error(f"启动 Xray 失败: {e}")
            self.process.status = "error"
            return False

        # 等待进程稳定
        await asyncio.sleep(1)

        # 检查进程是否仍在运行
        if self._is_process_alive():
            self.process.status = "running"
            # 写入 PID 文件 (H6: 使用原子写入)
            try:
                write_pid_file_atomic(XRAY_PID_FILE, self.process.pid)
                logger.debug(f"PID 文件已写入: {XRAY_PID_FILE}")
            except Exception as e:
                logger.warning(f"写入 PID 文件失败: {e}")

            logger.info("Xray 启动成功")
            return True
        else:
            self.process.status = "error"
            logger.error("Xray 启动后立即退出")
            return False

    async def stop(self) -> bool:
        """停止 Xray"""
        logger.info("停止 Xray...")

        # 获取 PID（优先使用实例变量，否则从文件读取）
        pid = self.process.pid or self._read_pid_from_file()

        # 停止 Xray 进程
        if pid:
            try:
                os.kill(pid, signal.SIGTERM)
                logger.debug(f"已发送 SIGTERM 到 Xray (PID: {pid})")

                # 等待进程退出
                for _ in range(10):
                    try:
                        os.kill(pid, 0)
                        await asyncio.sleep(0.5)
                    except ProcessLookupError:
                        break
                else:
                    # 强制杀死
                    try:
                        os.kill(pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
            except ProcessLookupError:
                pass

        self.process.pid = None

        # 清理 TUN 设备（从实例变量或数据库配置获取设备名）
        tun_device = self.process.tun_device
        if not tun_device:
            config = self._get_v2ray_inbound_config()
            if config:
                tun_device = config.get("tun_device", DEFAULT_TUN_DEVICE)
        if tun_device:
            self._cleanup_tun_device(tun_device)

        # 清理配置文件
        if XRAY_CONFIG_PATH.exists():
            XRAY_CONFIG_PATH.unlink()

        # 删除 PID 文件
        if XRAY_PID_FILE.exists():
            try:
                XRAY_PID_FILE.unlink()
            except Exception as e:
                logger.warning(f"删除 PID 文件失败: {e}")

        self.process.status = "stopped"
        logger.info("Xray 已停止")
        return True

    async def reload(self) -> bool:
        """重载配置"""
        logger.info("重载 Xray 配置...")

        # 读取新配置
        config = self._get_v2ray_inbound_config()
        if not config or not config.get("enabled"):
            # 配置已禁用，停止 Xray
            if self._is_process_alive():
                await self.stop()
            return True

        users = self._get_v2ray_users()

        # 加载 peer 节点配置
        peer_inbound_nodes = self._get_peer_nodes_for_inbound()
        peer_outbound_nodes = self._get_peer_nodes_for_outbound()
        chain_routing_entries = self._get_chain_routing_entries()
        logger.info(f"Peer 节点: {len(peer_inbound_nodes)} 入站, {len(peer_outbound_nodes)} 出站")
        if chain_routing_entries:
            logger.info(f"链路路由: {len(chain_routing_entries)} 条 (xray_email)")

        # 生成新配置（包含客户端用户、peer 节点和链路路由）
        try:
            xray_config = self._generate_xray_config(
                config, users, peer_inbound_nodes, peer_outbound_nodes,
                chain_routing_entries
            )
            XRAY_CONFIG_PATH.write_text(json.dumps(xray_config, indent=2))
            self.process.config = xray_config
        except Exception as e:
            logger.error(f"生成 Xray 配置失败: {e}")
            return False

        # 如果进程不在运行，启动它
        if not self._is_process_alive():
            return await self.start()

        # 发送 SIGHUP 重载配置
        # 注意：Xray 可能不支持 SIGHUP 热重载，需要重启
        logger.info("重启 Xray 以应用新配置")
        await self.stop()
        return await self.start()

    def _read_pid_from_file(self) -> Optional[int]:
        """从 PID 文件读取 PID"""
        if XRAY_PID_FILE.exists():
            try:
                pid_str = XRAY_PID_FILE.read_text().strip()
                return int(pid_str)
            except (ValueError, IOError):
                pass
        return None

    def _is_process_alive(self) -> bool:
        """检查 Xray 进程是否存活"""
        pid = self.process.pid or self._read_pid_from_file()
        if not pid:
            return False
        try:
            os.kill(pid, 0)
            return True
        except ProcessLookupError:
            return False

    def get_status(self) -> Dict:
        """获取状态信息"""
        alive = self._is_process_alive()
        pid = self.process.pid or self._read_pid_from_file()

        if alive:
            status = "running"
        elif self.process.status == "starting":
            status = "starting"
        elif self.process.status == "error":
            status = "error"
        else:
            status = "stopped"

        return {
            "status": status,
            "pid": pid if alive else None,
            "tun_device": self.process.tun_device,
            "tun_subnet": self.process.tun_subnet,
            "listen_port": self.process.listen_port
        }

    async def run_daemon(self):
        """以守护进程模式运行 - 带重试和指数退避

        Phase 10.5: 实现健康检查循环和指数退避重启策略
        - 初始启动最多重试 3 次（5s, 10s, 15s 间隔）
        - 运行时崩溃使用指数退避重启（最大 5 分钟）
        - 成功启动后重置重启计数
        """
        self._running = True
        logger.info("Xray 管理器启动（守护模式）")

        # 初始启动（最多重试 3 次）
        max_retries = 3
        startup_success = False
        for attempt in range(max_retries):
            if await self.start():
                startup_success = True
                break
            logger.warning(f"Xray 启动失败，重试 {attempt + 1}/{max_retries}")
            await asyncio.sleep(5 * (attempt + 1))  # 5s, 10s, 15s

        if not startup_success:
            logger.error(f"Xray 启动失败，已尝试 {max_retries} 次")
            # 继续监控循环，等待配置变更

        # 健康检查循环（带指数退避）
        restart_count = 0
        while self._running:
            await asyncio.sleep(10)

            # 检查进程健康
            if self.process.status == "running" and not self._is_process_alive():
                restart_count += 1
                # 指数退避：10s, 20s, 40s, 80s, 160s, 最大 300s (5分钟)
                delay = min(10 * (2 ** restart_count), 300)
                logger.warning(f"Xray 进程退出，{delay}s 后重启 (第 {restart_count} 次重试)")
                await asyncio.sleep(delay)

                if await self.start():
                    restart_count = 0  # 成功后重置计数
                    logger.info("Xray 重启成功，重试计数已重置")
                else:
                    logger.error(f"Xray 重启失败 (第 {restart_count} 次)")

        # 清理
        await self.stop()
        logger.info("Xray 管理器已停止")

    def stop_daemon(self):
        """停止守护进程"""
        self._running = False


def should_xray_run(db) -> bool:
    """判断是否需要运行 Xray 进程

    Phase 10.5: Xray 应该在以下情况运行：
    1. 有启用的 V2Ray 用户（V2Ray Ingress 功能）
    2. 有启用了 inbound 的 peer 节点（Peer Inbound 功能）

    Args:
        db: DatabaseManager 实例

    Returns:
        True 如果需要运行 Xray，否则 False
    """
    try:
        # 检查 V2Ray 入口配置是否启用
        v2ray_config = db.get_v2ray_inbound_config()
        if not v2ray_config or not v2ray_config.get("enabled"):
            logger.debug("V2Ray 入口未启用")
            return False

        # 检查是否有启用的 V2Ray 用户
        v2ray_users = db.get_v2ray_users(enabled_only=True)
        if v2ray_users:
            logger.debug(f"发现 {len(v2ray_users)} 个启用的 V2Ray 用户")
            return True

        # 检查是否有启用 inbound 的 peer 节点
        try:
            peers = db.get_peer_nodes_with_inbound()
            inbound_enabled_peers = [p for p in peers if p.get("inbound_enabled") and p.get("inbound_uuid")]
            if inbound_enabled_peers:
                logger.debug(f"发现 {len(inbound_enabled_peers)} 个启用 inbound 的 peer 节点")
                return True
        except Exception as e:
            logger.debug(f"检查 peer 节点时出错: {e}")

        logger.debug("无需运行 Xray: 没有 V2Ray 用户或启用 inbound 的 peer")
        return False

    except Exception as e:
        logger.error(f"检查 Xray 运行需求时出错: {e}")
        return False


def is_xray_running() -> bool:
    """检查 Xray 进程是否正在运行

    Returns:
        True 如果 Xray 进程存活，否则 False
    """
    if not XRAY_PID_FILE.exists():
        return False

    try:
        pid_str = XRAY_PID_FILE.read_text().strip()
        pid = int(pid_str)
        os.kill(pid, 0)  # 检查进程是否存在
        return True
    except (ValueError, ProcessLookupError, PermissionError, IOError):
        return False


async def ensure_xray_state(db) -> bool:
    """确保 Xray 进程状态正确

    Phase 10.5: 根据当前配置自动启停 Xray：
    - 如果需要运行但未运行 → 启动
    - 如果不需要运行但在运行 → 停止

    Args:
        db: DatabaseManager 实例

    Returns:
        True 如果操作成功（包括无需操作的情况），否则 False
    """
    should_run = should_xray_run(db)
    running = is_xray_running()

    if should_run and not running:
        logger.info("Xray 需要运行但未运行，正在启动...")
        manager = XrayManager()
        return await manager.start()
    elif not should_run and running:
        logger.info("Xray 不需要运行但在运行，正在停止...")
        manager = XrayManager()
        return await manager.stop()
    else:
        status = "运行中" if running else "已停止"
        logger.debug(f"Xray 状态正确: {status}")
        return True


def ensure_xray_state_sync(db) -> bool:
    """同步版本的 ensure_xray_state

    供非异步代码调用（如 API 端点的同步部分）。

    注意: 如果在异步上下文中调用，会在新线程中运行以避免事件循环嵌套。

    Args:
        db: DatabaseManager 实例

    Returns:
        True 如果操作成功，否则 False
    """
    import asyncio
    import concurrent.futures

    try:
        # 检查是否已有运行中的事件循环
        try:
            asyncio.get_running_loop()
            # 在异步上下文中，使用线程池避免嵌套事件循环
            with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
                future = executor.submit(asyncio.run, ensure_xray_state(db))
                return future.result(timeout=30)
        except RuntimeError:
            # 没有运行中的事件循环，直接运行
            return asyncio.run(ensure_xray_state(db))
    except concurrent.futures.TimeoutError:
        logger.error("ensure_xray_state_sync 超时 (30s)")
        return False
    except Exception as e:
        logger.error(f"ensure_xray_state_sync 失败: {e}")
        return False


def get_xray_chain_entry_ports(db) -> Dict[str, int]:
    """获取 Xray 链路入口的 SOCKS 端口映射（模块级函数）

    供 render_singbox.py 调用，生成 sing-box SOCKS outbound 配置。
    sing-box 将链路流量路由到 Xray 的入口链路 SOCKS 入站。

    Args:
        db: DatabaseManager 实例

    Returns:
        字典，键为链路 tag，值为 SOCKS 端口号
        例如: {"us-via-tokyo": 37301, "jp-gaming": 37302}
    """
    try:
        # 获取所有启用的 xray_email 类型链路
        chains = db.get_node_chains(enabled_only=True)
        xray_chains = [c for c in chains if c.get("chain_mark_type") == "xray_email"]

        # 获取有效的 peer 出站节点
        peer_nodes = db.get_peer_nodes(enabled_only=True)
        valid_peer_tags = set()
        for p in peer_nodes:
            if p.get("xray_peer_reality_public_key") and p.get("xray_uuid"):
                valid_peer_tags.add(p.get("tag"))

        result = {}
        for idx, chain in enumerate(xray_chains):
            chain_tag = chain.get("tag")
            hops = chain.get("hops", [])

            if not chain_tag or not hops:
                continue

            # 验证第一跳 peer 存在
            first_hop_tag = hops[0]
            if first_hop_tag in valid_peer_tags:
                socks_port = CHAIN_ENTRY_SOCKS_PORT_START + idx
                result[chain_tag] = socks_port

        return result
    except Exception as e:
        logger.warning(f"获取链路入口端口失败: {e}")
        return {}


def generate_reality_keys() -> Dict[str, str]:
    """生成 REALITY 密钥对"""
    try:
        # 使用 xray x25519 命令生成密钥对
        result = subprocess.run(
            ["xray", "x25519"],
            capture_output=True,
            text=True,
            check=True
        )

        output = result.stdout.strip()
        lines = output.split('\n')

        private_key = ""
        public_key = ""

        for line in lines:
            # 新版 Xray 格式: PrivateKey: xxx / Password: xxx (public key)
            # 旧版 Xray 格式: Private key: xxx / Public key: xxx
            line_lower = line.lower()
            if line_lower.startswith("privatekey:") or line_lower.startswith("private key:"):
                private_key = line.split(":", 1)[1].strip()
            elif line_lower.startswith("password:") or line_lower.startswith("public key:"):
                # 新版 Xray 称 public key 为 "Password"
                public_key = line.split(":", 1)[1].strip()

        if private_key and public_key:
            return {
                "private_key": private_key,
                "public_key": public_key
            }
        else:
            logger.error(f"xray x25519 输出解析失败，原始输出: {output}")
            raise ValueError(f"无法解析 xray x25519 输出: {output}")

    except subprocess.CalledProcessError as e:
        logger.error(f"生成 REALITY 密钥失败: {e}")
        raise
    except FileNotFoundError:
        logger.error("xray 命令未找到")
        raise


def generate_short_id() -> str:
    """生成 REALITY Short ID（8字节十六进制字符串）"""
    return secrets.token_hex(8)


async def main():
    parser = argparse.ArgumentParser(description='Xray 进程管理器')
    parser.add_argument('command', choices=['start', 'stop', 'reload', 'status', 'daemon', 'generate-keys'],
                        help='操作命令')
    parser.add_argument('--verbose', '-v', action='store_true', help='详细输出')
    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    if args.command == 'generate-keys':
        try:
            keys = generate_reality_keys()
            short_id = generate_short_id()
            print(json.dumps({
                "private_key": keys["private_key"],
                "public_key": keys["public_key"],
                "short_id": short_id
            }, indent=2))
        except Exception as e:
            print(json.dumps({"error": str(e)}), file=sys.stderr)
            sys.exit(1)
        return

    manager = XrayManager()

    if args.command == 'start':
        success = await manager.start()
        sys.exit(0 if success else 1)

    elif args.command == 'stop':
        success = await manager.stop()
        sys.exit(0 if success else 1)

    elif args.command == 'reload':
        success = await manager.reload()
        sys.exit(0 if success else 1)

    elif args.command == 'status':
        status = manager.get_status()
        print(json.dumps(status, indent=2, ensure_ascii=False))

    elif args.command == 'daemon':
        # 设置信号处理
        loop = asyncio.get_event_loop()

        def signal_handler():
            logger.info("收到停止信号")
            manager.stop_daemon()

        for sig in (signal.SIGTERM, signal.SIGINT):
            loop.add_signal_handler(sig, signal_handler)

        await manager.run_daemon()


if __name__ == '__main__':
    asyncio.run(main())

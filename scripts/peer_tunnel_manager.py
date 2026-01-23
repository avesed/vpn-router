#!/usr/bin/env python3
"""
对等节点隧道管理器

.. deprecated::
    此模块已弃用。rust-router 现在在用户空间管理对等节点隧道。
    
    - 在 userspace WireGuard 模式下，此管理器不再启动
    - 对等节点隧道通过 rust-router IPC 管理
    - 参见 rust-router/src/ingress/manager.rs
    
    保留此文件仅用于向后兼容和参考。entrypoint.sh 中已跳过此管理器的启动。

原始功能说明（已废弃）：
管理节点间的 WireGuard 和 Xray 隧道连接，支持：
- 从数据库读取节点配置
- 建立和维护点对点隧道
- 自动重连机制
- 隧道状态监控

WireGuard 隧道创建 wg-peer-{tag} 接口（内核模式，已废弃），
Xray 隧道使用 SOCKS5 代理桥接。

使用方法（已废弃）:
    python3 peer_tunnel_manager.py start      # 启动所有启用的隧道
    python3 peer_tunnel_manager.py stop       # 停止所有隧道
    python3 peer_tunnel_manager.py reload     # 重载配置
    python3 peer_tunnel_manager.py status     # 显示所有隧道状态
    python3 peer_tunnel_manager.py connect    # 连接指定节点
    python3 peer_tunnel_manager.py disconnect # 断开指定节点
"""

import argparse
import fcntl
import hashlib
import json
import logging
import os
import re
import signal
import subprocess
import sys
import tempfile
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime
from ipaddress import ip_address
from pathlib import Path
from typing import Any, Dict, List, Optional

import requests

# [安全] 主机名验证正则（RFC 1123 规范）
HOSTNAME_PATTERN = re.compile(
    r'^(?=.{1,253}$)'  # 总长度限制
    r'(?!-)'  # 不以连字符开头
    r'[a-zA-Z0-9]'  # 首字符必须是字母或数字
    r'([a-zA-Z0-9\-\.]*[a-zA-Z0-9])?$'  # 中间可含连字符和点，末尾不能是连字符
)

# 添加脚本目录到 Python 路径
sys.path.insert(0, str(Path(__file__).parent))

from db_helper import get_db

# 配置日志（统一日志配置，通过 LOG_LEVEL 环境变量控制）
try:
    from log_config import setup_logging, get_logger
    setup_logging()
    logger = get_logger(__name__)
except ImportError:
    _log_level = os.environ.get("LOG_LEVEL", "INFO").upper()
    logging.basicConfig(
        level=getattr(logging, _log_level, logging.INFO),
        format='[peer-tunnel] %(asctime)s %(levelname)s: %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    logger = logging.getLogger(__name__)

# 配置路径
PEER_RUN_DIR = Path("/run/peer-tunnels")
PEER_LOG_DIR = Path("/var/log/peer-tunnels")
PEER_PID_FILE = Path("/run/peer-tunnel-manager.pid")
GEODATA_DB_PATH = os.environ.get("GEODATA_DB_PATH", "/etc/sing-box/geoip-geodata.db")
USER_DB_PATH = os.environ.get("USER_DB_PATH", "/etc/sing-box/user-config.db")
SQLCIPHER_KEY = os.environ.get("SQLCIPHER_KEY")

# 隧道 IP 子网
PEER_TUNNEL_SUBNET = "10.200.200"

# ============ 端口分配说明 ============
#
# 端口用途表（可通过环境变量配置）:
#   WEB_PORT (36000)              Web UI + API（nginx）
#   WG_LISTEN_PORT (36100)        WireGuard 客户端入口
#   PEER_TUNNEL_PORT_MIN-MAX (36200-36299)   Peer 节点 WireGuard 隧道
#   V2RAY_SOCKS_PORT_BASE (37101+) V2Ray 出口 SOCKS 桥接端口
#   PEER_XRAY_SOCKS_PORT_START (37201+) Peer 节点 Xray SOCKS 端口
#   WARP_MASQUE_PORT_BASE (38001+) WARP MASQUE SOCKS 端口
#   38501                          Xray 入口到 sing-box SOCKS 桥接
#   SPEEDTEST_PORT_BASE (39001+)   速度测试专用 SOCKS 端口
#
# 重要：创建 peer 时 endpoint 应指向远程节点的 peer WireGuard 端口（而非 WG_LISTEN_PORT）
# 例如：10.1.100.12:36200 而非 10.1.100.12:36100
#
# ============================================

# Peer tunnel port range (must match db_helper.py and CLAUDE.md)
# Valid range: 36200-36299 (100 ports for peer tunnels)
PEER_TUNNEL_PORT_MIN = int(os.environ.get("PEER_TUNNEL_PORT_MIN", "36200"))
PEER_TUNNEL_PORT_MAX = int(os.environ.get("PEER_TUNNEL_PORT_MAX", "36299"))
PEER_XRAY_SOCKS_PORT_START = int(os.environ.get("PEER_XRAY_SOCKS_PORT_START", "37201"))

# Peer tunnel routing table range (500-599)
# Derived from port: table = PEER_TABLE_BASE + (port - PEER_TUNNEL_PORT_MIN)
PEER_TABLE_BASE = 500


def get_peer_routing_table(tunnel_port: int) -> int:
    """ 从隧道端口计算路由表号（确定性，无冲突）

    端口 36200-36299 映射到路由表 500-599。
    每个 peer 有唯一端口，因此路由表号也唯一。

    Args:
        tunnel_port: 隧道监听端口 (36200-36299)

    Returns:
        路由表号 (500-599)

    Raises:
        ValueError: 端口超出有效范围
    """
    if not isinstance(tunnel_port, int) or isinstance(tunnel_port, bool):
        raise ValueError(f"tunnel_port 必须是整数，收到 {type(tunnel_port).__name__}")
    if not (PEER_TUNNEL_PORT_MIN <= tunnel_port <= PEER_TUNNEL_PORT_MAX):
        raise ValueError(
            f"tunnel_port {tunnel_port} 超出有效范围 "
            f"({PEER_TUNNEL_PORT_MIN}-{PEER_TUNNEL_PORT_MAX})"
        )
    return PEER_TABLE_BASE + (tunnel_port - PEER_TUNNEL_PORT_MIN)


# 重连配置
RECONNECT_INTERVAL = 30  # 快速重连间隔（秒）
HEALTH_CHECK_INTERVAL = 60  # 健康检查间隔（秒）
MAX_FAST_RECONNECT_ATTEMPTS = 5  # 快速重连最大尝试次数
SLOW_RECONNECT_INTERVAL = 600  # 慢速重连间隔（秒）= 10 分钟
# 抖动配置（防止 thundering herd）
JITTER_FACTOR = 0.25  # 抖动因子：±25% 随机偏移
EXPONENTIAL_BACKOFF_BASE = 2  # 指数退避基数
MAX_BACKOFF_INTERVAL = 1800  # 最大退避间隔（30 分钟）


def calculate_jittered_backoff(attempt: int, base_interval: float) -> float:
    """ 计算带抖动的指数退避间隔

    防止多个节点同时重连导致的 "thundering herd" 问题。

    算法:
    - 指数退避: interval = base * (2 ^ attempt)
    - 添加随机抖动: final = interval * (1 ± jitter_factor)
    - 限制最大值: min(final, MAX_BACKOFF_INTERVAL)

    Args:
        attempt: 当前尝试次数 (0-based)
        base_interval: 基础间隔（秒）

    Returns:
        带抖动的退避间隔（秒）
    """
    import random

    # 指数退避（但在快速重连阶段使用固定间隔）
    if attempt < MAX_FAST_RECONNECT_ATTEMPTS:
        interval = base_interval
    else:
        # 慢速重连阶段使用指数退避
        backoff_multiplier = EXPONENTIAL_BACKOFF_BASE ** (attempt - MAX_FAST_RECONNECT_ATTEMPTS)
        interval = SLOW_RECONNECT_INTERVAL * min(backoff_multiplier, 4)  # 最多 4x

    # 添加随机抖动（±25%）
    jitter = interval * JITTER_FACTOR * (2 * random.random() - 1)
    final_interval = interval + jitter

    # 限制最大值
    return min(final_interval, MAX_BACKOFF_INTERVAL)


def write_pid_file_atomic(pid_path: Path, pid: int) -> None:
    """原子写入 PID 文件，使用文件锁防止竞态条件"""
    pid_path.parent.mkdir(parents=True, exist_ok=True)
    lock_path = pid_path.with_suffix(".lock")

    with open(lock_path, 'w') as lock_file:
        fcntl.flock(lock_file.fileno(), fcntl.LOCK_EX)
        try:
            tmp_path = pid_path.with_suffix(".tmp")
            tmp_path.write_text(str(pid))
            tmp_path.rename(pid_path)
        finally:
            fcntl.flock(lock_file.fileno(), fcntl.LOCK_UN)


def validate_hostname(hostname: str) -> bool:
    """[安全] 验证主机名是否符合 RFC 1123 规范或是有效 IP 地址

    Args:
        hostname: 要验证的主机名或 IP 地址

    Returns:
        是否有效
    """
    if not hostname:
        return False

    # 检查是否为有效 IP 地址
    try:
        ip_address(hostname)
        return True
    except ValueError:
        pass

    # 检查是否为有效主机名
    if HOSTNAME_PATTERN.match(hostname):
        # 额外检查：每个标签最多 63 字符
        labels = hostname.split('.')
        return all(len(label) <= 63 for label in labels)

    return False


def cleanup_stale_pid_file(pid_path: Path) -> None:
    """清理无效的 PID 文件"""
    if not pid_path.exists():
        return

    try:
        pid_str = pid_path.read_text().strip()
        pid = int(pid_str)
        os.kill(pid, 0)  # 检查进程是否存在
    except (ValueError, ProcessLookupError, PermissionError):
        try:
            pid_path.unlink()
            logger.debug(f"已清理无效 PID 文件: {pid_path}")
        except Exception as e:
            logger.warning(f"清理 PID 文件失败: {e}")
    except Exception as e:
        logger.warning(f"检查 PID 文件时出错: {e}")


def _get_db():
    """获取数据库连接"""
    return get_db(GEODATA_DB_PATH, USER_DB_PATH, SQLCIPHER_KEY)


def get_interface_name(tag: str, tunnel_type: str = "wireguard") -> str:
    """生成接口名称（最大 15 字符）

    Args:
        tag: 节点标识符
        tunnel_type: 隧道类型 (wireguard/xray)

    Returns:
        接口名称，如 wg-peer-tokyo 或 xray-peer-tok
    """
    if tunnel_type == "wireguard":
        prefix = "wg-peer-"
    else:
        prefix = "xray-peer-"

    max_tag_len = 15 - len(prefix)

    if len(tag) <= max_tag_len:
        return f"{prefix}{tag}"
    else:
        # 使用 MD5 哈希保证唯一性
        # 计算可用于 tag 部分的空间（需要留出 7 字符给 "-XXXXXX" 哈希后缀）
        available_space = max_tag_len - 7
        if available_space > 0:
            tag_hash = hashlib.md5(tag.encode()).hexdigest()[:6]
            return f"{prefix}{tag[:available_space]}-{tag_hash}"
        else:
            # 空间不足时只使用哈希（调整哈希长度以适应 max_tag_len）
            tag_hash = hashlib.md5(tag.encode()).hexdigest()[:max_tag_len]
            return f"{prefix}{tag_hash}"


def get_pending_interface_name(pairing_id: str) -> str:
    """生成待处理配对的接口名称

    使用 wg-pend-{hash} 格式，保证唯一性且不超过 15 字符

    Args:
        pairing_id: 配对标识（base64 hash）

    Returns:
        接口名称，如 wg-pend-a1b2c3d
    """
    # wg-pend- 是 8 字符，留 7 字符给 hash
    prefix = "wg-pend-"
    hash_part = hashlib.md5(pairing_id.encode()).hexdigest()[:7]
    return f"{prefix}{hash_part}"


def create_pending_wireguard_interface(
    pairing_id: str,
    local_ip: str,
    remote_ip: str,
    listen_port: int,
    private_key: str,
    expected_peer_public_key: str,
) -> tuple:
    """创建用于配对的待处理 WireGuard 接口

    此接口只监听，不设置 endpoint（等待对端主动连接）。
    当对端连接后，WireGuard 会自动学习对端的 endpoint。

    Args:
        pairing_id: 配对标识（用于生成接口名）
        local_ip: 本端隧道 IP（如 10.200.200.1）
        remote_ip: 对端隧道 IP（如 10.200.200.2）
        listen_port: 监听端口
        private_key: 本节点私钥
        expected_peer_public_key: 预生成的对端公钥（用于验证连接）

    Returns:
        (success, interface_name, error_message)
    """
    interface = get_pending_interface_name(pairing_id)

    logger.info(f"[pending-pairing] 创建待处理接口: {interface} (port={listen_port})")

    try:
        # 检查接口是否已存在
        check_result = subprocess.run(
            ["ip", "link", "show", interface],
            capture_output=True, text=True, timeout=10
        )
        if check_result.returncode == 0:
            logger.info(f"[pending-pairing] 接口 {interface} 已存在，先删除")
            subprocess.run(["ip", "link", "delete", interface], check=False, timeout=10)

        # 创建 WireGuard 接口
        subprocess.run(["ip", "link", "add", interface, "type", "wireguard"], check=True, timeout=10)

        # 设置私钥（使用原子替换）
        key_file = PEER_RUN_DIR / f"pending-{pairing_id[:8]}.key"
        PEER_RUN_DIR.mkdir(parents=True, exist_ok=True)
        fd, temp_path = tempfile.mkstemp(dir=PEER_RUN_DIR, suffix='.key')
        try:
            os.write(fd, private_key.encode('utf-8'))
            os.close(fd)
            os.chmod(temp_path, 0o600)
            os.rename(temp_path, str(key_file))
        except Exception:
            try:
                os.close(fd)
            except Exception:
                pass
            if os.path.exists(temp_path):
                os.unlink(temp_path)
            raise

        subprocess.run(["wg", "set", interface, "private-key", str(key_file)], check=True, timeout=10)

        # 设置监听端口
        subprocess.run(["wg", "set", interface, "listen-port", str(listen_port)], check=True, timeout=10)

        # 添加对端（不设置 endpoint，只等待对方连接）
        # allowed-ips 设置为对端的隧道 IP，这样只接受来自正确 IP 的流量
        subprocess.run([
            "wg", "set", interface, "peer", expected_peer_public_key,
            "allowed-ips", f"{remote_ip}/32",
            "persistent-keepalive", "25"
        ], check=True, timeout=10)

        # 配置 IP 地址
        subprocess.run(["ip", "addr", "add", f"{local_ip}/30", "dev", interface], check=True, timeout=10)

        # 启动接口
        subprocess.run(["ip", "link", "set", interface, "up"], check=True, timeout=10)

        logger.info(f"[pending-pairing] 待处理接口创建成功: {interface} ({local_ip} 等待 {remote_ip})")
        return True, interface, None

    except subprocess.CalledProcessError as e:
        error_msg = f"命令执行失败: {e}"
        logger.error(f"[pending-pairing] {error_msg}")
        # 清理部分创建的接口
        subprocess.run(["ip", "link", "delete", interface], check=False, timeout=10)
        return False, None, error_msg

    except subprocess.TimeoutExpired as e:
        error_msg = f"命令超时: {e}"
        logger.error(f"[pending-pairing] {error_msg}")
        subprocess.run(["ip", "link", "delete", interface], check=False, timeout=10)
        return False, None, error_msg

    except Exception as e:
        error_msg = f"未知错误: {e}"
        logger.error(f"[pending-pairing] {error_msg}")
        try:
            subprocess.run(["ip", "link", "delete", interface], check=False, timeout=10)
        except Exception:
            pass
        return False, None, error_msg


def teardown_pending_wireguard_interface(interface_name: str) -> bool:
    """清理待处理的 WireGuard 接口

    Args:
        interface_name: 接口名称

    Returns:
        是否成功
    """
    if not interface_name:
        return True

    logger.info(f"[pending-pairing] 清理待处理接口: {interface_name}")

    try:
        result = subprocess.run(
            ["ip", "link", "show", interface_name],
            capture_output=True, text=True, timeout=10
        )
        if result.returncode != 0:
            logger.debug(f"[pending-pairing] 接口 {interface_name} 不存在，无需清理")
            return True

        subprocess.run(["ip", "link", "delete", interface_name], check=True, timeout=10)
        logger.info(f"[pending-pairing] 接口 {interface_name} 已删除")
        return True

    except Exception as e:
        logger.warning(f"[pending-pairing] 清理接口失败: {e}")
        return False


def rename_wireguard_interface(old_name: str, new_name: str) -> bool:
    """重命名 WireGuard 接口

    将待处理接口重命名为正式接口（如 wg-pend-xxx -> wg-peer-node2）

    Args:
        old_name: 原接口名
        new_name: 新接口名

    Returns:
        是否成功
    """
    logger.info(f"[pending-pairing] 重命名接口: {old_name} -> {new_name}")

    try:
        # 先关闭接口
        subprocess.run(["ip", "link", "set", old_name, "down"], check=True, timeout=10)

        # 重命名
        subprocess.run(["ip", "link", "set", old_name, "name", new_name], check=True, timeout=10)

        # 重新启动
        subprocess.run(["ip", "link", "set", new_name, "up"], check=True, timeout=10)

        logger.info(f"[pending-pairing] 接口重命名成功")
        return True

    except subprocess.CalledProcessError as e:
        logger.error(f"[pending-pairing] 接口重命名失败: {e}")
        return False
    except Exception as e:
        logger.error(f"[pending-pairing] 接口重命名出错: {e}")
        return False


def update_wireguard_peer_endpoint(interface: str, peer_public_key: str, endpoint: str) -> bool:
    """更新 WireGuard 对端的 endpoint

    当对端连接后，如果需要主动发起连接，可以设置 endpoint

    Args:
        interface: 接口名称
        peer_public_key: 对端公钥
        endpoint: 对端端点（IP:port）

    Returns:
        是否成功
    """
    logger.info(f"[pending-pairing] 更新对端 endpoint: {interface} -> {endpoint}")

    try:
        subprocess.run([
            "wg", "set", interface, "peer", peer_public_key,
            "endpoint", endpoint
        ], check=True, timeout=10)
        return True
    except Exception as e:
        logger.error(f"[pending-pairing] 更新 endpoint 失败: {e}")
        return False


def create_wireguard_tunnel_with_endpoint(
    interface_name: str,
    local_ip: str,
    remote_ip: str,
    listen_port: int,
    private_key: str,
    peer_public_key: str,
    remote_endpoint: str,
) -> tuple:
    """ 创建 WireGuard 隧道并连接到远程端点

    用于导入配对请求时，Node B 创建隧道并连接到 Node A。

    Args:
        interface_name: 接口名称 (如 wg-peer-node1)
        local_ip: 本地隧道 IP (如 10.200.200.2)
        remote_ip: 对端隧道 IP (如 10.200.200.1)
        listen_port: 本地监听端口 (如 36301)
        private_key: 本地私钥
        peer_public_key: 对端公钥
        remote_endpoint: 远程端点 (如 10.1.100.11:36300)

    Returns:
        (success: bool, error_message: Optional[str])
    """
    logger.info(f"[tunnel] 创建 WireGuard 隧道: {interface_name} -> {remote_endpoint}")

    try:
        # 验证端点格式
        if ":" in remote_endpoint:
            ep_host, ep_port = remote_endpoint.rsplit(":", 1)
        else:
            return False, "Invalid endpoint format (missing port)"

        if not validate_hostname(ep_host):
            return False, f"Invalid endpoint hostname: {ep_host}"

        # 检查并删除已存在的接口
        check_result = subprocess.run(
            ["ip", "link", "show", interface_name],
            capture_output=True, text=True, timeout=10
        )
        if check_result.returncode == 0:
            logger.info(f"[tunnel] 接口 {interface_name} 已存在，先删除")
            subprocess.run(["ip", "link", "delete", interface_name], check=False, timeout=10)

        # 创建 WireGuard 接口
        subprocess.run(["ip", "link", "add", interface_name, "type", "wireguard"], check=True, timeout=10)

        # 写入私钥
        PEER_RUN_DIR.mkdir(parents=True, exist_ok=True)
        key_file = PEER_RUN_DIR / f"{interface_name}.key"
        fd, temp_path = tempfile.mkstemp(dir=PEER_RUN_DIR, suffix='.key')
        try:
            os.write(fd, private_key.encode('utf-8'))
            os.close(fd)
            os.chmod(temp_path, 0o600)
            os.rename(temp_path, str(key_file))
        except Exception:
            try:
                os.close(fd)
            except Exception:
                pass
            if os.path.exists(temp_path):
                os.unlink(temp_path)
            raise

        # 设置私钥
        subprocess.run(["wg", "set", interface_name, "private-key", str(key_file)], check=True, timeout=10)

        # 设置监听端口
        subprocess.run(["wg", "set", interface_name, "listen-port", str(listen_port)], check=True, timeout=10)

        # 添加对端（带 endpoint，用于主动连接）
        subprocess.run([
            "wg", "set", interface_name, "peer", peer_public_key,
            "endpoint", remote_endpoint,
            "allowed-ips", "0.0.0.0/0",
            "persistent-keepalive", "25"
        ], check=True, timeout=10)

        # 配置 IP 地址
        subprocess.run(["ip", "addr", "add", f"{local_ip}/30", "dev", interface_name], check=True, timeout=10)

        # 启动接口
        subprocess.run(["ip", "link", "set", interface_name, "up"], check=True, timeout=10)

        # 添加路由到对端
        subprocess.run(
            ["ip", "route", "add", f"{remote_ip}/32", "dev", interface_name],
            check=False, timeout=10
        )

        # 设置策略路由
        # 使用端口派生的确定性路由表号（替代 hash() 的非确定性行为）
        table_num = get_peer_routing_table(listen_port)
        subprocess.run(
            ["ip", "route", "add", "default", "via", remote_ip, "dev", interface_name, "table", str(table_num)],
            check=False, timeout=10
        )
        subprocess.run(
            ["ip", "rule", "add", "from", local_ip, "lookup", str(table_num), "priority", "50"],
            check=False, timeout=10
        )

        logger.info(f"[tunnel] WireGuard 隧道创建成功: {interface_name} ({local_ip} -> {remote_ip})")
        return True, None

    except subprocess.CalledProcessError as e:
        error_msg = f"WireGuard setup command failed: {e}"
        logger.error(f"[tunnel] {error_msg}")
        subprocess.run(["ip", "link", "delete", interface_name], check=False, timeout=10)
        return False, error_msg
    except subprocess.TimeoutExpired as e:
        error_msg = f"WireGuard setup timed out: {e}"
        logger.error(f"[tunnel] {error_msg}")
        subprocess.run(["ip", "link", "delete", interface_name], check=False, timeout=10)
        return False, error_msg
    except Exception as e:
        error_msg = f"WireGuard setup failed: {e}"
        logger.error(f"[tunnel] {error_msg}")
        try:
            subprocess.run(["ip", "link", "delete", interface_name], check=False, timeout=10)
        except Exception:
            pass
        return False, error_msg


def wait_for_wireguard_handshake(interface_name: str, timeout_seconds: int = 10) -> bool:
    """等待 WireGuard 隧道完成握手

    Args:
        interface_name: 接口名称
        timeout_seconds: 超时时间（秒）

    Returns:
        是否成功握手
    """
    import time
    start_time = time.time()

    while time.time() - start_time < timeout_seconds:
        try:
            result = subprocess.run(
                ["wg", "show", interface_name, "latest-handshakes"],
                capture_output=True, text=True, timeout=5
            )
            if result.returncode == 0:
                # 输出格式: <public_key>\t<timestamp>
                # 如果 timestamp > 0，说明已完成握手
                for line in result.stdout.strip().split('\n'):
                    parts = line.split('\t')
                    if len(parts) >= 2:
                        try:
                            handshake_time = int(parts[1])
                            if handshake_time > 0:
                                logger.info(f"[tunnel] WireGuard 握手成功: {interface_name}")
                                return True
                        except (ValueError, IndexError):
                            pass
        except Exception as e:
            logger.warning(f"[tunnel] 检查握手状态失败: {e}")

        time.sleep(0.5)

    logger.warning(f"[tunnel] WireGuard 握手超时 ({timeout_seconds}s): {interface_name}")
    return False


@dataclass
class PeerTunnel:
    """对等节点隧道状态"""
    tag: str
    name: str
    endpoint: str
    tunnel_type: str
    status: str = "disconnected"  # disconnected, connecting, connected, error
    interface: Optional[str] = None
    local_ip: Optional[str] = None
    remote_ip: Optional[str] = None
    last_seen: Optional[datetime] = None
    last_error: Optional[str] = None
    reconnect_attempts: int = 0
    last_reconnect_time: float = 0  # 上次重连尝试的时间戳
    process_pid: Optional[int] = None


class PeerTunnelManager:
    """对等节点隧道管理器"""

    def __init__(self):
        self.tunnels: Dict[str, PeerTunnel] = {}
        self._running = False
        self._shutdown_event = False

    def _load_peer_nodes(self) -> List[Dict]:
        """从数据库加载启用的对等节点"""
        try:
            db = _get_db()
            nodes = db.get_peer_nodes(enabled_only=True)
            return nodes
        except Exception as e:
            logger.error(f"加载节点配置失败: {e}")
            return []

    def _update_node_status(self, tag: str, status: str, error: str = None) -> None:
        """更新数据库中的节点状态"""
        try:
            db = _get_db()
            update_kwargs = {
                "tunnel_status": status,
            }
            if error:
                update_kwargs["last_error"] = error
            if status == "connected":
                update_kwargs["last_seen"] = datetime.now().isoformat()
                update_kwargs["last_error"] = None

            db.update_peer_node(tag, **update_kwargs)
        except Exception as e:
            logger.warning(f"更新节点 '{tag}' 状态失败: {e}")

    def _setup_wireguard_tunnel(self, node: Dict) -> bool:
        """设置 WireGuard 点对点隧道

        Args:
            node: 节点配置

        Returns:
            是否成功
        """
        tag = node["tag"]
        interface = get_interface_name(tag, "wireguard")

        # 检查必需字段
        if not node.get("wg_private_key"):
            logger.error(f"[{tag}] 缺少 WireGuard 私钥，需要先进行参数交换")
            return False

        if not node.get("wg_peer_public_key"):
            logger.error(f"[{tag}] 缺少对端公钥，需要先进行参数交换")
            return False

        if not node.get("tunnel_local_ip"):
            logger.error(f"[{tag}] 缺少本地隧道 IP")
            return False

        local_ip = node["tunnel_local_ip"]
        remote_ip = node.get("tunnel_remote_ip", f"{PEER_TUNNEL_SUBNET}.2")
        endpoint = node["endpoint"]
        # tunnel_port 必须在创建节点时分配，缺失则报错
        port = node.get("tunnel_port")
        if not port:
            logger.error(f"[{tag}] tunnel_port 未分配，请检查节点创建流程")
            return False
        private_key = node["wg_private_key"]
        peer_public_key = node["wg_peer_public_key"]

        # [安全] 解析并验证 endpoint 中的主机名
        if ":" in endpoint:
            ep_host = endpoint.rsplit(":", 1)[0]
        else:
            ep_host = endpoint
        if not validate_hostname(ep_host):
            logger.error(f"[{tag}] 无效的端点主机名: {ep_host}")
            return False

        logger.info(f"[{tag}] 设置 WireGuard 隧道: {interface}")

        try:
            # 检查接口是否已存在
            check_result = subprocess.run(
                ["ip", "link", "show", interface],
                capture_output=True, text=True, timeout=10
            )
            if check_result.returncode == 0:
                logger.info(f"[{tag}] 接口 {interface} 已存在，先删除")
                subprocess.run(["ip", "link", "delete", interface], check=False, timeout=10)

            # 创建 WireGuard 接口
            subprocess.run(["ip", "link", "add", interface, "type", "wireguard"], check=True, timeout=10)

            # [安全] 设置私钥（使用原子替换，避免 TOCTOU 竞态条件）
            key_file = PEER_RUN_DIR / f"{tag}.key"
            PEER_RUN_DIR.mkdir(parents=True, exist_ok=True)
            # 使用 tempfile + rename 实现原子写入
            fd, temp_path = tempfile.mkstemp(dir=PEER_RUN_DIR, suffix='.key')
            try:
                os.write(fd, private_key.encode('utf-8'))
                os.close(fd)
                os.chmod(temp_path, 0o600)
                os.rename(temp_path, str(key_file))  # 原子替换
            except Exception:
                os.close(fd) if not os.get_inheritable(fd) else None
                if os.path.exists(temp_path):
                    os.unlink(temp_path)
                raise
            subprocess.run(["wg", "set", interface, "private-key", str(key_file)], check=True, timeout=10)

            # 设置监听端口
            subprocess.run(["wg", "set", interface, "listen-port", str(port)], check=True, timeout=10)

            # 添加对端
            # AllowedIPs 设为 0.0.0.0/0 允许所有流量通过隧道
            # 实际流量走向由 Linux 路由表控制 (只有路由指向该接口的流量才会发送)
            subprocess.run([
                "wg", "set", interface, "peer", peer_public_key,
                "endpoint", endpoint,
                "allowed-ips", "0.0.0.0/0",
                "persistent-keepalive", "25"
            ], check=True, timeout=10)

            # 配置 IP 地址
            subprocess.run(["ip", "addr", "add", f"{local_ip}/30", "dev", interface], check=True, timeout=10)

            # 启动接口
            subprocess.run(["ip", "link", "set", interface, "up"], check=True, timeout=10)

            # 添加路由到对端
            subprocess.run(
                ["ip", "route", "add", f"{remote_ip}/32", "dev", interface],
                check=False, timeout=10  # 路由可能已存在
            )

            # 设置策略路由: 从本地隧道 IP 发出的流量通过对端转发
            # 这允许 sing-box 使用 bind_interface 时流量正确路由
            # 使用端口派生的确定性路由表号
            # 路由表分配：ECMP 200-299, DSCP 300-363, 中继 400-463, 对等 500-599
            table_num = get_peer_routing_table(port)

            # 添加默认路由到策略路由表
            subprocess.run(
                ["ip", "route", "add", "default", "via", remote_ip, "dev", interface, "table", str(table_num)],
                check=False, timeout=10
            )

            # 添加策略规则: 从本地隧道 IP 发出的流量使用该表
            subprocess.run(
                ["ip", "rule", "add", "from", local_ip, "lookup", str(table_num), "priority", "50"],
                check=False, timeout=10
            )

            logger.info(f"[{tag}] 策略路由设置: from {local_ip} -> table {table_num} (default via {remote_ip})")

            # 更新数据库
            db = _get_db()
            db.update_peer_node(tag, tunnel_interface=interface)

            logger.info(f"[{tag}] WireGuard 隧道设置成功: {interface} ({local_ip} -> {remote_ip})")
            return True

        except subprocess.CalledProcessError as e:
            logger.error(f"[{tag}] WireGuard 设置失败: {e}")
            # 清理部分创建的接口
            subprocess.run(["ip", "link", "delete", interface], check=False, timeout=10)
            return False
        except subprocess.TimeoutExpired as e:
            logger.error(f"[{tag}] WireGuard 设置超时: {e}")
            subprocess.run(["ip", "link", "delete", interface], check=False, timeout=10)
            return False
        except Exception as e:
            logger.error(f"[{tag}] WireGuard 设置失败: {e}")
            # 尝试清理接口
            try:
                subprocess.run(["ip", "link", "delete", interface], check=False, timeout=10)
            except Exception:
                pass
            return False

    def _teardown_wireguard_tunnel(self, tag: str, interface: str) -> None:
        """拆除 WireGuard 隧道"""
        logger.info(f"[{tag}] 拆除 WireGuard 隧道: {interface}")
        try:
            # 获取节点信息用于清理策略路由
            db = _get_db()
            node = db.get_peer_node(tag)
            local_ip = node.get("tunnel_local_ip") if node else None

            # 清理策略路由规则
            if local_ip and node:
                # 使用端口派生的确定性路由表号
                tunnel_port = node.get("tunnel_port")
                if tunnel_port:
                    table_num = get_peer_routing_table(tunnel_port)
                    # 删除策略规则
                    subprocess.run(
                        ["ip", "rule", "del", "from", local_ip, "lookup", str(table_num)],
                        check=False, timeout=10
                    )
                    # 删除路由表
                    subprocess.run(
                        ["ip", "route", "flush", "table", str(table_num)],
                        check=False, timeout=10
                    )
                    logger.info(f"[{tag}] 清理策略路由: from {local_ip} table {table_num}")
                else:
                    logger.warning(f"[{tag}] tunnel_port 未设置，跳过策略路由清理（可能有残留规则）")

            # 清理 DSCP iptables 规则（多跳链路相关）
            try:
                from dscp_manager import get_dscp_manager
                dscp_mgr = get_dscp_manager()
                dscp_mgr.cleanup_rules_for_interface(interface)
                logger.info(f"[{tag}] 清理 DSCP 规则: {interface}")
            except Exception as e:
                logger.warning(f"[{tag}] DSCP 规则清理失败: {e}")

            # 删除接口
            subprocess.run(["ip", "link", "delete", interface], check=False, timeout=10)

            # 清理密钥文件
            key_file = PEER_RUN_DIR / f"{tag}.key"
            if key_file.exists():
                key_file.unlink()
        except Exception as e:
            logger.warning(f"[{tag}] 拆除隧道失败: {e}")

    def _check_wireguard_health(self, tag: str, interface: str) -> bool:
        """检查 WireGuard 隧道健康状态

        通过检查最后握手时间判断隧道是否活跃
        """
        try:
            result = subprocess.run(
                ["wg", "show", interface, "latest-handshakes"],
                capture_output=True, text=True, timeout=5
            )
            if result.returncode != 0:
                return False

            # 解析握手时间
            output = result.stdout.strip()
            if not output:
                return False

            # 格式: <public_key>\t<timestamp>
            parts = output.split("\t")
            if len(parts) < 2:
                return False

            handshake_time = int(parts[1])
            if handshake_time == 0:
                # 从未握手
                return False

            # 检查握手时间是否在 3 分钟内
            age = time.time() - handshake_time
            return age < 180

        except Exception as e:
            logger.debug(f"[{tag}] 健康检查失败: {e}")
            return False

    def _setup_xray_tunnel(self, node: Dict) -> bool:
        """设置 Xray SOCKS5 代理隧道

        连接到对端节点的 Xray 服务，创建本地 SOCKS5 代理供 sing-box 使用。

        Args:
            node: 节点配置

        Returns:
            是否成功
        """
        tag = node["tag"]
        # 必须使用数据库中分配的端口以确保一致性
        socks_port = node.get("xray_socks_port")
        if not socks_port:
            # 基于 tag 计算确定性端口（使用 MD5 而非 hash()）
            # hash() 在不同 Python 进程间不稳定（hash randomization）
            # 注意：必须与 xray_manager.py 使用相同的算法
            tag_hash = int(hashlib.md5(tag.encode()).hexdigest()[:8], 16) % 99
            socks_port = PEER_XRAY_SOCKS_PORT_START + tag_hash
            logger.warning(
                f"[{tag}] 缺少 xray_socks_port，使用基于哈希的端口 {socks_port}"
            )
        endpoint = node.get("endpoint", "")
        xray_uuid = node.get("xray_uuid")

        # REALITY 配置（从对端获取的配置）
        reality_public_key = node.get("xray_peer_reality_public_key")
        reality_short_id = node.get("xray_peer_reality_short_id")
        reality_server_names = node.get("xray_peer_reality_server_names", '["www.microsoft.com"]')

        # 解析 server names JSON
        try:
            server_names_list = json.loads(reality_server_names) if isinstance(reality_server_names, str) else reality_server_names
        except (json.JSONDecodeError, TypeError):
            server_names_list = ["www.microsoft.com"]
        reality_server_name = server_names_list[0] if server_names_list else "www.microsoft.com"

        # XHTTP 传输配置（使用本地配置或默认值）
        xhttp_path = node.get("xray_xhttp_path", "/")
        xhttp_mode = node.get("xray_xhttp_mode", "auto")
        xhttp_host = node.get("xray_xhttp_host")

        # 检查必需字段
        if not xray_uuid:
            logger.error(f"[{tag}] 缺少 Xray UUID，需要先进行参数交换")
            return False

        if not endpoint:
            logger.error(f"[{tag}] 缺少对端 endpoint")
            return False

        if not reality_public_key or not reality_short_id:
            logger.error(f"[{tag}] 缺少 REALITY 配置，需要先进行参数交换获取对端公钥")
            return False

        # 解析 endpoint (格式: host:port)
        if ":" in endpoint:
            parts = endpoint.rsplit(":", 1)
            server_host = parts[0]
            try:
                server_port = int(parts[1])
            except ValueError:
                server_port = 443
        else:
            server_host = endpoint
            server_port = 443

        # [安全] 验证主机名，防止 SSRF 攻击
        if not validate_hostname(server_host):
            logger.error(f"[{tag}] 无效的主机名: {server_host}")
            return False

        logger.info(f"[{tag}] 设置 VLESS+XHTTP+REALITY 隧道: {server_host}:{server_port} -> SOCKS5:{socks_port}")

        # 生成 Xray 客户端配置（VLESS+XHTTP+REALITY）
        config = self._build_xray_peer_config(
            tag=tag,
            server_host=server_host,
            server_port=server_port,
            uuid=xray_uuid,
            socks_port=socks_port,
            reality_public_key=reality_public_key,
            reality_short_id=reality_short_id,
            reality_server_name=reality_server_name,
            xhttp_path=xhttp_path,
            xhttp_mode=xhttp_mode,
            xhttp_host=xhttp_host
        )

        # [安全] 写入配置文件（使用原子替换）
        PEER_RUN_DIR.mkdir(parents=True, exist_ok=True)
        config_file = PEER_RUN_DIR / f"xray-{tag}.json"
        fd, temp_path = tempfile.mkstemp(dir=PEER_RUN_DIR, suffix='.json')
        try:
            with os.fdopen(fd, 'w') as f:
                json.dump(config, f, indent=2)
            os.rename(temp_path, str(config_file))  # 原子替换
        except Exception:
            if os.path.exists(temp_path):
                os.unlink(temp_path)
            raise

        # 启动 Xray 进程
        log_file = PEER_LOG_DIR / f"xray-peer-{tag}.log"
        PEER_LOG_DIR.mkdir(parents=True, exist_ok=True)

        try:
            # [安全] 检查并停止已有进程（使用文件锁防止竞态条件）
            pid_file = PEER_RUN_DIR / f"xray-{tag}.pid"
            if pid_file.exists():
                try:
                    old_pid = int(pid_file.read_text().strip())
                    os.kill(old_pid, 0)  # 检查进程是否存在
                    logger.info(f"[{tag}] Xray 进程已存在 (PID: {old_pid})，先停止")
                    os.kill(old_pid, signal.SIGTERM)
                    # [安全] 等待进程实际终止（最多 5 秒）
                    for _ in range(50):
                        try:
                            os.kill(old_pid, 0)
                            time.sleep(0.1)
                        except ProcessLookupError:
                            break
                    else:
                        # 进程未终止，强制杀死
                        try:
                            os.kill(old_pid, signal.SIGKILL)
                            time.sleep(0.5)
                        except ProcessLookupError:
                            pass
                except (ValueError, ProcessLookupError):
                    pass

            # 启动新进程
            with open(log_file, "a") as log:
                proc = subprocess.Popen(
                    ["/usr/local/bin/xray", "run", "-c", str(config_file)],
                    stdout=log,
                    stderr=log,
                    start_new_session=True
                )

            # [安全] 使用原子写入 PID 文件
            fd, temp_path = tempfile.mkstemp(dir=PEER_RUN_DIR, suffix='.pid')
            try:
                os.write(fd, str(proc.pid).encode())
                os.close(fd)
                os.rename(temp_path, str(pid_file))
            except Exception:
                if os.path.exists(temp_path):
                    os.unlink(temp_path)
                raise

            # 等待启动
            time.sleep(1)

            # 检查进程是否正常运行
            if proc.poll() is not None:
                logger.error(f"[{tag}] Xray 进程启动失败，退出码: {proc.returncode}")
                return False

            # 检查 SOCKS 端口是否可用
            check_result = subprocess.run(
                ["ss", "-ln", f"sport = :{socks_port}"],
                capture_output=True, text=True, timeout=5
            )
            if f":{socks_port}" not in check_result.stdout:
                logger.warning(f"[{tag}] SOCKS 端口 {socks_port} 未监听，可能启动失败")

            # 更新数据库（包含 xray_socks_port，用于状态检测）
            db = _get_db()
            interface_name = get_interface_name(tag, "xray")
            db.update_peer_node(tag, tunnel_interface=interface_name, xray_socks_port=socks_port)

            logger.info(f"[{tag}] Xray 隧道启动成功 (PID: {proc.pid}, SOCKS: {socks_port})")
            return True

        except Exception as e:
            logger.error(f"[{tag}] Xray 隧道设置失败: {e}")
            return False

    def _setup_xray_inbound_tunnel(self, node: Dict) -> bool:
        """设置 Xray 隧道到对端的入站监听器（connection_mode='inbound'）

        与 _setup_xray_tunnel 类似，但连接目标是对端的入站监听端口而非主隧道端口。
        这允许双向连接：节点 A 可以通过节点 B 的入站监听器连接到节点 B。

        使用场景：
        - 当主隧道端口被防火墙阻止时，可以使用入站端口
        - 实现双向对等连接
        - 负载均衡或冗余路径

        Args:
            node: 节点配置，必须包含 peer_inbound_* 字段

        Returns:
            是否成功
        """
        tag = node["tag"]
        # 必须使用数据库中分配的端口以确保一致性
        socks_port = node.get("xray_socks_port")
        if not socks_port:
            # 基于 tag 计算确定性端口（使用 MD5 而非 hash()）
            # hash() 在不同 Python 进程间不稳定（hash randomization）
            # 注意：必须与 xray_manager.py 使用相同的算法
            tag_hash = int(hashlib.md5(tag.encode()).hexdigest()[:8], 16) % 99
            socks_port = PEER_XRAY_SOCKS_PORT_START + tag_hash
            logger.warning(
                f"[{tag}] 缺少 xray_socks_port，使用基于哈希的端口 {socks_port}"
            )
        endpoint = node.get("endpoint", "")

        # 检查对端是否启用了入站
        peer_inbound_enabled = node.get("peer_inbound_enabled")
        if not peer_inbound_enabled:
            logger.error(f"[{tag}] 对端未启用入站监听，无法使用 inbound 模式")
            return False

        # 获取对端入站配置
        peer_inbound_port = node.get("peer_inbound_port")
        peer_inbound_reality_public_key = node.get("peer_inbound_reality_public_key")
        peer_inbound_reality_short_id = node.get("peer_inbound_reality_short_id")

        # 使用对端入站的 UUID（对端在参数交换时返回的 inbound_uuid）
        # peer_inbound_uuid 是对端入站监听器期望的客户端 UUID
        peer_uuid = node.get("peer_inbound_uuid")
        if not peer_uuid:
            # 向后兼容：如果没有 peer_inbound_uuid，尝试用对端的 xray_uuid
            peer_uuid = node.get("xray_uuid")

        # 验证必需字段
        if not peer_inbound_port:
            logger.error(f"[{tag}] 缺少对端入站端口 (peer_inbound_port)")
            return False

        if not peer_inbound_reality_public_key or not peer_inbound_reality_short_id:
            logger.error(f"[{tag}] 缺少对端入站 REALITY 配置")
            return False

        if not peer_uuid:
            logger.error(f"[{tag}] 缺少对端入站 UUID (peer_inbound_uuid)，需要先进行参数交换")
            return False

        if not endpoint:
            logger.error(f"[{tag}] 缺少对端 endpoint")
            return False

        # 解析 endpoint 获取 host（忽略主端口，使用 peer_inbound_port）
        if ":" in endpoint:
            server_host = endpoint.rsplit(":", 1)[0]
        else:
            server_host = endpoint

        server_port = peer_inbound_port

        # [安全] 验证主机名
        if not validate_hostname(server_host):
            logger.error(f"[{tag}] 无效的主机名: {server_host}")
            return False

        logger.info(f"[{tag}] 设置入站模式隧道: {server_host}:{server_port} (inbound) -> SOCKS5:{socks_port}")

        # XHTTP 传输配置（使用本地配置或默认值）
        xhttp_path = node.get("xray_xhttp_path", "/")
        xhttp_mode = node.get("xray_xhttp_mode", "auto")
        xhttp_host = node.get("xray_xhttp_host")

        # 使用对端入站的 server name (通常与主隧道相同)
        reality_server_names = node.get("xray_peer_reality_server_names", '["www.microsoft.com"]')
        try:
            server_names_list = json.loads(reality_server_names) if isinstance(reality_server_names, str) else reality_server_names
        except (json.JSONDecodeError, TypeError):
            server_names_list = ["www.microsoft.com"]
        reality_server_name = server_names_list[0] if server_names_list else "www.microsoft.com"

        # 生成 Xray 客户端配置
        # 使用 {tag}-inbound 作为所有文件名，避免与 outbound 隧道冲突
        inbound_tag = f"{tag}-inbound"
        config = self._build_xray_peer_config(
            tag=inbound_tag,
            server_host=server_host,
            server_port=server_port,
            uuid=peer_uuid,
            socks_port=socks_port,
            reality_public_key=peer_inbound_reality_public_key,
            reality_short_id=peer_inbound_reality_short_id,
            reality_server_name=reality_server_name,
            xhttp_path=xhttp_path,
            xhttp_mode=xhttp_mode,
            xhttp_host=xhttp_host
        )

        # [安全] 写入配置文件（使用原子替换）
        PEER_RUN_DIR.mkdir(parents=True, exist_ok=True)
        config_file = PEER_RUN_DIR / f"xray-{inbound_tag}.json"
        fd, temp_path = tempfile.mkstemp(dir=PEER_RUN_DIR, suffix='.json')
        try:
            with os.fdopen(fd, 'w') as f:
                json.dump(config, f, indent=2)
            os.rename(temp_path, str(config_file))
        except Exception:
            if os.path.exists(temp_path):
                os.unlink(temp_path)
            raise

        # 启动 Xray 进程
        log_file = PEER_LOG_DIR / f"xray-peer-{inbound_tag}.log"
        PEER_LOG_DIR.mkdir(parents=True, exist_ok=True)

        try:
            # 检查并停止已有进程
            pid_file = PEER_RUN_DIR / f"xray-{inbound_tag}.pid"
            if pid_file.exists():
                try:
                    old_pid = int(pid_file.read_text().strip())
                    os.kill(old_pid, 0)
                    logger.info(f"[{tag}] Xray 进程已存在 (PID: {old_pid})，先停止")
                    os.kill(old_pid, signal.SIGTERM)
                    for _ in range(50):
                        try:
                            os.kill(old_pid, 0)
                            time.sleep(0.1)
                        except ProcessLookupError:
                            break
                    else:
                        try:
                            os.kill(old_pid, signal.SIGKILL)
                            time.sleep(0.5)
                        except ProcessLookupError:
                            pass
                except (ValueError, ProcessLookupError):
                    pass

            # 启动新进程
            with open(log_file, "a") as log:
                proc = subprocess.Popen(
                    ["/usr/local/bin/xray", "run", "-c", str(config_file)],
                    stdout=log,
                    stderr=log,
                    start_new_session=True
                )

            # 使用原子写入 PID 文件
            fd, temp_path = tempfile.mkstemp(dir=PEER_RUN_DIR, suffix='.pid')
            try:
                os.write(fd, str(proc.pid).encode())
                os.close(fd)
                os.rename(temp_path, str(pid_file))
            except Exception:
                if os.path.exists(temp_path):
                    os.unlink(temp_path)
                raise

            # 等待启动
            time.sleep(1)

            # 检查进程是否正常运行
            if proc.poll() is not None:
                logger.error(f"[{tag}] Xray 进程启动失败，退出码: {proc.returncode}")
                return False

            # 检查 SOCKS 端口是否可用
            check_result = subprocess.run(
                ["ss", "-ln", f"sport = :{socks_port}"],
                capture_output=True, text=True, timeout=5
            )
            if f":{socks_port}" not in check_result.stdout:
                logger.warning(f"[{tag}] SOCKS 端口 {socks_port} 未监听，可能启动失败")

            # 更新数据库（包含 xray_socks_port，用于状态检测）
            db = _get_db()
            interface_name = get_interface_name(tag, "xray")
            db.update_peer_node(tag, tunnel_interface=interface_name, xray_socks_port=socks_port)

            logger.info(f"[{tag}] Xray 入站模式隧道启动成功 (PID: {proc.pid}, SOCKS: {socks_port})")
            return True

        except Exception as e:
            logger.error(f"[{tag}] Xray 入站模式隧道设置失败: {e}")
            return False

    def _build_xray_peer_config(
        self,
        tag: str,
        server_host: str,
        server_port: int,
        uuid: str,
        socks_port: int,
        # REALITY 配置（对端作为服务端）
        reality_public_key: str,
        reality_short_id: str,
        reality_server_name: str = "www.microsoft.com",
        # XHTTP 传输配置
        xhttp_path: str = "/",
        xhttp_mode: str = "auto",
        xhttp_host: Optional[str] = None
    ) -> Dict:
        """构建 Xray 客户端配置（VLESS+XHTTP+REALITY）

        固定使用 VLESS 协议 + XHTTP 传输 + REALITY 安全层。

        Args:
            tag: 节点标识
            server_host: 远程服务器地址
            server_port: 远程服务器端口
            uuid: 用户 UUID
            socks_port: 本地 SOCKS5 端口
            reality_public_key: 对端 REALITY 公钥
            reality_short_id: 对端 REALITY Short ID
            reality_server_name: REALITY Server Name (SNI)
            xhttp_path: XHTTP 路径
            xhttp_mode: XHTTP 模式 (auto/packet-up/stream-up/stream-one)
            xhttp_host: XHTTP Host 头

        Returns:
            Xray 配置字典
        """
        logger.info(f"[{tag}] 构建 VLESS+XHTTP+REALITY 配置")
        logger.debug(f"[{tag}] 服务器: {server_host}:{server_port}")
        logger.debug(f"[{tag}] REALITY: public_key={reality_public_key[:16]}..., short_id={reality_short_id}")
        logger.debug(f"[{tag}] XHTTP: path={xhttp_path}, mode={xhttp_mode}")

        # 基础配置
        config = {
            "log": {
                "loglevel": "warning"
            },
            "inbounds": [
                {
                    "tag": f"socks-in-{tag}",
                    "protocol": "socks",
                    "listen": "127.0.0.1",
                    "port": socks_port,
                    "settings": {
                        "auth": "noauth",
                        "udp": True
                    }
                }
            ],
            "outbounds": []
        }

        # XHTTP 传输设置
        xhttp_settings: Dict[str, Any] = {
            "path": xhttp_path,
            "mode": xhttp_mode
        }
        if xhttp_host:
            xhttp_settings["host"] = xhttp_host

        # REALITY 客户端设置
        reality_settings = {
            "serverName": reality_server_name,
            "fingerprint": "chrome",  # 使用 Chrome 浏览器指纹
            "publicKey": reality_public_key,
            "shortId": reality_short_id
        }

        # VLESS 出站配置
        outbound = {
            "tag": f"peer-{tag}",
            "protocol": "vless",
            "settings": {
                "vnext": [{
                    "address": server_host,
                    "port": server_port,
                    "users": [{
                        "id": uuid,
                        "encryption": "none"
                    }]
                }]
            },
            "streamSettings": {
                "network": "xhttp",
                "xhttpSettings": xhttp_settings,
                "security": "reality",
                "realitySettings": reality_settings
            }
        }

        config["outbounds"].append(outbound)

        return config

    def _teardown_xray_tunnel(self, tag: str) -> None:
        """拆除 Xray 隧道"""
        logger.info(f"[{tag}] 拆除 Xray 隧道")

        pid_file = PEER_RUN_DIR / f"xray-{tag}.pid"
        config_file = PEER_RUN_DIR / f"xray-{tag}.json"

        # 停止进程
        if pid_file.exists():
            try:
                pid = int(pid_file.read_text().strip())
                os.kill(pid, signal.SIGTERM)
                time.sleep(1)
                # 如果还在运行，强制终止
                try:
                    os.kill(pid, 0)
                    os.kill(pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
            except (ValueError, ProcessLookupError):
                pass
            finally:
                try:
                    pid_file.unlink()
                except Exception as e:
                    logger.debug(f"[{tag}] 清理 PID 文件失败: {e}")

        # 清理配置文件
        if config_file.exists():
            try:
                config_file.unlink()
            except Exception as e:
                logger.debug(f"[{tag}] 清理配置文件失败: {e}")

    def _check_xray_health(self, tag: str) -> bool:
        """检查 Xray 隧道健康状态

        通过检查 SOCKS 端口是否监听判断
        """
        try:
            db = _get_db()
            node = db.get_peer_node(tag)
            if not node:
                return False

            socks_port = node.get("xray_socks_port")
            if not socks_port:
                return False

            # 检查端口是否监听
            result = subprocess.run(
                ["ss", "-ln", f"sport = :{socks_port}"],
                capture_output=True, text=True, timeout=5
            )
            return f":{socks_port}" in result.stdout

        except Exception as e:
            logger.debug(f"[{tag}] Xray 健康检查失败: {e}")
            return False

    def connect_node(self, tag: str) -> bool:
        """连接到指定节点

        Args:
            tag: 节点标识符

        Returns:
            是否成功
        """
        # 获取节点配置
        db = _get_db()
        node = db.get_peer_node(tag)

        if not node:
            logger.error(f"节点 '{tag}' 不存在")
            return False

        if not node.get("enabled"):
            logger.warning(f"节点 '{tag}' 未启用")
            return False

        tunnel_type = node.get("tunnel_type", "wireguard")
        connection_mode = node.get("connection_mode", "outbound")  # 默认 outbound
        self._update_node_status(tag, "connecting")

        if tunnel_type == "wireguard":
            success = self._setup_wireguard_tunnel(node)
        elif tunnel_type == "xray":
            # 根据 connection_mode 选择隧道建立方式
            if connection_mode == "inbound":
                # 连接到对端的入站监听器
                peer_inbound_enabled = node.get("peer_inbound_enabled")
                if not peer_inbound_enabled:
                    logger.error(f"[{tag}] inbound 模式要求对端启用入站监听，但 peer_inbound_enabled=0")
                    self._update_node_status(tag, "error", "对端未启用入站监听")
                    return False
                logger.info(f"[{tag}] 使用 inbound 模式连接（连接到对端入站监听器）")
                success = self._setup_xray_inbound_tunnel(node)
            else:
                # 默认 outbound 模式：连接到对端的主隧道端点
                logger.info(f"[{tag}] 使用 outbound 模式连接（连接到对端主隧道）")
                success = self._setup_xray_tunnel(node)
        else:
            logger.error(f"[{tag}] 不支持的隧道类型: {tunnel_type}")
            self._update_node_status(tag, "error", f"不支持的隧道类型: {tunnel_type}")
            return False

        if success:
            self._update_node_status(tag, "connected")
            if tag in self.tunnels:
                self.tunnels[tag].status = "connected"
                self.tunnels[tag].reconnect_attempts = 0
                self.tunnels[tag].last_reconnect_time = 0
            return True
        else:
            self._update_node_status(tag, "error", "隧道设置失败")
            return False

    def disconnect_node(self, tag: str) -> bool:
        """断开指定节点

        Args:
            tag: 节点标识符

        Returns:
            是否成功
        """
        db = _get_db()
        node = db.get_peer_node(tag)

        if not node:
            logger.warning(f"节点 '{tag}' 不存在")
            return False

        tunnel_type = node.get("tunnel_type", "wireguard")
        interface = node.get("tunnel_interface")

        if tunnel_type == "wireguard" and interface:
            self._teardown_wireguard_tunnel(tag, interface)
        elif tunnel_type == "xray":
            self._teardown_xray_tunnel(tag)

        self._update_node_status(tag, "disconnected")
        if tag in self.tunnels:
            self.tunnels[tag].status = "disconnected"

        return True

    def start_all(self) -> None:
        """启动所有启用的隧道"""
        nodes = self._load_peer_nodes()
        logger.info(f"发现 {len(nodes)} 个启用的节点")

        for node in nodes:
            tag = node["tag"]
            auto_reconnect = node.get("auto_reconnect", 1)

            if not auto_reconnect:
                logger.info(f"[{tag}] 跳过（未启用自动重连）")
                continue

            self.tunnels[tag] = PeerTunnel(
                tag=tag,
                name=node.get("name", tag),
                endpoint=node.get("endpoint", ""),
                tunnel_type=node.get("tunnel_type", "wireguard"),
            )

            self.connect_node(tag)

    def stop_all(self) -> None:
        """停止所有隧道"""
        nodes = self._load_peer_nodes()

        for node in nodes:
            tag = node["tag"]
            self.disconnect_node(tag)

        self.tunnels.clear()

    def reload(self) -> None:
        """重载配置（停止已删除，启动新增）"""
        nodes = self._load_peer_nodes()
        current_tags = {node["tag"] for node in nodes}
        running_tags = set(self.tunnels.keys())

        # 停止已删除的节点
        for tag in running_tags - current_tags:
            logger.info(f"[{tag}] 节点已删除，断开隧道")
            self.disconnect_node(tag)
            del self.tunnels[tag]

        # 启动新增的节点
        for tag in current_tags - running_tags:
            node = next((n for n in nodes if n["tag"] == tag), None)
            if node and node.get("auto_reconnect", 1):
                logger.info(f"[{tag}] 新节点，建立隧道")
                self.tunnels[tag] = PeerTunnel(
                    tag=tag,
                    name=node.get("name", tag),
                    endpoint=node.get("endpoint", ""),
                    tunnel_type=node.get("tunnel_type", "wireguard"),
                )
                self.connect_node(tag)

    def get_status(self) -> List[Dict[str, Any]]:
        """获取所有隧道状态"""
        nodes = self._load_peer_nodes()
        status_list = []

        for node in nodes:
            tag = node["tag"]
            tunnel_type = node.get("tunnel_type", "wireguard")
            interface = node.get("tunnel_interface")

            status = {
                "tag": tag,
                "name": node.get("name"),
                "endpoint": node.get("endpoint"),
                "tunnel_type": tunnel_type,
                "tunnel_status": node.get("tunnel_status", "disconnected"),
                "tunnel_interface": interface,
                "tunnel_local_ip": node.get("tunnel_local_ip"),
                "tunnel_remote_ip": node.get("tunnel_remote_ip"),
                "last_seen": node.get("last_seen"),
                "last_error": node.get("last_error"),
                "enabled": bool(node.get("enabled", 1)),
                "auto_reconnect": bool(node.get("auto_reconnect", 1)),
            }

            # 检查实际接口/进程状态
            if tunnel_type == "wireguard" and interface:
                check_result = subprocess.run(
                    ["ip", "link", "show", interface],
                    capture_output=True, text=True, timeout=5
                )
                status["interface_exists"] = check_result.returncode == 0

                if status["interface_exists"]:
                    status["health"] = "healthy" if self._check_wireguard_health(tag, interface) else "unhealthy"
                else:
                    status["health"] = "down"
            elif tunnel_type == "xray":
                # 检查 Xray 进程和 SOCKS 端口
                socks_port = node.get("xray_socks_port")
                status["xray_socks_port"] = socks_port
                pid_file = PEER_RUN_DIR / f"xray-{tag}.pid"
                if pid_file.exists():
                    try:
                        pid = int(pid_file.read_text().strip())
                        os.kill(pid, 0)  # 检查进程是否存在
                        status["process_running"] = True
                        status["process_pid"] = pid
                    except (ValueError, ProcessLookupError):
                        status["process_running"] = False
                else:
                    status["process_running"] = False

                status["health"] = "healthy" if self._check_xray_health(tag) else "unhealthy"

            status_list.append(status)

        return status_list

    def run_daemon(self) -> None:
        """运行守护进程模式"""
        self._running = True
        last_health_check = 0

        def signal_handler(signum, frame):
            logger.info(f"收到信号 {signum}，准备退出...")
            self._shutdown_event = True
            self._running = False

        signal.signal(signal.SIGTERM, signal_handler)
        signal.signal(signal.SIGINT, signal_handler)
        signal.signal(signal.SIGHUP, lambda s, f: self.reload())

        # 写入 PID 文件
        cleanup_stale_pid_file(PEER_PID_FILE)
        write_pid_file_atomic(PEER_PID_FILE, os.getpid())

        logger.info("守护进程启动")
        self.start_all()

        try:
            while self._running:
                time.sleep(1)

                if self._shutdown_event:
                    break

                # 定期健康检查和重连
                now = time.time()
                if now - last_health_check >= HEALTH_CHECK_INTERVAL:
                    last_health_check = now
                    self._health_check_and_reconnect()

        finally:
            logger.info("守护进程停止")
            self.stop_all()
            if PEER_PID_FILE.exists():
                PEER_PID_FILE.unlink()

    def _cleanup_stale_tunnels(self) -> None:
        """[CR-010] 清理数据库中已不存在的隧道条目"""
        try:
            nodes = self._load_peer_nodes()
            db_tags = {node["tag"] for node in nodes}
            stale_tags = [tag for tag in self.tunnels if tag not in db_tags]

            for tag in stale_tags:
                logger.info(f"[{tag}] 清理过期隧道条目（节点已从数据库删除）")
                # 确保断开连接并清理资源
                self.disconnect_node(tag)
                del self.tunnels[tag]

        except Exception as e:
            logger.error(f"[cleanup] 清理过期隧道失败: {e}")

    def _get_local_node_id(self) -> str:
        """获取本地节点标识

        用于在发送通知时标识发送方。优先使用主机名，
        回退时使用 machine-id 或生成唯一 ID。
        """
        import socket
        # 优先使用主机名
        try:
            hostname = socket.gethostname()
            if hostname and hostname != "localhost":
                return hostname
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

        # 最后回退：生成随机 ID
        return f"vpn-gateway-{uuid.uuid4().hex[:8]}"

    def _on_node_disconnected(self, node_tag: str) -> None:
        """当节点断开时，通知所有经过此节点的链的上游

        Args:
            node_tag: 断开的节点标签
        """
        try:
            db = _get_db()
            # 查询所有以此节点为下游的链路注册
            registrations = db.get_chain_registrations_by_downstream(node_tag)

            if not registrations:
                logger.debug(f"[{node_tag}] 没有注册的上游链路需要通知")
                return

            logger.info(f"[{node_tag}] 发现 {len(registrations)} 条注册的上游链路，发送断连通知")

            for reg in registrations:
                success = self._notify_upstream_disconnected(
                    upstream_endpoint=reg["upstream_endpoint"],
                    chain_id=reg["chain_id"],
                    disconnected_node=node_tag
                )
                if not success:
                    logger.warning(f"[{node_tag}] 链路 {reg['chain_id']} 通知上游失败")
        except Exception as e:
            logger.error(f"[{node_tag}] 发送断连通知时出错: {e}")

    def _notify_upstream_disconnected(
        self,
        upstream_endpoint: str,
        chain_id: str,
        disconnected_node: str
    ) -> bool:
        """向上游节点发送断连通知

        认证方式: 隧道 IP 认证 (WireGuard) 或 UUID 认证 (Xray)

        Args:
            upstream_endpoint: 上游节点端点 (IP:port)
            chain_id: 链路 ID
            disconnected_node: 断开的下游节点标签

        Returns:
            是否发送成功
        """
        # [安全] 验证端点格式
        if ":" in upstream_endpoint:
            host, port_str = upstream_endpoint.rsplit(":", 1)
            try:
                port = int(port_str)
                if not (1 <= port <= 65535):
                    logger.error(f"[cascade] 端点端口超出范围: {upstream_endpoint}")
                    return False
            except ValueError:
                logger.error(f"[cascade] 端点端口无效: {upstream_endpoint}")
                return False
        else:
            host = upstream_endpoint

        if not validate_hostname(host):
            logger.error(f"[cascade] 端点主机名无效: {upstream_endpoint}")
            return False

        notification_id = str(uuid.uuid4())
        timestamp = datetime.now().isoformat()
        local_node_id = self._get_local_node_id()

        url = f"http://{upstream_endpoint}/api/peer-notify/downstream-disconnected"
        payload = {
            "node_id": local_node_id,
            "chain_id": chain_id,
            "disconnected_node": disconnected_node,
            "notification_id": notification_id,
            "timestamp": timestamp
        }

        try:
            logger.info(f"[cascade] 向上游 {upstream_endpoint} 发送断连通知: chain={chain_id}, node={disconnected_node}")
            response = requests.post(url, json=payload, timeout=10)

            if response.status_code == 200:
                result = response.json()
                forwarded = result.get("forwarded", False)
                logger.info(f"[cascade] 上游 {upstream_endpoint} 接收成功, forwarded={forwarded}")
                return True
            else:
                logger.warning(f"[cascade] 上游 {upstream_endpoint} 返回错误: {response.status_code}")
                return False
        except requests.exceptions.Timeout:
            logger.error(f"[cascade] 向上游 {upstream_endpoint} 发送通知超时")
            return False
        except requests.exceptions.ConnectionError as e:
            logger.error(f"[cascade] 无法连接到上游 {upstream_endpoint}: {e}")
            return False
        except Exception as e:
            logger.error(f"[cascade] 发送通知到上游 {upstream_endpoint} 失败: {e}")
            return False

    def _health_check_and_reconnect(self) -> None:
        """健康检查和自动重连

        重连策略：
        - 前 5 次：快速重连，每次健康检查时尝试
        - 超过 5 次后：慢速重连，每 10 分钟尝试一次，不限次数
        """
        # [CR-010] 清理数据库中不存在的隧道
        self._cleanup_stale_tunnels()

        now = time.time()
        for tag, tunnel in list(self.tunnels.items()):
            if tunnel.status != "connected":
                # 使用抖动退避计算重连间隔
                required_interval = calculate_jittered_backoff(
                    tunnel.reconnect_attempts,
                    RECONNECT_INTERVAL
                )
                time_since_last = now - tunnel.last_reconnect_time

                if tunnel.reconnect_attempts < MAX_FAST_RECONNECT_ATTEMPTS:
                    # 快速重连阶段（前 5 次）- 使用基础间隔 + 抖动
                    if time_since_last >= required_interval or tunnel.reconnect_attempts == 0:
                        logger.info(
                            f"[{tag}] 快速重连 ({tunnel.reconnect_attempts + 1}/"
                            f"{MAX_FAST_RECONNECT_ATTEMPTS})，间隔={required_interval:.1f}s"
                        )
                        tunnel.reconnect_attempts += 1
                        tunnel.last_reconnect_time = now
                        self.connect_node(tag)
                else:
                    # 慢速重连阶段 - 使用指数退避 + 抖动
                    if time_since_last >= required_interval:
                        logger.info(
                            f"[{tag}] 慢速重连（第 {tunnel.reconnect_attempts + 1} 次，"
                            f"下次间隔≈{required_interval:.0f}s）"
                        )
                        tunnel.reconnect_attempts += 1
                        tunnel.last_reconnect_time = now
                        self.connect_node(tag)
                continue

            # 检查隧道健康
            is_healthy = False

            if tunnel.tunnel_type == "wireguard":
                db = _get_db()
                node = db.get_peer_node(tag)
                interface = node.get("tunnel_interface") if node else None
                if interface:
                    is_healthy = self._check_wireguard_health(tag, interface)
            elif tunnel.tunnel_type == "xray":
                is_healthy = self._check_xray_health(tag)

            if not is_healthy:
                logger.warning(f"[{tag}] 隧道不健康，尝试重连")
                # 在断开前，向上游发送断连通知（如果有注册的链路）
                self._on_node_disconnected(tag)
                self.disconnect_node(tag)
                tunnel.status = "disconnected"


def main():
    parser = argparse.ArgumentParser(description="对等节点隧道管理器")
    parser.add_argument(
        "command",
        choices=["start", "stop", "reload", "status", "connect", "disconnect", "daemon"],
        help="操作命令"
    )
    parser.add_argument("--tag", help="节点标识符（用于 connect/disconnect）")
    parser.add_argument("--json", action="store_true", help="以 JSON 格式输出")

    args = parser.parse_args()
    manager = PeerTunnelManager()

    if args.command == "start":
        manager.start_all()
    elif args.command == "stop":
        manager.stop_all()
    elif args.command == "reload":
        manager.reload()
    elif args.command == "status":
        status = manager.get_status()
        if args.json:
            print(json.dumps(status, indent=2, default=str))
        else:
            if not status:
                print("没有配置的对等节点")
                return

            print(f"{'标识':<15} {'名称':<15} {'类型':<12} {'状态':<12} {'接口':<15} {'本地IP':<15}")
            print("-" * 84)
            for s in status:
                print(f"{s['tag']:<15} {s.get('name', ''):<15} {s['tunnel_type']:<12} "
                      f"{s['tunnel_status']:<12} {s.get('tunnel_interface', '-'):<15} "
                      f"{s.get('tunnel_local_ip', '-'):<15}")
    elif args.command == "connect":
        if not args.tag:
            print("错误: connect 命令需要 --tag 参数")
            sys.exit(1)
        success = manager.connect_node(args.tag)
        sys.exit(0 if success else 1)
    elif args.command == "disconnect":
        if not args.tag:
            print("错误: disconnect 命令需要 --tag 参数")
            sys.exit(1)
        success = manager.disconnect_node(args.tag)
        sys.exit(0 if success else 1)
    elif args.command == "daemon":
        manager.run_daemon()


if __name__ == "__main__":
    main()

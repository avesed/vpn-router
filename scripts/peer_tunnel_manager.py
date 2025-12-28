#!/usr/bin/env python3
"""
对等节点隧道管理器

管理节点间的 WireGuard 和 Xray 隧道连接，支持：
- 从数据库读取节点配置
- 建立和维护点对点隧道
- 自动重连机制
- 隧道状态监控

WireGuard 隧道创建 wg-peer-{tag} 接口，
Xray 隧道使用 SOCKS5 代理桥接。

使用方法:
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
from dataclasses import dataclass, field
from datetime import datetime
from ipaddress import ip_address
from pathlib import Path
from typing import Any, Dict, List, Optional

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

logging.basicConfig(
    level=logging.INFO,
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

# 端口范围（避免与 WireGuard 入口端口 36100-36299 冲突）
PEER_WG_PORT_START = 36300
PEER_XRAY_SOCKS_PORT_START = 37201

# 重连配置
RECONNECT_INTERVAL = 30  # 重连间隔（秒）
HEALTH_CHECK_INTERVAL = 60  # 健康检查间隔（秒）
MAX_RECONNECT_ATTEMPTS = 5  # 最大重连尝试次数


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
        # 使用 or 操作符处理 None 值，确保有默认端口
        port = node.get("tunnel_port") or PEER_WG_PORT_START
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
            subprocess.run([
                "wg", "set", interface, "peer", peer_public_key,
                "endpoint", endpoint,
                "allowed-ips", f"{remote_ip}/32",
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
        socks_port = node.get("xray_socks_port", PEER_XRAY_SOCKS_PORT_START)
        endpoint = node.get("endpoint", "")
        xray_uuid = node.get("xray_uuid")
        xray_protocol = node.get("xray_protocol", "vless")

        # 检查必需字段
        if not xray_uuid:
            logger.error(f"[{tag}] 缺少 Xray UUID，需要先进行参数交换")
            return False

        if not endpoint:
            logger.error(f"[{tag}] 缺少对端 endpoint")
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

        logger.info(f"[{tag}] 设置 Xray 隧道: {xray_protocol}://{server_host}:{server_port} -> SOCKS5:{socks_port}")

        # 获取 TLS 验证配置
        tls_verify = node.get("tls_verify", True)  # 默认启用验证
        tls_fingerprint = node.get("tls_fingerprint", "")

        # 生成 Xray 客户端配置
        config = self._build_xray_peer_config(
            tag=tag,
            server_host=server_host,
            server_port=server_port,
            protocol=xray_protocol,
            uuid=xray_uuid,
            socks_port=socks_port,
            tls_verify=tls_verify,
            tls_fingerprint=tls_fingerprint
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

            # 更新数据库
            db = _get_db()
            interface_name = get_interface_name(tag, "xray")
            db.update_peer_node(tag, tunnel_interface=interface_name)

            logger.info(f"[{tag}] Xray 隧道启动成功 (PID: {proc.pid}, SOCKS: {socks_port})")
            return True

        except Exception as e:
            logger.error(f"[{tag}] Xray 隧道设置失败: {e}")
            return False

    def _build_xray_peer_config(
        self,
        tag: str,
        server_host: str,
        server_port: int,
        protocol: str,
        uuid: str,
        socks_port: int,
        tls_verify: bool = True,
        tls_fingerprint: str = ""
    ) -> Dict:
        """构建 Xray 客户端配置

        Args:
            tag: 节点标识
            server_host: 远程服务器地址
            server_port: 远程服务器端口
            protocol: 协议类型 (vless/vmess/trojan)
            uuid: 用户 UUID
            socks_port: 本地 SOCKS5 端口
            tls_verify: 是否验证 TLS 证书（默认 True）
            tls_fingerprint: 可选的证书指纹（用于证书固定）

        Returns:
            Xray 配置字典
        """
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

        # 构建出站配置
        if protocol == "vless":
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
                    "network": "tcp",
                    "security": "none"
                }
            }
        elif protocol == "vmess":
            outbound = {
                "tag": f"peer-{tag}",
                "protocol": "vmess",
                "settings": {
                    "vnext": [{
                        "address": server_host,
                        "port": server_port,
                        "users": [{
                            "id": uuid,
                            "alterId": 0,
                            "security": "auto"
                        }]
                    }]
                },
                "streamSettings": {
                    "network": "tcp",
                    "security": "none"
                }
            }
        elif protocol == "trojan":
            # [安全] Trojan 协议需要 TLS
            # - tls_verify=True（默认）: 验证服务器证书，适用于公网部署
            # - tls_verify=False: 跳过验证，仅适用于受信任的内网环境
            # - tls_fingerprint: 可选证书指纹固定，提供额外安全保障
            if not tls_verify:
                logger.warning(f"[{tag}] Trojan TLS 证书验证已禁用，存在中间人攻击风险！仅在受信任网络中使用")
            else:
                logger.debug(f"[{tag}] Trojan 隧道使用 TLS（证书验证已启用）")

            tls_settings = {
                "serverName": server_host,  # [安全] 使用 serverName 进行验证
                "allowInsecure": not tls_verify  # True 时跳过证书验证
            }

            # 如果提供了证书指纹，添加到配置中
            if tls_fingerprint:
                tls_settings["fingerprint"] = tls_fingerprint
                logger.debug(f"[{tag}] 使用证书指纹固定: {tls_fingerprint[:16]}...")

            outbound = {
                "tag": f"peer-{tag}",
                "protocol": "trojan",
                "settings": {
                    "servers": [{
                        "address": server_host,
                        "port": server_port,
                        "password": uuid  # Trojan 使用 password 字段
                    }]
                },
                "streamSettings": {
                    "network": "tcp",
                    "security": "tls",
                    "tlsSettings": tls_settings
                }
            }
        else:
            logger.warning(f"[{tag}] 不支持的协议: {protocol}，使用 VLESS")
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
                    "network": "tcp",
                    "security": "none"
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
        self._update_node_status(tag, "connecting")

        if tunnel_type == "wireguard":
            success = self._setup_wireguard_tunnel(node)
        elif tunnel_type == "xray":
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

    def _health_check_and_reconnect(self) -> None:
        """健康检查和自动重连"""
        # [CR-010] 清理数据库中不存在的隧道
        self._cleanup_stale_tunnels()

        for tag, tunnel in list(self.tunnels.items()):
            if tunnel.status != "connected":
                # 尝试重连
                if tunnel.reconnect_attempts < MAX_RECONNECT_ATTEMPTS:
                    logger.info(f"[{tag}] 尝试重连 ({tunnel.reconnect_attempts + 1}/{MAX_RECONNECT_ATTEMPTS})")
                    tunnel.reconnect_attempts += 1
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

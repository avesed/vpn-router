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
import secrets
import signal
import subprocess
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Any

# 添加脚本目录到 Python 路径
sys.path.insert(0, str(Path(__file__).parent))

from db_helper import get_db

logging.basicConfig(
    level=logging.INFO,
    format='[xray-mgr] %(asctime)s %(levelname)s: %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger(__name__)

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

    def _generate_xray_config(self, config: Dict, users: List[Dict]) -> Dict:
        """生成 Xray 配置"""
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
            "api": {
                "tag": "api",
                "services": ["StatsService"]
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
            "inbounds": [
                # API 入站 (gRPC 端口)
                {
                    "tag": "api",
                    "port": XRAY_INGRESS_API_PORT,
                    "listen": "127.0.0.1",
                    "protocol": "dokodemo-door",
                    "settings": {
                        "address": "127.0.0.1"
                    }
                }
            ],
            "outbounds": [],
            "routing": {
                "domainStrategy": "AsIs",
                "rules": [
                    # API 路由规则
                    {
                        "type": "field",
                        "inboundTag": ["api"],
                        "outboundTag": "api"
                    }
                ]
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
                transport_type = config.get("transport_type", "tcp")
                if config.get("xtls_vision_enabled") and transport_type == "tcp":
                    client["flow"] = user.get("flow") or "xtls-rprx-vision"
                clients.append(client)

            inbound["settings"] = {
                "clients": clients,
                "decryption": "none"
            }

        elif protocol == "vmess":
            clients = []
            for user in users:
                email = user.get("email") or user.get("name") or "user"
                clients.append({
                    "id": user.get("uuid"),
                    "alterId": user.get("alter_id", 0),
                    "email": email,
                    "level": 0  # 关联到 policy.levels.0 以启用 per-user 统计
                })
            inbound["settings"] = {"clients": clients}

        elif protocol == "trojan":
            clients = []
            for user in users:
                email = user.get("email") or user.get("name") or "user"
                clients.append({
                    "password": user.get("password"),
                    "email": email,
                    "level": 0  # 关联到 policy.levels.0 以启用 per-user 统计
                })
            inbound["settings"] = {"clients": clients}

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

        # 出站配置 - 通过 SOCKS5 连接到 sing-box 路由引擎
        # 使用 SOCKS5 代替 WireGuard，避免复杂的路由问题
        XRAY_SOCKS_PORT = 38001  # sing-box 的 SOCKS5 入站端口 (xray-in)
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
        logger.info(f"Xray 配置 SOCKS5 出站: 127.0.0.1:{XRAY_SOCKS_PORT}")

        # 直连出口（备用）
        xray_config["outbounds"].append({
            "tag": "freedom",
            "protocol": "freedom",
            "settings": {}
        })

        # 路由配置
        # 保留 API 路由规则，其他流量通过 SOCKS5 到 sing-box 路由引擎
        # 注意: routing 已在基础配置中定义，包含 API 路由规则
        # 无需添加其他规则，默认走第一个 outbound (socks-out)

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

        # 生成配置
        try:
            xray_config = self._generate_xray_config(config, users)
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

        # 生成新配置
        try:
            xray_config = self._generate_xray_config(config, users)
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
        """以守护进程模式运行"""
        self._running = True
        logger.info("Xray 管理器启动（守护模式）")

        # 启动 Xray
        await self.start()

        # 监控循环
        while self._running:
            await asyncio.sleep(10)

            # 检查进程健康
            if self.process.status == "running" and not self._is_process_alive():
                logger.warning("Xray 进程已退出，尝试重启")
                await self.start()

        # 清理
        await self.stop()
        logger.info("Xray 管理器已停止")

    def stop_daemon(self):
        """停止守护进程"""
        self._running = False


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

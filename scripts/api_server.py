#!/usr/bin/env python3
"""FastAPI 服务：为前端提供 sing-box 网关管理接口"""
import asyncio
import hashlib
import ipaddress
import json
import logging
import os
import re
import secrets
import shutil
import signal
import socket
import subprocess
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import base64
import io

# 加密支持
try:
    from cryptography.fernet import Fernet
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    HAS_CRYPTO = True
except ImportError:
    HAS_CRYPTO = False

import requests
import yaml
from fastapi import Body, FastAPI, Header, HTTPException, Query, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, PlainTextResponse, Response, StreamingResponse
from pydantic import BaseModel, Field, validator
from starlette.middleware.base import BaseHTTPMiddleware

# JWT 和密码哈希支持
import bcrypt
import jwt

try:
    import qrcode
    HAS_QRCODE = True
except ImportError:
    HAS_QRCODE = False

# 数据库支持
import sys
sys.path.insert(0, str(ENTRY_DIR if 'ENTRY_DIR' in dir() else Path("/usr/local/bin")))
try:
    from db_helper import get_db
    HAS_DATABASE = True
except ImportError:
    HAS_DATABASE = False
    print("WARNING: Database helper not available, falling back to JSON storage")

try:
    # [Xray-lite] Only import VLESS-related functions; VMess/Trojan removed
    from v2ray_uri_parser import parse_v2ray_uri, generate_vless_uri
    HAS_V2RAY_PARSER = True
except ImportError:
    HAS_V2RAY_PARSER = False
    print("WARNING: V2Ray URI parser not available")

try:
    from key_manager import KeyManager
    HAS_KEY_MANAGER = True
except ImportError:
    HAS_KEY_MANAGER = False
    print("WARNING: Key manager not available, v2.0 backup format disabled")

# [安全] 导入主机名验证函数和隧道管理函数
try:
    from peer_tunnel_manager import (
        validate_hostname,
        create_pending_wireguard_interface,
        teardown_pending_wireguard_interface,
        rename_wireguard_interface,
        update_wireguard_peer_endpoint,
        get_interface_name,
        create_wireguard_tunnel_with_endpoint,
        wait_for_wireguard_handshake,
        PEER_TUNNEL_PORT_MIN,
    )
    HAS_HOSTNAME_VALIDATOR = True
    HAS_PENDING_TUNNEL = True
except ImportError:
    HAS_HOSTNAME_VALIDATOR = False
    HAS_PENDING_TUNNEL = False
    PEER_TUNNEL_PORT_MIN = 36200  # Phase 6: 回退值 (must match valid range 36200-36299)
    # 回退实现：基本验证
    def validate_hostname(hostname: str) -> bool:
        """回退实现：基本主机名验证"""
        if not hostname:
            return False
        # 尝试解析为 IP
        try:
            ipaddress.ip_address(hostname)
            return True
        except ValueError:
            pass
        # 基本主机名正则
        hostname_pattern = re.compile(
            r'^(?=.{1,253}$)(?!-)[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?'
            r'(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$'
        )
        return bool(hostname_pattern.match(hostname))

# 离线配对系统
try:
    from peer_pairing import PairingCodeGenerator, PairingManager
    HAS_PAIRING = True
except ImportError:
    HAS_PAIRING = False
    print("WARNING: Peer pairing module not available")

# DSCP 管理器 (Phase 4 - 入口节点 DSCP 规则设置)
try:
    from dscp_manager import get_dscp_manager, ENTRY_ROUTING_MARK_BASE
    HAS_DSCP_MANAGER = True
except ImportError:
    HAS_DSCP_MANAGER = False
    ENTRY_ROUTING_MARK_BASE = 100  # 回退值
    print("WARNING: DSCP manager not available")

# Phase 7.7: Rust Router Client for DNS API
try:
    from rust_router_client import RustRouterClient
    HAS_RUST_ROUTER_CLIENT = True
except ImportError:
    HAS_RUST_ROUTER_CLIENT = False
    print("WARNING: Rust router client not available, DNS API disabled")

CONFIG_PATH = Path(os.environ.get("SING_BOX_CONFIG", "/etc/sing-box/sing-box.json"))
GENERATED_CONFIG_PATH = Path(os.environ.get("SING_BOX_GENERATED_CONFIG", "/etc/sing-box/sing-box.generated.json"))
GEODATA_DB_PATH = Path(os.environ.get("GEODATA_DB_PATH", "/etc/sing-box/geoip-geodata.db"))
USER_DB_PATH = Path(os.environ.get("USER_DB_PATH", "/etc/sing-box/user-config.db"))
SQLCIPHER_KEY = os.environ.get("SQLCIPHER_KEY")  # SQLCipher 加密密钥
PIA_PROFILES_FILE = Path(os.environ.get("PIA_PROFILES_FILE", "/etc/sing-box/pia/profiles.yml"))
PIA_PROFILES_OUTPUT = Path(os.environ.get("PIA_PROFILES_OUTPUT", "/etc/sing-box/pia-profiles.json"))
WG_CONFIG_PATH = Path(os.environ.get("WG_CONFIG_PATH", "/etc/sing-box/wireguard/server.json"))
CUSTOM_RULES_FILE = Path(os.environ.get("CUSTOM_RULES_FILE", "/etc/sing-box/custom-rules.json"))
DOMAIN_CATALOG_FILE = Path(os.environ.get("DOMAIN_CATALOG_FILE", "/etc/sing-box/domain-catalog.json"))
DOMAIN_LIST_DIR = Path(os.environ.get("DOMAIN_LIST_DIR", "/etc/sing-box/domain-list/data"))
IP_CATALOG_FILE = Path(os.environ.get("IP_CATALOG_FILE", "/etc/sing-box/ip-catalog.json"))
GEOIP_CATALOG_FILE = Path(os.environ.get("GEOIP_CATALOG_FILE", "/etc/sing-box/geoip-catalog.json"))
GEOIP_DIR = Path(os.environ.get("GEOIP_DIR", "/etc/sing-box/geoip"))
IP_LIST_DIR = Path(os.environ.get("IP_LIST_DIR", "/etc/sing-box/ip-list/country"))

# ============ 内存加载的目录数据 ============
_DOMAIN_CATALOG: Dict[str, Any] = {}
_GEOIP_CATALOG: Dict[str, Any] = {}
CUSTOM_CATEGORY_ITEMS_FILE = Path(os.environ.get("CUSTOM_CATEGORY_ITEMS_FILE", "/etc/sing-box/custom-category-items.json"))
SETTINGS_FILE = Path(os.environ.get("SETTINGS_FILE", "/etc/sing-box/settings.json"))
ENTRY_DIR = Path("/usr/local/bin")


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
        logging.warning(f"Invalid integer value '{value}' for {name}, using default {default}")
        return default


# Port and subnet configuration from environment
DEFAULT_WG_PORT = _safe_int_env("WG_LISTEN_PORT", 36100)
DEFAULT_WEB_PORT = _safe_int_env("WEB_PORT", 36000)
DEFAULT_WG_SUBNET = os.environ.get("WG_INGRESS_SUBNET", "10.25.0.1/24")

# Internal service ports (configurable via environment)
# These ports are used by internal services and should not be allocated for peer tunnels
DEFAULT_TPROXY_PORT = _safe_int_env("TPROXY_PORT", 7893)
DEFAULT_API_BACKEND_PORT = _safe_int_env("API_BACKEND_PORT", 8000)
DEFAULT_CLASH_API_PORT = _safe_int_env("CLASH_API_PORT", 9090)
DEFAULT_V2RAY_STATS_PORT = _safe_int_env("V2RAY_STATS_PORT", 10085)

# Port range configurations (configurable via environment)
PEER_TUNNEL_PORT_MIN = _safe_int_env("PEER_TUNNEL_PORT_MIN", 36200)
PEER_TUNNEL_PORT_MAX = _safe_int_env("PEER_TUNNEL_PORT_MAX", 36299)
V2RAY_SOCKS_PORT_BASE = _safe_int_env("V2RAY_SOCKS_PORT_BASE", 37101)
WARP_MASQUE_PORT_BASE = _safe_int_env("WARP_MASQUE_PORT_BASE", 38001)
SPEEDTEST_PORT_BASE = _safe_int_env("SPEEDTEST_PORT_BASE", 39001)

# Issue 7 Fix: Reserved ports that cannot be used for peer tunnels
# Built dynamically from environment-configured ports
RESERVED_PORTS = {
    DEFAULT_WEB_PORT: "Web UI/API",
    DEFAULT_WG_PORT: "WireGuard ingress",
    DEFAULT_TPROXY_PORT: "sing-box TPROXY",
    DEFAULT_API_BACKEND_PORT: "FastAPI backend",
    DEFAULT_CLASH_API_PORT: "sing-box Clash API",
    DEFAULT_V2RAY_STATS_PORT: "V2Ray Stats API",
}


def _validate_port_configuration() -> None:
    """Validate that configured ports don't conflict with each other.

    Called at module initialization to detect configuration errors early.
    Logs errors for any port conflicts found.
    """
    ports_used: Dict[int, str] = {}
    port_configs = [
        (DEFAULT_WEB_PORT, "WEB_PORT"),
        (DEFAULT_WG_PORT, "WG_LISTEN_PORT"),
        (DEFAULT_TPROXY_PORT, "TPROXY_PORT"),
        (DEFAULT_API_BACKEND_PORT, "API_BACKEND_PORT"),
        (DEFAULT_CLASH_API_PORT, "CLASH_API_PORT"),
        (DEFAULT_V2RAY_STATS_PORT, "V2RAY_STATS_PORT"),
    ]
    for port, name in port_configs:
        if port in ports_used:
            logging.error(f"Port conflict: {name}={port} conflicts with {ports_used[port]}")
        else:
            ports_used[port] = name


# Call at module load to detect configuration errors early
_validate_port_configuration()


def _validate_not_reserved_port(port: int) -> None:
    """Issue 7 Fix: Validate port is not reserved for other services.

    Args:
        port: Port number to validate

    Raises:
        HTTPException: If port is reserved
    """
    if port in RESERVED_PORTS:
        raise HTTPException(
            status_code=400,
            detail=f"端口 {port} 已被 {RESERVED_PORTS[port]} 占用，请使用 36200-36299 范围内的端口"
        )


def _allocate_peer_tunnel_port(db) -> int:
    """Issue 7/10 Fix: Safely allocate a peer tunnel port.

    Args:
        db: Database connection

    Returns:
        Allocated port number

    Raises:
        HTTPException: If port allocation fails (exhausted or error)
    """
    try:
        port = db.get_next_peer_tunnel_port()
        if port is None:
            raise HTTPException(
                status_code=503,
                detail=f"无法分配隧道端口：端口范围 {PEER_TUNNEL_PORT_MIN}-{PEER_TUNNEL_PORT_MAX} 已耗尽"
            )
        return port
    except ValueError as e:
        # get_next_peer_tunnel_port() raises ValueError for overflow
        raise HTTPException(
            status_code=503,
            detail=f"隧道端口分配失败: {e}"
        )


def _get_db():
    """获取加密数据库连接（单例模式）

    自动使用 SQLCIPHER_KEY 环境变量进行加密。
    """
    return get_db(str(GEODATA_DB_PATH), str(USER_DB_PATH), SQLCIPHER_KEY)


def _get_local_node_tag(db) -> str:
    """Phase 11-Cascade: 获取本节点标识符

    优先使用数据库中存储的 node_tag，如果不存在则使用 hostname。
    返回值会被规范化为小写并替换非法字符。

    Args:
        db: 数据库连接

    Returns:
        本节点标识符
    """
    import socket
    import re

    # 尝试从设置中获取 node_tag
    try:
        settings = db.get_all_settings()
        stored_tag = settings.get("node_tag", "").strip()
        if stored_tag:
            return stored_tag
    except Exception:
        pass

    # 使用 hostname 作为后备
    hostname = socket.gethostname()

    # 规范化: 小写，只保留 a-z0-9-，确保以字母开头
    normalized = re.sub(r'[^a-z0-9-]', '-', hostname.lower())
    normalized = re.sub(r'-+', '-', normalized).strip('-')

    # 确保以字母开头
    if not normalized or not normalized[0].isalpha():
        normalized = 'node-' + normalized

    return normalized[:64]  # 限制长度


def _get_available_outbounds(db) -> list:
    """获取所有可用出口列表

    从数据库收集所有启用的出口，包括：
    - direct（默认直连）
    - PIA WireGuard 线路
    - 自定义 WireGuard 出口
    - Direct 出口（接口/IP 绑定）
    - OpenVPN 出口
    - V2Ray 出口
    - WARP 出口
    - 出口组（负载均衡/故障转移）
    """
    available = ["direct"]

    # PIA profiles
    for profile in db.get_pia_profiles(enabled_only=True):
        if profile.get("private_key") and profile.get("name"):
            available.append(profile["name"])

    # Custom WireGuard egress
    for egress in db.get_custom_egress_list(enabled_only=True):
        if egress.get("tag"):
            available.append(egress["tag"])

    # Direct egress (interface/IP binding)
    for egress in db.get_direct_egress_list(enabled_only=True):
        if egress.get("tag"):
            available.append(egress["tag"])

    # OpenVPN egress
    for egress in db.get_openvpn_egress_list(enabled_only=True):
        if egress.get("tag"):
            available.append(egress["tag"])

    # V2Ray egress
    for egress in db.get_v2ray_egress_list(enabled_only=True):
        if egress.get("tag"):
            available.append(egress["tag"])

    # WARP egress
    for egress in db.get_warp_egress_list(enabled_only=True):
        if egress.get("tag"):
            available.append(egress["tag"])

    # Outbound groups
    for group in db.get_outbound_groups(enabled_only=True):
        if group.get("tag"):
            available.append(group["tag"])

    # Node chains (multi-hop)
    for chain in db.get_node_chains(enabled_only=True):
        if chain.get("tag"):
            available.append(chain['tag'])

    return available


def get_subnet_prefix(subnet_address: str = None) -> str:
    """从子网地址提取前缀（如 10.25.0.1/24 -> 10.25.0.）

    如果未提供地址，使用 DEFAULT_WG_SUBNET
    M19 修复: 添加输入验证，防止格式错误导致异常
    """
    addr_str = subnet_address or DEFAULT_WG_SUBNET

    # 验证基本格式: 需要包含 "/" 和至少一个 "."
    if "/" not in addr_str or "." not in addr_str.split("/")[0]:
        logging.warning(f"Invalid subnet format: {addr_str}, using default")
        addr_str = DEFAULT_WG_SUBNET

    try:
        ip_part = addr_str.split("/")[0]
        octets = ip_part.split(".")
        # 验证是否有 4 个八位组
        if len(octets) != 4:
            logging.warning(f"Invalid IP format: {ip_part}, using default")
            ip_part = DEFAULT_WG_SUBNET.split("/")[0]
            octets = ip_part.split(".")
        return ".".join(octets[:3]) + "."
    except Exception as e:
        logging.warning(f"Error parsing subnet {addr_str}: {e}, using default")
        return DEFAULT_WG_SUBNET.split("/")[0].rsplit(".", 1)[0] + "."

def get_default_peer_ip() -> str:
    """获取默认的 peer IP（基于 DEFAULT_WG_SUBNET）"""
    prefix = get_subnet_prefix(DEFAULT_WG_SUBNET)
    return f"{prefix}2/32"

PIA_SERVERLIST_URL = "https://serverlist.piaservers.net/vpninfo/servers/v6"

# ============ 规则类型验证常量 ============
# sing-box 支持的协议嗅探类型
VALID_PROTOCOLS = {
    "http", "tls", "quic", "bittorrent", "stun", "dtls", "ssh", "rdp", "dns", "ntp"
}
# sing-box 支持的网络类型
VALID_NETWORKS = {"tcp", "udp"}
# 支持的路由规则类型
VALID_RULE_TYPES = {
    "domain", "domain_keyword", "ip", "domain_list", "country",
    "protocol", "network", "port", "port_range"  # 新增协议/端口规则
}

CONFIG_LOCK = threading.Lock()

# 缓存 PIA 地区列表（有效期 1 小时）
_pia_regions_cache: Dict[str, Any] = {"data": None, "timestamp": 0}

# 缓存 WireGuard 子网前缀（避免频繁数据库查询）
_cached_wg_subnet_prefix: str = get_subnet_prefix(DEFAULT_WG_SUBNET)

def refresh_wg_subnet_cache() -> str:
    """刷新 WireGuard 子网前缀缓存，从数据库读取当前配置"""
    global _cached_wg_subnet_prefix
    try:
        db = _get_db()
        server = db.get_wireguard_server()
        if server and server.get("address"):
            _cached_wg_subnet_prefix = get_subnet_prefix(server.get("address"))
        else:
            _cached_wg_subnet_prefix = get_subnet_prefix(DEFAULT_WG_SUBNET)
    except Exception:
        _cached_wg_subnet_prefix = get_subnet_prefix(DEFAULT_WG_SUBNET)
    return _cached_wg_subnet_prefix

def get_cached_wg_subnet_prefix() -> str:
    """获取缓存的 WireGuard 子网前缀"""
    return _cached_wg_subnet_prefix

# ============ 安全凭据存储 ============
# 使用类变量存储凭据，避免暴露在 /proc/<pid>/environ
# 同时持久化到加密数据库，容器重启后保留
class _CredentialStore:
    """
    安全的凭据存储类（带数据库持久化）。

    凭据存储在进程内存中，避免通过 /proc/<pid>/environ 暴露。
    同时持久化到 SQLCipher 加密数据库，容器重启后自动恢复。
    """
    _credentials: Dict[str, str] = {}
    _lock = threading.Lock()
    _db_loaded = False  # 标记是否已从数据库加载

    @classmethod
    def _load_from_db(cls) -> None:
        """从数据库加载凭据（懒加载，仅执行一次）"""
        if cls._db_loaded:
            return
        cls._db_loaded = True

        try:
            if HAS_DATABASE and USER_DB_PATH.exists():
                db = _get_db()
                creds = db.get_pia_credentials()
                if creds:
                    cls._credentials["PIA_USERNAME"] = creds["username"]
                    cls._credentials["PIA_PASSWORD"] = creds["password"]
                    print("[CredentialStore] PIA credentials loaded from database")
        except Exception as e:
            print(f"[CredentialStore] Failed to load credentials from database: {e}")

    @classmethod
    def _save_pia_to_db(cls) -> None:
        """保存 PIA 凭据到数据库"""
        try:
            if HAS_DATABASE and USER_DB_PATH.exists():
                username = cls._credentials.get("PIA_USERNAME")
                password = cls._credentials.get("PIA_PASSWORD")
                if username and password:
                    db = _get_db()
                    db.set_pia_credentials(username, password)
                    print("[CredentialStore] PIA credentials saved to database")
        except Exception as e:
            print(f"[CredentialStore] Failed to save credentials to database: {e}")

    @classmethod
    def _delete_pia_from_db(cls) -> None:
        """从数据库删除 PIA 凭据"""
        try:
            if HAS_DATABASE and USER_DB_PATH.exists():
                db = _get_db()
                db.delete_pia_credentials()
                print("[CredentialStore] PIA credentials deleted from database")
        except Exception as e:
            print(f"[CredentialStore] Failed to delete credentials from database: {e}")

    @classmethod
    def set(cls, key: str, value: str) -> None:
        """设置凭据"""
        with cls._lock:
            cls._credentials[key] = value
            # 如果是 PIA 凭据，同步到数据库
            if key in ("PIA_USERNAME", "PIA_PASSWORD"):
                cls._save_pia_to_db()

    @classmethod
    def get(cls, key: str, default: Optional[str] = None) -> Optional[str]:
        """获取凭据"""
        with cls._lock:
            # 首次访问时从数据库加载
            cls._load_from_db()
            # 优先从内存存储获取，回退到环境变量（兼容容器启动时的环境变量）
            return cls._credentials.get(key) or os.environ.get(key, default)

    @classmethod
    def delete(cls, key: str) -> None:
        """删除凭据"""
        with cls._lock:
            cls._credentials.pop(key, None)
            # 如果删除的是 PIA 凭据，也从数据库删除
            if key in ("PIA_USERNAME", "PIA_PASSWORD"):
                cls._delete_pia_from_db()

    @classmethod
    def clear(cls) -> None:
        """清除所有凭据"""
        with cls._lock:
            cls._credentials.clear()
            cls._delete_pia_from_db()

    @classmethod
    def has(cls, key: str) -> bool:
        """检查凭据是否存在"""
        with cls._lock:
            cls._load_from_db()
            return bool(cls._credentials.get(key) or os.environ.get(key))

    @classmethod
    def get_env_for_subprocess(cls) -> Dict[str, str]:
        """
        获取用于 subprocess 的环境变量字典。
        将内存中的凭据合并到环境变量中供子进程使用。
        """
        env = os.environ.copy()
        with cls._lock:
            cls._load_from_db()
            env.update(cls._credentials)
        return env


# 便捷访问函数
def get_pia_credentials() -> tuple[Optional[str], Optional[str]]:
    """获取 PIA 凭据"""
    return _CredentialStore.get("PIA_USERNAME"), _CredentialStore.get("PIA_PASSWORD")


def set_pia_credentials(username: str, password: str) -> None:
    """设置 PIA 凭据（同时保存到数据库）"""
    _CredentialStore.set("PIA_USERNAME", username)
    _CredentialStore.set("PIA_PASSWORD", password)


def has_pia_credentials() -> bool:
    """检查是否有 PIA 凭据"""
    username, password = get_pia_credentials()
    return bool(username and password)


# ============ API 速率限制 (H3) ============
# 简单的内存速率限制器，无需额外依赖
_rate_limit_data: Dict[str, List[float]] = {}  # {client_ip: [timestamp1, timestamp2, ...]}
_rate_limit_lock = threading.Lock()
# 速率限制配置
_RATE_LIMIT_GENERAL = 300  # 一般 API: 每分钟 300 次（放宽以支持频繁操作）
_RATE_LIMIT_LOGIN = 10  # 登录 API: 每分钟 10 次
_RATE_LIMIT_WINDOW = 60  # 时间窗口（秒）


def _get_client_ip(request: Request) -> str:
    """获取客户端 IP 地址（用于普通 API 请求）

    对于通过 nginx 代理的请求，优先使用 X-Forwarded-For/X-Real-IP 头。
    注意：此函数不应用于安全敏感的隧道认证，那些场景应使用 _get_direct_client_ip()。
    """
    # 优先使用 X-Forwarded-For（nginx 代理设置）
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        return forwarded.split(",")[0].strip()
    # 其次使用 X-Real-IP
    real_ip = request.headers.get("x-real-ip")
    if real_ip:
        return real_ip
    # 最后使用直连 IP
    return request.client.host if request.client else "unknown"


def _get_direct_client_ip(request: Request) -> str:
    """获取直连客户端 IP 地址（用于隧道认证，忽略代理头）

    安全关键：此函数专门用于 /api/peer-tunnel/* 端点的身份验证。
    这些端点使用隧道 IP 作为身份证明，因此必须使用实际的 TCP 连接 IP，
    不能信任任何可被伪造的 HTTP 头（X-Forwarded-For, X-Real-IP 等）。

    Returns:
        直接 TCP 连接的客户端 IP 地址
    """
    if request.client and request.client.host:
        return request.client.host
    return "unknown"


def _check_rate_limit(client_ip: str, limit: int = _RATE_LIMIT_GENERAL) -> bool:
    """
    检查是否超过速率限制
    返回 True 表示允许请求，False 表示超限
    """
    now = time.time()
    cutoff = now - _RATE_LIMIT_WINDOW

    with _rate_limit_lock:
        if client_ip not in _rate_limit_data:
            _rate_limit_data[client_ip] = []

        # 清理过期记录
        _rate_limit_data[client_ip] = [
            ts for ts in _rate_limit_data[client_ip] if ts > cutoff
        ]

        # 检查是否超限
        if len(_rate_limit_data[client_ip]) >= limit:
            return False

        # 记录本次请求
        _rate_limit_data[client_ip].append(now)

        # 清理长时间不活跃的 IP（防止内存泄漏）
        if len(_rate_limit_data) > 10000:
            # 保留最近活跃的 5000 个 IP
            sorted_ips = sorted(
                _rate_limit_data.keys(),
                key=lambda ip: max(_rate_limit_data[ip]) if _rate_limit_data[ip] else 0,
                reverse=True
            )
            for ip in sorted_ips[5000:]:
                del _rate_limit_data[ip]

        return True


# Alias for peer node API rate limiting (previously used PSK-specific rate limit)
_check_api_rate_limit = _check_rate_limit


def _clear_rate_limit():
    """清除所有速率限制计数

    在备份导入后调用，因为：
    1. JWT secret 可能已改变，用户需要重新登录
    2. 之前的登录尝试次数不应影响新导入的配置
    """
    global _rate_limit_data
    with _rate_limit_lock:
        _rate_limit_data.clear()
    print("[api] Rate limit data cleared")


# ============ 流量统计 ============
# 累计流量统计（按出口分组）- 从 V2Ray API 获取精确数据
_traffic_stats: Dict[str, Dict[str, int]] = {}  # {outbound: {download: int, upload: int}}
# 当前速率（bytes/s）
_traffic_rates: Dict[str, Dict[str, float]] = {}  # {outbound: {download_rate: float, upload_rate: float}}
# 速率历史记录（保留24小时）
_rate_history: List[Dict[str, Any]] = []  # [{timestamp: int, rates: {outbound: rate_kb}}]
_traffic_stats_lock = threading.Lock()
_POLL_INTERVAL = 1  # 轮询间隔（秒）
_RATE_WINDOW = 1  # 速率计算窗口（秒）- 1秒窗口更准确反映瞬时速率
_HISTORY_INTERVAL = 1  # 历史记录间隔（秒）- 1秒更新，支持实时推进图表
_MAX_HISTORY_SECONDS = 24 * 60 * 60  # 保留24小时历史
_MAX_HISTORY_ENTRIES = 90000  # 最大条目数 (C9: 内存泄漏防护, ~86400 for 24h + buffer)
_last_history_time = 0  # 上次记录历史的时间
_rate_samples: List[Dict[str, Dict[str, int]]] = []  # 最近 N 个流量样本用于计算速率

# Outbounds 列表缓存（避免锁内 DB 查询）
_outbounds_cache: List[str] = []
_outbounds_cache_time: float = 0
_OUTBOUNDS_CACHE_TTL = 10  # 10秒刷新一次

# V2Ray API 客户端（懒加载）
_v2ray_client = None
# Xray 出站 V2Ray API 客户端（懒加载，用于获取 V2Ray 出口的流量统计）
_xray_egress_client = None
# Xray 出站 API 端口
XRAY_EGRESS_API_PORT = 10086
# Xray 入站 V2Ray API 客户端（懒加载，用于获取 V2Ray 入口用户的流量统计）
_xray_ingress_client = None
# Xray 入站 API 端口
XRAY_INGRESS_API_PORT = 10087

# V2Ray 用户活跃度缓存: {email: {"last_seen": timestamp, "upload": bytes, "download": bytes}}
# 用于跟踪用户在线状态
_v2ray_user_activity: Dict[str, Dict[str, Any]] = {}
_v2ray_user_activity_lock = threading.Lock()
_V2RAY_USER_ONLINE_TIMEOUT = 60  # 60 秒无流量变化视为离线

# ============ 级联通知去重 ============
# 防止循环通知：{notification_id: timestamp}
_cascade_notification_cache: Dict[str, float] = {}
_cascade_notification_lock = threading.Lock()
_CASCADE_NOTIFICATION_TTL = 300  # 5 分钟去重窗口
_CASCADE_NOTIFICATION_MAX_SIZE = 1000  # 最大缓存条目数

# Peer activity cache: {ip: {"last_seen": timestamp, "rx": bytes, "tx": bytes}}
# Used to track peer online status even when no active connections exist
_peer_activity_cache: Dict[str, Dict[str, Any]] = {}
_peer_activity_lock = threading.Lock()
_PEER_ONLINE_GRACE_PERIOD = 120  # Consider peer online for 120s after last activity

# clash_api 响应缓存（避免超时阻塞）
_clash_api_cache: Dict = {}
_clash_api_cache_time: float = 0
_CLASH_API_CACHE_TTL = 2  # 缓存有效期 2 秒
_CLASH_API_TIMEOUT = 0.5  # 超时从 2s 改为 0.5s

# Adblock 日志增量扫描（避免全量扫描大文件）
_adblock_count: int = 0
_adblock_log_position: int = 0
_adblock_log_inode: int = 0  # 用于检测日志轮转


# ============ Phase 2 Validation Helpers ============

def _parse_chain_hops(chain: Dict[str, Any], raise_on_error: bool = True) -> List[str]:
    """
    安全解析链路 hops，处理字符串和列表两种格式。

    修复 Issue 11 和 Issue 12：统一处理 hops 字段的类型不一致问题，
    并在解析失败时提供清晰的错误信息而非静默失败。

    Args:
        chain: 从数据库获取的链路字典
        raise_on_error: 如果为 True，解析错误时抛出 HTTPException；否则返回空列表

    Returns:
        节点标签列表
    """
    hops = chain.get("hops", [])
    chain_tag = chain.get("tag", "unknown")

    if isinstance(hops, list):
        return [str(h) for h in hops]

    if isinstance(hops, str):
        if not hops.strip():
            return []
        try:
            parsed = json.loads(hops)
            if not isinstance(parsed, list):
                if raise_on_error:
                    raise HTTPException(
                        status_code=500,
                        detail=f"链路 '{chain_tag}' 的 hops 格式错误：应为数组，实际为 {type(parsed).__name__}"
                    )
                logging.error(f"[chains] 链路 '{chain_tag}' hops 不是数组: {type(parsed)}")
                return []
            return [str(h) for h in parsed]
        except json.JSONDecodeError as e:
            if raise_on_error:
                raise HTTPException(
                    status_code=500,
                    detail=f"链路 '{chain_tag}' 的 hops JSON 解析失败：{e}"
                )
            logging.error(f"[chains] 链路 '{chain_tag}' hops JSON 解析失败: {e}")
            return []

    if raise_on_error:
        raise HTTPException(
            status_code=500,
            detail=f"链路 '{chain_tag}' 的 hops 类型无效：{type(hops).__name__}"
        )
    logging.error(f"[chains] 链路 '{chain_tag}' hops 类型无效: {type(hops)}")
    return []


def _verify_chain_membership(
    db,
    chain_tag: str,
    requesting_node_tag: str,
    source_node: Optional[str] = None
) -> tuple:
    """Phase 11-Fix.V.3: 验证请求节点是否为链路成员

    安全检查：确保只有链路中的节点可以注册/注销链路路由，
    防止恶意节点注册任意路由。

    Phase 11-Fix.V.3 修复:
    - 安全修复: hops 解析失败时 fail-closed（原来是 fail-open）
    - 功能修复: 支持入口节点调用（入口节点不在 hops 中，但是 source_node）
    - Chain 不存在时: 如果 source_node 匹配请求节点，允许（入口节点直接调用终端）

    Args:
        db: 数据库连接
        chain_tag: 链路标签
        requesting_node_tag: 发起请求的节点标签
        source_node: 可选，请求中指定的来源节点（入口节点标识）

    Returns:
        (is_member: bool, error_message: Optional[str])
        - (True, None): 验证通过
        - (False, "Chain not found"): 链路不存在且不是入口节点调用
        - (False, "Invalid configuration"): hops 配置无效
        - (False, "Not authorized"): 节点无权限
    """
    chain = db.get_node_chain(chain_tag)

    if not chain:
        # Chain 不存在于本地数据库
        # 场景 1: 入口节点直接调用终端节点
        # 如果 source_node 与 requesting_node_tag 匹配，说明是入口节点直接调用
        if source_node and source_node == requesting_node_tag:
            logging.info(
                f"[chain-auth] 允许入口节点 '{source_node}' 在终端注册链路 '{chain_tag}' "
                "(chain 仅存在于入口节点)"
            )
            return True, None

        # 场景 2: 中继节点转发请求（Phase 11-Fix.Z）
        # 当中继节点（如 node2）代表入口节点（如 node1）向终端节点（如 node3）转发请求时：
        # - requesting_node_tag = "node2"（通过隧道认证的实际调用者）
        # - source_node = "node1"（原始入口节点）
        # 如果 requesting_node_tag 是已连接的 peer，且 source_node 已指定，允许转发
        if source_node and source_node != requesting_node_tag:
            relay_peer = db.get_peer_node(requesting_node_tag)
            if relay_peer and relay_peer.get("tunnel_status") == "connected":
                logging.info(
                    f"[chain-auth] 允许中继节点 '{requesting_node_tag}' 代表入口节点 '{source_node}' "
                    f"在终端注册链路 '{chain_tag}'"
                )
                return True, None

        # Fail-closed: 拒绝未授权的请求
        logging.warning(
            f"[chain-auth] 链路 '{chain_tag}' 不存在，拒绝节点 '{requesting_node_tag}' 的请求"
        )
        return False, f"Chain '{chain_tag}' not found"

    # 解析 hops
    hops = _parse_chain_hops(chain, raise_on_error=False)

    # Phase 11-Fix.V.3 安全修复: fail-closed（原来是 fail-open 安全漏洞）
    if not hops:
        logging.error(
            f"[chain-auth] 链路 '{chain_tag}' hops 解析失败，拒绝访问 (fail-closed)"
        )
        return False, f"Chain '{chain_tag}' has invalid hops configuration"

    # 检查请求节点是否在 hops 中（中继/终端节点）
    if requesting_node_tag in hops:
        return True, None

    # 检查是否为入口节点（入口节点创建链路但不在 hops 中）
    # source_node 参数允许入口节点标识自己
    if source_node and source_node == requesting_node_tag:
        logging.debug(
            f"[chain-auth] 允许入口节点 '{source_node}' 操作链路 '{chain_tag}'"
        )
        return True, None

    logging.warning(
        f"[chain-auth] 节点 '{requesting_node_tag}' 不是链路 '{chain_tag}' 的成员. "
        f"链路成员: {hops}, source_node: {source_node}"
    )
    return False, f"Node '{requesting_node_tag}' is not authorized for chain '{chain_tag}'"


def _validate_tunnel_ip(ip: str, subnet: str = "10.200.200.0/24") -> bool:
    """
    验证隧道 IP 是否在预期范围内。

    修复 Issue 15：在导入配对信息时验证隧道 IP 地址合法性。

    Args:
        ip: 要验证的 IP 地址
        subnet: 预期的子网范围，默认为 10.200.200.0/24

    Returns:
        IP 是否在预期范围内
    """
    try:
        import ipaddress
        addr = ipaddress.ip_address(ip)
        network = ipaddress.ip_network(subnet)
        return addr in network
    except ValueError:
        return False


# ============ 认证相关模型 ============

class SetupRequest(BaseModel):
    """首次设置管理员密码"""
    password: str = Field(..., min_length=8, description="Admin password (min 8 chars)")


class LoginRequest(BaseModel):
    """登录请求"""
    password: str = Field(..., description="Admin password")


class TokenResponse(BaseModel):
    """JWT token 响应"""
    access_token: str
    token_type: str = "bearer"
    expires_in: int


# ============ 其他模型 ============

class WireGuardPeerModel(BaseModel):
    address: str
    port: int = Field(..., ge=1, le=65535)
    public_key: str
    pre_shared_key: Optional[str] = None
    allowed_ips: Optional[List[str]] = None
    persistent_keepalive_interval: Optional[int] = Field(None, ge=0)
    reserved: Optional[List[int]] = None


class EndpointUpdateRequest(BaseModel):
    address: Optional[List[str]] = None
    private_key: Optional[str] = None
    mtu: Optional[int] = Field(None, gt=0)
    workers: Optional[int] = Field(None, gt=0)
    peers: Optional[List[WireGuardPeerModel]] = None


class PiaLoginRequest(BaseModel):
    username: str
    password: str
    regenerate_config: bool = True


class ProfileCreateRequest(BaseModel):
    """创建新的 VPN 线路配置"""
    tag: str = Field(..., pattern=r"^[a-z][a-z0-9-]*$", description="线路标识符，如 us-stream")
    description: str = Field(..., description="线路描述，如 US 流媒体出口")
    region_id: str = Field(..., description="PIA 地区 ID，如 us-east")
    custom_dns: Optional[str] = Field(None, description="自定义 DNS（空=PIA DNS，或如 1.1.1.1, tls://dns.google）")


class ProfileUpdateRequest(BaseModel):
    """更新 VPN 线路配置"""
    description: Optional[str] = None
    region_id: Optional[str] = None
    custom_dns: Optional[str] = Field(None, description="自定义 DNS（空=PIA DNS，或如 1.1.1.1, tls://dns.google）")


class RouteRuleRequest(BaseModel):
    """路由规则配置"""
    tag: str = Field(..., description="规则集标识符")
    outbound: str = Field(..., description="出口线路 tag")
    domains: Optional[List[str]] = Field(None, description="域名后缀列表")
    domain_keywords: Optional[List[str]] = Field(None, description="域名关键词列表")
    ip_cidrs: Optional[List[str]] = Field(None, description="IP CIDR 列表")
    # 新增协议/端口匹配字段
    protocols: Optional[List[str]] = Field(None, description="协议列表 (bittorrent, stun, ssh 等)")
    network: Optional[str] = Field(None, description="网络类型 (tcp, udp)")
    ports: Optional[List[int]] = Field(None, description="目标端口列表")
    port_ranges: Optional[List[str]] = Field(None, description="端口范围列表 (如 '6881:6889')")


class RouteRulesUpdateRequest(BaseModel):
    """批量更新路由规则"""
    rules: List[RouteRuleRequest]
    default_outbound: str = Field("direct", description="默认出口")
    regenerate_config: bool = Field(True, description="是否重新生成配置并重载")


class CustomRuleRequest(BaseModel):
    """添加自定义规则"""
    tag: str = Field(..., description="规则标签名称")
    outbound: str = Field(..., description="出口")
    domains: Optional[List[str]] = Field(None, description="域名后缀列表")
    domain_keywords: Optional[List[str]] = Field(None, description="域名关键词列表")
    ip_cidrs: Optional[List[str]] = Field(None, description="IP CIDR 列表")
    # 新增协议/端口匹配字段
    protocols: Optional[List[str]] = Field(None, description="协议列表 (bittorrent, stun, ssh 等)")
    network: Optional[str] = Field(None, description="网络类型 (tcp, udp)")
    ports: Optional[List[int]] = Field(None, description="目标端口列表")
    port_ranges: Optional[List[str]] = Field(None, description="端口范围列表 (如 '6881:6889')")


class CustomCategoryItemRequest(BaseModel):
    """在分类中添加自定义域名列表项"""
    name: str = Field(..., description="列表名称，如 my-streaming")
    domains: List[str] = Field(..., description="域名列表")


class IngressPeerCreateRequest(BaseModel):
    """添加入口 WireGuard peer"""
    name: str = Field(..., description="客户端名称，如 laptop, phone")
    public_key: Optional[str] = Field(None, description="客户端公钥（可选，不填则服务端生成密钥对）")
    allow_lan: bool = Field(False, description="是否允许访问本地局域网")
    default_outbound: Optional[str] = Field(None, description="此客户端的默认出口（不填则使用入口默认或全局默认）")


class IngressPeerUpdateRequest(BaseModel):
    """更新入口 WireGuard peer"""
    name: Optional[str] = Field(None, description="客户端名称")
    default_outbound: Optional[str] = Field(None, description="此客户端的默认出口（空字符串表示清空，使用入口默认）")


class CustomEgressCreateRequest(BaseModel):
    """创建自定义出口"""
    tag: str = Field(..., pattern=r"^[a-z][a-z0-9-]*$", description="出口标识符")
    description: str = Field("", description="描述")
    server: str = Field(..., description="服务器地址")
    port: int = Field(51820, ge=1, le=65535, description="服务器端口")
    private_key: str = Field(..., description="客户端私钥")
    public_key: str = Field(..., description="服务端公钥")
    address: str = Field(..., description="客户端 IP 地址，如 10.0.0.2/32")
    mtu: int = Field(1420, ge=1280, le=9000, description="MTU")
    dns: str = Field("1.1.1.1", description="DNS 服务器")
    pre_shared_key: Optional[str] = Field(None, description="预共享密钥")
    reserved: Optional[List[int]] = Field(None, description="保留字节（用于某些服务如 WARP）")


class CustomEgressUpdateRequest(BaseModel):
    """更新自定义出口"""
    description: Optional[str] = None
    server: Optional[str] = None
    port: Optional[int] = Field(None, ge=1, le=65535)
    private_key: Optional[str] = None
    public_key: Optional[str] = None
    address: Optional[str] = None
    mtu: Optional[int] = Field(None, ge=1280, le=9000)
    dns: Optional[str] = None
    pre_shared_key: Optional[str] = None
    reserved: Optional[List[int]] = None


class DirectEgressCreateRequest(BaseModel):
    """创建 Direct 出口（绑定特定接口/IP）"""
    tag: str = Field(..., pattern=r"^[a-z][a-z0-9-]*$", description="出口标识符，如 direct-eth1")
    description: str = Field("", description="描述")
    bind_interface: Optional[str] = Field(None, description="绑定的网络接口，如 eth1, macvlan0")
    inet4_bind_address: Optional[str] = Field(None, description="绑定的 IPv4 地址")
    inet6_bind_address: Optional[str] = Field(None, description="绑定的 IPv6 地址")


class DirectEgressUpdateRequest(BaseModel):
    """更新 Direct 出口"""
    description: Optional[str] = None
    bind_interface: Optional[str] = None
    inet4_bind_address: Optional[str] = None
    inet6_bind_address: Optional[str] = None
    enabled: Optional[int] = Field(None, ge=0, le=1)


class OpenVPNEgressCreateRequest(BaseModel):
    """创建 OpenVPN 出口"""
    tag: str = Field(..., pattern=r"^[a-z][a-z0-9-]*$", description="出口标识符")
    description: str = Field("", description="描述")
    protocol: str = Field("udp", description="协议 (udp/tcp)")
    remote_host: str = Field(..., description="远程服务器地址")
    remote_port: int = Field(1194, ge=1, le=65535, description="远程端口")
    ca_cert: str = Field(..., description="CA 证书 (PEM 格式)")
    client_cert: Optional[str] = Field(None, description="客户端证书 (PEM 格式)")
    client_key: Optional[str] = Field(None, description="客户端私钥 (PEM 格式)")
    tls_auth: Optional[str] = Field(None, description="TLS Auth 密钥")
    tls_crypt: Optional[str] = Field(None, description="TLS Crypt 密钥 (与 tls_auth 二选一)")
    crl_verify: Optional[str] = Field(None, description="CRL 证书吊销列表 (PEM 格式)")
    auth_user: Optional[str] = Field(None, description="用户名 (用于用户名/密码认证)")
    auth_pass: Optional[str] = Field(None, description="密码 (用于用户名/密码认证)")
    cipher: str = Field("AES-256-GCM", description="加密算法")
    auth: str = Field("SHA256", description="认证算法")
    compress: Optional[str] = Field(None, description="压缩算法 (lzo/lz4)")
    extra_options: Optional[List[str]] = Field(None, description="额外 OpenVPN 选项")


class OpenVPNEgressUpdateRequest(BaseModel):
    """更新 OpenVPN 出口"""
    description: Optional[str] = None
    protocol: Optional[str] = None
    remote_host: Optional[str] = None
    remote_port: Optional[int] = Field(None, ge=1, le=65535)
    ca_cert: Optional[str] = None
    client_cert: Optional[str] = None
    client_key: Optional[str] = None
    tls_auth: Optional[str] = None
    tls_crypt: Optional[str] = None
    crl_verify: Optional[str] = None
    auth_user: Optional[str] = None
    auth_pass: Optional[str] = None
    cipher: Optional[str] = None
    auth: Optional[str] = None
    compress: Optional[str] = None
    extra_options: Optional[List[str]] = None
    enabled: Optional[int] = Field(None, ge=0, le=1)


class OpenVPNParseRequest(BaseModel):
    """解析 .ovpn 文件内容"""
    content: str = Field(..., description=".ovpn 文件内容")


class WireGuardConfParseRequest(BaseModel):
    """解析 WireGuard .conf 文件内容"""
    content: str = Field(..., description=".conf 文件内容")


class BackupExportRequest(BaseModel):
    """导出配置备份（v2.0: 密码必需）"""
    password: str = Field(..., min_length=1, description="加密密码（v2.0 必需，用于加密部署密钥）")
    # v2.0: PIA 凭据自动包含在加密数据库中，无需单独选项
    # 保留以兼容旧版本
    include_pia_credentials: bool = Field(True, description="[已废弃] v2.0 自动包含")


class BackupImportRequest(BaseModel):
    """导入配置备份"""
    data: str = Field(..., description="备份数据（JSON 字符串）")
    password: str = Field(..., min_length=1, description="解密密码（v2.0 必需）")
    # v2.0: 不再支持合并模式，始终完全替换
    merge_mode: str = Field("replace", description="[已废弃] v2.0 始终替换")


# ============ V2Ray Egress/Inbound Models ============

class V2RayEgressCreateRequest(BaseModel):
    """创建 V2Ray 出口 (VLESS only - VMess/Trojan removed in Xray-lite)"""
    tag: str = Field(..., pattern=r"^[a-z][a-z0-9-]*$", description="出口标识符")
    description: str = Field("", description="描述")
    protocol: str = Field("vless", description="协议 (仅支持 vless)")
    server: str = Field(..., description="服务器地址")
    server_port: int = Field(443, ge=1, le=65535, description="服务器端口")
    # Auth (VLESS)
    uuid: Optional[str] = Field(None, description="UUID (VLESS)")
    # [REMOVED] password, security, alter_id - VMess/Trojan fields removed in Xray-lite
    # VLESS specific
    flow: Optional[str] = Field(None, description="VLESS flow (xtls-rprx-vision)")
    # TLS
    tls_enabled: bool = Field(True, description="启用 TLS")
    tls_sni: Optional[str] = Field(None, description="TLS SNI")
    tls_alpn: Optional[List[str]] = Field(None, description="TLS ALPN")
    tls_allow_insecure: bool = Field(False, description="允许不安全证书")
    tls_fingerprint: Optional[str] = Field(None, description="uTLS 指纹")
    # REALITY
    reality_enabled: bool = Field(False, description="启用 REALITY")
    reality_public_key: Optional[str] = Field(None, description="REALITY 公钥")
    reality_short_id: Optional[str] = Field(None, description="REALITY short ID")
    # Transport
    transport_type: str = Field("tcp", description="传输类型 (tcp/ws/grpc/h2/quic/httpupgrade)")
    transport_config: Optional[Dict[str, Any]] = Field(None, description="传输配置 (JSON)")
    # Multiplex
    multiplex_enabled: bool = Field(False, description="启用多路复用")
    multiplex_protocol: Optional[str] = Field(None, description="多路复用协议 (smux/yamux/h2mux)")
    multiplex_max_connections: Optional[int] = Field(None, description="最大连接数")
    multiplex_min_streams: Optional[int] = Field(None, description="最小流数")
    multiplex_max_streams: Optional[int] = Field(None, description="最大流数")


class V2RayEgressUpdateRequest(BaseModel):
    """更新 V2Ray 出口 (VLESS only - Xray-lite)"""
    description: Optional[str] = None
    protocol: Optional[str] = None
    server: Optional[str] = None
    server_port: Optional[int] = Field(None, ge=1, le=65535)
    uuid: Optional[str] = None
    # [REMOVED in Xray-lite] password, security, alter_id - VMess/Trojan fields removed
    flow: Optional[str] = None
    tls_enabled: Optional[bool] = None
    tls_sni: Optional[str] = None
    tls_alpn: Optional[List[str]] = None
    tls_allow_insecure: Optional[bool] = None
    tls_fingerprint: Optional[str] = None
    reality_enabled: Optional[bool] = None
    reality_public_key: Optional[str] = None
    reality_short_id: Optional[str] = None
    transport_type: Optional[str] = None
    transport_config: Optional[Dict[str, Any]] = None
    multiplex_enabled: Optional[bool] = None
    multiplex_protocol: Optional[str] = None
    multiplex_max_connections: Optional[int] = None
    multiplex_min_streams: Optional[int] = None
    multiplex_max_streams: Optional[int] = None
    enabled: Optional[int] = Field(None, ge=0, le=1)


class V2RayURIParseRequest(BaseModel):
    """解析 V2Ray URI (仅支持 vless:// - VMess/Trojan removed in Xray-lite)"""
    uri: str = Field(..., description="V2Ray 分享链接 (vless:// only)")


class V2RayInboundUpdateRequest(BaseModel):
    """更新 V2Ray 入口配置（使用 Xray + TUN + TPROXY 架构）- VLESS only"""
    protocol: str = Field("vless", description="协议 (仅支持 vless)")
    listen_address: str = Field("0.0.0.0", description="监听地址")
    listen_port: int = Field(443, ge=1, le=65535, description="监听端口")
    tls_enabled: bool = Field(True, description="启用 TLS")
    tls_cert_path: Optional[str] = Field(None, description="TLS 证书路径")
    tls_key_path: Optional[str] = Field(None, description="TLS 私钥路径")
    tls_cert_content: Optional[str] = Field(None, description="TLS 证书内容 (PEM)")
    tls_key_content: Optional[str] = Field(None, description="TLS 私钥内容 (PEM)")
    # XTLS-Vision (VLESS only)
    xtls_vision_enabled: bool = Field(False, description="启用 XTLS-Vision (VLESS 专用)")
    # REALITY (Xray only, no certificate needed)
    reality_enabled: bool = Field(False, description="启用 REALITY (无需证书)")
    reality_private_key: Optional[str] = Field(None, description="REALITY 私钥")
    reality_public_key: Optional[str] = Field(None, description="REALITY 公钥")
    reality_short_ids: Optional[List[str]] = Field(None, description="REALITY Short ID 列表")
    reality_dest: Optional[str] = Field(None, description="REALITY 目标服务器")
    reality_server_names: Optional[List[str]] = Field(None, description="REALITY SNI 列表")
    # Transport
    transport_type: str = Field("tcp", description="传输类型")
    transport_config: Optional[Dict[str, Any]] = Field(None, description="传输配置")
    fallback_server: Optional[str] = Field(None, description="回落服务器")
    fallback_port: Optional[int] = Field(None, ge=1, le=65535, description="回落端口")
    # TUN config
    tun_device: str = Field("xray-tun0", description="TUN 设备名")
    tun_subnet: str = Field("10.24.0.0/24", description="TUN 子网")
    # Enable
    enabled: bool = Field(False, description="启用入口")


class V2RayUserCreateRequest(BaseModel):
    """创建 V2Ray 用户 (VLESS only - Xray-lite)"""
    name: str = Field(..., pattern=r"^[a-zA-Z][a-zA-Z0-9_-]*$", description="用户名")
    email: Optional[str] = Field(None, description="邮箱")
    uuid: Optional[str] = Field(None, description="UUID (VLESS，不填自动生成)")
    # [REMOVED in Xray-lite] password, alter_id - VMess/Trojan fields removed
    flow: Optional[str] = Field(None, description="VLESS flow (xtls-rprx-vision)")


class V2RayUserUpdateRequest(BaseModel):
    """更新 V2Ray 用户 (VLESS only - Xray-lite)"""
    email: Optional[str] = None
    uuid: Optional[str] = None
    # [REMOVED in Xray-lite] password, alter_id - VMess/Trojan fields removed
    flow: Optional[str] = None
    enabled: Optional[int] = Field(None, ge=0, le=1)


# ============ 对等节点 (Peer Node) 模型 ============

# NOTE: PeerAuthValidateRequest and PeerAuthExchangeRequest have been removed.
# PSK authentication is deprecated. Use tunnel IP authentication (WireGuard) or UUID authentication (Xray).


class PeerNotifyRequest(BaseModel):
    """对等节点连接/断开通知请求

    认证方式: 隧道 IP 认证 (WireGuard) 或 UUID 认证 (Xray)
    """
    node_id: str = Field(..., pattern=r"^[a-z][a-z0-9-]*$", description="发起方节点标识")
    # 发起方的隧道参数（接收方需要用这些参数建立隧道）
    initiator_endpoint: Optional[str] = Field(None, description="发起方的 WireGuard 监听端点 (IP:port)")
    initiator_public_key: Optional[str] = Field(None, description="发起方的 WireGuard 公钥")
    initiator_tunnel_ip: Optional[str] = Field(None, description="发起方的隧道 IP")


class ReverseSetupRequest(BaseModel):
    """Phase 11.2: 请求建立反向连接

    当节点 A 导入节点 B 的配对请求并完成配对后，
    A 通过隧道调用 B 的此 API，请求 B 建立到 A 的反向连接。

    认证方式：
    - WireGuard 隧道：通过 tunnel_remote_ip 验证（IP 即身份）
    - Xray 隧道：通过 X-Peer-UUID header 验证
    """
    node_id: str = Field(..., pattern=r"^[a-z][a-z0-9-]*$", description="请求方节点标识")
    # 请求方的隧道信息（B 需要这些信息连接到 A）
    endpoint: str = Field(..., description="请求方的 WireGuard 监听端点 (IP:port)")
    wg_public_key: str = Field(..., description="请求方的 WireGuard 公钥")
    tunnel_local_ip: str = Field(..., description="请求方的隧道 IP")


class CompleteHandshakeRequest(BaseModel):
    """Phase 11-Tunnel: 完成配对握手

    当 Node B 导入 Node A 的配对请求码并建立隧道后，
    B 通过隧道调用 A 的此 API，通知 A 完成配对。

    认证方式：
    - 通过 pairing_id 匹配 pending_pairing 记录
    - 验证请求来自预期的隧道 IP
    """
    pairing_id: str = Field(..., description="配对标识（由配对码前 32 字符的 MD5 生成）")
    node_tag: str = Field(..., pattern=r"^[a-z][a-z0-9-]*$", description="请求方（Node B）的节点标识")
    node_description: str = Field("", description="请求方节点描述")
    endpoint: str = Field(..., description="请求方的 WireGuard 监听端点 (IP:port)")
    tunnel_ip: str = Field(..., description="请求方的隧道 IP（应与 pending_pairing.tunnel_remote_ip 匹配）")
    wg_public_key: str = Field(..., description="请求方的 WireGuard 公钥")
    api_port: Optional[int] = Field(None, ge=1, le=65535, description="请求方的 API 端口（默认 36000）Phase 11-Fix.K")


class PeerEventRequest(BaseModel):
    """Phase 11-Cascade: 对等节点事件通知

    用于在节点间传播删除、断开等事件，实现级联清理。

    认证方式：
    - WireGuard 隧道：通过 tunnel_remote_ip 验证（IP 即身份）
    - Xray 隧道：通过 X-Peer-UUID header 验证
    """
    event_id: str = Field(
        ...,
        pattern=r"^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$",
        description="事件唯一 ID (UUID v4)，用于幂等性去重"
    )
    event_type: str = Field(
        ...,
        pattern=r"^(delete|disconnect|broadcast|port_change)$",
        description="事件类型: delete(删除通知), disconnect(断开通知), broadcast(广播通知), port_change(端口变更)"
    )
    source_node: str = Field(
        ...,
        pattern=r"^[a-z][a-z0-9-]*$",
        max_length=64,
        description="事件发起节点"
    )
    target_node: Optional[str] = Field(
        None,
        pattern=r"^[a-z][a-z0-9-]*$",
        max_length=64,
        description="目标节点 (broadcast 时必填)"
    )
    ttl: int = Field(3, ge=0, le=10, description="广播跳数限制 (0 表示不再转发)")
    reason: str = Field("", max_length=500, description="事件原因描述")
    details: Optional[Dict[str, Any]] = Field(None, description="附加信息 (JSON，最大 10KB)")

    @validator('details')
    def validate_details_size(cls, v):
        """验证 details 字段不超过 10KB"""
        if v is not None:
            import json
            json_size = len(json.dumps(v, separators=(',', ':')))
            if json_size > 10240:  # 10KB
                raise ValueError(f"details field exceeds 10KB limit ({json_size} bytes)")
        return v


class PeerNodeCreateRequest(BaseModel):
    """创建对等节点

    对于 Xray 类型节点，使用固定 VLESS+XHTTP+REALITY 协议组合。
    REALITY 密钥（私钥、公钥、Short ID）在创建时自动生成。

    认证方式: 隧道 IP 认证 (WireGuard) 或 UUID 认证 (Xray)
    """
    tag: str = Field(..., pattern=r"^[a-z][a-z0-9-]*$", description="节点标识符，如 node-tokyo")
    name: str = Field(..., description="节点显示名称")
    description: str = Field("", description="节点描述")
    endpoint: str = Field(..., description="节点连接地址 (IP:port 或 域名:port)")
    api_port: Optional[int] = Field(None, ge=1, le=65535, description="远程 API 端口（默认为 36000）")
    tunnel_type: str = Field("wireguard", pattern=r"^(wireguard|xray)$", description="隧道类型 (wireguard/xray)")

    # REALITY 配置（Dest 和 Server Names 可自定义）
    xray_reality_dest: str = Field("www.microsoft.com:443", description="REALITY Dest Server（伪装目标）")
    xray_reality_server_names: List[str] = Field(
        default=["www.microsoft.com"],
        description="REALITY Server Names（SNI 列表）"
    )
    # XHTTP 传输配置
    xray_xhttp_path: str = Field("/", description="XHTTP 路径")
    xray_xhttp_mode: str = Field(
        "auto",
        pattern=r"^(auto|packet-up|stream-up|stream-one)$",
        description="XHTTP 模式"
    )
    xray_xhttp_host: Optional[str] = Field(None, description="XHTTP Host")
    default_outbound: Optional[str] = Field(None, description="此节点入口的默认出口")
    auto_reconnect: int = Field(1, ge=0, le=1, description="是否自动重连")
    enabled: int = Field(1, ge=0, le=1, description="是否启用")
    # 连接模式
    connection_mode: str = Field(
        "outbound",
        pattern=r"^(outbound|inbound)$",
        description="连接模式：outbound（连接到对端主隧道）或 inbound（连接到对端入站监听）"
    )


class PeerNodeUpdateRequest(BaseModel):
    """更新对等节点"""
    name: Optional[str] = Field(None, description="节点显示名称")
    description: Optional[str] = Field(None, description="节点描述")
    endpoint: Optional[str] = Field(None, description="节点连接地址")
    api_port: Optional[int] = Field(None, ge=1, le=65535, description="远程 API 端口")
    tunnel_type: Optional[str] = Field(None, pattern=r"^(wireguard|xray)$", description="隧道类型")

    # REALITY 配置
    xray_reality_dest: Optional[str] = Field(None, description="REALITY Dest Server")
    xray_reality_server_names: Optional[List[str]] = Field(None, description="REALITY Server Names")
    # XHTTP 传输配置
    xray_xhttp_path: Optional[str] = Field(None, description="XHTTP 路径")
    xray_xhttp_mode: Optional[str] = Field(
        None,
        pattern=r"^(auto|packet-up|stream-up|stream-one)$",
        description="XHTTP 模式"
    )
    xray_xhttp_host: Optional[str] = Field(None, description="XHTTP Host")
    default_outbound: Optional[str] = Field(None, description="默认出口")
    auto_reconnect: Optional[int] = Field(None, ge=0, le=1, description="自动重连")
    enabled: Optional[int] = Field(None, ge=0, le=1, description="是否启用")
    # 连接模式
    connection_mode: Optional[str] = Field(
        None,
        pattern=r"^(outbound|inbound)$",
        description="连接模式：outbound（连接到对端主隧道）或 inbound（连接到对端入站监听）"
    )


# ============ 离线配对模型 ============

class GeneratePairRequestRequest(BaseModel):
    """生成配对请求码的请求参数

    认证方式: 隧道 IP 认证 (WireGuard) 或 UUID 认证 (Xray)
    """
    node_tag: str = Field(..., pattern=r"^[a-z][a-z0-9-]*$", description="本节点标识符")
    node_description: str = Field("", description="节点描述")
    endpoint: str = Field(..., description="隧道端点 (IP:port)")
    tunnel_type: str = Field("wireguard", pattern=r"^(wireguard|xray)$", description="隧道类型")
    bidirectional: bool = Field(True, description="启用双向自动连接 (Phase 11.2)")
    api_port: Optional[int] = Field(None, ge=1, le=65535, description="API 端口（默认 36000）Phase 11-Fix.K")


class GeneratePairRequestResponse(BaseModel):
    """生成配对请求码的响应"""
    code: str = Field(..., description="Base64 配对请求码")
    psk: str = Field("", description="[已废弃] 预共享密钥（不再使用）")
    pending_request: Dict[str, Any] = Field(..., description="待处理请求信息（用于完成配对）")


class ImportPairRequestRequest(BaseModel):
    """导入配对请求码的请求参数

    认证方式: 隧道 IP 认证 (WireGuard) 或 UUID 认证 (Xray)
    """
    code: str = Field(..., description="Base64 配对请求码")
    local_node_tag: str = Field(..., pattern=r"^[a-z][a-z0-9-]*$", description="本节点标识符")
    local_node_description: str = Field("", description="本节点描述")
    local_endpoint: str = Field(..., description="本节点端点 (IP:port)")
    api_port: Optional[int] = Field(None, ge=1, le=65535, description="本节点 API 端口（默认 36000）Phase 11-Fix.K")


class ImportPairRequestResponse(BaseModel):
    """导入配对请求码的响应"""
    success: bool = Field(..., description="是否成功")
    message: str = Field(..., description="结果消息")
    response_code: Optional[str] = Field(None, description="Base64 配对响应码（隧道优先模式下为 None）")
    created_node_tag: Optional[str] = Field(None, description="创建的节点标识符")
    tunnel_status: Optional[str] = Field(None, description="隧道连接状态")
    bidirectional: Optional[bool] = Field(None, description="是否为双向配对")


class CompletePairingRequest(BaseModel):
    """完成配对的请求参数"""
    code: str = Field(..., description="Base64 配对响应码")
    pending_request: Dict[str, Any] = Field(..., description="待处理请求信息（来自 generate-pair-request）")


class CompletePairingResponse(BaseModel):
    """完成配对的响应"""
    success: bool = Field(..., description="是否成功")
    message: str = Field(..., description="结果消息")
    created_node_tag: Optional[str] = Field(None, description="创建的节点标识符")


class NodeChainCreateRequest(BaseModel):
    """创建多跳链路"""
    tag: str = Field(..., pattern=r"^[a-z][a-z0-9-]*$", description="链路标识符")
    name: str = Field(..., description="链路名称")
    description: str = Field("", description="链路描述")
    # Phase 7 Fix: 添加最大长度限制（API 层限制 10 跳，递归验证使用 max_depth=5）
    hops: List[str] = Field(..., min_length=2, max_length=10, description="节点跳转列表（2-10 跳）")
    hop_protocols: Optional[Dict[str, str]] = Field(None, description="每跳协议配置")
    entry_rules: Optional[Dict[str, Any]] = Field(None, description="入口分流规则")
    relay_rules: Optional[Dict[str, Any]] = Field(None, description="中继分流规则")
    priority: int = Field(0, description="优先级")
    enabled: int = Field(1, ge=0, le=1, description="是否启用")
    # Phase 6 新增字段
    exit_egress: Optional[str] = Field(None, description="终端节点的本地出口")
    dscp_value: Optional[int] = Field(None, ge=1, le=63, description="DSCP 标记值（1-63），不提供则自动分配")
    chain_mark_type: str = Field("dscp", pattern=r"^dscp$", description="标记类型（仅支持 DSCP，Xray 隧道不支持多跳链路）")
    # Phase 11-Fix.C: 传递模式验证
    allow_transitive: bool = Field(False, description="是否允许传递验证（只验证第一跳，后续跳通过隧道验证）")


class NodeChainUpdateRequest(BaseModel):
    """更新多跳链路"""
    name: Optional[str] = Field(None, description="链路名称")
    description: Optional[str] = Field(None, description="链路描述")
    # Phase 7 Fix: 与 NodeChainCreateRequest 保持一致
    hops: Optional[List[str]] = Field(None, min_length=2, max_length=10, description="节点跳转列表（2-10 跳）")
    hop_protocols: Optional[Dict[str, str]] = Field(None, description="每跳协议配置")
    entry_rules: Optional[Dict[str, Any]] = Field(None, description="入口分流规则")
    relay_rules: Optional[Dict[str, Any]] = Field(None, description="中继分流规则")
    priority: Optional[int] = Field(None, description="优先级")
    enabled: Optional[int] = Field(None, ge=0, le=1, description="是否启用")
    # Phase 6 新增字段
    exit_egress: Optional[str] = Field(None, description="终端节点的本地出口")
    dscp_value: Optional[int] = Field(None, ge=1, le=63, description="DSCP 标记值（1-63）")
    chain_mark_type: Optional[str] = Field(None, pattern=r"^dscp$", description="标记类型（仅支持 DSCP）")
    chain_state: Optional[str] = Field(None, pattern=r"^(inactive|activating|active|error)$", description="链路状态")
    # Phase 11-Fix.C: 传递模式验证
    allow_transitive: Optional[bool] = Field(None, description="是否允许传递验证（只验证第一跳，后续跳通过隧道验证）")


# ============ 加密/解密工具 ============

def _derive_key(password: str, salt: bytes) -> bytes:
    """从密码派生加密密钥"""
    if not HAS_CRYPTO:
        raise HTTPException(status_code=500, detail="加密库未安装")
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode()))


def encrypt_sensitive_data(data: str, password: str) -> dict:
    """加密敏感数据"""
    if not password:
        return {"encrypted": False, "data": data}

    salt = secrets.token_bytes(16)
    key = _derive_key(password, salt)
    f = Fernet(key)
    encrypted = f.encrypt(data.encode())

    return {
        "encrypted": True,
        "salt": base64.b64encode(salt).decode(),
        "data": base64.b64encode(encrypted).decode(),
    }


def decrypt_sensitive_data(encrypted_obj: dict, password: str) -> str:
    """解密敏感数据"""
    if not encrypted_obj.get("encrypted"):
        return encrypted_obj.get("data", "")

    if not password:
        raise HTTPException(status_code=400, detail="需要密码来解密备份数据")

    try:
        salt = base64.b64decode(encrypted_obj["salt"])
        key = _derive_key(password, salt)
        f = Fernet(key)
        decrypted = f.decrypt(base64.b64decode(encrypted_obj["data"]))
        return decrypted.decode()
    except Exception as exc:
        logging.warning(f"Decryption failed: {exc}")
        raise HTTPException(status_code=400, detail="Decryption failed, password may be incorrect") from exc


def _detect_public_ip() -> Optional[str]:
    """检测服务器公网 IP 地址"""
    import urllib.request
    try:
        with urllib.request.urlopen("https://api.ipify.org", timeout=5) as response:
            return response.read().decode().strip()
    except Exception:
        try:
            with urllib.request.urlopen("https://ifconfig.me/ip", timeout=5) as response:
                return response.read().decode().strip()
        except Exception:
            return None


app = FastAPI(title="VPN Gateway API", version="0.1.0")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ============ 认证配置 ============
JWT_ALGORITHM = "HS256"
JWT_EXPIRY_HOURS = 24

# 公开端点（不需要认证）
PUBLIC_PATHS = {
    "/api/auth/status",
    "/api/auth/setup",
    "/api/auth/login",
    "/api/health",
    # NOTE: /api/peer-auth/validate 和 /api/peer-auth/exchange 端点已移除（PSK 认证已废弃）
    # 节点间连接通知端点（隧道 IP 认证）
    "/api/peer-notify/connected",
    "/api/peer-notify/disconnected",
    "/api/peer-notify/downstream-disconnected",  # 级联断连通知
    # 节点间链路注册端点（隧道 IP 认证）
    "/api/peer-chain/register",
    "/api/peer-chain/unregister",
    # 节点间中继查询端点（PSK 认证）
    "/api/peer-relay/status",
    # 隧道内 API 端点（通过隧道访问，隧道 IP/UUID 认证）
    "/api/peer-info/egress",
    "/api/chain-routing/register",
    "/api/chain-routing/unregister",
    "/api/chain-routing",
    "/api/chain-routing/status",
    # Phase 11.2: 双向自动连接
    "/api/peer-tunnel/reverse-setup",
    # Phase 11-Tunnel: 隧道优先配对握手（通过隧道调用）
    "/api/peer-tunnel/complete-handshake",
    # Phase 11-Cascade: 级联删除通知（隧道 IP 认证）
    "/api/peer-tunnel/peer-event",
    # Phase 11.4: 中继路由注册（PSK 认证）
    "/api/relay-routing/prepare",
    "/api/relay-routing/register",
    "/api/relay-routing/unregister",
    # Phase 11-Fix.C: 链路跳点验证（支持 PSK 远程调用）
    "/api/chains/validate-hops",
}

# 公开端点前缀（不需要认证，支持路径参数）
PUBLIC_PATH_PREFIXES = [
    # Phase 4: 转发出口查询（隧道 IP/UUID 认证，支持 /api/peer/forward-egress/{target_tag}）
    "/api/peer/forward-egress/",
]


def _hash_password(password: str) -> str:
    """使用 bcrypt 哈希密码"""
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()


def _verify_password(password: str, password_hash: str) -> bool:
    """验证密码"""
    return bcrypt.checkpw(password.encode(), password_hash.encode())


def _create_token(secret: str) -> tuple:
    """创建 JWT token，返回 (token, expires_in_seconds)"""
    from datetime import timedelta
    expires_at = datetime.now(timezone.utc) + timedelta(hours=JWT_EXPIRY_HOURS)
    payload = {
        "sub": "admin",
        "exp": expires_at,
        "iat": datetime.now(timezone.utc)
    }
    token = jwt.encode(payload, secret, algorithm=JWT_ALGORITHM)
    expires_in = int((expires_at - datetime.now(timezone.utc)).total_seconds())
    return token, expires_in


def _verify_token(token: str, secret: str) -> bool:
    """验证 JWT token"""
    try:
        jwt.decode(token, secret, algorithms=[JWT_ALGORITHM])
        return True
    except jwt.ExpiredSignatureError:
        return False
    except jwt.InvalidTokenError:
        return False


class AuthMiddleware(BaseHTTPMiddleware):
    """认证中间件：保护 API 端点 + 速率限制 (H3)"""

    async def dispatch(self, request: Request, call_next):
        path = request.url.path

        # 允许 CORS 预检请求通过（OPTIONS 请求没有 Authorization header）
        if request.method == "OPTIONS":
            return await call_next(request)

        # API 速率限制 (H3)
        if path.startswith("/api/"):
            client_ip = _get_client_ip(request)
            # 登录端点使用更严格的限制
            if path == "/api/auth/login":
                limit = _RATE_LIMIT_LOGIN
            else:
                limit = _RATE_LIMIT_GENERAL

            if not _check_rate_limit(client_ip, limit):
                return Response(
                    content='{"detail":"Too many requests, please try again later"}',
                    status_code=429,
                    media_type="application/json",
                    headers={"Retry-After": "60"}
                )

        # 公开端点不需要认证（精确匹配）
        if path in PUBLIC_PATHS:
            return await call_next(request)

        # 公开端点不需要认证（前缀匹配，支持路径参数）
        if any(path.startswith(prefix) for prefix in PUBLIC_PATH_PREFIXES):
            return await call_next(request)

        # 非 API 端点（前端静态文件）不需要认证
        if not path.startswith("/api/"):
            return await call_next(request)

        # 检查是否已设置密码，未设置则允许访问
        try:
            db = _get_db()
            if not db.is_admin_setup():
                return await call_next(request)
        except Exception as e:
            # 数据库错误时拒绝访问（安全优先，fail-closed）
            print(f"[AUTH] Database error in auth middleware: {e}")
            return Response(
                content='{"error":"Service temporarily unavailable"}',
                status_code=503,
                media_type="application/json"
            )

        # 检查 Authorization header
        auth_header = request.headers.get("Authorization")
        if not auth_header or not auth_header.startswith("Bearer "):
            return Response(
                content='{"detail":"Not authenticated"}',
                status_code=401,
                media_type="application/json",
                headers={"WWW-Authenticate": "Bearer"}
            )

        token = auth_header.split(" ")[1]
        secret = db.get_or_create_jwt_secret()

        if not _verify_token(token, secret):
            return Response(
                content='{"detail":"Invalid or expired token"}',
                status_code=401,
                media_type="application/json",
                headers={"WWW-Authenticate": "Bearer"}
            )

        return await call_next(request)


# 添加认证中间件（在 CORS 之后）
app.add_middleware(AuthMiddleware)


def load_catalogs():
    """启动时加载目录数据到内存"""
    global _DOMAIN_CATALOG, _GEOIP_CATALOG

    # 加载域名目录
    if DOMAIN_CATALOG_FILE.exists():
        try:
            _DOMAIN_CATALOG = json.loads(DOMAIN_CATALOG_FILE.read_text(encoding="utf-8"))
            domain_count = sum(
                lst.get("count", len(lst.get("domains", [])))
                for lst in _DOMAIN_CATALOG.get("lists", {}).values()
            )
            print(f"[Catalog] 已加载域名目录: {len(_DOMAIN_CATALOG.get('lists', {}))} 服务, {domain_count:,} 域名")
        except Exception as e:
            print(f"[Catalog] 加载域名目录失败: {e}")
            _DOMAIN_CATALOG = {"categories": {}, "lists": {}}
    else:
        print(f"[Catalog] 域名目录文件不存在: {DOMAIN_CATALOG_FILE}")
        _DOMAIN_CATALOG = {"categories": {}, "lists": {}}

    # 加载 GeoIP 目录
    if GEOIP_CATALOG_FILE.exists():
        try:
            _GEOIP_CATALOG = json.loads(GEOIP_CATALOG_FILE.read_text(encoding="utf-8"))
            print(f"[Catalog] 已加载 GeoIP 目录: {_GEOIP_CATALOG.get('total_countries', 0)} 国家 (JSON)")
        except Exception as e:
            print(f"[Catalog] 加载 GeoIP 目录失败: {e}")
            _GEOIP_CATALOG = {"countries": []}
    else:
        print(f"[Catalog] GeoIP 目录文件不存在: {GEOIP_CATALOG_FILE}")
        _GEOIP_CATALOG = {"countries": []}


def _get_all_outbounds() -> List[str]:
    """获取所有配置的出口（用于图表显示）"""
    # 始终包含标准出口
    outbounds = ["direct", "block", "adblock"]

    if HAS_DATABASE and USER_DB_PATH.exists():
        try:
            db = _get_db()

            # PIA profiles
            for profile in db.get_pia_profiles(enabled_only=False):
                tag = profile.get("name")
                if tag and tag not in outbounds:
                    outbounds.append(tag)

            # Custom WireGuard egress
            for egress in db.get_custom_egress_list():
                tag = egress.get("tag")
                if tag and tag not in outbounds:
                    outbounds.append(tag)

            # Direct egress (bound to interface/IP)
            for egress in db.get_direct_egress_list(enabled_only=True):
                tag = egress.get("tag")
                if tag and tag not in outbounds:
                    outbounds.append(tag)

            # OpenVPN egress
            for egress in db.get_openvpn_egress_list(enabled_only=True):
                tag = egress.get("tag")
                if tag and tag not in outbounds:
                    outbounds.append(tag)

            # V2Ray/Xray egress
            for egress in db.get_v2ray_egress_list(enabled_only=True):
                tag = egress.get("tag")
                if tag and tag not in outbounds:
                    outbounds.append(tag)

            # WARP egress
            for egress in db.get_warp_egress_list(enabled_only=True):
                tag = egress.get("tag")
                if tag and tag not in outbounds:
                    outbounds.append(tag)

            # Outbound groups (负载均衡/故障转移组)
            for group in db.get_outbound_groups(enabled_only=True):
                tag = group.get("tag")
                if tag and tag not in outbounds:
                    outbounds.append(tag)

            # 从路由规则中获取出口（包括协议规则、端口规则等）
            for rule in db.get_routing_rules():
                outbound = rule.get("outbound")
                if outbound and outbound not in outbounds:
                    outbounds.append(outbound)
        except Exception:
            pass

    return outbounds


def _get_cached_outbounds() -> List[str]:
    """获取缓存的 outbounds 列表（避免锁内 DB 查询）

    缓存 TTL 为 10 秒，新增的 egress 最多延迟 10 秒显示在图表中
    """
    global _outbounds_cache, _outbounds_cache_time
    now = time.time()
    if now - _outbounds_cache_time > _OUTBOUNDS_CACHE_TTL or not _outbounds_cache:
        _outbounds_cache = _get_all_outbounds()
        _outbounds_cache_time = now
    return _outbounds_cache


def _get_v2ray_client():
    """获取 V2Ray API 客户端（懒加载）"""
    global _v2ray_client
    if _v2ray_client is None:
        try:
            from v2ray_stats_client import V2RayStatsClient
            _v2ray_client = V2RayStatsClient()
        except ImportError:
            print("[Traffic] V2Ray stats client not available, using fallback")
            return None
    return _v2ray_client


def _get_xray_egress_client():
    """获取 Xray 出站 V2Ray API 客户端（懒加载）

    仅当有启用的 V2Ray 出口时才初始化客户端。
    Xray 出站 API 使用端口 10086（与 sing-box 的 10085 区分）。
    """
    global _xray_egress_client
    if _xray_egress_client is None:
        try:
            # 检查是否有启用的 V2Ray 出口
            db = _get_db()
            v2ray_egress = db.get_v2ray_egress_list(enabled_only=True)
            if not v2ray_egress:
                return None

            from v2ray_stats_client import V2RayStatsClient
            _xray_egress_client = V2RayStatsClient(f"127.0.0.1:{XRAY_EGRESS_API_PORT}")
        except ImportError:
            return None
        except Exception as e:
            print(f"[Traffic] Xray egress stats client init failed: {e}")
            return None
    return _xray_egress_client


def _reset_xray_egress_client():
    """重置 Xray 出站统计客户端

    在 V2Ray 出口配置改变后调用，以便重新初始化客户端。
    """
    global _xray_egress_client
    if _xray_egress_client is not None:
        try:
            _xray_egress_client.close()
        except Exception:
            pass
    _xray_egress_client = None


def _get_xray_ingress_client():
    """获取 Xray 入站 V2Ray API 客户端（懒加载）

    仅当 V2Ray 入口已配置且启用时才初始化客户端。
    Xray 入站 API 使用端口 10087。
    """
    global _xray_ingress_client
    if _xray_ingress_client is None:
        try:
            # 检查 V2Ray 入口是否已配置且启用
            db = _get_db()
            config = db.get_v2ray_inbound_config()
            if not config or not config.get("enabled"):
                return None

            from v2ray_stats_client import V2RayStatsClient
            _xray_ingress_client = V2RayStatsClient(f"127.0.0.1:{XRAY_INGRESS_API_PORT}")
        except ImportError:
            return None
        except Exception as e:
            print(f"[Traffic] Xray ingress stats client init failed: {e}")
            return None
    return _xray_ingress_client


def _reset_xray_ingress_client():
    """重置 Xray 入站统计客户端

    在 V2Ray 入口配置改变后调用，以便重新初始化客户端。
    """
    global _xray_ingress_client
    if _xray_ingress_client is not None:
        try:
            _xray_ingress_client.close()
        except Exception:
            pass
    _xray_ingress_client = None


def _update_v2ray_user_activity():
    """更新 V2Ray 用户活跃度缓存

    从 Xray 入站 API 获取每用户流量统计，检测流量变化来判断用户是否在线。
    """
    global _v2ray_user_activity

    ingress_client = _get_xray_ingress_client()
    if not ingress_client:
        return

    try:
        # 获取用户流量统计 (格式: user>>>email>>>traffic>>>uplink/downlink)
        user_stats = ingress_client.get_user_stats()
        now = time.time()

        with _v2ray_user_activity_lock:
            for email, stats in user_stats.items():
                upload = stats.get("upload", 0)
                download = stats.get("download", 0)

                if email in _v2ray_user_activity:
                    # 检测流量是否有变化
                    prev = _v2ray_user_activity[email]
                    if upload != prev.get("upload", 0) or download != prev.get("download", 0):
                        # 流量有变化，更新 last_seen
                        _v2ray_user_activity[email] = {
                            "last_seen": now,
                            "upload": upload,
                            "download": download
                        }
                    # 如果流量无变化，保持 last_seen 不变
                else:
                    # 新用户，记录初始状态
                    _v2ray_user_activity[email] = {
                        "last_seen": now,
                        "upload": upload,
                        "download": download
                    }
    except Exception as e:
        # 静默忽略错误（Xray 可能未启动）
        pass


def _update_traffic_stats():
    """后台线程：定期更新累计流量统计和实时速率

    使用 V2Ray API 获取精确的出口流量统计（100% 准确）
    """
    global _traffic_stats, _traffic_rates, _rate_history
    global _last_history_time, _rate_samples

    # 缓存清理计数器（每 300 秒 = 5 分钟清理一次）
    _cache_cleanup_counter = 0
    _CACHE_CLEANUP_INTERVAL = 300  # 秒

    while True:
        try:
            client = _get_v2ray_client()
            if client is None:
                time.sleep(_POLL_INTERVAL)
                continue

            # 从 sing-box V2Ray API 获取精确的出口流量统计
            outbound_stats = client.get_outbound_stats()

            # 从 Xray 出站获取 V2Ray 出口的流量统计
            xray_client = _get_xray_egress_client()
            if xray_client:
                try:
                    xray_stats = xray_client.get_outbound_stats()
                    # 合并 Xray 统计：Xray 出口的统计替换 sing-box 中对应的 SOCKS 出站统计
                    # 因为 sing-box 只看到到 SOCKS 代理的流量，而 Xray 看到的是实际出口流量
                    for tag, stats in xray_stats.items():
                        if tag not in ("api", "freedom"):  # 排除内部 tag
                            outbound_stats[tag] = stats
                except Exception as e:
                    # M5 修复: 记录 Xray 统计错误（可能还未启动或已停止）
                    logging.debug(f"Xray egress stats unavailable: {type(e).__name__}: {e}")

            # 在锁外获取 outbounds 列表（使用缓存，避免锁内 DB 查询）
            all_outbounds = _get_cached_outbounds()

            with _traffic_stats_lock:
                # 更新累计流量（使用合并后的精确数据）
                for outbound, stats in outbound_stats.items():
                    _traffic_stats[outbound] = {
                        "download": stats["download"],
                        "upload": stats["upload"]
                    }

                # 保存当前流量样本用于速率计算
                current_sample = {k: dict(v) for k, v in _traffic_stats.items()}
                _rate_samples.append(current_sample)
                max_samples = _RATE_WINDOW // _POLL_INTERVAL + 1
                if len(_rate_samples) > max_samples:
                    _rate_samples.pop(0)

                # 计算速率
                if len(_rate_samples) >= 2:
                    oldest = _rate_samples[0]
                    newest = _rate_samples[-1]
                    window_seconds = (len(_rate_samples) - 1) * _POLL_INTERVAL

                    for outbound in set(list(oldest.keys()) + list(newest.keys())):
                        old_dl = oldest.get(outbound, {}).get("download", 0)
                        old_ul = oldest.get(outbound, {}).get("upload", 0)
                        new_dl = newest.get(outbound, {}).get("download", 0)
                        new_ul = newest.get(outbound, {}).get("upload", 0)

                        dl_rate = (new_dl - old_dl) / window_seconds if window_seconds > 0 else 0
                        ul_rate = (new_ul - old_ul) / window_seconds if window_seconds > 0 else 0
                        _traffic_rates[outbound] = {
                            "download_rate": max(0, dl_rate),
                            "upload_rate": max(0, ul_rate)
                        }

                # 记录速率历史（KB/s）- 每 _HISTORY_INTERVAL 秒记录一次
                now = int(time.time())
                if now - _last_history_time >= _HISTORY_INTERVAL:
                    _last_history_time = now
                    history_point = {"timestamp": now, "rates": {}}
                    # 使用锁外预先获取的 all_outbounds（已缓存）
                    for outbound in all_outbounds:
                        if outbound in _traffic_rates:
                            rates = _traffic_rates[outbound]
                            total_rate = (rates["download_rate"] + rates["upload_rate"]) / 1024
                            history_point["rates"][outbound] = round(total_rate, 1)
                        else:
                            history_point["rates"][outbound] = 0.0
                    _rate_history.append(history_point)

                    # 清理24小时前的历史数据 (C9: 双重防护机制)
                    cutoff = now - _MAX_HISTORY_SECONDS
                    _rate_history[:] = [p for p in _rate_history if p["timestamp"] > cutoff]
                    # 二次防护：限制最大条目数，防止时间戳异常导致的内存泄漏
                    if len(_rate_history) > _MAX_HISTORY_ENTRIES:
                        _rate_history[:] = _rate_history[-_MAX_HISTORY_ENTRIES:]

            # Update peer activity cache by polling clash_api
            # This ensures peer online status is tracked even without API queries
            try:
                get_peer_status_from_clash_api()
            except Exception as e:
                # M5 修复: 记录缓存更新错误而不是静默忽略
                logging.debug(f"Peer status cache update failed: {type(e).__name__}: {e}")

            # Update V2Ray user activity for online status tracking
            try:
                _update_v2ray_user_activity()
            except Exception as e:
                # M5 修复: 记录用户活动更新错误
                logging.debug(f"V2Ray user activity update failed: {type(e).__name__}: {e}")

            # Phase 11.5: 定期清理过期的终端出口缓存
            _cache_cleanup_counter += _POLL_INTERVAL
            if _cache_cleanup_counter >= _CACHE_CLEANUP_INTERVAL:
                _cache_cleanup_counter = 0
                try:
                    if HAS_DATABASE and USER_DB_PATH.exists():
                        db = _get_db()
                        deleted = db.cleanup_expired_terminal_egress_cache()
                        if deleted > 0:
                            logging.info(f"[Cache] 已清理 {deleted} 条过期的终端出口缓存")
                except Exception as e:
                    logging.debug(f"[Cache] 清理过期缓存失败: {e}")

        except Exception as e:
            # M5 修复: 使用 logging 而不是 print，记录完整异常信息
            logging.exception(f"Traffic stats thread error: {type(e).__name__}: {e}")

        time.sleep(_POLL_INTERVAL)


def _bidirectional_status_checker():
    """Phase 11-Fix.B: 后台线程定期检查 peer 双向连接状态

    每 60 秒检查一次所有已连接但非 bidirectional 的节点，自动更新它们的双向状态。

    状态语义:
    - pending: 尚未检查或隧道未连接
    - outbound_only: 隧道已连接，等待确认双向性
    - bidirectional: 隧道已连接且确认双向通信可用

    对于 WireGuard 隧道，一旦密钥交换完成（有 wg_peer_public_key），就应该是 bidirectional。
    对于 Xray 隧道，需要检查 inbound_enabled 状态。
    """
    _BIDIR_CHECK_INTERVAL = 60  # 秒
    _STARTUP_DELAY = 10  # 启动延迟，等待系统初始化

    # 等待系统初始化完成
    time.sleep(_STARTUP_DELAY)

    while True:
        try:
            if HAS_DATABASE and USER_DB_PATH.exists():
                db = _get_db()

                # 检查所有已连接但非 bidirectional 的节点
                # 包括 pending 和 outbound_only 状态
                peers_to_check = db.get_peers_pending_bidirectional()  # pending
                outbound_only_peers = db.get_peers_by_bidirectional_status("outbound_only")

                # 合并去重
                checked_tags = set()
                all_peers = []
                for peer in peers_to_check + outbound_only_peers:
                    tag = peer.get("tag")
                    if tag and tag not in checked_tags:
                        checked_tags.add(tag)
                        all_peers.append(peer)

                for peer in all_peers:
                    tag = peer.get("tag")
                    tunnel_status = peer.get("tunnel_status")
                    if tag and tunnel_status == "connected":
                        try:
                            _check_and_update_bidirectional_status(db, tag)
                        except Exception as e:
                            logging.warning(f"[bidirectional-checker] 检查节点 '{tag}' 失败: {e}")

                if all_peers:
                    logging.debug(f"[bidirectional-checker] 已检查 {len(all_peers)} 个节点")

        except Exception as e:
            logging.warning(f"[bidirectional-checker] 检查循环异常: {e}")

        time.sleep(_BIDIR_CHECK_INTERVAL)


def _recover_orphaned_chains():
    """Phase 11-Fix.T: 启动时恢复孤立的链路状态

    在服务器崩溃或异常关闭后，链路可能卡在 'activating' 状态。
    此函数将这些链路重置为 'error' 状态，并记录错误消息，
    用户可以随后手动激活或删除。

    Returns:
        int: 恢复的链路数量
    """
    if not HAS_DATABASE or not USER_DB_PATH.exists():
        return 0

    try:
        db = _get_db()
        recovered_count = 0

        # 获取所有链路
        # Phase 11-Fix.U: 修复方法名 list_node_chains -> get_node_chains
        chains = db.get_node_chains()
        for chain in chains:
            chain_state = chain.get("chain_state", "inactive")
            tag = chain.get("tag", "unknown")

            # 恢复卡在 'activating' 状态的链路
            if chain_state == "activating":
                logging.warning(
                    f"[chain-recovery] 链路 '{tag}' 卡在 'activating' 状态，"
                    f"重置为 'error' 状态（服务重启恢复）"
                )
                # Phase 11-Fix.U: 使用原子事务同时更新状态和错误消息
                # 避免非原子的 update_node_chain 导致的潜在竞态条件
                success, error = db.atomic_chain_state_transition(
                    tag=tag,
                    expected_state="activating",
                    new_state="error",
                    last_error="服务重启时恢复 - 链路在激活过程中被中断"
                )
                if success:
                    recovered_count += 1
                else:
                    # 状态已被其他进程更改（可能已被用户手动处理）
                    logging.info(f"[chain-recovery] 链路 '{tag}' 状态转换失败: {error}")

        return recovered_count

    except Exception as e:
        logging.error(f"[chain-recovery] 链路恢复失败: {e}")
        return 0


@app.on_event("startup")
async def startup_event():
    """应用启动时加载数据"""
    load_catalogs()
    # 刷新 WireGuard 子网缓存
    refresh_wg_subnet_cache()
    print(f"[WireGuard] 子网前缀缓存已初始化: {get_cached_wg_subnet_prefix()}")
    # 启动流量统计后台线程（使用 V2Ray API 精确统计）
    traffic_thread = threading.Thread(target=_update_traffic_stats, daemon=True)
    traffic_thread.start()
    print("[Traffic] 流量统计后台线程已启动（V2Ray API 精确模式）")
    # Phase 11-Fix.B: 启动双向状态检查后台线程
    bidir_thread = threading.Thread(target=_bidirectional_status_checker, daemon=True)
    bidir_thread.start()
    print("[Bidirectional] 双向状态检查后台线程已启动（60秒间隔）")
    # Phase 11.1: 清理过期的终端出口缓存
    try:
        if HAS_DATABASE and USER_DB_PATH.exists():
            db = _get_db()
            deleted = db.cleanup_expired_terminal_egress_cache()
            if deleted > 0:
                print(f"[Cache] 已清理 {deleted} 条过期的终端出口缓存")
    except Exception as e:
        logging.warning(f"[Cache] 清理过期缓存失败: {e}")
    # Phase 11-Fix.T: 恢复卡在 'activating' 状态的孤立链路
    recovered = _recover_orphaned_chains()
    if recovered > 0:
        print(f"[Chain Recovery] 已恢复 {recovered} 条孤立链路（重置为 error 状态）")


def load_json_config() -> dict:
    if not CONFIG_PATH.exists():
        raise HTTPException(status_code=500, detail="配置文件不存在")
    with CONFIG_LOCK:
        data = json.loads(CONFIG_PATH.read_text())
    return data


def load_generated_config() -> dict:
    """读取生成的配置文件（当前运行的配置）"""
    # 优先使用生成的配置文件，如果不存在则回退到基础配置
    config_path = GENERATED_CONFIG_PATH if GENERATED_CONFIG_PATH.exists() else CONFIG_PATH
    if not config_path.exists():
        raise HTTPException(status_code=500, detail="配置文件不存在")
    with CONFIG_LOCK:
        data = json.loads(config_path.read_text())
    return data


def save_json_config(data: dict) -> None:
    with CONFIG_LOCK:
        CONFIG_PATH.write_text(json.dumps(data, indent=2))


def get_wireguard_status() -> dict:
    try:
        result = subprocess.run(
            ["wg", "show", "wg-ingress"],
            capture_output=True,
            text=True,
            check=True,
        )
        return {"raw": result.stdout}
    except subprocess.CalledProcessError as exc:
        return {"error": exc.stderr.strip() or "failed to read wg status"}
    except FileNotFoundError:
        return {"error": "wg binary not available"}


def list_processes(pattern: str) -> bool:
    try:
        subprocess.run(["pgrep", "-f", pattern], check=True, capture_output=True)
        return True
    except subprocess.CalledProcessError:
        return False
    except FileNotFoundError:
        return False


def load_pia_profiles_yaml() -> dict:
    if not PIA_PROFILES_FILE.exists():
        return {}
    return yaml.safe_load(PIA_PROFILES_FILE.read_text()) or {}


def run_command(cmd: List[str], env: Optional[dict] = None) -> str:
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            check=True,
            env=env,
        )
        return result.stdout.strip()
    except subprocess.CalledProcessError as exc:
        raise HTTPException(status_code=500, detail=exc.stderr or str(exc)) from exc


def fetch_pia_regions() -> List[Dict[str, Any]]:
    """获取 PIA 可用地区列表（带缓存）"""
    global _pia_regions_cache
    now = time.time()

    # 检查缓存是否有效（1小时）
    if _pia_regions_cache["data"] and now - _pia_regions_cache["timestamp"] < 3600:
        return _pia_regions_cache["data"]

    try:
        resp = requests.get(PIA_SERVERLIST_URL, timeout=15)
        resp.raise_for_status()
        # PIA 响应格式：JSON + 换行 + base64签名
        text = resp.text
        json_end = max(text.rfind("}"), text.rfind("]"))
        if json_end == -1:
            raise ValueError("无法解析 PIA serverlist")
        data = json.loads(text[:json_end + 1])

        # 解析地区列表
        regions = []
        for region in data.get("regions", []):
            # 检查是否支持 WireGuard
            servers = region.get("servers", {})
            has_wg = False
            if isinstance(servers, dict):
                has_wg = "wg" in servers and len(servers.get("wg", [])) > 0
            elif isinstance(servers, list):
                has_wg = any(s.get("service_config") == "wg" for s in servers)

            if has_wg:
                regions.append({
                    "id": region.get("id"),
                    "name": region.get("name"),
                    "country": region.get("country"),
                    "port_forward": region.get("port_forward", False),
                    "geo": region.get("geo", False),
                })

        # 按国家和名称排序
        regions.sort(key=lambda r: (r.get("country", ""), r.get("name", "")))

        _pia_regions_cache = {"data": regions, "timestamp": now}
        return regions
    except Exception as exc:
        # 如果有旧缓存，返回旧数据
        if _pia_regions_cache["data"]:
            return _pia_regions_cache["data"]
        logging.error(f"Failed to fetch PIA regions: {exc}")
        raise HTTPException(status_code=500, detail="Failed to fetch PIA region list") from exc


def save_pia_profiles_yaml(profiles: List[Dict[str, Any]]) -> None:
    """保存 PIA profiles 配置"""
    data = {"profiles": profiles}
    PIA_PROFILES_FILE.parent.mkdir(parents=True, exist_ok=True)
    PIA_PROFILES_FILE.write_text(yaml.dump(data, allow_unicode=True, default_flow_style=False))


def load_custom_rules() -> Dict[str, Any]:
    """加载自定义路由规则（数据库优先，降级到 JSON）"""
    if HAS_DATABASE and USER_DB_PATH.exists():
        # 从数据库加载
        try:
            db = _get_db()
            rules = db.get_routing_rules(enabled_only=True)
            # 转换为旧格式以保持兼容性
            legacy_rules = []
            for rule in rules:
                legacy_rule = {
                    "id": rule["id"],
                    "tag": f"rule-{rule['id']}",
                    "outbound": rule["outbound"],
                    "rule_type": rule["rule_type"],
                    "target": rule["target"],
                    "priority": rule.get("priority", 0)
                }
                legacy_rules.append(legacy_rule)
            return {"rules": legacy_rules, "default_outbound": "direct", "source": "database"}
        except Exception as e:
            print(f"WARNING: Failed to load from database: {e}, falling back to JSON")

    # 降级到 JSON 文件
    if not CUSTOM_RULES_FILE.exists():
        return {"rules": [], "default_outbound": "direct", "source": "json"}
    return {**json.loads(CUSTOM_RULES_FILE.read_text()), "source": "json"}


def save_custom_rules(data: Dict[str, Any]) -> None:
    """保存自定义路由规则（仅作为备份）"""
    CUSTOM_RULES_FILE.parent.mkdir(parents=True, exist_ok=True)
    CUSTOM_RULES_FILE.write_text(json.dumps(data, indent=2, ensure_ascii=False))


def generate_singbox_rules_from_db() -> List[Dict[str, Any]]:
    """从数据库生成 sing-box 路由规则"""
    if not HAS_DATABASE or not USER_DB_PATH.exists():
        return []

    db = _get_db()
    rules_db = db.get_routing_rules(enabled_only=True)

    # 按优先级排序（高优先级在前）
    rules_db.sort(key=lambda r: r.get("priority", 0), reverse=True)

    singbox_rules = []

    # 按规则类型和出口分组
    domain_rules = {}  # outbound -> [domains]
    ip_rules = {}      # outbound -> [cidrs]
    protocol_rules = {}  # outbound -> [protocols]
    network_rules = {}   # outbound -> network (tcp/udp)
    port_rules = {}      # outbound -> [ports]
    port_range_rules = {}  # outbound -> [port_ranges]

    for rule in rules_db:
        rule_type = rule["rule_type"]
        target = rule["target"]
        outbound = rule["outbound"]

        if rule_type == "domain":
            if outbound not in domain_rules:
                domain_rules[outbound] = []
            domain_rules[outbound].append(target)

        elif rule_type == "domain_keyword":
            singbox_rules.append({
                "domain_keyword": [target],
                "outbound": outbound
            })

        elif rule_type == "ip":
            if outbound not in ip_rules:
                ip_rules[outbound] = []
            ip_rules[outbound].append(target)

        elif rule_type == "geosite":
            singbox_rules.append({
                "rule_set": [f"geosite-{target}"],
                "outbound": outbound
            })

        elif rule_type == "geoip":
            singbox_rules.append({
                "rule_set": [f"geoip-{target}"],
                "outbound": outbound
            })

        elif rule_type == "protocol":
            if outbound not in protocol_rules:
                protocol_rules[outbound] = []
            protocol_rules[outbound].append(target)

        elif rule_type == "network":
            network_rules[outbound] = target  # tcp or udp

        elif rule_type == "port":
            if outbound not in port_rules:
                port_rules[outbound] = []
            try:
                port_rules[outbound].append(int(target))
            except ValueError:
                pass

        elif rule_type == "port_range":
            if outbound not in port_range_rules:
                port_range_rules[outbound] = []
            port_range_rules[outbound].append(target)

    # 合并同出口的域名规则
    for outbound, domains in domain_rules.items():
        if domains:
            singbox_rules.append({
                "domain": domains,
                "outbound": outbound
            })

    # 合并同出口的 IP 规则
    for outbound, cidrs in ip_rules.items():
        if cidrs:
            singbox_rules.append({
                "ip_cidr": cidrs,
                "outbound": outbound
            })

    # 合并同出口的协议/端口规则
    # 收集所有有协议/网络/端口规则的出口
    protocol_port_outbounds = set(protocol_rules.keys()) | set(network_rules.keys()) | \
                              set(port_rules.keys()) | set(port_range_rules.keys())

    for outbound in protocol_port_outbounds:
        rule = {"outbound": outbound}

        if outbound in protocol_rules and protocol_rules[outbound]:
            rule["protocol"] = protocol_rules[outbound]

        if outbound in network_rules:
            rule["network"] = network_rules[outbound]

        if outbound in port_rules and port_rules[outbound]:
            rule["port"] = port_rules[outbound]

        if outbound in port_range_rules and port_range_rules[outbound]:
            rule["port_range"] = port_range_rules[outbound]

        # 只有至少有一个规则条件才添加
        if len(rule) > 1:
            singbox_rules.append(rule)

    return singbox_rules


def load_custom_category_items() -> Dict[str, List[Dict]]:
    """加载分类自定义项目（数据库优先，降级到 JSON）"""
    if HAS_DATABASE and USER_DB_PATH.exists():
        try:
            db = _get_db()
            return db.get_custom_category_items()
        except Exception as e:
            print(f"WARNING: Failed to load custom category items from database: {e}")

    # 降级到 JSON 文件
    if not CUSTOM_CATEGORY_ITEMS_FILE.exists():
        return {}
    return json.loads(CUSTOM_CATEGORY_ITEMS_FILE.read_text())


def save_custom_category_items(data: Dict[str, List[Dict]]) -> None:
    """保存分类自定义项目（仅作为备份）"""
    CUSTOM_CATEGORY_ITEMS_FILE.parent.mkdir(parents=True, exist_ok=True)
    CUSTOM_CATEGORY_ITEMS_FILE.write_text(json.dumps(data, indent=2, ensure_ascii=False))


def load_settings() -> Dict[str, Any]:
    """加载系统设置"""
    if not SETTINGS_FILE.exists():
        return {"server_endpoint": "", "listen_port": DEFAULT_WG_PORT}
    return json.loads(SETTINGS_FILE.read_text())


def save_settings(data: Dict[str, Any]) -> None:
    """保存系统设置"""
    SETTINGS_FILE.parent.mkdir(parents=True, exist_ok=True)
    SETTINGS_FILE.write_text(json.dumps(data, indent=2, ensure_ascii=False))


def _derive_api_port_from_endpoint(endpoint: str, node: dict = None) -> tuple:
    """从 endpoint 推导 API 端口

    Phase 11-Fix.B: 修复错误的 wg_port - 100 公式

    Args:
        endpoint: "host:port" 格式的端点地址
        node: 可选的节点信息字典（检查 api_port 字段）

    Returns:
        (host, api_port) 元组
    """
    if ":" in endpoint:
        host, _ = endpoint.rsplit(":", 1)
    else:
        host = endpoint

    # 优先使用显式配置的 api_port
    if node and node.get("api_port"):
        return (host, node["api_port"])

    return (host, DEFAULT_WEB_PORT)


def _get_peer_tunnel_endpoint(node: dict) -> Optional[str]:
    """动态构建节点的隧道 API 端点

    Phase A (端口变更通知): 不再依赖存储的 tunnel_api_endpoint，
    而是从 tunnel_remote_ip + api_port 动态构建。

    这解决了当节点更改 api_port 后，其他节点的存储值过时的问题。

    Args:
        node: 节点信息字典

    Returns:
        "tunnel_ip:api_port" 格式的端点地址，如果无法构建则返回 None
    """
    if not node:
        return None

    tunnel_remote_ip = node.get("tunnel_remote_ip")
    if not tunnel_remote_ip:
        return None

    # Phase A 审核修复: 验证端口范围 (注意: bool 是 int 子类，需显式排除)
    api_port = node.get("api_port")
    if not isinstance(api_port, int) or isinstance(api_port, bool) or api_port < 1 or api_port > 65535:
        api_port = DEFAULT_WEB_PORT

    return f"{tunnel_remote_ip}:{api_port}"


def parse_wireguard_conf(content: str) -> Dict[str, Any]:
    """解析 WireGuard .conf 文件内容

    返回解析后的配置字典，包含：
    - private_key: 客户端私钥
    - address: 客户端 IP 地址
    - dns: DNS 服务器（可选）
    - mtu: MTU（可选）
    - server: 服务器地址
    - port: 服务器端口
    - public_key: 服务端公钥
    - pre_shared_key: 预共享密钥（可选）
    """
    result = {
        "private_key": "",
        "address": "",
        "dns": "1.1.1.1",
        "mtu": 1420,
        "server": "",
        "port": 51820,
        "public_key": "",
        "pre_shared_key": "",
    }

    current_section = None
    for line in content.strip().split("\n"):
        line = line.strip()
        if not line or line.startswith("#"):
            continue

        # 检测 section
        if line.startswith("[") and line.endswith("]"):
            current_section = line[1:-1].lower()
            continue

        # 解析键值对
        if "=" in line:
            key, value = line.split("=", 1)
            key = key.strip().lower()
            value = value.strip()

            if current_section == "interface":
                if key == "privatekey":
                    result["private_key"] = value
                elif key == "address":
                    # 可能有多个地址，取第一个
                    result["address"] = value.split(",")[0].strip()
                elif key == "dns":
                    result["dns"] = value.split(",")[0].strip()
                elif key == "mtu":
                    try:
                        result["mtu"] = int(value)
                    except ValueError:
                        pass
            elif current_section == "peer":
                if key == "publickey":
                    result["public_key"] = value
                elif key == "presharedkey":
                    result["pre_shared_key"] = value
                elif key == "endpoint":
                    # 解析 host:port
                    if ":" in value:
                        # 处理 IPv6 地址
                        if value.startswith("["):
                            # [IPv6]:port 格式
                            idx = value.rfind("]:")
                            if idx != -1:
                                result["server"] = value[1:idx]
                                try:
                                    result["port"] = int(value[idx+2:])
                                except ValueError:
                                    pass
                        else:
                            # host:port 格式
                            parts = value.rsplit(":", 1)
                            result["server"] = parts[0]
                            if len(parts) > 1:
                                try:
                                    result["port"] = int(parts[1])
                                except ValueError:
                                    pass
                    else:
                        result["server"] = value

    return result


# ============ 认证 API 端点 ============

@app.get("/api/auth/status")
def api_auth_status():
    """检查认证状态：是否已设置密码

    此端点始终公开，用于确定显示登录页还是设置页
    """
    try:
        db = _get_db()
        is_setup = db.is_admin_setup()
    except Exception:
        is_setup = False

    return {
        "is_setup": is_setup,
        "requires_auth": True
    }


@app.post("/api/auth/setup")
def api_auth_setup(request: SetupRequest):
    """首次设置：创建管理员密码

    仅在密码未设置时可用
    """
    db = _get_db()

    if db.is_admin_setup():
        raise HTTPException(
            status_code=400,
            detail="Admin password already set"
        )

    if len(request.password) < 8:
        raise HTTPException(
            status_code=400,
            detail="Password must be at least 8 characters"
        )

    password_hash = _hash_password(request.password)
    db.set_admin_password(password_hash)

    # 创建并返回 token
    secret = db.get_or_create_jwt_secret()
    token, expires_in = _create_token(secret)

    return {
        "message": "Admin password set successfully",
        "access_token": token,
        "token_type": "bearer",
        "expires_in": expires_in
    }


@app.post("/api/auth/login")
def api_auth_login(request: LoginRequest):
    """登录获取 JWT token"""
    db = _get_db()

    if not db.is_admin_setup():
        raise HTTPException(
            status_code=400,
            detail="Admin password not set, use /api/auth/setup first"
        )

    password_hash = db.get_admin_password_hash()
    if not password_hash or not _verify_password(request.password, password_hash):
        raise HTTPException(
            status_code=401,
            detail="Invalid credentials"
        )

    secret = db.get_or_create_jwt_secret()
    token, expires_in = _create_token(secret)

    return {
        "access_token": token,
        "token_type": "bearer",
        "expires_in": expires_in
    }


@app.post("/api/auth/refresh")
def api_auth_refresh(request: Request):
    """刷新 JWT token（延长会话）"""
    # 验证当前 token（由中间件完成）
    db = _get_db()
    secret = db.get_or_create_jwt_secret()
    token, expires_in = _create_token(secret)

    return {
        "access_token": token,
        "token_type": "bearer",
        "expires_in": expires_in
    }


@app.get("/api/auth/me")
def api_auth_me():
    """获取当前用户信息（验证 token 有效性）"""
    return {
        "username": "admin",
        "role": "admin"
    }


# ============ 系统状态端点 ============

@app.get("/api/health")
def api_health():
    """健康检查端点 - 用于容器编排和负载均衡

    返回:
    - status: "healthy" | "degraded" | "unhealthy"
    - sing_box: sing-box 进程是否运行
    - database: 数据库是否可访问
    - timestamp: 检查时间
    """
    checks = {
        "sing_box": False,
        "database": False,
    }

    # 检查 sing-box 进程
    checks["sing_box"] = list_processes("sing-box")

    # 检查数据库连接
    try:
        if HAS_DATABASE and USER_DB_PATH.exists():
            db = _get_db()
            # 简单查询验证数据库可用
            db.get_setting("health_check", "ok")
            checks["database"] = True
    except Exception:
        checks["database"] = False

    # 判断整体状态
    if all(checks.values()):
        status = "healthy"
    elif checks["sing_box"]:
        status = "degraded"
    else:
        status = "unhealthy"

    return {
        "status": status,
        "checks": checks,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


@app.get("/api/status")
def api_status():
    config_stat = CONFIG_PATH.stat() if CONFIG_PATH.exists() else None
    wireguard = get_wireguard_status()
    # 从数据库获取 PIA profiles
    db = _get_db()
    pia_profiles = db.get_pia_profiles(enabled_only=False)
    return {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "sing_box_running": list_processes("sing-box"),
        "wireguard_interface": wireguard,
        "config_mtime": config_stat.st_mtime if config_stat else None,
        "pia_profiles": pia_profiles,
    }


@app.get("/api/stats/dashboard")
def api_stats_dashboard(time_range: str = "1m"):
    """获取 Dashboard 可视化统计数据

    参数：
    - time_range: 时间范围 "1m" | "1h" | "24h"
      - 1m: 最近 60 秒，1 秒间隔
      - 1h: 最近 1 小时，10 分钟间隔（6 个数据点）
      - 24h: 最近 24 小时，1 小时间隔（24 个数据点）

    返回：
    - online_clients: 在线客户端数量（有活跃连接的 WireGuard peer）
    - total_clients: 总客户端数量（所有配置的 WireGuard peer）
    - traffic_by_outbound: 按出口分组的流量 {tag: {download, upload}}
    - adblock_connections: 匹配广告拦截规则的连接数
    - active_connections: 总活跃连接数
    - rate_history: 速率历史（根据 time_range 聚合）
    """
    import urllib.request

    # 初始化返回数据
    stats = {
        "online_clients": 0,
        "total_clients": 0,
        "traffic_by_outbound": {},
        "adblock_connections": 0,
        "active_connections": 0,
    }

    # 获取总客户端数量（从数据库）
    try:
        db = _get_db()
        peers = db.get_wireguard_peers()
        stats["total_clients"] = len(peers) if peers else 0
    except Exception:
        pass

    # 使用缓存的子网前缀（避免频繁数据库查询）
    wg_subnet_prefix = get_cached_wg_subnet_prefix()

    # 从 clash_api 获取活跃连接数和在线客户端
    try:
        with urllib.request.urlopen(f"http://127.0.0.1:{DEFAULT_CLASH_API_PORT}/connections", timeout=2) as resp:
            data = json.loads(resp.read().decode())

        connections = data.get("connections", [])
        stats["active_connections"] = len(connections)

        # 统计在线客户端（WireGuard 网段的唯一 IP）
        online_ips = set()
        for conn in connections:
            metadata = conn.get("metadata", {})
            src_ip = metadata.get("sourceIP", "")
            if src_ip.startswith(wg_subnet_prefix):
                online_ips.add(src_ip)

        stats["online_clients"] = len(online_ips)

    except Exception as e:
        # clash_api 不可用时返回空数据
        pass

    # 使用累计流量统计和实时速率（由后台线程更新）
    # 包含所有配置的出口，没有流量的显示为 0
    # 排除阻止类出口（block, adblock）- 这些没有实际流量数据
    all_outbounds = _get_all_outbounds()
    blocked_outbounds = {"block", "adblock"}  # 阻止类出口，不显示在图表中
    chart_outbounds = [o for o in all_outbounds if o not in blocked_outbounds]

    with _traffic_stats_lock:
        # 确保所有出口都有流量数据（没有流量的显示为 0）
        traffic_by_outbound = {}
        for outbound in chart_outbounds:
            if outbound in _traffic_stats:
                traffic_by_outbound[outbound] = dict(_traffic_stats[outbound])
            else:
                traffic_by_outbound[outbound] = {"download": 0, "upload": 0}
        stats["traffic_by_outbound"] = traffic_by_outbound
        # 确保所有出口都有速率数据
        traffic_rates = {}
        for outbound in chart_outbounds:
            if outbound in _traffic_rates:
                traffic_rates[outbound] = dict(_traffic_rates[outbound])
            else:
                traffic_rates[outbound] = {"download_rate": 0.0, "upload_rate": 0.0}
        stats["traffic_rates"] = traffic_rates

        # 根据 time_range 聚合 rate_history
        # 1m: 最近 60 秒，1 秒间隔（原始数据）
        # 1h: 最近 1 小时，10 分钟间隔（6 个数据点）
        # 24h: 最近 24 小时，1 小时间隔（24 个数据点）
        now = int(time.time())

        if time_range == "1h":
            # 最近 1 小时，每 10 分钟聚合一次（6 个数据点）
            interval_seconds = 10 * 60  # 10 分钟
            num_points = 6
            cutoff = now - 60 * 60  # 1 小时前
        elif time_range == "24h":
            # 最近 24 小时，每 1 小时聚合一次（24 个数据点）
            interval_seconds = 60 * 60  # 1 小时
            num_points = 24
            cutoff = now - 24 * 60 * 60  # 24 小时前
        else:  # "1m" 默认
            # 最近 60 秒，不聚合，直接返回原始数据
            interval_seconds = 1
            num_points = 60
            cutoff = now - 60  # 60 秒前

        # 过滤时间范围内的数据
        filtered_data = [p for p in _rate_history if p["timestamp"] > cutoff]

        if time_range == "1m":
            # 1 分钟视图：直接返回最近 60 个数据点
            filtered_history = []
            for point in filtered_data[-60:]:
                filtered_point = {
                    "timestamp": point["timestamp"],
                    "rates": {k: v for k, v in point["rates"].items() if k not in blocked_outbounds}
                }
                filtered_history.append(filtered_point)
        else:
            # 1h/24h 视图：按时间段聚合（取平均值）
            filtered_history = []

            for i in range(num_points):
                # 计算这个时间段的起止时间
                slot_end = now - i * interval_seconds
                slot_start = slot_end - interval_seconds

                # 找到这个时间段内的所有数据点
                slot_points = [p for p in filtered_data if slot_start < p["timestamp"] <= slot_end]

                if slot_points:
                    # 计算每个出口的平均速率
                    avg_rates = {}
                    for outbound in chart_outbounds:
                        rates = [p["rates"].get(outbound, 0) for p in slot_points]
                        avg_rates[outbound] = round(sum(rates) / len(rates), 1) if rates else 0

                    filtered_history.append({
                        "timestamp": slot_end,
                        "rates": avg_rates
                    })
                else:
                    # 没有数据时填充 0
                    filtered_history.append({
                        "timestamp": slot_end,
                        "rates": {o: 0 for o in chart_outbounds}
                    })

            # 反转顺序，使时间从旧到新
            filtered_history.reverse()

        stats["rate_history"] = filtered_history

    # 从 sing-box 日志文件统计广告拦截（增量扫描优化）
    # 使用专用的 adblock 出口，日志格式: outbound/block[adblock]: blocked connection to x.x.x.x:443
    global _adblock_count, _adblock_log_position, _adblock_log_inode
    try:
        log_file = Path("/var/log/sing-box.log")
        if log_file.exists():
            # 检测日志轮转（inode 变化或文件变小）
            stat = log_file.stat()
            current_inode = stat.st_ino
            current_size = stat.st_size

            if current_inode != _adblock_log_inode or current_size < _adblock_log_position:
                # 日志轮转，重新全量扫描
                _adblock_count = 0
                _adblock_log_position = 0
                _adblock_log_inode = current_inode

            # 增量扫描：从上次位置读取新内容
            with open(log_file, "r", encoding="utf-8", errors="ignore") as f:
                f.seek(_adblock_log_position)
                for line in f:
                    if "outbound/block[adblock]: blocked connection" in line:
                        _adblock_count += 1
                _adblock_log_position = f.tell()

        stats["adblock_connections"] = _adblock_count
    except Exception:
        stats["adblock_connections"] = _adblock_count  # 出错时返回已有计数

    return stats


@app.get("/api/endpoints")
def api_list_endpoints():
    """从数据库获取所有端点配置"""
    if not HAS_DATABASE or not USER_DB_PATH.exists():
        raise HTTPException(status_code=500, detail="Database not available")

    db = _get_db()
    endpoints = []

    # 1. WireGuard 服务器端点 (wg-server)
    server = db.get_wireguard_server()
    if server and server.get("private_key"):
        peers = db.get_wireguard_peers()
        wg_endpoint = {
            "type": "wireguard",
            "tag": "wg-server",
            "system": False,
            "mtu": server.get("mtu", 1420),
            "address": [server.get("address", DEFAULT_WG_SUBNET)],
            "private_key": server.get("private_key", ""),
            "listen_port": server.get("listen_port", DEFAULT_WG_PORT),
            "peers": [
                {
                    "public_key": p.get("public_key", ""),
                    "allowed_ips": [p.get("allowed_ips", get_default_peer_ip())]
                }
                for p in peers
            ] if peers else []
        }
        endpoints.append(wg_endpoint)

    # 2. PIA 出口端点
    pia_profiles = db.get_pia_profiles(enabled_only=True)
    for idx, profile in enumerate(pia_profiles):
        if not profile.get("private_key"):
            continue  # 跳过未配置凭证的 profile
        tag = profile["name"]  # 保持原始名称，不做转换
        peer_ip = profile.get("peer_ip", "")
        if peer_ip and "/" not in peer_ip:
            peer_ip = f"{peer_ip}/32"
        pia_endpoint = {
            "type": "wireguard",
            "tag": tag,
            "address": [peer_ip] if peer_ip else [f"172.31.{30 + idx}.2/32"],
            "private_key": profile.get("private_key", ""),
            "mtu": 1300,
            "peers": [{
                "address": profile.get("server_ip", ""),
                "port": profile.get("server_port", 51820),
                "public_key": profile.get("server_public_key", ""),
                "allowed_ips": ["0.0.0.0/0", "::/0"],
                "persistent_keepalive_interval": 25
            }]
        }
        endpoints.append(pia_endpoint)

    # 3. 自定义出口端点
    custom_egress = db.get_custom_egress_list(enabled_only=True)
    for egress in custom_egress:
        address = egress.get("address", "")
        if address and "/" not in address:
            address = f"{address}/32"
        custom_endpoint = {
            "type": "wireguard",
            "tag": egress.get("tag", "custom"),
            "address": [address] if address else [],
            "private_key": egress.get("private_key", ""),
            "mtu": egress.get("mtu", 1420),
            "peers": [{
                "address": egress.get("server", ""),
                "port": egress.get("port", 51820),
                "public_key": egress.get("public_key", ""),
                "allowed_ips": ["0.0.0.0/0", "::/0"],
                "persistent_keepalive_interval": 25
            }]
        }
        if egress.get("pre_shared_key"):
            custom_endpoint["peers"][0]["pre_shared_key"] = egress["pre_shared_key"]
        endpoints.append(custom_endpoint)

    return {"endpoints": endpoints}


@app.put("/api/endpoints/{tag}")
def api_update_endpoint(tag: str, payload: EndpointUpdateRequest):
    """更新端点配置（写入数据库）"""
    if not HAS_DATABASE or not USER_DB_PATH.exists():
        raise HTTPException(status_code=500, detail="Database not available")

    db = _get_db()

    # 判断端点类型并更新对应的数据库表
    if tag == "wg-server":
        # 更新 WireGuard 服务器配置
        updates = {}
        if payload.address is not None and payload.address:
            updates["address"] = payload.address[0] if isinstance(payload.address, list) else payload.address
        if payload.private_key is not None:
            updates["private_key"] = payload.private_key
        if payload.mtu is not None:
            updates["mtu"] = payload.mtu
        if updates:
            db.update_wireguard_server(**updates)
            # 同步内核 WireGuard 入口接口
            sync_msg = _sync_kernel_wg_ingress()
            return {"message": f"endpoint {tag} updated{sync_msg}"}
        return {"message": f"endpoint {tag} updated (no changes)"}

    # 检查是否是 PIA profile
    pia_profiles = db.get_pia_profiles(enabled_only=False)
    for profile in pia_profiles:
        profile_tag = profile["name"]  # 保持原始名称
        if profile_tag == tag:
            # 更新 PIA profile（主要是 MTU，其他字段由 PIA 服务器返回）
            # PIA profile 的更新通常通过重新连接来完成
            return {"message": f"endpoint {tag} updated (PIA profiles are managed via Profile Manager)"}

    # 检查是否是自定义出口
    custom_egress = db.get_custom_egress_list(enabled_only=False)
    for egress in custom_egress:
        if egress.get("tag") == tag:
            updates = {}
            if payload.address is not None and payload.address:
                updates["address"] = payload.address[0] if isinstance(payload.address, list) else payload.address
            if payload.private_key is not None:
                updates["private_key"] = payload.private_key
            if payload.mtu is not None:
                updates["mtu"] = payload.mtu
            if updates:
                db.update_custom_egress(tag, **updates)
                # 同步内核 WireGuard 出口接口并重载 sing-box
                wg_sync_msg = _sync_kernel_wg_egress()
                try:
                    _regenerate_and_reload()
                    return {"message": f"endpoint {tag} updated{wg_sync_msg}, config reloaded"}
                except Exception as e:
                    return {"message": f"endpoint {tag} updated{wg_sync_msg}, reload failed: {e}"}
            return {"message": f"endpoint {tag} updated (no changes)"}

    raise HTTPException(status_code=404, detail=f"endpoint {tag} not found")


@app.get("/api/pia/profiles")
def api_get_pia_profiles():
    """获取所有 PIA profiles（从数据库）"""
    if not HAS_DATABASE or not USER_DB_PATH.exists():
        raise HTTPException(status_code=500, detail="Database not available")

    db = _get_db()
    profiles = db.get_pia_profiles(enabled_only=False)
    return {"profiles": profiles}


@app.get("/api/pia/regions")
def api_get_pia_regions():
    """获取 PIA 可用地区列表"""
    regions = fetch_pia_regions()
    return {"regions": regions}


@app.get("/api/pia/credentials-status")
def api_pia_credentials_status():
    """检查 PIA 凭证是否可用"""
    has_creds = has_pia_credentials()
    return {
        "has_credentials": has_creds,
        "message": "已登录" if has_creds else "未登录，需要重新登录 PIA"
    }


# ============ Profile Management APIs ============

@app.get("/api/profiles")
def api_list_profiles():
    """获取所有 VPN 线路配置（从数据库，包含连接状态）"""
    if not HAS_DATABASE or not USER_DB_PATH.exists():
        # 降级到 YAML
        profiles_config = load_pia_profiles_yaml()
        profiles = profiles_config.get("profiles", [])
    else:
        db = _get_db()
        profiles = db.get_pia_profiles(enabled_only=False)

    result = []
    for p in profiles:
        name = p.get("name", "")
        tag = name  # 保持原始名称
        # 直接从数据库读取服务器信息
        server_ip = p.get("server_ip")
        server_port = p.get("server_port")
        is_connected = bool(server_ip and p.get("private_key"))
        result.append({
            "tag": tag,
            "name": name,
            "description": p.get("description", ""),
            "region_id": p.get("region_id", ""),
            "custom_dns": p.get("custom_dns") or "",  # 空=使用 PIA DNS
            "server_ip": server_ip,
            "server_port": server_port,
            "is_connected": is_connected,
            "enabled": p.get("enabled", 1) == 1,
        })
    return {"profiles": result}


@app.post("/api/profiles")
def api_create_profile(payload: ProfileCreateRequest):
    """创建新的 VPN 线路（存入数据库）"""
    if not HAS_DATABASE or not USER_DB_PATH.exists():
        raise HTTPException(status_code=500, detail="Database not available")

    db = _get_db()

    # 检查 tag 是否已存在
    name = payload.tag.replace("-", "_")
    existing = db.get_pia_profile_by_name(name)
    if existing:
        raise HTTPException(status_code=400, detail=f"线路 {payload.tag} 已存在")

    # 验证 region_id
    regions = fetch_pia_regions()
    valid_region_ids = [r["id"] for r in regions]
    if payload.region_id not in valid_region_ids:
        raise HTTPException(status_code=400, detail=f"无效的地区 ID: {payload.region_id}")

    # 添加新 profile 到数据库
    profile_id = db.add_pia_profile(
        name=name,
        region_id=payload.region_id,
        description=payload.description,
        custom_dns=payload.custom_dns
    )

    # 如果有 PIA 凭证，自动配置新线路
    username, password = get_pia_credentials()
    provision_result = None

    if username and password:
        env = _CredentialStore.get_env_for_subprocess()
        generated_config = Path("/etc/sing-box/sing-box.generated.json")
        env.update({
            "PIA_PROFILES_FILE": str(PIA_PROFILES_FILE),
            "PIA_PROFILES_OUTPUT": str(PIA_PROFILES_OUTPUT),
            "SING_BOX_BASE_CONFIG": str(CONFIG_PATH),
            "SING_BOX_GENERATED_CONFIG": str(generated_config),
        })
        provision_script = ENTRY_DIR / "pia_provision.py"
        render_script = ENTRY_DIR / "render_singbox.py"

        try:
            run_command(["python3", str(provision_script)], env=env)
            # 同步内核 WireGuard 接口
            wg_sync_status = _sync_kernel_wg_egress()
            run_command(["python3", str(render_script)], env=env)
            reload_result = reload_singbox()
            provision_result = {"success": True, "reload": reload_result, "wg_sync": wg_sync_status}
        except Exception as exc:
            provision_result = {"success": False, "error": str(exc)}

    return {
        "message": f"线路 {payload.tag} 创建成功" + ("，已自动配置" if provision_result and provision_result.get("success") else "，请重新登录 PIA 以配置"),
        "profile_id": profile_id,
        "provision": provision_result
    }


@app.put("/api/profiles/{tag}")
def api_update_profile(tag: str, payload: ProfileUpdateRequest):
    """更新 VPN 线路配置（数据库）"""
    if not HAS_DATABASE or not USER_DB_PATH.exists():
        raise HTTPException(status_code=500, detail="Database not available")

    db = _get_db()
    name = tag.replace("-", "_")
    profile = db.get_pia_profile_by_name(name)

    if not profile:
        raise HTTPException(status_code=404, detail=f"线路 {tag} 不存在")

    # 验证 region_id
    if payload.region_id is not None:
        regions = fetch_pia_regions()
        valid_region_ids = [r["id"] for r in regions]
        if payload.region_id not in valid_region_ids:
            raise HTTPException(status_code=400, detail=f"无效的地区 ID: {payload.region_id}")

    # 更新数据库
    db.update_pia_profile(
        profile_id=profile["id"],
        description=payload.description,
        region_id=payload.region_id,
        custom_dns=payload.custom_dns
    )

    # 如果 DNS 设置变化，需要重新生成配置
    if payload.custom_dns is not None:
        try:
            _regenerate_and_reload()
            return {"message": f"线路 {tag} 更新成功，配置已重载"}
        except Exception as exc:
            return {"message": f"线路 {tag} 更新成功，但配置重载失败: {exc}"}

    return {"message": f"线路 {tag} 更新成功"}


@app.delete("/api/profiles/{tag}")
def api_delete_profile(tag: str):
    """删除 VPN 线路（数据库）"""
    if not HAS_DATABASE or not USER_DB_PATH.exists():
        raise HTTPException(status_code=500, detail="Database not available")

    db = _get_db()
    name = tag.replace("-", "_")
    profile = db.get_pia_profile_by_name(name)

    if not profile:
        raise HTTPException(status_code=404, detail=f"线路 {tag} 不存在")

    # 从数据库删除
    db.delete_pia_profile(profile["id"])

    # 同步内核 WireGuard 接口（清理已删除的接口）并重新渲染配置
    reload_status = ""
    try:
        wg_sync_status = _sync_kernel_wg_egress()
        _regenerate_and_reload()
        reload_status = f"，已重载配置{wg_sync_status}"
    except Exception as exc:
        print(f"[api] 重载配置失败: {exc}")
        reload_status = f"，重载失败: {exc}"

    return {"message": f"线路 {tag} 已删除{reload_status}"}


# ============ Route Rules Management APIs ============

@app.get("/api/rules")
def api_get_rules():
    """获取路由规则配置（从数据库读取）"""
    # 从配置中提取可用出口
    generated_config = Path("/etc/sing-box/sing-box.generated.json")
    config_path = generated_config if generated_config.exists() else CONFIG_PATH

    available_outbounds = ["direct", "block"]
    default_outbound = "direct"

    # 从数据库读取默认出口设置和所有出口
    if HAS_DATABASE and USER_DB_PATH.exists():
        try:
            db = _get_db()
            default_outbound = db.get_setting("default_outbound", "direct")

            # 从数据库读取 PIA profiles (PIA uses 'name' as tag)
            pia_profiles = db.get_pia_profiles(enabled_only=False)
            for profile in pia_profiles:
                if profile.get("name") and profile["name"] not in available_outbounds:
                    available_outbounds.append(profile["name"])

            # 从数据库读取自定义出口
            custom_egress = db.get_custom_egress_list()
            for egress in custom_egress:
                if egress.get("tag") and egress["tag"] not in available_outbounds:
                    available_outbounds.append(egress["tag"])

            # 从数据库读取 direct 出口
            direct_egress = db.get_direct_egress_list(enabled_only=True)
            for egress in direct_egress:
                if egress.get("tag") and egress["tag"] not in available_outbounds:
                    available_outbounds.append(egress["tag"])

            # 从数据库读取 OpenVPN 出口
            openvpn_egress = db.get_openvpn_egress_list(enabled_only=True)
            for egress in openvpn_egress:
                if egress.get("tag") and egress["tag"] not in available_outbounds:
                    available_outbounds.append(egress["tag"])

            # 从数据库读取 V2Ray 出口
            v2ray_egress = db.get_v2ray_egress_list(enabled_only=True)
            for egress in v2ray_egress:
                if egress.get("tag") and egress["tag"] not in available_outbounds:
                    available_outbounds.append(egress["tag"])

            # 从数据库读取 WARP 出口
            warp_egress = db.get_warp_egress_list(enabled_only=True)
            for egress in warp_egress:
                if egress.get("tag") and egress["tag"] not in available_outbounds:
                    available_outbounds.append(egress["tag"])

            # 从数据库读取出口组（负载均衡/故障转移）
            outbound_groups = db.get_outbound_groups(enabled_only=True)
            for group in outbound_groups:
                if group.get("tag") and group["tag"] not in available_outbounds:
                    available_outbounds.append(group["tag"])

            # 从数据库读取多跳链路
            node_chains = db.get_node_chains(enabled_only=True)
            for chain in node_chains:
                if chain.get("tag") and chain['tag'] not in available_outbounds:
                    available_outbounds.append(chain['tag'])
        except Exception:
            pass

    # 如果数据库没有数据，回退到配置文件
    if len(available_outbounds) == 2:  # only direct and block
        if config_path.exists():
            config = json.loads(config_path.read_text())

            # 提取可用出口
            for endpoint in config.get("endpoints", []):
                if endpoint.get("type") == "wireguard":
                    tag = endpoint.get("tag")
                    if tag and tag != "wg-server" and tag not in available_outbounds:
                        available_outbounds.append(tag)

    # 从数据库读取自定义规则
    if HAS_DATABASE and USER_DB_PATH.exists():
        db = _get_db()
        db_rules = db.get_routing_rules(enabled_only=True)

        # 按 tag 分组规则（使用数据库中的实际 tag）
        rules_by_tag = {}
        for rule in db_rules:
            rule_type = rule["rule_type"]
            target = rule["target"]
            outbound = rule["outbound"]
            # 使用数据库中的 tag，如果没有则用 outbound 生成
            tag = rule.get("tag") or f"custom-{outbound}"

            if tag not in rules_by_tag:
                rules_by_tag[tag] = {
                    "tag": tag,
                    "outbound": outbound,
                    "domains": [],
                    "domain_keywords": [],
                    "ip_cidrs": [],
                    # 新增协议/端口匹配字段
                    "protocols": [],
                    "network": None,
                    "ports": [],
                    "port_ranges": [],
                    "type": "custom"
                }

            # 根据规则类型添加到对应字段
            if rule_type == "domain":
                rules_by_tag[tag]["domains"].append(target)
            elif rule_type == "domain_keyword":
                rules_by_tag[tag]["domain_keywords"].append(target)
            elif rule_type == "ip":
                rules_by_tag[tag]["ip_cidrs"].append(target)
            # 新增协议/端口规则类型
            elif rule_type == "protocol":
                rules_by_tag[tag]["protocols"].append(target)
            elif rule_type == "network":
                rules_by_tag[tag]["network"] = target
            elif rule_type == "port":
                try:
                    rules_by_tag[tag]["ports"].append(int(target))
                except ValueError:
                    pass  # 忽略无效端口
            elif rule_type == "port_range":
                rules_by_tag[tag]["port_ranges"].append(target)

        rules = list(rules_by_tag.values())
    else:
        # 降级到 JSON 文件
        custom = load_custom_rules()
        rules = custom.get("rules", [])

    return {
        "rules": rules,
        "default_outbound": default_outbound,
        "available_outbounds": available_outbounds,
    }


@app.put("/api/rules")
def api_update_rules(payload: RouteRulesUpdateRequest):
    """更新路由规则（数据库版本，使用批量操作优化性能）"""
    if HAS_DATABASE and USER_DB_PATH.exists():
        # 使用数据库存储（方案 B）
        db = _get_db()

        # 批量删除所有规则，但保留 __adblock__ 前缀的规则（由广告拦截页面管理）
        deleted_count = db.delete_all_routing_rules(preserve_adblock=True)

        # 收集所有规则用于批量插入
        # 格式: (rule_type, target, outbound, tag, priority)
        batch_rules = []
        for rule in payload.rules:
            tag = rule.tag  # 使用规则的 tag

            # 收集域名规则
            if rule.domains:
                for domain in rule.domains:
                    batch_rules.append(("domain", domain, rule.outbound, tag, 0))

            # 收集关键词规则
            if rule.domain_keywords:
                for keyword in rule.domain_keywords:
                    batch_rules.append(("domain_keyword", keyword, rule.outbound, tag, 0))

            # 收集 IP 规则
            if rule.ip_cidrs:
                for cidr in rule.ip_cidrs:
                    batch_rules.append(("ip", cidr, rule.outbound, tag, 0))

            # 收集协议规则
            if rule.protocols:
                for protocol in rule.protocols:
                    if protocol in VALID_PROTOCOLS:
                        batch_rules.append(("protocol", protocol, rule.outbound, tag, 0))

            # 收集网络类型规则
            if rule.network and rule.network in VALID_NETWORKS:
                batch_rules.append(("network", rule.network, rule.outbound, tag, 0))

            # 收集端口规则
            if rule.ports:
                for port in rule.ports:
                    batch_rules.append(("port", str(port), rule.outbound, tag, 0))

            # 收集端口范围规则
            if rule.port_ranges:
                for port_range in rule.port_ranges:
                    batch_rules.append(("port_range", port_range, rule.outbound, tag, 0))

        # 批量插入所有规则（使用 executemany）
        added_count = db.add_routing_rules_batch(batch_rules) if batch_rules else 0

        # 保存默认出口到数据库
        db.set_setting("default_outbound", payload.default_outbound)

        # 重新生成配置并重载 sing-box
        reload_status = None
        if payload.regenerate_config:
            try:
                _regenerate_and_reload()
                reload_status = "已重载"
            except Exception as exc:
                print(f"[api] 重载配置失败: {exc}")
                reload_status = f"重载失败: {exc}"

        message = f"路由规则已保存到数据库（删除 {deleted_count} 条，添加 {added_count} 条）"
        if reload_status:
            message += f"，{reload_status}"
        return {"message": message}
    else:
        # 降级到 JSON 文件存储
        custom_data = {
            "rules": [r.dict(exclude_none=True) for r in payload.rules],
            "default_outbound": payload.default_outbound,
        }
        save_custom_rules(custom_data)
        return {"message": "路由规则已保存，需要重新连接 VPN 生效"}


class DefaultOutboundRequest(BaseModel):
    """默认出口切换请求"""
    outbound: str = Field(..., description="新的默认出口 tag")


@app.put("/api/outbound/default")
def api_switch_default_outbound(payload: DefaultOutboundRequest):
    """通过 Clash API 热切换默认出口（不中断现有连接）

    使用 sing-box 的 selector 出口 + Clash API 实现热切换：
    1. 验证出口是否有效
    2. 通过 Clash API 更新 default-exit selector 的选中项
    3. 更新数据库中的 default_outbound 设置

    由于 selector 设置了 interrupt_exist_connections: false，
    切换时现有连接不会中断。
    """
    import urllib.request
    import urllib.error
    import urllib.parse

    new_outbound = payload.outbound

    # 验证出口是否有效
    db = _get_db()
    available_outbounds = ["direct"]

    # 收集所有可用出口
    for profile in db.get_pia_profiles(enabled_only=True):
        if profile.get("private_key"):
            available_outbounds.append(profile["name"])

    for egress in db.get_custom_egress_list(enabled_only=True):
        available_outbounds.append(egress["tag"])

    for egress in db.get_direct_egress_list(enabled_only=True):
        available_outbounds.append(egress["tag"])

    for egress in db.get_openvpn_egress_list(enabled_only=True):
        available_outbounds.append(egress["tag"])

    for egress in db.get_v2ray_egress_list(enabled_only=True):
        available_outbounds.append(egress["tag"])

    for egress in db.get_warp_egress_list(enabled_only=True):
        available_outbounds.append(egress["tag"])

    for group in db.get_outbound_groups(enabled_only=True):
        available_outbounds.append(group["tag"])

    for chain in db.get_node_chains(enabled_only=True):
        if chain.get("tag"):
            available_outbounds.append(chain['tag'])

    if new_outbound not in available_outbounds:
        raise HTTPException(
            status_code=400,
            detail=f"无效的出口: {new_outbound}。可用: {', '.join(available_outbounds)}"
        )

    # 通过 Clash API 切换 selector
    # PUT /proxies/{selector_name} with body {"name": "outbound_name"}
    clash_url = f"http://127.0.0.1:{DEFAULT_CLASH_API_PORT}/proxies/default-exit"
    try:
        req_data = json.dumps({"name": new_outbound}).encode("utf-8")
        req = urllib.request.Request(
            clash_url,
            data=req_data,
            method="PUT",
            headers={"Content-Type": "application/json"}
        )
        with urllib.request.urlopen(req, timeout=5) as resp:
            # Clash API 返回 204 No Content 表示成功
            if resp.status in (200, 204):
                # 更新数据库设置
                db.set_setting("default_outbound", new_outbound)
                return {
                    "message": f"默认出口已切换为 {new_outbound}（无需重载，连接不中断）",
                    "outbound": new_outbound,
                    "hot_switch": True
                }

    except urllib.error.HTTPError as e:
        if e.code == 404:
            # selector 不存在，可能是旧配置，需要重载
            db.set_setting("default_outbound", new_outbound)
            try:
                _regenerate_and_reload()
                return {
                    "message": f"默认出口已切换为 {new_outbound}（需要重载配置）",
                    "outbound": new_outbound,
                    "hot_switch": False,
                    "reloaded": True
                }
            except Exception as reload_err:
                return {
                    "message": f"默认出口已保存，但重载失败: {reload_err}",
                    "outbound": new_outbound,
                    "hot_switch": False,
                    "reloaded": False,
                    "error": str(reload_err)
                }
        else:
            raise HTTPException(status_code=500, detail=f"Clash API 错误: HTTP {e.code}")

    except urllib.error.URLError as e:
        # sing-box 未运行，保存设置并尝试重载
        db.set_setting("default_outbound", new_outbound)
        try:
            _regenerate_and_reload()
            return {
                "message": f"默认出口已切换为 {new_outbound}（sing-box 已重载）",
                "outbound": new_outbound,
                "hot_switch": False,
                "reloaded": True
            }
        except Exception as reload_err:
            return {
                "message": f"默认出口已保存，但重载失败: {reload_err}",
                "outbound": new_outbound,
                "hot_switch": False,
                "reloaded": False,
                "error": str(reload_err)
            }

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"切换失败: {e}")


@app.get("/api/outbound/default")
def api_get_default_outbound():
    """获取当前默认出口设置"""
    db = _get_db()
    default_outbound = db.get_setting("default_outbound", "direct")

    # 收集所有可用出口
    available_outbounds = ["direct"]

    for profile in db.get_pia_profiles(enabled_only=True):
        if profile.get("private_key"):
            available_outbounds.append(profile["name"])

    for egress in db.get_custom_egress_list(enabled_only=True):
        available_outbounds.append(egress["tag"])

    for egress in db.get_direct_egress_list(enabled_only=True):
        available_outbounds.append(egress["tag"])

    for egress in db.get_openvpn_egress_list(enabled_only=True):
        available_outbounds.append(egress["tag"])

    for egress in db.get_v2ray_egress_list(enabled_only=True):
        available_outbounds.append(egress["tag"])

    for egress in db.get_warp_egress_list(enabled_only=True):
        available_outbounds.append(egress["tag"])

    for group in db.get_outbound_groups(enabled_only=True):
        available_outbounds.append(group["tag"])

    for chain in db.get_node_chains(enabled_only=True):
        if chain.get("tag"):
            available_outbounds.append(chain['tag'])

    return {
        "outbound": default_outbound,
        "available_outbounds": available_outbounds
    }


@app.post("/api/rules")
def api_add_rule(payload: CustomRuleRequest):
    """添加路由规则（Phase 11-Fix.AB: 别名，等同于 POST /api/rules/custom）"""
    return api_add_custom_rule(payload)


@app.post("/api/rules/custom")
def api_add_custom_rule(payload: CustomRuleRequest):
    """添加自定义路由规则（数据库版本，使用批量操作优化性能）"""
    # 验证至少有一种匹配规则
    has_domain_rules = payload.domains or payload.domain_keywords or payload.ip_cidrs
    has_protocol_rules = payload.protocols or payload.network or payload.ports or payload.port_ranges
    if not has_domain_rules and not has_protocol_rules:
        raise HTTPException(
            status_code=400,
            detail="至少需要提供一种匹配规则（域名、关键词、IP、协议或端口）"
        )

    # 验证协议类型
    if payload.protocols:
        invalid_protocols = [p for p in payload.protocols if p not in VALID_PROTOCOLS]
        if invalid_protocols:
            raise HTTPException(
                status_code=400,
                detail=f"无效的协议类型: {', '.join(invalid_protocols)}。支持: {', '.join(VALID_PROTOCOLS)}"
            )

    # 验证网络类型
    if payload.network and payload.network not in VALID_NETWORKS:
        raise HTTPException(
            status_code=400,
            detail=f"无效的网络类型: {payload.network}。支持: tcp, udp"
        )

    if not HAS_DATABASE or not USER_DB_PATH.exists():
        raise HTTPException(status_code=500, detail="数据库不可用")

    db = _get_db()

    try:
        # 收集所有规则用于批量插入
        # 格式: (rule_type, target, outbound, tag, priority)
        batch_rules = []

        # 收集域名规则
        if payload.domains:
            for domain in payload.domains:
                batch_rules.append(("domain", domain, payload.outbound, payload.tag, 0))

        # 收集域名关键词规则
        if payload.domain_keywords:
            for keyword in payload.domain_keywords:
                batch_rules.append(("domain_keyword", keyword, payload.outbound, payload.tag, 0))

        # 收集 IP 规则
        if payload.ip_cidrs:
            for cidr in payload.ip_cidrs:
                batch_rules.append(("ip", cidr, payload.outbound, payload.tag, 0))

        # 收集协议规则
        if payload.protocols:
            for protocol in payload.protocols:
                batch_rules.append(("protocol", protocol, payload.outbound, payload.tag, 0))

        # 收集网络类型规则
        if payload.network:
            batch_rules.append(("network", payload.network, payload.outbound, payload.tag, 0))

        # 收集端口规则
        if payload.ports:
            for port in payload.ports:
                batch_rules.append(("port", str(port), payload.outbound, payload.tag, 0))

        # 收集端口范围规则
        if payload.port_ranges:
            for port_range in payload.port_ranges:
                batch_rules.append(("port_range", port_range, payload.outbound, payload.tag, 0))

        # 批量插入所有规则
        added_count = db.add_routing_rules_batch(batch_rules) if batch_rules else 0

        return {
            "message": f"自定义规则 '{payload.tag}' 已添加到数据库（{added_count} 条）",
            "tag": payload.tag,
            "outbound": payload.outbound,
            "count": added_count
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"添加规则失败: {str(e)}")


@app.delete("/api/rules/custom/{rule_id}")
def api_delete_custom_rule(rule_id: int):
    """删除自定义路由规则（数据库版本）"""
    if not HAS_DATABASE or not USER_DB_PATH.exists():
        raise HTTPException(status_code=500, detail="数据库不可用")

    db = _get_db()
    success = db.delete_routing_rule(rule_id)

    if not success:
        raise HTTPException(status_code=404, detail=f"规则 ID {rule_id} 不存在")

    return {"message": f"规则 ID {rule_id} 已删除"}


@app.delete("/api/rules/custom/by-tag/{tag}")
def api_delete_custom_rule_by_tag(tag: str):
    """删除自定义路由规则（通过 tag，兼容旧接口）
    注意：此端点已废弃，建议使用 DELETE /api/rules/custom/{rule_id}
    """
    if not HAS_DATABASE or not USER_DB_PATH.exists():
        raise HTTPException(status_code=503, detail="数据库不可用")

    # 由于数据库中没有直接存储 tag，我们无法通过 tag 删除
    # 返回提示信息，建议使用新的 API
    raise HTTPException(
        status_code=410,
        detail="此 API 已废弃。请使用 DELETE /api/rules/custom/{rule_id} 或通过前端界面删除规则"
    )


@app.post("/api/pia/login")
def api_pia_login(payload: PiaLoginRequest):
    # 先验证凭证（获取 token）
    try:
        token_resp = requests.post(
            "https://www.privateinternetaccess.com/api/client/v2/token",
            json={"username": payload.username, "password": payload.password},
            timeout=10
        )
        if token_resp.status_code != 200:
            logging.warning(f"PIA login failed: status={token_resp.status_code}")
            raise HTTPException(
                status_code=401,
                detail="PIA login failed, please check your credentials"
            )
        token_data = token_resp.json()
        if not token_data.get("token"):
            raise HTTPException(status_code=401, detail="PIA login failed: invalid response")
    except requests.RequestException as exc:
        logging.error(f"Cannot connect to PIA server: {exc}")
        raise HTTPException(status_code=500, detail="Cannot connect to PIA server") from exc

    # 保存凭证到安全存储（内存，不暴露在 /proc/<pid>/environ）
    set_pia_credentials(payload.username, payload.password)

    # 检查是否有 profiles 配置（从数据库读取）
    db = _get_db()
    profiles = db.get_pia_profiles(enabled_only=True)

    if not profiles:
        # 没有配置线路，仅保存凭证
        return {
            "message": "PIA 凭证验证成功。请先在「PIA 线路」页面添加线路配置。",
            "has_profiles": False
        }

    # 有 profiles，运行完整的 provision 流程
    env = _CredentialStore.get_env_for_subprocess()
    generated_config = Path("/etc/sing-box/sing-box.generated.json")
    env.update(
        {
            "PIA_PROFILES_FILE": str(PIA_PROFILES_FILE),
            "PIA_PROFILES_OUTPUT": str(PIA_PROFILES_OUTPUT),
            "SING_BOX_BASE_CONFIG": str(CONFIG_PATH),
            "SING_BOX_GENERATED_CONFIG": str(generated_config),
        }
    )
    provision_script = ENTRY_DIR / "pia_provision.py"
    render_script = ENTRY_DIR / "render_singbox.py"
    run_command(["python3", str(provision_script)], env=env)

    if payload.regenerate_config:
        run_command(["python3", str(render_script)], env=env)
        # 自动重载 sing-box 使配置生效
        reload_result = reload_singbox()
        # 同步内核 WireGuard 出口接口（PIA 使用 kernel WG）
        wg_sync_msg = _sync_kernel_wg_egress()
        return {
            "message": f"PIA 登录成功，配置已生成并重载{wg_sync_msg}",
            "has_profiles": True,
            "reload": reload_result
        }
    return {"message": "PIA 登录成功，配置已生成（未重载）", "has_profiles": True}


@app.post("/api/actions/geodata")
def api_refresh_geodata():
    fetch_script = ENTRY_DIR / "fetch-geodata.sh"
    run_command([str(fetch_script), "/etc/sing-box"])
    return {"message": "geodata refresh started"}


def reload_singbox() -> dict:
    """重新加载 sing-box 配置

    entrypoint.sh 现在会自动监控 sing-box 进程：
    - 如果 sing-box 退出，entrypoint 会自动用最新配置重启它
    - 优先使用生成的配置 (/etc/sing-box/sing-box.generated.json)

    重载策略：
    1. 先尝试 SIGHUP 热重载
    2. 如果失败，杀掉 sing-box 让 entrypoint 重启
    """
    generated_config = Path("/etc/sing-box/sing-box.generated.json")

    try:
        # 检查生成的配置是否存在
        if not generated_config.exists():
            return {"success": False, "message": "生成的配置文件不存在，请先登录 PIA"}

        # 验证配置文件语法
        check_result = subprocess.run(
            ["sing-box", "check", "-c", str(generated_config)],
            capture_output=True,
            text=True,
        )
        if check_result.returncode != 0:
            return {"success": False, "message": f"配置文件语法错误: {check_result.stderr}"}

        # 检查 sing-box 是否正在运行
        if not list_processes("sing-box"):
            # sing-box 未运行，entrypoint 应该会自动启动
            # 等待几秒看是否启动
            time.sleep(3)
            if list_processes("sing-box"):
                return {"success": True, "message": "sing-box 已由 entrypoint 启动", "method": "auto"}
            return {"success": False, "message": "sing-box 未运行，请检查容器状态"}

        # 尝试 SIGHUP 热重载 (sing-box 使用 generated_config 启动，会重新加载该文件)
        result = subprocess.run(
            ["pkill", "-HUP", "sing-box"],
            capture_output=True,
            text=True,
        )
        if result.returncode == 0:
            time.sleep(1)
            if list_processes("sing-box"):
                return {"success": True, "message": "sing-box 配置已重新加载", "method": "SIGHUP"}

        # SIGHUP 失败，杀掉进程让 entrypoint 自动重启
        subprocess.run(["pkill", "sing-box"], capture_output=True)
        time.sleep(3)  # 等待 entrypoint 重启 sing-box

        if list_processes("sing-box"):
            return {"success": True, "message": "sing-box 已重启", "method": "restart"}
        return {"success": False, "message": "sing-box 重启失败，请检查容器日志"}
    except Exception as exc:
        return {"success": False, "message": str(exc)}


@app.post("/api/actions/reload")
def api_reload_singbox():
    """重新加载 sing-box 配置"""
    result = reload_singbox()
    if not result.get("success"):
        # Phase 11-Fix.U: 防御性默认值
        raise HTTPException(status_code=500, detail=result.get("message", "Reload failed"))
    return result


@app.get("/api/profiles/status")
def api_profiles_status():
    """获取各 WireGuard 出口的连接状态（从数据库）"""
    # 从数据库获取 PIA profiles
    db = _get_db()
    db_profiles = db.get_pia_profiles(enabled_only=True)

    # 构建 name -> profile 映射
    profile_by_name = {p["name"]: p for p in db_profiles}

    profiles = []
    sing_box_running = list_processes("sing-box")

    for db_profile in db_profiles:
        name = db_profile["name"]
        tag = name  # 保持原始名称
        server_ip = db_profile.get("server_ip", "")
        server_port = db_profile.get("server_port", 0)
        private_key = db_profile.get("private_key", "")

        # 检查是否有有效配置
        is_configured = bool(server_ip and private_key)

        profiles.append({
            "tag": tag,
            "description": db_profile.get("description", tag),
            "region_id": db_profile.get("region_id", ""),
            "server_ip": server_ip if is_configured else "未配置",
            "server_port": server_port,
            "is_configured": is_configured,
            "status": "connected" if is_configured and sing_box_running else "disconnected"
        })

    return {"profiles": profiles, "sing_box_running": sing_box_running}


class ProfileReconnectRequest(BaseModel):
    profile_tag: str


@app.post("/api/profiles/reconnect")
def api_reconnect_profile(payload: ProfileReconnectRequest):
    """重新连接指定的 VPN 线路

    此 API 会为指定的 profile 重新生成 WireGuard 密钥并重新连接。
    需要先登录 PIA（凭证存储在安全存储中或之前的会话中）。
    """
    # 检查安全存储中是否有 PIA 凭证
    if not has_pia_credentials():
        raise HTTPException(status_code=400, detail="PIA 凭证未设置，请通过登录页面登录")

    # 动态映射 tag 到 profile key（tag 用 - 分隔，key 用 _ 分隔）
    profile_key = payload.profile_tag.replace("-", "_")

    # 验证 profile 是否存在于数据库
    db = _get_db()
    profiles = db.get_pia_profiles(enabled_only=True)
    valid_names = [p.get("name") for p in profiles]
    if profile_key not in valid_names:
        raise HTTPException(status_code=400, detail=f"未知的 profile: {payload.profile_tag}")

    # 为了重新连接单个 profile，我们运行 provision 脚本
    # 但只更新指定的 profile
    env = _CredentialStore.get_env_for_subprocess()
    generated_config = Path("/etc/sing-box/sing-box.generated.json")
    env.update({
        "PIA_PROFILES_FILE": str(PIA_PROFILES_FILE),
        "PIA_PROFILES_OUTPUT": str(PIA_PROFILES_OUTPUT),
        "SING_BOX_BASE_CONFIG": str(CONFIG_PATH),
        "SING_BOX_GENERATED_CONFIG": str(generated_config),
    })

    provision_script = ENTRY_DIR / "pia_provision.py"
    render_script = ENTRY_DIR / "render_singbox.py"

    try:
        # 只重连指定的 profile
        run_command(["python3", str(provision_script), "--profile", profile_key], env=env)
        run_command(["python3", str(render_script)], env=env)
        reload_result = reload_singbox()
        # 同步内核 WireGuard 出口接口（PIA 使用 kernel WG）
        wg_sync_msg = _sync_kernel_wg_egress()
        # 同步所有出口组的 ECMP 路由和 SNAT 规则（peer_ip 可能改变）
        ecmp_sync_msg = _sync_all_ecmp_groups()
        return {
            "message": f"已重新连接 {payload.profile_tag}{wg_sync_msg}{ecmp_sync_msg}",
            "reload": reload_result
        }
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@app.get("/api/wireguard/peers")
def api_list_wireguard_peers():
    if not WG_CONFIG_PATH.exists():
        raise HTTPException(status_code=404, detail="wireguard server config missing")
    data = json.loads(WG_CONFIG_PATH.read_text())
    return data


# ============ Ingress WireGuard Management APIs ============

def load_ingress_config() -> dict:
    """加载入口 WireGuard 配置（从数据库）"""
    if not HAS_DATABASE or not USER_DB_PATH.exists():
        # 降级到 JSON 文件
        if not WG_CONFIG_PATH.exists():
            return {
                "interface": {
                    "name": "wg-ingress",
                    "address": DEFAULT_WG_SUBNET,
                    "listen_port": DEFAULT_WG_PORT,
                    "mtu": 1420,
                    "private_key": ""
                },
                "peers": []
            }
        return json.loads(WG_CONFIG_PATH.read_text())

    # 从数据库加载
    db = _get_db()

    # 获取服务器配置
    server = db.get_wireguard_server()

    # 如果没有服务器配置或没有私钥，自动初始化
    if not server or not server.get("private_key"):
        try:
            private_key = subprocess.run(
                ["wg", "genkey"],
                capture_output=True, text=True, check=True
            ).stdout.strip()
            db.set_wireguard_server(
                interface_name="wg-ingress",
                address=DEFAULT_WG_SUBNET,
                listen_port=DEFAULT_WG_PORT,
                mtu=1420,
                private_key=private_key
            )
            server = db.get_wireguard_server()
            print("[api] Auto-initialized WireGuard server config with generated private key")
        except Exception as e:
            print(f"[api] Warning: Failed to auto-initialize WireGuard server: {e}")

    interface_data = {
        "name": server.get("interface_name", "wg-ingress") if server else "wg-ingress",
        "address": server.get("address", DEFAULT_WG_SUBNET) if server else DEFAULT_WG_SUBNET,
        "listen_port": server.get("listen_port", DEFAULT_WG_PORT) if server else DEFAULT_WG_PORT,
        "mtu": server.get("mtu", 1420) if server else 1420,
        "private_key": server.get("private_key", "") if server else ""
    }

    # 获取对等点配置
    peers = db.get_wireguard_peers(enabled_only=False)
    peers_data = []
    for peer in peers:
        peers_data.append({
            "id": peer["id"],
            "name": peer["name"],
            "public_key": peer["public_key"],
            "allowed_ips": peer["allowed_ips"].split(",") if isinstance(peer["allowed_ips"], str) else peer["allowed_ips"],
            "preshared_key": peer.get("preshared_key"),
            "allow_lan": peer.get("allow_lan", 0) == 1,
            "lan_subnet": peer.get("lan_subnet"),
            "default_outbound": peer.get("default_outbound"),
            "enabled": peer.get("enabled", 1) == 1
        })

    return {
        "interface": interface_data,
        "peers": peers_data
    }


def save_ingress_config(data: dict) -> None:
    """保存入口 WireGuard 配置（到数据库）"""
    if not HAS_DATABASE or not USER_DB_PATH.exists():
        # 降级到 JSON 文件
        WG_CONFIG_PATH.parent.mkdir(parents=True, exist_ok=True)
        WG_CONFIG_PATH.write_text(json.dumps(data, indent=2, ensure_ascii=False))
        return

    db = _get_db()

    # 保存服务器配置
    interface = data.get("interface", {})
    db.set_wireguard_server(
        interface_name=interface.get("name", "wg-ingress"),
        address=interface.get("address", DEFAULT_WG_SUBNET),
        listen_port=interface.get("listen_port", DEFAULT_WG_PORT),
        mtu=interface.get("mtu", 1420),
        private_key=interface.get("private_key", "")
    )

    # 注意：对等点的添加/删除应该通过专用的 db.add_wireguard_peer() 和 db.delete_wireguard_peer()
    # 这个函数主要用于保存接口配置，对等点管理在 API 层面单独处理


def generate_wireguard_keypair() -> tuple:
    """生成 WireGuard 密钥对"""
    try:
        # 生成私钥
        private_key = subprocess.run(
            ["wg", "genkey"],
            capture_output=True, text=True, check=True
        ).stdout.strip()
        # 从私钥生成公钥
        public_key = subprocess.run(
            ["wg", "pubkey"],
            input=private_key,
            capture_output=True, text=True, check=True
        ).stdout.strip()
        return private_key, public_key
    except subprocess.CalledProcessError as exc:
        raise HTTPException(status_code=500, detail=f"生成密钥对失败: {exc.stderr}") from exc
    except FileNotFoundError:
        raise HTTPException(status_code=500, detail="wg 命令不可用") from None


def get_next_peer_ip(config: dict) -> str:
    """获取下一个可用的 peer IP（避开出口端点使用的 IP）"""
    interface_addr = config.get("interface", {}).get("address", DEFAULT_WG_SUBNET)
    # 解析网段
    base_ip = interface_addr.split("/")[0]
    parts = base_ip.rsplit(".", 1)
    base = parts[0]

    # 收集已用的 IP
    used_ips = {1}  # 1 是网关自己

    # 1. 已有的入口客户端
    for peer in config.get("peers", []):
        allowed_ips = peer.get("allowed_ips", [])
        # 处理数据库中的字符串格式和列表格式
        if isinstance(allowed_ips, str):
            allowed_ips = [allowed_ips]
        for allowed_ip in allowed_ips:
            ip = allowed_ip.split("/")[0]
            if ip.startswith(base):
                last_octet = int(ip.rsplit(".", 1)[1])
                used_ips.add(last_octet)

    # 2. 检查出口端点使用的 IP（避免冲突）
    try:
        db = _get_db()

        # 2a. Custom WireGuard 出口
        for egress in db.get_custom_egress_list():
            addr = egress.get("address", "")
            if addr:
                ip = addr.split("/")[0]
                if ip.startswith(base):
                    try:
                        last_octet = int(ip.rsplit(".", 1)[1])
                        used_ips.add(last_octet)
                    except (ValueError, IndexError):
                        pass

        # 2b. PIA 出口
        for profile in db.get_pia_profiles(enabled_only=False):
            peer_ip = profile.get("peer_ip", "")
            if peer_ip:
                ip = peer_ip.split("/")[0]
                if ip.startswith(base):
                    try:
                        last_octet = int(ip.rsplit(".", 1)[1])
                        used_ips.add(last_octet)
                    except (ValueError, IndexError):
                        pass
    except Exception as e:
        # 数据库错误时仍然继续，只是不检查出口冲突
        print(f"[WARN] 检查出口 IP 冲突时出错: {e}")

    # 找到下一个可用的
    for i in range(2, 255):
        if i not in used_ips:
            return f"{base}.{i}"

    raise HTTPException(status_code=400, detail="IP 地址已用尽")


def get_ingress_public_key(config: dict) -> str:
    """从私钥计算入口接口的公钥"""
    private_key = config.get("interface", {}).get("private_key", "")
    if not private_key:
        return ""
    try:
        public_key = subprocess.run(
            ["wg", "pubkey"],
            input=private_key,
            capture_output=True, text=True, check=True
        ).stdout.strip()
        return public_key
    except Exception:
        return ""


def get_peer_status_from_clash_api() -> dict:
    """从 sing-box clash_api 获取 peer 连接状态

    Updates global _peer_activity_cache with last_seen timestamps for each peer IP.
    This cache is used to determine online status even when no active connections exist.

    优化: 使用缓存 + 短超时避免阻塞
    - 超时从 2s 改为 0.5s
    - 失败时返回缓存数据（10秒有效期）
    """
    global _peer_activity_cache, _clash_api_cache, _clash_api_cache_time
    import time
    peer_status = {}  # ip -> {"active": bool, "last_seen": timestamp, "rx": int, "tx": int}

    # 使用缓存的子网前缀（避免频繁数据库查询）
    wg_subnet_prefix = get_cached_wg_subnet_prefix()
    now = time.time()
    now_int = int(now)

    # 尝试获取 clash_api 数据
    data = None
    try:
        # 查询 sing-box clash_api 获取活跃连接（超时 0.5s）
        import urllib.request
        with urllib.request.urlopen(f"http://127.0.0.1:{DEFAULT_CLASH_API_PORT}/connections", timeout=_CLASH_API_TIMEOUT) as resp:
            data = json.loads(resp.read().decode())
        # 成功时更新缓存
        _clash_api_cache = data
        _clash_api_cache_time = now
    except Exception:
        # 失败时使用缓存（10秒有效期）
        if now - _clash_api_cache_time < 10 and _clash_api_cache:
            data = _clash_api_cache

    if data is None:
        return peer_status

    connections = data.get("connections", [])

    # 遍历所有连接，按源 IP 分组
    for conn in connections:
        metadata = conn.get("metadata", {})
        src_ip = metadata.get("sourceIP", "")

        # 只处理来自 WireGuard 网段的连接
        if not src_ip.startswith(wg_subnet_prefix):
            continue

        # 提取流量数据
        download = conn.get("download", 0)
        upload = conn.get("upload", 0)

        if src_ip not in peer_status:
            peer_status[src_ip] = {
                "active": True,
                "last_seen": now_int,
                "rx": 0,
                "tx": 0,
                "connections": 0
            }

        peer_status[src_ip]["rx"] += download
        peer_status[src_ip]["tx"] += upload
        peer_status[src_ip]["connections"] += 1

    # Update global peer activity cache with current activity
    with _peer_activity_lock:
        for ip, status in peer_status.items():
            if ip not in _peer_activity_cache:
                _peer_activity_cache[ip] = {"last_seen": 0, "rx": 0, "tx": 0}

            # Update last_seen timestamp when we see new activity
            if status["rx"] > 0 or status["tx"] > 0:
                _peer_activity_cache[ip]["last_seen"] = now_int
                _peer_activity_cache[ip]["rx"] = status["rx"]
                _peer_activity_cache[ip]["tx"] = status["tx"]

    return peer_status


def get_wg_show_info() -> dict:
    """从内核 WireGuard 获取接口和 peer 状态

    使用 wg show 命令获取真实的 WireGuard 状态，包括:
    - 握手时间 (latest handshake)
    - 流量统计 (transfer)
    - 端点信息 (endpoint)
    """
    import time
    interface = os.environ.get("WG_INTERFACE", "wg-ingress")

    result = {"interface": {}, "peers": {}}

    try:
        proc = subprocess.run(
            ["wg", "show", interface],
            capture_output=True, text=True
        )
        if proc.returncode != 0:
            return result

        current_peer = None
        for line in proc.stdout.strip().split('\n'):
            line = line.rstrip()

            if line.startswith('interface:'):
                result["interface"]["name"] = line.split(':', 1)[1].strip()
            elif line.startswith('  public key:'):
                result["interface"]["public_key"] = line.split(':', 1)[1].strip()
            elif line.startswith('  listening port:'):
                result["interface"]["listen_port"] = int(line.split(':', 1)[1].strip())
            elif line.startswith('peer:'):
                current_peer = line.split(':', 1)[1].strip()
                result["peers"][current_peer] = {
                    "public_key": current_peer,
                    "endpoint": None,
                    "allowed_ips": None,
                    "latest_handshake": 0,
                    "rx_bytes": 0,
                    "tx_bytes": 0
                }
            elif current_peer:
                if line.startswith('  endpoint:'):
                    result["peers"][current_peer]["endpoint"] = line.split(':', 1)[1].strip()
                elif line.startswith('  allowed ips:'):
                    result["peers"][current_peer]["allowed_ips"] = line.split(':', 1)[1].strip()
                elif line.startswith('  latest handshake:'):
                    # Parse "X seconds/minutes/hours ago" or "never"
                    handshake_str = line.split(':', 1)[1].strip()
                    if handshake_str != "(none)":
                        # Convert to timestamp
                        result["peers"][current_peer]["latest_handshake"] = _parse_handshake_time(handshake_str)
                elif line.startswith('  transfer:'):
                    # Parse "X received, Y sent"
                    transfer_str = line.split(':', 1)[1].strip()
                    rx, tx = _parse_transfer(transfer_str)
                    result["peers"][current_peer]["rx_bytes"] = rx
                    result["peers"][current_peer]["tx_bytes"] = tx

    except Exception as e:
        print(f"[api] wg show failed: {e}")

    return result


def _parse_handshake_time(handshake_str: str) -> int:
    """解析 wg show 的握手时间字符串，返回 Unix 时间戳"""
    import time
    import re

    if not handshake_str or handshake_str == "(none)":
        return 0

    now = int(time.time())

    # Match patterns like "47 seconds ago", "2 minutes, 30 seconds ago"
    total_seconds = 0

    # Extract all time components
    patterns = [
        (r'(\d+)\s*second', 1),
        (r'(\d+)\s*minute', 60),
        (r'(\d+)\s*hour', 3600),
        (r'(\d+)\s*day', 86400),
    ]

    for pattern, multiplier in patterns:
        match = re.search(pattern, handshake_str)
        if match:
            total_seconds += int(match.group(1)) * multiplier

    if total_seconds > 0:
        return now - total_seconds

    return 0


def _parse_transfer(transfer_str: str) -> tuple:
    """解析 wg show 的流量字符串，返回 (rx_bytes, tx_bytes)"""
    import re

    rx_bytes = 0
    tx_bytes = 0

    # Match patterns like "47.71 KiB received, 176.50 KiB sent"
    # or "1.23 MiB received, 456.78 KiB sent"
    units = {'B': 1, 'KiB': 1024, 'MiB': 1024**2, 'GiB': 1024**3, 'TiB': 1024**4}

    rx_match = re.search(r'([\d.]+)\s*(B|KiB|MiB|GiB|TiB)\s*received', transfer_str)
    tx_match = re.search(r'([\d.]+)\s*(B|KiB|MiB|GiB|TiB)\s*sent', transfer_str)

    if rx_match:
        rx_bytes = int(float(rx_match.group(1)) * units.get(rx_match.group(2), 1))
    if tx_match:
        tx_bytes = int(float(tx_match.group(1)) * units.get(tx_match.group(2), 1))

    return rx_bytes, tx_bytes


def get_peer_handshake_info() -> dict:
    """获取 peer 握手状态（从内核 WireGuard）

    使用 wg show 命令获取真实的握手时间，比 clash_api 推断更准确。
    """
    handshakes = {}

    # 从内核 WireGuard 获取状态
    wg_info = get_wg_show_info()

    for pubkey, peer_info in wg_info.get("peers", {}).items():
        handshakes[pubkey] = peer_info.get("latest_handshake", 0)

    return handshakes


def get_peer_transfer_info() -> dict:
    """获取 peer 流量统计（从内核 WireGuard）

    使用 wg show 命令获取真实的流量统计。
    """
    transfers = {}

    # 从内核 WireGuard 获取状态
    wg_info = get_wg_show_info()

    for pubkey, peer_info in wg_info.get("peers", {}).items():
        transfers[pubkey] = {
            "rx": peer_info.get("rx_bytes", 0),
            "tx": peer_info.get("tx_bytes", 0)
        }

    return transfers


def apply_ingress_config(config: dict) -> dict:
    """应用入口 WireGuard 配置到系统

    Phase 11-Fix.AA: 支持用户态和内核 WireGuard 两种模式：
    - USERSPACE_WG=true (默认): 通过 IPC 调用 rust-router 管理 peer
    - USERSPACE_WG=false: 通过 wg set 命令直接管理 peer (内核模式)
    """
    # Phase 11-Fix.AA/AC: Userspace WireGuard mode is default (matches entrypoint.sh)
    userspace_wg = os.environ.get("USERSPACE_WG", "true").lower() == "true"

    if userspace_wg:
        return _apply_ingress_config_userspace(config)
    else:
        return _apply_ingress_config_kernel(config)


def _apply_ingress_config_userspace(config: dict) -> dict:
    """Phase 11-Fix.AA: 应用入口配置到用户态 WireGuard (via IPC)"""
    import asyncio
    from rust_router_client import RustRouterClient

    async def _sync_peers_via_ipc():
        try:
            client = RustRouterClient()
            peers = config.get("peers", [])

            # Get current peers from rust-router
            current_peers_list = await client.list_ingress_peers()
            current_peers = {p.get("public_key") for p in current_peers_list if p.get("public_key")}

            # Calculate desired peers
            desired_peers = {p.get("public_key") for p in peers if p.get("public_key")}

            removed_count = 0
            added_count = 0
            updated_count = 0

            # Remove peers not in desired list
            for pubkey in current_peers - desired_peers:
                if pubkey:
                    result = await client.remove_ingress_peer(pubkey)
                    if result.success:
                        removed_count += 1
                        print(f"[api] Removed peer via IPC: {pubkey[:20]}...")
                    else:
                        print(f"[api] Failed to remove peer via IPC: {result.error or result.message}")

            # Add or update peers
            for peer in peers:
                pubkey = peer.get("public_key")
                if not pubkey:
                    continue

                allowed_ips = peer.get("allowed_ips", get_default_peer_ip())
                if isinstance(allowed_ips, list):
                    allowed_ips = ",".join(allowed_ips)

                name = peer.get("name")
                preshared_key = peer.get("preshared_key")

                result = await client.add_ingress_peer(
                    public_key=pubkey,
                    allowed_ips=allowed_ips,
                    name=name,
                    preshared_key=preshared_key,
                )

                if result.success:
                    if pubkey in current_peers:
                        updated_count += 1
                        print(f"[api] Updated peer via IPC: {peer.get('name', 'unknown')} ({pubkey[:20]}...)")
                    else:
                        added_count += 1
                        print(f"[api] Added peer via IPC: {peer.get('name', 'unknown')} ({pubkey[:20]}...)")
                else:
                    print(f"[api] Failed to add/update peer via IPC: {result.error or result.message}")

            await client.close()
            return {
                "success": True,
                "message": f"Peers synced via IPC (added={added_count}, updated={updated_count}, removed={removed_count})"
            }
        except Exception as exc:
            return {"success": False, "message": f"IPC sync failed: {exc}"}

    # Run async code in sync context
    try:
        loop = asyncio.get_event_loop()
        if loop.is_running():
            # If already in an async context, create a new loop in a thread
            import concurrent.futures
            with concurrent.futures.ThreadPoolExecutor() as pool:
                future = pool.submit(asyncio.run, _sync_peers_via_ipc())
                return future.result(timeout=30)
        else:
            return loop.run_until_complete(_sync_peers_via_ipc())
    except RuntimeError:
        # No event loop exists, create one
        return asyncio.run(_sync_peers_via_ipc())


def _apply_ingress_config_kernel(config: dict) -> dict:
    """应用入口配置到内核 WireGuard (via wg set)"""
    try:
        interface = os.environ.get("WG_INTERFACE", "wg-ingress")
        peers = config.get("peers", [])

        # 获取当前内核 WireGuard peers
        result = subprocess.run(
            ["wg", "show", interface, "peers"],
            capture_output=True, text=True
        )
        current_peers = set()
        if result.returncode == 0 and result.stdout.strip():
            current_peers = set(line.strip() for line in result.stdout.strip().split('\n') if line.strip())

        # 计算期望的 peers
        desired_peers = {p.get("public_key") for p in peers if p.get("public_key")}

        # 删除不在期望列表中的 peers
        for pubkey in current_peers - desired_peers:
            if pubkey:
                subprocess.run(
                    ["wg", "set", interface, "peer", pubkey, "remove"],
                    check=True
                )
                print(f"[api] Removed peer: {pubkey[:20]}...")

        # 添加或更新 peers
        for peer in peers:
            pubkey = peer.get("public_key")
            if not pubkey:
                continue

            allowed_ips = peer.get("allowed_ips", get_default_peer_ip())
            # allowed_ips can be a list or string, wg set expects comma-separated string
            if isinstance(allowed_ips, list):
                allowed_ips = ",".join(allowed_ips)

            cmd = ["wg", "set", interface, "peer", pubkey, "allowed-ips", allowed_ips]

            # 处理 preshared key
            psk_file = None
            if peer.get("preshared_key"):
                import tempfile
                with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.psk') as f:
                    f.write(peer["preshared_key"])
                    psk_file = f.name
                cmd.extend(["preshared-key", psk_file])

            try:
                subprocess.run(cmd, check=True)
                action = "Updated" if pubkey in current_peers else "Added"
                print(f"[api] {action} peer: {peer.get('name', 'unknown')} ({pubkey[:20]}...)")
            finally:
                if psk_file:
                    os.unlink(psk_file)

        return {"success": True, "message": f"Peers synced via wg set ({len(peers)} peers)"}

    except subprocess.CalledProcessError as exc:
        return {"success": False, "message": f"wg set failed: {exc}"}
    except Exception as exc:
        return {"success": False, "message": str(exc)}


# ============ Phase 11-Fix.AC: Userspace WG Pairing Helpers ============

async def _generate_pair_request_via_ipc(
    node_tag: str,
    node_description: str,
    endpoint: str,
    api_port: int,
    bidirectional: bool,
    tunnel_type: str,
) -> Tuple[bool, str, Optional[str], Dict[str, Any]]:
    """Generate pairing request via rust-router IPC (userspace WG mode).

    Returns:
        Tuple of (success, code_or_error, peer_tag, pending_request_dict)
    """
    from rust_router_client import RustRouterClient

    client = RustRouterClient()
    try:
        # Ping to check availability
        ping_result = await client.ping()
        if not ping_result.success:
            return False, "rust-router unavailable", None, {}

        # Map tunnel_type from API format to IPC format
        # IPC uses "wireguard" (same as API), but double-check
        ipc_tunnel_type = tunnel_type

        result = await client.generate_pair_request(
            local_tag=node_tag,
            local_description=node_description,
            local_endpoint=endpoint,
            local_api_port=api_port or 36000,
            bidirectional=bidirectional,
            tunnel_type=ipc_tunnel_type,
        )

        if result.success:
            code = result.data.get("code", "") if result.data else ""
            peer_tag = result.data.get("peer_tag") if result.data else None
            return True, code, peer_tag, result.data or {}
        else:
            return False, result.error or "IPC request failed", None, {}
    finally:
        await client.close()


async def _import_pair_request_via_ipc(
    code: str,
    local_tag: str,
    local_description: str,
    local_endpoint: str,
    local_api_port: int,
) -> Tuple[bool, str, Optional[str], Dict[str, Any]]:
    """Import pairing request via rust-router IPC (userspace WG mode).

    Returns:
        Tuple of (success, response_code_or_error, remote_node_tag, response_data)
    """
    from rust_router_client import RustRouterClient

    client = RustRouterClient()
    try:
        ping_result = await client.ping()
        if not ping_result.success:
            return False, "rust-router unavailable", None, {}

        result = await client.import_pair_request(
            code=code,
            local_tag=local_tag,
            local_description=local_description,
            local_endpoint=local_endpoint,
            local_api_port=local_api_port,
        )

        if result.success:
            response_code = ""
            if result.data:
                response_code = result.data.get("response_code") or result.data.get("code") or ""
            remote_tag = result.data.get("remote_node_tag") if result.data else None
            return True, response_code, remote_tag, result.data or {}
        else:
            return False, result.error or "IPC request failed", None, {}
    finally:
        await client.close()


async def _complete_handshake_via_ipc(code: str) -> Tuple[bool, str, Optional[str]]:
    """Complete pairing handshake via rust-router IPC (userspace WG mode).

    Returns:
        Tuple of (success, message_or_error, peer_tag)
    """
    from rust_router_client import RustRouterClient

    client = RustRouterClient()
    try:
        ping_result = await client.ping()
        if not ping_result.success:
            return False, "rust-router unavailable", None

        result = await client.complete_handshake(code)

        if result.success:
            peer_tag = result.data.get("peer_tag") if result.data else None
            return True, result.message or "Handshake completed", peer_tag
        else:
            return False, result.error or "IPC request failed", None
    finally:
        await client.close()


def _run_async_ipc(coro):
    """Run async IPC coroutine in sync context.

    Handles event loop management for FastAPI sync endpoints.
    Returns the coroutine result, or raises HTTPException on timeout/error.

    Phase 11-Fix.AC: Uses asyncio.get_running_loop() for Python 3.10+ compatibility,
    handles TimeoutError and general exceptions properly.
    """
    import asyncio
    import concurrent.futures

    IPC_TIMEOUT_SECONDS = 30

    try:
        # Python 3.10+: Use get_running_loop() to check if we're in async context
        try:
            loop = asyncio.get_running_loop()
            # We're in a running loop - use thread pool to run in separate loop
            with concurrent.futures.ThreadPoolExecutor() as pool:
                future = pool.submit(asyncio.run, coro)
                return future.result(timeout=IPC_TIMEOUT_SECONDS)
        except RuntimeError:
            # No running loop - safe to create one with asyncio.run()
            return asyncio.run(coro)

    except concurrent.futures.TimeoutError:
        logging.error(f"[pairing] IPC operation timed out after {IPC_TIMEOUT_SECONDS}s")
        raise HTTPException(status_code=504, detail=f"IPC operation timed out after {IPC_TIMEOUT_SECONDS} seconds")
    except Exception as e:
        logging.error(f"[pairing] IPC communication error: {e}")
        raise HTTPException(status_code=503, detail=f"IPC communication error: {e}")


def _sync_userspace_peer_from_codes(
    db,
    request_code: Optional[str],
    response_code: Optional[str],
    local_tag: str,
    local_endpoint: Optional[str] = None,
    tunnel_status: str = "connected",
) -> Optional[str]:
    """Sync peer_nodes for userspace WG pairing using decoded request/response codes."""
    if not HAS_PAIRING:
        return None

    try:
        from peer_pairing import PairingCodeGenerator

        generator = PairingCodeGenerator(db)
        request_data = generator.decode_pairing_code(request_code) if request_code else None
        response_data = generator.decode_pairing_code(response_code) if response_code else None

        remote_tag = None
        tunnel_type = "wireguard"

        response_is_local = False
        if response_data and response_data.get("type") == "pair_response":
            response_node_tag = response_data.get("node_tag")
            request_node_tag = response_data.get("request_node_tag")
            response_is_local = response_node_tag == local_tag
            if response_is_local:
                remote_tag = request_node_tag
            else:
                remote_tag = response_node_tag
            tunnel_type = response_data.get("tunnel_type", tunnel_type)
        elif request_data and request_data.get("type") == "pair_request":
            remote_tag = request_data.get("node_tag")
            tunnel_type = request_data.get("tunnel_type", tunnel_type)

        if not remote_tag or remote_tag == local_tag:
            return None

        remote_endpoint = None
        remote_api_port = None
        tunnel_remote_ip = None
        tunnel_local_ip = None
        tunnel_api_endpoint = None
        wg_peer_public_key = None

        if request_data and request_data.get("type") == "pair_request":
            remote_endpoint = request_data.get("endpoint") or remote_endpoint
            remote_api_port = request_data.get("api_port") or remote_api_port
            tunnel_remote_ip = request_data.get("tunnel_ip") or tunnel_remote_ip
            tunnel_local_ip = request_data.get("remote_tunnel_ip") or tunnel_local_ip
            wg_peer_public_key = request_data.get("wg_public_key") or wg_peer_public_key
            if not local_endpoint:
                local_endpoint = request_data.get("endpoint")

        if response_data and response_data.get("type") == "pair_response" and not response_is_local:
            remote_endpoint = response_data.get("endpoint") or remote_endpoint
            remote_api_port = response_data.get("api_port") or remote_api_port
            tunnel_remote_ip = response_data.get("tunnel_local_ip") or tunnel_remote_ip
            tunnel_local_ip = response_data.get("tunnel_remote_ip") or tunnel_local_ip
            tunnel_api_endpoint = response_data.get("tunnel_api_endpoint") or tunnel_api_endpoint
            wg_peer_public_key = response_data.get("wg_public_key") or wg_peer_public_key

        if not tunnel_api_endpoint and tunnel_remote_ip and remote_api_port:
            tunnel_api_endpoint = f"{tunnel_remote_ip}:{remote_api_port}"

        local_port = None
        if local_endpoint and ":" in local_endpoint:
            try:
                local_port = int(local_endpoint.rsplit(":", 1)[1])
            except ValueError:
                local_port = None

        existing = db.get_peer_node(remote_tag)
        if existing:
            db.update_peer_node(
                remote_tag,
                endpoint=remote_endpoint or existing.get("endpoint"),
                api_port=remote_api_port or existing.get("api_port"),
                tunnel_type=tunnel_type,
                tunnel_status=tunnel_status,
                tunnel_local_ip=tunnel_local_ip or existing.get("tunnel_local_ip"),
                tunnel_remote_ip=tunnel_remote_ip or existing.get("tunnel_remote_ip"),
                tunnel_port=local_port or existing.get("tunnel_port"),
                tunnel_api_endpoint=tunnel_api_endpoint or existing.get("tunnel_api_endpoint"),
                wg_peer_public_key=wg_peer_public_key or existing.get("wg_peer_public_key"),
                bidirectional_status="bidirectional",
                last_error=None,
            )
        else:
            db.add_peer_node(
                tag=remote_tag,
                name=remote_tag,
                description="",
                endpoint=remote_endpoint or "",
                api_port=remote_api_port,
                tunnel_type=tunnel_type,
                tunnel_status=tunnel_status,
                tunnel_local_ip=tunnel_local_ip,
                tunnel_remote_ip=tunnel_remote_ip,
                tunnel_port=local_port,
                tunnel_api_endpoint=tunnel_api_endpoint,
                wg_peer_public_key=wg_peer_public_key,
                auto_reconnect=False,
                enabled=True,
                bidirectional_status="bidirectional",
            )

        return remote_tag
    except Exception as exc:
        logging.warning(f"[pairing] userspace peer DB sync failed: {exc}")
        return None


@app.get("/api/ingress")
def api_get_ingress():
    """获取入口 WireGuard 配置和状态"""
    config = load_ingress_config()
    interface = config.get("interface", {})

    # 获取公钥
    public_key = get_ingress_public_key(config)

    # 获取 peer 状态
    handshakes = get_peer_handshake_info()
    transfers = get_peer_transfer_info()

    # 丰富 peer 信息
    peers = []
    for peer in config.get("peers", []):
        pubkey = peer.get("public_key", "")
        last_handshake = handshakes.get(pubkey, 0)
        transfer = transfers.get(pubkey, {"rx": 0, "tx": 0})

        # 判断是否在线（在 grace period 内有活动）
        import time
        now = int(time.time())
        is_online = last_handshake > 0 and (now - last_handshake) < _PEER_ONLINE_GRACE_PERIOD

        peers.append({
            "name": peer.get("name", "unknown"),
            "public_key": pubkey,
            "allowed_ips": peer.get("allowed_ips", []),
            "last_handshake": last_handshake,
            "is_online": is_online,
            "rx_bytes": transfer.get("rx", 0),
            "tx_bytes": transfer.get("tx", 0),
            "allow_lan": peer.get("allow_lan", False),
            "lan_subnet": peer.get("lan_subnet"),
            "default_outbound": peer.get("default_outbound"),
        })

    return {
        "interface": {
            "name": interface.get("name", "wg-ingress"),
            "address": interface.get("address", ""),
            "listen_port": interface.get("listen_port", 51820),
            "mtu": interface.get("mtu", 1420),
            "public_key": public_key,
        },
        "peers": peers,
        "peer_count": len(peers),
    }


def detect_lan_subnet() -> Optional[str]:
    """检测本地局域网子网"""
    import socket
    lan_ip = None
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(1)
        s.connect(("8.8.8.8", 80))
        lan_ip = s.getsockname()[0]
        s.close()
    except Exception:
        pass

    if not lan_ip or lan_ip.startswith("127.") or lan_ip.startswith("172."):
        return None

    # 从 IP 推断子网 (假设 /24)
    parts = lan_ip.split('.')
    if len(parts) == 4:
        return f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"
    return None


def calculate_allowed_ips_excluding_subnet(exclude_subnet: str) -> str:
    """计算 Split Tunnel 的 AllowedIPs

    排除所有 RFC1918 私有地址范围 (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16)，
    使本地局域网流量不走 VPN。包含 1.1.1.1/32 确保 DNS 查询走 VPN。

    Args:
        exclude_subnet: 要排除的子网（用于日志记录）

    Returns:
        Split Tunnel 的 CIDR 列表
    """
    # 精确排除 RFC1918 私有地址，覆盖所有公网 IP + Cloudflare DNS
    return ("1.0.0.0/8, 2.0.0.0/8, 3.0.0.0/8, 4.0.0.0/6, 8.0.0.0/7, 11.0.0.0/8, "
            "12.0.0.0/6, 16.0.0.0/4, 32.0.0.0/3, 64.0.0.0/2, 128.0.0.0/3, "
            "160.0.0.0/5, 168.0.0.0/6, 172.0.0.0/12, 172.32.0.0/11, 172.64.0.0/10, "
            "172.128.0.0/9, 173.0.0.0/8, 174.0.0.0/7, 176.0.0.0/4, 192.0.0.0/9, "
            "192.128.0.0/11, 192.160.0.0/13, 192.169.0.0/16, 192.170.0.0/15, "
            "192.172.0.0/14, 192.176.0.0/12, 192.192.0.0/10, 193.0.0.0/8, "
            "194.0.0.0/7, 196.0.0.0/6, 200.0.0.0/5, 208.0.0.0/4, 1.1.1.1/32")


@app.post("/api/ingress/peers")
def api_add_ingress_peer(payload: IngressPeerCreateRequest):
    """添加新的入口 peer（客户端）到数据库"""
    config = load_ingress_config()

    # 检查名称是否已存在
    for peer in config.get("peers", []):
        if peer.get("name") == payload.name:
            raise HTTPException(status_code=400, detail=f"客户端 '{payload.name}' 已存在")

    # 获取下一个可用 IP
    peer_ip = get_next_peer_ip(config)

    # 处理密钥
    client_private_key = None
    if payload.public_key:
        # 用户提供了公钥
        client_public_key = payload.public_key
    else:
        # 服务端生成密钥对
        client_private_key, client_public_key = generate_wireguard_keypair()

    # 如果启用 LAN 访问，自动检测 LAN 子网
    lan_subnet = None
    if payload.allow_lan:
        lan_subnet = detect_lan_subnet()

    # 添加到数据库
    if HAS_DATABASE and USER_DB_PATH.exists():
        db = _get_db()
        peer_id = db.add_wireguard_peer(
            name=payload.name,
            public_key=client_public_key,
            allowed_ips=f"{peer_ip}/32",
            allow_lan=payload.allow_lan,
            lan_subnet=lan_subnet,
            default_outbound=payload.default_outbound
        )
    else:
        # 降级到配置文件
        new_peer = {
            "name": payload.name,
            "public_key": client_public_key,
            "allowed_ips": [f"{peer_ip}/32"],
        }
        config.setdefault("peers", []).append(new_peer)
        save_ingress_config(config)

    # 重新加载配置并应用
    config = load_ingress_config()
    apply_result = apply_ingress_config(config)

    result = {
        "message": f"客户端 '{payload.name}' 已添加",
        "peer": {
            "name": payload.name,
            "public_key": client_public_key,
            "address": peer_ip,
        },
        "apply_result": apply_result,
    }

    # 如果是服务端生成的密钥，返回私钥
    if client_private_key:
        result["client_private_key"] = client_private_key

    return result


@app.delete("/api/ingress/peers/{peer_name}")
def api_delete_ingress_peer(peer_name: str):
    """删除入口 peer（从数据库）"""
    config = load_ingress_config()

    # 查找 peer
    peer_to_delete = None
    for peer in config.get("peers", []):
        if peer.get("name") == peer_name:
            peer_to_delete = peer
            break

    if not peer_to_delete:
        raise HTTPException(status_code=404, detail=f"客户端 '{peer_name}' 不存在")

    # 从数据库删除
    if HAS_DATABASE and USER_DB_PATH.exists():
        db = _get_db()
        if "id" in peer_to_delete:
            db.delete_wireguard_peer(peer_to_delete["id"])
    else:
        # 降级到配置文件
        config["peers"] = [p for p in config.get("peers", []) if p.get("name") != peer_name]
        save_ingress_config(config)

    # 重新加载配置并应用
    config = load_ingress_config()
    apply_result = apply_ingress_config(config)

    return {
        "message": f"客户端 '{peer_name}' 已删除",
        "apply_result": apply_result,
    }


@app.put("/api/ingress/peers/{peer_name}")
def api_update_ingress_peer(peer_name: str, payload: IngressPeerUpdateRequest):
    """更新入口 peer 配置（如默认出口）"""
    if not HAS_DATABASE or not USER_DB_PATH.exists():
        raise HTTPException(status_code=500, detail="数据库不可用")

    db = _get_db()
    peer = db.get_wireguard_peer_by_name(peer_name)

    if not peer:
        raise HTTPException(status_code=404, detail=f"客户端 '{peer_name}' 不存在")

    # 准备更新参数
    update_kwargs = {}
    if payload.name is not None:
        update_kwargs["name"] = payload.name
    if payload.default_outbound is not None:
        # 验证出口是否存在（空字符串表示清空，允许通过）
        if payload.default_outbound:
            available = _get_available_outbounds(db)
            if payload.default_outbound not in available:
                raise HTTPException(
                    status_code=400,
                    detail=f"出口 '{payload.default_outbound}' 不存在"
                )
        # 空字符串表示清空，设为 None
        update_kwargs["default_outbound"] = payload.default_outbound if payload.default_outbound else None

    if not update_kwargs:
        return {"message": "无需更新", "peer": peer, "reload_success": True}

    # 更新数据库
    db.update_wireguard_peer(peer["id"], **update_kwargs)

    # 如果更改了默认出口，需要重新生成配置
    reload_success = True
    reload_message = ""
    if "default_outbound" in update_kwargs:
        try:
            _regenerate_and_reload()
            reload_message = "，配置已重载"
        except Exception as exc:
            reload_success = False
            reload_message = f"，重载失败: {exc}"
            logging.error(f"更新客户端 '{peer_name}' 后重载失败: {exc}")

    # 获取更新后的 peer
    updated_peer = db.get_wireguard_peer_by_name(payload.name if payload.name else peer_name)

    return {
        "message": f"客户端 '{peer_name}' 已更新{reload_message}",
        "peer": updated_peer,
        "reload_success": reload_success,
    }


@app.get("/api/ingress/peers/{peer_name}/config", response_class=PlainTextResponse)
def api_get_peer_config(peer_name: str, private_key: Optional[str] = None):
    """获取客户端 WireGuard 配置文件"""
    config = load_ingress_config()
    interface = config.get("interface", {})

    # 查找 peer
    peer = None
    for p in config.get("peers", []):
        if p.get("name") == peer_name:
            peer = p
            break

    if not peer:
        raise HTTPException(status_code=404, detail=f"客户端 '{peer_name}' 不存在")

    # 获取服务端公钥
    server_public_key = get_ingress_public_key(config)
    if not server_public_key:
        raise HTTPException(status_code=500, detail="服务端公钥不可用")

    # 客户端 IP - Phase 11-Fix.AB: 从 allowed_ips 提取客户端 IP 地址
    # allowed_ips 应该是一个列表，如 ["10.23.0.2/32"]
    allowed_ips_list = peer.get("allowed_ips")
    if not allowed_ips_list:
        # 如果没有 allowed_ips，使用默认值
        client_ip = get_default_peer_ip()
    elif isinstance(allowed_ips_list, str):
        # 如果是字符串（不应该发生，但防御性处理）
        client_ip = allowed_ips_list.split(",")[0].strip() if allowed_ips_list else get_default_peer_ip()
    elif isinstance(allowed_ips_list, list) and len(allowed_ips_list) > 0:
        # 正常情况：是一个非空列表
        client_ip = allowed_ips_list[0]
        if not client_ip or client_ip == "None":
            # 防御性检查：如果第一个元素是None或字符串"None"
            client_ip = get_default_peer_ip()
    else:
        # 其他异常情况
        client_ip = get_default_peer_ip()

    # WireGuard Address 字段需要 CIDR 格式（如 10.23.0.2/32）
    # 确保 client_ip 包含 CIDR 后缀
    if "/" not in client_ip:
        client_ip = f"{client_ip}/32"

    # 服务端地址（优先使用设置文件，其次使用环境变量）
    settings = load_settings()
    listen_port = interface.get("listen_port", DEFAULT_WG_PORT)
    server_endpoint = settings.get("server_endpoint", "") or os.environ.get("WG_SERVER_ENDPOINT", "")
    if server_endpoint:
        if ":" not in server_endpoint:
            server_endpoint = f"{server_endpoint}:{listen_port}"
    else:
        server_endpoint = f"YOUR_SERVER_IP:{listen_port}"

    # 获取 peer 的 LAN 访问设置
    allow_lan = peer.get("allow_lan", False)
    lan_subnet = peer.get("lan_subnet", "")

    # 只有当 allow_lan=True 且没有存储 lan_subnet 时才动态检测
    # 当 allow_lan=False 时，不检测 LAN 子网（用户未请求 LAN 访问）
    if allow_lan and not lan_subnet:
        lan_subnet = detect_lan_subnet() or ""

    # 生成 AllowedIPs
    # - allow_lan=True + lan_subnet: Split Tunnel，排除本地 LAN（本地局域网流量不走 VPN）
    # - allow_lan=True 但无 lan_subnet: 全部流量走 VPN
    # - allow_lan=False: 全部流量走 VPN（默认行为）
    if allow_lan and lan_subnet:
        # 启用保留局域网连接：Split Tunnel，排除本地 LAN 网段
        # 本地局域网流量直接走本地网络，其他流量走 VPN
        allowed_ips = calculate_allowed_ips_excluding_subnet(lan_subnet)
    else:
        # 默认：全部流量走 VPN
        allowed_ips = "0.0.0.0/0"

    # 构建配置
    client_config = f"""[Interface]
PrivateKey = {private_key or 'YOUR_PRIVATE_KEY'}
Address = {client_ip}
DNS = 1.1.1.1

[Peer]
PublicKey = {server_public_key}
Endpoint = {server_endpoint}
AllowedIPs = {allowed_ips}
PersistentKeepalive = 25
"""
    return client_config


@app.get("/api/ingress/peers/{peer_name}/qrcode")
def api_get_peer_qrcode(peer_name: str, private_key: Optional[str] = None):
    """获取客户端配置的 QR 码（PNG 图片）"""
    if not HAS_QRCODE:
        raise HTTPException(status_code=501, detail="QR 码功能不可用，请安装 qrcode 库")

    # 获取配置内容
    config_text = api_get_peer_config(peer_name, private_key)

    # 生成 QR 码
    qr = qrcode.QRCode(version=1, box_size=10, border=4)
    qr.add_data(config_text)
    qr.make(fit=True)

    img = qr.make_image(fill_color="black", back_color="white")

    # 转换为 PNG
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    buf.seek(0)

    return Response(content=buf.getvalue(), media_type="image/png")


@app.post("/api/ingress/apply")
def api_apply_ingress_config():
    """手动应用入口 WireGuard 配置"""
    config = load_ingress_config()
    result = apply_ingress_config(config)
    if not result.get("success"):
        # Phase 11-Fix.U: 防御性默认值
        raise HTTPException(status_code=500, detail=result.get("message", "Apply config failed"))
    return result


class SubnetUpdateRequest(BaseModel):
    """更新入口子网"""
    address: str = Field(..., description="新的子网地址，如 10.25.0.1/24")
    migrate_peers: bool = Field(True, description="是否自动迁移现有客户端 IP 到新子网")


@app.get("/api/ingress/subnet")
def api_get_ingress_subnet():
    """获取入口子网配置"""
    import ipaddress
    db = _get_db()
    server = db.get_wireguard_server()
    address = server.get("address", DEFAULT_WG_SUBNET) if server else DEFAULT_WG_SUBNET

    # 检查是否与出口地址冲突
    conflicts = []
    try:
        network = ipaddress.ip_network(address, strict=False)

        for egress in db.get_custom_egress_list():
            addr = egress.get("address", "")
            if addr:
                try:
                    egress_ip = ipaddress.ip_address(addr.split("/")[0])
                    if egress_ip in network:
                        conflicts.append({
                            "type": "custom_egress",
                            "tag": egress.get("tag"),
                            "address": addr
                        })
                except ValueError:
                    pass

        for profile in db.get_pia_profiles(enabled_only=False):
            peer_ip = profile.get("peer_ip", "")
            if peer_ip:
                try:
                    profile_ip = ipaddress.ip_address(peer_ip.split("/")[0])
                    if profile_ip in network:
                        conflicts.append({
                            "type": "pia_profile",
                            "tag": profile.get("name"),
                            "address": peer_ip
                        })
                except ValueError:
                    pass
    except ValueError:
        pass

    return {
        "address": address,
        "conflicts": conflicts
    }


@app.put("/api/ingress/subnet")
def api_update_ingress_subnet(payload: SubnetUpdateRequest):
    """更新入口子网（可选自动迁移客户端 IP）"""
    import ipaddress

    # 1. 验证格式
    try:
        network = ipaddress.ip_network(payload.address, strict=False)
        gateway_ip = ipaddress.ip_address(payload.address.split("/")[0])
    except ValueError as e:
        raise HTTPException(status_code=400, detail=f"Invalid subnet format: {e}")

    # 2. 检查与出口地址的冲突
    db = _get_db()
    conflicts = []

    for egress in db.get_custom_egress_list():
        addr = egress.get("address", "")
        if addr:
            try:
                egress_ip = ipaddress.ip_address(addr.split("/")[0])
                if egress_ip in network:
                    conflicts.append(f"Custom egress '{egress.get('tag')}' uses {addr}")
            except ValueError:
                pass

    for profile in db.get_pia_profiles(enabled_only=False):
        peer_ip = profile.get("peer_ip", "")
        if peer_ip:
            try:
                profile_ip = ipaddress.ip_address(peer_ip.split("/")[0])
                if profile_ip in network:
                    conflicts.append(f"PIA profile '{profile.get('name')}' uses {peer_ip}")
            except ValueError:
                pass

    if conflicts:
        raise HTTPException(
            status_code=400,
            detail=f"Subnet conflicts with egress addresses: {', '.join(conflicts)}"
        )

    # 3. 如果需要迁移客户端 IP
    migrated_count = 0
    if payload.migrate_peers:
        peers = db.get_wireguard_peers(enabled_only=False)
        new_base = str(network.network_address).rsplit(".", 1)[0]
        for i, peer in enumerate(peers, start=2):
            new_ip = f"{new_base}.{i}/32"
            db.update_wireguard_peer(peer["id"], allowed_ips=new_ip)
            migrated_count += 1

    # 4. 更新服务器地址
    server = db.get_wireguard_server()
    db.set_wireguard_server(
        interface_name=server.get("interface_name", "wg-ingress") if server else "wg-ingress",
        address=payload.address,
        listen_port=server.get("listen_port", DEFAULT_WG_PORT) if server else DEFAULT_WG_PORT,
        mtu=server.get("mtu", 1420) if server else 1420,
        private_key=server.get("private_key", "") if server else ""
    )

    # 4.5. 刷新子网缓存
    refresh_wg_subnet_cache()

    # 5. 重新生成配置并应用
    _regenerate_and_reload()

    # 6. 同步内核 WireGuard 接口（更新地址和 peer allowed_ips）
    wg_sync_result = _sync_kernel_wg_ingress()

    return {
        "success": True,
        "message": f"Subnet updated to {payload.address}{wg_sync_result}",
        "address": payload.address,
        "migrated_peers": migrated_count
    }


# ============ Ingress Outbound Binding APIs (入口绑定出口) ============

class IngressOutboundRequest(BaseModel):
    """设置入口默认出口"""
    outbound: Optional[str] = Field(None, description="出口标签（NULL=使用全局默认）")


@app.get("/api/ingress/wireguard/outbound")
def api_get_wireguard_ingress_outbound():
    """获取 WireGuard 入口的默认出口设置"""
    db = _get_db()
    server = db.get_wireguard_server()

    if not server:
        raise HTTPException(status_code=404, detail="WireGuard server not configured")

    # 获取可用出口列表
    available_outbounds = _get_available_outbounds(db)

    # 获取全局默认出口
    global_default = db.get_setting("default_outbound", "direct")

    return {
        "outbound": server.get("default_outbound"),  # None = 使用全局默认
        "global_default": global_default,
        "available_outbounds": available_outbounds
    }


@app.put("/api/ingress/wireguard/outbound")
def api_set_wireguard_ingress_outbound(payload: IngressOutboundRequest):
    """设置 WireGuard 入口的默认出口（热切换：仅需重载配置，不影响 WireGuard 隧道）"""
    db = _get_db()
    server = db.get_wireguard_server()

    if not server:
        raise HTTPException(status_code=404, detail="WireGuard server not configured")

    # 验证出口是否存在
    if payload.outbound:
        available = _get_available_outbounds(db)
        if payload.outbound not in available:
            raise HTTPException(
                status_code=400,
                detail=f"Outbound '{payload.outbound}' not found. Available: {available}"
            )

    # 更新数据库
    db.set_wireguard_server(
        interface_name=server.get("interface_name", "wg-ingress"),
        address=server.get("address"),
        listen_port=server.get("listen_port"),
        mtu=server.get("mtu", 1420),
        private_key=server.get("private_key"),
        default_outbound=payload.outbound
    )

    # 重新生成配置并重载（sing-box 路由规则变更需要重载）
    try:
        _regenerate_and_reload()
        return {
            "success": True,
            "message": f"WireGuard ingress outbound set to {payload.outbound or 'global default'}",
            "outbound": payload.outbound,
            "reloaded": True
        }
    except Exception as e:
        return {
            "success": True,
            "message": f"Outbound saved but reload failed: {e}",
            "outbound": payload.outbound,
            "reloaded": False,
            "error": str(e)
        }


@app.get("/api/ingress/v2ray/outbound")
def api_get_v2ray_ingress_outbound():
    """获取 V2Ray 入口的默认出口设置"""
    db = _get_db()
    config = db.get_v2ray_inbound_config()

    if not config:
        raise HTTPException(status_code=404, detail="V2Ray inbound not configured")

    # 获取可用出口列表
    available_outbounds = _get_available_outbounds(db)

    # 获取全局默认出口
    global_default = db.get_setting("default_outbound", "direct")

    return {
        "outbound": config.get("default_outbound"),  # None = 使用全局默认
        "global_default": global_default,
        "available_outbounds": available_outbounds
    }


@app.put("/api/ingress/v2ray/outbound")
def api_set_v2ray_ingress_outbound(payload: IngressOutboundRequest):
    """设置 V2Ray 入口的默认出口（热切换：仅需重载配置）"""
    db = _get_db()
    config = db.get_v2ray_inbound_config()

    if not config:
        raise HTTPException(status_code=404, detail="V2Ray inbound not configured")

    # 验证出口是否存在
    if payload.outbound:
        available = _get_available_outbounds(db)
        if payload.outbound not in available:
            raise HTTPException(
                status_code=400,
                detail=f"Outbound '{payload.outbound}' not found. Available: {available}"
            )

    # 更新数据库 - 使用现有 save 方法，添加 default_outbound 字段
    db.save_v2ray_inbound_config(
        protocol=config.get("protocol", "vless"),
        listen_address=config.get("listen_address", "0.0.0.0"),
        listen_port=config.get("listen_port", 443),
        tls_enabled=config.get("tls_enabled", 1),
        tls_cert_path=config.get("tls_cert_path"),
        tls_key_path=config.get("tls_key_path"),
        tls_cert_content=config.get("tls_cert_content"),
        tls_key_content=config.get("tls_key_content"),
        transport_type=config.get("transport_type", "tcp"),
        transport_config=config.get("transport_config"),
        fallback_server=config.get("fallback_server"),
        fallback_port=config.get("fallback_port"),
        enabled=config.get("enabled", 0),
        xtls_vision_enabled=config.get("xtls_vision_enabled", 0),
        reality_enabled=config.get("reality_enabled", 0),
        reality_private_key=config.get("reality_private_key"),
        reality_public_key=config.get("reality_public_key"),
        reality_short_ids=config.get("reality_short_ids"),
        reality_dest=config.get("reality_dest"),
        reality_server_names=config.get("reality_server_names"),
        tun_device=config.get("tun_device", "xray-tun0"),
        tun_subnet=config.get("tun_subnet", "10.24.0.0/24"),
        default_outbound=payload.outbound
    )

    # 重新生成配置并重载
    try:
        _regenerate_and_reload()
        return {
            "success": True,
            "message": f"V2Ray ingress outbound set to {payload.outbound or 'global default'}",
            "outbound": payload.outbound,
            "reloaded": True
        }
    except Exception as e:
        return {
            "success": True,
            "message": f"Outbound saved but reload failed: {e}",
            "outbound": payload.outbound,
            "reloaded": False,
            "error": str(e)
        }


# ============ Settings APIs ============

class SettingsUpdateRequest(BaseModel):
    """更新系统设置"""
    server_endpoint: Optional[str] = Field(None, description="服务器公网地址，如 1.2.3.4 或 vpn.example.com")


class PortChangeAnnouncementRequest(BaseModel):
    """Phase C (端口变更通知): 端口变更广播请求"""
    new_port: int = Field(..., ge=1, le=65535, description="新的 API 端口号")


@app.get("/api/settings")
def api_get_settings():
    """获取系统设置"""
    settings = load_settings()
    ingress_config = load_ingress_config()
    interface = ingress_config.get("interface", {})

    return {
        "server_endpoint": settings.get("server_endpoint", ""),
        "listen_port": interface.get("listen_port", DEFAULT_WG_PORT),
    }


@app.get("/api/settings/detect-ip")
def api_detect_ip():
    """自动检测服务器的公网和局域网 IP 地址"""
    import socket
    import urllib.request

    result = {
        "public_ip": None,
        "lan_ip": None,
        "message": ""
    }

    # 检测公网 IP（通过外部服务）
    try:
        with urllib.request.urlopen("https://api.ipify.org", timeout=5) as response:
            result["public_ip"] = response.read().decode().strip()
    except Exception:
        # 备用服务
        try:
            with urllib.request.urlopen("https://ifconfig.me/ip", timeout=5) as response:
                result["public_ip"] = response.read().decode().strip()
        except Exception:
            pass

    # 检测局域网 IP
    # 方法1：通过连接外部地址获取本机出口 IP（host 网络模式下可以获取真实局域网 IP）
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(1)
        s.connect(("8.8.8.8", 80))
        lan_ip = s.getsockname()[0]
        s.close()
        # 排除 localhost 和 Docker 内部网络
        if lan_ip and not lan_ip.startswith("127.") and not lan_ip.startswith("172."):
            result["lan_ip"] = lan_ip
    except Exception:
        pass

    # 方法2：如果方法1失败，尝试从路由表获取
    if not result["lan_ip"]:
        try:
            output = subprocess.check_output(["ip", "route", "get", "1"], text=True, timeout=5)
            for line in output.split('\n'):
                if 'src' in line:
                    parts = line.split()
                    src_idx = parts.index('src')
                    src_ip = parts[src_idx + 1]
                    if not src_ip.startswith("127."):
                        result["lan_ip"] = src_ip
                        break
        except Exception:
            pass

    # 构建消息
    messages = []
    if result["public_ip"]:
        messages.append(f"公网 IP: {result['public_ip']}")
    if result["lan_ip"]:
        messages.append(f"局域网 IP: {result['lan_ip']}")

    if messages:
        result["message"] = "，".join(messages)
    else:
        result["message"] = "无法自动检测 IP，请手动输入"

    return result


@app.put("/api/settings")
def api_update_settings(payload: SettingsUpdateRequest):
    """更新系统设置"""
    settings = load_settings()

    if payload.server_endpoint is not None:
        # 清理输入：移除协议前缀和端口
        endpoint = payload.server_endpoint.strip()
        if endpoint.startswith("http://"):
            endpoint = endpoint[7:]
        elif endpoint.startswith("https://"):
            endpoint = endpoint[8:]
        # 移除路径
        endpoint = endpoint.split("/")[0]
        # 移除端口（如果有）
        if ":" in endpoint:
            endpoint = endpoint.split(":")[0]
        settings["server_endpoint"] = endpoint

    save_settings(settings)
    return {"message": "设置已保存", "settings": settings}


@app.post("/api/settings/announce-port-change")
def api_announce_port_change(payload: PortChangeAnnouncementRequest):
    """Phase C (端口变更通知): 广播端口变更到所有已连接的 peer

    在更改本节点 API 端口之前，调用此接口通知所有已连接的 peer 节点。
    这样 peer 节点可以更新它们存储的 api_port 记录，确保端口更改后通信不中断。

    使用流程：
    1. 调用此 API 通知所有 peer 新端口号
    2. 修改 WEB_PORT 环境变量
    3. 重启容器

    Returns:
        success: 是否全部通知成功
        total_peers: 已连接的 peer 总数
        success_count: 通知成功的数量
        results: 每个 peer 的通知结果详情
    """
    db = _get_db()
    new_port = payload.new_port

    # 获取本节点标识（用于 source_node）
    local_node_id = _get_local_node_id()

    # 广播到所有已连接的 peer
    from tunnel_api_client import TunnelAPIClientManager
    client_mgr = TunnelAPIClientManager(db)
    results = client_mgr.broadcast_port_change(
        source_node=local_node_id,
        new_port=new_port,
    )

    success_count = sum(1 for v in results.values() if v)
    total_peers = len(results)
    # QA 修复: 当没有 peer 时应该返回 success=True（没有需要通知的对象）
    all_success = (total_peers == 0) or (success_count == total_peers)

    return {
        "success": all_success,
        "message": f"已通知 {success_count}/{total_peers} 个已连接的 peer 节点" if total_peers > 0 else "没有已连接的 peer 节点",
        "new_port": new_port,
        "total_peers": total_peers,
        "success_count": success_count,
        "results": results,
    }


# ============ Custom Egress APIs ============

@app.get("/api/egress")
def api_list_all_egress():
    """列出所有出口（PIA + 自定义 + Direct + OpenVPN + V2Ray）"""
    pia_result = []
    custom_result = []
    direct_result = []
    openvpn_result = []
    v2ray_result = []

    # 从数据库获取 PIA profiles
    db = _get_db()
    pia_profiles = db.get_pia_profiles(enabled_only=False)

    for p in pia_profiles:
        name = p.get("name", "")
        tag = name  # 保持原始名称
        pia_result.append({
            "tag": tag,
            "type": "pia",
            "description": p.get("description", ""),
            "region_id": p.get("region_id", ""),
            "server": p.get("server_ip", ""),
            "port": p.get("server_port", 0),
            "is_configured": bool(p.get("private_key")),
        })

    # 获取自定义出口
    custom_egress = db.get_custom_egress_list()
    for eg in custom_egress:
        custom_result.append({
            "tag": eg.get("tag", ""),
            "type": "custom",
            "description": eg.get("description", ""),
            "server": eg.get("server", ""),
            "port": eg.get("port", 51820),
            "is_configured": True,
        })

    # 获取 direct 出口
    direct_egress = db.get_direct_egress_list()
    for eg in direct_egress:
        direct_result.append({
            "tag": eg.get("tag", ""),
            "type": "direct",
            "description": eg.get("description", ""),
            "bind_interface": eg.get("bind_interface"),
            "inet4_bind_address": eg.get("inet4_bind_address"),
            "inet6_bind_address": eg.get("inet6_bind_address"),
            "enabled": eg.get("enabled", 1),
            "is_configured": True,  # direct 出口总是已配置
        })

    # 获取 OpenVPN 出口
    openvpn_egress = db.get_openvpn_egress_list()
    for eg in openvpn_egress:
        openvpn_result.append({
            "tag": eg.get("tag", ""),
            "type": "openvpn",
            "description": eg.get("description", ""),
            "server": eg.get("remote_host", ""),
            "port": eg.get("remote_port", 1194),
            "protocol": eg.get("protocol", "udp"),
            "tun_device": eg.get("tun_device"),
            "enabled": eg.get("enabled", 1),
            "is_configured": True,
        })

    # 获取 V2Ray 出口
    v2ray_egress = db.get_v2ray_egress_list()
    for eg in v2ray_egress:
        v2ray_result.append({
            "tag": eg.get("tag", ""),
            "type": "v2ray",
            "description": eg.get("description", ""),
            "protocol": eg.get("protocol", ""),
            "server": eg.get("server", ""),
            "port": eg.get("server_port", 443),
            "transport": eg.get("transport_type", "tcp"),
            "tls_enabled": eg.get("tls_enabled", 1),
            "enabled": eg.get("enabled", 1),
            "is_configured": True,
        })

    return {"pia": pia_result, "custom": custom_result, "direct": direct_result, "openvpn": openvpn_result, "v2ray": v2ray_result}


# ============ Default Direct Outbound DNS APIs ============

@app.get("/api/egress/direct-default")
def api_get_direct_default():
    """获取默认 direct 出口的配置（包括 DNS 设置）"""
    db = _get_db()

    # 从 settings 表读取 DNS 配置
    dns_servers_json = db.get_setting("direct_dns_servers", "[]")
    try:
        dns_servers = json.loads(dns_servers_json)
    except json.JSONDecodeError:
        dns_servers = []

    # 如果没有配置，返回默认值
    if not dns_servers:
        dns_servers = ["1.1.1.1"]

    return {
        "tag": "direct",
        "type": "direct",
        "description": "Default direct outbound",
        "dns_servers": dns_servers,
        "is_default": True
    }


class DirectDefaultUpdate(BaseModel):
    dns_servers: List[str]


@app.put("/api/egress/direct-default")
def api_update_direct_default(data: DirectDefaultUpdate):
    """更新默认 direct 出口的 DNS 设置

    支持的格式:
    - IP 地址: 8.8.8.8, 2001:4860:4860::8888
    - 域名: dns.google
    - DoH: https://dns.google/dns-query
    - DoT: tls://dns.google
    - DoQ: quic://dns.adguard.com
    - DoH3: h3://dns.google/dns-query
    """
    if not data.dns_servers:
        raise HTTPException(status_code=400, detail="At least one DNS server is required")

    import re
    import ipaddress
    from urllib.parse import urlparse

    # 支持的 DNS URL 协议
    DNS_URL_SCHEMES = {'https', 'tls', 'quic', 'h3'}
    # 特殊关键字（不需要 server 字段）
    DNS_SPECIAL_KEYWORDS = {'local'}
    domain_pattern = re.compile(r'^[a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?)*$')

    for server in data.dns_servers:
        # 检查特殊关键字
        if server.lower() in DNS_SPECIAL_KEYWORDS:
            continue  # 有效的特殊关键字

        # 检查 DNS URL 格式（DoH/DoT/DoQ）
        if '://' in server:
            parsed = urlparse(server)
            if parsed.scheme not in DNS_URL_SCHEMES:
                raise HTTPException(status_code=400, detail=f"Unsupported DNS scheme: {parsed.scheme}")
            if not parsed.netloc:
                raise HTTPException(status_code=400, detail=f"Invalid DNS URL: {server}")
            continue  # 有效的 DNS URL

        # 检查 IP 地址（IPv4/IPv6）
        try:
            ipaddress.ip_address(server)
            continue  # 有效的 IP 地址
        except ValueError:
            pass

        # 检查域名格式
        if not domain_pattern.match(server):
            raise HTTPException(status_code=400, detail=f"Invalid DNS server format: {server}")

    db = _get_db()
    db.set_setting("direct_dns_servers", json.dumps(data.dns_servers))

    # 重新生成配置并重载
    reload_status = ""
    try:
        _regenerate_and_reload()
        reload_status = ", config reloaded"
    except Exception as exc:
        print(f"[api] Direct default DNS reload failed: {exc}")
        reload_status = f", reload failed: {exc}"

    return {
        "success": True,
        "message": f"Direct DNS updated{reload_status}",
        "dns_servers": data.dns_servers
    }


# ============ Kernel WireGuard Egress Interface APIs ============

@app.get("/api/egress/wg/interfaces")
def api_list_wg_egress_interfaces():
    """List all kernel WireGuard egress interfaces status

    Shows status of wg-pia-* and wg-eg-* interfaces created for PIA and custom WireGuard egress.
    """
    try:
        from setup_kernel_wg_egress import get_all_egress_status, get_existing_egress_interfaces
        interfaces = get_existing_egress_interfaces()
        statuses = get_all_egress_status()

        result = []
        for iface in interfaces:
            status = statuses.get(iface, {})
            # Extract peer info
            peers = status.get("peers", [])
            peer_info = None
            if peers:
                peer = peers[0]
                peer_info = {
                    "endpoint": peer.get("endpoint"),
                    "allowed_ips": peer.get("allowed_ips"),
                    "latest_handshake": peer.get("latest_handshake"),
                    "transfer": {
                        "rx": peer.get("rx"),
                        "tx": peer.get("tx")
                    }
                }

            result.append({
                "interface": iface,
                "public_key": status.get("interface", {}).get("public_key"),
                "listen_port": status.get("interface", {}).get("listen_port"),
                "peer": peer_info
            })

        return {"interfaces": result}
    except ImportError:
        raise HTTPException(status_code=500, detail="setup_kernel_wg_egress module not available")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/egress/wg/sync")
def api_sync_wg_egress_interfaces():
    """Sync kernel WireGuard egress interfaces with database

    Creates missing interfaces and removes stale ones.
    """
    try:
        from setup_kernel_wg_egress import setup_all_egress_interfaces
        result = setup_all_egress_interfaces()

        if result.get("success"):
            # Regenerate sing-box config to update direct outbounds
            _regenerate_and_reload()

        return {
            "success": result.get("success"),
            "interfaces": result.get("interfaces", []),
            "created": result.get("created", 0),
            "updated": result.get("updated", 0),
            "removed": result.get("removed", 0),
            "failed": result.get("failed", 0)
        }
    except ImportError:
        raise HTTPException(status_code=500, detail="setup_kernel_wg_egress module not available")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/egress/wg/interface/{interface}")
def api_get_wg_egress_interface(interface: str):
    """Get status of a specific kernel WireGuard egress interface"""
    import subprocess

    # Validate interface name (must start with wg-pia- or wg-eg-)
    if not interface.startswith("wg-pia-") and not interface.startswith("wg-eg-"):
        raise HTTPException(status_code=400, detail="Invalid interface name. Must start with wg-pia- or wg-eg-")

    try:
        result = subprocess.run(
            ["wg", "show", interface],
            capture_output=True,
            text=True,
            check=False
        )

        if result.returncode != 0:
            raise HTTPException(status_code=404, detail=f"Interface {interface} not found")

        # Parse wg show output
        from setup_kernel_wg_egress import parse_wg_show_output
        status = parse_wg_show_output(result.stdout)

        return {"interface": interface, "status": status}
    except ImportError:
        # Fallback: return raw output
        return {"interface": interface, "raw_output": result.stdout}
    except subprocess.SubprocessError as e:
        logging.error(f"Failed to query WireGuard interface {interface}: {e}")
        raise HTTPException(status_code=500, detail="Failed to query interface")


@app.get("/api/egress/custom")
def api_list_custom_egress():
    """列出所有自定义出口"""
    db = _get_db()
    egress_list = db.get_custom_egress_list()
    # 不返回敏感信息（私钥）
    result = []
    for eg in egress_list:
        result.append({
            "tag": eg.get("tag", ""),
            "description": eg.get("description", ""),
            "server": eg.get("server", ""),
            "port": eg.get("port", 51820),
            "address": eg.get("address", ""),
            "mtu": eg.get("mtu", 1420),
            "dns": eg.get("dns", "1.1.1.1"),
            "has_psk": bool(eg.get("pre_shared_key")),
            "has_reserved": bool(eg.get("reserved")),
        })
    return {"egress": result}


@app.post("/api/egress/custom")
def api_create_custom_egress(payload: CustomEgressCreateRequest):
    """创建自定义出口"""
    db = _get_db()

    # 检查 tag 是否已存在
    if db.get_custom_egress(payload.tag):
        raise HTTPException(status_code=400, detail=f"出口 '{payload.tag}' 已存在")

    # 检查是否与 PIA profiles 冲突
    pia_profiles = db.get_pia_profiles(enabled_only=False)
    pia_tags = {p.get("name", "") for p in pia_profiles}  # 保持原始名称
    if payload.tag in pia_tags:
        raise HTTPException(status_code=400, detail=f"出口 '{payload.tag}' 与 PIA 线路冲突")

    # 添加到数据库
    db.add_custom_egress(
        tag=payload.tag,
        server=payload.server,
        private_key=payload.private_key,
        public_key=payload.public_key,
        address=payload.address,
        description=payload.description,
        port=payload.port,
        mtu=payload.mtu,
        dns=payload.dns,
        pre_shared_key=payload.pre_shared_key,
        reserved=payload.reserved,
    )

    # 同步内核 WireGuard 接口并重新渲染配置
    reload_status = ""
    try:
        wg_sync_status = _sync_kernel_wg_egress()
        _regenerate_and_reload()
        reload_status = f"，已重载配置{wg_sync_status}"
    except Exception as exc:
        print(f"[api] 重载配置失败: {exc}")
        reload_status = f"，重载失败: {exc}"

    return {
        "message": f"出口 '{payload.tag}' 已创建{reload_status}",
        "tag": payload.tag,
    }


@app.post("/api/egress/custom/parse")
def api_parse_wireguard_conf(payload: WireGuardConfParseRequest):
    """解析 WireGuard .conf 文件内容"""
    try:
        result = parse_wireguard_conf(payload.content)

        # 验证必要字段
        errors = []
        if not result.get("private_key"):
            errors.append("缺少 PrivateKey")
        if not result.get("public_key"):
            errors.append("缺少 Peer PublicKey")
        if not result.get("server"):
            errors.append("缺少 Peer Endpoint")
        if not result.get("address"):
            errors.append("缺少 Address")

        if errors:
            raise HTTPException(status_code=400, detail=f"配置解析错误: {', '.join(errors)}")

        # 返回解析后的结果，直接作为顶层对象
        return result
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(status_code=400, detail=f"解析失败: {exc}")


@app.put("/api/egress/custom/{tag}")
def api_update_custom_egress(tag: str, payload: CustomEgressUpdateRequest):
    """更新自定义出口"""
    db = _get_db()

    # 检查出口是否存在
    if not db.get_custom_egress(tag):
        raise HTTPException(status_code=404, detail=f"出口 '{tag}' 不存在")

    # 构建更新字段（空字符串不更新，防止覆盖现有值）
    updates = {}
    if payload.description is not None and payload.description.strip():
        updates["description"] = payload.description
    if payload.server is not None and payload.server.strip():
        updates["server"] = payload.server
    if payload.port is not None:
        updates["port"] = payload.port
    if payload.private_key is not None and payload.private_key.strip():
        updates["private_key"] = payload.private_key
    if payload.public_key is not None and payload.public_key.strip():
        updates["public_key"] = payload.public_key
    if payload.address is not None and payload.address.strip():
        updates["address"] = payload.address
    if payload.mtu is not None:
        updates["mtu"] = payload.mtu
    if payload.dns is not None and payload.dns.strip():
        updates["dns"] = payload.dns
    # pre_shared_key 允许清空（设为空字符串）
    if payload.pre_shared_key is not None:
        updates["pre_shared_key"] = payload.pre_shared_key
    if payload.reserved is not None:
        updates["reserved"] = payload.reserved

    db.update_custom_egress(tag, **updates)

    # 同步内核 WireGuard 接口并重新渲染配置
    reload_status = ""
    try:
        wg_sync_status = _sync_kernel_wg_egress()
        _regenerate_and_reload()
        reload_status = f"，已重载配置{wg_sync_status}"
    except Exception as exc:
        print(f"[api] 重载配置失败: {exc}")
        reload_status = f"，重载失败: {exc}"

    return {"message": f"出口 '{tag}' 已更新{reload_status}"}


@app.delete("/api/egress/custom/{tag}")
def api_delete_custom_egress(tag: str):
    """删除自定义出口"""
    db = _get_db()

    # 检查出口是否存在
    if not db.get_custom_egress(tag):
        raise HTTPException(status_code=404, detail=f"出口 '{tag}' 不存在")

    # 删除
    db.delete_custom_egress(tag)

    # 同步内核 WireGuard 接口（清理已删除的接口）并重新渲染配置
    reload_status = ""
    try:
        wg_sync_status = _sync_kernel_wg_egress()
        _regenerate_and_reload()
        reload_status = f"，已重载配置{wg_sync_status}"
    except Exception as exc:
        print(f"[api] 重载配置失败: {exc}")
        reload_status = f"，重载失败: {exc}"

    return {"message": f"出口 '{tag}' 已删除{reload_status}"}


# ============ Direct Egress APIs ============

@app.get("/api/egress/direct")
def api_list_direct_egress():
    """列出所有 direct 出口"""
    db = _get_db()
    egress_list = db.get_direct_egress_list(enabled_only=False)
    return {"egress": egress_list}


@app.get("/api/egress/direct/{tag}")
def api_get_direct_egress(tag: str):
    """获取单个 direct 出口"""
    db = _get_db()
    egress = db.get_direct_egress(tag)
    if not egress:
        raise HTTPException(status_code=404, detail=f"Direct 出口 '{tag}' 不存在")
    return egress


@app.post("/api/egress/direct")
def api_create_direct_egress(payload: DirectEgressCreateRequest):
    """创建 direct 出口"""
    db = _get_db()

    # 不允许使用保留名称
    if payload.tag == "direct":
        raise HTTPException(status_code=400, detail="'direct' 是保留名称，请使用其他名称")

    # 检查 tag 是否已存在
    if db.get_direct_egress(payload.tag):
        raise HTTPException(status_code=400, detail=f"Direct 出口 '{payload.tag}' 已存在")

    # 检查是否与其他出口冲突
    if db.get_custom_egress(payload.tag):
        raise HTTPException(status_code=400, detail=f"出口 '{payload.tag}' 与自定义 WireGuard 出口冲突")

    pia_profiles = db.get_pia_profiles(enabled_only=False)
    pia_tags = {p.get("name", "") for p in pia_profiles}  # 保持原始名称
    if payload.tag in pia_tags:
        raise HTTPException(status_code=400, detail=f"出口 '{payload.tag}' 与 PIA 线路冲突")

    # 至少需要绑定接口或地址之一
    if not payload.bind_interface and not payload.inet4_bind_address and not payload.inet6_bind_address:
        raise HTTPException(status_code=400, detail="至少需要指定 bind_interface、inet4_bind_address 或 inet6_bind_address 之一")

    # 添加到数据库
    db.add_direct_egress(
        tag=payload.tag,
        description=payload.description,
        bind_interface=payload.bind_interface,
        inet4_bind_address=payload.inet4_bind_address,
        inet6_bind_address=payload.inet6_bind_address,
    )

    # 重新渲染配置并重载
    reload_status = ""
    try:
        _regenerate_and_reload()
        reload_status = "，已重载配置"
    except Exception as exc:
        print(f"[api] 重载配置失败: {exc}")
        reload_status = f"，重载失败: {exc}"

    return {
        "message": f"Direct 出口 '{payload.tag}' 已创建{reload_status}",
        "tag": payload.tag,
    }


@app.put("/api/egress/direct/{tag}")
def api_update_direct_egress(tag: str, payload: DirectEgressUpdateRequest):
    """更新 direct 出口"""
    db = _get_db()

    # 检查出口是否存在
    if not db.get_direct_egress(tag):
        raise HTTPException(status_code=404, detail=f"Direct 出口 '{tag}' 不存在")

    # 构建更新字段（空字符串不更新，防止覆盖现有值）
    updates = {}
    if payload.description is not None and payload.description.strip():
        updates["description"] = payload.description
    # 绑定字段允许清空（从接口绑定切换到IP绑定时需要）
    if payload.bind_interface is not None:
        updates["bind_interface"] = payload.bind_interface
    if payload.inet4_bind_address is not None:
        updates["inet4_bind_address"] = payload.inet4_bind_address
    if payload.inet6_bind_address is not None:
        updates["inet6_bind_address"] = payload.inet6_bind_address
    if payload.enabled is not None:
        updates["enabled"] = payload.enabled

    if updates:
        db.update_direct_egress(tag, **updates)

    # 重新渲染配置并重载
    reload_status = ""
    try:
        _regenerate_and_reload()
        reload_status = "，已重载配置"
    except Exception as exc:
        print(f"[api] 重载配置失败: {exc}")
        reload_status = f"，重载失败: {exc}"

    return {"message": f"Direct 出口 '{tag}' 已更新{reload_status}"}


@app.delete("/api/egress/direct/{tag}")
def api_delete_direct_egress(tag: str):
    """删除 direct 出口"""
    db = _get_db()

    # 检查出口是否存在
    if not db.get_direct_egress(tag):
        raise HTTPException(status_code=404, detail=f"Direct 出口 '{tag}' 不存在")

    # 删除
    db.delete_direct_egress(tag)

    # 重新渲染配置并重载
    reload_status = ""
    try:
        _regenerate_and_reload()
        reload_status = "，已重载配置"
    except Exception as exc:
        print(f"[api] 重载配置失败: {exc}")
        reload_status = f"，重载失败: {exc}"

    return {"message": f"Direct 出口 '{tag}' 已删除{reload_status}"}


# ============ OpenVPN Egress APIs ============

def _parse_ovpn_content(content: str) -> dict:
    """解析 .ovpn 文件内容，提取配置"""
    import re

    result = {
        "protocol": "udp",
        "remote_host": "",
        "remote_port": 1194,
        "ca_cert": "",
        "client_cert": "",
        "client_key": "",
        "tls_auth": "",
        "tls_crypt": "",
        "cipher": "AES-256-GCM",
        "auth": "SHA256",
        "compress": None,
        "extra_options": [],
    }

    # 提取 remote 指令
    remote_match = re.search(r'^remote\s+(\S+)\s+(\d+)(?:\s+(\w+))?', content, re.MULTILINE)
    if remote_match:
        result["remote_host"] = remote_match.group(1)
        result["remote_port"] = int(remote_match.group(2))
        if remote_match.group(3):
            result["protocol"] = remote_match.group(3)

    # 使用 [^\S\n] 匹配水平空白（不包括换行符）以避免跨行匹配

    # 提取协议
    proto_match = re.search(r'^proto[^\S\n]+(\S+)[^\S\n]*$', content, re.MULTILINE)
    if proto_match:
        result["protocol"] = proto_match.group(1)

    # 提取加密算法
    cipher_match = re.search(r'^cipher[^\S\n]+(\S+)[^\S\n]*$', content, re.MULTILINE)
    if cipher_match:
        result["cipher"] = cipher_match.group(1)

    # 提取认证算法 (需要排除 auth-user-pass 等指令)
    auth_match = re.search(r'^auth[^\S\n]+(\S+)[^\S\n]*$', content, re.MULTILINE)
    if auth_match and not auth_match.group(1).startswith('-'):
        result["auth"] = auth_match.group(1)

    # 提取压缩 - 支持 "compress" 无参数或 "compress lzo/lz4" 有参数
    compress_match = re.search(r'^compress(?:[^\S\n]+(\S+))?[^\S\n]*$', content, re.MULTILINE)
    if compress_match:
        if compress_match.group(1):
            result["compress"] = compress_match.group(1)
        else:
            # compress 无参数等于 compress stub (不压缩发送，但接受压缩数据)
            result["compress"] = "stub"
    # 也检查 comp-lzo (旧格式)
    if re.search(r'^comp-lzo', content, re.MULTILINE):
        result["compress"] = "lzo"

    # 提取嵌入的证书/密钥
    def extract_block(tag: str) -> str:
        pattern = rf'<{tag}>(.*?)</{tag}>'
        match = re.search(pattern, content, re.DOTALL)
        return match.group(1).strip() if match else ""

    result["ca_cert"] = extract_block("ca")
    result["client_cert"] = extract_block("cert")
    result["client_key"] = extract_block("key")
    result["tls_auth"] = extract_block("tls-auth")
    result["tls_crypt"] = extract_block("tls-crypt")
    result["crl_verify"] = extract_block("crl-verify")

    # 检测是否需要用户名/密码认证
    if re.search(r'^auth-user-pass', content, re.MULTILINE):
        result["requires_auth"] = True

    return result


@app.get("/api/egress/openvpn")
def api_list_openvpn_egress():
    """列出所有 OpenVPN 出口"""
    db = _get_db()
    egress_list = db.get_openvpn_egress_list(enabled_only=False)
    # 隐藏敏感信息
    for egress in egress_list:
        if egress.get("auth_pass"):
            egress["auth_pass"] = "***"
        if egress.get("client_key"):
            egress["client_key"] = "[hidden]"
    return {"egress": egress_list}


@app.get("/api/egress/openvpn/{tag}")
def api_get_openvpn_egress(tag: str):
    """获取单个 OpenVPN 出口（包含完整配置）"""
    db = _get_db()
    egress = db.get_openvpn_egress(tag)
    if not egress:
        raise HTTPException(status_code=404, detail=f"OpenVPN 出口 '{tag}' 不存在")
    return egress


@app.post("/api/egress/openvpn")
def api_create_openvpn_egress(payload: OpenVPNEgressCreateRequest):
    """创建 OpenVPN 出口"""
    db = _get_db()

    # 检查 tag 是否已存在
    if db.get_openvpn_egress(payload.tag):
        raise HTTPException(status_code=400, detail=f"OpenVPN 出口 '{payload.tag}' 已存在")

    # 检查是否与其他出口冲突
    if db.get_custom_egress(payload.tag):
        raise HTTPException(status_code=400, detail=f"出口 '{payload.tag}' 与自定义 WireGuard 出口冲突")
    if db.get_direct_egress(payload.tag):
        raise HTTPException(status_code=400, detail=f"出口 '{payload.tag}' 与 Direct 出口冲突")

    pia_profiles = db.get_pia_profiles(enabled_only=False)
    pia_tags = {p.get("name", "") for p in pia_profiles}
    if payload.tag in pia_tags:
        raise HTTPException(status_code=400, detail=f"出口 '{payload.tag}' 与 PIA 线路冲突")

    # 验证 CA 证书
    if not payload.ca_cert or not payload.ca_cert.strip():
        raise HTTPException(status_code=400, detail="CA 证书不能为空")

    # 添加到数据库
    egress_id = db.add_openvpn_egress(
        tag=payload.tag,
        remote_host=payload.remote_host,
        ca_cert=payload.ca_cert,
        description=payload.description,
        protocol=payload.protocol,
        remote_port=payload.remote_port,
        client_cert=payload.client_cert,
        client_key=payload.client_key,
        tls_auth=payload.tls_auth,
        tls_crypt=payload.tls_crypt,
        crl_verify=payload.crl_verify,
        auth_user=payload.auth_user,
        auth_pass=payload.auth_pass,
        cipher=payload.cipher,
        auth=payload.auth,
        compress=payload.compress,
        extra_options=payload.extra_options,
    )

    # 获取分配的 TUN 设备
    egress = db.get_openvpn_egress(payload.tag)
    tun_device = egress.get("tun_device") if egress else None

    # 重新渲染配置并重载
    reload_status = ""
    try:
        _regenerate_and_reload()
        reload_status = "，已重载配置"
        # 重载 OpenVPN 管理器以启动新隧道
        reload_status += _reload_openvpn_manager()
    except Exception as exc:
        print(f"[api] 重载配置失败: {exc}")
        reload_status = f"，重载失败: {exc}"

    return {
        "message": f"OpenVPN 出口 '{payload.tag}' 已创建{reload_status}",
        "tag": payload.tag,
        "tun_device": tun_device,
    }


@app.post("/api/egress/openvpn/parse")
def api_parse_openvpn_file(payload: OpenVPNParseRequest):
    """解析 .ovpn 文件内容，返回提取的配置"""
    try:
        result = _parse_ovpn_content(payload.content)
        return result  # 直接返回解析结果，不包装在 parsed 对象中
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"解析 .ovpn 文件失败: {e}")


@app.put("/api/egress/openvpn/{tag}")
def api_update_openvpn_egress(tag: str, payload: OpenVPNEgressUpdateRequest):
    """更新 OpenVPN 出口"""
    db = _get_db()

    # 检查出口是否存在
    if not db.get_openvpn_egress(tag):
        raise HTTPException(status_code=404, detail=f"OpenVPN 出口 '{tag}' 不存在")

    # 构建更新字段（空字符串不更新，防止覆盖现有值）
    updates = {}
    # 字符串字段：空字符串不更新
    string_fields = {
        "description", "protocol", "remote_host",
        "ca_cert", "client_cert", "client_key", "tls_auth", "tls_crypt",
        "crl_verify", "auth_user", "auth_pass", "cipher", "auth", "compress",
        "extra_options"
    }
    for field in string_fields:
        value = getattr(payload, field, None)
        if value is not None and isinstance(value, str) and value.strip():
            updates[field] = value
    # 数字/布尔字段：直接更新
    if payload.remote_port is not None:
        updates["remote_port"] = payload.remote_port
    if payload.enabled is not None:
        updates["enabled"] = payload.enabled

    if updates:
        db.update_openvpn_egress(tag, **updates)

    # 重新渲染配置并重载
    reload_status = ""
    try:
        _regenerate_and_reload()
        reload_status = "，已重载配置"
        # 重载 OpenVPN 管理器以应用新配置
        reload_status += _reload_openvpn_manager()
    except Exception as exc:
        print(f"[api] 重载配置失败: {exc}")
        reload_status = f"，重载失败: {exc}"

    return {"message": f"OpenVPN 出口 '{tag}' 已更新{reload_status}"}


@app.delete("/api/egress/openvpn/{tag}")
def api_delete_openvpn_egress(tag: str):
    """删除 OpenVPN 出口"""
    db = _get_db()

    # 检查出口是否存在
    if not db.get_openvpn_egress(tag):
        raise HTTPException(status_code=404, detail=f"OpenVPN 出口 '{tag}' 不存在")

    # 删除
    db.delete_openvpn_egress(tag)

    # 重新渲染配置并重载
    reload_status = ""
    try:
        _regenerate_and_reload()
        reload_status = "，已重载配置"
        # 重载 OpenVPN 管理器以停止已删除的隧道
        reload_status += _reload_openvpn_manager()
    except Exception as exc:
        print(f"[api] 重载配置失败: {exc}")
        reload_status = f"，重载失败: {exc}"

    return {"message": f"OpenVPN 出口 '{tag}' 已删除{reload_status}"}


@app.get("/api/egress/openvpn/{tag}/status")
def api_get_openvpn_status(tag: str):
    """获取 OpenVPN 隧道状态"""
    db = _get_db()

    # 检查出口是否存在
    egress = db.get_openvpn_egress(tag)
    if not egress:
        raise HTTPException(status_code=404, detail=f"OpenVPN 出口 '{tag}' 不存在")

    # 检查进程状态
    import subprocess
    try:
        result = subprocess.run(
            ["python3", "/usr/local/bin/openvpn_manager.py", "status", "--tag", tag],
            capture_output=True,
            text=True,
            timeout=5
        )
        if result.returncode == 0:
            import json as json_module
            status_data = json_module.loads(result.stdout)
            return {"status": status_data}
        else:
            return {"status": {"tag": tag, "status": "unknown", "error": result.stderr}}
    except Exception as e:
        return {"status": {"tag": tag, "status": "error", "error": str(e)}}


# ============ V2Ray Egress APIs ============

@app.get("/api/egress/v2ray")
def api_list_v2ray_egress():
    """列出所有 V2Ray 出口"""
    db = _get_db()
    egress_list = db.get_v2ray_egress_list(enabled_only=False)
    # 隐藏敏感信息
    for egress in egress_list:
        if egress.get("password"):
            egress["password"] = "***"
    return {"egress": egress_list}


@app.get("/api/egress/v2ray/{tag}")
def api_get_v2ray_egress(tag: str):
    """获取单个 V2Ray 出口（包含完整配置）"""
    db = _get_db()
    egress = db.get_v2ray_egress(tag)
    if not egress:
        raise HTTPException(status_code=404, detail=f"V2Ray egress '{tag}' not found")
    return egress


@app.post("/api/egress/v2ray")
def api_create_v2ray_egress(payload: V2RayEgressCreateRequest):
    """创建 V2Ray 出口"""
    db = _get_db()

    # 验证协议 - [Xray-lite] 仅支持 VLESS
    if payload.protocol != "vless":
        raise HTTPException(
            status_code=400,
            detail=f"Invalid protocol: {payload.protocol}. Only 'vless' is supported in Xray-lite. "
            "VMess and Trojan have been removed. See docs/VMESS_TROJAN_MIGRATION.md"
        )

    # 检查 tag 是否已存在
    if db.get_v2ray_egress(payload.tag):
        raise HTTPException(status_code=400, detail=f"V2Ray egress '{payload.tag}' already exists")

    # 检查是否与其他出口冲突
    if db.get_custom_egress(payload.tag):
        raise HTTPException(status_code=400, detail=f"Egress '{payload.tag}' conflicts with custom WireGuard egress")
    if db.get_direct_egress(payload.tag):
        raise HTTPException(status_code=400, detail=f"Egress '{payload.tag}' conflicts with Direct egress")
    if db.get_openvpn_egress(payload.tag):
        raise HTTPException(status_code=400, detail=f"Egress '{payload.tag}' conflicts with OpenVPN egress")

    pia_profiles = db.get_pia_profiles(enabled_only=False)
    pia_tags = {p.get("name", "") for p in pia_profiles}
    if payload.tag in pia_tags:
        raise HTTPException(status_code=400, detail=f"Egress '{payload.tag}' conflicts with PIA profile")

    # 验证认证信息 - VLESS 需要 UUID
    if not payload.uuid:
        raise HTTPException(status_code=400, detail="VLESS requires UUID")

    # 构建 transport_config JSON
    transport_config_json = json.dumps(payload.transport_config) if payload.transport_config else None
    tls_alpn_json = json.dumps(payload.tls_alpn) if payload.tls_alpn else None

    # 添加到数据库
    egress_id = db.add_v2ray_egress(
        tag=payload.tag,
        protocol=payload.protocol,
        server=payload.server,
        server_port=payload.server_port,
        description=payload.description,
        uuid=payload.uuid,
        password=payload.password,
        security=payload.security,
        alter_id=payload.alter_id,
        flow=payload.flow,
        tls_enabled=1 if payload.tls_enabled else 0,
        tls_sni=payload.tls_sni,
        tls_alpn=tls_alpn_json,
        tls_allow_insecure=1 if payload.tls_allow_insecure else 0,
        tls_fingerprint=payload.tls_fingerprint,
        reality_enabled=1 if payload.reality_enabled else 0,
        reality_public_key=payload.reality_public_key,
        reality_short_id=payload.reality_short_id,
        transport_type=payload.transport_type,
        transport_config=transport_config_json,
        multiplex_enabled=1 if payload.multiplex_enabled else 0,
        multiplex_protocol=payload.multiplex_protocol,
        multiplex_max_connections=payload.multiplex_max_connections,
        multiplex_min_streams=payload.multiplex_min_streams,
        multiplex_max_streams=payload.multiplex_max_streams,
    )

    # 重新渲染配置并重载 sing-box 和 Xray egress
    reload_status = ""
    try:
        _regenerate_and_reload()
        reload_status = ", config reloaded"
        # 重载 Xray egress manager（启动新的出口）
        reload_status += _reload_xray_egress()
    except Exception as exc:
        print(f"[api] Reload failed: {exc}")
        reload_status = f", reload failed: {exc}"

    return {
        "message": f"V2Ray egress '{payload.tag}' created{reload_status}",
        "tag": payload.tag,
        "id": egress_id,
    }


@app.post("/api/egress/v2ray/parse")
def api_parse_v2ray_uri(payload: V2RayURIParseRequest):
    """解析 V2Ray 分享链接（vmess://, vless://, trojan://）"""
    if not HAS_V2RAY_PARSER:
        raise HTTPException(status_code=500, detail="V2Ray URI parser not available")

    try:
        result = parse_v2ray_uri(payload.uri)
        return result
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Failed to parse V2Ray URI: {e}")


@app.put("/api/egress/v2ray/{tag}")
def api_update_v2ray_egress(tag: str, payload: V2RayEgressUpdateRequest):
    """更新 V2Ray 出口"""
    db = _get_db()

    # 检查出口是否存在
    if not db.get_v2ray_egress(tag):
        raise HTTPException(status_code=404, detail=f"V2Ray egress '{tag}' not found")

    # 构建更新字段（空字符串不更新，防止覆盖现有值）
    updates = {}
    # 字符串字段：空字符串不更新
    string_fields = {
        "description", "protocol", "server", "uuid", "password", "security", "flow",
        "tls_sni", "tls_fingerprint", "reality_public_key", "reality_short_id",
        "transport_type", "multiplex_protocol"
    }
    # 布尔字段：转为整数
    bool_fields = {"tls_enabled", "tls_allow_insecure", "reality_enabled", "multiplex_enabled", "enabled"}
    # JSON 字段
    json_fields = {"tls_alpn", "transport_config"}
    # 数字字段
    numeric_fields = {"server_port", "alter_id", "multiplex_max_connections", "multiplex_min_streams", "multiplex_max_streams"}

    for field in string_fields | bool_fields | json_fields | numeric_fields:
        value = getattr(payload, field, None)
        if value is not None:
            # 字符串字段：空字符串不更新
            if field in string_fields:
                if isinstance(value, str) and not value.strip():
                    continue  # 跳过空字符串
                updates[field] = value
            # 布尔字段：转为整数
            elif field in bool_fields:
                updates[field] = 1 if value else 0
            # JSON 字段
            elif field in json_fields:
                updates[field] = json.dumps(value) if value else None
            # 数字字段：直接更新
            else:
                updates[field] = value

    if updates:
        db.update_v2ray_egress(tag, **updates)

    # 重新渲染配置并重载 sing-box 和 Xray egress
    reload_status = ""
    try:
        _regenerate_and_reload()
        reload_status = ", config reloaded"
        # 重载 Xray egress manager（更新出口配置）
        reload_status += _reload_xray_egress()
    except Exception as exc:
        print(f"[api] Reload failed: {exc}")
        reload_status = f", reload failed: {exc}"

    return {"message": f"V2Ray egress '{tag}' updated{reload_status}"}


@app.delete("/api/egress/v2ray/{tag}")
def api_delete_v2ray_egress(tag: str):
    """删除 V2Ray 出口"""
    db = _get_db()

    # 检查出口是否存在
    if not db.get_v2ray_egress(tag):
        raise HTTPException(status_code=404, detail=f"V2Ray egress '{tag}' not found")

    # 删除
    db.delete_v2ray_egress(tag)

    # 重新渲染配置并重载 sing-box 和 Xray egress
    reload_status = ""
    try:
        _regenerate_and_reload()
        reload_status = ", config reloaded"
        # 重载 Xray egress manager（移除出口）
        reload_status += _reload_xray_egress()
    except Exception as exc:
        print(f"[api] Reload failed: {exc}")
        reload_status = f", reload failed: {exc}"

    return {"message": f"V2Ray egress '{tag}' deleted{reload_status}"}


# ============ WARP Egress APIs ============

class WarpEgressCreate(BaseModel):
    """WARP 出口创建请求"""
    tag: str
    description: str = ""
    license_key: Optional[str] = None
    protocol: str = "masque"  # masque 或 wireguard


class WarpEgressUpdate(BaseModel):
    """WARP 出口更新请求"""
    description: Optional[str] = None
    license_key: Optional[str] = None
    endpoint_v4: Optional[str] = None
    endpoint_v6: Optional[str] = None
    enabled: Optional[bool] = None


class WarpEndpointUpdate(BaseModel):
    """WARP Endpoint 设置请求"""
    endpoint_v4: Optional[str] = None
    endpoint_v6: Optional[str] = None


class WarpEndpointsTest(BaseModel):
    """WARP Endpoint 测试请求"""
    endpoints: Optional[List[str]] = None
    sample_count: int = 50
    top_n: int = 10


def _reload_warp_manager() -> str:
    """重载 WARP 管理器

    如果守护进程运行中，发送 SIGHUP 信号重载配置。
    如果守护进程未运行，启动新的守护进程。

    Returns:
        状态消息
    """
    from pathlib import Path
    import subprocess

    pid_file = Path("/run/warp-manager.pid")

    # 检查守护进程是否运行
    daemon_running = False
    if pid_file.exists():
        try:
            daemon_pid = int(pid_file.read_text().strip())
            os.kill(daemon_pid, 0)  # 检查进程是否存在
            daemon_running = True
        except (ValueError, ProcessLookupError, PermissionError):
            # PID 文件无效或进程不存在，清理
            pid_file.unlink(missing_ok=True)

    if daemon_running:
        # 发送 SIGHUP 重载
        try:
            daemon_pid = int(pid_file.read_text().strip())
            os.kill(daemon_pid, signal.SIGHUP)
            print(f"[api] Sent SIGHUP to WARP manager (PID: {daemon_pid})")
            return ", warp manager reloaded"
        except (ValueError, ProcessLookupError, PermissionError) as e:
            print(f"[api] WARP manager reload failed: {e}")
            return ", warp manager reload failed"
    else:
        # 启动新的守护进程
        try:
            log_file = open("/var/log/warp-manager.log", "a")
            subprocess.Popen(
                ["python3", "/usr/local/bin/warp_manager.py", "daemon"],
                stdout=log_file,
                stderr=log_file,
                start_new_session=True
            )
            print("[api] Started WARP manager daemon")
            time.sleep(1)  # 等待启动
            return ", warp manager started"
        except Exception as e:
            print(f"[api] Failed to start WARP manager: {e}")
            return f", warp manager start failed: {e}"


@app.get("/api/egress/warp")
def api_list_warp_egress(enabled_only: bool = False):
    """列出所有 WARP 出口"""
    db = _get_db()
    egress_list = db.get_warp_egress_list(enabled_only)
    return {"warp_egress": egress_list}


@app.get("/api/egress/warp/{tag}")
def api_get_warp_egress(tag: str):
    """获取单个 WARP 出口"""
    db = _get_db()
    egress = db.get_warp_egress(tag)
    if not egress:
        raise HTTPException(status_code=404, detail=f"WARP egress '{tag}' not found")
    return egress


@app.post("/api/egress/warp/register")
def api_register_warp_egress(data: WarpEgressCreate):
    """一键注册 WARP 设备并创建出口"""
    from warp_manager import WarpManager

    db = _get_db()

    # 检查 tag 是否已存在
    if db.get_warp_egress(data.tag):
        raise HTTPException(status_code=400, detail=f"WARP egress '{data.tag}' already exists")

    # 获取下一个可用端口
    try:
        socks_port = db.get_next_warp_socks_port()
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

    # 验证协议
    if data.protocol not in ("masque", "wireguard"):
        raise HTTPException(status_code=400, detail=f"Invalid protocol: {data.protocol}")

    # 调用 warp_manager 进行注册
    manager = WarpManager()
    result = manager.register(data.tag, data.license_key, protocol=data.protocol)

    if not result.get("success"):
        raise HTTPException(status_code=500, detail=result.get("error", "Registration failed"))

    # 保存到数据库
    config_path = result.get("config_path", "")
    account_type = result.get("account_type", "free")

    db.add_warp_egress(
        tag=data.tag,
        description=data.description,
        protocol=data.protocol,
        config_path=config_path,
        license_key=data.license_key,
        account_type=account_type,
        mode="socks",
        socks_port=socks_port,
        enabled=True
    )

    # 重新渲染配置并重载
    reload_status = ""
    try:
        _regenerate_and_reload()
        reload_status = ", config reloaded"
        reload_status += _reload_warp_manager()
    except Exception as exc:
        print(f"[api] Reload failed: {exc}")
        reload_status = f", reload failed: {exc}"

    return {
        "message": f"WARP egress '{data.tag}' registered{reload_status}",
        "tag": data.tag,
        "socks_port": socks_port,
        "account_type": account_type,
        "device_id": result.get("device_id", "")
    }


@app.put("/api/egress/warp/{tag}")
def api_update_warp_egress(tag: str, data: WarpEgressUpdate):
    """更新 WARP 出口"""
    db = _get_db()

    if not db.get_warp_egress(tag):
        raise HTTPException(status_code=404, detail=f"WARP egress '{tag}' not found")

    # 构建更新字段
    updates = {}
    if data.description is not None:
        updates["description"] = data.description
    if data.endpoint_v4 is not None:
        updates["endpoint_v4"] = data.endpoint_v4
    if data.endpoint_v6 is not None:
        updates["endpoint_v6"] = data.endpoint_v6
    if data.enabled is not None:
        updates["enabled"] = data.enabled

    if updates:
        db.update_warp_egress(tag, **updates)

    # 重新渲染配置并重载
    reload_status = ""
    try:
        _regenerate_and_reload()
        reload_status = ", config reloaded"
        reload_status += _reload_warp_manager()
    except Exception as exc:
        print(f"[api] Reload failed: {exc}")
        reload_status = f", reload failed: {exc}"

    return {"message": f"WARP egress '{tag}' updated{reload_status}"}


@app.delete("/api/egress/warp/{tag}")
def api_delete_warp_egress(tag: str):
    """删除 WARP 出口"""
    from warp_manager import WarpManager

    db = _get_db()

    if not db.get_warp_egress(tag):
        raise HTTPException(status_code=404, detail=f"WARP egress '{tag}' not found")

    # 停止代理并删除配置
    manager = WarpManager()
    import asyncio
    asyncio.run(manager.stop_proxy(tag))
    manager.delete_config(tag)

    # 从数据库删除
    db.delete_warp_egress(tag)

    # 重新渲染配置并重载
    reload_status = ""
    try:
        _regenerate_and_reload()
        reload_status = ", config reloaded"
        reload_status += _reload_warp_manager()
    except Exception as exc:
        print(f"[api] Reload failed: {exc}")
        reload_status = f", reload failed: {exc}"

    return {"message": f"WARP egress '{tag}' deleted{reload_status}"}


@app.post("/api/egress/warp/{tag}/reregister")
def api_reregister_warp_egress(tag: str):
    """重新注册 WARP 设备（修复 TLS 握手失败等问题）"""
    from warp_manager import WarpManager
    import asyncio

    db = _get_db()

    egress = db.get_warp_egress(tag)
    if not egress:
        raise HTTPException(status_code=404, detail=f"WARP egress '{tag}' not found")

    # 停止当前代理
    manager = WarpManager()
    asyncio.run(manager.stop_proxy(tag))

    # 删除旧配置文件（但保留数据库记录）
    manager.delete_config(tag)

    # 重新注册
    license_key = egress.get("license_key")
    protocol = egress.get("protocol", "masque")
    result = manager.register(tag, license_key, protocol=protocol)

    if not result.get("success"):
        raise HTTPException(status_code=500, detail=result.get("error", "Re-registration failed"))

    # 更新数据库中的配置路径和账户类型
    config_path = result.get("config_path", "")
    account_type = result.get("account_type", "free")
    db.update_warp_egress(tag, config_path=config_path, account_type=account_type)

    # 立即启动新代理（不依赖 reload 机制）
    proxy_status = ""
    try:
        started = asyncio.run(manager.start_proxy(tag))
        if started:
            proxy_status = ", proxy started"
        else:
            proxy_status = ", proxy start failed"
    except Exception as exc:
        print(f"[api] Proxy start failed: {exc}")
        proxy_status = f", proxy start failed: {exc}"

    # 重新渲染配置并重载 sing-box
    reload_status = ""
    try:
        _regenerate_and_reload()
        reload_status = ", config reloaded"
    except Exception as exc:
        print(f"[api] Reload failed: {exc}")
        reload_status = f", reload failed: {exc}"

    return {
        "message": f"WARP egress '{tag}' re-registered{proxy_status}{reload_status}",
        "account_type": account_type,
        "device_id": result.get("device_id", "")
    }


@app.get("/api/egress/warp/{tag}/status")
def api_get_warp_status(tag: str):
    """获取 WARP 代理状态"""
    from warp_manager import WarpManager

    db = _get_db()
    egress = db.get_warp_egress(tag)
    if not egress:
        raise HTTPException(status_code=404, detail=f"WARP egress '{tag}' not found")

    manager = WarpManager()
    status = manager.get_status(tag)

    return status


@app.post("/api/egress/warp/{tag}/apply-license")
def api_apply_warp_license(tag: str, license_key: str = Body(..., embed=True)):
    """应用 WARP+ License"""
    from warp_manager import WarpManager

    db = _get_db()
    egress = db.get_warp_egress(tag)
    if not egress:
        raise HTTPException(status_code=404, detail=f"WARP egress '{tag}' not found")

    manager = WarpManager()
    result = manager.apply_license(tag, license_key)

    if not result.get("success"):
        raise HTTPException(status_code=400, detail=result.get("error", "Failed to apply license"))

    # 更新数据库
    db.update_warp_egress(tag, license_key=license_key, account_type="warp+")

    # 重载代理以应用新 license
    reload_status = _reload_warp_manager()

    return {"message": f"WARP+ license applied to '{tag}'{reload_status}"}


@app.put("/api/egress/warp/{tag}/endpoint")
def api_set_warp_endpoint(tag: str, data: WarpEndpointUpdate):
    """设置自定义 Endpoint（指定地区节点）"""
    from warp_manager import WarpManager

    db = _get_db()
    egress = db.get_warp_egress(tag)
    if not egress:
        raise HTTPException(status_code=404, detail=f"WARP egress '{tag}' not found")

    manager = WarpManager()
    result = manager.set_endpoint(tag, data.endpoint_v4, data.endpoint_v6)

    if not result.get("success"):
        raise HTTPException(status_code=400, detail=result.get("error", "Failed to set endpoint"))

    # 更新数据库
    updates = {}
    if data.endpoint_v4:
        updates["endpoint_v4"] = data.endpoint_v4
    if data.endpoint_v6:
        updates["endpoint_v6"] = data.endpoint_v6
    if updates:
        db.update_warp_egress(tag, **updates)

    protocol = egress.get("protocol", "masque")
    reload_status = ""

    if protocol == "wireguard":
        # WireGuard: 重新渲染配置并重载 sing-box
        try:
            _regenerate_and_reload()
            reload_status = ", config reloaded"
        except Exception as exc:
            print(f"[api] Reload failed: {exc}")
            reload_status = f", reload failed: {exc}"
    else:
        # MASQUE: 重载 WARP manager 以应用新 endpoint
        reload_status = _reload_warp_manager()

    return {
        "message": f"Endpoint updated for '{tag}'{reload_status}",
        "endpoint_v4": data.endpoint_v4,
        "endpoint_v6": data.endpoint_v6
    }


@app.post("/api/egress/warp/endpoints/test")
async def api_test_warp_endpoints(data: WarpEndpointsTest):
    """测试 WARP Endpoint 延迟和可用性"""
    from warp_endpoint_optimizer import optimize_endpoints, test_specific_endpoints

    try:
        if data.endpoints:
            # 测试指定的 endpoints
            results = await test_specific_endpoints(data.endpoints)
        else:
            # 随机优选
            results = await optimize_endpoints(
                sample_count=data.sample_count,
                top_n=data.top_n
            )

        return {
            "results": [r.to_dict() for r in results],
            "count": len(results)
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/egress/warp/endpoints/test/stream")
async def api_test_warp_endpoints_stream(data: WarpEndpointsTest):
    """测试 WARP Endpoint 延迟和可用性（SSE 流式进度）"""
    import asyncio
    from warp_endpoint_optimizer import test_endpoint_ping, PROTOCOL_PORTS, get_all_ips
    import random

    async def generate():
        try:
            default_port = PROTOCOL_PORTS.get("masque", 443)

            if data.endpoints:
                # 测试指定的 endpoints
                endpoints_to_test = data.endpoints
            else:
                # 随机采样 IP
                all_ips = get_all_ips()
                sample_ips = random.sample(all_ips, min(data.sample_count, len(all_ips)))
                endpoints_to_test = sample_ips

            total = len(endpoints_to_test)
            yield f"data: {json.dumps({'type': 'start', 'total': total})}\n\n"

            results = []
            # 批量并发测试，但定期发送进度
            batch_size = 5  # 每批测试数量（较小批次=更平滑进度）
            for batch_start in range(0, total, batch_size):
                batch_end = min(batch_start + batch_size, total)
                batch = endpoints_to_test[batch_start:batch_end]

                # 并发测试当前批次
                async def test_one(endpoint):
                    try:
                        if isinstance(endpoint, str) and ":" in endpoint:
                            ip, port_str = endpoint.rsplit(":", 1)
                            port = int(port_str)
                        else:
                            ip = endpoint
                            port = default_port
                        return await test_endpoint_ping(ip, port, 2.0, 3)
                    except Exception:
                        return None

                batch_results = await asyncio.gather(*[test_one(ep) for ep in batch])
                results.extend([r for r in batch_results if r is not None])

                # 发送进度
                yield f"data: {json.dumps({'type': 'progress', 'current': batch_end, 'total': total})}\n\n"

            # 排序并取 top N
            results.sort(key=lambda r: (r.loss_rate, r.latency_ms))
            top_results = results[:data.top_n]

            # 发送最终结果
            yield f"data: {json.dumps({'type': 'done', 'results': [r.to_dict() for r in top_results], 'count': len(top_results)})}\n\n"

        except Exception as e:
            yield f"data: {json.dumps({'type': 'error', 'message': str(e)})}\n\n"

    return StreamingResponse(
        generate(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no"
        }
    )


# ============ Outbound Groups APIs (ECMP 负载均衡) ============

class OutboundGroupCreate(BaseModel):
    """出口组创建请求"""
    tag: str = Field(..., min_length=1, max_length=30, pattern=r'^[a-zA-Z0-9_-]+$')
    description: str = ""
    type: str = Field(..., pattern=r'^(loadbalance|failover)$')
    members: List[str] = Field(..., min_length=2, max_length=10)
    weights: Optional[Dict[str, int]] = None
    health_check_url: str = "http://www.gstatic.com/generate_204"
    health_check_interval: int = Field(60, ge=10, le=3600)
    health_check_timeout: int = Field(5, ge=1, le=30)


class OutboundGroupUpdate(BaseModel):
    """出口组更新请求"""
    description: Optional[str] = None
    members: Optional[List[str]] = Field(None, min_length=2, max_length=10)
    weights: Optional[Dict[str, int]] = None
    health_check_url: Optional[str] = None
    health_check_interval: Optional[int] = Field(None, ge=10, le=3600)
    health_check_timeout: Optional[int] = Field(None, ge=1, le=30)
    enabled: Optional[bool] = None


def _sync_ecmp_for_group(group: Dict) -> str:
    """同步单个出口组的 ECMP 路由

    Returns:
        状态消息
    """
    try:
        from ecmp_manager import sync_group
        db = _get_db()
        if sync_group(db, group):
            return ", ecmp synced"
        else:
            return ", ecmp sync failed"
    except ImportError:
        return ", ecmp_manager not available"
    except Exception as e:
        print(f"[api] ECMP sync failed: {e}")
        return f", ecmp sync failed: {e}"


def _teardown_ecmp_for_group(tag: str) -> str:
    """删除出口组的 ECMP 路由

    Returns:
        状态消息
    """
    try:
        from ecmp_manager import teardown_group
        db = _get_db()
        if teardown_group(db, tag):
            return ", ecmp removed"
        else:
            return ", ecmp removal failed"
    except ImportError:
        return ", ecmp_manager not available"
    except Exception as e:
        print(f"[api] ECMP teardown failed: {e}")
        return f", ecmp teardown failed: {e}"


def _sync_all_ecmp_groups() -> str:
    """同步所有出口组的 ECMP 路由和 SNAT 规则

    当 WireGuard 出口重新连接后，peer_ip 可能改变，需要更新 SNAT 规则。

    Returns:
        状态消息
    """
    try:
        from ecmp_manager import sync_all_groups
        db = _get_db()
        results = sync_all_groups(db)
        success_count = sum(1 for v in results.values() if v)
        total_count = len(results)
        if total_count == 0:
            return ""
        if success_count == total_count:
            return f", {total_count} ecmp group(s) synced"
        else:
            return f", {success_count}/{total_count} ecmp group(s) synced"
    except ImportError:
        return ""
    except Exception as e:
        print(f"[api] ECMP sync all failed: {e}")
        return f", ecmp sync failed: {e}"


@app.get("/api/outbound-groups")
def api_list_outbound_groups(enabled_only: bool = False):
    """列出所有出口组"""
    db = _get_db()
    groups = db.get_outbound_groups(enabled_only)

    # 获取健康状态
    try:
        from health_checker import get_health_status
        health_status = get_health_status()
    except ImportError:
        health_status = {}

    # 附加健康状态到每个组
    for group in groups:
        group_tag = group.get("tag")
        if group_tag in health_status:
            group["health_status"] = health_status[group_tag]
        else:
            group["health_status"] = {}

    return {"groups": groups}


@app.get("/api/outbound-groups/available-members")
def api_get_available_members():
    """获取可用的出口成员列表（用于创建组时选择）

    只返回支持 ECMP 负载均衡的出口类型（有内核接口的）：
    - PIA WireGuard profiles
    - Custom WireGuard egress
    - WARP WireGuard egress (protocol == "wireguard")
    - Direct egress (with bind_interface)
    - OpenVPN egress (使用 TUN 设备直接绑定)

    不支持 ECMP 的类型（使用 SOCKS 代理）：
    - V2Ray egress (通过 SOCKS5 桥接)
    - WARP MASQUE (通过 SOCKS5 代理)
    """
    db = _get_db()

    members = []

    # PIA profiles (WireGuard)
    try:
        pia_profiles = db.get_pia_profiles(enabled_only=True)
        for p in pia_profiles:
            members.append({
                "tag": p.get("name"),
                "type": "pia",
                "description": p.get("description") or p.get("name"),
            })
    except Exception as e:
        print(f"WARNING: Failed to get PIA profiles: {e}")

    # Custom egress (WireGuard)
    try:
        custom_list = db.get_custom_egress_list()
        for e in custom_list:
            members.append({
                "tag": e.get("tag"),
                "type": "wireguard",
                "description": e.get("description", e.get("tag")),
            })
    except Exception as e:
        print(f"WARNING: Failed to get custom egress: {e}")

    # Direct egress (只包含有 bind_interface 的)
    try:
        direct_list = db.get_direct_egress_list()
        for e in direct_list:
            # 只有绑定了接口的 Direct egress 才能参与 ECMP
            if e.get("bind_interface"):
                members.append({
                    "tag": e.get("tag"),
                    "type": "direct",
                    "description": e.get("description", e.get("tag")),
                })
    except Exception as e:
        print(f"WARNING: Failed to get direct egress: {e}")

    # WARP egress (只包含 WireGuard 协议的)
    try:
        warp_list = db.get_warp_egress_list()
        for e in warp_list:
            # 只有 WireGuard 协议的 WARP 才有内核接口，才能参与 ECMP
            if e.get("protocol") == "wireguard":
                members.append({
                    "tag": e.get("tag"),
                    "type": "warp",
                    "description": e.get("description", e.get("tag")),
                })
    except Exception as e:
        print(f"WARNING: Failed to get WARP egress: {e}")

    # OpenVPN egress (使用 TUN 设备直接绑定)
    try:
        openvpn_list = db.get_openvpn_egress_list(enabled_only=True)
        for e in openvpn_list:
            # 只有已分配 tun_device 的 OpenVPN 才能参与 ECMP
            if e.get("tun_device"):
                members.append({
                    "tag": e.get("tag"),
                    "type": "openvpn",
                    "description": e.get("description") or e.get("tag"),
                })
    except Exception as e:
        print(f"WARNING: Failed to get OpenVPN egress: {e}")

    # 注意：以下类型不支持 ECMP，不列出
    # - V2Ray egress (SOCKS5 桥接)
    # - WARP MASQUE (SOCKS5 代理)
    # - builtin "direct" (没有特定接口)

    return {"members": members}


@app.get("/api/outbound-groups/{tag}")
def api_get_outbound_group(tag: str):
    """获取单个出口组详情"""
    db = _get_db()
    group = db.get_outbound_group(tag)
    if not group:
        raise HTTPException(status_code=404, detail=f"Outbound group '{tag}' not found")

    # 获取健康状态
    try:
        from health_checker import get_health_status
        health_status = get_health_status(tag)
        group["health_status"] = health_status.get(tag, {})
    except ImportError:
        group["health_status"] = {}

    return group


@app.post("/api/outbound-groups")
def api_create_outbound_group(data: OutboundGroupCreate):
    """创建出口组"""
    db = _get_db()

    # 1. 验证 tag 唯一性（跨所有出口类型）
    if db.tag_exists_in_any_egress(data.tag):
        raise HTTPException(status_code=400, detail=f"Tag '{data.tag}' is already used by another egress")

    # 2. 验证成员有效性
    valid, error, invalid = db.validate_group_members(data.members)
    if not valid:
        raise HTTPException(status_code=400, detail=f"Invalid members: {', '.join(invalid)}")

    # 3. 检测循环引用
    has_cycle, path = db.check_circular_reference(data.tag, data.members)
    if has_cycle:
        raise HTTPException(status_code=400, detail=f"Circular reference detected: {' → '.join(path)}")

    # 4. 验证权重配置
    if data.weights:
        for member, weight in data.weights.items():
            if member not in data.members:
                raise HTTPException(status_code=400, detail=f"Weight config for '{member}' not in member list")
            if weight < 1 or weight > 100:
                raise HTTPException(status_code=400, detail="Weight must be between 1 and 100")

    # 5. 创建组
    try:
        group_id = db.add_outbound_group(
            tag=data.tag,
            description=data.description,
            group_type=data.type,
            members=data.members,
            weights=data.weights,
            health_check_url=data.health_check_url,
            health_check_interval=data.health_check_interval,
            health_check_timeout=data.health_check_timeout
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to create outbound group: {str(e)}")

    # 6. 获取创建的组
    group = db.get_outbound_group(data.tag)

    # 7. 同步 ECMP 路由
    ecmp_status = _sync_ecmp_for_group(group)

    # 8. 重新生成 sing-box 配置并 reload
    reload_status = ""
    try:
        _regenerate_and_reload()
        reload_status = ", config reloaded"
    except Exception as exc:
        print(f"[api] Reload failed: {exc}")
        reload_status = f", reload failed: {exc}"

    return {
        "success": True,
        "group": group,
        "message": f"Outbound group '{data.tag}' created{ecmp_status}{reload_status}"
    }


@app.put("/api/outbound-groups/{tag}")
def api_update_outbound_group(tag: str, data: OutboundGroupUpdate):
    """更新出口组"""
    db = _get_db()

    # 检查组是否存在
    existing = db.get_outbound_group(tag)
    if not existing:
        raise HTTPException(status_code=404, detail=f"Outbound group '{tag}' not found")

    # 如果更新成员，需要验证
    if data.members is not None:
        # 验证成员有效性
        valid, error, invalid = db.validate_group_members(data.members, exclude_tag=tag)
        if not valid:
            raise HTTPException(status_code=400, detail=f"Invalid members: {', '.join(invalid)}")

        # 检测循环引用
        has_cycle, path = db.check_circular_reference(tag, data.members)
        if has_cycle:
            raise HTTPException(status_code=400, detail=f"Circular reference detected: {' → '.join(path)}")

    # 验证权重配置
    # existing.members 已经被 get_outbound_group() 解析为 list，不需要 json.loads
    members_to_check = data.members if data.members is not None else existing.get("members", [])
    if data.weights:
        for member, weight in data.weights.items():
            if member not in members_to_check:
                raise HTTPException(status_code=400, detail=f"Weight config for '{member}' not in member list")
            if weight < 1 or weight > 100:
                raise HTTPException(status_code=400, detail="Weight must be between 1 and 100")

    # 构建更新参数
    update_kwargs = {}
    if data.description is not None:
        update_kwargs["description"] = data.description
    if data.members is not None:
        update_kwargs["members"] = data.members
    if data.weights is not None:
        update_kwargs["weights"] = data.weights
    if data.health_check_url is not None:
        update_kwargs["health_check_url"] = data.health_check_url
    if data.health_check_interval is not None:
        update_kwargs["health_check_interval"] = data.health_check_interval
    if data.health_check_timeout is not None:
        update_kwargs["health_check_timeout"] = data.health_check_timeout
    if data.enabled is not None:
        update_kwargs["enabled"] = data.enabled

    # 更新数据库
    try:
        db.update_outbound_group(tag, **update_kwargs)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to update outbound group: {str(e)}")

    # 获取更新后的组
    group = db.get_outbound_group(tag)

    # 同步 ECMP 路由
    ecmp_status = _sync_ecmp_for_group(group)

    # 重新生成 sing-box 配置并 reload
    reload_status = ""
    try:
        _regenerate_and_reload()
        reload_status = ", config reloaded"
    except Exception as exc:
        print(f"[api] Reload failed: {exc}")
        reload_status = f", reload failed: {exc}"

    return {
        "success": True,
        "group": group,
        "message": f"Outbound group '{tag}' updated{ecmp_status}{reload_status}"
    }


@app.delete("/api/outbound-groups/{tag}")
def api_delete_outbound_group(tag: str):
    """删除出口组"""
    db = _get_db()

    # 检查组是否存在
    if not db.get_outbound_group(tag):
        raise HTTPException(status_code=404, detail=f"Outbound group '{tag}' not found")

    # 先删除 ECMP 路由
    ecmp_status = _teardown_ecmp_for_group(tag)

    # 删除数据库记录
    db.delete_outbound_group(tag)

    # 重新生成 sing-box 配置并 reload
    reload_status = ""
    try:
        _regenerate_and_reload()
        reload_status = ", config reloaded"
    except Exception as exc:
        print(f"[api] Reload failed: {exc}")
        reload_status = f", reload failed: {exc}"

    return {
        "success": True,
        "message": f"Outbound group '{tag}' deleted{ecmp_status}{reload_status}"
    }


@app.post("/api/outbound-groups/{tag}/health-check")
def api_trigger_group_health_check(tag: str):
    """立即触发出口组的健康检查"""
    db = _get_db()

    # 检查组是否存在
    group = db.get_outbound_group(tag)
    if not group:
        raise HTTPException(status_code=404, detail=f"Outbound group '{tag}' not found")

    try:
        from health_checker import check_and_update_group
        member_status = check_and_update_group(db, group)
        return {
            "success": True,
            "tag": tag,
            "health_status": member_status
        }
    except ImportError:
        raise HTTPException(status_code=500, detail="Health checker not available")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Health check failed: {str(e)}")


# ============ V2Ray Inbound APIs ============

@app.get("/api/ingress/v2ray")
def api_get_v2ray_inbound():
    """获取 V2Ray 入口配置和用户列表"""
    db = _get_db()

    config = db.get_v2ray_inbound_config()
    users = db.get_v2ray_users(enabled_only=False)

    # 隐藏用户密码
    for user in users:
        if user.get("password"):
            user["password"] = "***"

    # 解析 JSON 字段
    if config:
        if config.get("reality_short_ids"):
            try:
                config["reality_short_ids"] = json.loads(config["reality_short_ids"])
            except (json.JSONDecodeError, TypeError):
                pass
        if config.get("reality_server_names"):
            try:
                config["reality_server_names"] = json.loads(config["reality_server_names"])
            except (json.JSONDecodeError, TypeError):
                pass

    return {
        "config": config or {
            "protocol": "vless",
            "listen_address": "0.0.0.0",
            "listen_port": 443,
            "tls_enabled": 1,
            "xtls_vision_enabled": 0,
            "reality_enabled": 0,
            "reality_private_key": None,
            "reality_public_key": None,
            "reality_short_ids": None,
            "reality_dest": None,
            "reality_server_names": None,
            "transport_type": "tcp",
            "tun_device": "xray-tun0",
            "tun_subnet": "10.24.0.0/24",
            "enabled": 0,
        },
        "users": users,
    }


@app.put("/api/ingress/v2ray")
def api_update_v2ray_inbound(payload: V2RayInboundUpdateRequest):
    """更新 V2Ray 入口配置（使用 Xray + TUN + TPROXY 架构）- VLESS only"""
    db = _get_db()

    # 验证协议 - [Xray-lite] 仅支持 VLESS
    if payload.protocol != "vless":
        raise HTTPException(
            status_code=400,
            detail=f"Invalid protocol: {payload.protocol}. Only 'vless' is supported in Xray-lite. "
            "VMess and Trojan have been removed. See docs/VMESS_TROJAN_MIGRATION.md"
        )

    # Note: XTLS-Vision and REALITY checks removed - they are implicitly VLESS-only now

    # REALITY 需要密钥和目标服务器
    if payload.reality_enabled:
        if not payload.reality_private_key or not payload.reality_public_key:
            raise HTTPException(status_code=400, detail="REALITY requires private and public keys")
        if not payload.reality_dest:
            raise HTTPException(status_code=400, detail="REALITY requires destination server")
        if not payload.reality_server_names:
            raise HTTPException(status_code=400, detail="REALITY requires server names (SNI)")

    # 构建 transport_config JSON
    transport_config_json = json.dumps(payload.transport_config) if payload.transport_config else None

    # 构建 REALITY 字段 JSON
    reality_short_ids_json = json.dumps(payload.reality_short_ids) if payload.reality_short_ids else None
    reality_server_names_json = json.dumps(payload.reality_server_names) if payload.reality_server_names else None

    # 更新配置
    db.set_v2ray_inbound_config(
        protocol=payload.protocol,
        listen_address=payload.listen_address,
        listen_port=payload.listen_port,
        tls_enabled=1 if payload.tls_enabled else 0,
        tls_cert_path=payload.tls_cert_path,
        tls_key_path=payload.tls_key_path,
        tls_cert_content=payload.tls_cert_content,
        tls_key_content=payload.tls_key_content,
        xtls_vision_enabled=1 if payload.xtls_vision_enabled else 0,
        reality_enabled=1 if payload.reality_enabled else 0,
        reality_private_key=payload.reality_private_key,
        reality_public_key=payload.reality_public_key,
        reality_short_ids=reality_short_ids_json,
        reality_dest=payload.reality_dest,
        reality_server_names=reality_server_names_json,
        transport_type=payload.transport_type,
        transport_config=transport_config_json,
        fallback_server=payload.fallback_server,
        fallback_port=payload.fallback_port,
        tun_device=payload.tun_device,
        tun_subnet=payload.tun_subnet,
        enabled=1 if payload.enabled else 0,
    )

    # 重新渲染配置并重载
    reload_status = ""
    try:
        _regenerate_and_reload()
        reload_status = ", config reloaded"
    except Exception as exc:
        print(f"[api] Reload failed: {exc}")
        reload_status = f", reload failed: {exc}"

    # 如果启用了 V2Ray 入口，需要重启 Xray 进程
    if payload.enabled:
        try:
            import subprocess
            subprocess.run(
                ["python3", "/usr/local/bin/xray_manager.py", "reload"],
                capture_output=True, timeout=10
            )
            reload_status += ", Xray reloaded"
        except Exception as exc:
            print(f"[api] Xray reload failed: {exc}")
            reload_status += f", Xray reload failed: {exc}"

    return {"message": f"V2Ray inbound config updated{reload_status}"}


@app.get("/api/ingress/v2ray/users/online")
def api_get_v2ray_users_online():
    """获取 V2Ray 用户在线状态

    返回每个用户的在线状态，基于流量活动检测。
    如果用户在过去 60 秒内有流量变化，则认为在线。

    Returns:
        {email: {"online": bool, "last_seen": timestamp, "upload": bytes, "download": bytes}}
    """
    db = _get_db()
    users = db.get_v2ray_users(enabled_only=True)

    now = time.time()
    result = {}

    with _v2ray_user_activity_lock:
        for user in users:
            # 用户的 email 字段用于统计标识（如果为空则使用 name）
            email = user.get("email") or user.get("name") or "user"
            activity = _v2ray_user_activity.get(email)

            if activity:
                last_seen = activity.get("last_seen", 0)
                online = (now - last_seen) < _V2RAY_USER_ONLINE_TIMEOUT
                result[email] = {
                    "online": online,
                    "last_seen": last_seen,
                    "upload": activity.get("upload", 0),
                    "download": activity.get("download", 0),
                }
            else:
                # 用户未有任何流量记录
                result[email] = {
                    "online": False,
                    "last_seen": 0,
                    "upload": 0,
                    "download": 0,
                }

    return result


@app.post("/api/ingress/v2ray/users")
def api_add_v2ray_user(payload: V2RayUserCreateRequest):
    """添加 V2Ray 用户"""
    import uuid as uuid_module

    db = _get_db()

    # 检查用户名是否已存在
    if db.get_v2ray_user_by_name(payload.name):
        raise HTTPException(status_code=400, detail=f"User '{payload.name}' already exists")

    # 如果未提供 UUID，自动生成
    user_uuid = payload.uuid or str(uuid_module.uuid4())

    # 添加用户
    user_id = db.add_v2ray_user(
        name=payload.name,
        email=payload.email,
        uuid=user_uuid,
        password=payload.password,
        alter_id=payload.alter_id,
        flow=payload.flow,
    )

    # 重新渲染配置并重载
    reload_status = ""
    try:
        _regenerate_and_reload()
        reload_status = ", config reloaded"
    except Exception as exc:
        print(f"[api] Reload failed: {exc}")
        reload_status = f", reload failed: {exc}"

    return {
        "message": f"V2Ray user '{payload.name}' created{reload_status}",
        "id": user_id,
        "uuid": user_uuid,
    }


@app.put("/api/ingress/v2ray/users/{user_id}")
def api_update_v2ray_user(user_id: int, payload: V2RayUserUpdateRequest):
    """更新 V2Ray 用户"""
    db = _get_db()

    # 检查用户是否存在
    user = db.get_v2ray_user(user_id)
    if not user:
        raise HTTPException(status_code=404, detail=f"User ID {user_id} not found")

    # 构建更新字段
    updates = {}
    for field in ["email", "uuid", "password", "alter_id", "flow", "enabled"]:
        value = getattr(payload, field, None)
        if value is not None:
            updates[field] = value

    if updates:
        db.update_v2ray_user(user_id, **updates)

    # 重新渲染配置并重载
    reload_status = ""
    try:
        _regenerate_and_reload()
        reload_status = ", config reloaded"
    except Exception as exc:
        print(f"[api] Reload failed: {exc}")
        reload_status = f", reload failed: {exc}"

    return {"message": f"V2Ray user updated{reload_status}"}


@app.delete("/api/ingress/v2ray/users/{user_id}")
def api_delete_v2ray_user(user_id: int):
    """删除 V2Ray 用户"""
    db = _get_db()

    # 检查用户是否存在
    user = db.get_v2ray_user(user_id)
    if not user:
        raise HTTPException(status_code=404, detail=f"User ID {user_id} not found")

    # 删除用户
    db.delete_v2ray_user(user_id)

    # 重新渲染配置并重载
    reload_status = ""
    try:
        _regenerate_and_reload()
        reload_status = ", config reloaded"
    except Exception as exc:
        print(f"[api] Reload failed: {exc}")
        reload_status = f", reload failed: {exc}"

    return {"message": f"V2Ray user deleted{reload_status}"}


def _parse_reality_short_id(short_ids_raw: str) -> str:
    """Parse REALITY short_ids from database (may be JSON array or comma-separated)"""
    if not short_ids_raw:
        return ""
    try:
        # Try JSON array first
        short_ids = json.loads(short_ids_raw)
        if isinstance(short_ids, list) and len(short_ids) > 0:
            return str(short_ids[0]).strip()
    except (json.JSONDecodeError, TypeError):
        pass
    # Fallback to comma-separated
    return short_ids_raw.split(",")[0].strip()


@app.get("/api/ingress/v2ray/users/{user_id}/share")
def api_get_v2ray_user_share_uri(user_id: int):
    """获取 V2Ray 用户的分享链接"""
    if not HAS_V2RAY_PARSER:
        raise HTTPException(status_code=500, detail="V2Ray URI generator not available")

    db = _get_db()

    # 获取用户
    user = db.get_v2ray_user(user_id)
    if not user:
        raise HTTPException(status_code=404, detail=f"User ID {user_id} not found")

    # 获取入口配置
    config = db.get_v2ray_inbound_config()
    if not config:
        raise HTTPException(status_code=400, detail="V2Ray inbound not configured")
    if not config.get("enabled"):
        raise HTTPException(status_code=400, detail="V2Ray inbound is disabled")

    # 获取服务器公网地址
    server_settings = db.get_all_settings() or {}
    public_endpoint = server_settings.get("public_endpoint", "")
    if not public_endpoint:
        # 尝试检测
        detected_ip = _detect_public_ip()
        public_endpoint = detected_ip or "your-server-ip"

    protocol = config.get("protocol", "vless")
    port = config.get("listen_port", 443)
    transport_type = config.get("transport_type", "tcp")
    transport_config_raw = config.get("transport_config")
    transport_config = json.loads(transport_config_raw) if transport_config_raw else {}
    tls_enabled = config.get("tls_enabled", 1)
    tls_sni = config.get("tls_sni") or public_endpoint
    reality_enabled = config.get("reality_enabled", 0)

    remark = user.get("name", f"user-{user_id}")

    # 对于 REALITY，SNI 应该是伪装目标服务器名称
    if reality_enabled:
        reality_server_names = config.get("reality_server_names")
        if reality_server_names:
            try:
                names = json.loads(reality_server_names)
                if isinstance(names, list) and len(names) > 0:
                    tls_sni = names[0]
            except (json.JSONDecodeError, TypeError):
                pass

    # 构建分享配置字典
    share_config = {
        "server": public_endpoint,
        "server_port": port,
        "description": remark,
        "transport_type": transport_type,
        "transport_config": transport_config,
        "tls_enabled": tls_enabled,
        "tls_sni": tls_sni,
        "reality_enabled": reality_enabled,
        "reality_public_key": config.get("reality_public_key", ""),
        "reality_short_id": _parse_reality_short_id(config.get("reality_short_ids")),
    }

    # REALITY 需要指纹伪装
    if reality_enabled:
        share_config["tls_fingerprint"] = "chrome"

    # XTLS-Vision flow 从服务端配置获取（仅 TCP 传输支持）
    xtls_vision_enabled = config.get("xtls_vision_enabled", 0)
    if xtls_vision_enabled and transport_type == "tcp":
        server_flow = "xtls-rprx-vision"
    else:
        server_flow = ""

    # 构建分享链接 - [Xray-lite] 仅支持 VLESS
    if protocol == "vmess":
        # [REMOVED in Xray-lite]
        raise HTTPException(
            status_code=400,
            detail="VMess protocol is no longer supported in Xray-lite. "
            "Please migrate to VLESS. See docs/VMESS_TROJAN_MIGRATION.md"
        )
    elif protocol == "vless":
        share_config["uuid"] = user.get("uuid")
        # Flow 从服务端配置获取，不再从用户配置获取
        share_config["flow"] = server_flow
        uri = generate_vless_uri(share_config)
    elif protocol == "trojan":
        # [REMOVED in Xray-lite]
        raise HTTPException(
            status_code=400,
            detail="Trojan protocol is no longer supported in Xray-lite. "
            "Please migrate to VLESS. See docs/VMESS_TROJAN_MIGRATION.md"
        )
    else:
        raise HTTPException(status_code=400, detail=f"Unsupported protocol: {protocol}. Only 'vless' is supported.")

    return {"uri": uri, "protocol": protocol, "user": user.get("name")}


@app.get("/api/ingress/v2ray/users/{user_id}/qrcode")
def api_get_v2ray_user_qrcode(user_id: int):
    """获取 V2Ray 用户分享链接的二维码"""
    if not HAS_QRCODE:
        raise HTTPException(status_code=501, detail="QR code feature not available, please install qrcode library")

    # 复用分享链接生成逻辑
    share_result = api_get_v2ray_user_share_uri(user_id)
    uri = share_result["uri"]

    # 生成二维码
    qr = qrcode.QRCode(version=1, box_size=10, border=4)
    qr.add_data(uri)
    qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color="white")

    # 转换为 PNG 字节
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    buf.seek(0)

    return Response(content=buf.getvalue(), media_type="image/png")


# ============ Xray Control APIs ============

@app.get("/api/ingress/v2ray/xray/status")
def api_get_xray_status():
    """获取 Xray 进程状态"""
    import subprocess
    try:
        result = subprocess.run(
            ["python3", "/usr/local/bin/xray_manager.py", "status"],
            capture_output=True, text=True, timeout=5
        )
        if result.returncode == 0:
            status = json.loads(result.stdout)
            # 转换为前端期望的格式
            # 获取 V2Ray 配置以补充 REALITY/XTLS 状态
            _db = _get_db()
            v2ray_config = _db.get_v2ray_inbound_config()
            config = v2ray_config.get("config", {}) if v2ray_config else {}
            return {
                "running": status.get("status") == "running",
                "enabled": config.get("enabled", 0) == 1,
                "pid": status.get("pid"),
                "tun_device": status.get("tun_device"),
                "tun_configured": bool(status.get("tun_device")),
                "reality_enabled": config.get("reality_enabled", 0) == 1,
                "xtls_vision_enabled": config.get("xtls_vision_enabled", 0) == 1,
                "listen_port": status.get("listen_port"),
            }
        else:
            return {"running": False, "enabled": False, "tun_configured": False,
                    "reality_enabled": False, "xtls_vision_enabled": False,
                    "message": result.stderr}
    except subprocess.TimeoutExpired:
        return {"running": False, "enabled": False, "tun_configured": False,
                "reality_enabled": False, "xtls_vision_enabled": False,
                "message": "Timeout"}
    except Exception as e:
        return {"running": False, "enabled": False, "tun_configured": False,
                "reality_enabled": False, "xtls_vision_enabled": False,
                "message": str(e)}


@app.post("/api/ingress/v2ray/xray/restart")
def api_restart_xray():
    """重启 Xray 进程"""
    import subprocess
    try:
        # 先停止
        subprocess.run(
            ["python3", "/usr/local/bin/xray_manager.py", "stop"],
            capture_output=True, timeout=10
        )
        # 再启动
        result = subprocess.run(
            ["python3", "/usr/local/bin/xray_manager.py", "start"],
            capture_output=True, text=True, timeout=10
        )
        if result.returncode == 0:
            return {"message": "Xray restarted successfully"}
        else:
            raise HTTPException(status_code=500, detail=f"Failed to start Xray: {result.stderr}")
    except subprocess.TimeoutExpired:
        raise HTTPException(status_code=500, detail="Xray restart timeout")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/ingress/v2ray/xray/reload")
def api_reload_xray():
    """重载 Xray 配置"""
    import subprocess
    try:
        result = subprocess.run(
            ["python3", "/usr/local/bin/xray_manager.py", "reload"],
            capture_output=True, text=True, timeout=10
        )
        if result.returncode == 0:
            return {"message": "Xray config reloaded successfully"}
        else:
            raise HTTPException(status_code=500, detail=f"Failed to reload Xray: {result.stderr}")
    except subprocess.TimeoutExpired:
        raise HTTPException(status_code=500, detail="Xray reload timeout")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


def _generate_xray_reality_keys() -> Optional[Dict[str, str]]:
    """生成 Xray REALITY 密钥对（内部辅助函数）

    Returns:
        成功返回 {"private_key": str, "public_key": str, "short_id": str}
        失败返回 None
    """
    import subprocess
    try:
        result = subprocess.run(
            ["python3", "/usr/local/bin/xray_manager.py", "generate-keys"],
            capture_output=True, text=True, timeout=10
        )
        if result.returncode == 0:
            return json.loads(result.stdout)
        else:
            logging.error(f"生成 REALITY 密钥失败: {result.stderr}")
            return None
    except subprocess.TimeoutExpired:
        logging.error("生成 REALITY 密钥超时")
        return None
    except Exception as e:
        logging.error(f"生成 REALITY 密钥异常: {e}")
        return None


@app.post("/api/ingress/v2ray/reality/generate-keys")
def api_generate_reality_keys():
    """生成 REALITY 密钥对"""
    keys = _generate_xray_reality_keys()
    if keys:
        return keys
    else:
        raise HTTPException(status_code=500, detail="Failed to generate REALITY keys")


# ============ Xray Egress Control APIs ============

@app.get("/api/egress/xray/status")
def api_get_xray_egress_status():
    """获取 Xray 出站进程状态"""
    import subprocess
    try:
        result = subprocess.run(
            ["python3", "/usr/local/bin/xray_egress_manager.py", "status"],
            capture_output=True, text=True, timeout=5
        )
        if result.returncode == 0:
            status = json.loads(result.stdout)
            return {
                "running": status.get("status") == "running",
                "pid": status.get("pid"),
                "egress_count": status.get("egress_count", 0),
                "socks_ports": status.get("socks_ports", [])
            }
        else:
            return {"running": False, "egress_count": 0, "socks_ports": [],
                    "message": result.stderr}
    except subprocess.TimeoutExpired:
        return {"running": False, "egress_count": 0, "socks_ports": [],
                "message": "Timeout"}
    except Exception as e:
        return {"running": False, "egress_count": 0, "socks_ports": [],
                "message": str(e)}


@app.post("/api/egress/xray/restart")
def api_restart_xray_egress():
    """重启 Xray 出站进程"""
    import subprocess
    try:
        # 先停止
        subprocess.run(
            ["python3", "/usr/local/bin/xray_egress_manager.py", "stop"],
            capture_output=True, timeout=10
        )
        # 再启动
        result = subprocess.run(
            ["python3", "/usr/local/bin/xray_egress_manager.py", "start"],
            capture_output=True, text=True, timeout=10
        )
        if result.returncode == 0:
            return {"message": "Xray egress restarted successfully"}
        else:
            raise HTTPException(status_code=500, detail=f"Failed to start Xray egress: {result.stderr}")
    except subprocess.TimeoutExpired:
        raise HTTPException(status_code=500, detail="Xray egress restart timeout")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/egress/xray/reload")
def api_reload_xray_egress():
    """重载 Xray 出站配置"""
    import subprocess
    try:
        result = subprocess.run(
            ["python3", "/usr/local/bin/xray_egress_manager.py", "reload"],
            capture_output=True, text=True, timeout=10
        )
        if result.returncode == 0:
            return {"message": "Xray egress config reloaded successfully"}
        else:
            raise HTTPException(status_code=500, detail=f"Failed to reload Xray egress: {result.stderr}")
    except subprocess.TimeoutExpired:
        raise HTTPException(status_code=500, detail="Xray egress reload timeout")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# ============ Egress Connection Test API ============

@app.get("/api/test/egress/{tag}")
def api_test_egress_connection(tag: str, timeout: int = 5000):
    """测试出口连接延迟

    根据出口类型选择不同的测试方法:
    - direct/direct-*: 使用 subprocess curl 直接测试 (绕过 sing-box 路由)
    - block/adblock: 不可测试
    - WireGuard endpoints: 使用 clash_api 测试
    - SOCKS outbounds: 使用 curl + SOCKS 代理测试
    """
    import urllib.request
    import urllib.error
    import urllib.parse

    test_url = "http://cp.cloudflare.com/"  # Cloudflare 204 测试 (国内可访问)
    timeout_sec = timeout / 1000

    # 首先获取出口类型
    proxy_type = None
    try:
        clash_proxy_url = f"http://127.0.0.1:{DEFAULT_CLASH_API_PORT}/proxies/{urllib.parse.quote(tag)}"
        with urllib.request.urlopen(clash_proxy_url, timeout=5) as resp:
            proxy_info = json.loads(resp.read().decode())
            proxy_type = proxy_info.get("type", "").lower()
    except Exception:
        pass

    # block 类型不可测试
    if tag in ("block", "adblock") or proxy_type == "reject":
        return {"success": False, "delay": -1, "message": "Block egress, cannot test"}

    # direct 类型使用 subprocess curl 直接测试
    if tag == "direct" or tag.startswith("direct-") or proxy_type == "direct":
        return _test_direct_connection(tag, test_url, timeout_sec)

    # SOCKS 类型：尝试获取端口并使用 curl + SOCKS 代理
    if proxy_type == "socks":
        return _test_socks_connection(tag, test_url, timeout_sec)

    # WireGuard 和其他类型：先检查活跃流量，再尝试 clash_api
    return _test_wireguard_endpoint(tag, test_url, timeout)


def _test_direct_connection(tag: str, test_url: str, timeout_sec: float) -> dict:
    """使用 subprocess curl 测试 direct 类型出口"""
    try:
        # 构建 curl 命令
        curl_cmd = [
            "curl", "-s", "-o", "/dev/null",
            "-w", "%{http_code}|%{time_total}",
            "--max-time", str(int(timeout_sec + 1)),
            test_url
        ]

        # 如果是 direct-* 类型，尝试获取绑定配置
        # Phase 11-Fix.U: 修复方法名 get_direct_egress_by_tag -> get_direct_egress
        if tag.startswith("direct-") and HAS_DATABASE:
            db = _get_db()
            direct_egress = db.get_direct_egress(tag)
            if direct_egress:
                if direct_egress.get("bind_interface"):
                    curl_cmd.extend(["--interface", direct_egress["bind_interface"]])
                elif direct_egress.get("inet4_bind_address"):
                    curl_cmd.extend(["--interface", direct_egress["inet4_bind_address"]])

        start_time = time.time()
        result = subprocess.run(curl_cmd, capture_output=True, text=True, timeout=timeout_sec + 2)

        if result.returncode == 0:
            parts = result.stdout.strip().split("|")
            if len(parts) == 2:
                http_code = parts[0]
                time_total = float(parts[1])
                delay_ms = int(time_total * 1000)

                if http_code in ("200", "204", "301", "302"):
                    return {"success": True, "delay": delay_ms, "message": f"{delay_ms}ms"}
                else:
                    return {"success": False, "delay": -1, "message": f"HTTP {http_code}"}

        return {"success": False, "delay": -1, "message": "Connection failed"}

    except subprocess.TimeoutExpired:
        return {"success": False, "delay": -1, "message": "连接超时"}
    except Exception as e:
        return {"success": False, "delay": -1, "message": str(e)}


def _test_socks_connection(tag: str, test_url: str, timeout_sec: float) -> dict:
    """使用 curl + SOCKS 代理测试 SOCKS 类型出口（V2Ray、WARP MASQUE）"""
    try:
        # 从数据库获取 SOCKS 端口
        socks_port = None
        if HAS_DATABASE:
            db = _get_db()
            # 检查 OpenVPN（现在使用 TUN 设备，不是 SOCKS）
            openvpn_egress = db.get_openvpn_egress(tag)
            if openvpn_egress and openvpn_egress.get("tun_device"):
                # OpenVPN 使用接口绑定测试
                return _test_interface_connection(openvpn_egress["tun_device"], test_url, timeout_sec)
            # 再检查 WARP（仅 MASQUE 协议使用 SOCKS）
            warp_egress = db.get_warp_egress(tag)
            if warp_egress and warp_egress.get("socks_port"):
                socks_port = warp_egress.get("socks_port")

        if not socks_port:
            # 回退到 clash_api 测试
            return _test_via_clash_api(tag, test_url, int(timeout_sec * 1000))

        # 使用 curl + SOCKS5 代理测试
        curl_cmd = [
            "curl", "-s", "-o", "/dev/null",
            "-w", "%{http_code}|%{time_total}",
            "--max-time", str(int(timeout_sec + 1)),
            "--proxy", f"socks5://127.0.0.1:{socks_port}",
            test_url
        ]

        result = subprocess.run(curl_cmd, capture_output=True, text=True, timeout=timeout_sec + 2)

        if result.returncode == 0:
            parts = result.stdout.strip().split("|")
            if len(parts) == 2:
                http_code = parts[0]
                time_total = float(parts[1])
                delay_ms = int(time_total * 1000)

                if http_code in ("200", "204", "301", "302"):
                    return {"success": True, "delay": delay_ms, "message": f"{delay_ms}ms"}
                else:
                    return {"success": False, "delay": -1, "message": f"HTTP {http_code}"}

        # SOCKS 代理连接失败
        return {"success": False, "delay": -1, "message": "SOCKS proxy not connected"}

    except subprocess.TimeoutExpired:
        return {"success": False, "delay": -1, "message": "Connection timeout"}
    except Exception as e:
        return {"success": False, "delay": -1, "message": str(e)}


def _test_wireguard_endpoint(tag: str, test_url: str, timeout: int) -> dict:
    """测试 WireGuard 端点

    WireGuard 隧道是惰性的，只有流量通过时才会建立连接。
    clash_api 的延迟测试对 WireGuard 端点有时会失败，即使隧道正常工作。

    策略:
    1. 检查是否有活跃流量通过该端点
    2. 如果有活跃流量，认为连接正常
    3. 如果没有活跃流量，尝试 clash_api 延迟测试
    4. 如果延迟测试失败，尝试 ping 服务器 (验证配置是否正确)
    """
    import urllib.request
    import urllib.error
    import urllib.parse

    # 首先检查是否有活跃流量通过该端点
    try:
        with urllib.request.urlopen(f"http://127.0.0.1:{DEFAULT_CLASH_API_PORT}/connections", timeout=3) as resp:
            data = json.loads(resp.read().decode())
            connections = data.get("connections", []) or []

            # 统计通过该端点的活跃连接数和流量
            active_count = 0
            total_download = 0
            total_upload = 0

            for conn in connections:
                chains = conn.get("chains", [])
                # chains 可能是 ["us-stream", "direct"] 或类似格式
                # 检查端点是否在链中
                if tag in chains:
                    active_count += 1
                    total_download += conn.get("download", 0)
                    total_upload += conn.get("upload", 0)

            if active_count > 0:
                # 有活跃流量，认为连接正常
                total_kb = (total_download + total_upload) / 1024
                if total_kb >= 1024:
                    traffic_str = f"{total_kb/1024:.1f}MB"
                else:
                    traffic_str = f"{total_kb:.0f}KB"
                return {
                    "success": True,
                    "delay": 0,  # 无法测量延迟，但确认有流量
                    "message": f"✓ 活跃 ({active_count}连接, {traffic_str})"
                }

    except Exception as e:
        # 无法检查连接，继续尝试延迟测试
        pass

    # 没有活跃流量，尝试 clash_api 延迟测试
    result = _test_via_clash_api(tag, test_url, timeout)

    # 如果延迟测试成功，直接返回
    if result.get("success"):
        return result

    # 延迟测试失败，尝试 ping 服务器作为最后手段
    # 这至少可以验证服务器是否可达
    ping_result = _ping_wireguard_server(tag)
    if ping_result:
        return ping_result

    # 都失败了，返回原始延迟测试结果
    return result


def _ping_wireguard_server(tag: str) -> Optional[dict]:
    """尝试 ping WireGuard 端点的服务器地址

    从 sing-box 配置读取服务器地址并进行 ping 测试。
    成功则返回延迟结果，失败返回 None。
    """
    try:
        # 读取 sing-box 配置获取服务器地址
        config_path = os.environ.get("SING_BOX_CONFIG", "/etc/sing-box/sing-box.json")
        generated_path = config_path.replace(".json", ".generated.json")

        with open(generated_path, "r") as f:
            config = json.load(f)

        # 查找匹配的端点
        server_address = None
        for endpoint in config.get("endpoints", []):
            if endpoint.get("tag") == tag:
                peers = endpoint.get("peers", [])
                if peers:
                    server_address = peers[0].get("address")
                break

        if not server_address:
            return None

        # 使用 ping 测试 (3次，超时3秒)
        result = subprocess.run(
            ["ping", "-c", "3", "-W", "3", server_address],
            capture_output=True,
            text=True,
            timeout=10
        )

        if result.returncode == 0:
            # 解析 ping 输出获取平均延迟
            # 格式: rtt min/avg/max/mdev = 73.457/74.116/74.798/0.547 ms
            import re
            match = re.search(r"rtt.*?=.*?/([\d.]+)/", result.stdout)
            if match:
                avg_ms = int(float(match.group(1)))
                return {
                    "success": True,
                    "delay": avg_ms,
                    "message": f"✓ 服务器可达 ({avg_ms}ms)"
                }
            return {
                "success": True,
                "delay": 0,
                "message": "✓ 服务器可达"
            }

    except Exception:
        pass

    return None


def _test_via_clash_api(tag: str, test_url: str, timeout: int) -> dict:
    """使用 clash_api 测试出口延迟"""
    import urllib.request
    import urllib.error
    import urllib.parse

    try:
        clash_url = f"http://127.0.0.1:{DEFAULT_CLASH_API_PORT}/proxies/{urllib.parse.quote(tag)}/delay?url={urllib.parse.quote(test_url)}&timeout={timeout}"
        with urllib.request.urlopen(clash_url, timeout=timeout/1000 + 2) as resp:
            data = json.loads(resp.read().decode())
            delay = data.get("delay", -1)

        if delay > 0:
            return {"success": True, "delay": delay, "message": f"{delay}ms"}
        else:
            return {"success": False, "delay": -1, "message": "Connection timeout"}

    except urllib.error.HTTPError as e:
        if e.code == 504:
            return {"success": False, "delay": -1, "message": "Connection timeout"}
        elif e.code == 404:
            return {"success": False, "delay": -1, "message": f"Egress '{tag}' not found"}
        else:
            return {"success": False, "delay": -1, "message": f"Test failed (HTTP {e.code})"}
    except urllib.error.URLError:
        return {"success": False, "delay": -1, "message": "sing-box not running"}
    except socket.timeout:
        return {"success": False, "delay": -1, "message": "Connection timeout"}
    except Exception as e:
        return {"success": False, "delay": -1, "message": str(e)}


# ============ Egress Speed Test API ============

def _get_speedtest_socks_port(tag: str) -> Optional[int]:
    """获取 WireGuard 出口的测速 SOCKS 端口

    从 sing-box.generated.json 配置中读取 speedtest-{tag} inbound 的端口
    """
    config_path = os.environ.get("SING_BOX_CONFIG", "/etc/sing-box/sing-box.json")
    generated_path = config_path.replace(".json", ".generated.json")

    try:
        with open(generated_path, "r") as f:
            config = json.load(f)

        for inbound in config.get("inbounds", []):
            if inbound.get("tag") == f"speedtest-{tag}":
                return inbound.get("listen_port")
    except Exception:
        pass

    return None


def _is_openvpn_egress(tag: str) -> bool:
    """检查是否是 OpenVPN 出口"""
    if not HAS_DATABASE:
        return False
    try:
        db = _get_db()
        egress = db.get_openvpn_egress(tag)
        return egress is not None and egress.get("tun_device") is not None
    except Exception:
        return False


def _get_openvpn_tun_device(tag: str) -> Optional[str]:
    """获取 OpenVPN 出口的 TUN 设备名（仅当 TUN 设备存在时返回）"""
    if not HAS_DATABASE:
        return None
    try:
        db = _get_db()
        egress = db.get_openvpn_egress(tag)
        if egress:
            tun_device = egress.get("tun_device")
            if tun_device:
                # 检查 TUN 设备是否存在
                from pathlib import Path
                if Path(f"/sys/class/net/{tun_device}").exists():
                    return tun_device
    except Exception:
        pass
    return None


def _is_warp_egress(tag: str) -> bool:
    """检查是否是 WARP 出口"""
    if not HAS_DATABASE:
        return False
    try:
        db = _get_db()
        egress = db.get_warp_egress(tag)
        return egress is not None
    except Exception:
        return False


def _get_warp_socks_port(tag: str) -> Optional[int]:
    """获取 WARP 出口的 SOCKS 端口（仅当端口正在监听时返回）"""
    if not HAS_DATABASE:
        return None
    try:
        db = _get_db()
        egress = db.get_warp_egress(tag)
        if egress:
            socks_port = egress.get("socks_port")
            if socks_port:
                # 检查端口是否正在监听
                import socket
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                result = sock.connect_ex(("127.0.0.1", socks_port))
                sock.close()
                if result == 0:
                    return socks_port
    except Exception:
        pass
    return None


def _test_speed_download(tag: str, size_mb: int = 10, timeout_sec: float = 30) -> dict:
    """通过下载文件测速

    Args:
        tag: 出口标识
        size_mb: 下载文件大小 (MB)
        timeout_sec: 超时时间 (秒)

    Returns:
        测速结果字典
    """
    test_url = f"https://speed.cloudflare.com/__down?bytes={size_mb * 1024 * 1024}"

    curl_cmd = [
        "curl", "-s", "-o", "/dev/null",
        "-w", "%{speed_download}",  # 输出下载速度 (bytes/sec)
        "--max-time", str(int(timeout_sec)),
    ]

    # 根据出口类型添加代理参数
    proxy_info = ""
    if tag == "direct":
        proxy_info = "直连"
    elif tag.startswith("direct-"):
        # Direct 出口：绑定接口
        # Phase 11-Fix.U: 修复方法名 get_direct_egress_by_tag -> get_direct_egress
        if HAS_DATABASE:
            db = _get_db()
            direct_egress = db.get_direct_egress(tag)
            if direct_egress:
                if direct_egress.get("bind_interface"):
                    curl_cmd.extend(["--interface", direct_egress["bind_interface"]])
                    proxy_info = f"接口 {direct_egress['bind_interface']}"
                elif direct_egress.get("inet4_bind_address"):
                    curl_cmd.extend(["--interface", direct_egress["inet4_bind_address"]])
                    proxy_info = f"IP {direct_egress['inet4_bind_address']}"
    elif _is_openvpn_egress(tag):
        # OpenVPN：使用 TUN 设备直接绑定
        tun_device = _get_openvpn_tun_device(tag)
        if tun_device:
            curl_cmd.extend(["--interface", tun_device])
            proxy_info = f"接口 {tun_device}"
        else:
            return {"success": False, "speed_mbps": 0, "message": "OpenVPN tunnel not connected"}
    elif _is_warp_egress(tag):
        # WARP：根据协议类型选择测试方式
        if HAS_DATABASE:
            db = _get_db()
            warp_egress = db.get_warp_egress(tag)
            if warp_egress and warp_egress.get("protocol") == "wireguard":
                # WireGuard 协议：使用内核接口
                from setup_kernel_wg_egress import get_egress_interface_name
                interface = get_egress_interface_name(tag, egress_type="warp")
                curl_cmd.extend(["--interface", interface])
                proxy_info = f"接口 {interface}"
            else:
                # MASQUE 协议：使用 SOCKS 端口
                socks_port = _get_warp_socks_port(tag)
                if socks_port:
                    curl_cmd.extend(["--proxy", f"socks5://127.0.0.1:{socks_port}"])
                    proxy_info = f"SOCKS5 :{socks_port}"
                else:
                    return {"success": False, "speed_mbps": 0, "message": "WARP not connected"}
        else:
            return {"success": False, "speed_mbps": 0, "message": "Database not available"}
    elif tag in ("block", "adblock"):
        return {"success": False, "speed_mbps": 0, "message": "Block egress, cannot test speed"}
    else:
        # WireGuard/PIA：使用测速专用 SOCKS 端口
        socks_port = _get_speedtest_socks_port(tag)
        if socks_port:
            curl_cmd.extend(["--proxy", f"socks5://127.0.0.1:{socks_port}"])
            proxy_info = f"SOCKS5 :{socks_port}"
        else:
            return {"success": False, "speed_mbps": 0, "message": "Speed test port not configured, restart container"}

    curl_cmd.append(test_url)

    try:
        start_time = time.time()
        result = subprocess.run(curl_cmd, capture_output=True, text=True, timeout=timeout_sec + 5)
        elapsed = time.time() - start_time

        if result.returncode == 0 and result.stdout.strip():
            try:
                bytes_per_sec = float(result.stdout.strip())
                if bytes_per_sec > 0:
                    mbps = (bytes_per_sec * 8) / 1_000_000
                    return {
                        "success": True,
                        "speed_mbps": round(mbps, 2),
                        "download_bytes": size_mb * 1024 * 1024,
                        "duration_sec": round(elapsed, 2),
                        "message": f"{mbps:.1f} Mbps"
                    }
            except ValueError:
                pass

        # curl 失败
        stderr = result.stderr.strip() if result.stderr else ""
        if "Connection refused" in stderr or "SOCKS" in stderr:
            return {"success": False, "speed_mbps": 0, "message": "Proxy connection failed"}
        elif "timed out" in stderr.lower() or "timeout" in stderr.lower():
            return {"success": False, "speed_mbps": 0, "message": "Download timeout"}
        else:
            return {"success": False, "speed_mbps": 0, "message": f"Speed test failed: {stderr[:50]}"}

    except subprocess.TimeoutExpired:
        return {"success": False, "speed_mbps": 0, "message": "Download timeout"}
    except Exception as e:
        return {"success": False, "speed_mbps": 0, "message": str(e)[:50]}


@app.get("/api/test/egress/{tag}/speed")
def api_test_egress_speed(tag: str, size: int = 10, timeout: int = 30):
    """测速端点 - 通过下载文件测量出口速度

    Args:
        tag: 出口标识
        size: 下载文件大小 (MB)，默认 10
        timeout: 超时时间 (秒)，默认 30

    Returns:
        测速结果
    """
    # 限制参数范围
    size = max(1, min(100, size))  # 1-100 MB
    timeout = max(10, min(120, timeout))  # 10-120 秒

    return _test_speed_download(tag, size, timeout)


# ============ Adblock Rule Sets APIs ============

class AdblockRuleSetUpdateRequest(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    url: Optional[str] = None
    format: Optional[str] = None
    outbound: Optional[str] = None
    enabled: Optional[int] = None
    priority: Optional[int] = None
    category: Optional[str] = None
    region: Optional[str] = None


class AdblockRuleSetCreateRequest(BaseModel):
    tag: str
    name: str
    url: str
    description: str = ""
    format: str = "adblock"  # adblock, hosts, domains
    outbound: str = "block"
    category: str = "general"
    region: Optional[str] = None
    priority: int = 0


@app.get("/api/adblock/rules")
def api_list_adblock_rules(category: Optional[str] = None):
    """列出所有广告拦截规则集"""
    db = _get_db()
    rules = db.get_remote_rule_sets(enabled_only=False, category=category)

    # 按分类分组
    by_category = {}
    for rule in rules:
        cat = rule.get("category", "general")
        if cat not in by_category:
            by_category[cat] = []
        by_category[cat].append(rule)

    return {
        "rules": rules,
        "by_category": by_category,
        "total": len(rules),
        "enabled_count": sum(1 for r in rules if r.get("enabled"))
    }


@app.get("/api/adblock/rules/{tag}")
def api_get_adblock_rule(tag: str):
    """获取单个广告拦截规则集"""
    db = _get_db()
    rule = db.get_remote_rule_set(tag)
    if not rule:
        raise HTTPException(status_code=404, detail=f"规则集 '{tag}' 不存在")
    return rule


@app.put("/api/adblock/rules/{tag}/toggle")
def api_toggle_adblock_rule(tag: str):
    """切换广告拦截规则集启用状态"""
    db = _get_db()

    # 检查规则是否存在
    rule = db.get_remote_rule_set(tag)
    if not rule:
        raise HTTPException(status_code=404, detail=f"规则集 '{tag}' 不存在")

    # 切换状态
    db.toggle_remote_rule_set(tag)
    new_state = "启用" if not rule.get("enabled") else "禁用"

    return {
        "message": f"规则集 '{tag}' 已{new_state}",
        "tag": tag,
        "enabled": not rule.get("enabled")
    }


@app.put("/api/adblock/rules/{tag}")
def api_update_adblock_rule(tag: str, payload: AdblockRuleSetUpdateRequest):
    """更新广告拦截规则集"""
    db = _get_db()

    # 检查规则是否存在
    if not db.get_remote_rule_set(tag):
        raise HTTPException(status_code=404, detail=f"规则集 '{tag}' 不存在")

    # 更新
    updates = {k: v for k, v in payload.dict().items() if v is not None}
    if updates:
        db.update_remote_rule_set(tag, **updates)

    return {"message": f"规则集 '{tag}' 已更新"}


@app.post("/api/adblock/rules")
def api_create_adblock_rule(payload: AdblockRuleSetCreateRequest):
    """创建新的广告拦截规则集"""
    db = _get_db()

    # 检查 tag 是否已存在
    if db.get_remote_rule_set(payload.tag):
        raise HTTPException(status_code=400, detail=f"规则集 '{payload.tag}' 已存在")

    # 创建
    db.add_remote_rule_set(
        tag=payload.tag,
        name=payload.name,
        url=payload.url,
        description=payload.description,
        format=payload.format,
        outbound=payload.outbound,
        category=payload.category,
        region=payload.region,
        priority=payload.priority
    )

    return {"message": f"规则集 '{payload.tag}' 已创建", "tag": payload.tag}


@app.delete("/api/adblock/rules/{tag}")
def api_delete_adblock_rule(tag: str):
    """删除广告拦截规则集"""
    db = _get_db()

    # 检查规则是否存在
    if not db.get_remote_rule_set(tag):
        raise HTTPException(status_code=404, detail=f"规则集 '{tag}' 不存在")

    # 删除
    db.delete_remote_rule_set(tag)

    return {"message": f"规则集 '{tag}' 已删除"}


@app.post("/api/adblock/apply")
def api_apply_adblock_rules():
    """应用广告拦截规则（下载启用的规则并重新生成配置）"""
    reload_status = ""
    try:
        _regenerate_and_reload()
        reload_status = "配置已重新生成并重载"
    except Exception as exc:
        logging.error(f"Failed to apply adblock rules: {exc}")
        raise HTTPException(status_code=500, detail="Failed to apply configuration")

    return {"message": reload_status, "status": "success"}


def _regenerate_and_reload():
    """重新生成配置并重载 sing-box

    Raises:
        RuntimeError: 如果配置生成或重载失败
    """
    # 调用 render_singbox.py 重新生成配置
    result = subprocess.run(
        ["python3", str(ENTRY_DIR / "render_singbox.py")],
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        error_msg = f"配置生成失败: {result.stderr.strip() or result.stdout.strip()}"
        print(f"[api] render_singbox.py 失败: {result.stderr}")
        raise RuntimeError(error_msg)

    print(f"[api] render_singbox.py 成功")

    # 重载 sing-box
    reload_result = reload_singbox()
    if not reload_result.get("success"):
        error_msg = reload_result.get("message", "未知错误")
        raise RuntimeError(f"配置重载失败: {error_msg}")


def _full_regenerate_after_import():
    """备份导入后完整重新生成所有接口和配置

    在数据库被替换后调用，重新生成：
    1. WireGuard 入口接口
    2. WireGuard 出口接口（PIA、自定义）
    3. sing-box 配置
    4. Xray 入口（如果启用 V2Ray ingress）
    5. Xray 出口（如果配置了 V2Ray egress）
    6. OpenVPN 隧道（如果配置）
    7. WARP 代理（如果配置）

    Returns:
        dict: 各组件的重新生成状态
    """
    results = {
        "wireguard_ingress": False,
        "wireguard_egress": False,
        "singbox": False,
        "xray_ingress": False,
        "xray_egress": False,
        "openvpn": False,
        "warp": False,
    }

    # 1. WireGuard 入口接口
    try:
        result = subprocess.run(
            ["python3", "/usr/local/bin/setup_kernel_wg.py"],
            capture_output=True, text=True, timeout=30
        )
        if result.returncode == 0:
            print("[backup-import] WireGuard ingress interface synced")
            results["wireguard_ingress"] = True
        else:
            print(f"[backup-import] WireGuard ingress sync failed: {result.stderr.strip()}")
    except Exception as e:
        print(f"[backup-import] WireGuard ingress error: {e}")

    # 2. WireGuard 出口接口（PIA、自定义）
    try:
        result = subprocess.run(
            ["python3", "/usr/local/bin/setup_kernel_wg_egress.py"],
            capture_output=True, text=True, timeout=30
        )
        if result.returncode == 0:
            print("[backup-import] WireGuard egress interfaces synced")
            results["wireguard_egress"] = True
        else:
            print(f"[backup-import] WireGuard egress sync failed: {result.stderr.strip()}")
    except Exception as e:
        print(f"[backup-import] WireGuard egress error: {e}")

    # 3. sing-box 配置
    try:
        _regenerate_and_reload()
        results["singbox"] = True
        print("[backup-import] sing-box config regenerated and reloaded")
    except Exception as e:
        print(f"[backup-import] sing-box error: {e}")

    # 4. Xray 入口（检查 V2Ray ingress 是否启用）
    try:
        db = _get_db()
        v2ray_config = db.get_v2ray_inbound_config()
        if v2ray_config and v2ray_config.get("enabled"):
            result = subprocess.run(
                ["python3", "/usr/local/bin/xray_manager.py", "restart"],
                capture_output=True, text=True, timeout=30
            )
            if result.returncode == 0:
                print("[backup-import] Xray ingress restarted")
                results["xray_ingress"] = True
            else:
                print(f"[backup-import] Xray ingress restart failed: {result.stderr.strip()}")
        else:
            results["xray_ingress"] = True  # 未启用，视为成功
    except Exception as e:
        print(f"[backup-import] Xray ingress error: {e}")

    # 5. Xray 出口（检查 V2Ray egress）
    try:
        db = _get_db()
        v2ray_egress = db.get_v2ray_egress_list()
        if v2ray_egress:
            result = subprocess.run(
                ["python3", "/usr/local/bin/xray_egress_manager.py", "daemon"],
                capture_output=True, text=True, timeout=5
            )
            # daemon 会后台运行，立即返回
            print("[backup-import] Xray egress manager started")
            results["xray_egress"] = True
        else:
            results["xray_egress"] = True  # 无配置，视为成功
    except Exception as e:
        print(f"[backup-import] Xray egress error: {e}")

    # 6. OpenVPN 隧道
    try:
        db = _get_db()
        openvpn_list = db.get_openvpn_egress_list()
        if openvpn_list:
            result = subprocess.run(
                ["python3", "/usr/local/bin/openvpn_manager.py", "daemon"],
                capture_output=True, text=True, timeout=5
            )
            print("[backup-import] OpenVPN manager started")
            results["openvpn"] = True
        else:
            results["openvpn"] = True  # 无配置，视为成功
    except Exception as e:
        print(f"[backup-import] OpenVPN error: {e}")

    # 7. WARP 代理
    try:
        db = _get_db()
        warp_list = db.get_warp_egress_list()
        if warp_list:
            result = subprocess.run(
                ["python3", "/usr/local/bin/warp_manager.py", "daemon"],
                capture_output=True, text=True, timeout=5
            )
            print("[backup-import] WARP manager started")
            results["warp"] = True
        else:
            results["warp"] = True  # 无配置，视为成功
    except Exception as e:
        print(f"[backup-import] WARP error: {e}")

    return results


def _reload_xray_egress() -> str:
    """重载或启动 Xray 出站进程

    如果守护进程没有运行，则启动它；如果已运行则重载配置。

    Returns:
        状态消息
    """
    try:
        # 先检查状态
        status_result = subprocess.run(
            ["python3", "/usr/local/bin/xray_egress_manager.py", "status"],
            capture_output=True, text=True, timeout=5
        )
        is_running = False
        if status_result.returncode == 0:
            try:
                status = json.loads(status_result.stdout)
                is_running = status.get("status") == "running"
            except json.JSONDecodeError:
                pass

        # 根据状态决定操作
        if is_running:
            # 已运行，使用 reload
            result = subprocess.run(
                ["python3", "/usr/local/bin/xray_egress_manager.py", "reload"],
                capture_output=True, text=True, timeout=10
            )
            if result.returncode == 0:
                print("[api] Xray egress reloaded")
                _reset_xray_egress_client()
                return ", Xray egress reloaded"
            else:
                print(f"[api] Xray egress reload failed: {result.stderr.strip()}")
                return ", Xray egress reload failed"
        else:
            # 未运行，使用 start
            result = subprocess.run(
                ["python3", "/usr/local/bin/xray_egress_manager.py", "start"],
                capture_output=True, text=True, timeout=10
            )
            if result.returncode == 0:
                print("[api] Xray egress started")
                _reset_xray_egress_client()
                return ", Xray egress started"
            else:
                print(f"[api] Xray egress start failed: {result.stderr.strip()}")
                return ", Xray egress start failed"

    except subprocess.TimeoutExpired:
        print("[api] Xray egress operation timeout")
        return ", Xray egress timeout"
    except Exception as e:
        print(f"[api] Xray egress error: {e}")
        return ""


def _reload_openvpn_manager() -> str:
    """重载或启动 OpenVPN 管理器守护进程（同步数据库变更）

    如果守护进程已运行，通过 SIGHUP 信号通知重载配置。
    如果守护进程未运行且有启用的 OpenVPN 出口，则启动守护进程。

    Returns:
        状态消息
    """
    import signal as sig_module
    import fcntl

    pid_file = Path("/run/openvpn-manager.pid")
    lock_file = Path("/run/openvpn-manager.lock")

    # 使用文件锁防止竞态条件
    lock_file.parent.mkdir(parents=True, exist_ok=True)
    with open(lock_file, 'w') as lf:
        try:
            fcntl.flock(lf.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            # 另一个进程正在启动守护进程，等待并重试
            import time
            time.sleep(0.5)
            fcntl.flock(lf.fileno(), fcntl.LOCK_EX)

        try:
            # 检查守护进程是否在运行
            daemon_running = False
            if pid_file.exists():
                try:
                    daemon_pid = int(pid_file.read_text().strip())
                    os.kill(daemon_pid, 0)  # 检查进程是否存在
                    daemon_running = True
                except (ValueError, ProcessLookupError):
                    pid_file.unlink(missing_ok=True)
                except PermissionError:
                    daemon_running = True  # 进程存在但无权限检查

            if daemon_running:
                # 发送 SIGHUP 重载
                try:
                    daemon_pid = int(pid_file.read_text().strip())
                    os.kill(daemon_pid, sig_module.SIGHUP)
                    print(f"[api] Sent SIGHUP to OpenVPN manager (PID: {daemon_pid})")
                    return ", OpenVPN manager reloaded"
                except Exception as e:
                    print(f"[api] OpenVPN manager reload error: {e}")
                    return ""
            else:
                # 守护进程未运行，检查是否有启用的 OpenVPN 出口
                try:
                    db = _get_db()
                    openvpn_list = db.get_openvpn_egress_list()
                    enabled_count = sum(1 for eg in openvpn_list if eg.get("enabled", 0) == 1)

                    if enabled_count > 0:
                        # 启动守护进程
                        subprocess.Popen(
                            ["python3", "/usr/local/bin/openvpn_manager.py", "daemon"],
                            stdout=subprocess.DEVNULL,
                            stderr=subprocess.DEVNULL,
                            start_new_session=True
                        )
                        # 等待 PID 文件创建
                        import time
                        for _ in range(10):
                            time.sleep(0.2)
                            if pid_file.exists():
                                break
                        print(f"[api] Started OpenVPN manager daemon ({enabled_count} tunnels)")
                        return ", OpenVPN manager started"
                    else:
                        print("[api] No enabled OpenVPN egress, skipping manager start")
                        return ""
                except Exception as e:
                    print(f"[api] Failed to start OpenVPN manager: {e}")
                    return ""
        finally:
            fcntl.flock(lf.fileno(), fcntl.LOCK_UN)


def _sync_kernel_wg_egress() -> str:
    """同步内核 WireGuard 出口接口与数据库

    创建/更新/删除 PIA 或自定义出口后调用此函数，
    确保内核 WireGuard 接口与数据库保持同步。

    Returns:
        状态消息
    """
    try:
        result = subprocess.run(
            ["python3", "/usr/local/bin/setup_kernel_wg_egress.py"],
            capture_output=True, text=True, timeout=30
        )
        if result.returncode == 0:
            print("[api] Kernel WireGuard egress interfaces synced")
            return ", WireGuard interfaces synced"
        else:
            # Phase 5: Include actual error details in return message (Issue #9)
            error_detail = result.stderr.strip() or result.stdout.strip() or "unknown error"
            print(f"[api] WireGuard sync failed: {error_detail}")
            return f", WireGuard sync failed: {error_detail}"
    except subprocess.TimeoutExpired:
        print("[api] WireGuard sync timeout")
        return ", WireGuard sync timeout (30s)"
    except Exception as e:
        print(f"[api] WireGuard sync error: {e}")
        return f", WireGuard sync error: {e}"


def _sync_kernel_wg_ingress() -> str:
    """同步内核 WireGuard 入口接口与数据库

    更新 WireGuard 服务器配置后调用此函数，
    确保内核 wg-ingress 接口与数据库保持同步。

    注意: 不使用 --sync-only，因为需要应用服务器配置更改
    (private_key, listen_port, address, mtu)

    Returns:
        状态消息
    """
    try:
        result = subprocess.run(
            ["python3", "/usr/local/bin/setup_kernel_wg.py"],
            capture_output=True, text=True, timeout=30
        )
        if result.returncode == 0:
            print("[api] Kernel WireGuard ingress interface synced")
            return ", WireGuard ingress synced"
        else:
            # Phase 5: Include actual error details in return message (Issue #9)
            error_detail = result.stderr.strip() or result.stdout.strip() or "unknown error"
            print(f"[api] WireGuard ingress sync failed: {error_detail}")
            return f", WireGuard ingress sync failed: {error_detail}"
    except subprocess.TimeoutExpired:
        print("[api] WireGuard ingress sync timeout")
        return ", WireGuard ingress sync timeout (30s)"
    except Exception as e:
        print(f"[api] WireGuard ingress sync error: {e}")
        return f", WireGuard ingress sync error: {e}"


# ============ Domain List Catalog APIs ============

def load_domain_catalog() -> dict:
    """从内存返回域名目录"""
    return _DOMAIN_CATALOG


def get_domain_list(list_id: str) -> dict:
    """获取指定域名列表的详细信息"""
    lists = _DOMAIN_CATALOG.get("lists", {})
    if list_id not in lists:
        return {}

    lst = lists[list_id]
    domains = lst.get("domains", [])
    return {
        "id": list_id,
        "name": lst.get("name", list_id),
        "domains": domains,
        "full_domains": lst.get("full_domains", []),
        "regexps": lst.get("regexps", []),
        "count": lst.get("count", len(domains))
    }


def parse_domain_list_file(name: str, visited: Optional[set] = None) -> dict:
    """解析单个域名列表文件"""
    if visited is None:
        visited = set()

    if name in visited:
        return {"domains": [], "full_domains": [], "regexps": []}
    visited.add(name)

    file_path = DOMAIN_LIST_DIR / name
    if not file_path.exists():
        return {"domains": [], "full_domains": [], "regexps": []}

    domains = []
    full_domains = []
    regexps = []
    includes = []

    content = file_path.read_text(encoding="utf-8")
    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue

        # 移除 @tag 标记
        if " @" in line:
            line = line.split(" @")[0].strip()

        if line.startswith("include:"):
            includes.append(line[8:])
        elif line.startswith("full:"):
            full_domains.append(line[5:])
        elif line.startswith("regexp:"):
            regexps.append(line[7:])
        else:
            domains.append(line)

    # 递归处理 include
    for inc in includes:
        inc_data = parse_domain_list_file(inc, visited)
        domains.extend(inc_data.get("domains", []))
        full_domains.extend(inc_data.get("full_domains", []))
        regexps.extend(inc_data.get("regexps", []))

    return {
        "domains": list(set(domains)),
        "full_domains": list(set(full_domains)),
        "regexps": list(set(regexps)),
    }


@app.get("/api/domain-catalog")
def api_get_domain_catalog():
    """获取域名列表目录（分类概览）"""
    catalog = load_domain_catalog()
    categories = catalog.get("categories", {})

    # 合并自定义项目到各分类
    custom_items = load_custom_category_items()
    for cat_id, items in custom_items.items():
        if cat_id in categories:
            # 将自定义项目添加到分类的 lists 中
            for item in items:
                categories[cat_id]["lists"].append({
                    "id": item["id"],
                    "domain_count": item["domain_count"],
                    "sample_domains": item.get("sample_domains", []),
                    "is_custom": True,  # 标记为自定义项目
                })

    return {"categories": categories}


@app.get("/api/domain-catalog/categories")
def api_get_domain_categories():
    """获取所有分类"""
    catalog = load_domain_catalog()
    categories = catalog.get("categories", {})
    return {
        "categories": [
            {
                "id": cat_id,
                "name": cat_info.get("name"),
                "description": cat_info.get("description"),
                "recommended_exit": cat_info.get("recommended_exit"),
                "list_count": len(cat_info.get("lists", [])),
            }
            for cat_id, cat_info in categories.items()
        ]
    }


@app.get("/api/domain-catalog/categories/{category_id}")
def api_get_domain_category(category_id: str):
    """获取指定分类的详细信息"""
    catalog = load_domain_catalog()
    categories = catalog.get("categories", {})

    if category_id not in categories:
        raise HTTPException(status_code=404, detail=f"分类 {category_id} 不存在")

    return categories[category_id]


@app.get("/api/domain-catalog/lists/{list_id}")
def api_get_domain_list_detail(list_id: str):
    """获取指定域名列表的完整域名"""
    data = get_domain_list(list_id)
    if not data:
        raise HTTPException(status_code=404, detail=f"域名列表 {list_id} 不存在")
    return data


@app.get("/api/domain-catalog/search")
def api_search_domain_lists(q: str):
    """搜索域名列表（从内存）"""
    q_lower = q.lower()
    results = []

    lists = _DOMAIN_CATALOG.get("lists", {})
    for list_id, lst in lists.items():
        # 搜索列表 ID
        if q_lower in list_id.lower():
            results.append({"id": list_id, "name": lst.get("name", list_id)})
            continue

        # 搜索域名
        for domain in lst.get("domains", [])[:100]:  # 只搜索前100个域名
            if q_lower in domain.lower():
                results.append({"id": list_id, "name": lst.get("name", list_id)})
                break

        if len(results) >= 50:
            break

    return {"results": results}


class QuickRuleRequest(BaseModel):
    """快速创建规则请求"""
    list_ids: List[str] = Field(..., description="域名列表 ID 列表")
    outbound: str = Field(..., description="出口线路 tag")
    tag: Optional[str] = Field(None, description="规则集标签，不填则自动生成")


# 广告拦截相关的域名列表 (来自 advertising 和 adblock-extended 分类)
ADBLOCK_LIST_IDS = {
    "category-ads", "category-ads-all", "google-ads", "facebook-ads", "amazon-ads",
    "baidu-ads", "bytedance-ads", "tencent-ads", "alibaba-ads", "apple-ads",
    "acfun-ads", "dmm-ads", "sina-ads", "sohu-ads", "unity-ads", "spotify-ads",
    "xiaomi-ads", "adjust-ads", "applovin-ads", "adcolony-ads", "clearbit-ads",
    "segment-ads", "sensorsdata-ads", "taboola", "supersonic-ads", "tappx-ads",
    "television-ads", "atom-data-ads", "emogi-ads", "umeng-ads", "xhamster-ads",
    "uberads-ads", "tagtic-ads", "category-ads-ir", "ext-reject-all",
    # 安全隐私类的广告拦截相关列表
    "adblock", "adblockplus", "adguard"
}


def is_adblock_list(list_id: str) -> bool:
    """检查是否为广告拦截相关的域名列表"""
    list_lower = list_id.lower()
    # 直接匹配或包含 -ads 后缀
    if list_lower in ADBLOCK_LIST_IDS or list_lower.endswith("-ads"):
        return True
    return False


@app.post("/api/domain-catalog/quick-rule")
def api_create_quick_rule(payload: QuickRuleRequest):
    """从域名列表快速创建路由规则"""
    # 使用数据库存储
    if not HAS_DATABASE or not USER_DB_PATH.exists():
        raise HTTPException(status_code=503, detail="Database unavailable")

    db = _get_db()

    # 收集所有域名 - 从内存中的 _DOMAIN_CATALOG 读取
    all_domains = []
    lists = _DOMAIN_CATALOG.get("lists", {})
    for list_id in payload.list_ids:
        if list_id in lists:
            domains = lists[list_id].get("domains", [])
            all_domains.extend(domains)
        else:
            print(f"[QuickRule] 跳过未找到的列表: {list_id}")

    if not all_domains:
        raise HTTPException(status_code=400, detail="没有找到任何域名")

    # 去重
    all_domains = list(set(all_domains))

    # 检查是否为广告拦截规则 (所有选择的列表都是广告相关的)
    is_adblock_rule = all(is_adblock_list(lid) for lid in payload.list_ids)

    # 生成规则标签
    if payload.tag:
        tag = payload.tag
    elif is_adblock_rule:
        # 广告拦截规则使用 __adblock__ 前缀 + 随机ID，不会显示在路由规则页面
        import uuid
        tag = f"__adblock__{uuid.uuid4().hex[:8]}"
    else:
        tag = f"custom-{'-'.join(payload.list_ids[:3])}"

    # 批量添加域名到数据库（使用 executemany 一次性插入）
    # 格式: (rule_type, target, outbound, tag, priority)
    rules = [("domain", domain, payload.outbound, tag, 0) for domain in all_domains]
    added_count = db.add_routing_rules_batch(rules)

    return {
        "message": f"快速规则已创建，添加了 {added_count} 个域名到数据库",
        "tag": tag,
        "domain_count": added_count,
        "outbound": payload.outbound,
    }


@app.post("/api/domain-catalog/categories/{category_id}/items")
def api_add_custom_category_item(category_id: str, payload: CustomCategoryItemRequest):
    """在指定分类中添加自定义域名列表项"""
    # 验证分类存在
    catalog = load_domain_catalog()
    categories = catalog.get("categories", {})
    if category_id not in categories:
        raise HTTPException(status_code=404, detail=f"分类 {category_id} 不存在")

    # 验证域名列表不为空
    domains = [d.strip() for d in payload.domains if d.strip()]
    if not domains:
        raise HTTPException(status_code=400, detail="域名列表不能为空")

    # 生成唯一的项目 ID
    item_id = f"custom-{category_id}-{payload.name}"

    # 使用数据库存储
    if HAS_DATABASE and USER_DB_PATH.exists():
        db = _get_db()

        # 检查是否已存在
        existing_item = db.get_custom_category_item(item_id)
        if existing_item:
            raise HTTPException(status_code=400, detail=f"项目 '{payload.name}' 已存在于此分类中")

        # 添加到数据库
        db.add_custom_category_item(category_id, item_id, payload.name, domains)

        # 同步保存到 JSON 作为备份
        custom_items = db.get_custom_category_items()
        save_custom_category_items(custom_items)
    else:
        # 降级到 JSON 文件
        custom_items = load_custom_category_items()
        if category_id not in custom_items:
            custom_items[category_id] = []

        # 检查是否已存在同名项目
        existing_ids = [item["id"] for item in custom_items[category_id]]
        if item_id in existing_ids:
            raise HTTPException(status_code=400, detail=f"项目 '{payload.name}' 已存在于此分类中")

        # 添加新项目
        custom_items[category_id].append({
            "id": item_id,
            "name": payload.name,
            "domains": domains,
            "domain_count": len(domains),
            "sample_domains": domains[:5],
        })

        save_custom_category_items(custom_items)

    return {
        "message": f"已添加 '{payload.name}' 到 {categories[category_id]['name']}",
        "item_id": item_id,
        "domain_count": len(domains),
        "category_id": category_id,
    }


@app.delete("/api/domain-catalog/categories/{category_id}/items/{item_id}")
def api_delete_custom_category_item(category_id: str, item_id: str):
    """删除分类中的自定义域名列表项"""
    # 使用数据库删除
    if HAS_DATABASE and USER_DB_PATH.exists():
        db = _get_db()

        # 删除项目
        deleted = db.delete_custom_category_item(item_id)
        if not deleted:
            raise HTTPException(status_code=404, detail=f"项目 {item_id} 不存在")

        # 同步保存到 JSON 作为备份
        custom_items = db.get_custom_category_items()
        save_custom_category_items(custom_items)
    else:
        # 降级到 JSON 文件
        custom_items = load_custom_category_items()

        if category_id not in custom_items:
            raise HTTPException(status_code=404, detail=f"分类 {category_id} 没有自定义项目")

        # 查找并删除项目
        original_count = len(custom_items[category_id])
        custom_items[category_id] = [
            item for item in custom_items[category_id]
            if item["id"] != item_id
        ]

        if len(custom_items[category_id]) == original_count:
            raise HTTPException(status_code=404, detail=f"项目 {item_id} 不存在")

        # 如果分类为空，删除整个分类
        if not custom_items[category_id]:
            del custom_items[category_id]

        save_custom_category_items(custom_items)

    return {"message": f"项目 '{item_id}' 已删除"}


# ============ IP List Catalog APIs ============

# 国家代码到中文名称的映射
COUNTRY_NAMES = {
    "cn": "🇨🇳 中国", "hk": "🇭🇰 中国香港", "tw": "🇹🇼 中国台湾", "mo": "🇲🇴 中国澳门",
    "jp": "🇯🇵 日本", "kr": "🇰🇷 韩国", "sg": "🇸🇬 新加坡", "us": "🇺🇸 美国",
    "gb": "🇬🇧 英国", "de": "🇩🇪 德国", "fr": "🇫🇷 法国", "nl": "🇳🇱 荷兰",
    "au": "🇦🇺 澳大利亚", "ca": "🇨🇦 加拿大", "ru": "🇷🇺 俄罗斯", "in": "🇮🇳 印度",
    "br": "🇧🇷 巴西", "id": "🇮🇩 印尼", "th": "🇹🇭 泰国", "vn": "🇻🇳 越南",
    "my": "🇲🇾 马来西亚", "ph": "🇵🇭 菲律宾", "it": "🇮🇹 意大利", "es": "🇪🇸 西班牙",
    "ch": "🇨🇭 瑞士", "se": "🇸🇪 瑞典", "tr": "🇹🇷 土耳其", "ua": "🇺🇦 乌克兰",
    "il": "🇮🇱 以色列", "ae": "🇦🇪 阿联酋", "ir": "🇮🇷 伊朗",
}

RECOMMENDED_IP_EXITS = {
    "cn": "direct", "hk": "hk-stream", "tw": "tw-stream", "jp": "jp-stream",
    "kr": "kr-stream", "sg": "sg-stream", "us": "us-stream", "gb": "uk-stream",
}

def load_ip_catalog() -> dict:
    """从内存返回 IP 目录"""
    countries_list = _GEOIP_CATALOG.get("countries", [])

    countries = {}
    for country in countries_list:
        code = country["code"].lower()
        countries[code] = {
            "country_code": code.upper(),
            "country_name": country["name"],
            "display_name": COUNTRY_NAMES.get(code, country.get("display_name", country["name"])),
            "ipv4_count": country.get("ipv4_count", 0),
            "ipv6_count": country.get("ipv6_count", 0),
            "recommended_exit": RECOMMENDED_IP_EXITS.get(code, country.get("recommended_exit", "direct"))
        }

    stats = {
        "total_countries": len(countries),
        "total_ipv4": _GEOIP_CATALOG.get("total_ipv4_ranges", 0),
        "total_ipv6": _GEOIP_CATALOG.get("total_ipv6_ranges", 0)
    }

    return {"countries": countries, "stats": stats}


def get_country_ip_info(country_code: str) -> dict:
    """获取国家 IP 信息（优先 JSON，fallback 到 SQLite）"""
    cc = country_code.lower()

    # 从目录中获取国家基本信息
    country_info = None
    for c in _GEOIP_CATALOG.get("countries", []):
        if c["code"].lower() == cc:
            country_info = c
            break

    if not country_info:
        return {}

    ipv4_cidrs = []
    ipv6_cidrs = []

    # 优先从 JSON 文件加载
    ip_file = GEOIP_DIR / f"{cc}.json"
    if ip_file.exists():
        try:
            ip_data = json.loads(ip_file.read_text(encoding="utf-8"))
            ipv4_cidrs = ip_data.get("ipv4_ranges", [])
            ipv6_cidrs = ip_data.get("ipv6_ranges", [])
        except Exception:
            pass

    return {
        "country_code": cc.upper(),
        "country_name": country_info["name"],
        "display_name": COUNTRY_NAMES.get(cc, country_info.get("display_name", country_info["name"])),
        "ipv4_cidrs": ipv4_cidrs,
        "ipv6_cidrs": ipv6_cidrs,
        "ipv4_count": len(ipv4_cidrs),
        "ipv6_count": len(ipv6_cidrs),
        "recommended_exit": RECOMMENDED_IP_EXITS.get(cc, country_info.get("recommended_exit", "direct")),
    }


@app.get("/api/ip-catalog")
def api_get_ip_catalog():
    """获取 IP 列表目录（国家概览）"""
    return load_ip_catalog()


@app.get("/api/ip-catalog/countries/{country_code}")
def api_get_country_ips(country_code: str):
    """获取指定国家的完整 IP CIDR 列表"""
    cc = country_code.lower()
    info = get_country_ip_info(cc)
    if not info:
        raise HTTPException(status_code=404, detail=f"国家 {country_code} 不存在")
    return info


@app.get("/api/ip-catalog/search")
def api_search_countries(q: str):
    """搜索国家/地区（从内存）"""
    q_lower = q.lower()
    results = []

    # 从内存获取所有国家
    for country in _GEOIP_CATALOG.get("countries", []):
        cc = country["code"].lower()
        name = country["name"]
        display_name = COUNTRY_NAMES.get(cc, country.get("display_name", name))

        if q_lower in cc or q_lower in name.lower() or q_lower in display_name.lower():
            results.append({"country_code": cc.upper(), "display_name": display_name})

        if len(results) >= 30:
            break

    return {"results": results}


class IpQuickRuleRequest(BaseModel):
    """IP 快速创建规则请求"""
    country_codes: List[str] = Field(..., description="国家代码列表")
    outbound: str = Field(..., description="出口线路 tag")
    tag: Optional[str] = Field(None, description="规则集标签")
    ipv4_only: bool = Field(True, description="仅 IPv4")


@app.post("/api/ip-catalog/quick-rule")
def api_create_ip_quick_rule(payload: IpQuickRuleRequest):
    """从 IP 列表快速创建路由规则"""
    all_cidrs = []

    for cc in payload.country_codes:
        info = get_country_ip_info(cc.lower())
        if info:
            all_cidrs.extend(info.get("ipv4_cidrs", []))
            if not payload.ipv4_only:
                all_cidrs.extend(info.get("ipv6_cidrs", []))

    if not all_cidrs:
        raise HTTPException(status_code=400, detail="没有找到任何 IP CIDR")

    # 去重
    all_cidrs = list(set(all_cidrs))

    # 生成规则标签（用户自定义的保持原样，自动生成的加前缀）
    if payload.tag:
        tag = payload.tag
    else:
        tag = f"ip-{'-'.join(payload.country_codes[:3])}"

    # 使用数据库存储
    if not HAS_DATABASE or not USER_DB_PATH.exists():
        raise HTTPException(status_code=503, detail="数据库不可用")

    db = _get_db()

    # 批量添加 IP CIDR 到数据库（使用 executemany 一次性插入）
    # 格式: (rule_type, target, outbound, tag, priority)
    rules = [("ip", cidr, payload.outbound, tag, 0) for cidr in all_cidrs]
    added_count = db.add_routing_rules_batch(rules)

    return {
        "message": f"IP 快速规则已创建，添加了 {added_count} 个 CIDR 到数据库",
        "tag": tag,
        "cidr_count": added_count,
        "outbound": payload.outbound,
    }


# ============ Backup / Restore APIs ============

BACKUP_VERSION = "2.0"


@app.post("/api/backup/export")
def api_export_backup(payload: BackupExportRequest):
    """导出配置备份 (v2.0: SQLCipher 加密数据库 + 加密部署密钥)

    v2.0 格式:
    - database: base64 编码的 SQLCipher 加密数据库
    - encryption_key: 用用户密码加密的部署密钥
    - checksum: SHA256 校验和
    - 所有数据（包括 PIA 凭据）自动包含在加密数据库中
    """
    import hashlib
    import base64

    # 检查 KeyManager 是否可用
    if not HAS_KEY_MANAGER:
        raise HTTPException(status_code=500, detail="KeyManager not available")

    # 检查数据库是否存在
    if not USER_DB_PATH.exists():
        raise HTTPException(status_code=500, detail="Database not found")

    # 1. 读取 SQLCipher 加密的数据库文件
    db_bytes = USER_DB_PATH.read_bytes()
    db_size = len(db_bytes)

    # 2. 计算 SHA256 校验和
    checksum = hashlib.sha256(db_bytes).hexdigest()

    # 3. 用用户密码加密部署密钥
    try:
        encrypted_key = KeyManager.encrypt_key_for_export(payload.password)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to encrypt key: {e}") from e

    # 4. 构建 v2.0 备份数据
    backup_data = {
        "version": BACKUP_VERSION,
        "type": "vpn-gateway-backup",
        "created_at": datetime.now(timezone.utc).isoformat(),
        "checksum": f"sha256:{checksum}",
        "database_size_bytes": db_size,
        "database": base64.b64encode(db_bytes).decode("utf-8"),
        "encryption_key": encrypted_key,
    }

    return {
        "message": "备份已生成 (v2.0)",
        "backup": backup_data,
        "encrypted": True,
        "database_size_bytes": db_size,
        "checksum": f"sha256:{checksum}",
    }


# 保留 v1.0 导出逻辑的辅助函数，供向后兼容
def _export_backup_v1(payload: BackupExportRequest) -> dict:
    """v1.0 格式导出（已废弃，仅用于参考）"""
    backup_data = {
        "version": "1.0",
        "created_at": datetime.now(timezone.utc).isoformat(),
        "type": "vpn-gateway-backup",
    }

    # 1. 导出设置
    settings = load_settings()
    backup_data["settings"] = settings

    # 2. 导出入口配置（ingress）
    ingress_config = load_ingress_config()
    # 敏感数据：私钥
    ingress_sensitive = {
        "interface_private_key": ingress_config.get("interface", {}).get("private_key", ""),
        "peers": []
    }
    for peer in ingress_config.get("peers", []):
        # 如果peer有存储的私钥（用于生成客户端配置），也需要加密
        peer_data = {
            "name": peer.get("name", ""),
            "public_key": peer.get("public_key", ""),
            "allowed_ips": peer.get("allowed_ips", []),
        }
        ingress_sensitive["peers"].append(peer_data)

    # 非敏感的入口配置
    ingress_public = {
        "interface": {
            "name": ingress_config.get("interface", {}).get("name", "wg-ingress"),
            "address": ingress_config.get("interface", {}).get("address", DEFAULT_WG_SUBNET),
            "listen_port": ingress_config.get("interface", {}).get("listen_port", DEFAULT_WG_PORT),
            "mtu": ingress_config.get("interface", {}).get("mtu", 1420),
        },
        "peer_count": len(ingress_config.get("peers", [])),
    }
    backup_data["ingress"] = ingress_public
    backup_data["ingress_sensitive"] = encrypt_sensitive_data(
        json.dumps(ingress_sensitive), payload.password
    )

    # 3. 导出自定义出口配置（从数据库）
    db = _get_db()
    egress_list = db.get_custom_egress_list()

    # 分离敏感和非敏感数据
    egress_public = []
    egress_sensitive = []
    for eg in egress_list:
        egress_public.append({
            "tag": eg.get("tag", ""),
            "description": eg.get("description", ""),
            "server": eg.get("server", ""),
            "port": eg.get("port", 51820),
            "address": eg.get("address", ""),
            "mtu": eg.get("mtu", 1420),
            "dns": eg.get("dns", "1.1.1.1"),
        })
        egress_sensitive.append({
            "tag": eg.get("tag", ""),
            "private_key": eg.get("private_key", ""),
            "public_key": eg.get("public_key", ""),
            "pre_shared_key": eg.get("pre_shared_key", ""),
            "reserved": eg.get("reserved"),
        })

    backup_data["custom_egress"] = egress_public
    backup_data["custom_egress_sensitive"] = encrypt_sensitive_data(
        json.dumps(egress_sensitive), payload.password
    )

    # 4. 导出 PIA 配置（从数据库）
    pia_profiles = db.get_pia_profiles(enabled_only=False)
    # 转换为备份格式（不包含敏感凭证）
    backup_data["pia_profiles"] = [
        {
            "name": p["name"],
            "description": p.get("description", ""),
            "region_id": p.get("region_id", ""),
            "custom_dns": p.get("custom_dns") or "",
            "enabled": p.get("enabled", 1) == 1,
        }
        for p in pia_profiles
    ]

    # 5. 导出 PIA 凭证（如果存在且用户要求）
    if payload.include_pia_credentials:
        pia_username, pia_password = get_pia_credentials()
        if pia_username and pia_password:
            pia_creds = {"username": pia_username, "password": pia_password}
            backup_data["pia_credentials"] = encrypt_sensitive_data(
                json.dumps(pia_creds), payload.password
            )

    # 6. 导出路由规则（从数据库）
    if HAS_DATABASE and USER_DB_PATH.exists():
        db = _get_db()
        db_rules = db.get_routing_rules(enabled_only=False)

        # 将数据库规则转换为备份格式
        custom_rules = {
            "rules": [],
            "default_outbound": "direct",
            "source": "database"
        }

        # 按 outbound 分组
        rules_by_outbound = {}
        for rule in db_rules:
            outbound = rule["outbound"]
            if outbound not in rules_by_outbound:
                rules_by_outbound[outbound] = {
                    "tag": f"custom-{outbound}",
                    "outbound": outbound,
                    "domains": [],
                    "domain_keywords": [],
                    "ip_cidrs": []
                }

            if rule["rule_type"] == "domain":
                rules_by_outbound[outbound]["domains"].append(rule["target"])
            elif rule["rule_type"] == "domain_keyword":
                rules_by_outbound[outbound]["domain_keywords"].append(rule["target"])
            elif rule["rule_type"] == "ip":
                rules_by_outbound[outbound]["ip_cidrs"].append(rule["target"])

        custom_rules["rules"] = list(rules_by_outbound.values())
        backup_data["custom_rules"] = custom_rules
    else:
        # 降级到 JSON 文件
        custom_rules = load_custom_rules()
        backup_data["custom_rules"] = custom_rules

    # 7. 导出 V2Ray 出口配置
    v2ray_egress_list = db.get_v2ray_egress_list(enabled_only=False)
    v2ray_egress_public = []
    v2ray_egress_sensitive = []
    for eg in v2ray_egress_list:
        v2ray_egress_public.append({
            "tag": eg.get("tag", ""),
            "description": eg.get("description", ""),
            "protocol": eg.get("protocol", ""),
            "server": eg.get("server", ""),
            "server_port": eg.get("server_port", 443),
            "security": eg.get("security", "auto"),
            "alter_id": eg.get("alter_id", 0),
            "flow": eg.get("flow"),
            "tls_enabled": eg.get("tls_enabled", 1),
            "tls_sni": eg.get("tls_sni"),
            "tls_alpn": eg.get("tls_alpn"),
            "tls_allow_insecure": eg.get("tls_allow_insecure", 0),
            "tls_fingerprint": eg.get("tls_fingerprint"),
            "reality_enabled": eg.get("reality_enabled", 0),
            "reality_public_key": eg.get("reality_public_key"),
            "reality_short_id": eg.get("reality_short_id"),
            "transport_type": eg.get("transport_type", "tcp"),
            "transport_config": eg.get("transport_config"),
            "multiplex_enabled": eg.get("multiplex_enabled", 0),
            "multiplex_protocol": eg.get("multiplex_protocol"),
            "multiplex_max_connections": eg.get("multiplex_max_connections"),
            "multiplex_min_streams": eg.get("multiplex_min_streams"),
            "multiplex_max_streams": eg.get("multiplex_max_streams"),
            "enabled": eg.get("enabled", 1),
        })
        v2ray_egress_sensitive.append({
            "tag": eg.get("tag", ""),
            "uuid": eg.get("uuid", ""),
            "password": eg.get("password", ""),
        })

    backup_data["v2ray_egress"] = v2ray_egress_public
    backup_data["v2ray_egress_sensitive"] = encrypt_sensitive_data(
        json.dumps(v2ray_egress_sensitive), payload.password
    )

    # 8. 导出 V2Ray 入口配置和用户
    v2ray_inbound = db.get_v2ray_inbound_config()
    v2ray_users = db.get_v2ray_users(enabled_only=False)

    if v2ray_inbound:
        v2ray_inbound_public = {
            "protocol": v2ray_inbound.get("protocol", "vless"),
            "listen_address": v2ray_inbound.get("listen_address", "0.0.0.0"),
            "listen_port": v2ray_inbound.get("listen_port", 443),
            "tls_enabled": v2ray_inbound.get("tls_enabled", 1),
            "tls_cert_path": v2ray_inbound.get("tls_cert_path"),
            "tls_key_path": v2ray_inbound.get("tls_key_path"),
            "transport_type": v2ray_inbound.get("transport_type", "tcp"),
            "transport_config": v2ray_inbound.get("transport_config"),
            "fallback_server": v2ray_inbound.get("fallback_server"),
            "fallback_port": v2ray_inbound.get("fallback_port"),
            "enabled": v2ray_inbound.get("enabled", 0),
        }
        v2ray_inbound_sensitive = {
            "tls_cert_content": v2ray_inbound.get("tls_cert_content", ""),
            "tls_key_content": v2ray_inbound.get("tls_key_content", ""),
        }
        backup_data["v2ray_inbound"] = v2ray_inbound_public
        backup_data["v2ray_inbound_sensitive"] = encrypt_sensitive_data(
            json.dumps(v2ray_inbound_sensitive), payload.password
        )

    v2ray_users_public = []
    v2ray_users_sensitive = []
    for user in v2ray_users:
        v2ray_users_public.append({
            "name": user.get("name", ""),
            "email": user.get("email"),
            "alter_id": user.get("alter_id", 0),
            "flow": user.get("flow"),
            "enabled": user.get("enabled", 1),
        })
        v2ray_users_sensitive.append({
            "name": user.get("name", ""),
            "uuid": user.get("uuid", ""),
            "password": user.get("password", ""),
        })

    backup_data["v2ray_users"] = v2ray_users_public
    backup_data["v2ray_users_sensitive"] = encrypt_sensitive_data(
        json.dumps(v2ray_users_sensitive), payload.password
    )

    return {
        "message": "备份已生成",
        "backup": backup_data,
        "encrypted": bool(payload.password),
    }


@app.post("/api/backup/import")
def api_import_backup(payload: BackupImportRequest):
    """导入配置备份 (支持 v2.0 和 v1.0 格式)

    v2.0: 直接替换 SQLCipher 加密数据库
    v1.0: 向后兼容的 JSON 格式导入
    """
    import hashlib
    import base64
    import shutil
    import tempfile

    try:
        backup_data = json.loads(payload.data)
    except json.JSONDecodeError as exc:
        raise HTTPException(status_code=400, detail=f"无效的备份数据格式: {exc}") from exc

    # 验证备份格式
    if backup_data.get("type") != "vpn-gateway-backup":
        raise HTTPException(status_code=400, detail="无效的备份文件类型")

    version = backup_data.get("version", "1.0")

    # === v2.0 格式处理 ===
    if version == "2.0":
        if not HAS_KEY_MANAGER:
            raise HTTPException(status_code=500, detail="KeyManager not available")

        # 1. 解密部署密钥
        try:
            encrypted_key = backup_data.get("encryption_key")
            if not encrypted_key:
                raise HTTPException(status_code=400, detail="Missing encryption_key in backup")
            decrypted_key = KeyManager.decrypt_key_from_import(encrypted_key, payload.password)
        except ValueError as e:
            raise HTTPException(status_code=400, detail=f"解密密钥失败（密码错误？）: {e}") from e

        # 2. 解码数据库
        try:
            db_base64 = backup_data.get("database")
            if not db_base64:
                raise HTTPException(status_code=400, detail="Missing database in backup")
            db_bytes = base64.b64decode(db_base64)
        except Exception as e:
            raise HTTPException(status_code=400, detail=f"解码数据库失败: {e}") from e

        # 3. 验证校验和
        expected_checksum = backup_data.get("checksum", "")
        if expected_checksum.startswith("sha256:"):
            expected_hash = expected_checksum[7:]
            actual_hash = hashlib.sha256(db_bytes).hexdigest()
            if expected_hash != actual_hash:
                raise HTTPException(status_code=400, detail="备份校验失败：数据可能已损坏")

        # 4. 验证密钥能打开数据库（使用临时文件）
        with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as tmp:
            tmp_path = tmp.name
            tmp.write(db_bytes)

        try:
            if not KeyManager.validate_key_for_database(tmp_path, decrypted_key):
                raise HTTPException(status_code=400, detail="密钥无法打开数据库（密码错误？）")
        finally:
            if os.path.exists(tmp_path):
                os.unlink(tmp_path)

        # 5. 原子替换：数据库 + 密钥文件
        # 备份当前数据库
        backup_db_path = USER_DB_PATH.with_suffix(".db.backup")
        if USER_DB_PATH.exists():
            shutil.copy2(USER_DB_PATH, backup_db_path)

        try:
            # 写入新数据库
            with tempfile.NamedTemporaryFile(dir=USER_DB_PATH.parent, suffix=".db.tmp", delete=False) as tmp:
                tmp.write(db_bytes)
                tmp_db_path = tmp.name
            shutil.move(tmp_db_path, USER_DB_PATH)

            # 保存新密钥
            KeyManager.save_key(decrypted_key)

            # 更新环境变量（当前进程）
            os.environ["SQLCIPHER_KEY"] = decrypted_key
            global SQLCIPHER_KEY
            SQLCIPHER_KEY = decrypted_key

            # 重置数据库管理器缓存
            global _db_manager
            from db_helper import _db_manager as db_mgr
            # 强制重新创建数据库连接
            import db_helper
            db_helper._db_manager = None

            # 重新加载 PIA 凭据到内存
            _CredentialStore._db_loaded = False  # 强制重新加载

        except Exception as e:
            # 回滚
            if backup_db_path.exists():
                shutil.move(backup_db_path, USER_DB_PATH)
            raise HTTPException(status_code=500, detail=f"导入失败: {e}") from e

        # 6. 完整重新生成所有接口和配置
        regen_results = {}
        try:
            regen_results = _full_regenerate_after_import()
            print(f"[backup] 重新生成结果: {regen_results}")
        except Exception as e:
            print(f"[backup] 重新生成配置失败: {e}")
            # 不回滚，数据已成功导入

        # 7. 清除速率限制（用户可能需要重新登录，之前的限制不应影响）
        _clear_rate_limit()

        return {
            "message": "备份导入成功 (v2.0)",
            "version": "2.0",
            "checksum_verified": True,
            "database_size_bytes": len(db_bytes),
            "regeneration_results": regen_results,
        }

    # === v1.0 格式处理（向后兼容）===
    # version 已在上面检查过

    results = {
        "settings": False,
        "ingress": False,
        "custom_egress": False,
        "pia_profiles": False,
        "pia_credentials": False,
        "custom_rules": False,
        "v2ray_egress": False,
        "v2ray_inbound": False,
        "v2ray_users": False,
    }

    # 1. 导入设置
    if "settings" in backup_data:
        try:
            save_settings(backup_data["settings"])
            results["settings"] = True
        except Exception as exc:
            print(f"[backup] 导入设置失败: {exc}")

    # 2. 导入入口配置
    if "ingress" in backup_data and "ingress_sensitive" in backup_data:
        try:
            # 解密敏感数据
            sensitive_json = decrypt_sensitive_data(
                backup_data["ingress_sensitive"], payload.password
            )
            sensitive = json.loads(sensitive_json)

            # 构建完整的入口配置
            ingress_public = backup_data["ingress"]
            ingress_config = {
                "interface": {
                    "name": ingress_public.get("interface", {}).get("name", "wg-ingress"),
                    "address": ingress_public.get("interface", {}).get("address", DEFAULT_WG_SUBNET),
                    "listen_port": ingress_public.get("interface", {}).get("listen_port", DEFAULT_WG_PORT),
                    "mtu": ingress_public.get("interface", {}).get("mtu", 1420),
                    "private_key": sensitive.get("interface_private_key", ""),
                },
                "peers": sensitive.get("peers", []),
            }

            if payload.merge_mode == "merge":
                # 合并模式：保留现有配置，只添加新的 peer
                existing = load_ingress_config()
                existing_peer_names = {p.get("name") for p in existing.get("peers", [])}
                for peer in ingress_config.get("peers", []):
                    if peer.get("name") not in existing_peer_names:
                        existing.setdefault("peers", []).append(peer)
                ingress_config = existing

            save_ingress_config(ingress_config)
            # 应用配置
            apply_ingress_config(ingress_config)
            results["ingress"] = True
        except Exception as exc:
            print(f"[backup] 导入入口配置失败: {exc}")

    # 3. 导入自定义出口（到数据库）
    if "custom_egress" in backup_data and "custom_egress_sensitive" in backup_data:
        try:
            db = _get_db()
            sensitive_json = decrypt_sensitive_data(
                backup_data["custom_egress_sensitive"], payload.password
            )
            sensitive_list = json.loads(sensitive_json)
            sensitive_map = {s["tag"]: s for s in sensitive_list}

            # 如果是替换模式，先删除所有现有出口
            if payload.merge_mode == "replace":
                existing = db.get_custom_egress_list()
                for eg in existing:
                    db.delete_custom_egress(eg["tag"])

            # 获取现有标签（用于合并模式）
            existing_tags = {eg["tag"] for eg in db.get_custom_egress_list()}

            # 导入备份中的出口
            for eg in backup_data["custom_egress"]:
                tag = eg.get("tag", "")
                if tag in existing_tags:
                    continue  # 跳过已存在的
                sens = sensitive_map.get(tag, {})
                db.add_custom_egress(
                    tag=tag,
                    server=eg.get("server", ""),
                    private_key=sens.get("private_key", ""),
                    public_key=sens.get("public_key", ""),
                    address=eg.get("address", ""),
                    description=eg.get("description", ""),
                    port=eg.get("port", 51820),
                    mtu=eg.get("mtu", 1420),
                    dns=eg.get("dns", "1.1.1.1"),
                    pre_shared_key=sens.get("pre_shared_key"),
                    reserved=sens.get("reserved"),
                )
            results["custom_egress"] = True
        except Exception as exc:
            print(f"[backup] 导入自定义出口失败: {exc}")

    # 4. 导入 PIA profiles（到数据库）
    if "pia_profiles" in backup_data:
        try:
            profiles = backup_data["pia_profiles"]
            db = _get_db()

            if payload.merge_mode == "replace":
                # 删除所有现有 profiles
                existing = db.get_pia_profiles(enabled_only=False)
                for p in existing:
                    db.delete_pia_profile(p["id"])

            existing_names = {p["name"] for p in db.get_pia_profiles(enabled_only=False)}
            for p in profiles:
                if p.get("name") not in existing_names:
                    db.add_pia_profile(
                        name=p["name"],
                        region_id=p.get("region_id", ""),
                        description=p.get("description", ""),
                        custom_dns=p.get("custom_dns") or None
                    )
            results["pia_profiles"] = True
        except Exception as exc:
            print(f"[backup] 导入 PIA 配置失败: {exc}")

    # 5. 导入 PIA 凭证
    if "pia_credentials" in backup_data:
        try:
            creds_json = decrypt_sensitive_data(
                backup_data["pia_credentials"], payload.password
            )
            creds = json.loads(creds_json)
            if creds.get("username") and creds.get("password"):
                set_pia_credentials(creds["username"], creds["password"])
                results["pia_credentials"] = True
        except Exception as exc:
            print(f"[backup] 导入 PIA 凭证失败: {exc}")

    # 6. 导入路由规则（到数据库）- 使用批量处理
    if "custom_rules" in backup_data:
        try:
            rules_data = backup_data["custom_rules"]
            rules_list = rules_data.get("rules", [])

            if HAS_DATABASE and USER_DB_PATH.exists():
                db = _get_db()

                # 如果是替换模式，先批量删除所有规则（但保留广告拦截规则）
                if payload.merge_mode == "replace":
                    db.delete_all_routing_rules(preserve_adblock=True)

                # 收集所有规则用于批量插入
                # 格式: [(rule_type, target, outbound, tag, priority), ...]
                batch_rules = []
                for rule in rules_list:
                    outbound = rule.get("outbound", "direct")
                    tag = rule.get("tag", "custom-direct")

                    # 收集域名规则
                    for domain in rule.get("domains", []):
                        batch_rules.append(("domain", domain, outbound, tag, 0))

                    # 收集域名关键词规则
                    for keyword in rule.get("domain_keywords", []):
                        batch_rules.append(("domain_keyword", keyword, outbound, tag, 0))

                    # 收集 IP 规则
                    for cidr in rule.get("ip_cidrs", []):
                        batch_rules.append(("ip", cidr, outbound, tag, 0))

                # 批量插入
                if batch_rules:
                    imported_count = db.add_routing_rules_batch(batch_rules)
                    print(f"[backup] 批量导入 {imported_count} 条规则到数据库")
                else:
                    imported_count = 0
                    print("[backup] 没有路由规则需要导入")

                results["custom_rules"] = True
            else:
                # 降级到 JSON 文件
                save_custom_rules(rules_data)
                results["custom_rules"] = True
        except Exception as exc:
            print(f"[backup] 导入路由规则失败: {exc}")

    # 7. 导入 V2Ray 出口配置
    if "v2ray_egress" in backup_data and "v2ray_egress_sensitive" in backup_data:
        try:
            db = _get_db()

            # 解密敏感数据
            sensitive_json = decrypt_sensitive_data(
                backup_data["v2ray_egress_sensitive"], payload.password
            )
            sensitive_list = json.loads(sensitive_json)
            sensitive_by_tag = {s["tag"]: s for s in sensitive_list}

            if payload.merge_mode == "replace":
                # 删除所有现有 V2Ray 出口
                existing = db.get_v2ray_egress_list(enabled_only=False)
                for eg in existing:
                    db.delete_v2ray_egress(eg["tag"])

            existing_tags = {eg["tag"] for eg in db.get_v2ray_egress_list(enabled_only=False)}
            skipped_count = 0
            for eg in backup_data["v2ray_egress"]:
                tag = eg.get("tag", "")
                protocol = eg.get("protocol", "vless")

                # [Xray-lite] Skip VMess/Trojan egress from backup - only VLESS supported
                if protocol != "vless":
                    print(f"[backup] Skipping unsupported protocol '{protocol}' for egress '{tag}' - "
                          "only VLESS is supported in Xray-lite. See docs/VMESS_TROJAN_MIGRATION.md")
                    skipped_count += 1
                    continue

                if tag and tag not in existing_tags:
                    sens = sensitive_by_tag.get(tag, {})
                    db.add_v2ray_egress(
                        tag=tag,
                        protocol=protocol,
                        server=eg.get("server", ""),
                        server_port=eg.get("server_port", 443),
                        description=eg.get("description", ""),
                        uuid=sens.get("uuid"),
                        password=sens.get("password"),
                        security=eg.get("security", "auto"),
                        alter_id=eg.get("alter_id", 0),
                        flow=eg.get("flow"),
                        tls_enabled=eg.get("tls_enabled", 1),
                        tls_sni=eg.get("tls_sni"),
                        tls_alpn=eg.get("tls_alpn"),
                        tls_allow_insecure=eg.get("tls_allow_insecure", 0),
                        tls_fingerprint=eg.get("tls_fingerprint"),
                        reality_enabled=eg.get("reality_enabled", 0),
                        reality_public_key=eg.get("reality_public_key"),
                        reality_short_id=eg.get("reality_short_id"),
                        transport_type=eg.get("transport_type", "tcp"),
                        transport_config=eg.get("transport_config"),
                        multiplex_enabled=eg.get("multiplex_enabled", 0),
                        multiplex_protocol=eg.get("multiplex_protocol"),
                        multiplex_max_connections=eg.get("multiplex_max_connections"),
                        multiplex_min_streams=eg.get("multiplex_min_streams"),
                        multiplex_max_streams=eg.get("multiplex_max_streams"),
                        enabled=eg.get("enabled", 1),
                    )
            results["v2ray_egress"] = True
        except Exception as exc:
            print(f"[backup] 导入 V2Ray 出口失败: {exc}")

    # 8. 导入 V2Ray 入口配置
    if "v2ray_inbound" in backup_data:
        try:
            db = _get_db()
            inbound_public = backup_data["v2ray_inbound"]

            inbound_sensitive = {}
            if "v2ray_inbound_sensitive" in backup_data:
                sensitive_json = decrypt_sensitive_data(
                    backup_data["v2ray_inbound_sensitive"], payload.password
                )
                inbound_sensitive = json.loads(sensitive_json)

            db.set_v2ray_inbound_config(
                protocol=inbound_public.get("protocol", "vless"),
                listen_address=inbound_public.get("listen_address", "0.0.0.0"),
                listen_port=inbound_public.get("listen_port", 443),
                tls_enabled=inbound_public.get("tls_enabled", 1),
                tls_cert_path=inbound_public.get("tls_cert_path"),
                tls_key_path=inbound_public.get("tls_key_path"),
                tls_cert_content=inbound_sensitive.get("tls_cert_content"),
                tls_key_content=inbound_sensitive.get("tls_key_content"),
                transport_type=inbound_public.get("transport_type", "tcp"),
                transport_config=inbound_public.get("transport_config"),
                fallback_server=inbound_public.get("fallback_server"),
                fallback_port=inbound_public.get("fallback_port"),
                enabled=inbound_public.get("enabled", 0),
            )
            results["v2ray_inbound"] = True
        except Exception as exc:
            print(f"[backup] 导入 V2Ray 入口配置失败: {exc}")

    # 9. 导入 V2Ray 用户
    if "v2ray_users" in backup_data and "v2ray_users_sensitive" in backup_data:
        try:
            db = _get_db()

            # 解密敏感数据
            sensitive_json = decrypt_sensitive_data(
                backup_data["v2ray_users_sensitive"], payload.password
            )
            sensitive_list = json.loads(sensitive_json)
            sensitive_by_name = {s["name"]: s for s in sensitive_list}

            if payload.merge_mode == "replace":
                # 删除所有现有用户
                existing = db.get_v2ray_users(enabled_only=False)
                for user in existing:
                    db.delete_v2ray_user(user["id"])

            existing_names = {u["name"] for u in db.get_v2ray_users(enabled_only=False)}
            for user in backup_data["v2ray_users"]:
                name = user.get("name", "")
                if name and name not in existing_names:
                    sens = sensitive_by_name.get(name, {})
                    db.add_v2ray_user(
                        name=name,
                        email=user.get("email"),
                        uuid=sens.get("uuid"),
                        password=sens.get("password"),
                        alter_id=user.get("alter_id", 0),
                        flow=user.get("flow"),
                        enabled=user.get("enabled", 1),
                    )
            results["v2ray_users"] = True
        except Exception as exc:
            print(f"[backup] 导入 V2Ray 用户失败: {exc}")

    # 完整重新生成所有接口和配置
    reload_status = ""
    regen_results = {}
    try:
        regen_results = _full_regenerate_after_import()
        reload_status = "，已重新生成所有接口"
        print(f"[backup-v1] 重新生成结果: {regen_results}")
    except Exception as exc:
        print(f"[backup] 重载配置失败: {exc}")
        reload_status = f"，重载失败: {exc}"

    # 清除速率限制（用户可能需要重新登录）
    _clear_rate_limit()

    imported_count = sum(1 for v in results.values() if v)
    return {
        "message": f"已导入 {imported_count} 项配置{reload_status}",
        "results": results,
        "regeneration_results": regen_results,
    }


@app.get("/api/backup/status")
def api_backup_status():
    """获取备份相关状态（v2.0）"""
    ingress = load_ingress_config()
    settings = load_settings()

    # 从数据库获取数据
    db = _get_db()
    pia_profiles = db.get_pia_profiles(enabled_only=False)
    custom_egress = db.get_custom_egress_list()

    # v2.0: 数据库大小和加密状态
    db_size_bytes = USER_DB_PATH.stat().st_size if USER_DB_PATH.exists() else 0
    db_encrypted = False
    if HAS_KEY_MANAGER and USER_DB_PATH.exists():
        db_encrypted = KeyManager.is_database_encrypted(str(USER_DB_PATH))

    return {
        # v2.0 新增字段
        "backup_version": BACKUP_VERSION,
        "database_size_bytes": db_size_bytes,
        "database_encrypted": db_encrypted,
        "key_manager_available": HAS_KEY_MANAGER,
        # 现有字段
        "encryption_available": HAS_CRYPTO,
        "has_ingress": bool(ingress.get("interface", {}).get("private_key")),
        "ingress_peer_count": len(ingress.get("peers", [])),
        "custom_egress_count": len(custom_egress),
        "pia_profile_count": len(pia_profiles),
        "has_pia_credentials": has_pia_credentials(),
        "has_settings": bool(settings.get("server_endpoint")),
    }


# ============ Database API Endpoints ============

@app.get("/api/db/stats")
def api_get_db_stats():
    """获取数据库统计信息"""
    if not HAS_DATABASE or not USER_DB_PATH.exists():
        raise HTTPException(status_code=503, detail="数据库不可用")

    db = _get_db()
    return db.get_statistics()


@app.get("/api/db/rules")
def api_get_db_rules(enabled_only: bool = True):
    """获取数据库中的所有路由规则"""
    if not HAS_DATABASE or not USER_DB_PATH.exists():
        raise HTTPException(status_code=503, detail="数据库不可用")

    db = _get_db()
    rules = db.get_routing_rules(enabled_only=enabled_only)
    return {"rules": rules, "count": len(rules)}


@app.put("/api/db/rules/{rule_id}")
def api_update_db_rule(
    rule_id: int,
    outbound: Optional[str] = None,
    priority: Optional[int] = None,
    enabled: Optional[bool] = None
):
    """更新路由规则"""
    if not HAS_DATABASE or not USER_DB_PATH.exists():
        raise HTTPException(status_code=503, detail="数据库不可用")

    db = _get_db()
    success = db.update_routing_rule(rule_id, outbound, priority, enabled)

    if not success:
        raise HTTPException(status_code=404, detail=f"规则 ID {rule_id} 不存在")

    return {"message": f"规则 ID {rule_id} 已更新"}


# Legacy /api/db/* endpoints removed - GeoIP data now served from JSON catalogs via /api/ip-catalog
# Domain data served from JSON catalog via /api/domain-catalog


# ============ Peer Node API Endpoints ============


# === Peer Tunnel IP Allocation ===

# 隧道 IP 子网基址
PEER_TUNNEL_SUBNET_BASE = "10.200.200"
# 最大 /30 子网数量 (每个子网 4 个 IP: .0=网络, .1=主机1, .2=主机2, .3=广播)
# 256 addresses / 4 per subnet = 64 subnets (indices 0-63)
# Subnet 0: .0-.3 (hosts .1, .2), Subnet 63: .252-.255 (hosts .253, .254)
MAX_PEER_TUNNEL_SUBNETS = 64


def _extract_subnet_idx_from_ip(ip_str: str) -> int:
    """从隧道 IP 地址提取 /30 子网索引

    Args:
        ip_str: IP 地址字符串 (如 "10.200.200.5")

    Returns:
        子网索引 (0, 1, 2, ...)，失败返回 -1
    """
    if not ip_str:
        return -1
    try:
        # 去除可能的 CIDR 前缀
        ip = ip_str.split("/")[0]
        parts = ip.split(".")
        if len(parts) != 4:
            return -1
        # 验证前三个八位组匹配子网基址
        if ".".join(parts[:3]) != PEER_TUNNEL_SUBNET_BASE:
            return -1
        last_octet = int(parts[3])
        # 子网索引: .1/.2 → 0, .5/.6 → 1, .9/.10 → 2, ...
        # 计算公式: (last_octet - 1) // 4
        if last_octet < 1 or last_octet > 254:
            return -1
        return (last_octet - 1) // 4
    except (ValueError, IndexError):
        return -1


def _get_next_peer_tunnel_subnet(db, local_node_tag: str = None, remote_node_tag: str = None) -> tuple:
    """获取下一个可用的 /30 子网

    Phase 11-Fix.A 增强版：支持确定性分配以避免多节点场景下的冲突。

    当提供 local_node_tag 和 remote_node_tag 时，使用确定性算法：
    1. 基于节点对的哈希值计算起始子网索引
    2. 从该索引开始搜索可用子网
    这确保无论连接方向如何，同一对节点始终使用相同子网。

    Args:
        db: 数据库连接
        local_node_tag: 本地节点标识（可选，用于确定性分配）
        remote_node_tag: 远程节点标识（可选，用于确定性分配）

    Returns:
        (subnet_idx, local_ip, peer_ip) 元组
        如 (1, "10.200.200.5", "10.200.200.6")

    Raises:
        HTTPException: 所有子网已用尽
    """
    import hashlib

    # 收集所有已使用的子网索引
    used_subnets = set()
    existing_nodes = db.get_peer_nodes()

    for node in existing_nodes:
        # 检查 tunnel_local_ip
        local_ip = node.get("tunnel_local_ip")
        if local_ip:
            idx = _extract_subnet_idx_from_ip(local_ip)
            if idx >= 0:
                used_subnets.add(idx)

        # 检查 tunnel_remote_ip (对端 IP 也占用了子网的另一半)
        remote_ip = node.get("tunnel_remote_ip")
        if remote_ip:
            idx = _extract_subnet_idx_from_ip(remote_ip)
            if idx >= 0:
                used_subnets.add(idx)

    logging.debug(f"[peer-tunnel-ip] 已使用子网: {sorted(used_subnets)}")

    # 确定起始搜索索引
    if local_node_tag and remote_node_tag:
        # 确定性分配：基于节点对哈希值
        # 排序确保无论连接方向如何结果一致
        pair_key = "|".join(sorted([local_node_tag, remote_node_tag]))
        hash_value = int(hashlib.md5(pair_key.encode()).hexdigest()[:8], 16)
        start_idx = hash_value % MAX_PEER_TUNNEL_SUBNETS
        logging.debug(f"[peer-tunnel-ip] 确定性分配: pair={pair_key}, start_idx={start_idx}")
    else:
        # 向后兼容：从 0 开始
        start_idx = 0

    # 从起始索引开始搜索可用子网
    for offset in range(MAX_PEER_TUNNEL_SUBNETS):
        subnet_idx = (start_idx + offset) % MAX_PEER_TUNNEL_SUBNETS
        if subnet_idx not in used_subnets:
            # 计算 IP 地址: .1 和 .2 为子网的两个有效主机地址
            subnet_base = subnet_idx * 4
            local_ip = f"{PEER_TUNNEL_SUBNET_BASE}.{subnet_base + 1}"
            peer_ip = f"{PEER_TUNNEL_SUBNET_BASE}.{subnet_base + 2}"
            logging.info(f"[peer-tunnel-ip] 分配子网 {subnet_idx}: {local_ip}/30 (peer: {peer_ip})")
            return (subnet_idx, local_ip, peer_ip)

    # 所有子网已用尽
    logging.error(f"[peer-tunnel-ip] All {MAX_PEER_TUNNEL_SUBNETS} /30 subnets exhausted, used indices: {sorted(used_subnets)}")
    raise HTTPException(
        status_code=500,
        detail=f"No available tunnel IP (all {MAX_PEER_TUNNEL_SUBNETS} /30 subnets exhausted)"
    )


def _calculate_peer_ip_from_local(local_ip: str) -> str:
    """根据本地隧道 IP 计算对端 IP

    在同一个 /30 子网中，.1 对应 .2，.2 对应 .1

    Args:
        local_ip: 本地隧道 IP (如 "10.200.200.5")

    Returns:
        对端 IP (如 "10.200.200.6")
    """
    try:
        parts = local_ip.rsplit(".", 1)
        if len(parts) != 2:
            return None
        base = parts[0]
        last_octet = int(parts[1])

        # 计算子网内的位置: .1, .2, .5, .6, .9, .10, ...
        # 子网起始偏移: 0, 4, 8, 12, ...
        subnet_offset = ((last_octet - 1) // 4) * 4
        pos_in_subnet = last_octet - subnet_offset  # 1 或 2

        if pos_in_subnet == 1:
            peer_last = subnet_offset + 2
        else:
            peer_last = subnet_offset + 1

        return f"{base}.{peer_last}"
    except (ValueError, IndexError) as e:
        logging.error(f"[peer-tunnel-ip] 计算对端 IP 失败: {local_ip}, 错误: {e}")
        return None


# NOTE: /api/peer-auth/validate endpoint has been removed.
# PSK authentication is deprecated. Use tunnel IP authentication (WireGuard) or UUID authentication (Xray).


def _find_peer_node_by_ip(db, client_ip: str):
    """通过源 IP 查找对等节点

    遍历所有节点，检查 endpoint 或 tunnel_remote_ip 是否匹配该 IP。
    支持不同 tag 的互联场景。

    Phase 11-Fix.C3: 增加 tunnel_remote_ip 检查，支持隧道内 API 调用
    当请求通过隧道到达时，client_ip 是隧道 IP（如 10.200.200.242），
    而不是外部 endpoint IP（如 10.1.100.11）。
    """
    all_nodes = db.get_peer_nodes()
    for node in all_nodes:
        # 优先检查 tunnel_remote_ip（隧道内请求）
        tunnel_remote_ip = node.get("tunnel_remote_ip", "")
        if tunnel_remote_ip:
            # tunnel_remote_ip 格式: "10.200.200.242/30" 或 "10.200.200.242"
            tunnel_ip_clean = tunnel_remote_ip.split("/")[0]
            if tunnel_ip_clean == client_ip:
                logging.debug(f"[peer-lookup] 通过 tunnel_remote_ip 找到节点: {node.get('tag')}")
                return node

        # 其次检查 endpoint（外部 IP 请求）
        endpoint = node.get("endpoint", "")
        # endpoint 格式: "ip:port" 或 "hostname:port"
        if ":" in endpoint:
            endpoint_host = endpoint.rsplit(":", 1)[0]
        else:
            endpoint_host = endpoint
        if endpoint_host == client_ip:
            logging.debug(f"[peer-lookup] 通过 endpoint 找到节点: {node.get('tag')}")
            return node
    return None


def _resolve_peer_node(db, node_identifier: str, fallback_ip: str = None) -> Optional[dict]:
    """解析节点标识符到本地 peer_node

    Phase 11-Fix.D: 支持多种查找方式

    尝试多种查找方式:
    1. 精确 tag 匹配
    2. 通过 endpoint hostname 匹配
    3. 通过 remote_hostname 字段匹配
    4. 通过隧道 IP 匹配 (fallback)

    Args:
        db: 数据库实例
        node_identifier: 节点标识符（可以是 tag、hostname 等）
        fallback_ip: 回退 IP（用于最后的 IP 匹配）

    Returns:
        匹配的节点信息字典，或 None
    """
    # 1. 精确 tag 匹配
    node = db.get_peer_node(node_identifier)
    if node:
        logging.debug(f"[resolve-peer] 精确匹配 tag: {node_identifier}")
        return node

    # 2. 遍历查找 endpoint 或 hostname
    for peer in db.get_peer_nodes():
        # 检查 endpoint 中的 hostname
        endpoint = peer.get("endpoint", "")
        if ":" in endpoint:
            ep_host = endpoint.rsplit(":", 1)[0]
            if ep_host == node_identifier:
                logging.debug(f"[resolve-peer] 通过 endpoint hostname 找到: {peer.get('tag')}")
                return peer

        # 检查 remote_hostname 字段（如果有）
        if peer.get("remote_hostname") == node_identifier:
            logging.debug(f"[resolve-peer] 通过 remote_hostname 找到: {peer.get('tag')}")
            return peer

    # 3. Fallback: 通过 IP 查找
    if fallback_ip:
        node = _find_peer_node_by_ip(db, fallback_ip)
        if node:
            logging.debug(f"[resolve-peer] 通过 fallback IP 找到: {node.get('tag')}")
            return node

    logging.debug(f"[resolve-peer] 未找到节点: {node_identifier}")
    return None


# NOTE: /api/peer-auth/exchange endpoint has been removed.
# PSK authentication is deprecated. Use tunnel IP authentication (WireGuard) or UUID authentication (Xray).


@app.post("/api/peer-notify/connected")
def api_peer_notify_connected(request: Request, payload: PeerNotifyRequest):
    """接收远程节点的连接通知

    当远程节点完成隧道建立后调用此端点，通知本节点也建立其侧的隧道。
    这实现了双向连接同步。

    认证方式: 隧道 IP 认证 (WireGuard) 或 UUID 认证 (Xray)
    """
    client_ip = _get_client_ip(request)

    # 速率限制检查
    if not _check_api_rate_limit(client_ip):
        raise HTTPException(
            status_code=429,
            detail="Too many requests, please try again later"
        )

    if not HAS_DATABASE or not USER_DB_PATH.exists():
        raise HTTPException(status_code=503, detail="Database unavailable")

    db = _get_db()

    # Phase 11-Fix.M: 使用灵活认证函数
    # 认证方式：隧道 IP 认证（WireGuard）或 UUID 认证（Xray）
    # PSK 认证已废弃（Phase 11-Fix.N），所有节点间通信使用隧道认证
    node = _verify_peer_request_flexible(
        request, db,
        payload_node_id=payload.node_id
    )
    if not node:
        raise HTTPException(status_code=401, detail="Authentication failed")

    tag = node["tag"]
    tunnel_type = node.get("tunnel_type", "wireguard")
    current_status = node.get("tunnel_status", "disconnected")

    logging.info(f"[peer-notify] 收到连接通知: 节点 '{tag}', 当前状态={current_status} (from {client_ip})")

    # 如果已经连接，直接返回成功
    if current_status == "connected":
        return {"success": True, "message": "Already connected", "status": "connected"}

    # 更新发起方的参数（如果提供）
    if payload.initiator_public_key:
        db.update_peer_node(
            tag,
            wg_peer_public_key=payload.initiator_public_key,
            tunnel_remote_ip=payload.initiator_tunnel_ip,
        )
        # 重新获取更新后的节点信息
        node = db.get_peer_node(tag)

    # 检查是否有建立隧道所需的参数
    if tunnel_type == "wireguard":
        if not node.get("wg_private_key"):
            logging.warning(f"[peer-notify] 节点 '{tag}' 缺少本地私钥，需要先进行参数交换")
            raise HTTPException(
                status_code=400,
                detail="Missing local private key. Key exchange required first."
            )
        if not node.get("wg_peer_public_key"):
            logging.warning(f"[peer-notify] 节点 '{tag}' 缺少对端公钥")
            raise HTTPException(
                status_code=400,
                detail="Missing peer public key. Provide initiator_public_key or complete key exchange first."
            )

    # 建立本地隧道
    try:
        from peer_tunnel_manager import PeerTunnelManager
        manager = PeerTunnelManager()
        success = manager.connect_node(tag)

        if success:
            logging.info(f"[peer-notify] 节点 '{tag}' 隧道已建立（响应远程通知）")
            return {"success": True, "message": "Tunnel established", "status": "connected"}
        else:
            updated_node = db.get_peer_node(tag)
            internal_error = updated_node.get("last_error", "Unknown error")
            logging.error(f"[peer-notify] 节点 '{tag}' 隧道建立失败: {internal_error}")
            # 不暴露内部错误详情给客户端
            raise HTTPException(status_code=500, detail="Tunnel setup failed")
    except HTTPException:
        raise
    except Exception as e:
        logging.exception(f"[peer-notify] 节点 '{tag}' 隧道建立异常: {e}")
        # 不暴露内部异常详情给客户端
        raise HTTPException(status_code=500, detail="Internal tunnel error")


@app.post("/api/peer-notify/disconnected")
def api_peer_notify_disconnected(request: Request, payload: PeerNotifyRequest):
    """接收远程节点的断开通知

    当远程节点断开隧道时调用此端点，通知本节点也断开其侧的隧道。
    这实现了双向断开同步。

    认证方式: 隧道 IP 认证 (WireGuard) 或 UUID 认证 (Xray)
    """
    client_ip = _get_client_ip(request)

    # 速率限制检查
    if not _check_api_rate_limit(client_ip):
        raise HTTPException(
            status_code=429,
            detail="Too many requests, please try again later"
        )

    if not HAS_DATABASE or not USER_DB_PATH.exists():
        raise HTTPException(status_code=503, detail="Database unavailable")

    db = _get_db()

    # Phase 11-Fix.M: 使用灵活认证函数
    # 注意：require_psk=False 允许新配对节点（无 PSK）使用隧道 IP 认证
    # 断开通知通常在隧道断开前发送，此时隧道可能还在
    # 对于无 PSK 的节点：如果隧道已连接，使用 IP 认证；否则认证失败（可接受）
    node = _verify_peer_request_flexible(
        request, db,
        payload_node_id=payload.node_id
    )
    if not node:
        raise HTTPException(status_code=401, detail="Authentication failed")

    tag = node["tag"]
    current_status = node.get("tunnel_status", "disconnected")

    logging.info(f"[peer-notify] 收到断开通知: 节点 '{tag}', 当前状态={current_status} (from {client_ip})")

    # 如果已经断开，直接返回成功
    if current_status == "disconnected":
        return {"success": True, "message": "Already disconnected", "status": "disconnected"}

    # 断开本地隧道
    try:
        from peer_tunnel_manager import PeerTunnelManager
        manager = PeerTunnelManager()
        success = manager.disconnect_node(tag)

        # Phase 5: 更新使用该节点的链路状态
        chain_result = _update_chains_for_disconnected_peer(db, tag)
        chains_updated = chain_result.get("updated", [])

        # Phase 11-Fix.V.5: 使客户端缓存失效
        try:
            from tunnel_api_client import TunnelAPIClientManager
            client_mgr = TunnelAPIClientManager(db)
            client_mgr.invalidate_client(tag)
        except Exception as cache_err:
            logging.debug(f"[peer-notify] 清除客户端缓存失败: {cache_err}")

        if success:
            logging.info(f"[peer-notify] 节点 '{tag}' 隧道已断开（响应远程通知）")
            return {
                "success": True,
                "message": "Tunnel disconnected",
                "status": "disconnected",
                "chains_updated": chains_updated,  # Phase 5
            }
        else:
            # 断开失败也更新状态（可能接口已经不存在）
            db.update_peer_node(tag, tunnel_status="disconnected")
            return {
                "success": True,
                "message": "Tunnel marked as disconnected",
                "status": "disconnected",
                "chains_updated": chains_updated,  # Phase 5
            }
    except Exception as e:
        logging.warning(f"[peer-notify] 节点 '{tag}' 断开异常: {e}")
        # 异常情况下也标记为断开
        db.update_peer_node(tag, tunnel_status="disconnected")
        # Phase 11-Fix.V.5: 使客户端缓存失效
        try:
            from tunnel_api_client import TunnelAPIClientManager
            client_mgr = TunnelAPIClientManager(db)
            client_mgr.invalidate_client(tag)
        except Exception:
            pass
        # Phase 5: 即使断开异常，也要更新链路状态
        chain_result = _update_chains_for_disconnected_peer(db, tag)
        return {
            "success": True,
            "message": "Tunnel marked as disconnected",
            "status": "disconnected",
            "chains_updated": chain_result.get("updated", []),  # Phase 5
        }


@app.post("/api/peer-tunnel/reverse-setup")
def api_peer_tunnel_reverse_setup(request: Request, payload: ReverseSetupRequest):
    """Phase 11.2: 请求建立反向连接

    当节点 A 完成配对并连接到节点 B 后，A 通过隧道调用此 API，
    请求 B 也建立到 A 的连接，实现双向自动连接。

    认证方式: 隧道 IP/UUID (无需 JWT，通过隧道连接认证)

    流程:
    1. A 导入 B 的配对请求，创建 peer_node
    2. A 调用 B 的 /api/peer-auth/exchange 获取隧道参数
    3. A 建立到 B 的隧道 (WireGuard/Xray)
    4. A 通过隧道调用 B 的此 API
    5. B 收到请求，使用 A 提供的参数建立反向连接
    6. 双向连接完成，两端都更新 bidirectional_status = "bidirectional"
    """
    # 安全关键：使用直连 IP 进行隧道认证，忽略可伪造的代理头
    client_ip = _get_direct_client_ip(request)

    # 速率限制检查
    if not _check_api_rate_limit(client_ip):
        raise HTTPException(
            status_code=429,
            detail="Too many requests, please try again later"
        )

    if not HAS_DATABASE or not USER_DB_PATH.exists():
        raise HTTPException(status_code=503, detail="Database unavailable")

    db = _get_db()

    # 通过源 IP 查找对应的节点
    # 由于这个请求来自隧道内，源 IP 应该是隧道的 remote_ip
    node = _find_peer_node_by_ip(db, client_ip)
    if not node:
        # 尝试通过隧道 IP 匹配
        nodes = db.get_peer_nodes()
        for n in nodes:
            if n.get("tunnel_remote_ip") == client_ip:
                node = n
                break

    if not node:
        # HIGH-1 修复: 通过 node_id 查找时也验证 IP
        candidate = db.get_peer_node(payload.node_id)
        if candidate:
            # 验证客户端 IP 与节点的 endpoint 或 tunnel_remote_ip 匹配
            tunnel_remote = candidate.get("tunnel_remote_ip", "")
            endpoint = candidate.get("endpoint", "")
            endpoint_host = endpoint.split(":")[0] if ":" in endpoint else endpoint
            if tunnel_remote == client_ip or endpoint_host == client_ip:
                node = candidate
            else:
                logging.warning(f"[reverse-setup] node_id '{payload.node_id}' IP 不匹配 "
                              f"(client={client_ip}, tunnel_remote={tunnel_remote}, endpoint_host={endpoint_host})")

    if not node:
        logging.warning(f"[reverse-setup] 请求失败: 未找到匹配节点 (from {client_ip}, node_id={payload.node_id})")
        raise HTTPException(status_code=401, detail="Unknown peer")

    # PSK 已废弃 - 现在使用隧道 IP 认证（WireGuard）或 UUID 认证（Xray）
    # 由于已通过 _find_peer_node_by_ip 或 tunnel_remote_ip 匹配找到节点，
    # 对于 WireGuard 隧道来说，IP 匹配本身就是认证
    tunnel_type = node.get("tunnel_type", "wireguard")
    if tunnel_type == "xray":
        # Xray 隧道需要验证 X-Peer-UUID header
        peer_uuid = request.headers.get("X-Peer-UUID", "")
        expected_uuid = node.get("inbound_uuid", "")  # 我们给对方分配的 UUID
        if not peer_uuid or peer_uuid != expected_uuid:
            logging.warning(f"[reverse-setup] Xray UUID 验证失败 (from {client_ip}, "
                          f"got='{peer_uuid[:8]}...', expected='{expected_uuid[:8]}...')")
            raise HTTPException(status_code=401, detail="Authentication failed")
    # WireGuard 隧道：IP 匹配已完成认证，无需额外验证

    tag = node["tag"]
    current_status = node.get("tunnel_status", "disconnected")
    bidirectional_status = node.get("bidirectional_status")

    logging.info(f"[reverse-setup] 收到反向连接请求: 节点 '{tag}', 隧道类型={tunnel_type}, "
                 f"当前状态={current_status}, 双向状态={bidirectional_status} (from {client_ip})")

    # 更新对端的 WireGuard 参数（如果提供）
    if tunnel_type == "wireguard" and payload.wg_public_key:
        update_params = {
            "wg_peer_public_key": payload.wg_public_key,
        }
        # 更新 endpoint（如果对方提供）
        if payload.endpoint:
            update_params["endpoint"] = payload.endpoint

        db.update_peer_node(tag, **update_params)
        logging.info(f"[reverse-setup] 更新节点 '{tag}' 的 WireGuard 参数")

    # 如果已经是双向连接，直接返回成功
    if bidirectional_status == "bidirectional" and current_status == "connected":
        return {
            "success": True,
            "message": "Already bidirectional",
            "status": "bidirectional",
            "tunnel_status": current_status
        }

    # 尝试建立连接
    try:
        from peer_tunnel_manager import PeerTunnelManager
        manager = PeerTunnelManager()

        # 刷新节点数据（可能已更新）
        node = db.get_peer_node(tag)

        if current_status != "connected":
            # 建立隧道连接
            # 注：不需要再通知对方，因为对方调用了此 API 说明已经知道我们要连接
            success = manager.connect_node(tag)
            if success:
                current_status = "connected"
                logging.info(f"[reverse-setup] 节点 '{tag}' 隧道已建立")
            else:
                logging.warning(f"[reverse-setup] 节点 '{tag}' 隧道建立失败")
                return {
                    "success": False,
                    "message": "Failed to establish tunnel",
                    "status": bidirectional_status or "pending",
                    "tunnel_status": current_status
                }

        # 更新双向连接状态
        db.update_peer_node(tag, bidirectional_status="bidirectional")
        logging.info(f"[reverse-setup] 节点 '{tag}' 双向连接已建立")

        return {
            "success": True,
            "message": "Bidirectional connection established",
            "status": "bidirectional",
            "tunnel_status": "connected"
        }

    except Exception as e:
        # HIGH-2 修复: 不暴露异常详情，只返回通用错误消息
        logging.error(f"[reverse-setup] 节点 '{tag}' 反向连接失败: {e}")
        return {
            "success": False,
            "message": "Connection failed",  # 通用错误消息，不暴露内部详情
            "status": bidirectional_status or "pending",
            "tunnel_status": current_status
        }


@app.post("/api/peer-tunnel/complete-handshake")
def api_peer_tunnel_complete_handshake(request: Request, payload: CompleteHandshakeRequest):
    """Phase 11-Tunnel: 完成隧道优先配对

    当 Node B 导入 Node A 的配对码并建立隧道后，
    B 通过隧道调用此 API 通知 A 完成配对流程。

    认证方式:
    - 通过 pairing_id 匹配 pending_pairing 记录
    - 验证请求来自预期的隧道 IP (tunnel_remote_ip)

    流程:
    1. B 导入 A 的配对码
    2. B 使用预生成密钥创建 WireGuard 接口
    3. B 连接到 A（A 的 pending 接口正在监听）
    4. 隧道建立后，B 通过隧道调用此 API
    5. A 验证请求，创建 peer_node 记录
    6. A 重命名 pending 接口为永久接口
    7. A 更新 WireGuard peer 的 endpoint
    8. A 删除 pending_pairing 记录
    9. 配对完成，双方都有 peer_node 记录
    """
    # 安全关键：使用直连 IP 进行隧道认证，忽略可伪造的代理头
    client_ip = _get_direct_client_ip(request)

    # 速率限制检查
    if not _check_api_rate_limit(client_ip):
        raise HTTPException(
            status_code=429,
            detail="Too many requests, please try again later"
        )

    if not HAS_DATABASE or not USER_DB_PATH.exists():
        raise HTTPException(status_code=503, detail="Database unavailable")

    db = _get_db()

    # Step 1: 根据 pairing_id 查找 pending_pairing 记录
    pending = db.get_pending_pairing(payload.pairing_id)
    if not pending:
        logging.warning(f"[complete-handshake] 未找到待处理配对: pairing_id={payload.pairing_id} (from {client_ip})")
        return {"success": False, "message": "Pending pairing not found"}

    logging.info(f"[complete-handshake] 收到握手请求: pairing_id={payload.pairing_id}, "
                f"from={client_ip}, node_tag={payload.node_tag}")

    # Step 2: 验证请求来自预期的隧道 IP
    # Node B 应该使用 pending.tunnel_remote_ip 作为自己的隧道 IP
    expected_ip = pending.get("tunnel_remote_ip")
    if expected_ip and client_ip != expected_ip:
        logging.warning(f"[complete-handshake] IP 不匹配: expected={expected_ip}, got={client_ip}")
        return {"success": False, "message": "IP verification failed"}

    # Step 3: 验证公钥匹配（确保是预期的 Node B）
    expected_public_key = pending.get("remote_wg_public_key")
    if expected_public_key and payload.wg_public_key != expected_public_key:
        logging.warning(f"[complete-handshake] 公钥不匹配")
        return {"success": False, "message": "Public key mismatch"}

    # Step 4: 检查是否已存在同名节点
    existing = db.get_peer_node(payload.node_tag)
    if existing:
        logging.warning(f"[complete-handshake] 节点已存在: {payload.node_tag}")
        return {"success": False, "message": f"Peer node '{payload.node_tag}' already exists"}

    try:
        # Step 5: 获取 pending 接口信息
        pending_interface = pending.get("interface_name")
        local_tag = pending.get("local_tag")  # Node A 的 tag
        local_ip = pending.get("tunnel_local_ip")
        remote_ip = pending.get("tunnel_remote_ip")
        tunnel_port = pending.get("tunnel_port")

        # Step 6: 重命名 pending 接口为永久接口
        permanent_interface = get_interface_name(payload.node_tag, "wireguard")

        if pending_interface and HAS_PENDING_TUNNEL:
            success = rename_wireguard_interface(pending_interface, permanent_interface)
            if not success:
                logging.warning(f"[complete-handshake] 接口重命名失败: {pending_interface} -> {permanent_interface}")
                # 继续执行，接口可能已被重命名

        # Step 7: 更新 WireGuard peer 的 endpoint
        # 这样 A 也可以主动发起连接到 B
        if payload.endpoint and payload.wg_public_key:
            update_wireguard_peer_endpoint(
                interface=permanent_interface,
                peer_public_key=payload.wg_public_key,
                endpoint=payload.endpoint
            )

        # Step 8: 创建 peer_node 记录（在 Node A 上记录 Node B 的信息）
        db.add_peer_node(
            tag=payload.node_tag,
            name=payload.node_tag,
            description=payload.node_description or f"Paired via tunnel",
            endpoint=payload.endpoint,
            api_port=payload.api_port,  # Phase 11-Fix.K: 保存 API 端口
            tunnel_type="wireguard",
            tunnel_status="connected",
            tunnel_interface=permanent_interface,
            tunnel_local_ip=local_ip,
            tunnel_remote_ip=remote_ip,
            tunnel_port=tunnel_port,
            wg_private_key=pending.get("wg_private_key"),
            wg_public_key=pending.get("wg_public_key"),  # A 的公钥
            wg_peer_public_key=payload.wg_public_key,  # B 的公钥
            # Phase 11-Fix.K: 使用正确的 api_port
            tunnel_api_endpoint=f"{remote_ip}:{payload.api_port or DEFAULT_WEB_PORT}",
            bidirectional_status="bidirectional",
        )

        logging.info(f"[complete-handshake] 创建节点成功: {payload.node_tag}")

        # Step 9: 删除 pending_pairing 记录
        db.delete_pending_pairing(payload.pairing_id)

        logging.info(f"[complete-handshake] 配对完成: {payload.node_tag} (interface={permanent_interface})")

        return {
            "success": True,
            "message": "Handshake completed",
            "node_tag": local_tag,  # 返回 A 的 tag 给 B
            "tunnel_status": "connected"
        }

    except Exception as e:
        logging.error(f"[complete-handshake] 处理失败: {e}")
        return {
            "success": False,
            "message": "Handshake processing failed"
        }


@app.post("/api/peer-tunnel/peer-event")
def api_peer_tunnel_peer_event(request: Request, payload: PeerEventRequest):
    """Phase 11-Cascade: 接收对等节点事件通知

    当节点删除或断开另一个节点时，通过隧道调用此 API 通知对方。
    支持级联广播，让所有连接的节点得知变更。

    认证方式：
    - WireGuard 隧道：通过 tunnel_remote_ip 验证（IP 即身份）
    - Xray 隧道：通过 X-Peer-UUID header 验证

    事件类型：
    - delete: A 删除 B，通知 B 清理与 A 的连接
    - disconnect: A 断开与 B 的隧道（可能重连）
    - broadcast: A 广播某节点不可用（级联通知）
    - port_change: A 的 API 端口变更，通知 B 更新记录 (Phase B)

    流程：
    1. 验证请求来自已连接的 peer
    2. 检查幂等性 (event_id)
    3. 检查墓碑状态
    4. 处理事件（断开隧道、添加墓碑等）
    5. 可选：广播给其他连接的 peer
    """
    import uuid
    from threading import Thread

    # 安全关键：使用直连 IP 进行隧道认证，忽略可伪造的代理头
    client_ip = _get_direct_client_ip(request)

    # 速率限制检查 (M-1: 防止 DoS 攻击)
    if not _check_api_rate_limit(client_ip):
        logging.warning(f"[peer-event] 速率限制: {client_ip}")
        raise HTTPException(
            status_code=429,
            detail="Too many requests, please try again later"
        )

    if not HAS_DATABASE or not USER_DB_PATH.exists():
        raise HTTPException(status_code=503, detail="Database unavailable")

    db = _get_db()

    logging.info(f"[peer-event] 收到事件: type={payload.event_type}, source={payload.source_node}, "
                 f"target={payload.target_node}, event_id={payload.event_id[:8]}..., from={client_ip}")

    # Step 1: 验证请求来自已知 peer（通过隧道 IP 或 UUID）
    authenticated_peer = None
    peer_uuid_header = request.headers.get("X-Peer-UUID", "")

    for peer in db.get_peer_nodes():
        # WireGuard: 检查隧道远程 IP
        if peer.get("tunnel_remote_ip") == client_ip:
            authenticated_peer = peer
            break
        # Xray: 检查 UUID
        if peer_uuid_header and peer.get("inbound_uuid") == peer_uuid_header:
            authenticated_peer = peer
            break

    if not authenticated_peer:
        logging.warning(f"[peer-event] 未授权: IP={client_ip}, UUID={peer_uuid_header[:8]}...")
        return JSONResponse(
            status_code=403,
            content={"success": False, "message": "Unauthorized: not from a connected peer"}
        )

    peer_tag = authenticated_peer.get("tag")
    logging.info(f"[peer-event] 已认证 peer: {peer_tag}")

    # Step 2: 前置验证（在标记事件之前验证，避免标记后验证失败）
    if payload.event_type == "broadcast" and not payload.target_node:
        logging.warning(f"[peer-event] 广播事件缺少 target_node")
        return {"success": False, "message": "target_node required for broadcast event"}

    # Step 3: 检查源节点是否在墓碑期（忽略来自已删除节点的事件）
    if db.is_peer_tombstoned(payload.source_node):
        logging.warning(f"[peer-event] 忽略来自墓碑节点的事件: {payload.source_node}")
        return {"success": False, "message": f"Source node '{payload.source_node}' is tombstoned"}

    # Step 4: 原子幂等性检查和标记（防止 TOCTOU 竞态条件）
    was_processed, now_marked = db.mark_event_if_not_processed(
        payload.event_id, payload.source_node, payload.event_type
    )
    if was_processed:
        logging.info(f"[peer-event] 事件已处理 (幂等): {payload.event_id[:8]}...")
        return {"success": True, "message": "Event already processed", "idempotent": True}

    # Step 5: 记录事件到审计日志
    db.log_peer_event(
        event_type="received",
        peer_tag=payload.source_node,
        event_id=payload.event_id,
        from_node=peer_tag,
        details={"original_type": payload.event_type, "target": payload.target_node, "reason": payload.reason},
        source_ip=client_ip
    )

    # Step 6: 根据事件类型处理
    result = {"success": True, "actions_taken": []}

    if payload.event_type == "delete":
        # 对方节点删除了我们，我们需要清理与对方的连接
        # 使用 peer_tag（从隧道 IP 认证的本地 peer 标识）而不是 payload.source_node
        # 因为 payload.source_node 是对方的 hostname，可能与本地存储的 tag 不同
        source_peer = authenticated_peer  # 直接使用已认证的 peer
        if source_peer:
            logging.info(f"[peer-event] 处理删除事件: 清理与 {peer_tag} 的连接 (source_node={payload.source_node})")

            # 断开隧道（如果已连接）
            if source_peer.get("tunnel_status") == "connected":
                try:
                    from peer_tunnel_manager import disconnect_peer_tunnel
                    disconnect_peer_tunnel(db, peer_tag)
                    result["actions_taken"].append(f"disconnected tunnel to {peer_tag}")
                except Exception as e:
                    logging.error(f"[peer-event] 断开隧道失败: {e}")

            # 添加墓碑，防止对方重连 (L-2: 错误不应阻止删除操作)
            try:
                db.add_peer_tombstone(
                    tag=peer_tag,
                    deleted_by=payload.source_node,  # 记录原始 source_node 供审计
                    reason=payload.reason or "remote_delete"
                )
                result["actions_taken"].append(f"tombstoned {peer_tag}")
            except Exception as e:
                logging.exception(f"[peer-event] 添加墓碑失败 (非致命): {e}")
                result["actions_taken"].append(f"tombstone failed for {peer_tag}")

            # 删除本地 peer_node 记录
            db.delete_peer_node(peer_tag)
            result["actions_taken"].append(f"deleted peer_node {peer_tag}")

        result["message"] = f"Processed delete event from {peer_tag} (source={payload.source_node})"

    elif payload.event_type == "disconnect":
        # 对方断开连接（可能重连）
        # 同样使用 peer_tag 而不是 payload.source_node
        source_peer = authenticated_peer
        if source_peer:
            logging.info(f"[peer-event] 处理断开事件: 更新 {peer_tag} 状态 (source_node={payload.source_node})")
            db.update_peer_node(peer_tag, tunnel_status="disconnected")
            result["actions_taken"].append(f"updated status of {peer_tag}")

            # Phase 5: 更新使用该节点的链路状态
            chain_result = _update_chains_for_disconnected_peer(db, peer_tag)
            if chain_result.get("updated"):
                result["actions_taken"].append(f"updated {len(chain_result['updated'])} chains to error state")

        result["message"] = f"Processed disconnect event from {payload.source_node}"

    elif payload.event_type == "broadcast":
        # 广播事件：某节点不可用 (target_node 已在 Step 2 验证)
        logging.info(f"[peer-event] 处理广播事件: {payload.target_node} 不可用 (来自 {payload.source_node})")

        # 检查我们是否有到 target_node 的连接
        target_peer = db.get_peer_node(payload.target_node)
        if target_peer:
            # 更新状态为 disconnected
            db.update_peer_node(payload.target_node, tunnel_status="disconnected")
            result["actions_taken"].append(f"marked {payload.target_node} as disconnected")

        # 添加墓碑 (L-2: 错误不应阻止广播处理)
        try:
            db.add_peer_tombstone(
                tag=payload.target_node,
                deleted_by=payload.source_node,
                reason=payload.reason or "broadcast_notification"
            )
            result["actions_taken"].append(f"tombstoned {payload.target_node}")
        except Exception as e:
            logging.exception(f"[peer-event] 添加墓碑失败 (非致命): {e}")
            result["actions_taken"].append(f"tombstone failed for {payload.target_node}")

        result["message"] = f"Processed broadcast: {payload.target_node} unavailable"

    elif payload.event_type == "port_change":
        # Phase B: 对方节点的 API 端口变更了
        # 从 details 中提取新端口，更新本地记录，使缓存失效
        new_port = None
        if payload.details and isinstance(payload.details, dict):
            new_port = payload.details.get("new_port")

        # Phase B 审核修复: 添加 bool 类型排除 (与 Phase A 保持一致)
        if not new_port or not isinstance(new_port, int) or isinstance(new_port, bool) or new_port < 1 or new_port > 65535:
            logging.warning(f"[peer-event] port_change 事件缺少有效的 new_port: {payload.details}")
            result["success"] = False
            result["message"] = "port_change event requires valid new_port in details"
        else:
            logging.info(f"[peer-event] 处理端口变更事件: {peer_tag} 新端口 {new_port}")

            # 更新本地 peer_node 的 api_port
            db.update_peer_node(peer_tag, api_port=new_port)
            result["actions_taken"].append(f"updated api_port of {peer_tag} to {new_port}")

            # 使 TunnelAPIClientManager 缓存失效
            try:
                from tunnel_api_client import TunnelAPIClientManager
                client_mgr = TunnelAPIClientManager(db)
                client_mgr.invalidate_client(peer_tag)
                result["actions_taken"].append(f"invalidated client cache for {peer_tag}")
            except Exception as e:
                logging.warning(f"[peer-event] 清除客户端缓存失败: {e}")

            result["message"] = f"Processed port_change: {peer_tag} now uses port {new_port}"

    # Step 7: 继续广播给其他连接的 peer（如果 TTL > 0）
    if payload.ttl > 0 and payload.event_type in ("delete", "broadcast"):
        def _broadcast_to_peers():
            """后台线程：将事件广播给其他连接的 peer"""
            try:
                from tunnel_api_client import TunnelAPIClient

                # 获取新的数据库连接（避免线程安全问题，不使用闭包捕获的 db）
                thread_db = get_db(_GEOIP_PATH, _USER_DB_PATH)

                broadcast_target = payload.target_node or payload.source_node
                new_ttl = payload.ttl - 1

                for other_peer in thread_db.get_peer_nodes():
                    other_tag = other_peer.get("tag")

                    # 跳过：自己、事件源、事件目标
                    if other_tag in (payload.source_node, broadcast_target, peer_tag):
                        continue

                    # 跳过未连接的 peer
                    if other_peer.get("tunnel_status") != "connected":
                        continue

                    try:
                        # Phase A: 动态构建隧道 API 端点
                        tunnel_api = _get_peer_tunnel_endpoint(other_peer)
                        if not tunnel_api:
                            continue

                        tunnel_type = other_peer.get("tunnel_type", "wireguard")
                        socks_port = other_peer.get("xray_socks_port") if tunnel_type == "xray" else None

                        peer_uuid = other_peer.get("xray_uuid") if tunnel_type == "xray" else None
                        client = TunnelAPIClient(
                            node_tag=other_tag,
                            tunnel_endpoint=tunnel_api,
                            tunnel_type=tunnel_type,
                            socks_port=socks_port,
                            peer_uuid=peer_uuid,
                            timeout=10
                        )

                        # 发送广播事件
                        broadcast_event = {
                            "event_id": str(uuid.uuid4()),  # 新的事件 ID
                            "event_type": "broadcast",
                            "source_node": payload.source_node,  # 保持原始来源
                            "target_node": broadcast_target,
                            "ttl": new_ttl,
                            "reason": payload.reason
                        }

                        resp = client.post("/api/peer-tunnel/peer-event", json=broadcast_event)
                        if resp.get("success"):
                            logging.info(f"[peer-event] 广播成功: {other_tag}")
                        else:
                            # Phase 11-Fix.U: 防御性默认值
                            logging.warning(f"[peer-event] 广播失败: {other_tag}: {resp.get('message', 'Unknown error')}")

                    except Exception as e:
                        # M-2: 使用 exception() 记录完整堆栈
                        logging.exception(f"[peer-event] 广播到 {other_tag} 失败: {e}")

            except Exception as e:
                # M-2: 后台线程异常需要完整堆栈跟踪以便调试
                logging.exception(f"[peer-event] 广播线程异常: {e}")

        # 在后台线程中执行广播
        Thread(target=_broadcast_to_peers, daemon=True).start()
        result["broadcast_scheduled"] = True

    logging.info(f"[peer-event] 处理完成: {result}")
    return result


# ============ Peer Notification Helpers ============


def _trigger_bidirectional_connect(db, node_tag: str, pending_request: Dict[str, Any]) -> bool:
    """Phase 11.2/11.3: 触发双向自动连接 (WireGuard/Xray)

    在配对完成后自动执行：
    1. 建立到远程节点的隧道连接
    2. 通过隧道调用远程节点的 /api/peer-tunnel/reverse-setup API
    3. 远程节点收到请求后也建立到本节点的连接
    4. 双向连接完成

    对于 WireGuard：直接通过隧道 IP 发起 HTTP 请求
    对于 Xray：通过 SOCKS5 代理发起 HTTP 请求

    Args:
        db: 数据库实例
        node_tag: 新创建的节点标识符
        pending_request: 包含本节点信息的 pending_request

    Returns:
        是否成功建立双向连接
    """
    import requests
    from peer_tunnel_manager import PeerTunnelManager

    node = db.get_peer_node(node_tag)
    if not node:
        logging.error(f"[bidirectional] 节点 '{node_tag}' 不存在")
        return False

    tunnel_type = node.get("tunnel_type", "wireguard")

    # PSK 已废弃 - WireGuard 用隧道 IP 认证，Xray 用 UUID 认证
    # 不再需要 PSK 验证

    logging.info(f"[bidirectional] 开始双向自动连接: 节点 '{node_tag}', 类型={tunnel_type}")

    # Step 1: 建立到远程节点的隧道
    try:
        manager = PeerTunnelManager()
        connect_success = manager.connect_node(node_tag)
        if not connect_success:
            logging.warning(f"[bidirectional] 节点 '{node_tag}' 连接失败")
            db.update_peer_node(node_tag, bidirectional_status="outbound_only")
            return False
        logging.info(f"[bidirectional] 节点 '{node_tag}' 出站隧道已建立")
    except Exception as e:
        logging.error(f"[bidirectional] 建立隧道异常: {e}")
        db.update_peer_node(node_tag, bidirectional_status="outbound_only")
        return False

    # 刷新节点数据（连接后会更新隧道信息）
    node = db.get_peer_node(node_tag)

    # Step 2: 通过外网 endpoint 调用 reverse-setup API
    # 注意：不能用 tunnel_api_endpoint，因为此时对方的隧道接口还不存在！
    # 我们需要用对方的外网 IP + API 端口
    endpoint = node.get("endpoint", "")  # 格式: IP:WG_PORT (如 10.1.100.12:36200，端口范围 36200-36299)

    if not endpoint:
        logging.warning(f"[bidirectional] 节点 '{node_tag}' 缺少 endpoint")
        db.update_peer_node(node_tag, bidirectional_status="outbound_only")
        return False

    # Phase 11-Fix.B: 使用统一的 API 端口推导函数
    remote_ip, api_port = _derive_api_port_from_endpoint(endpoint, node)

    reverse_setup_url = f"http://{remote_ip}:{api_port}/api/peer-tunnel/reverse-setup"
    logging.info(f"[bidirectional] 使用外网地址调用 reverse-setup: {reverse_setup_url}")

    # 准备请求参数
    local_tag = pending_request.get("node_tag", "unknown")
    local_endpoint = pending_request.get("endpoint", "")
    local_wg_public_key = pending_request.get("wg_public_key", "")
    tunnel_local_ip = node.get("tunnel_local_ip", "")

    payload = {
        "psk": "",  # PSK 已废弃 - WireGuard 用隧道 IP 认证
        "node_id": local_tag,
        "endpoint": local_endpoint,
        "wg_public_key": local_wg_public_key,
        "tunnel_local_ip": tunnel_local_ip,
    }

    # 根据隧道类型选择请求方式
    proxies = None
    if tunnel_type == "xray":
        # Phase 11.3: Xray 通过 SOCKS5 代理发起请求
        xray_socks_port = node.get("xray_socks_port")
        # HIGH 修复: SOCKS 端口验证
        if not xray_socks_port or not (1 <= xray_socks_port <= 65535):
            logging.warning(f"[bidirectional] 节点 '{node_tag}' Xray 隧道 SOCKS 端口无效: {xray_socks_port}")
            db.update_peer_node(node_tag, bidirectional_status="outbound_only")
            return False
        proxies = {
            "http": f"socks5h://127.0.0.1:{xray_socks_port}",
            "https": f"socks5h://127.0.0.1:{xray_socks_port}",
        }
        logging.info(f"[bidirectional] 使用 SOCKS5 代理 (端口 {xray_socks_port}) 调用 reverse-setup")

    try:
        logging.info(f"[bidirectional] 调用 reverse-setup API: {reverse_setup_url}")
        response = requests.post(
            reverse_setup_url,
            json=payload,
            timeout=30,
            proxies=proxies,
        )

        if response.status_code == 200:
            result = response.json()
            if result.get("success"):
                db.update_peer_node(node_tag, bidirectional_status="bidirectional")
                logging.info(f"[bidirectional] 节点 '{node_tag}' 双向连接成功")
                return True
            else:
                logging.warning(f"[bidirectional] reverse-setup 返回失败: {result.get('message')}")
        else:
            logging.warning(f"[bidirectional] reverse-setup 请求失败: HTTP {response.status_code}")

    except requests.exceptions.Timeout:
        logging.warning(f"[bidirectional] reverse-setup 请求超时")
    except requests.exceptions.ProxyError as e:
        # HIGH 修复: 显式捕获 SOCKS5 代理错误（隧道未连接、Xray 未运行等）
        logging.warning(f"[bidirectional] reverse-setup SOCKS5 代理错误 (隧道可能未连接): {e}")
    except requests.exceptions.ConnectionError as e:
        logging.warning(f"[bidirectional] reverse-setup 连接错误: {e}")
    except Exception as e:
        logging.error(f"[bidirectional] reverse-setup 异常: {e}")

    # 反向连接失败，但出站连接已建立
    db.update_peer_node(node_tag, bidirectional_status="outbound_only")
    return False


def _check_and_update_bidirectional_status(db, tag: str) -> str:
    """Phase 11-Fix.B: 检查并更新双向连接状态

    在手动连接成功后调用，检测是否建立了双向连接。

    WireGuard 隧道: 一旦密钥交换完成且隧道连接，就是双向的
    Xray 隧道: 需要检查 inbound_enabled 状态

    Args:
        db: 数据库实例
        tag: 节点标识

    Returns:
        更新后的 bidirectional_status ('pending', 'outbound_only', 'bidirectional')
    """
    node = db.get_peer_node(tag)
    if not node:
        logging.warning(f"[bidirectional-check] 节点 '{tag}' 不存在")
        return "pending"

    current_status = node.get("bidirectional_status", "pending")
    tunnel_status = node.get("tunnel_status")
    tunnel_type = node.get("tunnel_type", "wireguard")

    # 如果隧道未连接，状态保持 pending
    if tunnel_status != "connected":
        logging.debug(f"[bidirectional-check] 节点 '{tag}' 隧道未连接，状态保持 {current_status}")
        return current_status

    # 根据隧道类型确定双向状态
    if tunnel_type == "wireguard":
        # WireGuard 隧道: 密钥交换完成后，双方都有对方的公钥，隧道本身就是双向的
        # 只需检查是否有对方的公钥（表示密钥交换成功）
        wg_peer_public_key = node.get("wg_peer_public_key")
        if wg_peer_public_key:
            new_status = "bidirectional"
        else:
            # 没有对方公钥说明密钥交换未完成
            new_status = "outbound_only"
    else:
        # Xray 隧道: 需要检查 inbound_enabled 状态
        inbound_enabled = node.get("inbound_enabled", False)
        if inbound_enabled:
            new_status = "bidirectional"
        else:
            new_status = "outbound_only"

    if new_status != current_status:
        logging.info(f"[bidirectional-check] 节点 '{tag}' ({tunnel_type}) 状态更新: {current_status} -> {new_status}")
        db.update_peer_bidirectional_status(tag, new_status)
    else:
        logging.debug(f"[bidirectional-check] 节点 '{tag}' 状态不变: {current_status}")

    return new_status


def _notify_peer_connected(db, node: dict) -> bool:
    """通知远程节点我们已建立隧道

    调用远程节点的 /api/peer-notify/connected 端点，
    让对方也建立其侧的隧道，实现双向连接。

    Phase 2 修复：优先使用隧道通信，如果隧道不可用则回退到 LAN 端点。
    这对于初始连接建立（bootstrap）场景很重要，因为此时隧道可能尚未完全建立。

    Args:
        db: 数据库实例
        node: 节点信息字典

    Returns:
        是否通知成功
    """
    import requests
    from tunnel_api_client import TunnelAPIClient

    tag = node["tag"]

    # 准备通知请求（认证通过隧道 IP/UUID）
    payload = {
        "node_id": tag,
        # 提供我们的参数，让对方可以连接到我们
        # Phase 6 Fix: 使用有效范围内的端口常量
        "initiator_endpoint": f"{_get_local_ip()}:{node.get('tunnel_port', PEER_TUNNEL_PORT_MIN)}",
        "initiator_public_key": node.get("wg_public_key"),
        "initiator_tunnel_ip": node.get("tunnel_local_ip"),
    }

    # Phase 2: 优先使用隧道通信（如果隧道已连接）
    tunnel_api = _get_peer_tunnel_endpoint(node)
    if tunnel_api and node.get("tunnel_status") == "connected":
        tunnel_type = node.get("tunnel_type", "wireguard")
        socks_port = node.get("xray_socks_port") if tunnel_type == "xray" else None
        peer_uuid = node.get("xray_uuid") if tunnel_type == "xray" else None

        try:
            client = TunnelAPIClient(
                node_tag=tag,
                tunnel_endpoint=tunnel_api,
                tunnel_type=tunnel_type,
                socks_port=socks_port,
                peer_uuid=peer_uuid,
                timeout=30
            )
            logging.info(f"[peer-notify] 通过隧道通知节点 '{tag}' 建立连接: {tunnel_api}")
            resp = client.post("/api/peer-notify/connected", json=payload)
            if resp.get("success"):
                logging.info(f"[peer-notify] 远程节点 '{tag}' 已通过隧道确认建立隧道")
                return True
            else:
                # Phase 11-Fix.U: 防御性默认值
                logging.warning(f"[peer-notify] 隧道通知 '{tag}' 失败: {resp.get('message', 'Unknown error')}, 尝试 LAN 回退")
        except Exception as e:
            logging.warning(f"[peer-notify] 隧道调用 '{tag}' 失败: {e}, 尝试 LAN 回退")

    # LAN 回退（用于 bootstrap 场景：隧道尚未建立）
    endpoint = node.get("endpoint", "")
    if not endpoint:
        logging.warning(f"[peer-notify] 无法通知节点 '{tag}': 缺少 endpoint 且隧道不可用")
        return False

    # 使用统一的 API 端口推导函数
    host, api_port = _derive_api_port_from_endpoint(endpoint, node)
    notify_url = f"http://{host}:{api_port}/api/peer-notify/connected"

    try:
        logging.info(f"[peer-notify] 通过 LAN 通知远程节点 '{tag}' 建立隧道: {notify_url}")
        resp = requests.post(
            notify_url,
            json=payload,
            timeout=30
        )

        if resp.status_code == 200:
            logging.info(f"[peer-notify] 远程节点 '{tag}' 已通过 LAN 确认建立隧道")
            return True
        else:
            logging.warning(f"[peer-notify] 远程节点 '{tag}' LAN 响应: {resp.status_code} - {resp.text}")
            return False
    except requests.RequestException as e:
        logging.warning(f"[peer-notify] LAN 通知节点 '{tag}' 失败: {e}")
        return False


def _notify_peer_disconnected(db, node: dict) -> bool:
    """通知远程节点我们已断开隧道

    调用远程节点的 /api/peer-notify/disconnected 端点，
    让对方也断开其侧的隧道，实现双向断开。

    Phase 2 修复：优先使用隧道通信，如果隧道不可用则回退到 LAN 端点。
    断开通知时隧道可能仍然可用（正在断开过程中），优先使用隧道可确保消息送达。

    Args:
        db: 数据库实例
        node: 节点信息字典

    Returns:
        是否通知成功
    """
    import requests
    from tunnel_api_client import TunnelAPIClient

    tag = node["tag"]

    # 认证通过隧道 IP/UUID
    payload = {
        "node_id": tag,
    }

    # Phase 2: 优先使用隧道通信（如果隧道已连接）
    tunnel_api = _get_peer_tunnel_endpoint(node)
    if tunnel_api and node.get("tunnel_status") == "connected":
        tunnel_type = node.get("tunnel_type", "wireguard")
        socks_port = node.get("xray_socks_port") if tunnel_type == "xray" else None
        peer_uuid = node.get("xray_uuid") if tunnel_type == "xray" else None

        try:
            client = TunnelAPIClient(
                node_tag=tag,
                tunnel_endpoint=tunnel_api,
                tunnel_type=tunnel_type,
                socks_port=socks_port,
                peer_uuid=peer_uuid,
                timeout=10
            )
            logging.info(f"[peer-notify] 通过隧道通知节点 '{tag}' 断开连接: {tunnel_api}")
            resp = client.post("/api/peer-notify/disconnected", json=payload)
            if resp.get("success"):
                logging.info(f"[peer-notify] 远程节点 '{tag}' 已通过隧道确认断开")
                return True
            else:
                # Phase 11-Fix.U: 防御性默认值
                logging.warning(f"[peer-notify] 隧道断开通知 '{tag}' 失败: {resp.get('message', 'Unknown error')}, 尝试 LAN 回退")
        except Exception as e:
            logging.warning(f"[peer-notify] 隧道调用 '{tag}' 失败: {e}, 尝试 LAN 回退")

    # LAN 回退（隧道可能已断开）
    endpoint = node.get("endpoint", "")
    if not endpoint:
        logging.debug(f"[peer-notify] 节点 '{tag}' 无 endpoint 且隧道不可用，跳过断开通知")
        return False

    # 使用统一的 API 端口推导函数
    host, api_port = _derive_api_port_from_endpoint(endpoint, node)
    notify_url = f"http://{host}:{api_port}/api/peer-notify/disconnected"

    try:
        logging.info(f"[peer-notify] 通过 LAN 通知远程节点 '{tag}' 断开隧道: {notify_url}")
        resp = requests.post(
            notify_url,
            json=payload,
            timeout=10  # 断开通知超时短一些
        )
        if resp.status_code == 200:
            logging.info(f"[peer-notify] 远程节点 '{tag}' 已通过 LAN 确认断开")
            return True
        else:
            logging.warning(f"[peer-notify] 远程节点 '{tag}' LAN 断开响应: {resp.status_code}")
            return False
    except requests.RequestException as e:
        logging.warning(f"[peer-notify] LAN 通知节点 '{tag}' 断开失败: {e}")
        return False


# ============ Cascade Notification Helpers ============

def _is_duplicate_notification(notification_id: str) -> bool:
    """检查通知是否重复（防止循环通知）

    Args:
        notification_id: 唯一通知 ID

    Returns:
        True 如果是重复通知，False 如果是新通知
    """
    import time
    now = time.time()

    with _cascade_notification_lock:
        # 检查是否已存在
        if notification_id in _cascade_notification_cache:
            return True

        # 添加到缓存
        _cascade_notification_cache[notification_id] = now

        # 清理过期条目
        cutoff = now - _CASCADE_NOTIFICATION_TTL
        expired_keys = [k for k, v in _cascade_notification_cache.items() if v < cutoff]
        for k in expired_keys:
            del _cascade_notification_cache[k]

        # 防止缓存过大
        if len(_cascade_notification_cache) > _CASCADE_NOTIFICATION_MAX_SIZE:
            # 删除最老的一半
            sorted_items = sorted(_cascade_notification_cache.items(), key=lambda x: x[1])
            for k, _ in sorted_items[:len(sorted_items) // 2]:
                del _cascade_notification_cache[k]

        return False


def _forward_downstream_disconnected(
    db,
    upstream_reg: dict,
    chain_id: str,
    disconnected_node: str,
    notification_id: str,
    timestamp: str
) -> bool:
    """向上游节点转发下游断连通知

    Phase 2 修复：仅通过隧道通信。级联通知发生在链路激活期间，
    此时隧道必须已建立。如果隧道不可用，则通知无法送达。

    Args:
        db: 数据库实例
        upstream_reg: 上游注册信息
        chain_id: 链路 ID
        disconnected_node: 断开的节点标签
        notification_id: 通知 ID（用于去重）
        timestamp: 原始时间戳

    Returns:
        是否转发成功
    """
    from tunnel_api_client import TunnelAPIClient

    # 获取上游节点信息
    upstream_node_tag = upstream_reg.get("upstream_node_tag", "")
    if not upstream_node_tag:
        logging.warning(f"[cascade-notify] 无法转发: 缺少 upstream_node_tag")
        return False

    upstream_node = db.get_peer_node(upstream_node_tag)
    if not upstream_node:
        logging.warning(f"[cascade-notify] 无法转发: 未找到上游节点 '{upstream_node_tag}'")
        return False

    # Phase 2: 使用隧道通信（级联通知必须通过隧道）
    tunnel_api = _get_peer_tunnel_endpoint(upstream_node)
    if not tunnel_api:
        logging.warning(f"[cascade-notify] 节点 '{upstream_node_tag}' 隧道不可用，无法转发")
        return False

    tunnel_type = upstream_node.get("tunnel_type", "wireguard")
    socks_port = upstream_node.get("xray_socks_port") if tunnel_type == "xray" else None
    peer_uuid = upstream_node.get("xray_uuid") if tunnel_type == "xray" else None

    # 认证通过隧道 IP/UUID
    payload = {
        "node_id": upstream_node.get("tag", ""),
        "chain_id": chain_id,
        "disconnected_node": disconnected_node,
        "notification_id": notification_id,
        "timestamp": timestamp,
    }

    try:
        client = TunnelAPIClient(
            node_tag=upstream_node_tag,
            tunnel_endpoint=tunnel_api,
            tunnel_type=tunnel_type,
            socks_port=socks_port,
            peer_uuid=peer_uuid,
            timeout=10
        )
        logging.info(f"[cascade-notify] 通过隧道转发下游断连通知到 '{upstream_node_tag}': {tunnel_api}")
        resp = client.post("/api/peer-notify/downstream-disconnected", json=payload)
        if resp.get("success"):
            logging.info(f"[cascade-notify] 上游节点 '{upstream_node_tag}' 已通过隧道收到通知")
            return True
        else:
            # Phase 11-Fix.U: 防御性默认值
            logging.warning(f"[cascade-notify] 上游节点响应: {resp.get('message', 'Unknown error')}")
            return False
    except Exception as e:
        logging.warning(f"[cascade-notify] 转发失败: {e}")
        return False


def _get_local_api_endpoint() -> str:
    """获取本地 API 端点

    用于向其他节点注册时提供回调地址。
    优先使用设置中的 server_endpoint，否则尝试自动检测。
    """
    import socket

    # 从设置中读取
    settings = load_settings()
    server_endpoint = settings.get("server_endpoint", "")
    if server_endpoint:
        # 确保有端口
        if ":" not in server_endpoint:
            return f"{server_endpoint}:{DEFAULT_WEB_PORT}"
        return server_endpoint

    # 自动检测
    try:
        # 获取本地 IP
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.connect(("8.8.8.8", 80))
            local_ip = s.getsockname()[0]
            return f"{local_ip}:{DEFAULT_WEB_PORT}"
        finally:
            s.close()
    except Exception:
        pass

    return f"127.0.0.1:{DEFAULT_WEB_PORT}"


def _register_chain_with_peers(db, chain: dict) -> dict:
    """向链路中的中间节点发送注册请求

    当链路启用时，需要向所有中间节点注册，以便它们知道此链路经过它们。

    Phase 2 修复：仅通过隧道通信。链路注册发生在链路激活期间，
    此时所有隧道必须已建立。如果隧道不可用，则跳过该节点。

    Args:
        db: 数据库实例
        chain: 链路配置字典

    Returns:
        注册结果 {tag: success_bool, ...}
    """
    from tunnel_api_client import TunnelAPIClient

    # Issue 11/12 修复：使用统一的 hops 解析函数
    hops = _parse_chain_hops(chain, raise_on_error=False)

    if len(hops) < 2:
        return {}  # 少于 2 跳无需注册

    chain_id = chain.get("tag", "")
    local_endpoint = _get_local_api_endpoint()
    results = {}

    # 对于 A → B → C 的链路:
    # - 向 B 注册，告知 C 是下游
    # 对于 A → B → C → D:
    # - 向 B 注册，告知后面都是下游（C, D）
    # - 向 C 注册，告知 D 是下游

    for i in range(len(hops) - 1):
        intermediate_tag = hops[i]
        downstream_tag = hops[i + 1]  # 直接下游节点

        # 获取中间节点信息
        intermediate_node = db.get_peer_node(intermediate_tag)
        if not intermediate_node:
            logging.warning(f"[chain-register] 中间节点 '{intermediate_tag}' 不存在，跳过")
            results[intermediate_tag] = False
            continue

        # Phase 2: 使用隧道通信（链路注册必须通过隧道）
        tunnel_api = _get_peer_tunnel_endpoint(intermediate_node)
        if not tunnel_api:
            logging.warning(f"[chain-register] 节点 '{intermediate_tag}' 隧道不可用，跳过")
            results[intermediate_tag] = False
            continue

        tunnel_type = intermediate_node.get("tunnel_type", "wireguard")
        socks_port = intermediate_node.get("xray_socks_port") if tunnel_type == "xray" else None
        peer_uuid = intermediate_node.get("xray_uuid") if tunnel_type == "xray" else None

        # 发送注册请求（认证通过隧道 IP/UUID）
        payload = {
            "node_id": intermediate_tag,  # 这是我们认识的节点 tag
            "chain_id": chain_id,
            "upstream_endpoint": local_endpoint,
            "downstream_node": downstream_tag,
        }

        try:
            client = TunnelAPIClient(
                node_tag=intermediate_tag,
                tunnel_endpoint=tunnel_api,
                tunnel_type=tunnel_type,
                socks_port=socks_port,
                peer_uuid=peer_uuid,
                timeout=10
            )
            logging.info(f"[chain-register] 通过隧道向 '{intermediate_tag}' 注册链路 '{chain_id}': {tunnel_api}")
            resp = client.post("/api/peer-chain/register", json=payload)
            if resp.get("success"):
                logging.info(f"[chain-register] 节点 '{intermediate_tag}' 通过隧道注册成功")
                results[intermediate_tag] = True
            else:
                # Phase 11-Fix.U: 防御性默认值
                logging.warning(f"[chain-register] 节点 '{intermediate_tag}' 注册失败: {resp.get('message', 'Unknown error')}")
                results[intermediate_tag] = False
        except Exception as e:
            logging.warning(f"[chain-register] 向 '{intermediate_tag}' 注册失败: {e}")
            results[intermediate_tag] = False

    return results


def _unregister_chain_from_peers(db, chain: dict) -> dict:
    """向链路中的中间节点发送注销请求

    当链路禁用或删除时，需要通知所有中间节点注销此链路注册。

    Phase 2 修复：仅通过隧道通信。链路注销发生在链路停用期间，
    如果隧道不可用，则跳过该节点（尽力清理）。

    Args:
        db: 数据库实例
        chain: 链路配置字典

    Returns:
        注销结果 {tag: success_bool, ...}
    """
    from tunnel_api_client import TunnelAPIClient

    # Issue 11/12 修复：使用统一的 hops 解析函数
    hops = _parse_chain_hops(chain, raise_on_error=False)

    if len(hops) < 2:
        return {}

    chain_id = chain.get("tag", "")
    results = {}

    for i in range(len(hops) - 1):
        intermediate_tag = hops[i]

        intermediate_node = db.get_peer_node(intermediate_tag)
        if not intermediate_node:
            results[intermediate_tag] = False
            continue

        # Phase 2: 使用隧道通信（链路注销必须通过隧道）
        tunnel_api = _get_peer_tunnel_endpoint(intermediate_node)
        if not tunnel_api:
            logging.warning(f"[chain-unregister] 节点 '{intermediate_tag}' 隧道不可用，跳过")
            results[intermediate_tag] = False
            continue

        tunnel_type = intermediate_node.get("tunnel_type", "wireguard")
        socks_port = intermediate_node.get("xray_socks_port") if tunnel_type == "xray" else None
        peer_uuid = intermediate_node.get("xray_uuid") if tunnel_type == "xray" else None

        # 发送注销请求（认证通过隧道 IP/UUID）
        payload = {
            "node_id": intermediate_tag,
            "chain_id": chain_id,
        }

        try:
            client = TunnelAPIClient(
                node_tag=intermediate_tag,
                tunnel_endpoint=tunnel_api,
                tunnel_type=tunnel_type,
                socks_port=socks_port,
                peer_uuid=peer_uuid,
                timeout=10
            )
            logging.info(f"[chain-unregister] 通过隧道向 '{intermediate_tag}' 注销链路 '{chain_id}': {tunnel_api}")
            resp = client.delete("/api/peer-chain/unregister", json=payload)
            if resp.get("success"):
                logging.info(f"[chain-unregister] 节点 '{intermediate_tag}' 通过隧道注销成功")
                results[intermediate_tag] = True
            else:
                # Phase 11-Fix.U: 防御性默认值
                logging.warning(f"[chain-unregister] 节点 '{intermediate_tag}' 注销失败: {resp.get('message', 'Unknown error')}")
                results[intermediate_tag] = False
        except Exception as e:
            logging.warning(f"[chain-unregister] 向 '{intermediate_tag}' 注销失败: {e}")
            results[intermediate_tag] = False

    return results


# ============ Cascade Notification Endpoints ============

class DownstreamDisconnectedRequest(BaseModel):
    """下游断连通知请求

    认证方式: 隧道 IP 认证 (WireGuard) 或 UUID 认证 (Xray)
    """
    node_id: str = Field(..., description="发送通知的节点 ID")
    chain_id: str = Field(..., description="链路 ID")
    disconnected_node: str = Field(..., description="断开的下游节点")
    notification_id: str = Field(..., description="唯一通知 ID（用于去重）")
    timestamp: str = Field(..., description="断开时间戳")


@app.post("/api/peer-notify/downstream-disconnected")
def api_peer_notify_downstream_disconnected(request: Request, payload: DownstreamDisconnectedRequest):
    """接收下游节点断连通知

    当链路中的下游节点断开时，中间节点会调用此端点通知上游节点。
    实现级联通知机制。

    认证方式: 隧道 IP 认证 (WireGuard) 或 UUID 认证 (Xray)
    """
    client_ip = _get_client_ip(request)

    # 速率限制检查
    if not _check_api_rate_limit(client_ip):
        raise HTTPException(
            status_code=429,
            detail="Too many requests, please try again later"
        )

    if not HAS_DATABASE or not USER_DB_PATH.exists():
        raise HTTPException(status_code=503, detail="Database unavailable")

    db = _get_db()

    # 去重检查（防止循环通知）
    if _is_duplicate_notification(payload.notification_id):
        logging.info(f"[cascade-notify] 忽略重复通知: {payload.notification_id[:8]}...")
        return {"status": "duplicate", "forwarded": False}

    # Phase 11-Fix.M: 使用灵活认证函数（可通过隧道调用，支持 IP 认证）
    node = _verify_peer_request_flexible(
        request, db,
        payload_node_id=payload.node_id
    )
    if not node:
        raise HTTPException(status_code=401, detail="Authentication failed")

    logging.info(
        f"[cascade-notify] 收到下游断连通知: chain={payload.chain_id}, "
        f"disconnected={payload.disconnected_node} (from {node['tag']})"
    )

    # 更新本地链路状态
    db.update_chain_downstream_status(
        payload.chain_id,
        "disconnected",
        payload.disconnected_node
    )

    # 检查是否需要继续向上游转发
    upstream_reg = db.get_chain_upstream_registration(payload.chain_id)
    forwarded = False
    if upstream_reg:
        forwarded = _forward_downstream_disconnected(
            db,
            upstream_reg,
            payload.chain_id,
            payload.disconnected_node,
            payload.notification_id,
            payload.timestamp
        )

    return {"status": "received", "forwarded": forwarded}


class ChainRegisterRequest(BaseModel):
    """链路注册请求

    认证方式: 隧道 IP 认证 (WireGuard) 或 UUID 认证 (Xray)
    """
    node_id: str = Field(..., description="发送请求的节点 ID（上游节点）")
    chain_id: str = Field(..., description="链路 ID")
    upstream_endpoint: str = Field(..., description="上游节点端点（用于发送断连通知）")
    downstream_node: str = Field(..., description="下游节点标签")


@app.post("/api/peer-chain/register")
def api_peer_chain_register(request: Request, payload: ChainRegisterRequest):
    """注册链路经过此节点

    当上游节点启用链路时，向中间节点发送注册请求。
    中间节点记录链路信息，以便在下游断开时发送通知。

    认证方式: 隧道 IP 认证 (WireGuard) 或 UUID 认证 (Xray)
    """
    client_ip = _get_client_ip(request)

    # 速率限制检查
    if not _check_api_rate_limit(client_ip):
        raise HTTPException(
            status_code=429,
            detail="Too many requests, please try again later"
        )

    if not HAS_DATABASE or not USER_DB_PATH.exists():
        raise HTTPException(status_code=503, detail="Database unavailable")

    db = _get_db()

    # Phase 11-Fix.M: 使用灵活认证函数（可通过隧道调用，支持 IP 认证）
    node = _verify_peer_request_flexible(
        request, db,
        payload_node_id=payload.node_id
    )
    if not node:
        raise HTTPException(status_code=401, detail="Authentication failed")

    logging.info(
        f"[chain-register] 注册链路: chain={payload.chain_id}, "
        f"upstream={payload.node_id}, downstream={payload.downstream_node}"
    )

    # 添加链路注册（用于后续向上游发送通知）
    db.add_chain_registration(
        chain_id=payload.chain_id,
        upstream_node_tag=payload.node_id,
        upstream_endpoint=payload.upstream_endpoint,
        upstream_psk="",  # PSK 已废弃，使用隧道 IP/UUID 认证
        downstream_node_tag=payload.downstream_node
    )

    # Phase 11-Fix.Z: 添加 success 字段，与 _register_chain_with_peers 的 resp.get("success") 匹配
    return {"success": True, "status": "registered", "chain_id": payload.chain_id}


class ChainUnregisterRequest(BaseModel):
    """链路注销请求

    认证方式: 隧道 IP 认证 (WireGuard) 或 UUID 认证 (Xray)
    """
    node_id: str = Field(..., description="发送请求的节点 ID（上游节点）")
    chain_id: str = Field(..., description="链路 ID")


@app.delete("/api/peer-chain/unregister")
def api_peer_chain_unregister(request: Request, payload: ChainUnregisterRequest):
    """注销链路

    当上游节点禁用链路时，向中间节点发送注销请求。
    中间节点删除链路记录。

    认证方式: 隧道 IP 认证 (WireGuard) 或 UUID 认证 (Xray)
    """
    client_ip = _get_client_ip(request)

    # 速率限制检查
    if not _check_api_rate_limit(client_ip):
        raise HTTPException(
            status_code=429,
            detail="Too many requests, please try again later"
        )

    if not HAS_DATABASE or not USER_DB_PATH.exists():
        raise HTTPException(status_code=503, detail="Database unavailable")

    db = _get_db()

    # Phase 11-Fix.M: 使用灵活认证函数（可通过隧道调用，支持 IP 认证）
    node = _verify_peer_request_flexible(
        request, db,
        payload_node_id=payload.node_id
    )
    if not node:
        raise HTTPException(status_code=401, detail="Authentication failed")

    logging.info(f"[chain-unregister] 注销链路: chain={payload.chain_id}, from={payload.node_id}")

    # 删除链路注册
    deleted = db.delete_chain_registration(payload.chain_id, payload.node_id)

    return {"status": "unregistered" if deleted else "not_found", "chain_id": payload.chain_id}


# ============ Phase 3: 隧道 API 通信 ============
# 这些端点通过已建立的隧道访问
# - WireGuard 隧道：通过 tunnel_remote_ip 验证（IP 即身份）
# - Xray 隧道：通过 X-Peer-UUID header 验证


def _find_peer_by_tunnel_ip(db, client_ip: str) -> Optional[Dict]:
    """通过隧道 IP 查找 peer 节点

    WireGuard 隧道的身份验证：隧道 IP 即身份。
    只有持有正确私钥的节点才能建立隧道，所以来自隧道 IP 的请求必然来自配对的节点。

    Args:
        db: 数据库连接
        client_ip: 请求来源 IP

    Returns:
        找到的节点信息 dict，或 None
    """
    all_nodes = db.get_peer_nodes()
    for node in all_nodes:
        tunnel_remote_ip = node.get("tunnel_remote_ip", "")
        if tunnel_remote_ip:
            # tunnel_remote_ip 格式: "10.200.200.242/30" 或 "10.200.200.242"
            tunnel_ip_clean = tunnel_remote_ip.split("/")[0]
            if tunnel_ip_clean == client_ip:
                return node
    return None


def _find_peer_by_uuid(db, peer_uuid: str) -> Optional[Dict]:
    """通过 UUID 查找 peer 节点

    Xray 隧道的身份验证：使用 peer 的 inbound_uuid 或 xray_uuid。

    Args:
        db: 数据库连接
        peer_uuid: X-Peer-UUID header 中的 UUID

    Returns:
        找到的节点信息 dict，或 None
    """
    if not peer_uuid:
        return None

    all_nodes = db.get_peer_nodes()
    for node in all_nodes:
        # 检查 inbound_uuid（对方用来连接我们的 UUID）
        if node.get("inbound_uuid") == peer_uuid:
            return node
        # 检查 xray_uuid（我们用来连接对方的 UUID，对方可能用它来标识自己）
        if node.get("xray_uuid") == peer_uuid:
            return node
    return None


def _verify_tunnel_request(request: Request, db) -> Optional[Dict]:
    """验证隧道内 API 请求

    根据隧道类型使用不同的认证方式：
    - WireGuard 隧道：通过 tunnel_remote_ip 验证（IP 即身份）
    - Xray 隧道：通过 X-Peer-UUID header 验证

    安全关键（Phase 11-Fix.M）：
    - 必须使用 _get_direct_client_ip() 而非 _get_client_ip()
    - 不能信任 X-Forwarded-For 等可伪造的 HTTP 头
    - 已移除 endpoint IP 回退认证（安全风险）

    Args:
        request: FastAPI 请求对象
        db: 数据库连接

    Returns:
        认证成功返回节点信息 dict，失败返回 None
    """
    # Phase 11-Fix.M: 使用直连 IP，防止 X-Forwarded-For 欺骗
    client_ip = _get_direct_client_ip(request)

    # 方式 1: WireGuard 隧道 - 通过 tunnel_remote_ip 验证
    node = _find_peer_by_tunnel_ip(db, client_ip)
    if node:
        tunnel_type = node.get("tunnel_type", "wireguard")
        if tunnel_type == "wireguard":
            # WireGuard 隧道：IP 即身份，无需额外验证
            if node.get("tunnel_status") == "connected":
                logging.debug(f"[tunnel-api] WireGuard 认证成功: {node['tag']} (IP: {client_ip})")
                return node
            else:
                logging.warning(f"[tunnel-api] WireGuard 隧道未连接: {node['tag']}")
                return None

    # 方式 2: Xray 隧道 - 通过 X-Peer-UUID header 验证
    peer_uuid = request.headers.get("X-Peer-UUID")
    if peer_uuid:
        node = _find_peer_by_uuid(db, peer_uuid)
        if node:
            tunnel_type = node.get("tunnel_type", "wireguard")
            if tunnel_type == "xray":
                if node.get("tunnel_status") == "connected":
                    logging.debug(f"[tunnel-api] Xray 认证成功: {node['tag']} (UUID: {peer_uuid[:8]}...)")
                    return node
                else:
                    logging.warning(f"[tunnel-api] Xray 隧道未连接: {node['tag']}")
                    return None

    # Phase 11-Fix.M: 已移除 endpoint IP 回退认证
    # 原因：endpoint IP 可被 NAT 共享，存在安全风险
    # 所有隧道内 API 必须通过 tunnel_remote_ip 或 X-Peer-UUID 认证

    logging.warning(f"[tunnel-api] 认证失败 (from {client_ip}, UUID: {peer_uuid or 'none'})")
    return None


# Phase 5: 重命名别名以反映实际功能（PSK 已废弃）
# 保留别名以保持向后兼容，实际使用隧道认证
_verify_tunnel_header = _verify_tunnel_request


def _verify_peer_request_flexible(
    request: Request,
    db,
    payload_node_id: str = None,
    allow_tunnel_auth: bool = True
) -> Optional[Dict]:
    """灵活的对等节点请求认证函数

    支持两种认证方式，按优先级尝试：
    1. 隧道认证（最安全）: 通过 _verify_tunnel_request() 验证
       - WireGuard: 通过 tunnel_remote_ip 验证
       - Xray: 通过 X-Peer-UUID header 验证
    2. 隧道 IP 认证（仅限已连接）: tunnel_status == "connected" 且 client_ip == tunnel_remote_ip

    NOTE: PSK 认证已废弃并移除。所有节点必须使用隧道 IP 认证 (WireGuard) 或 UUID 认证 (Xray)。

    Args:
        request: FastAPI 请求对象
        db: 数据库连接
        payload_node_id: 请求体中的节点 ID（用于日志记录）
        allow_tunnel_auth: 是否允许隧道认证（默认 True）

    Returns:
        认证成功返回节点信息 dict，失败返回 None

    安全约束：
    - 隧道 IP 认证仅在 tunnel_status == "connected" 时允许
    - Endpoint IP 认证已移除（不安全，易被 IP 欺骗）
    - 使用 _get_direct_client_ip() 防止 IP 欺骗
    """
    # 使用直连 IP 进行认证，防止 X-Forwarded-For 欺骗
    client_ip = _get_direct_client_ip(request)

    # === 优先级 1: 隧道认证 ===
    if allow_tunnel_auth:
        node = _verify_tunnel_request(request, db)
        if node:
            logging.debug(
                f"[peer-auth-flexible] 认证成功: {node['tag']} "
                f"(method=tunnel, ip={client_ip})"
            )
            return node

    # === 优先级 2: 隧道 IP 认证（仅限已连接状态）===
    # 安全约束：只有 tunnel_status == "connected" 且 client_ip == tunnel_remote_ip 时才允许
    if allow_tunnel_auth:
        node = _find_peer_by_tunnel_ip(db, client_ip)
        if node:
            if node.get("tunnel_status") == "connected":
                logging.debug(
                    f"[peer-auth-flexible] 认证成功: {node['tag']} "
                    f"(method=tunnel_ip, ip={client_ip})"
                )
                return node
            else:
                logging.info(
                    f"[peer-auth-flexible] 隧道 IP 匹配但状态非 connected: {node['tag']} "
                    f"(status={node.get('tunnel_status')}, ip={client_ip})"
                )

    # === 所有认证方式都失败 ===
    logging.warning(
        f"[peer-auth-flexible] 认证失败 "
        f"(from {client_ip}, node_id={payload_node_id})"
    )
    return None


@app.get("/api/peer-info/egress")
def api_peer_info_egress(request: Request):
    """获取本节点的可用出口列表

    供远程节点通过隧道查询，用于链路终端出口选择。

    认证方式: 隧道 IP/UUID
    """
    client_ip = _get_client_ip(request)

    # 速率限制
    if not _check_api_rate_limit(client_ip):
        raise HTTPException(status_code=429, detail="Too many requests")

    if not HAS_DATABASE or not USER_DB_PATH.exists():
        raise HTTPException(status_code=503, detail="Database unavailable")

    db = _get_db()

    # 验证隧道认证（WireGuard IP / Xray UUID）
    node = _verify_tunnel_header(request, db)
    if not node:
        raise HTTPException(status_code=401, detail="Authentication failed")

    logging.info(f"[tunnel-api] 获取出口列表请求: from {node['tag']} ({client_ip})")

    # 收集所有可用出口
    egress_list = []

    # 1. PIA profiles
    for profile in db.get_pia_profiles(enabled_only=True):
        egress_list.append({
            "tag": profile["name"],
            "name": profile.get("description") or profile["name"],
            "type": "pia",
            "enabled": True,
            "description": f"PIA {profile.get('region_id', 'Unknown')}",
        })

    # 2. Custom WireGuard
    for egress in db.get_custom_egress_list(enabled_only=True):
        egress_list.append({
            "tag": egress["tag"],
            "name": egress.get("description") or egress["tag"],
            "type": "custom",
            "enabled": True,
            "description": "Custom WireGuard",
        })

    # 3. Direct egress
    for egress in db.get_direct_egress_list(enabled_only=True):
        egress_list.append({
            "tag": egress["tag"],
            "name": egress.get("description") or egress["tag"],
            "type": "direct",
            "enabled": True,
            "description": f"Direct ({egress.get('bind_interface') or egress.get('inet4_bind_address', '')})",
        })

    # 4. OpenVPN egress
    for egress in db.get_openvpn_egress_list(enabled_only=True):
        egress_list.append({
            "tag": egress["tag"],
            "name": egress.get("description") or egress["tag"],
            "type": "openvpn",
            "enabled": True,
            "description": f"OpenVPN {egress.get('remote_host', '')}",
        })

    # 5. V2Ray egress
    for egress in db.get_v2ray_egress_list(enabled_only=True):
        egress_list.append({
            "tag": egress["tag"],
            "name": egress.get("description") or egress["tag"],
            "type": "v2ray",
            "enabled": True,
            "description": f"V2Ray {egress.get('protocol', '')}",
        })

    # 6. WARP egress
    for egress in db.get_warp_egress_list(enabled_only=True):
        egress_list.append({
            "tag": egress["tag"],
            "name": egress.get("description") or egress["tag"],
            "type": "warp",
            "enabled": True,
            "description": f"WARP {egress.get('protocol', '')}",
            "protocol": egress.get("protocol", "wireguard"),  # Phase 11-Fix.Q: 用于 MASQUE 检测
        })

    # 7. 添加内置 direct 出口
    egress_list.append({
        "tag": "direct",
        "name": "Direct",
        "type": "direct",
        "enabled": True,
        "description": "Default direct connection",
    })

    logging.info(f"[tunnel-api] 返回 {len(egress_list)} 个可用出口给节点 '{node['tag']}'")
    return {"egress": egress_list, "node_tag": node["tag"]}


# 链路路由有效标记类型
VALID_MARK_TYPES = {"dscp", "xray_email"}

# 标签名称正则：小写字母开头，允许小写字母、数字、连字符，最长64字符
TAG_PATTERN = r"^[a-z][a-z0-9-]{0,63}$"

# Phase 11-Fix.J: 不能作为链路终端出口的 egress 类型
# 这些 outbound 没有 bind_interface，无法用于 DSCP 路由
INVALID_CHAIN_TERMINAL_EGRESS = frozenset({"direct", "block", "adblock"})


def _validate_chain_terminal_egress_static(egress_tag: str):
    """静态验证 egress 是否可作为链路终端出口

    Phase 11-Fix.Q: 仅执行静态检查，不查询数据库。
    用于链路创建/更新时的快速验证。
    完整验证在链路激活时通过 _validate_remote_terminal_egress() 执行。

    Args:
        egress_tag: 出口标识

    Raises:
        HTTPException: 如果 egress 在静态无效列表中
    """
    if egress_tag in INVALID_CHAIN_TERMINAL_EGRESS:
        raise HTTPException(
            status_code=400,
            detail=f"'{egress_tag}' 不能作为链路终端出口 - "
                   "请选择具有网络接口的出口 (PIA/Custom WireGuard/OpenVPN)"
        )


def _validate_remote_terminal_egress(
    db,
    chain_hops: list,
    exit_egress: str,
    allow_transitive: bool = False
) -> Optional[str]:
    """Phase 11-Fix.Q: 远程验证终端节点出口

    通过隧道查询终端节点的出口列表，验证 exit_egress 存在且兼容 DSCP 路由。

    Args:
        db: 数据库实例
        chain_hops: 链路节点列表（最后一个是终端节点）
        exit_egress: 要验证的出口标识
        allow_transitive: 是否使用传递模式（通过中间节点转发查询）

    Returns:
        错误消息（如有），None 表示验证通过
    """
    if not chain_hops or len(chain_hops) < 2:
        return "Chain must have at least 2 hops"

    terminal_tag = chain_hops[-1]

    # 静态检查
    if exit_egress in INVALID_CHAIN_TERMINAL_EGRESS:
        return f"'{exit_egress}' cannot be used as chain terminal egress"

    # 尝试通过隧道查询终端节点的出口列表
    try:
        from tunnel_api_client import TunnelAPIClientManager
        client_mgr = TunnelAPIClientManager(db)

        egress_list = []

        if allow_transitive and len(chain_hops) > 2:
            # 传递模式：通过第一个中间节点转发查询
            first_hop = chain_hops[0]
            first_client = client_mgr.get_client(first_hop)
            if first_client:
                try:
                    egress_list = first_client.get_forwarded_egress_list(terminal_tag)
                except Exception as e:
                    logging.warning(f"[validate-egress] 转发查询失败: {e}")
        else:
            # 直接模式：查询第一跳（如果第一跳就是终端，或使用直连）
            # 优先尝试直接连接终端节点
            terminal_client = client_mgr.get_client(terminal_tag)
            if terminal_client:
                try:
                    egress_list = terminal_client.get_egress_list()
                except Exception as e:
                    logging.warning(f"[validate-egress] 直接查询失败: {e}")

            # 如果直连失败，尝试通过第一跳转发
            if not egress_list and len(chain_hops) > 1:
                first_hop = chain_hops[0]
                first_client = client_mgr.get_client(first_hop)
                if first_client:
                    try:
                        egress_list = first_client.get_forwarded_egress_list(terminal_tag)
                    except Exception as e:
                        logging.warning(f"[validate-egress] 转发查询也失败: {e}")

        if not egress_list:
            # 无法连接终端节点 - 在激活时这是一个问题
            return f"Cannot reach terminal node '{terminal_tag}' to validate egress"

        # 检查 exit_egress 是否存在于终端节点
        egress_tags = [e.tag for e in egress_list]
        if exit_egress not in egress_tags:
            return f"Egress '{exit_egress}' not found on terminal node '{terminal_tag}'"

        # 检查出口类型是否兼容 DSCP 路由
        for egress in egress_list:
            if egress.tag == exit_egress:
                if egress.type in ("v2ray", "socks"):
                    return f"Egress '{exit_egress}' is SOCKS-based ({egress.type}), incompatible with DSCP routing"
                # Phase 11-Fix.Q: 使用 protocol 字段检测 WARP MASQUE
                if egress.type == "warp" and egress.protocol == "masque":
                    return f"WARP MASQUE egress '{exit_egress}' is SOCKS-based, incompatible with DSCP routing"
                break

        logging.info(f"[validate-egress] 终端出口验证通过: {exit_egress} on {terminal_tag}")
        return None  # 验证通过

    except ImportError as e:
        logging.error(f"[validate-egress] 无法导入 TunnelAPIClientManager: {e}")
        return "Internal error: TunnelAPIClientManager unavailable"
    except Exception as e:
        logging.error(f"[validate-egress] 验证失败: {e}")
        return f"Failed to validate egress on terminal node: {str(e)}"


def _validate_chain_terminal_egress(egress_tag: str, for_tunnel_api: bool = False):
    """验证 egress 是否可作为链路终端出口（本地验证）

    Phase 4 Issue 24 修复: 增加对 V2Ray 和 WARP MASQUE 出口的检查
    这些出口基于 SOCKS 代理，无法接收 DSCP 标记的流量。

    注意：此函数查询 LOCAL 数据库，适用于：
    - 终端节点上的 /api/chain-routing/register 端点（for_tunnel_api=True）

    对于入口节点的链路激活，应使用 _validate_remote_terminal_egress() 替代。

    Args:
        egress_tag: 出口标识
        for_tunnel_api: 若为 True，返回 dict 而非抛出 HTTPException

    Returns:
        for_tunnel_api=True 时返回 dict 或 None
        for_tunnel_api=False 时无返回值或抛出异常
    """
    # 检查静态无效出口列表
    if egress_tag in INVALID_CHAIN_TERMINAL_EGRESS:
        msg_en = (f"'{egress_tag}' cannot be used as chain terminal egress - "
                  "requires interface binding (PIA/Custom WireGuard/OpenVPN)")
        msg_zh = (f"'{egress_tag}' 不能作为链路终端出口 - "
                  "请选择具有网络接口的出口 (PIA/Custom WireGuard/OpenVPN)")

        if for_tunnel_api:
            return {"success": False, "message": msg_en}
        raise HTTPException(status_code=400, detail=msg_zh)

    # Phase 4 Issue 24: 检查 V2Ray 出口 (SOCKS-based)
    if HAS_DATABASE and USER_DB_PATH.exists():
        db = _get_db()

        # 检查是否为 V2Ray 出口
        v2ray_egress = db.get_v2ray_egress(egress_tag) if hasattr(db, 'get_v2ray_egress') else None
        if v2ray_egress:
            msg_en = (f"V2Ray egress '{egress_tag}' uses SOCKS proxy, "
                      "incompatible with DSCP routing")
            msg_zh = (f"V2Ray 出口 '{egress_tag}' 基于 SOCKS 代理，"
                      "与 DSCP 路由不兼容")

            if for_tunnel_api:
                return {"success": False, "message": msg_en}
            raise HTTPException(status_code=400, detail=msg_zh)

        # 检查是否为 WARP MASQUE 出口 (SOCKS-based)
        warp_egress = db.get_warp_egress(egress_tag) if hasattr(db, 'get_warp_egress') else None
        if warp_egress and warp_egress.get("protocol") == "masque":
            msg_en = (f"WARP MASQUE egress '{egress_tag}' uses SOCKS proxy, "
                      "incompatible with DSCP routing")
            msg_zh = (f"WARP MASQUE 出口 '{egress_tag}' 基于 SOCKS 代理，"
                      "与 DSCP 路由不兼容")

            if for_tunnel_api:
                return {"success": False, "message": msg_en}
            raise HTTPException(status_code=400, detail=msg_zh)

        # Phase 7 Fix: 验证出口实际存在
        # 如果上面没有找到 V2Ray/WARP 出口，检查其他类型
        if not v2ray_egress and not warp_egress:
            # 检查是否为 WARP WireGuard 出口（非 MASQUE）
            warp_wg = db.get_warp_egress(egress_tag) if hasattr(db, 'get_warp_egress') else None
            if warp_wg:
                return None  # WARP WireGuard 有效

            # 检查是否为 PIA 出口
            pia_profile = db.get_pia_profile_by_name(egress_tag) if hasattr(db, 'get_pia_profile_by_name') else None
            if pia_profile:
                return None  # PIA 有效

            # 检查是否为自定义 WireGuard 出口
            custom_egress = db.get_custom_egress(egress_tag) if hasattr(db, 'get_custom_egress') else None
            if custom_egress:
                return None  # Custom WireGuard 有效

            # 检查是否为 Direct 出口
            direct_egress = db.get_direct_egress(egress_tag) if hasattr(db, 'get_direct_egress') else None
            if direct_egress:
                return None  # Direct 有效

            # 检查是否为 OpenVPN 出口
            openvpn_egress = db.get_openvpn_egress(egress_tag) if hasattr(db, 'get_openvpn_egress') else None
            if openvpn_egress:
                return None  # OpenVPN 有效

            # 没找到任何匹配的出口
            msg_en = f"Egress '{egress_tag}' not found in any egress table"
            msg_zh = f"出口 '{egress_tag}' 不存在"

            if for_tunnel_api:
                return {"success": False, "message": msg_en}
            raise HTTPException(status_code=404, detail=msg_zh)

    return None


class ChainRoutingRegisterRequest(BaseModel):
    """链路路由注册请求"""
    chain_tag: str = Field(
        ..., pattern=TAG_PATTERN,
        description="链路标识 (小写字母开头，允许小写字母、数字、连字符)"
    )
    mark_value: int = Field(
        ..., ge=1, le=63,
        description="标记值 (DSCP: 1-63)"
    )
    mark_type: str = Field(
        default="dscp",
        pattern=r"^dscp$",
        description="标记类型（仅支持 DSCP）"
    )
    egress_tag: str = Field(
        ..., pattern=TAG_PATTERN,
        description="出口标识 (小写字母开头)"
    )
    source_node: Optional[str] = Field(
        default=None, pattern=TAG_PATTERN,
        description="来源节点标识"
    )
    # Phase 11-Fix.E: 支持转发注册到目标节点（用于传递模式）
    target_node: Optional[str] = Field(
        default=None, pattern=TAG_PATTERN,
        description="目标节点（如果指定，将转发注册到该节点）"
    )


@app.post("/api/chain-routing/register")
def api_chain_routing_register(request: Request, payload: ChainRoutingRegisterRequest):
    """注册链路路由

    当入口节点激活多跳链路时，在终端节点注册 DSCP/email 到出口的映射。
    终端节点根据此映射选择正确的本地出口。

    Phase 11-Fix.E: 支持 target_node 参数，当指定时将转发注册到目标节点。

    认证方式: 隧道 IP/UUID
    """
    client_ip = _get_client_ip(request)

    # 速率限制
    if not _check_api_rate_limit(client_ip):
        raise HTTPException(status_code=429, detail="Too many requests")

    if not HAS_DATABASE or not USER_DB_PATH.exists():
        raise HTTPException(status_code=503, detail="Database unavailable")

    db = _get_db()

    # 验证隧道认证（WireGuard IP / Xray UUID）
    node = _verify_tunnel_header(request, db)
    if not node:
        raise HTTPException(status_code=401, detail="Authentication failed")

    # Phase 11-Fix.V.3: 验证请求节点是否为链路成员（传入 source_node 支持入口节点）
    is_member, membership_error = _verify_chain_membership(
        db, payload.chain_tag, node["tag"], source_node=payload.source_node
    )
    if not is_member:
        logging.warning(f"[tunnel-api] 链路成员验证失败: {membership_error}")
        raise HTTPException(status_code=403, detail=membership_error)

    # Phase 11-Fix.E: 如果指定了 target_node，转发注册到目标节点
    if payload.target_node:
        logging.info(
            f"[tunnel-api] 链路路由转发注册: chain={payload.chain_tag}, "
            f"target={payload.target_node}, from {node['tag']} ({client_ip})"
        )

        # 获取目标节点信息
        target_peer = db.get_peer_node(payload.target_node)
        if not target_peer:
            return {"success": False, "message": f"Target node '{payload.target_node}' not found"}

        if target_peer.get("tunnel_status") != "connected":
            return {"success": False, "message": f"Target node '{payload.target_node}' not connected"}

        # 转发注册到目标节点
        try:
            from tunnel_api_client import TunnelAPIClientManager

            target_client_mgr = TunnelAPIClientManager(db)
            target_client = target_client_mgr.get_client(payload.target_node)

            if not target_client:
                return {"success": False, "message": f"Cannot create client for target '{payload.target_node}'"}

            # 转发时不再带 target_node 参数，防止无限循环
            success = target_client.register_chain_route(
                chain_tag=payload.chain_tag,
                mark_value=payload.mark_value,
                egress_tag=payload.egress_tag,
                mark_type=payload.mark_type,
                source_node=payload.source_node or node["tag"],
                target_node=None,  # 不再转发
            )

            if success:
                logging.info(f"[tunnel-api] 链路路由转发成功: -> {payload.target_node}")
                return {"success": True, "message": f"Chain route forwarded to '{payload.target_node}'"}
            else:
                return {"success": False, "message": f"Failed to forward to '{payload.target_node}'"}

        except Exception as e:
            logging.error(f"[tunnel-api] 链路路由转发失败: {e}")
            return {"success": False, "message": f"Forward error: {str(e)}"}

    logging.info(
        f"[tunnel-api] 链路路由注册: chain={payload.chain_tag}, "
        f"mark={payload.mark_value}, egress={payload.egress_tag}, "
        f"from {node['tag']} ({client_ip})"
    )

    # 验证 egress_tag 存在
    all_egress_tags = db.get_all_egress_tags()
    all_egress_tags.add("direct")  # 添加内置 direct
    if payload.egress_tag not in all_egress_tags:
        logging.warning(f"[tunnel-api] 出口不存在: {payload.egress_tag}")
        return {"success": False, "message": f"Egress '{payload.egress_tag}' not found"}

    # Phase 11-Fix.J: 拒绝无法用于 DSCP 路由的出口类型
    validation_result = _validate_chain_terminal_egress(payload.egress_tag, for_tunnel_api=True)
    if validation_result:
        logging.warning(f"[tunnel-api] 拒绝无效终端出口: {payload.egress_tag}")
        return validation_result

    try:
        # Phase 11-Fix.I: 原子事务模式 - DB 写入 + iptables 规则必须同时成功
        # Step 1: 写入数据库
        db.add_or_update_chain_routing(
            chain_tag=payload.chain_tag,
            mark_value=payload.mark_value,
            egress_tag=payload.egress_tag,
            mark_type=payload.mark_type,
            source_node=payload.source_node or node["tag"],
        )
        logging.info(
            f"[tunnel-api] 链路路由 DB 写入成功: chain={payload.chain_tag}, "
            f"mark={payload.mark_value} -> {payload.egress_tag}"
        )

        # Step 2: 应用 iptables/ip 路由规则
        try:
            from chain_route_manager import get_chain_route_manager

            chain_route_mgr = get_chain_route_manager(db)
            route_applied = chain_route_mgr.add_route(
                chain_tag=payload.chain_tag,
                mark_value=payload.mark_value,
                egress_tag=payload.egress_tag,
                mark_type=payload.mark_type,
                source_node=payload.source_node or node["tag"],
            )

            if not route_applied:
                # iptables 失败，回滚 DB
                logging.error(
                    f"[tunnel-api] iptables 规则应用失败，回滚 DB: "
                    f"chain={payload.chain_tag}, egress={payload.egress_tag}"
                )
                try:
                    db.delete_chain_routing(
                        chain_tag=payload.chain_tag,
                        mark_value=payload.mark_value,
                        mark_type=payload.mark_type,
                    )
                except Exception as rollback_err:
                    logging.critical(
                        f"[tunnel-api] 回滚失败，数据可能不一致: {rollback_err}"
                    )
                return {
                    "success": False,
                    "message": f"Failed to apply iptables rules for egress '{payload.egress_tag}'"
                }

            logging.info(
                f"[tunnel-api] 链路路由注册完成（DB + iptables）: "
                f"chain={payload.chain_tag}, mark={payload.mark_value}"
            )
            return {"success": True, "message": "Chain route registered", "iptables_applied": True}

        except ImportError as e:
            # chain_route_manager 模块不可用，回滚 DB
            logging.error(f"[tunnel-api] chain_route_manager 导入失败: {e}")
            try:
                db.delete_chain_routing(
                    chain_tag=payload.chain_tag,
                    mark_value=payload.mark_value,
                    mark_type=payload.mark_type,
                )
            except Exception as rollback_err:
                logging.critical(
                    f"[tunnel-api] 回滚失败，数据可能不一致: {rollback_err}"
                )
            return {"success": False, "message": "Chain route manager unavailable"}
        except Exception as e:
            # 其他异常，回滚 DB
            logging.error(f"[tunnel-api] iptables 应用异常: {e}")
            try:
                db.delete_chain_routing(
                    chain_tag=payload.chain_tag,
                    mark_value=payload.mark_value,
                    mark_type=payload.mark_type,
                )
            except Exception as rollback_err:
                logging.critical(
                    f"[tunnel-api] 回滚失败，数据可能不一致: {rollback_err}"
                )
            return {"success": False, "message": f"iptables error: {str(e)}"}

    except ValueError as e:
        logging.warning(f"[tunnel-api] 链路路由参数错误: {e}")
        return {"success": False, "message": str(e)}
    except sqlite3.IntegrityError as e:
        logging.error(f"[tunnel-api] 链路路由数据库约束错误: {e}")
        return {"success": False, "message": "Database constraint error"}
    except sqlite3.OperationalError as e:
        logging.error(f"[tunnel-api] 链路路由数据库操作错误: {e}")
        return {"success": False, "message": "Database operation error"}
    except Exception as e:
        logging.error(f"[tunnel-api] 链路路由注册失败: {e}")
        return {"success": False, "message": "Failed to register chain route"}


@app.delete("/api/chain-routing/unregister")
def api_chain_routing_unregister(
    request: Request,
    chain_tag: str = Query(
        ..., pattern=TAG_PATTERN,
        description="链路标识 (小写字母开头)"
    ),
    mark_value: int = Query(
        ..., ge=1, le=63,
        description="标记值 (1-63)"
    ),
    mark_type: str = Query(
        default="dscp",
        pattern=r"^dscp$",
        description="标记类型（仅支持 DSCP，Xray 隧道不支持多跳链路）"
    ),
    target_node: Optional[str] = Query(
        default=None,
        pattern=TAG_PATTERN,
        description="目标节点 (用于传递模式转发)"
    ),
    # Phase 11-Fix.V.3: 添加 source_node 参数支持入口节点验证
    source_node: Optional[str] = Query(
        default=None,
        pattern=TAG_PATTERN,
        description="来源节点标识（入口节点）"
    ),
):
    """注销链路路由

    当链路被停用时，清理终端节点的路由映射。

    认证方式: 隧道 IP/UUID

    Query Parameters:
        chain_tag: 链路标识
        mark_value: 标记值
        mark_type: 标记类型 (默认 dscp)
        target_node: 可选的目标节点（传递模式下转发注销请求）
    """
    client_ip = _get_client_ip(request)

    # 速率限制
    if not _check_api_rate_limit(client_ip):
        raise HTTPException(status_code=429, detail="Too many requests")

    if not HAS_DATABASE or not USER_DB_PATH.exists():
        raise HTTPException(status_code=503, detail="Database unavailable")

    db = _get_db()

    # 验证隧道认证（WireGuard IP / Xray UUID）
    node = _verify_tunnel_header(request, db)
    if not node:
        raise HTTPException(status_code=401, detail="Authentication failed")

    # Phase 11-Fix.V.3: 验证请求节点是否为链路成员（传入 source_node 支持入口节点）
    is_member, membership_error = _verify_chain_membership(
        db, chain_tag, node["tag"], source_node=source_node
    )
    if not is_member:
        logging.warning(f"[tunnel-api] 链路成员验证失败: {membership_error}")
        raise HTTPException(status_code=403, detail=membership_error)

    logging.info(
        f"[tunnel-api] 链路路由注销: chain={chain_tag}, "
        f"mark={mark_value}, from {node['tag']} ({client_ip})"
    )

    # Phase 11-Fix.E: 如果指定了 target_node，转发注销到目标节点
    if target_node:
        target_peer = db.get_peer_node(target_node)
        if not target_peer:
            logging.warning(f"[tunnel-api] 转发注销失败: 目标节点 '{target_node}' 不存在")
            return {"success": False, "message": f"Target node '{target_node}' not found"}

        if target_peer.get("tunnel_status") != "connected":
            logging.warning(f"[tunnel-api] 转发注销失败: 目标节点 '{target_node}' 隧道未连接")
            return {"success": False, "message": f"Target node '{target_node}' tunnel not connected"}

        try:
            from tunnel_api_client import TunnelAPIClientManager
            client_mgr = TunnelAPIClientManager(db)
            target_client = client_mgr.get_client(target_node)

            if not target_client:
                return {"success": False, "message": f"Cannot create client for '{target_node}'"}

            logging.info(f"[tunnel-api] 转发链路注销到 '{target_node}'")
            success = target_client.unregister_chain_route(
                chain_tag=chain_tag,
                mark_value=mark_value,
                mark_type=mark_type,
                target_node=None,  # 不再转发
                source_node=source_node,  # Phase 11-Fix.V.3: 传递原始入口节点
            )
            return {"success": success, "message": "Forwarded to target node", "target_node": target_node}
        except Exception as e:
            logging.error(f"[tunnel-api] 转发注销失败: {e}")
            return {"success": False, "message": f"Forward failed: {e}"}

    try:
        # Phase 11-Fix.I: 同时清理 DB 和 iptables 规则
        deleted = db.delete_chain_routing(
            chain_tag=chain_tag,
            mark_value=mark_value,
            mark_type=mark_type,
        )
        if deleted:
            logging.info(
                f"[tunnel-api] 链路路由 DB 删除成功: chain={chain_tag}, "
                f"mark={mark_value}"
            )

            # 清理 iptables 规则（最佳努力，不影响 DB 删除结果）
            iptables_cleaned = False
            try:
                from chain_route_manager import get_chain_route_manager

                chain_route_mgr = get_chain_route_manager(db)
                iptables_cleaned = chain_route_mgr.remove_route(
                    chain_tag=chain_tag,
                    mark_value=mark_value,
                    mark_type=mark_type,
                )
                if iptables_cleaned:
                    logging.info(
                        f"[tunnel-api] iptables 规则清理成功: chain={chain_tag}, "
                        f"mark={mark_value}"
                    )
                else:
                    logging.warning(
                        f"[tunnel-api] iptables 规则不存在或清理失败: chain={chain_tag}, "
                        f"mark={mark_value}"
                    )
            except ImportError:
                logging.warning("[tunnel-api] chain_route_manager 不可用，跳过 iptables 清理")
            except Exception as e:
                logging.warning(f"[tunnel-api] iptables 清理异常: {e}")

            return {
                "success": True,
                "message": "Chain route unregistered",
                "iptables_cleaned": iptables_cleaned
            }
        else:
            logging.warning(
                f"[tunnel-api] 链路路由不存在: chain={chain_tag}, "
                f"mark={mark_value}"
            )
            return {"success": False, "message": "Chain route not found"}
    except sqlite3.IntegrityError as e:
        logging.error(f"[tunnel-api] 链路路由注销数据库约束错误: {e}")
        return {"success": False, "message": "Database constraint error"}
    except sqlite3.OperationalError as e:
        logging.error(f"[tunnel-api] 链路路由注销数据库操作错误: {e}")
        return {"success": False, "message": "Database operation error"}
    except Exception as e:
        logging.error(f"[tunnel-api] 链路路由注销失败: {e}")
        return {"success": False, "message": "Failed to unregister chain route"}


@app.get("/api/chain-routing")
def api_chain_routing_list(request: Request, mark_type: Optional[str] = None):
    """获取链路路由列表

    获取此节点注册的所有链路路由。

    认证方式: 隧道 IP/UUID
    """
    client_ip = _get_client_ip(request)

    # 速率限制
    if not _check_api_rate_limit(client_ip):
        raise HTTPException(status_code=429, detail="Too many requests")

    if not HAS_DATABASE or not USER_DB_PATH.exists():
        raise HTTPException(status_code=503, detail="Database unavailable")

    db = _get_db()

    # 验证隧道认证（WireGuard IP / Xray UUID）
    node = _verify_tunnel_header(request, db)
    if not node:
        raise HTTPException(status_code=401, detail="Authentication failed")

    logging.debug(f"[tunnel-api] 获取链路路由列表: from {node['tag']} ({client_ip})")

    try:
        routes = db.get_chain_routing_list(mark_type=mark_type)
        return {
            "routes": [
                {
                    "chain_tag": r["chain_tag"],
                    "mark_value": r["mark_value"],
                    "mark_type": r.get("mark_type", "dscp"),
                    "egress_tag": r["egress_tag"],
                    "source_node": r.get("source_node"),
                    "registered_at": r.get("registered_at"),
                }
                for r in routes
            ]
        }
    except sqlite3.OperationalError as e:
        logging.error(f"[tunnel-api] 获取链路路由列表数据库操作错误: {e}")
        raise HTTPException(status_code=500, detail="Database operation error")
    except Exception as e:
        logging.error(f"[tunnel-api] 获取链路路由列表失败: {e}")
        raise HTTPException(status_code=500, detail="Failed to get chain routing list")


# 链路状态有效值
VALID_CHAIN_STATUSES = {"active", "inactive", "error"}


class ChainStatusRequest(BaseModel):
    """链路状态通知请求"""
    chain_tag: str = Field(
        ..., pattern=TAG_PATTERN,
        description="链路标识 (小写字母开头)"
    )
    status: str = Field(
        ..., pattern=r"^(active|inactive|error)$",
        description="链路状态 (active/inactive/error)"
    )
    message: Optional[str] = Field(
        default=None, max_length=500,
        description="可选状态消息"
    )


@app.post("/api/chain-routing/status")
def api_chain_routing_status(request: Request, payload: ChainStatusRequest):
    """通知链路状态变更

    用于在链路状态变更时通知相关节点（如中继节点或终端节点）。

    认证方式: 隧道 IP/UUID
    """
    client_ip = _get_client_ip(request)

    # 速率限制
    if not _check_api_rate_limit(client_ip):
        raise HTTPException(status_code=429, detail="Too many requests")

    if not HAS_DATABASE or not USER_DB_PATH.exists():
        raise HTTPException(status_code=503, detail="Database unavailable")

    db = _get_db()

    # 验证隧道认证（WireGuard IP / Xray UUID）
    node = _verify_tunnel_header(request, db)
    if not node:
        raise HTTPException(status_code=401, detail="Authentication failed")

    logging.info(
        f"[tunnel-api] 链路状态通知: chain={payload.chain_tag}, "
        f"status={payload.status}, from {node['tag']} ({client_ip})"
    )

    # 根据状态执行相应操作
    if payload.status == "inactive":
        # 链路停用，清理相关路由
        deleted_count = db.delete_chain_routing_by_chain(payload.chain_tag)
        logging.info(
            f"[tunnel-api] 链路停用，清理 {deleted_count} 条路由: chain={payload.chain_tag}"
        )
        return {
            "success": True,
            "message": f"Chain deactivated, {deleted_count} routes removed",
        }
    elif payload.status == "error":
        # 链路错误，记录日志但不自动清理
        logging.warning(
            f"[tunnel-api] 链路错误: chain={payload.chain_tag}, "
            f"message={payload.message}, from {node['tag']}"
        )
        return {"success": True, "message": "Chain error acknowledged"}
    else:
        # 链路激活（active），仅记录
        logging.info(f"[tunnel-api] 链路激活: chain={payload.chain_tag}, from {node['tag']}")
        return {"success": True, "message": "Chain activated"}


def _resolve_hostname(hostname: str) -> Optional[str]:
    """解析主机名为 IP 地址

    Args:
        hostname: 要解析的主机名

    Returns:
        解析后的 IP 地址，失败返回 None
    """
    import socket
    try:
        return socket.gethostbyname(hostname)
    except socket.gaierror:
        return None


def _get_local_ip() -> str:
    """获取本机 IP 地址（用于告知对端如何连接我们）"""
    import socket
    try:
        # 通过连接外部地址来获取本机 IP
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()
        return local_ip
    except Exception:
        return "127.0.0.1"


# ============ Endpoint Validation Helper ============

def _validate_endpoint(endpoint: str) -> tuple:
    """[安全] 完整验证 endpoint 格式 (host:port)

    Args:
        endpoint: 要验证的端点字符串

    Returns:
        (is_valid, error_message, host, port) - 验证结果、错误信息、主机名、端口号
    """
    if not endpoint:
        return False, "endpoint 不能为空", None, None

    if ":" not in endpoint:
        return False, "endpoint 格式应为 host:port", None, None

    # 分离主机名和端口
    try:
        host, port_str = endpoint.rsplit(":", 1)
    except ValueError:
        return False, "endpoint 格式无效", None, None

    # 验证主机名不为空
    if not host:
        return False, "主机名不能为空", None, None

    # [CR-003] 验证主机名格式
    if not validate_hostname(host):
        return False, f"主机名 '{host}' 格式无效（应为有效域名或 IP 地址）", None, None

    # [CR-004] 验证端口
    try:
        port = int(port_str)
    except ValueError:
        return False, f"端口 '{port_str}' 不是有效数字", None, None

    if not (1 <= port <= 65535):
        return False, f"端口 {port} 超出有效范围 (1-65535)", None, None

    return True, "", host, port


# ============ Peer Node CRUD API ============


def _check_peer_tunnel_status(node: dict) -> str:
    """检查对等节点隧道的实时状态

    对于 WireGuard 隧道：检查接口是否存在以及最后握手时间
    对于 Xray 隧道：检查 SOCKS 端口是否响应

    Args:
        node: 节点信息字典

    Returns:
        实时状态: "connected", "disconnected", "stale"
    """
    import time

    db_status = node.get("tunnel_status", "disconnected")
    tunnel_type = node.get("tunnel_type", "wireguard")
    userspace_wg = os.environ.get("USERSPACE_WG", "true").lower() == "true"

    # 如果数据库状态不是已连接，直接返回
    if db_status != "connected":
        return db_status

    if userspace_wg and tunnel_type == "wireguard":
        return db_status

    if tunnel_type == "wireguard":
        tunnel_interface = node.get("tunnel_interface")
        if not tunnel_interface:
            return "disconnected"

        try:
            # 检查接口是否存在
            result = subprocess.run(
                ["ip", "link", "show", tunnel_interface],
                capture_output=True, timeout=5
            )
            if result.returncode != 0:
                return "disconnected"

            # 检查最后握手时间
            result = subprocess.run(
                ["wg", "show", tunnel_interface, "latest-handshakes"],
                capture_output=True, text=True, timeout=5
            )
            if result.returncode != 0:
                return "disconnected"

            # 解析握手时间
            output = result.stdout.strip()
            if output:
                parts = output.split()
                if len(parts) >= 2:
                    try:
                        last_handshake = int(parts[1])
                        # 如果握手时间为0，说明接口已创建但尚未完成握手
                        # 这是正常的"正在连接"状态，不应该标记为断开
                        if last_handshake == 0:
                            return "connecting"  # 接口已创建，等待握手
                        elapsed = int(time.time()) - last_handshake
                        if elapsed > 180:
                            return "stale"  # 握手超时
                    except ValueError:
                        pass

            return "connected"
        except (subprocess.TimeoutExpired, Exception) as e:
            logging.warning(f"[peers] 检查 WireGuard 隧道状态失败: {e}")
            return db_status  # 检查失败时返回数据库状态

    elif tunnel_type == "xray":
        xray_socks_port = node.get("xray_socks_port")
        if not xray_socks_port:
            return "disconnected"

        try:
            import socket
            # 尝试连接 SOCKS 端口
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            result = sock.connect_ex(("127.0.0.1", xray_socks_port))
            sock.close()

            if result == 0:
                return "connected"
            else:
                return "disconnected"
        except Exception as e:
            logging.warning(f"[peers] 检查 Xray 隧道状态失败: {e}")
            return db_status

    return db_status


def _update_stale_peer_status(db, node: dict, real_status: str) -> None:
    """如果实时状态与数据库状态不一致，更新数据库

    Args:
        db: 数据库实例
        node: 节点信息
        real_status: 实时检测到的状态 (connected/connecting/stale/disconnected)
    """
    tag = node.get("tag")
    db_status = node.get("tunnel_status", "disconnected")

    # 如果实时状态是 "connecting"，说明接口已创建但尚未完成握手
    # 这是正常状态，不需要更新数据库（保持 "connected" 状态）
    if real_status == "connecting":
        return

    if real_status in ("disconnected", "stale") and db_status == "connected":
        try:
            db.update_peer_node(
                tag,
                tunnel_status="disconnected",
                last_error="隧道连接已断开（远端不可达）"
            )
            logging.info(f"[peers] 节点 '{tag}' 状态已更新为 disconnected（实时检测）")
        except Exception as e:
            logging.warning(f"[peers] 更新节点 '{tag}' 状态失败: {e}")


def _update_chains_for_disconnected_peer(db, peer_tag: str) -> dict:
    """Phase 5: 当节点断开时，更新受影响的链路状态

    查找使用该节点的所有活跃链路，并将其状态更新为 'error'。
    这确保了链路状态与实际隧道状态保持一致。

    Args:
        db: 数据库实例
        peer_tag: 断开的节点标签

    Returns:
        更新结果: {"updated": [链路列表], "errors": [错误列表]}
    """
    result = {"updated": [], "errors": []}

    try:
        # 使用已有的 get_chains_with_downstream_node 查找受影响的链路
        affected_chains = db.get_chains_with_downstream_node(peer_tag)

        for chain in affected_chains:
            chain_tag = chain.get("tag")
            chain_state = chain.get("chain_state", "inactive")

            # 只更新活跃的链路
            if chain_state in ("active", "activating"):
                try:
                    db.update_node_chain(
                        chain_tag,
                        chain_state="error",
                        last_error=f"Peer node '{peer_tag}' disconnected"
                    )
                    result["updated"].append(chain_tag)
                    logging.warning(
                        f"[chains] 链路 '{chain_tag}' 状态更新为 error: "
                        f"节点 '{peer_tag}' 已断开连接"
                    )
                except Exception as e:
                    result["errors"].append({"chain": chain_tag, "error": str(e)})
                    logging.error(f"[chains] 更新链路 '{chain_tag}' 状态失败: {e}")

        if result["updated"]:
            logging.info(
                f"[chains] 因节点 '{peer_tag}' 断开，已更新 {len(result['updated'])} 条链路状态"
            )

    except Exception as e:
        logging.error(f"[chains] 查找受影响链路失败: {e}")
        result["errors"].append({"chain": None, "error": str(e)})

    return result


@app.get("/api/peers")
def api_list_peers(enabled_only: bool = False):
    """列出所有对等节点"""
    if not HAS_DATABASE or not USER_DB_PATH.exists():
        raise HTTPException(status_code=503, detail="Database unavailable")

    db = _get_db()
    nodes = db.get_peer_nodes(enabled_only=enabled_only)

    # 实时检测隧道状态并更新
    for node in nodes:
        if node.get("tunnel_status") == "connected":
            real_status = _check_peer_tunnel_status(node)
            if real_status == "connecting":
                # 接口已创建但尚未完成握手，保持 "connected" 状态
                # 这是刚连接后的正常过渡状态
                pass
            elif real_status != "connected":
                # 真正的断开状态（disconnected 或 stale）
                _update_stale_peer_status(db, node, real_status)
                node["tunnel_status"] = "disconnected"

        # 隐藏敏感字段
        node.pop("psk_hash", None)
        node.pop("psk_encrypted", None)
        node.pop("wg_private_key", None)
        node.pop("remote_wg_private_key", None)  # Phase 11.1: 预生成密钥不应暴露
        node.pop("xray_reality_private_key", None)

    return {"nodes": nodes, "count": len(nodes)}


@app.get("/api/peers/{tag}")
def api_get_peer(tag: str):
    """获取单个对等节点详情"""
    if not HAS_DATABASE or not USER_DB_PATH.exists():
        raise HTTPException(status_code=503, detail="Database unavailable")

    db = _get_db()
    node = db.get_peer_node(tag)

    if not node:
        raise HTTPException(status_code=404, detail=f"节点 '{tag}' 不存在")

    # 实时检测隧道状态并更新
    if node.get("tunnel_status") == "connected":
        real_status = _check_peer_tunnel_status(node)
        if real_status == "connecting":
            # 接口已创建但尚未完成握手，保持 "connected" 状态
            pass
        elif real_status != "connected":
            _update_stale_peer_status(db, node, real_status)
            node["tunnel_status"] = "disconnected"

    # 隐藏敏感字段
    node.pop("psk_hash", None)
    node.pop("psk_encrypted", None)
    node.pop("wg_private_key", None)
    node.pop("remote_wg_private_key", None)  # Phase 11.1: 预生成密钥不应暴露
    node.pop("xray_reality_private_key", None)

    return node


@app.post("/api/peers")
def api_create_peer(payload: PeerNodeCreateRequest):
    """创建新的对等节点

    对于 Xray 类型节点，自动生成 REALITY 密钥（私钥、公钥、Short ID）。
    固定使用 VLESS+XHTTP+REALITY 协议组合。
    """
    if not HAS_DATABASE or not USER_DB_PATH.exists():
        raise HTTPException(status_code=503, detail="Database unavailable")

    db = _get_db()

    # 检查 tag 是否已存在
    if db.get_peer_node(payload.tag):
        raise HTTPException(status_code=400, detail=f"节点标识 '{payload.tag}' 已存在")

    # Phase 11-Cascade: 检查墓碑（防止删除后立即重建）
    if db.is_peer_tombstoned(payload.tag):
        raise HTTPException(
            status_code=409,
            detail=f"节点 '{payload.tag}' 处于墓碑期，请等待墓碑过期后再创建"
        )

    # [CR-003/CR-004] 完整验证 endpoint 格式 (host:port)
    is_valid, error_msg, _, _ = _validate_endpoint(payload.endpoint)
    if not is_valid:
        raise HTTPException(status_code=400, detail=error_msg)

    # Phase 6 Fix: 端口配置提示（使用有效范围 36200-36299）
    # Peer WireGuard 端口: 36200-36299, API 端口: 36000
    # 常见错误: 使用 36100 (WireGuard 入口端口) 而非 36200-36299
    try:
        port_str = payload.endpoint.rsplit(":", 1)[1] if ":" in payload.endpoint else ""
        port = int(port_str) if port_str else 0
        peer_port_min = int(os.environ.get("PEER_TUNNEL_PORT_MIN", "36200"))
        peer_port_max = int(os.environ.get("PEER_TUNNEL_PORT_MAX", "36299"))
        # 检查是否在有效范围内（peer 端口范围或 API 端口）
        is_valid_peer_port = peer_port_min <= port <= peer_port_max
        is_api_port = port == DEFAULT_WEB_PORT
        if port and not is_valid_peer_port and not is_api_port:
            if port == DEFAULT_WG_PORT:
                logging.warning(
                    f"[peers] 端口配置提示: '{payload.tag}' 使用端口 {port}。"
                    f"{DEFAULT_WG_PORT} 是客户端 WireGuard 入口端口，peer 隧道应使用 {peer_port_min}-{peer_port_max}。"
                    f"请确认远程节点的 peer WireGuard 监听端口配置。"
                )
            elif port < 36000 or port > 40000:
                logging.info(
                    f"[peers] 端口配置提示: '{payload.tag}' 使用非标准端口 {port}。"
                    f"标准端口: {peer_port_min}-{peer_port_max} (peer WireGuard), {DEFAULT_WEB_PORT} (API)。"
                )
    except (ValueError, IndexError):
        pass  # 端口解析失败，跳过警告

    # 验证隧道类型
    if payload.tunnel_type not in ("wireguard", "xray"):
        raise HTTPException(status_code=400, detail="tunnel_type 必须是 wireguard 或 xray")

    # 验证默认出口存在
    if payload.default_outbound:
        available = _get_available_outbounds(db)
        if payload.default_outbound not in available:
            raise HTTPException(status_code=400, detail=f"出口 '{payload.default_outbound}' 不存在")

    # PSK 已废弃 - WireGuard 用隧道 IP 认证，Xray 用 UUID 认证

    # 为 Xray 节点自动生成 REALITY 密钥
    xray_reality_private_key = None
    xray_reality_public_key = None
    xray_reality_short_id = None

    if payload.tunnel_type == "xray":
        reality_keys = _generate_xray_reality_keys()
        if not reality_keys:
            raise HTTPException(status_code=500, detail="生成 REALITY 密钥失败")
        xray_reality_private_key = reality_keys["private_key"]
        xray_reality_public_key = reality_keys["public_key"]
        xray_reality_short_id = reality_keys["short_id"]
        logging.info(f"[peers] 为节点 '{payload.tag}' 生成 REALITY 密钥")

    # 将 Server Names 列表转为 JSON 字符串存储
    xray_reality_server_names = json.dumps(payload.xray_reality_server_names)

    try:
        node_id = db.add_peer_node(
            tag=payload.tag,
            name=payload.name,
            description=payload.description,
            endpoint=payload.endpoint,
            api_port=payload.api_port,
            # PSK 已废弃，传空值保持向后兼容
            psk_hash="",
            psk_encrypted=None,
            tunnel_type=payload.tunnel_type,
            # Xray 协议固定为 VLESS
            xray_protocol="vless",
            # REALITY 配置
            xray_reality_private_key=xray_reality_private_key,
            xray_reality_public_key=xray_reality_public_key,
            xray_reality_short_id=xray_reality_short_id,
            xray_reality_dest=payload.xray_reality_dest,
            xray_reality_server_names=xray_reality_server_names,
            # XHTTP 传输配置
            xray_xhttp_path=payload.xray_xhttp_path,
            xray_xhttp_mode=payload.xray_xhttp_mode,
            xray_xhttp_host=payload.xray_xhttp_host,
            # 连接模式
            connection_mode=payload.connection_mode,
            default_outbound=payload.default_outbound,
            auto_reconnect=payload.auto_reconnect,
            enabled=payload.enabled,
        )
    except Exception as e:
        logging.error(f"创建节点失败: {e}")
        raise HTTPException(status_code=500, detail=f"创建节点失败: {e}")

    logging.info(f"[peers] 创建节点 '{payload.tag}' (id={node_id})")
    return {
        "message": f"节点 '{payload.tag}' 创建成功",
        "id": node_id,
        "tag": payload.tag,
    }


@app.put("/api/peers/{tag}")
def api_update_peer(tag: str, payload: PeerNodeUpdateRequest):
    """更新对等节点配置"""
    if not HAS_DATABASE or not USER_DB_PATH.exists():
        raise HTTPException(status_code=503, detail="Database unavailable")

    db = _get_db()

    # 检查节点是否存在
    node = db.get_peer_node(tag)
    if not node:
        raise HTTPException(status_code=404, detail=f"节点 '{tag}' 不存在")

    # 构建更新参数
    update_kwargs = {}

    if payload.name is not None:
        update_kwargs["name"] = payload.name
    if payload.description is not None:
        update_kwargs["description"] = payload.description
    if payload.endpoint is not None:
        # [CR-003/CR-004] 完整验证 endpoint 格式
        is_valid, error_msg, _, _ = _validate_endpoint(payload.endpoint)
        if not is_valid:
            raise HTTPException(status_code=400, detail=error_msg)
        update_kwargs["endpoint"] = payload.endpoint
    if payload.api_port is not None:
        update_kwargs["api_port"] = payload.api_port
    # NOTE: psk field removed - WireGuard uses tunnel IP authentication, Xray uses UUID authentication
    if payload.tunnel_type is not None:
        if payload.tunnel_type not in ("wireguard", "xray"):
            raise HTTPException(status_code=400, detail="tunnel_type 必须是 wireguard 或 xray")
        update_kwargs["tunnel_type"] = payload.tunnel_type
        # 如果切换到 xray 且没有 REALITY 密钥，自动生成
        if payload.tunnel_type == "xray" and not node.get("xray_reality_private_key"):
            reality_keys = _generate_xray_reality_keys()
            if reality_keys:
                update_kwargs["xray_reality_private_key"] = reality_keys["private_key"]
                update_kwargs["xray_reality_public_key"] = reality_keys["public_key"]
                update_kwargs["xray_reality_short_id"] = reality_keys["short_id"]
                logging.info(f"[peers] 为节点 '{tag}' 生成 REALITY 密钥")

    # REALITY 配置
    if payload.xray_reality_dest is not None:
        update_kwargs["xray_reality_dest"] = payload.xray_reality_dest
    if payload.xray_reality_server_names is not None:
        update_kwargs["xray_reality_server_names"] = json.dumps(payload.xray_reality_server_names)

    # XHTTP 传输配置
    if payload.xray_xhttp_path is not None:
        update_kwargs["xray_xhttp_path"] = payload.xray_xhttp_path
    if payload.xray_xhttp_mode is not None:
        update_kwargs["xray_xhttp_mode"] = payload.xray_xhttp_mode
    if payload.xray_xhttp_host is not None:
        update_kwargs["xray_xhttp_host"] = payload.xray_xhttp_host

    if payload.default_outbound is not None:
        if payload.default_outbound:
            available = _get_available_outbounds(db)
            if payload.default_outbound not in available:
                raise HTTPException(status_code=400, detail=f"出口 '{payload.default_outbound}' 不存在")
        update_kwargs["default_outbound"] = payload.default_outbound or None
    if payload.auto_reconnect is not None:
        update_kwargs["auto_reconnect"] = payload.auto_reconnect
    if payload.enabled is not None:
        update_kwargs["enabled"] = payload.enabled
    # 连接模式
    if payload.connection_mode is not None:
        update_kwargs["connection_mode"] = payload.connection_mode

    if not update_kwargs:
        return {"message": "没有需要更新的字段", "peer": node}

    success = db.update_peer_node(tag, **update_kwargs)
    if not success:
        raise HTTPException(status_code=500, detail="更新节点失败")

    # Phase A 审核修复: 当 api_port 变更时，使客户端缓存失效
    # 确保后续 API 调用使用新端口
    if "api_port" in update_kwargs:
        try:
            from tunnel_api_client import TunnelAPIClientManager
            client_mgr = TunnelAPIClientManager(db)
            client_mgr.invalidate_client(tag)
            logging.info(f"[peers] 端口变更，清除客户端缓存: {tag}")
        except Exception as e:
            logging.warning(f"[peers] 清除客户端缓存失败: {e}")

    updated_node = db.get_peer_node(tag)
    updated_node.pop("psk_hash", None)
    updated_node.pop("psk_encrypted", None)
    updated_node.pop("wg_private_key", None)
    updated_node.pop("remote_wg_private_key", None)  # Phase 11.1: 预生成密钥不应暴露
    updated_node.pop("xray_reality_private_key", None)

    logging.info(f"[peers] 更新节点 '{tag}'")
    return {"message": f"节点 '{tag}' 已更新", "peer": updated_node}


@app.delete("/api/peers/{tag}")
def api_delete_peer(tag: str, cascade: bool = Query(True, description="是否发送级联删除通知")):
    """删除对等节点

    Phase 11-Cascade: 支持级联删除通知
    - 删除前通知目标节点（让对方清理连接）
    - 删除后广播给所有其他连接的节点
    - 添加墓碑防止对方重连
    """
    if not HAS_DATABASE or not USER_DB_PATH.exists():
        raise HTTPException(status_code=503, detail="Database unavailable")

    db = _get_db()

    # 检查节点是否存在
    node = db.get_peer_node(tag)
    if not node:
        raise HTTPException(status_code=404, detail=f"节点 '{tag}' 不存在")

    # 检查是否有链路使用此节点
    chains = db.get_node_chains()
    for chain in chains:
        # Issue 11/12 修复：使用统一的 hops 解析函数
        hops = _parse_chain_hops(chain, raise_on_error=False)
        if tag in hops:
            raise HTTPException(
                status_code=400,
                detail=f"无法删除: 节点 '{tag}' 被链路 '{chain['tag']}' 使用"
            )

    # Phase 11-Cascade: 获取本节点标识
    local_node_tag = _get_local_node_tag(db)
    cascade_results = {"notified_target": False, "broadcast_count": 0}

    # Phase 11-Cascade: 在删除前通知目标节点（如果已连接）
    if cascade and node.get("tunnel_status") == "connected":
        try:
            from tunnel_api_client import TunnelAPIClientManager
            api_manager = TunnelAPIClientManager(db)

            # 尝试通知目标节点
            notified = api_manager.notify_peer_delete(
                peer_tag=tag,
                source_node=local_node_tag,
                reason="local_delete",
            )
            cascade_results["notified_target"] = notified

            if notified:
                logging.info(f"[peers] 级联通知: 已通知 {tag} 删除事件")
            else:
                logging.warning(f"[peers] 级联通知: 无法通知 {tag}")

        except Exception as e:
            logging.warning(f"[peers] 级联通知目标节点失败: {e}")

    # 清理 WireGuard/Xray 隧道接口（无论数据库状态如何，确保内核接口被删除）
    try:
        from peer_tunnel_manager import PeerTunnelManager
        manager = PeerTunnelManager()
        manager.disconnect_node(tag)
        logging.info(f"[peers] 删除前清理隧道接口: {tag}")
    except Exception as e:
        # 接口可能不存在，忽略错误继续删除
        logging.debug(f"[peers] 清理隧道接口: {e}")

    # 删除数据库记录
    success = db.delete_peer_node(tag)
    if not success:
        raise HTTPException(status_code=500, detail="删除节点失败")

    # Phase 11-Cascade: 添加墓碑防止对方重连
    try:
        db.add_peer_tombstone(
            tag=tag,
            deleted_by=local_node_tag,
            reason="local_delete",
            ttl_hours=24
        )
        logging.info(f"[peers] 添加墓碑: {tag}")
    except Exception as e:
        logging.warning(f"[peers] 添加墓碑失败: {e}")

    # Phase 11-Cascade: 广播给所有其他连接的节点
    if cascade:
        try:
            from tunnel_api_client import TunnelAPIClientManager
            api_manager = TunnelAPIClientManager(db)

            broadcast_results = api_manager.broadcast_delete_event(
                deleted_node=tag,
                source_node=local_node_tag,
                reason="peer_deleted",
                ttl=2,  # 广播最多传播 2 跳
            )
            cascade_results["broadcast_count"] = sum(1 for v in broadcast_results.values() if v)
            cascade_results["broadcast_results"] = broadcast_results

            logging.info(f"[peers] 级联广播: 通知 {cascade_results['broadcast_count']} 个节点")

        except Exception as e:
            logging.warning(f"[peers] 级联广播失败: {e}")

    # 记录删除事件到审计日志
    try:
        db.log_peer_event(
            event_type="delete",
            peer_tag=tag,
            from_node=local_node_tag,
            details={"cascade": cascade, "cascade_results": cascade_results}
        )
    except Exception as e:
        logging.debug(f"[peers] 记录删除事件失败: {e}")

    logging.info(f"[peers] 删除节点 '{tag}'")
    return {
        "message": f"节点 '{tag}' 已删除",
        "cascade": cascade_results if cascade else None
    }


# ============ 离线配对 API ============

@app.post("/api/peer/generate-pair-request", response_model=GeneratePairRequestResponse)
def api_generate_pair_request(payload: GeneratePairRequestRequest):
    """生成配对请求码（Phase 11-Tunnel: 隧道优先模式）

    生成配对请求码，同时创建 WireGuard 接口开始监听。
    这样对端导入配对码后可以直接连接，通过隧道完成握手。

    新流程：
    1. 验证端点格式
    2. 生成 WireGuard 密钥对（包括为对端预生成的密钥）
    3. 分配隧道 IP 子网和监听端口
    4. 创建 WireGuard 接口并开始监听
    5. 保存到 pending_pairings 表
    6. 返回配对码（对端可直接连接）
    """
    if not HAS_DATABASE or not USER_DB_PATH.exists():
        raise HTTPException(status_code=503, detail="Database unavailable")

    if not HAS_PAIRING:
        raise HTTPException(status_code=503, detail="Pairing module not available")

    # 验证端点格式 (IP:port 或 域名:port)
    endpoint = payload.endpoint.strip()
    if ':' not in endpoint:
        raise HTTPException(status_code=400, detail="Endpoint must include port (e.g., '10.1.1.1:36200')")

    host, port_str = endpoint.rsplit(':', 1)
    try:
        port = int(port_str)
        if not (1 <= port <= 65535):
            raise ValueError("Port out of range")
    except ValueError:
        raise HTTPException(status_code=400, detail=f"Invalid port in endpoint: {port_str}")

    if not validate_hostname(host):
        raise HTTPException(status_code=400, detail=f"Invalid hostname: {host}")

    db = _get_db()
    generator = PairingCodeGenerator(db)

    interface_name = None  # 用于错误时清理
    pairing_id = None  # Phase 6 Issue 30: 用于错误时清理 pending_pairing

    try:
        # Phase 11-Fix.AC: Check userspace WG mode - route to IPC
        userspace_wg = os.environ.get("USERSPACE_WG", "true").lower() == "true"

        if userspace_wg and payload.tunnel_type == "wireguard":
            # Use rust-router IPC for pairing in userspace WG mode
            success, code_or_error, peer_tag, pending_data = _run_async_ipc(
                _generate_pair_request_via_ipc(
                    node_tag=payload.node_tag,
                    node_description=payload.node_description,
                    endpoint=endpoint,
                    api_port=payload.api_port,
                    bidirectional=payload.bidirectional,
                    tunnel_type=payload.tunnel_type,
                )
            )

            if not success:
                raise HTTPException(status_code=503, detail=code_or_error)

            # Build pending_request for response
            pending_request = {
                "node_tag": payload.node_tag,
                "tunnel_type": payload.tunnel_type,
                "bidirectional": payload.bidirectional,
            }
            pending_request.update(pending_data)

            logging.info(f"[pairing] 生成配对请求码 (IPC): node_tag={payload.node_tag}")
            return GeneratePairRequestResponse(
                code=code_or_error,
                psk="",
                pending_request=pending_request
            )

        # Existing kernel WireGuard code path continues below...
        # Step 1: 分配隧道 IP 和端口（需要在生成配对码之前，以便包含在配对码中）
        # Phase 11-Fix.C: 使用确定性分配以避免多节点场景下的冲突
        local_ip = None
        remote_ip = None
        listen_port = None
        actual_endpoint = endpoint  # 使用实际分配的端口

        if payload.tunnel_type == "wireguard" and payload.bidirectional and HAS_PENDING_TUNNEL:
            import socket
            local_hostname = socket.gethostname()
            subnet_idx, local_ip, remote_ip = _get_next_peer_tunnel_subnet(
                db,
                local_node_tag=local_hostname,
                remote_node_tag=payload.node_tag
            )
            logging.info(f"[pairing] 确定性分配隧道 IP: local={local_ip}, remote={remote_ip} (基于 {local_hostname} <-> {payload.node_tag})")

            # Issue 7 Fix: 在生成配对码之前分配端口，确保配对码中包含正确的端口
            # endpoint 中用户指定的端口可能与保留端口(36100等)冲突，需使用自动分配的端口
            listen_port = _allocate_peer_tunnel_port(db)

            # Issue 7 Fix: 如果用户指定的端口是保留端口，使用分配的端口替换 endpoint
            if port in RESERVED_PORTS or port != listen_port:
                actual_endpoint = f"{host}:{listen_port}"
                if port in RESERVED_PORTS:
                    logging.warning(f"[pairing] 用户指定端口 {port} 是保留端口 ({RESERVED_PORTS[port]})，替换为 {listen_port}")
                else:
                    logging.info(f"[pairing] 分配隧道监听端口: {listen_port} (用户指定端口 {port})")

        # Step 2: 生成配对码和密钥对（包含隧道 IP 和正确的端口）
        # Phase 11-Fix.K: 传递 api_port
        code, _, request_obj = generator.generate_pair_request(
            node_tag=payload.node_tag,
            node_description=payload.node_description,
            endpoint=actual_endpoint,  # Issue 7 Fix: 使用实际分配的端口
            tunnel_type=payload.tunnel_type,
            # PSK 已废弃，使用隧道 IP/UUID 认证
            bidirectional=payload.bidirectional,
            tunnel_local_ip=local_ip,
            tunnel_remote_ip=remote_ip,
            api_port=payload.api_port,
        )

        # Step 3: 为 WireGuard 隧道创建接口（只有 bidirectional + wireguard 才创建）
        if payload.tunnel_type == "wireguard" and payload.bidirectional and HAS_PENDING_TUNNEL:
            # Phase 11-Fix.C: 使用完整 code 生成 pairing_id + 碰撞检测
            import secrets
            pairing_id = hashlib.md5(code.encode()).hexdigest()  # 使用完整 code
            # 碰撞检测：如果已存在相同 pairing_id，添加随机后缀
            if db.get_pending_pairing(pairing_id):
                collision_suffix = secrets.token_hex(4)
                pairing_id = pairing_id[:24] + collision_suffix
                logging.warning(f"[pairing] pairing_id 碰撞检测: 添加随机后缀 {collision_suffix}")

            # 获取密钥
            private_key = getattr(request_obj, '_private_key', None)
            remote_public_key = request_obj.remote_wg_public_key

            if not private_key or not remote_public_key:
                raise ValueError("缺少 WireGuard 密钥")

            # 创建 WireGuard 接口
            success, interface_name, error = create_pending_wireguard_interface(
                pairing_id=pairing_id,
                local_ip=local_ip,
                remote_ip=remote_ip,
                listen_port=listen_port,
                private_key=private_key,
                expected_peer_public_key=remote_public_key,
            )

            if not success:
                raise ValueError(f"创建 WireGuard 接口失败: {error}")

            # 保存到 pending_pairings 表
            db.add_pending_pairing(
                pairing_id=pairing_id,
                local_tag=payload.node_tag,
                local_endpoint=actual_endpoint,  # Issue 7 Fix: 使用实际分配的端口
                tunnel_type=payload.tunnel_type,
                tunnel_local_ip=local_ip,
                tunnel_remote_ip=remote_ip,
                tunnel_port=listen_port,
                wg_private_key=private_key,
                wg_public_key=request_obj.wg_public_key,
                remote_wg_private_key=request_obj.remote_wg_private_key,
                remote_wg_public_key=remote_public_key,
                interface_name=interface_name,
            )

            logging.info(f"[pairing] 创建待处理配对: pairing_id={pairing_id}, interface={interface_name}, "
                        f"local_ip={local_ip}, listen_port={listen_port}")

        # Step 3: 构建待处理请求信息
        pending_request = {
            "node_tag": payload.node_tag,
            "tunnel_type": payload.tunnel_type,
            "bidirectional": payload.bidirectional,
        }

        # 保存密钥信息
        if payload.tunnel_type == "wireguard":
            pending_request["wg_private_key"] = getattr(request_obj, '_private_key', None)
            pending_request["wg_public_key"] = request_obj.wg_public_key
            if payload.bidirectional:
                pending_request["remote_wg_private_key"] = request_obj.remote_wg_private_key
                pending_request["remote_wg_public_key"] = request_obj.remote_wg_public_key
        elif payload.tunnel_type == "xray":
            pending_request["xray_private_key"] = getattr(request_obj, '_private_key', None)
            pending_request["xray_public_key"] = request_obj.xray_reality_public_key
            pending_request["xray_short_id"] = request_obj.xray_reality_short_id

        logging.info(f"[pairing] 生成配对请求码: node_tag={payload.node_tag}, bidirectional={payload.bidirectional}")
        return GeneratePairRequestResponse(
            code=code,
            psk="",  # PSK 已废弃，保留空字符串向后兼容
            pending_request=pending_request
        )

    except HTTPException:
        # 清理接口
        if interface_name and HAS_PENDING_TUNNEL:
            teardown_pending_wireguard_interface(interface_name)
        # Phase 6 Issue 30: 清理 pending_pairing 记录
        if pairing_id:
            try:
                db.delete_pending_pairing(pairing_id)
                logging.info(f"[pairing] 清理 pending_pairing: {pairing_id}")
            except Exception:
                pass
        raise

    except Exception as e:
        # 清理接口
        if interface_name and HAS_PENDING_TUNNEL:
            teardown_pending_wireguard_interface(interface_name)
        # Phase 6 Issue 30: 清理 pending_pairing 记录
        if pairing_id:
            try:
                db.delete_pending_pairing(pairing_id)
                logging.info(f"[pairing] 清理 pending_pairing: {pairing_id}")
            except Exception:
                pass
        logging.error(f"[pairing] 生成配对请求码失败: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to generate pairing code: {e}")


@app.post("/api/peer/import-pair-request", response_model=ImportPairRequestResponse)
def api_import_pair_request(payload: ImportPairRequestRequest):
    """导入配对请求码

    Phase 11-Tunnel: 隧道优先配对流程

    导入对方发送的配对请求码，通过隧道完成配对。

    新流程（隧道优先）：
    1. 验证配对请求码
    2. 使用预生成密钥创建 WireGuard 接口
    3. 连接到对方端点
    4. 通过隧道调用对方的 complete-handshake API
    5. 创建本地 peer_node

    旧流程（回退）：
    如果配对码中没有预生成密钥，使用旧的响应码方式
    """
    if not HAS_DATABASE or not USER_DB_PATH.exists():
        raise HTTPException(status_code=503, detail="Database unavailable")

    if not HAS_PAIRING:
        raise HTTPException(status_code=503, detail="Pairing module not available")

    # 验证端点格式
    endpoint = payload.local_endpoint.strip()
    if ':' not in endpoint:
        raise HTTPException(status_code=400, detail="Endpoint must include port (e.g., '10.1.1.1:36200')")

    host, port_str = endpoint.rsplit(':', 1)
    try:
        local_listen_port = int(port_str)
        if not (1 <= local_listen_port <= 65535):
            raise ValueError("Port out of range")
    except ValueError:
        raise HTTPException(status_code=400, detail=f"Invalid port in endpoint: {port_str}")

    if not validate_hostname(host):
        raise HTTPException(status_code=400, detail=f"Invalid hostname: {host}")

    db = _get_db()
    generator = PairingCodeGenerator(db)

    # Step 1: 验证配对请求码 (moved BEFORE IPC check to get tunnel_type)
    is_valid, error, request_obj = generator.validate_pair_request(payload.code)
    if not is_valid:
        return ImportPairRequestResponse(
            success=False,
            message=f"Invalid pairing code: {error}",
            response_code=None,
            created_node_tag=None
        )

    # Phase 11-Fix.AC: Check userspace WG mode - route to IPC for WireGuard only
    # Xray tunnels always use kernel code path
    userspace_wg = os.environ.get("USERSPACE_WG", "true").lower() == "true"

    if userspace_wg and request_obj.tunnel_type == "wireguard":
        # Use rust-router IPC for importing in userspace WG mode
        success, response_code_or_error, remote_tag, response_data = _run_async_ipc(
            _import_pair_request_via_ipc(
                code=payload.code,
                local_tag=payload.local_node_tag,
                local_description=payload.local_node_description,
                local_endpoint=endpoint,
                local_api_port=payload.api_port or 36000,
            )
        )

        if not success:
            return ImportPairRequestResponse(
                success=False,
                message=response_code_or_error,
                response_code=None,
                created_node_tag=None
            )

        # Check if tunnel was established directly (no response code needed)
        tunnel_status = response_data.get("tunnel_status")
        bidirectional = response_data.get("bidirectional", request_obj.bidirectional)

        _sync_userspace_peer_from_codes(
            db,
            request_code=payload.code,
            response_code=response_code_or_error,
            local_tag=payload.local_node_tag,
            local_endpoint=endpoint,
            tunnel_status="connected" if bidirectional else "disconnected",
        )

        logging.info(f"[pairing] 导入配对请求 (IPC): remote_tag={remote_tag}, tunnel_status={tunnel_status}")
        return ImportPairRequestResponse(
            success=True,
            message=response_data.get("message", "Pairing request imported via IPC"),
            response_code=response_code_or_error if response_code_or_error else None,
            created_node_tag=remote_tag,
            tunnel_status=tunnel_status,
            bidirectional=bidirectional
        )

    # Existing kernel WireGuard / Xray code path continues below...
    # (validation already done above at the start of the function)

    # 检查是否已存在同名节点
    remote_node_tag = request_obj.node_tag
    existing = db.get_peer_node(remote_node_tag)
    if existing:
        return ImportPairRequestResponse(
            success=False,
            message=f"Peer node '{remote_node_tag}' already exists",
            response_code=None,
            created_node_tag=None
        )

    # Step 2: 判断使用隧道优先还是旧流程
    is_tunnel_first = (
        request_obj.tunnel_type == "wireguard" and
        request_obj.bidirectional and
        request_obj.remote_wg_private_key and
        request_obj.remote_wg_public_key and
        HAS_PENDING_TUNNEL
    )

    if not is_tunnel_first:
        # 回退到旧流程（使用响应码）
        logging.info(f"[pairing] 使用旧流程（响应码模式）: 缺少预生成密钥或非 WireGuard")
        manager = PairingManager(db)
        try:
            # Phase 11-Fix.K: 传递 api_port
            # PSK 已废弃，使用隧道 IP/UUID 认证
            success, message, response_code = manager.import_pair_request(
                code=payload.code,
                local_node_tag=payload.local_node_tag,
                local_node_description=payload.local_node_description,
                local_endpoint=endpoint,
                api_port=payload.api_port,
            )
            if not success:
                return ImportPairRequestResponse(
                    success=False,
                    message=message,
                    response_code=None,
                    created_node_tag=None
                )
            return ImportPairRequestResponse(
                success=True,
                message=message,
                response_code=response_code,
                created_node_tag=remote_node_tag,
                bidirectional=False
            )
        except Exception as e:
            logging.error(f"[pairing] 旧流程导入失败: {e}")
            raise HTTPException(status_code=500, detail=f"Failed to import pairing request: {e}")

    # ===== 隧道优先流程 =====
    logging.info(f"[pairing] 使用隧道优先流程: remote_node={remote_node_tag}")

    interface_name = None
    try:
        # Issue 7 Fix: 使用自动分配的端口，避免与保留端口冲突
        # 用户指定的 endpoint 端口可能是 36100 等保留端口
        allocated_listen_port = _allocate_peer_tunnel_port(db)
        if local_listen_port in RESERVED_PORTS:
            logging.warning(f"[pairing] 用户指定端口 {local_listen_port} 是保留端口 ({RESERVED_PORTS[local_listen_port]})，使用分配端口 {allocated_listen_port}")
        local_listen_port = allocated_listen_port
        # 更新 endpoint 以使用正确的端口
        endpoint = f"{host}:{local_listen_port}"

        # Step 3: 计算 pairing_id（与 generate-pair-request 相同的算法）
        # Phase 11-Fix.C: 使用完整 code 计算（与生成端保持一致）
        pairing_id = hashlib.md5(payload.code.encode()).hexdigest()

        # Step 4: 获取隧道 IP（从配对码中）
        # 注意：我们是 Node B，使用配对码中的 remote_wg_* 作为自己的密钥
        # IP 分配：A 的 tunnel_local_ip 是 A 的 IP，A 的 tunnel_remote_ip 是给 B 预分配的 IP
        # 所以对于 B：local_ip = A 的 tunnel_remote_ip，remote_ip = A 的 tunnel_local_ip
        if request_obj.tunnel_local_ip and request_obj.tunnel_remote_ip:
            # 使用配对码中的 IP（交换 local/remote）
            local_ip = request_obj.tunnel_remote_ip  # B 使用 A 预分配的 IP
            remote_ip = request_obj.tunnel_local_ip  # A 的 IP
            logging.info(f"[pairing] 使用配对码中的隧道 IP: local={local_ip}, remote={remote_ip}")
        else:
            # 回退：使用确定性分配
            logging.warning("[pairing] 配对码中没有隧道 IP，使用确定性分配")
            subnet_idx, _, _ = _get_next_peer_tunnel_subnet(db, payload.local_node_tag, remote_node_tag)
            local_ip = f"10.200.200.{subnet_idx * 4 + 2}"  # B 使用 .2
            remote_ip = f"10.200.200.{subnet_idx * 4 + 1}"  # A 使用 .1

        # Step 5: 创建 WireGuard 接口并连接
        interface_name = get_interface_name(remote_node_tag, "wireguard")

        # 使用预生成的密钥
        local_private_key = request_obj.remote_wg_private_key
        local_public_key = request_obj.remote_wg_public_key
        peer_public_key = request_obj.wg_public_key  # A 的公钥

        success, error = create_wireguard_tunnel_with_endpoint(
            interface_name=interface_name,
            local_ip=local_ip,
            remote_ip=remote_ip,
            listen_port=local_listen_port,
            private_key=local_private_key,
            peer_public_key=peer_public_key,
            remote_endpoint=request_obj.endpoint,  # A 的端点
        )

        if not success:
            raise ValueError(f"Failed to create WireGuard tunnel: {error}")

        logging.info(f"[pairing] WireGuard 接口已创建: {interface_name}")

        # Step 6: 等待握手完成
        if not wait_for_wireguard_handshake(interface_name, timeout_seconds=15):
            raise ValueError("WireGuard handshake timeout - remote endpoint may not be listening")

        logging.info(f"[pairing] WireGuard 握手成功，开始隧道握手")

        # Step 7: 通过隧道调用对方的 complete-handshake API
        from tunnel_api_client import TunnelAPIClient

        # Phase 11-Fix.K: 隧道 API 端点使用正确的 api_port
        remote_api_port = request_obj.api_port or DEFAULT_WEB_PORT
        tunnel_api_endpoint = f"{remote_ip}:{remote_api_port}"

        client = TunnelAPIClient(
            node_tag=remote_node_tag,
            tunnel_endpoint=tunnel_api_endpoint,
            tunnel_type="wireguard",
        )

        # Phase 11-Fix.K: 传递本节点 API 端口
        handshake_result = client.request_complete_handshake(
            pairing_id=pairing_id,
            local_node_tag=payload.local_node_tag,
            local_node_description=payload.local_node_description,
            local_endpoint=endpoint,
            local_tunnel_ip=local_ip,
            wg_public_key=local_public_key,
            api_port=payload.api_port,  # Phase 11-Fix.K
        )

        if not handshake_result.get("success"):
            raise ValueError(f"Handshake failed: {handshake_result.get('message', 'Unknown error')}")

        logging.info(f"[pairing] 隧道握手完成")

        # Step 8: 创建本地 peer_node
        # Phase 11-Fix.K: 保存 api_port 到数据库
        db.add_peer_node(
            tag=remote_node_tag,
            name=remote_node_tag,
            description=request_obj.node_description or f"Paired from {request_obj.endpoint}",
            endpoint=request_obj.endpoint,
            api_port=request_obj.api_port,  # Phase 11-Fix.K: 保存 API 端口
            tunnel_type="wireguard",
            tunnel_status="connected",
            tunnel_interface=interface_name,
            tunnel_local_ip=local_ip,
            tunnel_remote_ip=remote_ip,
            tunnel_port=local_listen_port,
            wg_private_key=local_private_key,
            wg_public_key=local_public_key,
            wg_peer_public_key=peer_public_key,
            tunnel_api_endpoint=tunnel_api_endpoint,
            bidirectional_status="bidirectional",
        )

        logging.info(f"[pairing] 隧道优先配对完成: {remote_node_tag}")

        return ImportPairRequestResponse(
            success=True,
            message="Pairing completed via tunnel",
            response_code=None,  # 隧道优先模式不需要响应码
            created_node_tag=remote_node_tag,
            tunnel_status="connected",
            bidirectional=True
        )

    except Exception as e:
        # 清理接口
        if interface_name:
            try:
                subprocess.run(["ip", "link", "delete", interface_name], check=False, timeout=10)
            except Exception:
                pass
        logging.error(f"[pairing] 隧道优先配对失败: {e}")
        return ImportPairRequestResponse(
            success=False,
            message=str(e),
            response_code=None,
            created_node_tag=None
        )


@app.post("/api/peer/complete-pairing", response_model=CompletePairingResponse)
def api_complete_pairing(payload: CompletePairingRequest):
    """完成配对

    导入对方发送的配对响应码，完成配对流程。

    流程：
    1. 验证配对响应码
    2. 验证 request_node_tag 匹配
    3. 创建 peer_node
    """
    if not HAS_DATABASE or not USER_DB_PATH.exists():
        raise HTTPException(status_code=503, detail="Database unavailable")

    if not HAS_PAIRING:
        raise HTTPException(status_code=503, detail="Pairing module not available")

    db = _get_db()

    # Phase 11-Fix.AC: Check userspace WG mode - route to IPC
    userspace_wg = os.environ.get("USERSPACE_WG", "true").lower() == "true"

    # Check tunnel_type from pending_request to decide routing
    tunnel_type = payload.pending_request.get("tunnel_type", "wireguard")

    if userspace_wg and tunnel_type == "wireguard":
        # Use rust-router IPC for completing pairing in userspace WG mode
        success, message_or_error, peer_tag = _run_async_ipc(
            _complete_handshake_via_ipc(payload.code)
        )

        if not success:
            logging.warning(f"[pairing] 完成配对失败 (IPC): {message_or_error}")
            return CompletePairingResponse(
                success=False,
                message=message_or_error,
                created_node_tag=None
            )

        _sync_userspace_peer_from_codes(
            db,
            request_code=payload.pending_request.get("code"),
            response_code=payload.code,
            local_tag=payload.pending_request.get("node_tag", ""),
            tunnel_status="connected",
        )

        logging.info(f"[pairing] 配对完成 (IPC): node_tag={peer_tag}")
        return CompletePairingResponse(
            success=True,
            message=message_or_error,
            created_node_tag=peer_tag
        )

    # Existing kernel WireGuard code path continues below...
    manager = PairingManager(db)

    # 验证 pending_request 包含必要字段（psk 已废弃，不再必需）
    required_fields = ["node_tag", "tunnel_type"]
    for field in required_fields:
        if field not in payload.pending_request:
            raise HTTPException(status_code=400, detail=f"Missing required field in pending_request: {field}")

    try:
        success, message = manager.complete_pairing(
            code=payload.code,
            pending_request=payload.pending_request,
        )

        if not success:
            logging.warning(f"[pairing] 完成配对失败: {message}")
            return CompletePairingResponse(
                success=False,
                message=message,
                created_node_tag=None
            )

        # 从响应码中提取创建的节点 tag
        created_node_tag = None
        try:
            generator = PairingCodeGenerator(db)
            _, _, response_obj = generator.validate_pair_response(payload.code)
            if response_obj:
                created_node_tag = response_obj.node_tag  # 对方的 tag
        except Exception:
            pass

        logging.info(f"[pairing] 配对完成，创建节点 '{created_node_tag}'")

        # Phase 11.2: 双向自动连接
        # 如果是双向配对，自动建立连接并请求反向连接
        bidirectional = payload.pending_request.get("bidirectional", True)
        if bidirectional and created_node_tag:
            try:
                _trigger_bidirectional_connect(db, created_node_tag, payload.pending_request)
            except Exception as e:
                # 自动连接失败不影响配对结果，只记录警告
                logging.warning(f"[pairing] 双向自动连接失败: {e}")

        return CompletePairingResponse(
            success=True,
            message=message,
            created_node_tag=created_node_tag
        )

    except Exception as e:
        logging.error(f"[pairing] 完成配对异常: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to complete pairing: {e}")


@app.get("/api/peers/{tag}/status")
def api_get_peer_status(tag: str):
    """获取对等节点隧道状态"""
    if not HAS_DATABASE or not USER_DB_PATH.exists():
        raise HTTPException(status_code=503, detail="Database unavailable")

    db = _get_db()
    node = db.get_peer_node(tag)

    if not node:
        raise HTTPException(status_code=404, detail=f"节点 '{tag}' 不存在")

    status = {
        "tag": tag,
        "name": node.get("name"),
        "tunnel_type": node.get("tunnel_type"),
        "tunnel_status": node.get("tunnel_status", "disconnected"),
        "tunnel_interface": node.get("tunnel_interface"),
        "tunnel_local_ip": node.get("tunnel_local_ip"),
        "tunnel_remote_ip": node.get("tunnel_remote_ip"),
        "last_seen": node.get("last_seen"),
        "last_error": node.get("last_error"),
        "enabled": bool(node.get("enabled", 1)),
    }

    # 如果是 WireGuard 隧道，尝试获取接口状态
    if node.get("tunnel_type") == "wireguard" and node.get("tunnel_interface"):
        try:
            result = subprocess.run(
                ["wg", "show", node["tunnel_interface"]],
                capture_output=True, text=True, timeout=5
            )
            if result.returncode == 0:
                status["wg_status"] = "up"
                # 解析最后握手时间
                for line in result.stdout.split("\n"):
                    if "latest handshake" in line.lower():
                        status["last_handshake"] = line.split(":", 1)[1].strip()
            else:
                status["wg_status"] = "down"
        except subprocess.TimeoutExpired:
            status["wg_status"] = "timeout"
        except Exception as e:
            status["wg_status"] = f"error: {e}"

    return status


class TunnelStatusUpdateRequest(BaseModel):
    """手动更新隧道状态请求 (Phase 10.4)"""
    status: str = Field(..., pattern=r"^(connected|disconnected|error)$")
    message: Optional[str] = Field(None, max_length=500)


@app.put("/api/peers/{tag}/tunnel-status")
def api_update_peer_tunnel_status(tag: str, request: TunnelStatusUpdateRequest):
    """手动设置对等节点隧道状态 (Phase 10.4)

    用于调试或恢复异常状态。例如：
    - 隧道实际已连接但状态显示错误时
    - 需要强制重置状态进行调试时

    Args:
        tag: 节点标识
        request: 包含 status (connected/disconnected/error) 和可选 message

    Returns:
        更新结果
    """
    if not HAS_DATABASE or not USER_DB_PATH.exists():
        raise HTTPException(status_code=503, detail="Database unavailable")

    db = _get_db()
    node = db.get_peer_node(tag)

    if not node:
        raise HTTPException(status_code=404, detail=f"节点 '{tag}' 不存在")

    old_status = node.get("tunnel_status", "disconnected")
    new_status = request.status

    try:
        # 更新数据库中的隧道状态
        update_fields = {"tunnel_status": new_status}
        if request.message:
            update_fields["last_error"] = request.message if new_status == "error" else None
        elif new_status != "error":
            # 清除旧错误消息
            update_fields["last_error"] = None

        db.update_peer_node(tag, **update_fields)

        logging.info(f"[peer-status] 手动更新 {tag} 隧道状态: {old_status} -> {new_status}")

        return {
            "success": True,
            "tag": tag,
            "tunnel_status": new_status,
            "previous_status": old_status,
            "message": f"状态已更新为 {new_status}"
        }

    except Exception as e:
        logging.error(f"[peer-status] 更新 {tag} 隧道状态失败: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to update tunnel status: {e}")


def _do_peer_exchange(db, node: dict) -> dict:
    """与远程节点执行参数交换

    NOTE: 此函数已废弃。PSK 认证和 /api/peer-auth/exchange 端点已移除。
    请使用离线配对流程（generate_pair_request/import_pair_request）。
    """
    raise HTTPException(
        status_code=400,
        detail="参数交换功能已废弃。请使用离线配对流程：生成配对请求码 -> 导入配对请求码 -> 完成配对"
    )


@app.post("/api/peers/{tag}/connect")
def api_peer_connect(tag: str):
    """连接到对等节点

    建立与指定节点的隧道连接（WireGuard 或 Xray）。
    如果尚未完成参数交换，会自动与远程节点交换参数。
    """
    if not HAS_DATABASE or not USER_DB_PATH.exists():
        raise HTTPException(status_code=503, detail="Database unavailable")

    db = _get_db()
    node = db.get_peer_node(tag)

    if not node:
        raise HTTPException(status_code=404, detail=f"节点 '{tag}' 不存在")

    if not node.get("enabled"):
        raise HTTPException(status_code=400, detail=f"节点 '{tag}' 未启用")

    # 检查是否需要参数交换
    tunnel_type = node.get("tunnel_type", "wireguard")
    needs_exchange = False

    if tunnel_type == "wireguard":
        if not node.get("wg_private_key") or not node.get("wg_peer_public_key"):
            needs_exchange = True
    elif tunnel_type == "xray":
        # 需要 xray_uuid 和远程 peer 的 REALITY 公钥才能建立连接
        if not node.get("xray_uuid") or not node.get("xray_peer_reality_public_key"):
            needs_exchange = True

    # 自动执行参数交换
    if needs_exchange:
        logging.info(f"[peers] 节点 '{tag}' 需要参数交换，自动执行...")
        node = _do_peer_exchange(db, node)

    # 调用隧道管理器连接
    try:
        # 导入并使用 peer_tunnel_manager
        from peer_tunnel_manager import PeerTunnelManager
        manager = PeerTunnelManager()
        success = manager.connect_node(tag)

        if success:
            # 重新获取更新后的节点信息
            node = db.get_peer_node(tag)

            # Phase 11-Fix.C2: 设置 tunnel_api_endpoint 用于通过隧道调用远程 API
            tunnel_remote_ip = node.get("tunnel_remote_ip")
            if tunnel_remote_ip and not node.get("tunnel_api_endpoint"):
                # Phase 11-Fix.K: 使用节点的 api_port 或默认端口
                remote_api_port = node.get("api_port") or DEFAULT_WEB_PORT
                tunnel_api_endpoint = f"{tunnel_remote_ip}:{remote_api_port}"
                db.update_peer_node(tag, tunnel_api_endpoint=tunnel_api_endpoint)
                logging.info(f"[peers] 设置隧道 API 端点: {tag} -> {tunnel_api_endpoint}")
                # 刷新 node 对象
                node = db.get_peer_node(tag)

            # 通知远程节点也建立隧道（双向同步）
            notify_success = False
            try:
                notify_success = _notify_peer_connected(db, node)
            except Exception as e:
                logging.warning(f"[peers] 通知远程节点失败: {e}")

            # Phase 11-Fix.B: 连接成功后异步检查并更新双向状态
            def _async_bidirectional_check():
                try:
                    # 等待一小段时间让远程节点完成连接
                    import time
                    time.sleep(2)
                    _check_and_update_bidirectional_status(_get_db(), tag)
                except Exception as e:
                    logging.warning(f"[peers] 双向状态检查失败: {e}")

            threading.Thread(target=_async_bidirectional_check, daemon=True).start()

            return {
                "success": True,
                "message": "隧道连接成功" + ("，远程节点已同步" if notify_success else ""),
                "tag": tag,
                "tunnel_status": node.get("tunnel_status"),
                "tunnel_interface": node.get("tunnel_interface"),
                "remote_notified": notify_success,
            }
        else:
            node = db.get_peer_node(tag)
            raise HTTPException(
                status_code=500,
                detail=node.get("last_error", "隧道连接失败")
            )
    except HTTPException:
        raise
    except Exception as e:
        logging.error(f"[peers] 连接节点 '{tag}' 失败: {e}")
        raise HTTPException(status_code=500, detail=f"连接失败: {str(e)}")


@app.post("/api/peers/{tag}/disconnect")
def api_peer_disconnect(tag: str):
    """断开对等节点隧道

    断开与指定节点的隧道连接。
    会同时通知远程节点断开其侧的隧道（双向同步）。
    """
    if not HAS_DATABASE or not USER_DB_PATH.exists():
        raise HTTPException(status_code=503, detail="Database unavailable")

    db = _get_db()
    node = db.get_peer_node(tag)

    if not node:
        raise HTTPException(status_code=404, detail=f"节点 '{tag}' 不存在")

    # 先通知远程节点断开（在本地断开之前，否则无法获取连接信息）
    notify_success = False
    if node.get("tunnel_status") == "connected":
        try:
            notify_success = _notify_peer_disconnected(db, node)
        except Exception as e:
            logging.warning(f"[peers] 通知远程节点断开失败: {e}")

    # 调用隧道管理器断开本地隧道
    try:
        from peer_tunnel_manager import PeerTunnelManager
        manager = PeerTunnelManager()
        success = manager.disconnect_node(tag)

        if success:
            # Phase 11-Fix.V.5: 使客户端缓存失效
            try:
                from tunnel_api_client import TunnelAPIClientManager
                client_mgr = TunnelAPIClientManager(db)
                client_mgr.invalidate_client(tag)
            except Exception as cache_err:
                logging.warning(f"[peers] 清除客户端缓存失败: {cache_err}")

            # Phase 5: 更新使用该节点的链路状态
            chain_update_result = _update_chains_for_disconnected_peer(db, tag)

            return {
                "success": True,
                "message": "隧道已断开" + ("，远程节点已同步" if notify_success else ""),
                "tag": tag,
                "tunnel_status": "disconnected",
                "remote_notified": notify_success,
                "chains_updated": chain_update_result.get("updated", []),  # Phase 5
            }
        else:
            raise HTTPException(status_code=500, detail="断开隧道失败")
    except HTTPException:
        raise
    except Exception as e:
        logging.error(f"[peers] 断开节点 '{tag}' 失败: {e}")
        raise HTTPException(status_code=500, detail=f"断开失败: {str(e)}")


@app.post("/api/peers/{tag}/retry-bidirectional")
def api_peer_retry_bidirectional(tag: str):
    """Phase 11-Fix.B: 手动触发双向连接状态检测

    用于手动检查并更新指定节点的双向连接状态。
    适用于自动检测未生效或需要立即刷新状态的场景。

    状态语义:
    - pending: 尚未检查或隧道未连接
    - outbound_only: 隧道已连接，但本地未启用 inbound
    - bidirectional: 隧道已连接，且本地已启用 inbound
    """
    if not HAS_DATABASE or not USER_DB_PATH.exists():
        raise HTTPException(status_code=503, detail="Database unavailable")

    db = _get_db()
    node = db.get_peer_node(tag)

    if not node:
        raise HTTPException(status_code=404, detail=f"节点 '{tag}' 不存在")

    old_status = node.get("bidirectional_status", "pending")

    try:
        new_status = _check_and_update_bidirectional_status(db, tag)
    except Exception as e:
        logging.error(f"[peers] 检查节点 '{tag}' 双向状态失败: {e}")
        raise HTTPException(status_code=500, detail=f"检查失败: {str(e)}")

    return {
        "success": True,
        "tag": tag,
        "old_status": old_status,
        "new_status": new_status,
        "changed": old_status != new_status,
    }


# ============ Peer Node Inbound API ============

@app.post("/api/peers/{tag}/inbound/enable")
def api_enable_peer_inbound(tag: str):
    """启用对等节点的入站监听

    启用后，本节点将能够接收来自该对等节点的连接请求。
    系统会自动分配入站端口（36500+）并生成 REALITY 密钥（如果未配置）。
    """
    if not HAS_DATABASE or not USER_DB_PATH.exists():
        raise HTTPException(status_code=503, detail="Database unavailable")

    db = _get_db()
    node = db.get_peer_node(tag)

    if not node:
        raise HTTPException(status_code=404, detail=f"节点 '{tag}' 不存在")

    # 获取 V2Ray 入站配置的端口（合并架构使用统一端口）
    v2ray_config = db.get_v2ray_inbound_config()
    unified_port = v2ray_config.get("listen_port", 443) if v2ray_config else 443

    # 检查是否已启用
    if node.get("inbound_enabled"):
        return {
            "success": True,
            "message": "入站监听已启用",
            "tag": tag,
            "inbound_port": node.get("inbound_port"),
            "inbound_uuid": node.get("inbound_uuid"),
        }

    # 分配入站端口（如果未分配）
    inbound_port = node.get("inbound_port")
    if not inbound_port:
        try:
            inbound_port = db.get_next_peer_inbound_port()
        except ValueError as e:
            raise HTTPException(status_code=500, detail=str(e))

    # 生成入站 UUID（使用对方的 UUID，从交换获取）
    # 如果还没有进行交换，使用临时 UUID
    inbound_uuid = node.get("inbound_uuid") or node.get("xray_uuid")
    if not inbound_uuid:
        import uuid
        inbound_uuid = str(uuid.uuid4())

    # 检查 REALITY 密钥（如果未配置则生成）
    if not node.get("xray_reality_private_key"):
        try:
            from xray_manager import generate_reality_keys
            keys = generate_reality_keys()
            private_key = keys["private_key"]
            public_key = keys["public_key"]
            short_id = secrets.token_hex(4)  # 8 字符 hex
        except Exception as e:
            logging.error(f"生成 REALITY 密钥失败: {e}")
            raise HTTPException(status_code=500, detail=f"生成 REALITY 密钥失败: {str(e)}")
    else:
        private_key = node.get("xray_reality_private_key")
        public_key = node.get("xray_reality_public_key")
        short_id = node.get("xray_reality_short_id")

    # 更新数据库
    db.update_peer_node(
        tag,
        inbound_enabled=1,
        inbound_port=inbound_port,
        inbound_uuid=inbound_uuid,
        xray_reality_private_key=private_key,
        xray_reality_public_key=public_key,
        xray_reality_short_id=short_id,
    )

    # 合并架构: reload 主 Xray 进程以加载新的 peer UUID
    try:
        import subprocess
        result = subprocess.run(
            ["python3", "/usr/local/bin/xray_manager.py", "reload"],
            capture_output=True, text=True, timeout=10
        )
        if result.returncode == 0:
            logging.info(f"[peers] 节点 '{tag}' 入站监听已启用 (合并架构, Xray reloaded)")
            return {
                "success": True,
                "message": "入站监听已启用",
                "tag": tag,
                "inbound_port": unified_port,  # 合并架构使用统一端口
                "inbound_uuid": inbound_uuid,
                "reality_public_key": public_key,
                "reality_short_id": short_id,
            }
        else:
            logging.error(f"[peers] Xray reload 失败: {result.stderr}")
            raise HTTPException(status_code=500, detail=f"Xray reload 失败: {result.stderr}")
    except subprocess.TimeoutExpired:
        logging.error("[peers] Xray reload 超时")
        raise HTTPException(status_code=500, detail="Xray reload 超时")
    except HTTPException:
        raise
    except Exception as e:
        logging.error(f"[peers] 启动入站监听失败: {e}")
        raise HTTPException(status_code=500, detail=f"启动入站监听失败: {str(e)}")


@app.post("/api/peers/{tag}/inbound/disable")
def api_disable_peer_inbound(tag: str):
    """禁用对等节点的入站监听

    禁用后，本节点将不再接收来自该对等节点的连接请求。
    已有的出站连接不受影响。
    """
    if not HAS_DATABASE or not USER_DB_PATH.exists():
        raise HTTPException(status_code=503, detail="Database unavailable")

    db = _get_db()
    node = db.get_peer_node(tag)

    if not node:
        raise HTTPException(status_code=404, detail=f"节点 '{tag}' 不存在")

    # 检查是否已禁用
    if not node.get("inbound_enabled"):
        return {
            "success": True,
            "message": "入站监听已禁用",
            "tag": tag,
        }

    # 更新数据库
    db.update_peer_node(tag, inbound_enabled=0)

    # 合并架构: reload 主 Xray 进程以移除 peer UUID
    try:
        import subprocess
        result = subprocess.run(
            ["python3", "/usr/local/bin/xray_manager.py", "reload"],
            capture_output=True, text=True, timeout=10
        )
        if result.returncode != 0:
            logging.warning(f"[peers] Xray reload 返回非零: {result.stderr}")
    except Exception as e:
        logging.warning(f"[peers] Xray reload 时出错: {e}")

    logging.info(f"[peers] 节点 '{tag}' 入站监听已禁用 (合并架构)")
    return {
        "success": True,
        "message": "入站监听已禁用",
        "tag": tag,
    }


@app.get("/api/peers/{tag}/inbound/status")
def api_get_peer_inbound_status(tag: str):
    """获取对等节点入站状态

    返回入站监听器的运行状态、端口等信息。
    合并架构: 检查主 Xray 进程状态，peer 入站共享同一进程。
    """
    if not HAS_DATABASE or not USER_DB_PATH.exists():
        raise HTTPException(status_code=503, detail="Database unavailable")

    db = _get_db()
    node = db.get_peer_node(tag)

    if not node:
        raise HTTPException(status_code=404, detail=f"节点 '{tag}' 不存在")

    # 获取 V2Ray 入站配置的端口（合并架构使用统一端口）
    v2ray_config = db.get_v2ray_inbound_config()
    unified_port = v2ray_config.get("listen_port", 443) if v2ray_config else 443

    # 合并架构: 检查主 Xray 进程状态
    process_status = "stopped"
    pid = None
    try:
        import subprocess
        result = subprocess.run(
            ["python3", "/usr/local/bin/xray_manager.py", "status"],
            capture_output=True, text=True, timeout=5
        )
        if result.returncode == 0 and "running" in result.stdout.lower():
            process_status = "running"
            # 尝试从输出提取 PID
            import re
            pid_match = re.search(r'PID[:\s]+(\d+)', result.stdout)
            if pid_match:
                pid = int(pid_match.group(1))
    except Exception as e:
        logging.warning(f"[peers] 获取 Xray 状态失败: {e}")

    return {
        "tag": tag,
        "inbound_enabled": bool(node.get("inbound_enabled")),
        "inbound_port": unified_port if node.get("inbound_enabled") else None,  # 合并架构使用统一端口
        "inbound_uuid": node.get("inbound_uuid"),
        "process_status": process_status if node.get("inbound_enabled") else "disabled",
        "pid": pid if node.get("inbound_enabled") else None,
        "reality_public_key": node.get("xray_reality_public_key"),
        "reality_short_id": node.get("xray_reality_short_id"),
    }


@app.get("/api/peers/inbound/all")
def api_get_all_peer_inbound_status():
    """获取所有启用入站的节点状态

    合并架构: 所有 peer 入站共享同一个 Xray 进程。
    """
    if not HAS_DATABASE or not USER_DB_PATH.exists():
        raise HTTPException(status_code=503, detail="Database unavailable")

    db = _get_db()

    # 获取主 Xray 进程状态
    xray_running = False
    xray_pid = None
    try:
        import subprocess
        result = subprocess.run(
            ["python3", "/usr/local/bin/xray_manager.py", "status"],
            capture_output=True, text=True, timeout=5
        )
        if result.returncode == 0 and "running" in result.stdout.lower():
            xray_running = True
            import re
            pid_match = re.search(r'PID[:\s]+(\d+)', result.stdout)
            if pid_match:
                xray_pid = int(pid_match.group(1))
    except Exception as e:
        logging.warning(f"[peers] 获取 Xray 状态失败: {e}")

    # 获取所有启用入站的节点
    nodes = db.get_peer_nodes()
    statuses = []
    for node in nodes:
        if node.get("inbound_enabled"):
            statuses.append({
                "tag": node.get("tag"),
                "status": "running" if xray_running else "stopped",
                "pid": xray_pid,
                "port": 443,  # 合并架构使用统一端口
                "uuid": node.get("inbound_uuid"),
                "reality_public_key": node.get("xray_reality_public_key"),
            })

    return {"inbounds": statuses, "count": len(statuses), "xray_status": "running" if xray_running else "stopped"}


# ============ Node Chain CRUD API ============

@app.get("/api/chains")
def api_list_chains(enabled_only: bool = False):
    """列出所有多跳链路"""
    if not HAS_DATABASE or not USER_DB_PATH.exists():
        raise HTTPException(status_code=503, detail="Database unavailable")

    db = _get_db()
    chains = db.get_node_chains(enabled_only=enabled_only)

    # 解析 JSON 字段（使用安全解析器）
    for chain in chains:
        chain["hops"] = _parse_chain_hops(chain, raise_on_error=False)
        # 解析其他 JSON 字段，出错时使用默认值
        for field in ("hop_protocols", "entry_rules", "relay_rules"):
            if isinstance(chain.get(field), str) and chain.get(field):
                try:
                    chain[field] = json.loads(chain[field])
                except json.JSONDecodeError as e:
                    logging.warning(f"[chains] 链路 '{chain.get('tag')}' 的 {field} JSON 解析失败: {e}")
                    chain[field] = {} if field != "hop_protocols" else []

    return {"chains": chains, "count": len(chains)}


@app.get("/api/chains/{tag}")
def api_get_chain(tag: str):
    """获取单个链路详情"""
    if not HAS_DATABASE or not USER_DB_PATH.exists():
        raise HTTPException(status_code=503, detail="Database unavailable")

    db = _get_db()
    chain = db.get_node_chain(tag)

    if not chain:
        raise HTTPException(status_code=404, detail=f"链路 '{tag}' 不存在")

    # 解析 JSON 字段（使用安全解析器）
    chain["hops"] = _parse_chain_hops(chain, raise_on_error=False)
    # 解析其他 JSON 字段，出错时使用默认值
    for field in ("hop_protocols", "entry_rules", "relay_rules"):
        if isinstance(chain.get(field), str) and chain.get(field):
            try:
                chain[field] = json.loads(chain[field])
            except json.JSONDecodeError as e:
                logging.warning(f"[chains] 链路 '{tag}' 的 {field} JSON 解析失败: {e}")
                chain[field] = {} if field != "hop_protocols" else []

    return chain


@app.post("/api/chains")
def api_create_chain(payload: NodeChainCreateRequest):
    """创建新的多跳链路"""
    if not HAS_DATABASE or not USER_DB_PATH.exists():
        raise HTTPException(status_code=503, detail="Database unavailable")

    db = _get_db()

    # 检查 tag 是否已存在
    if db.get_node_chain(payload.tag):
        raise HTTPException(status_code=400, detail=f"链路标识 '{payload.tag}' 已存在")

    # Issue 27 修复：验证 hops 列表
    if payload.hops is not None:
        if len(payload.hops) < 2:
            raise HTTPException(status_code=400, detail="链路至少需要 2 个节点")
        if len(payload.hops) != len(set(payload.hops)):
            raise HTTPException(status_code=400, detail="链路包含重复节点（循环）")

    # Phase 11-Fix.C: 验证所有跳转节点
    if payload.allow_transitive:
        # 传递模式：通过隧道递归验证后续跳点
        valid, error = _validate_chain_hops_recursive(db, payload.hops)
    else:
        # 严格模式：所有跳点必须在本地 peer_nodes 表
        valid, errors = db.validate_chain_hops(payload.hops, allow_transitive=False)
        error = "; ".join(errors) if isinstance(errors, list) and errors else (errors[0] if errors else None)
    if not valid:
        raise HTTPException(status_code=400, detail=error)

    # Phase 11-Fix.P: 拒绝使用 Xray 隧道的多跳链路
    # Xray 中继不支持，多跳链路应使用 WireGuard 隧道
    for hop in payload.hops:
        peer = db.get_peer_node(hop)
        if peer and peer.get("tunnel_type") == "xray":
            raise HTTPException(
                status_code=400,
                detail=f"Multi-hop chains with Xray tunnels not supported. "
                       f"Node '{hop}' uses Xray tunnel type. "
                       f"Use WireGuard tunnels for multi-hop chains."
            )

    # 自动分配 DSCP 值（如果未提供）
    dscp_value = payload.dscp_value
    if dscp_value is None:
        dscp_value = db.get_next_available_dscp_value()
        if dscp_value is None:
            raise HTTPException(status_code=409, detail="无可用的 DSCP 值（已达上限 63）")
        logging.info(f"[chains] 自动分配 DSCP 值: {dscp_value}")

    # Phase 11-Fix.J + Phase 11-Fix.Q: 静态验证终端出口（如已指定）
    # 完整验证在链路激活时通过远程查询终端节点执行
    if payload.exit_egress:
        _validate_chain_terminal_egress_static(payload.exit_egress)

    try:
        chain_id = db.add_node_chain(
            tag=payload.tag,
            name=payload.name,
            description=payload.description,
            hops=payload.hops,
            hop_protocols=payload.hop_protocols,
            entry_rules=payload.entry_rules,
            relay_rules=payload.relay_rules,
            priority=payload.priority,
            enabled=payload.enabled,
            exit_egress=payload.exit_egress,
            dscp_value=dscp_value,
            chain_mark_type=payload.chain_mark_type,
            allow_transitive=payload.allow_transitive,  # Phase 11-Fix.Q
        )
    except Exception as e:
        logging.error(f"创建链路失败: {e}")
        raise HTTPException(status_code=500, detail=f"创建链路失败: {e}")

    logging.info(f"[chains] 创建链路 '{payload.tag}' (id={chain_id})")

    # 如果链路启用，向中间节点注册
    registration_results = {}
    if payload.enabled:
        chain = db.get_node_chain(payload.tag)
        if chain:
            registration_results = _register_chain_with_peers(db, chain)

    return {
        "message": f"链路 '{payload.tag}' 创建成功",
        "id": chain_id,
        "tag": payload.tag,
        "registration_results": registration_results,
    }


@app.put("/api/chains/{tag}")
def api_update_chain(tag: str, payload: NodeChainUpdateRequest):
    """更新链路配置"""
    if not HAS_DATABASE or not USER_DB_PATH.exists():
        raise HTTPException(status_code=503, detail="Database unavailable")

    db = _get_db()

    # 检查链路是否存在
    chain = db.get_node_chain(tag)
    if not chain:
        raise HTTPException(status_code=404, detail=f"链路 '{tag}' 不存在")

    # Phase 7 Fix: 检查链路状态 - 活跃链路不能修改关键配置
    chain_status = chain.get("chain_state", "inactive")
    if chain_status == "active":
        # 活跃链路只允许修改非关键字段（name, description, priority, enabled）
        critical_fields = ["hops", "exit_egress", "dscp_value", "chain_mark_type", "allow_transitive"]
        requested_critical = [f for f in critical_fields if getattr(payload, f, None) is not None]
        if requested_critical:
            raise HTTPException(
                status_code=409,
                detail=f"无法修改活跃链路的关键配置 ({', '.join(requested_critical)})。请先停用链路。"
            )

    # 构建更新参数
    update_kwargs = {}

    if payload.name is not None:
        update_kwargs["name"] = payload.name
    if payload.description is not None:
        update_kwargs["description"] = payload.description
    if payload.hops is not None:
        # Issue 27 修复：验证 hops 列表
        if len(payload.hops) < 2:
            raise HTTPException(status_code=400, detail="链路至少需要 2 个节点")
        if len(payload.hops) != len(set(payload.hops)):
            raise HTTPException(status_code=400, detail="链路包含重复节点（循环）")

        # Phase 11-Fix.C: 验证所有跳转节点
        allow_transitive = payload.allow_transitive if payload.allow_transitive is not None else False
        if allow_transitive:
            # 传递模式：通过隧道递归验证后续跳点
            valid, error = _validate_chain_hops_recursive(db, payload.hops)
        else:
            # 严格模式：所有跳点必须在本地 peer_nodes 表
            valid, errors = db.validate_chain_hops(payload.hops, allow_transitive=False)
            error = "; ".join(errors) if isinstance(errors, list) and errors else (errors[0] if errors else None)
        if not valid:
            raise HTTPException(status_code=400, detail=error)

        # Phase 11-Fix.P: 拒绝使用 Xray 隧道的多跳链路（与 api_create_chain 保持一致）
        for hop in payload.hops:
            peer = db.get_peer_node(hop)
            if peer and peer.get("tunnel_type") == "xray":
                raise HTTPException(
                    status_code=400,
                    detail=f"Multi-hop chains with Xray tunnels not supported. "
                           f"Node '{hop}' uses Xray tunnel type. "
                           f"Use WireGuard tunnels for multi-hop chains."
                )

        update_kwargs["hops"] = json.dumps(payload.hops)
    if payload.hop_protocols is not None:
        update_kwargs["hop_protocols"] = json.dumps(payload.hop_protocols) if payload.hop_protocols else None
    if payload.entry_rules is not None:
        update_kwargs["entry_rules"] = json.dumps(payload.entry_rules) if payload.entry_rules else None
    if payload.relay_rules is not None:
        update_kwargs["relay_rules"] = json.dumps(payload.relay_rules) if payload.relay_rules else None
    if payload.priority is not None:
        update_kwargs["priority"] = payload.priority
    if payload.enabled is not None:
        update_kwargs["enabled"] = payload.enabled
    # Phase 6 新增字段
    if payload.exit_egress is not None:
        # Phase 11-Fix.J + Phase 11-Fix.Q: 静态验证终端出口
        # 完整验证在链路激活时通过远程查询终端节点执行
        _validate_chain_terminal_egress_static(payload.exit_egress)
        update_kwargs["exit_egress"] = payload.exit_egress
    if payload.dscp_value is not None:
        update_kwargs["dscp_value"] = payload.dscp_value
    if payload.chain_mark_type is not None:
        update_kwargs["chain_mark_type"] = payload.chain_mark_type
    if payload.chain_state is not None:
        update_kwargs["chain_state"] = payload.chain_state
    if payload.allow_transitive is not None:
        update_kwargs["allow_transitive"] = 1 if payload.allow_transitive else 0

    if not update_kwargs:
        return {"message": "没有需要更新的字段", "chain": chain}

    # 记录当前启用状态，用于判断是否需要注册/注销
    was_enabled = chain.get("enabled", 0)
    will_be_enabled = payload.enabled if payload.enabled is not None else was_enabled

    success = db.update_node_chain(tag, **update_kwargs)
    if not success:
        raise HTTPException(status_code=500, detail="更新链路失败")

    updated_chain = db.get_node_chain(tag)

    # 处理链路注册/注销
    registration_results = {}
    if payload.enabled is not None:
        if will_be_enabled and not was_enabled:
            # 从禁用变为启用：注册
            logging.info(f"[chains] 链路 '{tag}' 启用，向中间节点注册")
            registration_results = _register_chain_with_peers(db, updated_chain)
        elif not will_be_enabled and was_enabled:
            # 从启用变为禁用：注销
            logging.info(f"[chains] 链路 '{tag}' 禁用，向中间节点注销")
            registration_results = _unregister_chain_from_peers(db, chain)

    logging.info(f"[chains] 更新链路 '{tag}'")
    return {
        "message": f"链路 '{tag}' 已更新",
        "chain": updated_chain,
        "registration_results": registration_results,
    }


@app.delete("/api/chains/{tag}")
def api_delete_chain(tag: str):
    """删除链路

    Phase 5: 增强状态检查
    - 拒绝删除正在激活中的链路（防止竞态条件）
    - 自动停用并注销活跃链路
    """
    if not HAS_DATABASE or not USER_DB_PATH.exists():
        raise HTTPException(status_code=503, detail="Database unavailable")

    db = _get_db()

    # 检查链路是否存在
    chain = db.get_node_chain(tag)
    if not chain:
        raise HTTPException(status_code=404, detail=f"链路 '{tag}' 不存在")

    # Phase 5: 检查链路状态，拒绝删除正在激活中的链路
    chain_state = chain.get("chain_state", "inactive")
    if chain_state == "activating":
        raise HTTPException(
            status_code=409,
            detail="链路正在激活中，请稍后再试或先停用链路"
        )

    # Phase 5: 如果链路是 active 状态，使用 chain_state 而非 enabled 字段
    # 这确保状态检查的一致性
    unregistration_results = {}
    if chain_state == "active" or chain.get("enabled"):
        logging.info(f"[chains] 删除前停用并注销链路 '{tag}' (state={chain_state})")
        unregistration_results = _unregister_chain_from_peers(db, chain)

    success = db.delete_node_chain(tag)
    if not success:
        raise HTTPException(status_code=500, detail="删除链路失败")

    logging.info(f"[chains] 删除链路 '{tag}'")
    return {
        "message": f"链路 '{tag}' 已删除",
        "unregistration_results": unregistration_results,
    }


# ============ Phase 11-Fix.C: Chain Hops Validation API ============


def _validate_chain_hops_recursive(db, hops: List[str], max_depth: int = 5) -> tuple:
    """Phase 11-Fix.C: 递归验证链路跳点（支持线性拓扑）

    对于 A→B→C 链路：
    1. 验证 B 是 A 的本地 peer 且已连接
    2. 通过 A→B 隧道调用 B 的 /api/chains/validate-hops 验证 [C]
    3. B 验证 C 是其本地 peer 且已连接

    Args:
        db: 数据库实例
        hops: 跳点列表（从本地节点视角）
        max_depth: 最大递归深度（防止无限循环）

    Returns:
        (valid: bool, error: str|None)
    """
    if not hops:
        return False, "hops cannot be empty"

    if max_depth <= 0:
        return False, "maximum recursion depth exceeded"

    # 检测循环（重复节点）
    seen = set()
    for hop in hops:
        if hop in seen:
            return False, f"circular chain detected: duplicate node '{hop}'"
        seen.add(hop)

    # 验证第一跳是本地已连接的 peer
    first_hop = hops[0]
    node = db.get_peer_node(first_hop)
    if not node:
        return False, f"first hop '{first_hop}' not found in local peer_nodes"
    if node.get("tunnel_status") != "connected":
        return False, f"first hop '{first_hop}' is not connected (status: {node.get('tunnel_status')})"

    # 只有一跳时，验证完成
    if len(hops) == 1:
        return True, None

    # 有多跳时，通过隧道验证后续跳点
    remaining_hops = hops[1:]
    try:
        from tunnel_api_client import TunnelAPIClientManager

        client_mgr = TunnelAPIClientManager(db)
        client = client_mgr.get_client(first_hop)

        if not client:
            return False, f"cannot connect to '{first_hop}' for remote validation"

        # 调用远程节点验证剩余跳点
        # 使用 allow_transitive=True 让远程节点也使用递归验证
        result = client.validate_chain_hops(remaining_hops, allow_transitive=True)

        if result.get("valid"):
            logging.info(f"[chains] 递归验证通过: {hops} (via {first_hop})")
            return True, None
        else:
            error = result.get("error", "remote validation failed")
            return False, f"remote validation at '{first_hop}' failed: {error}"

    except Exception as e:
        logging.error(f"[chains] 递归验证异常: {e}")
        return False, f"validation through tunnel failed: {str(e)}"


def _check_chain_cycle(hops: List[str]) -> bool:
    """Phase 11-Fix.E: 检查链路是否存在循环

    Returns:
        True 如果存在循环，False 如果没有循环
    """
    return len(hops) != len(set(hops))


def _get_terminal_node_through_tunnel(db, hops: List[str]) -> tuple:
    """Phase 11-Fix.E: 通过隧道获取终端节点信息

    对于线性拓扑 A→B→C，A 只知道 B，需要通过 B 查询 C 的信息。

    Args:
        db: 数据库实例
        hops: 跳点列表（从本地节点视角）

    Returns:
        (terminal_info: dict|None, client: TunnelAPIClient|None, clients_cache: dict)
        terminal_info: 终端节点信息 {"tag": str, "via_relay": str|None, "direct": bool}
        client: 用于到达终端节点的客户端（直接连接或通过中继）
        clients_cache: 中间节点客户端缓存 {tag: client}
    """
    from tunnel_api_client import TunnelAPIClientManager

    if not hops:
        return None, None, {}

    if _check_chain_cycle(hops):
        logging.error(f"[chains] 检测到循环链路: {hops}")
        return None, None, {}

    terminal_tag = hops[-1]
    client_mgr = TunnelAPIClientManager(db)

    if len(hops) == 1:
        # 直接连接
        client = client_mgr.get_client(terminal_tag)
        if client and client.ping():
            return {"tag": terminal_tag, "direct": True}, client, {}
        return None, None, {}

    # 多跳：通过第一跳到达终端节点
    first_hop_tag = hops[0]
    first_hop_client = client_mgr.get_client(first_hop_tag)

    if not first_hop_client:
        logging.warning(f"[chains] 无法获取第一跳 '{first_hop_tag}' 的客户端")
        return None, None, {}

    if not first_hop_client.ping():
        logging.warning(f"[chains] 第一跳 '{first_hop_tag}' 不可达")
        return None, None, {}

    # 递归验证后续跳点
    remaining_hops = hops[1:]
    try:
        result = first_hop_client.validate_chain_hops(remaining_hops, allow_transitive=True)
    except Exception as e:
        logging.error(f"[chains] 通过 '{first_hop_tag}' 验证后续跳点失败: {e}")
        return None, None, {}

    if not result.get("valid"):
        logging.warning(f"[chains] 后续跳点验证失败: {result.get('error')}")
        return None, None, {}

    # 验证通过，返回终端节点信息
    terminal_info = {"tag": terminal_tag, "via_relay": first_hop_tag, "direct": False}
    clients_cache = {first_hop_tag: first_hop_client}

    logging.info(f"[chains] 传递模式: 终端节点 '{terminal_tag}' 可通过 '{first_hop_tag}' 到达")
    return terminal_info, first_hop_client, clients_cache


class ChainHopsValidateRequest(BaseModel):
    """链路跳点验证请求"""
    hops: List[str] = Field(..., min_items=1, max_items=10, description="跳点节点列表")
    allow_transitive: bool = Field(False, description="是否允许传递模式（只验证第一跳）")


@app.post("/api/chains/validate-hops")
def api_validate_chain_hops(request: Request, payload: ChainHopsValidateRequest):
    """Phase 11-Fix.C: 验证链路跳点有效性（支持远程调用）

    认证方式: 隧道 IP/UUID (节点间调用，无需 JWT)

    当 allow_transitive=False（默认）时：
        所有跳点必须是本地 peer_nodes 表中存在的节点

    当 allow_transitive=True 时：
        只验证第一跳是本地已连接的 peer，后续跳通过递归查询验证
        这用于线性拓扑 A→B→C，其中 A 只知道 B，不知道 C
    """
    client_ip = _get_client_ip(request)

    # 速率限制
    if not _check_api_rate_limit(client_ip):
        raise HTTPException(status_code=429, detail="Too many requests")

    if not HAS_DATABASE or not USER_DB_PATH.exists():
        raise HTTPException(status_code=503, detail="Database unavailable")

    db = _get_db()

    # Phase 11-Fix.C 安全修复: 验证 PSK 认证
    node = _verify_tunnel_header(request, db)
    if not node:
        raise HTTPException(status_code=401, detail="Authentication failed")

    logging.info(f"[chains] 验证跳点请求: from {node['tag']} ({client_ip}), hops={payload.hops}")

    # 验证 hops 格式
    for hop in payload.hops:
        if not hop or not isinstance(hop, str):
            return {"valid": False, "error": "hops 包含无效条目"}
        # 验证 tag 格式
        if not re.match(r"^[a-z][a-z0-9-]*$", hop):
            return {"valid": False, "error": f"hop '{hop}' 格式无效（应为小写字母开头，只含字母数字和短横线）"}

    try:
        if payload.allow_transitive:
            # 传递模式：使用递归验证（通过隧道验证后续跳点）
            valid, error = _validate_chain_hops_recursive(db, payload.hops)
            if valid:
                return {"valid": True, "error": None}
            else:
                return {"valid": False, "error": error}
        else:
            # 严格模式：所有跳点必须在本地 peer_nodes 表中
            valid, errors = db.validate_chain_hops(payload.hops, allow_transitive=False)
            if valid:
                return {"valid": True, "error": None}
            else:
                # errors 是列表，合并为字符串
                error_msg = "; ".join(errors) if isinstance(errors, list) else str(errors)
                return {"valid": False, "error": error_msg}
    except Exception as e:
        logging.error(f"[chains] 验证跳点失败: {e}")
        return {"valid": False, "error": f"验证失败: {str(e)}"}


# ============ Peer Relay Status API (PSK Authenticated) ============


class PeerRelayStatusRequest(BaseModel):
    """中继状态查询请求

    认证方式: 隧道 IP 认证 (WireGuard) 或 UUID 认证 (Xray)
    """
    node_id: str = Field(..., pattern=r"^[a-z][a-z0-9-]*$", max_length=64, description="调用方节点标识")
    target_node: str = Field(..., pattern=r"^[a-z][a-z0-9-]*$", max_length=64, description="目标节点标识")
    # 用于多跳递归查询：如果设置，会通过 target_node 继续查询 next_hop
    next_hop: Optional[str] = Field(None, pattern=r"^[a-z][a-z0-9-]*$", max_length=64, description="下一跳节点（递归查询）")


@app.post("/api/peer-relay/status")
def api_peer_relay_status(request: Request, payload: PeerRelayStatusRequest):
    """通过已连接的隧道查询目标节点的状态

    此端点用于多跳链路中的状态查询。例如：
    - A 想知道 C 的状态
    - A 通过与 B 的隧道调用 B 的此端点
    - B 查询其与 C 的隧道状态并返回

    认证方式: 隧道 IP 认证 (WireGuard) 或 UUID 认证 (Xray)
    """
    client_ip = _get_client_ip(request)

    # 速率限制检查
    if not _check_api_rate_limit(client_ip):
        raise HTTPException(
            status_code=429,
            detail="Too many requests, please try again later"
        )

    if not HAS_DATABASE or not USER_DB_PATH.exists():
        raise HTTPException(status_code=503, detail="Database unavailable")

    db = _get_db()

    # Phase 11-Fix.M: 使用灵活认证函数（通过隧道调用，支持 IP 认证）
    caller_node = _verify_peer_request_flexible(
        request, db,
        payload_node_id=payload.node_id
    )
    if not caller_node:
        raise HTTPException(status_code=401, detail="Authentication failed")

    caller_tag = caller_node["tag"]
    target_tag = payload.target_node

    logging.info(f"[peer-relay] 收到中继查询: 调用方='{caller_tag}', 目标='{target_tag}' (from {client_ip})")

    # 查找目标节点
    target_node = db.get_peer_node(target_tag)
    if not target_node:
        return {
            "success": False,
            "target_node": target_tag,
            "status": "not_found",
            "message": f"目标节点 '{target_tag}' 不存在于本节点配置中"
        }

    # 检查本节点到目标节点的隧道状态
    tunnel_status = target_node.get("tunnel_status", "disconnected")
    real_status = _check_peer_tunnel_status(target_node)

    # 如果数据库状态与实际状态不一致，更新数据库
    if real_status != tunnel_status and real_status not in ("connecting",):
        db.update_peer_node(target_tag, tunnel_status=real_status)
        tunnel_status = real_status

    result = {
        "success": True,
        "target_node": target_tag,
        "status": tunnel_status,
        "tunnel_type": target_node.get("tunnel_type", "wireguard"),
        "tunnel_interface": target_node.get("tunnel_interface"),
        "message": f"节点 '{target_tag}' 状态: {tunnel_status}"
    }

    # 如果指定了 next_hop 并且 target_node 已连接，递归查询下一跳
    if payload.next_hop and tunnel_status == "connected":
        next_hop_result = _query_relay_status(db, target_node, payload.next_hop)
        result["next_hop_result"] = next_hop_result

    return result


def _query_relay_status(db, relay_node: dict, target_node_tag: str) -> dict:
    """通过中继节点查询目标节点状态

    Phase 2 修复：仅通过隧道通信。中继状态查询用于链路健康检查，
    必须通过隧道进行。如果隧道不可用，则返回错误状态。

    Args:
        db: 数据库实例
        relay_node: 中继节点信息
        target_node_tag: 目标节点标识

    Returns:
        查询结果字典
    """
    from tunnel_api_client import TunnelAPIClient

    relay_tag = relay_node["tag"]

    # Phase 2: 使用隧道通信（中继查询必须通过隧道）
    tunnel_api = _get_peer_tunnel_endpoint(relay_node)
    if not tunnel_api:
        return {
            "success": False,
            "target_node": target_node_tag,
            "status": "error",
            "message": f"中继节点 '{relay_tag}' 隧道不可用"
        }

    tunnel_type = relay_node.get("tunnel_type", "wireguard")
    socks_port = relay_node.get("xray_socks_port") if tunnel_type == "xray" else None
    peer_uuid = relay_node.get("xray_uuid") if tunnel_type == "xray" else None

    # 认证通过隧道 IP/UUID
    payload = {
        "node_id": relay_tag,  # 添加 node_id 用于日志
        "target_node": target_node_tag,
    }

    try:
        client = TunnelAPIClient(
            node_tag=relay_tag,
            tunnel_endpoint=tunnel_api,
            tunnel_type=tunnel_type,
            socks_port=socks_port,
            peer_uuid=peer_uuid,
            timeout=15
        )
        logging.info(f"[peer-relay] 通过隧道中继 '{relay_tag}' 查询 '{target_node_tag}' 状态: {tunnel_api}")
        resp = client.post("/api/peer-relay/status", json=payload)

        # TunnelAPIClient 已经解析了 JSON，直接返回
        if resp.get("success"):
            return resp
        else:
            return {
                "success": False,
                "target_node": target_node_tag,
                "status": "error",
                "message": resp.get("message", "中继查询失败")
            }
    except Exception as e:
        logging.warning(f"[peer-relay] 隧道中继查询失败: {e}")
        return {
            "success": False,
            "target_node": target_node_tag,
            "status": "unreachable",
            "message": f"无法通过隧道连接中继节点"
        }


# ============ Phase 11.4: 中继路由 API ============


class RelayRouteRegisterRequest(BaseModel):
    """中继路由注册请求

    认证方式: 隧道 IP 认证 (WireGuard) 或 UUID 认证 (Xray)
    """
    chain_tag: str = Field(..., description="链路标识")
    source_node: str = Field(..., description="上游节点 tag")
    target_node: str = Field(..., description="下游节点 tag")
    dscp_value: int = Field(..., description="DSCP 标记值")
    mark_type: str = Field("dscp", pattern=r"^dscp$", description="标记类型（仅支持 DSCP）")


class RelayRouteUnregisterRequest(BaseModel):
    """中继路由注销请求

    认证方式: 隧道 IP 认证 (WireGuard) 或 UUID 认证 (Xray)
    """
    chain_tag: str = Field(..., description="链路标识")
    # Phase 11-Fix.V.3: 添加 source_node 支持入口节点验证
    source_node: Optional[str] = Field(None, description="来源节点标识（入口节点）")


@app.post("/api/relay-routing/prepare")
def api_relay_routing_prepare(request: Request, payload: RelayRouteRegisterRequest):
    """Phase 11-Fix.T: 2PC 准备阶段 - 验证中继路由可注册性

    在实际注册前调用，验证所有条件但不应用 iptables 规则。
    用于实现两阶段提交：先在所有节点准备成功，再统一注册。

    认证方式: 隧道 IP/UUID 认证 (无需 JWT)

    Returns:
        {"prepared": True, "transaction_id": "..."} - 准备成功
        {"prepared": False, "error": "..."} - 准备失败
    """
    import uuid as uuid_module

    client_ip = _get_client_ip(request)

    # 速率限制检查
    if not _check_api_rate_limit(client_ip):
        raise HTTPException(
            status_code=429,
            detail="Too many requests, please try again later"
        )

    if not HAS_DATABASE or not USER_DB_PATH.exists():
        raise HTTPException(status_code=503, detail="Database unavailable")

    db = _get_db()

    # 验证调用方身份（通过 IP 查找调用方节点）
    caller_node = _find_peer_node_by_ip(db, client_ip)
    if not caller_node:
        return {"prepared": False, "error": f"Unknown caller IP: {client_ip}"}

    # 隧道 IP 认证
    tunnel_remote_ip = caller_node.get("tunnel_remote_ip", "")
    if tunnel_remote_ip:
        tunnel_remote_ip = tunnel_remote_ip.split("/")[0]
    if not (tunnel_remote_ip and tunnel_remote_ip == client_ip):
        return {"prepared": False, "error": "Tunnel IP authentication failed"}

    # Phase 11-Fix.V.3: 验证请求节点是否为链路成员（传入 source_node 支持入口节点）
    is_member, membership_error = _verify_chain_membership(
        db, payload.chain_tag, caller_node["tag"], source_node=payload.source_node
    )
    if not is_member:
        return {"prepared": False, "error": membership_error}

    # 验证 DSCP 值范围
    if not (0 <= payload.dscp_value <= 63):
        return {"prepared": False, "error": f"Invalid DSCP value: {payload.dscp_value} (must be 0-63)"}

    # 验证标记类型
    if payload.mark_type != "dscp":
        return {"prepared": False, "error": f"Invalid mark_type: {payload.mark_type}. Only 'dscp' is supported."}

    # 验证中继节点 DSCP 是否已被占用
    try:
        from relay_config_manager import get_relay_manager

        relay_mgr = get_relay_manager(db)
        for rule in relay_mgr.get_active_rules():
            if (
                rule.get("mark_type") == payload.mark_type
                and rule.get("dscp_value") == payload.dscp_value
                and rule.get("chain_tag") != payload.chain_tag
            ):
                return {
                    "prepared": False,
                    "error": (
                        f"DSCP value {payload.dscp_value} already used by chain "
                        f"'{rule.get('chain_tag')}'"
                    ),
                }
    except ImportError:
        return {"prepared": False, "error": "Relay config manager unavailable"}

    # 验证源节点和目标节点存在且已连接
    source_peer = _resolve_peer_node(db, payload.source_node, client_ip)
    target_peer = _resolve_peer_node(db, payload.target_node)

    if not source_peer:
        return {"prepared": False, "error": f"Source node '{payload.source_node}' not found"}

    if not target_peer:
        return {"prepared": False, "error": f"Target node '{payload.target_node}' not found"}

    # 验证节点使用 WireGuard 隧道（Xray 不支持 DSCP 中继）
    source_tunnel_type = source_peer.get("tunnel_type", "wireguard")
    target_tunnel_type = target_peer.get("tunnel_type", "wireguard")

    if source_tunnel_type == "xray":
        return {
            "prepared": False,
            "error": f"Source node '{payload.source_node}' uses Xray tunnel (DSCP not preserved)"
        }

    if target_tunnel_type == "xray":
        return {
            "prepared": False,
            "error": f"Target node '{payload.target_node}' uses Xray tunnel (DSCP not preserved)"
        }

    # 验证目标节点隧道已连接
    if target_peer.get("tunnel_status") != "connected":
        return {
            "prepared": False,
            "error": f"Target node '{payload.target_node}' tunnel not connected"
        }

    # 生成事务 ID（用于关联 prepare 和 commit）
    transaction_id = str(uuid_module.uuid4())[:8]

    logging.info(
        f"[relay-routing-2pc] PREPARE 成功: chain={payload.chain_tag}, "
        f"tx={transaction_id}, from {caller_node['tag']} ({client_ip})"
    )

    return {
        "prepared": True,
        "transaction_id": transaction_id,
        "chain_tag": payload.chain_tag,
        "source_node": payload.source_node,
        "target_node": payload.target_node,
    }


@app.post("/api/relay-routing/register")
def api_relay_routing_register(request: Request, payload: RelayRouteRegisterRequest):
    """Phase 11.4: 在此节点注册中继转发规则

    当激活多跳链路时，入口节点通过隧道调用中间节点的此端点，
    请求中间节点配置转发规则。

    认证方式: 隧道 IP/UUID 认证 (无需 JWT)
    - WireGuard 隧道: 通过 tunnel_remote_ip 验证身份
    - Xray 隧道: 通过 X-Peer-UUID 请求头验证身份

    流程:
    1. 入口节点 A 激活链路 A → B → C
    2. A 通过与 B 的隧道调用 B 的此 API
    3. B 配置 iptables 规则：匹配 DSCP 标记 → 转发到 wg-peer-C
    4. 流量到达 B 后，根据 DSCP 标记转发到 C
    """
    client_ip = _get_client_ip(request)

    # 速率限制检查
    if not _check_api_rate_limit(client_ip):
        raise HTTPException(
            status_code=429,
            detail="Too many requests, please try again later"
        )

    if not HAS_DATABASE or not USER_DB_PATH.exists():
        raise HTTPException(status_code=503, detail="Database unavailable")

    db = _get_db()

    # 验证调用方身份（通过 IP 查找调用方节点）
    caller_node = _find_peer_node_by_ip(db, client_ip)
    if not caller_node:
        logging.warning(f"[relay-routing] 注册失败: 未找到调用方节点 (from {client_ip})")
        raise HTTPException(status_code=401, detail="Unknown caller")

    # 隧道 IP 认证 - 验证通过隧道调用（已通过 _find_peer_node_by_ip 验证）
    tunnel_remote_ip = caller_node.get("tunnel_remote_ip", "")
    if tunnel_remote_ip:
        tunnel_remote_ip = tunnel_remote_ip.split("/")[0]
    if not (tunnel_remote_ip and tunnel_remote_ip == client_ip):
        logging.warning(f"[relay-routing] IP 认证失败: client_ip={client_ip}, expected={tunnel_remote_ip}")
        raise HTTPException(status_code=401, detail="Authentication failed")
    logging.info(f"[relay-routing] IP 认证成功: {client_ip} -> {caller_node['tag']}")

    # Phase 11-Fix.V.3: 验证请求节点是否为链路成员（传入 source_node 支持入口节点）
    is_member, membership_error = _verify_chain_membership(
        db, payload.chain_tag, caller_node["tag"], source_node=payload.source_node
    )
    if not is_member:
        logging.warning(f"[relay-routing] 链路成员验证失败: {membership_error}")
        raise HTTPException(status_code=403, detail=membership_error)

    caller_tag = caller_node["tag"]
    chain_tag = payload.chain_tag
    source_node = payload.source_node
    target_node = payload.target_node
    dscp_value = payload.dscp_value
    mark_type = payload.mark_type

    logging.info(f"[relay-routing] 收到中继路由注册: 链路='{chain_tag}', "
                f"来源='{source_node}' → 目标='{target_node}', DSCP={dscp_value} (from {caller_tag})")

    # 验证 DSCP 值范围
    if not (0 <= dscp_value <= 63):
        return {
            "success": False,
            "message": f"Invalid DSCP value: {dscp_value} (must be 0-63)"
        }

    # 验证标记类型 (Phase 11-Fix.P: 仅支持 DSCP)
    if mark_type != "dscp":
        return {
            "success": False,
            "message": f"Invalid mark_type: {mark_type}. Only 'dscp' is supported for relay routing."
        }

    # Phase 11-Fix.D: 使用 _resolve_peer_node 支持多种命名方式
    # source_node 可能是 tag、hostname 或 IP
    source_peer = _resolve_peer_node(db, source_node, client_ip)
    target_peer = _resolve_peer_node(db, target_node)

    if not source_peer:
        logging.warning(f"[relay-routing] 源节点未找到: '{source_node}' (fallback_ip={client_ip})")
        return {
            "success": False,
            "message": f"Source node '{source_node}' not found"
        }

    if not target_peer:
        logging.warning(f"[relay-routing] 目标节点未找到: '{target_node}'")
        return {
            "success": False,
            "message": f"Target node '{target_node}' not found"
        }

    # Phase 11-Fix.P: 验证节点使用 WireGuard 隧道（非 Xray）
    # Xray 隧道使用 SOCKS5 代理，无法保留 DSCP 标记，因此不支持中继路由
    source_tunnel_type = source_peer.get("tunnel_type", "wireguard")
    target_tunnel_type = target_peer.get("tunnel_type", "wireguard")

    if source_tunnel_type == "xray":
        logging.warning(f"[relay-routing] 源节点 '{source_node}' 使用 Xray 隧道，不支持中继路由")
        return {
            "success": False,
            "message": f"Source node '{source_node}' uses Xray tunnel. "
                       f"Relay routing requires WireGuard tunnels (DSCP not preserved through SOCKS5)."
        }

    if target_tunnel_type == "xray":
        logging.warning(f"[relay-routing] 目标节点 '{target_node}' 使用 Xray 隧道，不支持中继路由")
        return {
            "success": False,
            "message": f"Target node '{target_node}' uses Xray tunnel. "
                       f"Relay routing requires WireGuard tunnels (DSCP not preserved through SOCKS5)."
        }

    # 获取接口名称 - 使用解析后的 peer tag
    source_tag = source_peer.get("tag", source_node)
    target_tag = target_peer.get("tag", target_node)
    source_interface = source_peer.get("tunnel_interface", f"wg-peer-{source_tag}")
    target_interface = target_peer.get("tunnel_interface", f"wg-peer-{target_tag}")

    # 配置中继路由
    try:
        from relay_config_manager import get_relay_manager

        relay_mgr = get_relay_manager(db)
        success = relay_mgr.setup_relay_route(
            chain_tag=chain_tag,
            source_interface=source_interface,
            target_interface=target_interface,
            dscp_value=dscp_value,
            mark_type=mark_type
        )

        if success:
            logging.info(f"[relay-routing] 链路 '{chain_tag}' 中继路由已配置")
            return {
                "success": True,
                "message": f"Relay route configured for chain '{chain_tag}'",
                "chain_tag": chain_tag,
                "source_interface": source_interface,
                "target_interface": target_interface,
                "dscp_value": dscp_value
            }
        else:
            return {
                "success": False,
                "message": f"Failed to configure relay route for chain '{chain_tag}'"
            }

    except ImportError:
        logging.error("[relay-routing] 无法导入 relay_config_manager")
        return {
            "success": False,
            "message": "Relay config manager not available"
        }
    except Exception as e:
        logging.error(f"[relay-routing] 配置中继路由失败: {e}")
        return {
            "success": False,
            "message": "Internal error"
        }


@app.post("/api/relay-routing/unregister")
def api_relay_routing_unregister(request: Request, payload: RelayRouteUnregisterRequest):
    """Phase 11.4: 注销此节点的中继转发规则

    当停用多跳链路时，入口节点调用此端点请求中间节点清理转发规则。

    认证方式: 隧道 IP 认证 (WireGuard) 或 UUID 认证 (Xray)
    """
    client_ip = _get_client_ip(request)

    # 速率限制检查
    if not _check_api_rate_limit(client_ip):
        raise HTTPException(
            status_code=429,
            detail="Too many requests, please try again later"
        )

    if not HAS_DATABASE or not USER_DB_PATH.exists():
        raise HTTPException(status_code=503, detail="Database unavailable")

    db = _get_db()

    # 验证调用方身份
    caller_node = _find_peer_node_by_ip(db, client_ip)
    if not caller_node:
        logging.warning(f"[relay-routing] 注销失败: 未找到调用方节点 (from {client_ip})")
        raise HTTPException(status_code=401, detail="Unknown caller")

    # 隧道 IP 认证 - 验证通过隧道调用
    tunnel_remote_ip = caller_node.get("tunnel_remote_ip", "")
    if tunnel_remote_ip:
        tunnel_remote_ip = tunnel_remote_ip.split("/")[0]
    if not (tunnel_remote_ip and tunnel_remote_ip == client_ip):
        logging.warning(f"[relay-routing] IP 认证失败: client_ip={client_ip}, expected={tunnel_remote_ip}")
        raise HTTPException(status_code=401, detail="Authentication failed")
    logging.info(f"[relay-routing] IP 认证成功: {client_ip} -> {caller_node['tag']}")

    # Phase 11-Fix.V.3: 验证请求节点是否为链路成员（传入 source_node 支持入口节点）
    is_member, membership_error = _verify_chain_membership(
        db, payload.chain_tag, caller_node["tag"], source_node=payload.source_node
    )
    if not is_member:
        logging.warning(f"[relay-routing] 链路成员验证失败: {membership_error}")
        raise HTTPException(status_code=403, detail=membership_error)

    caller_tag = caller_node["tag"]
    chain_tag = payload.chain_tag

    logging.info(f"[relay-routing] 收到中继路由注销: 链路='{chain_tag}' (from {caller_tag})")

    # 清理中继路由
    try:
        from relay_config_manager import get_relay_manager

        relay_mgr = get_relay_manager(db)
        success = relay_mgr.cleanup_relay_route(chain_tag)

        if success:
            logging.info(f"[relay-routing] 链路 '{chain_tag}' 中继路由已清理")
            return {
                "success": True,
                "message": f"Relay route cleaned up for chain '{chain_tag}'",
                "chain_tag": chain_tag
            }
        else:
            return {
                "success": False,
                "message": f"Failed to cleanup relay route for chain '{chain_tag}'"
            }

    except ImportError:
        logging.error("[relay-routing] 无法导入 relay_config_manager")
        return {
            "success": False,
            "message": "Relay config manager not available"
        }
    except Exception as e:
        logging.error(f"[relay-routing] 清理中继路由失败: {e}")
        return {
            "success": False,
            "message": "Internal error"
        }


MAX_CHAIN_HOPS = 10  # 防止 DoS 攻击的最大跳数限制


@app.post("/api/chains/{tag}/health-check")
def api_chain_health_check(tag: str):
    """检查多跳链路的健康状态

    遍历链路中的所有跳转，检查每一跳的隧道状态。
    对于多跳链路，使用递归中继查询来获取下游节点的状态。

    例如链路 A → B → C → D：
    1. 检查本节点 (A) 到 B 的隧道状态（直接查询）
    2. 通过 B 查询 B 到 C 的隧道状态（中继查询）
    3. 通过 B 查询 C 到 D 的隧道状态（B 递归转发给 C）
    """
    if not HAS_DATABASE or not USER_DB_PATH.exists():
        raise HTTPException(status_code=503, detail="Database unavailable")

    db = _get_db()

    # 获取链路配置
    chain = db.get_node_chain(tag)
    if not chain:
        raise HTTPException(status_code=404, detail=f"链路 '{tag}' 不存在")

    # Issue 11/12 修复：使用统一的 hops 解析函数
    hops = _parse_chain_hops(chain, raise_on_error=True)

    if not hops:
        return {
            "chain": tag,
            "healthy": False,
            "message": "链路没有配置跳转节点",
            "hops": []
        }

    # 跳数限制
    if len(hops) > MAX_CHAIN_HOPS:
        raise HTTPException(
            status_code=400,
            detail=f"链路跳数 ({len(hops)}) 超过最大限制 ({MAX_CHAIN_HOPS})"
        )

    hop_results = []
    all_healthy = True
    first_hop_node = None  # 第一跳节点，用于所有后续中继查询

    for i, hop_tag in enumerate(hops):
        hop_result = {
            "hop": i + 1,
            "node": hop_tag,
            "status": "unknown",
            "tunnel_type": None,
            "message": None,
        }

        if i == 0:
            # 第一跳：直接查询本节点到该节点的隧道状态
            node = db.get_peer_node(hop_tag)
            if not node:
                hop_result["status"] = "not_found"
                hop_result["message"] = f"节点 '{hop_tag}' 不存在"
                all_healthy = False
            else:
                real_status = _check_peer_tunnel_status(node)
                hop_result["status"] = real_status
                hop_result["tunnel_type"] = node.get("tunnel_type", "wireguard")
                hop_result["message"] = f"本节点到 '{hop_tag}' 的隧道状态"

                if real_status != "connected":
                    all_healthy = False
                else:
                    first_hop_node = node
        elif i == 1:
            # 第二跳：通过第一跳中继查询
            if not first_hop_node:
                hop_result["status"] = "unreachable"
                hop_result["message"] = f"第一跳 '{hops[0]}' 不可用，无法查询"
                all_healthy = False
            else:
                relay_result = _query_relay_status(db, first_hop_node, hop_tag)
                hop_result["status"] = relay_result.get("status", "error")
                hop_result["tunnel_type"] = relay_result.get("tunnel_type")
                hop_result["message"] = relay_result.get("message")

                if hop_result["status"] != "connected":
                    all_healthy = False
        else:
            # 第三跳及以后：通过第一跳进行递归中继查询
            # 请求第一跳查询 hops[i-1] 到 hop_tag 的状态
            if not first_hop_node:
                hop_result["status"] = "unreachable"
                hop_result["message"] = f"第一跳 '{hops[0]}' 不可用，无法查询"
                all_healthy = False
            else:
                # 使用递归查询：通过第一跳，查询 hops[i-1]，并让其转发查询 hop_tag
                relay_result = _query_relay_status_recursive(
                    db, first_hop_node, hops[i-1], hop_tag
                )
                hop_result["status"] = relay_result.get("status", "error")
                hop_result["tunnel_type"] = relay_result.get("tunnel_type")
                hop_result["message"] = relay_result.get("message")

                if hop_result["status"] != "connected":
                    all_healthy = False

        hop_results.append(hop_result)

    return {
        "chain": tag,
        "healthy": all_healthy,
        "message": "链路健康" if all_healthy else "链路存在断开的节点",
        "total_hops": len(hops),
        "hops": hop_results,
    }


def _query_relay_status_recursive(
    db, relay_node: dict, target_node_tag: str, next_hop_tag: str
) -> dict:
    """通过中继节点递归查询目标节点的下一跳状态

    用于 3+ 跳链路的健康检查。例如 A->B->C->D 链路中：
    - A 调用此函数，relay_node=B, target_node_tag=C, next_hop_tag=D
    - B 收到请求后，查询自己到 C 的状态
    - 如果 C 已连接，B 递归查询 C 到 D 的状态

    Phase 2 修复：仅通过隧道通信。递归中继查询用于链路健康检查，
    必须通过隧道进行。如果隧道不可用，则返回错误状态。

    Args:
        db: 数据库实例
        relay_node: 中继节点信息（第一跳）
        target_node_tag: 目标节点标识（中间跳）
        next_hop_tag: 下一跳节点标识（要查询的最终目标）

    Returns:
        查询结果字典
    """
    from tunnel_api_client import TunnelAPIClient

    relay_tag = relay_node["tag"]

    # Phase 2: 使用隧道通信（递归中继查询必须通过隧道）
    tunnel_api = _get_peer_tunnel_endpoint(relay_node)
    if not tunnel_api:
        return {
            "success": False,
            "target_node": next_hop_tag,
            "status": "error",
            "message": f"中继节点 '{relay_tag}' 隧道不可用"
        }

    tunnel_type = relay_node.get("tunnel_type", "wireguard")
    socks_port = relay_node.get("xray_socks_port") if tunnel_type == "xray" else None
    peer_uuid = relay_node.get("xray_uuid") if tunnel_type == "xray" else None

    # 使用 next_hop 参数进行递归查询（认证通过隧道 IP/UUID）
    payload = {
        "node_id": relay_tag,  # 添加 node_id 用于日志
        "target_node": target_node_tag,
        "next_hop": next_hop_tag,
    }

    try:
        client = TunnelAPIClient(
            node_tag=relay_tag,
            tunnel_endpoint=tunnel_api,
            tunnel_type=tunnel_type,
            socks_port=socks_port,
            peer_uuid=peer_uuid,
            timeout=20
        )
        logging.info(
            f"[peer-relay] 通过隧道中继 '{relay_tag}' 递归查询 '{target_node_tag}' -> '{next_hop_tag}': {tunnel_api}"
        )
        result = client.post("/api/peer-relay/status", json=payload)

        # 从递归结果中提取下一跳状态
        if "next_hop_result" in result:
            return result["next_hop_result"]
        else:
            # 如果没有 next_hop_result，可能是中间节点未连接
            return {
                "success": False,
                "target_node": next_hop_tag,
                "status": "unreachable",
                "message": f"中间节点 '{target_node_tag}' 状态: {result.get('status', 'unknown')}"
            }
    except Exception as e:
        logging.warning(f"[peer-relay] 隧道递归中继查询失败: {e}")
        return {
            "success": False,
            "target_node": next_hop_tag,
            "status": "unreachable",
            "message": f"无法通过隧道连接中继节点"
        }


# ============ 链路激活/停用 API (Phase 6) ============

@app.get("/api/chains/{tag}/terminal-egress")
def api_get_chain_terminal_egress(tag: str, refresh: bool = False, allow_transitive: bool = False):
    """Phase 11.5: 获取链路终端节点的可用出口列表（带缓存）

    通过隧道 API 获取链路终端节点（最后一跳）上的可用出口。
    用于在链路创建/更新时选择 exit_egress。

    参数:
        tag: 链路标识
        refresh: 强制刷新缓存（默认 False）
        allow_transitive: 允许传递模式（默认 False）
            当终端节点未直接连接时，通过第一跳中继查询

    返回:
        {
            "chain": "链路标识",
            "terminal_node": "终端节点 tag",
            "egress": [...],
            "cached": true/false,      # Phase 11.5: 是否来自缓存
            "cached_at": "timestamp"   # Phase 11.5: 缓存时间（如果 cached=true）
        }
    """
    if not HAS_DATABASE or not USER_DB_PATH.exists():
        raise HTTPException(status_code=503, detail="Database unavailable")

    db = _get_db()

    # 获取链路配置
    chain = db.get_node_chain(tag)
    if not chain:
        raise HTTPException(status_code=404, detail=f"链路 '{tag}' 不存在")

    # Issue 11/12 修复：使用统一的 hops 解析函数
    hops = _parse_chain_hops(chain, raise_on_error=True)

    if not hops or len(hops) < 2:
        raise HTTPException(status_code=400, detail="链路至少需要 2 跳")

    # 终端节点是最后一跳
    terminal_tag = hops[-1]

    # Phase 11.5: 检查缓存（除非强制刷新）
    if not refresh:
        cache = db.get_terminal_egress_cache(tag)
        if cache:
            from datetime import datetime
            expires_at_str = cache.get("expires_at")
            if expires_at_str:
                try:
                    expires_at = datetime.fromisoformat(expires_at_str.replace("Z", "+00:00"))
                    if expires_at > datetime.now(expires_at.tzinfo) if expires_at.tzinfo else datetime.now():
                        # 缓存有效
                        egress_list = json.loads(cache.get("egress_list", "[]"))
                        logging.debug(f"[chains] 使用缓存的终端出口列表: 链路='{tag}'")
                        return {
                            "chain": tag,
                            "terminal_node": cache.get("terminal_node", terminal_tag),
                            "egress": egress_list,
                            "cached": True,
                            "cached_at": cache.get("cached_at"),
                        }
                except (ValueError, TypeError) as e:
                    logging.warning(f"[chains] 解析缓存过期时间失败: {e}")

    # 获取终端节点信息
    terminal_node = db.get_peer_node(terminal_tag)

    # Phase 5 Issue 4: 支持 allow_transitive，允许通过中继获取终端出口
    # 使用链路配置中的 allow_transitive 或参数覆盖
    chain_allow_transitive = chain.get("allow_transitive", False)
    effective_allow_transitive = allow_transitive or chain_allow_transitive

    via_relay = None  # 标记是否通过中继获取

    # 通过隧道 API 获取出口列表
    try:
        from tunnel_api_client import TunnelAPIClientManager, TunnelProxyError

        client_mgr = TunnelAPIClientManager(db)
        client = None

        # 检查终端节点是否存在且已连接
        if terminal_node and terminal_node.get("tunnel_status") == "connected":
            # 直接连接模式
            tunnel_api_endpoint = _get_peer_tunnel_endpoint(terminal_node)
            if tunnel_api_endpoint:
                client = client_mgr.get_client(terminal_tag)

        # 如果直接连接不可用，尝试传递模式
        if not client and effective_allow_transitive and len(hops) > 1:
            logging.info(f"[chains] 使用传递模式获取终端出口: 链路='{tag}'")
            terminal_info, relay_client, _ = _get_terminal_node_through_tunnel(db, hops)

            if terminal_info and relay_client:
                via_relay = terminal_info.get("via_relay")
                logging.info(f"[chains] 传递模式: 通过 '{via_relay}' 转发查询到终端 '{terminal_tag}'")

                # Phase 4 Fix: 通过中继转发出口查询到终端节点
                # BUG FIX: 之前直接调用 relay_client.get_egress_list() 会返回中继节点的出口，
                # 而不是终端节点的出口。现在使用 get_forwarded_egress_list() 转发查询。
                try:
                    egress_list = relay_client.get_forwarded_egress_list(terminal_tag)

                    # 转换为可序列化格式
                    egress_data = [
                        {
                            "tag": e.tag,
                            "name": e.name,
                            "type": e.type,
                            "enabled": e.enabled,
                            "description": e.description,
                        }
                        for e in egress_list
                    ]

                    # 更新缓存
                    try:
                        db.update_terminal_egress_cache(
                            chain_tag=tag,
                            terminal_node=terminal_tag,
                            egress_list=egress_data,
                            ttl_seconds=300
                        )
                    except Exception as cache_error:
                        logging.warning(f"[chains] 更新缓存失败: {cache_error}")

                    return {
                        "chain": tag,
                        "terminal_node": terminal_tag,
                        "egress": egress_data,
                        "cached": False,
                        "via_relay": via_relay,
                    }
                except Exception as e:
                    logging.error(f"[chains] 传递模式出口查询失败: {e}")
                    raise HTTPException(
                        status_code=503,
                        detail=f"无法通过中继 '{via_relay}' 获取终端 '{terminal_tag}' 的出口列表: {str(e)}"
                    )

        # 如果仍然没有客户端，返回错误
        if not client:
            if not terminal_node:
                if effective_allow_transitive:
                    raise HTTPException(
                        status_code=503,
                        detail=f"无法通过中继到达终端节点 '{terminal_tag}'（传递模式失败）"
                    )
                else:
                    raise HTTPException(
                        status_code=404,
                        detail=f"终端节点 '{terminal_tag}' 不存在（启用 allow_transitive 可支持线性拓扑）"
                    )
            elif terminal_node.get("tunnel_status") != "connected":
                if effective_allow_transitive:
                    raise HTTPException(
                        status_code=503,
                        detail=f"终端节点 '{terminal_tag}' 未连接，且无法通过中继到达"
                    )
                else:
                    raise HTTPException(
                        status_code=400,
                        detail=f"终端节点 '{terminal_tag}' 隧道未连接"
                    )
            else:
                raise HTTPException(
                    status_code=400,
                    detail=f"终端节点 '{terminal_tag}' 配置不完整或隧道未就绪"
                )

        # 直接连接模式：获取终端节点的出口列表
        egress_list = client.get_egress_list()

        # 转换为可序列化的格式
        egress_data = [
            {
                "tag": e.tag,
                "name": e.name,
                "type": e.type,
                "enabled": e.enabled,
                "description": e.description,
            }
            for e in egress_list
        ]

        # Phase 11.5: 更新缓存（TTL 5 分钟）
        try:
            db.update_terminal_egress_cache(
                chain_tag=tag,
                terminal_node=terminal_tag,
                egress_list=egress_data,
                ttl_seconds=300  # 5 分钟
            )
            logging.debug(f"[chains] 终端出口列表已缓存: 链路='{tag}'")
        except Exception as cache_error:
            logging.warning(f"[chains] 更新缓存失败: {cache_error}")

        result = {
            "chain": tag,
            "terminal_node": terminal_tag,
            "egress": egress_data,
            "cached": False,
        }
        # Phase 5 Issue 4: 添加 via_relay 信息（传递模式下）
        if via_relay:
            result["via_relay"] = via_relay
        return result

    except ImportError:
        raise HTTPException(
            status_code=500,
            detail="tunnel_api_client 模块不可用"
        )
    except TunnelProxyError as e:
        # Phase 10.3: 特别处理 SOCKS 代理错误
        logging.error(f"[chains] SOCKS 代理错误: {e}")
        raise HTTPException(
            status_code=503,
            detail=f"无法通过隧道连接到终端节点: {e}"
        )
    except HTTPException:
        raise
    except Exception as e:
        logging.error(f"[chains] 获取终端出口列表失败: {e}", exc_info=True)
        raise HTTPException(
            status_code=500,
            detail="获取终端出口列表失败，请检查日志获取详细信息"
        )


@app.get("/api/peer/forward-egress/{target_tag}")
def api_peer_forward_egress(request: Request, target_tag: str) -> dict:
    """Phase 4: 转发出口查询到目标节点

    用于传递模式下，中继节点代理转发对终端节点的出口查询。

    流程说明（A→B→C 场景）:
    1. 节点 A 需要获取终端节点 C 的出口列表
    2. A 只与 B 有隧道连接，无法直接访问 C
    3. A 调用 B 的 /api/peer/forward-egress/C 端点
    4. B 作为中继，查询其与 C 的隧道并获取 C 的出口列表
    5. B 将结果返回给 A

    注意: 此端点仅支持单跳转发（2-hop 链路）。对于更长的链路（如 A→B→C→D），
    需要额外实现多跳转发机制（携带 hop 计数和已访问节点列表）。

    认证: 隧道 IP/UUID (节点间调用，无需 JWT)

    Args:
        target_tag: 目标节点标识（终端节点）

    Returns:
        目标节点的出口列表
    """
    if not HAS_DATABASE or not USER_DB_PATH.exists():
        raise HTTPException(status_code=503, detail="Database unavailable")

    # Phase 4 Fix: Tag 验证
    if not target_tag or len(target_tag) > 64:
        raise HTTPException(status_code=400, detail="Invalid target_tag: must be 1-64 characters")

    db = _get_db()

    # Phase 4 Fix: 检查是否查询自己
    local_tag = _get_local_node_tag(db)
    if target_tag == local_tag:
        raise HTTPException(status_code=400, detail="Cannot forward egress query to self")

    # 验证请求来自已连接的 peer（隧道认证）
    caller = _verify_peer_request_flexible(request, db)
    if not caller:
        raise HTTPException(status_code=401, detail="Unauthorized: not from known peer tunnel")

    caller_tag = caller.get("tag", "unknown")
    logging.info(f"[forward-egress] 收到转发请求: caller={caller_tag}, target={target_tag}")

    # 查找目标节点
    target_node = db.get_peer_node(target_tag)
    if not target_node:
        logging.warning(f"[forward-egress] 目标节点不存在: {target_tag}")
        raise HTTPException(status_code=404, detail=f"Target node '{target_tag}' not found")

    # 检查目标节点是否已连接
    if target_node.get("tunnel_status") != "connected":
        logging.warning(f"[forward-egress] 目标节点未连接: {target_tag}")
        raise HTTPException(status_code=503, detail=f"Target node '{target_tag}' not connected")

    # 获取目标节点的出口列表
    try:
        from tunnel_api_client import TunnelAPIClientManager

        client_mgr = TunnelAPIClientManager(db)
        client = client_mgr.get_client(target_tag)

        if not client:
            logging.error(f"[forward-egress] 无法创建到 {target_tag} 的客户端")
            raise HTTPException(status_code=503, detail=f"Cannot create client for '{target_tag}'")

        egress_list = client.get_egress_list()

        local_node_tag = _get_local_node_tag(db)

        logging.info(
            f"[forward-egress] 转发成功: {caller_tag} -> {local_node_tag} -> {target_tag}, "
            f"egress count={len(egress_list)}"
        )

        return {
            "success": True,
            "target_node": target_tag,
            "forwarded_by": local_node_tag,
            "egress": [
                {
                    "tag": e.tag,
                    "name": e.name,
                    "type": e.type,
                    "enabled": e.enabled,
                    "description": e.description,
                }
                for e in egress_list
            ]
        }
    except HTTPException:
        raise
    except Exception as e:
        logging.error(f"[forward-egress] 获取 '{target_tag}' 出口列表失败: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Failed to query target node: {str(e)}")


@app.post("/api/chains/{tag}/activate")
def api_activate_chain(tag: str):
    """激活链路

    1. 验证链路配置完整（exit_egress、dscp_value）
    2. 更新链路状态为 'activating'
    3. 在终端节点注册链路路由
    4. 更新链路状态为 'active' 或 'error'
    5. 重新生成 sing-box 配置

    Phase 6 Issue 29: 使用 try/finally 确保状态转换原子性
    """
    if not HAS_DATABASE or not USER_DB_PATH.exists():
        raise HTTPException(status_code=503, detail="Database unavailable")

    db = _get_db()

    # 获取链路配置
    chain = db.get_node_chain(tag)
    if not chain:
        raise HTTPException(status_code=404, detail=f"链路 '{tag}' 不存在")

    # 验证必要字段
    exit_egress = chain.get("exit_egress")
    dscp_value = chain.get("dscp_value")
    chain_mark_type = chain.get("chain_mark_type", "dscp")

    if not exit_egress:
        raise HTTPException(
            status_code=400,
            detail="链路未配置终端出口 (exit_egress)"
        )

    # Phase 11-Fix.J + Phase 11-Fix.Q: 静态验证（完整验证在 hops 解析后）
    _validate_chain_terminal_egress_static(exit_egress)

    if not dscp_value:
        raise HTTPException(
            status_code=400,
            detail="链路未配置 DSCP 值 (dscp_value)"
        )

    # 检查当前状态
    current_state = chain.get("chain_state", "inactive")
    if current_state == "active":
        return {
            "message": "链路已处于激活状态",
            "chain": tag,
            "chain_state": "active"
        }

    # Phase 11-Fix.T: 使用原子状态转换防止并发激活竞态条件
    # 替代原有的 check-then-act 模式，确保只有一个请求能成功转换状态
    success, error = db.atomic_chain_state_transition(
        tag=tag,
        expected_state="inactive",
        new_state="activating",
        timeout_ms=30000  # 30秒锁等待超时
    )

    if not success:
        if "Expected state" in (error or ""):
            # 状态不匹配 - 可能是并发请求或已激活
            if "activating" in (error or ""):
                raise HTTPException(
                    status_code=409,
                    detail="链路正在激活中，请稍后再试"
                )
            elif "active" in (error or ""):
                return {
                    "message": "链路已处于激活状态",
                    "chain": tag,
                    "chain_state": "active"
                }
            elif "error" in (error or ""):
                raise HTTPException(
                    status_code=400,
                    detail="链路处于错误状态，请先重置后再激活"
                )
        # 其他错误（数据库错误、链路不存在等）
        raise HTTPException(
            status_code=500,
            detail=f"状态转换失败: {error}"
        )

    # Phase 6 Issue 29: 使用 activation_success 标记追踪激活是否成功
    activation_success = False

    try:
        # Issue 11/12 修复：使用统一的 hops 解析函数
        hops = _parse_chain_hops(chain, raise_on_error=True)

        if not hops or len(hops) < 2:
            raise HTTPException(status_code=400, detail="链路至少需要 2 跳")

        # 终端节点是最后一跳
        terminal_tag = hops[-1]

        # Phase 11-Fix.Q: 远程验证终端节点出口存在且兼容 DSCP 路由
        allow_transitive = chain.get("allow_transitive", False)
        egress_error = _validate_remote_terminal_egress(db, hops, exit_egress, allow_transitive)
        if egress_error:
            raise HTTPException(
                status_code=400,
                detail=f"终端出口验证失败: {egress_error}"
            )

        # Phase 4 Issue 25 修复: 预检查所有中继节点的连接状态
        # 如果任何中继节点未连接，拒绝激活（避免链路部分生效导致流量丢失）
        # allow_transitive 已在 Phase 11-Fix.Q 中定义
        if not allow_transitive:
            # 非传递模式下，所有中继节点必须已连接
            for i in range(len(hops) - 1):  # 除了终端节点
                relay_tag = hops[i]
                relay_node = db.get_peer_node(relay_tag)

                if not relay_node:
                    raise HTTPException(
                        status_code=400,
                        detail=f"中继节点 '{relay_tag}' 不存在"
                    )

                if relay_node.get("tunnel_status") != "connected":
                    raise HTTPException(
                        status_code=400,
                        detail=f"中继节点 '{relay_tag}' 隧道未连接，请先建立连接"
                    )

        # 获取本地节点 ID（用于 source_node）
        local_node_id = _get_local_node_id()

        # 在终端节点注册链路路由
        from tunnel_api_client import TunnelAPIClientManager, TunnelProxyError

        # Phase 11-Fix.E: 支持传递模式（线性拓扑 A→B→C，A 只知道 B）
        # allow_transitive 已在上面预检查中定义
        terminal_node = db.get_peer_node(terminal_tag)
        client_mgr = TunnelAPIClientManager(db)
        client = None
        via_relay = None  # 标记是否通过中继到达

        if terminal_node:
            # 直接连接模式：终端节点在本地数据库中
            if terminal_node.get("tunnel_status") != "connected":
                raise HTTPException(
                    status_code=400,
                    detail=f"终端节点 '{terminal_tag}' 隧道未连接"
                )
            client = client_mgr.get_client(terminal_tag)
        elif allow_transitive:
            # 传递模式：通过第一跳到达终端节点
            logging.info(f"[chains] 使用传递模式激活链路 '{tag}'")
            terminal_info, relay_client, _ = _get_terminal_node_through_tunnel(db, hops)

            if not terminal_info:
                raise HTTPException(
                    status_code=503,
                    detail=f"无法通过中继到达终端节点 '{terminal_tag}'（传递模式失败）"
                )

            via_relay = terminal_info.get("via_relay")
            client = relay_client
            logging.info(f"[chains] 传递模式激活: 通过 '{via_relay}' 代理链路注册")
        else:
            # 非传递模式且终端节点不存在
            raise HTTPException(
                status_code=404,
                detail=f"终端节点 '{terminal_tag}' 不存在（启用 allow_transitive 可支持线性拓扑）"
            )

        if not client:
            raise HTTPException(
                status_code=400,
                detail=f"终端节点 '{terminal_tag}' 配置不完整或隧道未就绪"
            )

        # 验证连通性（直接连接或通过中继）
        target_desc = f"中继节点 '{via_relay}'" if via_relay else f"终端节点 '{terminal_tag}'"
        logging.info(f"[chains] 验证 {target_desc} 连通性...")
        if not client.ping():
            if terminal_node:
                client_mgr.invalidate_client(terminal_tag)
            raise HTTPException(
                status_code=503,
                detail=f"无法连接到 {target_desc} API，请检查隧道连接状态"
            )
        logging.info(f"[chains] {target_desc} 连通性验证成功")

        # 注册链路路由
        # Phase 11-Fix.E: 传递模式下，通过中继转发注册到终端节点
        success = client.register_chain_route(
            chain_tag=tag,
            mark_value=dscp_value,
            egress_tag=exit_egress,
            mark_type=chain_mark_type,
            source_node=local_node_id,
            target_node=terminal_tag if via_relay else None,  # 传递模式需要转发
        )

        if not success:
            # Phase 10.3: 注册失败也清理客户端缓存，确保下次重试使用新连接
            client_mgr.invalidate_client(terminal_tag)
            raise HTTPException(
                status_code=500,
                detail="在终端节点注册链路路由失败"
            )

        # Phase 11.4 + Phase 11-Fix.T: 使用 2PC 模式在中间节点注册中继路由
        # 对于链路 local -> A -> B -> C (hops = [A, B, C])
        # - A 是中间节点，需要配置: source=local -> target=B
        # - B 是中间节点，需要配置: source=A -> target=C
        # - C 是终端节点，已在上面注册链路路由
        #
        # 2PC 流程:
        # 1. PREPARE: 在所有中间节点验证配置可行性
        # 2. COMMIT: 如果全部准备成功，执行实际注册
        # 3. ABORT: 如果任何准备失败，中止而不应用任何更改
        relay_results = []
        relay_configs = []  # 收集要配置的中继节点信息

        if len(hops) > 1:
            logging.info(f"[chains-2pc] 准备配置 {len(hops) - 1} 个中间节点的中继路由...")

            # Phase 1: 收集所有中继节点配置
            for i in range(len(hops) - 1):
                relay_tag = hops[i]
                relay_node = db.get_peer_node(relay_tag)

                if not relay_node:
                    logging.warning(f"[chains-2pc] 中间节点 '{relay_tag}' 不存在，跳过")
                    continue

                if relay_node.get("tunnel_status") != "connected":
                    logging.warning(f"[chains-2pc] 中间节点 '{relay_tag}' 隧道未连接，跳过")
                    continue

                relay_client = client_mgr.get_client(relay_tag)
                if not relay_client:
                    logging.warning(f"[chains-2pc] 无法获取中间节点 '{relay_tag}' 的 API 客户端，跳过")
                    continue

                # 确定源节点和目标节点
                source_node = local_node_id if i == 0 else hops[i - 1]
                target_node = hops[i + 1]

                relay_configs.append({
                    "tag": relay_tag,
                    "client": relay_client,
                    "source": source_node,
                    "target": target_node,
                })

            # Phase 2: PREPARE - 在所有节点验证
            if relay_configs:
                logging.info(f"[chains-2pc] PREPARE 阶段: 验证 {len(relay_configs)} 个中继节点...")
                prepare_results = []

                for config in relay_configs:
                    prepare_result = config["client"].prepare_relay_route(
                        chain_tag=tag,
                        source_node=config["source"],
                        target_node=config["target"],
                        dscp_value=dscp_value,
                        mark_type=chain_mark_type,
                    )
                    prepare_results.append({
                        "tag": config["tag"],
                        "prepared": prepare_result.get("prepared", False),
                        "error": prepare_result.get("error"),
                        "transaction_id": prepare_result.get("transaction_id"),
                    })

                # 检查是否所有节点都准备成功
                failed_prepares = [p for p in prepare_results if not p["prepared"]]
                if failed_prepares:
                    # ABORT: 有节点准备失败，回滚终端路由
                    failed_nodes = [p["tag"] for p in failed_prepares]
                    failed_errors = [f"{p['tag']}: {p['error']}" for p in failed_prepares]
                    logging.error(
                        f"[chains-2pc] PREPARE 失败，中止激活: {failed_errors}"
                    )

                    # 回滚已注册的终端路由
                    try:
                        if client:
                            client.unregister_chain_route(
                                chain_tag=tag,
                                mark_value=dscp_value,
                                mark_type=chain_mark_type,
                                target_node=terminal_tag if via_relay else None,
                                source_node=local_node_id,  # Phase 11-Fix.V.3
                            )
                    except Exception as rollback_err:
                        logging.warning(f"[chains-2pc] 回滚终端路由时出错: {rollback_err}")

                    raise HTTPException(
                        status_code=503,
                        detail=f"中继节点准备失败 (2PC ABORT): {', '.join(failed_nodes)}"
                    )

                logging.info(f"[chains-2pc] PREPARE 成功，进入 COMMIT 阶段...")

                # Phase 3: COMMIT - 执行实际注册
                for config in relay_configs:
                    relay_success = config["client"].register_relay_route(
                        chain_tag=tag,
                        source_node=config["source"],
                        target_node=config["target"],
                        dscp_value=dscp_value,
                        mark_type=chain_mark_type,
                    )

                    relay_results.append({
                        "node": config["tag"],
                        "success": relay_success,
                        "source": config["source"],
                        "target": config["target"],
                    })

                    if relay_success:
                        logging.info(
                            f"[chains-2pc] COMMIT 成功: '{config['tag']}' "
                            f"({config['source']} -> {config['target']})"
                        )
                    else:
                        logging.warning(
                            f"[chains-2pc] COMMIT 失败: '{config['tag']}' "
                            f"({config['source']} -> {config['target']})"
                        )

        # Phase 5 Issue 28: 检查中继结果，任意失败则中止激活
        if relay_results:
            failed_relays = [r for r in relay_results if not r.get("success")]

            if failed_relays:
                failed_nodes = [r["node"] for r in failed_relays]
                logging.error(f"[chains] 中继节点配置失败，中止激活: {failed_nodes}")

                # 回滚: 注销终端和已成功的中继路由
                try:
                    if client:
                        client.unregister_chain_route(
                            chain_tag=tag,
                            mark_value=dscp_value,
                            mark_type=chain_mark_type,
                            target_node=terminal_tag if via_relay else None,
                            source_node=local_node_id,  # Phase 11-Fix.V.3
                        )
                    for relay_result in relay_results:
                        if relay_result.get("success"):
                            relay_tag = relay_result["node"]
                            relay_client = client_mgr.get_client(relay_tag)
                            if relay_client:
                                relay_client.unregister_relay_route(
                                    chain_tag=tag,
                                    source_node=local_node_id,  # Phase 11-Fix.V.3
                                )
                except Exception as rollback_err:
                    logging.warning(f"[chains] 回滚中继路由时出错: {rollback_err}")

                raise HTTPException(
                    status_code=503,
                    detail=f"中继节点配置失败: {', '.join(failed_nodes)}"
                )

        # Phase 4 Issue 3 修复: 设置入口节点 DSCP 规则
        # sing-box 使用 routing_mark 标记流量，iptables 将 mark 转换为 DSCP
        # Phase 3: DSCP manager 不可用时必须失败（不再仅警告）
        if not HAS_DSCP_MANAGER:
            logging.error(f"[chains] DSCP manager unavailable - cannot activate chain '{tag}'")
            db.update_node_chain(tag, chain_state="error", last_error="DSCP manager unavailable")
            raise HTTPException(
                status_code=503,
                detail="DSCP manager unavailable - chain activation requires DSCP support"
            )

        dscp_mgr = get_dscp_manager()
        routing_mark = ENTRY_ROUTING_MARK_BASE + dscp_value

        if not dscp_mgr.setup_entry_rules(tag, routing_mark, dscp_value):
            # 回滚: 注销终端和中继路由
            logging.error(f"[chains] 设置入口 DSCP 规则失败，回滚链路 '{tag}'")
            try:
                if client:
                    client.unregister_chain_route(
                        chain_tag=tag,
                        mark_value=dscp_value,
                        mark_type=chain_mark_type,
                        target_node=terminal_tag if via_relay else None,
                        source_node=local_node_id,  # Phase 11-Fix.V.3
                    )
                # 注销中继路由
                for relay_result in relay_results:
                    if relay_result.get("success"):
                        relay_tag = relay_result["node"]
                        relay_client = client_mgr.get_client(relay_tag)
                        if relay_client:
                            relay_client.unregister_relay_route(
                                chain_tag=tag,
                                source_node=local_node_id,  # Phase 11-Fix.V.3
                            )
            except Exception as rollback_err:
                logging.warning(f"[chains] 回滚链路路由时出错: {rollback_err}")

            db.update_node_chain(tag, chain_state="error", last_error="Entry DSCP rules setup failed")
            raise HTTPException(
                status_code=500,
                detail="设置入口 DSCP 规则失败"
            )

        # Phase 3: 验证 DSCP 规则是否实际生效
        if not dscp_mgr.verify_entry_rules(tag, routing_mark, dscp_value):
            logging.error(f"[chains] Entry DSCP rules verification failed for '{tag}'")
            # 清理可能部分应用的规则
            dscp_mgr.cleanup_entry_rules(tag, routing_mark, dscp_value)
            # 回滚终端和中继路由
            try:
                if client:
                    client.unregister_chain_route(
                        chain_tag=tag,
                        mark_value=dscp_value,
                        mark_type=chain_mark_type,
                        target_node=terminal_tag if via_relay else None,
                        source_node=local_node_id,  # Phase 11-Fix.V.3
                    )
                for relay_result in relay_results:
                    if relay_result.get("success"):
                        relay_tag = relay_result["node"]
                        relay_client = client_mgr.get_client(relay_tag)
                        if relay_client:
                            relay_client.unregister_relay_route(
                                chain_tag=tag,
                                source_node=local_node_id,  # Phase 11-Fix.V.3
                            )
            except Exception as rollback_err:
                logging.warning(f"[chains] 回滚链路路由时出错: {rollback_err}")

            db.update_node_chain(tag, chain_state="error", last_error="DSCP rules verification failed")
            raise HTTPException(
                status_code=500,
                detail="DSCP rules verification failed - rules may not have been applied correctly"
            )

        logging.info(
            f"[chains] 链路 '{tag}' 入口 DSCP 规则已设置并验证: "
            f"routing_mark={routing_mark}, dscp={dscp_value}"
        )

        # 更新为 active（清除之前的错误信息）
        db.update_node_chain(tag, chain_state="active", enabled=1, last_error=None)

        # Phase 6 Issue 29: 标记激活成功
        activation_success = True

        # 重新生成 sing-box 配置
        reload_status = "success"
        try:
            _regenerate_and_reload()
        except Exception as e:
            logging.warning(f"[chains] 重新加载配置失败: {e}")
            reload_status = "failed"

        logging.info(f"[chains] 链路 '{tag}' 已激活")

        return {
            "message": f"链路 '{tag}' 已激活",
            "chain": tag,
            "chain_state": "active",
            "terminal_node": terminal_tag,
            "exit_egress": exit_egress,
            "dscp_value": dscp_value,
            "routing_mark": ENTRY_ROUTING_MARK_BASE + dscp_value,  # Phase 4: 入口 routing_mark
            "reload_status": reload_status,
            "relay_routes": relay_results,  # Phase 11.4: 中继路由配置结果
        }

    except ImportError:
        logging.error(f"[chains] tunnel_api_client 模块不可用")
        raise HTTPException(
            status_code=500,
            detail="tunnel_api_client 模块不可用"
        )
    except HTTPException:
        raise
    except TunnelProxyError as e:
        # Phase 10.3: 特别处理 SOCKS 代理错误
        logging.error(f"[chains] SOCKS 代理错误: {e}")
        raise HTTPException(
            status_code=503,
            detail=f"无法通过隧道连接到终端节点: {e}"
        )
    except Exception as e:
        logging.error(f"[chains] 激活链路失败: {e}", exc_info=True)
        raise HTTPException(
            status_code=500,
            detail="激活链路失败，请检查日志获取详细信息"
        )
    finally:
        # Phase 6 Issue 29: 确保状态不会卡在 'activating'
        # Phase 6: 同时保存错误信息到 last_error 字段便于调试
        if not activation_success:
            try:
                db.update_node_chain(tag, chain_state="error", last_error="Activation failed (see logs)")
            except Exception as e:
                logging.error(f"[chains] 更新链路 '{tag}' 状态失败: {e}")


@app.post("/api/chains/{tag}/deactivate")
def api_deactivate_chain(tag: str):
    """停用链路

    1. 更新链路状态为 'inactive'
    2. 在终端节点注销链路路由
    3. 重新生成 sing-box 配置

    Phase 6 Issue 20: 跟踪并报告清理状态
    """
    if not HAS_DATABASE or not USER_DB_PATH.exists():
        raise HTTPException(status_code=503, detail="Database unavailable")

    db = _get_db()

    # 获取链路配置
    chain = db.get_node_chain(tag)
    if not chain:
        raise HTTPException(status_code=404, detail=f"链路 '{tag}' 不存在")

    # Phase 11-Fix.V.4: 使用原子状态转换防止并发停用竞态条件
    # 尝试从 "active" 或 "error" 转换到 "inactive"
    current_state = chain.get("chain_state", "inactive")

    if current_state == "inactive":
        return {
            "message": "链路已处于停用状态",
            "chain": tag,
            "chain_state": "inactive"
        }

    if current_state == "activating":
        raise HTTPException(
            status_code=409,
            detail="链路正在激活中，请稍后再试"
        )

    # 原子转换: active → inactive 或 error → inactive
    transition_success = False
    if current_state == "active":
        success, error = db.atomic_chain_state_transition(
            tag=tag,
            expected_state="active",
            new_state="inactive",
            timeout_ms=30000
        )
        if success:
            transition_success = True
            logging.info(f"[chains] 链路 '{tag}' 状态已原子转换: active → inactive")
        else:
            # 可能被其他请求先处理了，重新获取状态
            chain = db.get_node_chain(tag)
            current_state = chain.get("chain_state", "inactive") if chain else "inactive"
            logging.warning(f"[chains] 原子转换失败: {error}，当前状态: {current_state}")

    if not transition_success and current_state == "error":
        success, error = db.atomic_chain_state_transition(
            tag=tag,
            expected_state="error",
            new_state="inactive",
            timeout_ms=30000
        )
        if success:
            transition_success = True
            logging.info(f"[chains] 链路 '{tag}' 状态已原子转换: error → inactive")
        else:
            chain = db.get_node_chain(tag)
            current_state = chain.get("chain_state", "inactive") if chain else "inactive"
            logging.warning(f"[chains] 原子转换失败: {error}，当前状态: {current_state}")

    # 如果转换失败，检查最终状态
    if not transition_success:
        if current_state == "inactive":
            return {
                "message": "链路已处于停用状态（并发请求已处理）",
                "chain": tag,
                "chain_state": "inactive"
            }
        elif current_state == "activating":
            raise HTTPException(
                status_code=409,
                detail="链路正在激活中，请稍后再试"
            )
        else:
            raise HTTPException(
                status_code=500,
                detail=f"状态转换失败: 当前状态 '{current_state}'"
            )

    dscp_value = chain.get("dscp_value")
    chain_mark_type = chain.get("chain_mark_type", "dscp")

    # Phase 6 Issue 20: 跟踪清理状态
    cleanup_results = {
        "entry_dscp": {"status": "skipped", "error": None},
        "terminal": {"status": "skipped", "error": None},
        "relays": [],
    }

    # Phase 4 Issue 17 修复: 先清理本地入口 DSCP 规则，再进行远程调用
    # 即使远程调用失败，本地规则也必须清理（否则流量仍会被错误标记）
    entry_dscp_cleanup_result = None
    if HAS_DSCP_MANAGER and dscp_value:
        try:
            dscp_mgr = get_dscp_manager()
            routing_mark = ENTRY_ROUTING_MARK_BASE + dscp_value
            dscp_mgr.cleanup_entry_rules(tag, routing_mark, dscp_value)

            # Phase 3: 验证清理是否成功（规则应该不再存在）
            if dscp_mgr.verify_entry_rules(tag, routing_mark, dscp_value):
                # 规则仍然存在 - 清理失败
                entry_dscp_cleanup_result = "partial"
                cleanup_results["entry_dscp"]["status"] = "partial"
                cleanup_results["entry_dscp"]["error"] = "rules still exist after cleanup"
                logging.error(f"[chains] Entry DSCP rules cleanup verification failed for '{tag}' - rules still exist")
            else:
                entry_dscp_cleanup_result = "success"
                cleanup_results["entry_dscp"]["status"] = "success"
                logging.info(f"[chains] 链路 '{tag}' 入口 DSCP 规则已清理并验证")
        except Exception as e:
            entry_dscp_cleanup_result = f"error: {e}"
            cleanup_results["entry_dscp"]["status"] = "error"
            cleanup_results["entry_dscp"]["error"] = str(e)
            logging.warning(f"[chains] 链路 '{tag}' 入口 DSCP 规则清理失败: {e}")

    # Issue 11/12 修复：使用统一的 hops 解析函数
    hops = _parse_chain_hops(chain, raise_on_error=False)

    # Phase 11-Fix.V.3: 获取本地节点 ID（用于 source_node 参数）
    local_node_id = _get_local_node_id()

    # 在终端节点注销链路路由（如果有配置）
    unregister_result = None
    if hops and len(hops) >= 2 and dscp_value:
        terminal_tag = hops[-1]
        allow_transitive = chain.get("allow_transitive", False)

        try:
            from tunnel_api_client import TunnelAPIClientManager

            terminal_node = db.get_peer_node(terminal_tag)
            client_mgr = TunnelAPIClientManager(db)
            client = None
            via_relay = None  # Phase 11-Fix.E: 标记是否通过中继

            if terminal_node and terminal_node.get("tunnel_status") == "connected":
                # 直接连接模式：终端节点在本地数据库中
                client = client_mgr.get_client(terminal_tag)
            elif allow_transitive:
                # Phase 11-Fix.E: 传递模式 - 通过第一跳到达终端节点
                terminal_info, relay_client, _ = _get_terminal_node_through_tunnel(db, hops)
                if terminal_info:
                    via_relay = terminal_info.get("via_relay")
                    client = relay_client
                    logging.info(f"[chains] 传递模式注销: 通过 '{via_relay}' 代理")

            if client:
                success = client.unregister_chain_route(
                    chain_tag=tag,
                    mark_value=dscp_value,
                    mark_type=chain_mark_type,
                    target_node=terminal_tag if via_relay else None,  # 传递模式需要转发
                    source_node=local_node_id,  # Phase 11-Fix.V.3: 入口节点标识
                )
                unregister_result = "success" if success else "failed"
                cleanup_results["terminal"]["status"] = "success" if success else "failed"
                if via_relay:
                    unregister_result += f" (via {via_relay})"
            else:
                unregister_result = "skipped (client unavailable)"
                cleanup_results["terminal"]["status"] = "skipped"
                cleanup_results["terminal"]["error"] = "client unavailable"

        except ImportError:
            unregister_result = "skipped (module unavailable)"
            cleanup_results["terminal"]["status"] = "skipped"
            cleanup_results["terminal"]["error"] = "module unavailable"
        except Exception as e:
            logging.warning(f"[chains] 注销链路路由时出错: {e}")
            unregister_result = f"error: {e}"
            cleanup_results["terminal"]["status"] = "error"
            cleanup_results["terminal"]["error"] = str(e)

    # Phase 11.4: 在中间节点注销中继路由
    relay_unregister_results = []
    if hops and len(hops) > 1:
        try:
            from tunnel_api_client import TunnelAPIClientManager

            client_mgr = TunnelAPIClientManager(db)

            for i in range(len(hops) - 1):  # 除了终端节点
                relay_tag = hops[i]
                relay_node = db.get_peer_node(relay_tag)

                if not relay_node:
                    relay_unregister_results.append({
                        "node": relay_tag,
                        "result": "skipped (node not found)"
                    })
                    continue

                if relay_node.get("tunnel_status") != "connected":
                    relay_unregister_results.append({
                        "node": relay_tag,
                        "result": "skipped (tunnel not connected)"
                    })
                    continue

                relay_client = client_mgr.get_client(relay_tag)
                if not relay_client:
                    relay_unregister_results.append({
                        "node": relay_tag,
                        "result": "skipped (client unavailable)"
                    })
                    continue

                # 注销中继路由（认证通过隧道 IP/UUID）
                # Phase 11-Fix.V.3: 传递入口节点标识
                success = relay_client.unregister_relay_route(
                    chain_tag=tag,
                    source_node=local_node_id,
                )
                relay_result = {
                    "node": relay_tag,
                    "result": "success" if success else "failed"
                }
                relay_unregister_results.append(relay_result)
                cleanup_results["relays"].append(relay_result)

                if success:
                    logging.info(f"[chains] 中间节点 '{relay_tag}' 中继路由已注销")
                else:
                    logging.warning(f"[chains] 中间节点 '{relay_tag}' 中继路由注销失败")

        except ImportError:
            logging.warning("[chains] tunnel_api_client 模块不可用，跳过中继路由注销")
        except Exception as e:
            logging.warning(f"[chains] 注销中继路由时出错: {e}")

    # Phase 11-Fix.V.4: 状态已在开始时原子转换为 inactive
    # 这里只需清除 enabled 标志和错误信息
    db.update_node_chain(tag, enabled=0, last_error=None)

    # 重新生成 sing-box 配置
    reload_status = "success"
    try:
        _regenerate_and_reload()
    except Exception as e:
        logging.warning(f"[chains] 重新加载配置失败: {e}")
        reload_status = "failed"

    logging.info(f"[chains] 链路 '{tag}' 已停用")

    # Phase 6 Issue 20: 判断是否部分清理
    terminal_ok = cleanup_results["terminal"]["status"] in ("success", "skipped")
    entry_ok = cleanup_results["entry_dscp"]["status"] in ("success", "skipped")
    relays_ok = all(r.get("result") == "success" for r in cleanup_results["relays"]) if cleanup_results["relays"] else True
    partial_cleanup = not (terminal_ok and entry_ok and relays_ok)

    if partial_cleanup:
        logging.warning(f"[chains] 链路 '{tag}' 部分清理失败: {cleanup_results}")

    return {
        "message": f"链路 '{tag}' 已停用",
        "chain": tag,
        "chain_state": "inactive",
        "entry_dscp_cleanup": entry_dscp_cleanup_result,  # Phase 4: 入口 DSCP 规则清理结果
        "unregister_result": unregister_result,
        "relay_unregister_results": relay_unregister_results,  # Phase 11.4
        "reload_status": reload_status,
        "cleanup_results": cleanup_results,  # Phase 6 Issue 20: 详细清理结果
        "partial_cleanup": partial_cleanup,  # Phase 6 Issue 20: 是否部分清理
    }


def _get_local_node_id() -> str:
    """获取本地节点标识

    用于标识入口节点，作为链路路由注册的 source_node。
    """
    import socket

    # 尝试从环境变量获取
    node_id = os.environ.get("VPN_ROUTER_NODE_ID")
    if node_id:
        return node_id

    # 使用主机名
    try:
        hostname = socket.gethostname()
        if hostname:
            # 清理主机名，只保留安全字符
            import re
            clean_name = re.sub(r'[^a-z0-9\-]', '', hostname.lower())[:32]
            if clean_name:
                return clean_name
    except Exception:
        pass

    # 使用 machine-id（如果可用）
    try:
        machine_id_path = Path("/etc/machine-id")
        if machine_id_path.exists():
            machine_id = machine_id_path.read_text().strip()[:8]
            if machine_id:
                return f"node-{machine_id}"
    except Exception:
        pass

    # 默认值
    return "vpn-gateway"


@app.post("/api/config/regenerate")
def api_regenerate_config():
    """重新生成 sing-box 配置（包含数据库规则）"""
    if not HAS_DATABASE or not USER_DB_PATH.exists():
        raise HTTPException(status_code=503, detail="Database unavailable")

    try:
        # 从数据库获取规则
        db_rules = generate_singbox_rules_from_db()

        # 读取现有配置
        if not CONFIG_PATH.exists():
            raise HTTPException(status_code=500, detail="sing-box 配置文件不存在")

        config = json.loads(CONFIG_PATH.read_text())

        # 更新路由规则（将数据库规则插入到配置中）
        route = config.get("route", {})
        static_rules = route.get("rules", [])

        # 数据库规则优先（放在前面）
        route["rules"] = db_rules + static_rules
        config["route"] = route

        # 保存配置
        output_path = CONFIG_PATH.parent / "sing-box.generated.json"
        output_path.write_text(json.dumps(config, indent=2, ensure_ascii=False))

        return {
            "message": "配置已重新生成",
            "output": str(output_path),
            "db_rules_count": len(db_rules),
            "static_rules_count": len(static_rules)
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"生成配置失败: {str(e)}")


# ============ Remote API Proxy ============

# 隧道子网（用于验证 tunnel_remote_ip）
PEER_TUNNEL_SUBNET = ipaddress.ip_network("10.200.200.0/24")

# 允许的 API 路径字符（防止 SSRF 路径注入）
ALLOWED_PATH_PATTERN = re.compile(r'^[a-zA-Z0-9_\-/\.]+$')


def _validate_api_path(path: str) -> bool:
    """验证 API 路径是否安全

    防止路径遍历和 URL 注入攻击。
    """
    # 禁止路径遍历
    if ".." in path:
        return False
    # 禁止 URL 编码的遍历
    if "%2e" in path.lower() or "%2f" in path.lower():
        return False
    # 禁止特殊 URL 字符
    if any(c in path for c in ['#', '?', '\x00', '\n', '\r']):
        return False
    # 只允许安全字符
    if not ALLOWED_PATH_PATTERN.match(path):
        return False
    return True


def _validate_tunnel_ip(ip_str: str) -> bool:
    """验证隧道 IP 是否在允许的子网内"""
    try:
        ip = ipaddress.ip_address(ip_str)
        return ip in PEER_TUNNEL_SUBNET
    except ValueError:
        return False


@app.api_route("/api/remote/{peer_tag}/{path:path}", methods=["GET", "POST", "PUT", "DELETE", "PATCH"])
async def api_remote_proxy(
    peer_tag: str,
    path: str,
    request: Request,
    authorization: Optional[str] = Header(None),
):
    """代理 API 请求到远程节点

    通过已建立的隧道（WireGuard 或 Xray SOCKS）转发 API 请求到远程节点。

    Args:
        peer_tag: 目标节点的标识符
        path: 要代理的 API 路径（不含 /api/ 前缀）

    示例:
        GET /api/remote/node-tokyo/status → GET http://10.200.200.2:8000/api/status
        PUT /api/remote/node-tokyo/rules → PUT http://10.200.200.2:8000/api/rules
    """
    # [安全] 验证路径参数，防止 SSRF 路径注入
    if not _validate_api_path(path):
        raise HTTPException(status_code=400, detail="Invalid API path")

    if not HAS_DATABASE or not USER_DB_PATH.exists():
        raise HTTPException(status_code=503, detail="Database unavailable")

    db = _get_db()
    node = db.get_peer_node(peer_tag)

    if not node:
        raise HTTPException(status_code=404, detail=f"节点 '{peer_tag}' 不存在")

    # 检查隧道状态
    tunnel_status = node.get("tunnel_status", "disconnected")
    if tunnel_status != "connected":
        raise HTTPException(
            status_code=503,
            detail=f"节点 '{peer_tag}' 隧道未连接 (状态: {tunnel_status})"
        )

    tunnel_type = node.get("tunnel_type", "wireguard")
    tunnel_remote_ip = node.get("tunnel_remote_ip")
    xray_socks_port = node.get("xray_socks_port")

    # [安全] 验证隧道 IP 在允许的子网内
    if not tunnel_remote_ip or not _validate_tunnel_ip(tunnel_remote_ip):
        raise HTTPException(status_code=500, detail="Invalid tunnel IP configuration")

    # 构建目标 URL
    target_port = 8000  # 远程节点 API 端口
    target_url = f"http://{tunnel_remote_ip}:{target_port}/api/{path}"

    # 获取查询参数
    query_string = str(request.query_params)
    if query_string:
        target_url += f"?{query_string}"

    # 获取请求体
    body = None
    if request.method in ["POST", "PUT", "PATCH"]:
        body = await request.body()

    # 准备请求头（转发 Authorization 头）
    headers = {}
    if authorization:
        headers["Authorization"] = authorization
    content_type = request.headers.get("content-type")
    if content_type:
        headers["Content-Type"] = content_type

    try:
        if tunnel_type == "wireguard":
            # WireGuard 隧道: 直接通过隧道内网 IP 访问
            response = await _proxy_request_direct(
                method=request.method,
                url=target_url,
                headers=headers,
                body=body,
                timeout=30,
            )
        else:
            # Xray 隧道: 通过 SOCKS5 代理
            if not xray_socks_port:
                raise HTTPException(
                    status_code=500,
                    detail=f"节点 '{peer_tag}' 缺少 SOCKS 端口配置"
                )
            response = await _proxy_request_via_socks(
                method=request.method,
                url=target_url,
                headers=headers,
                body=body,
                socks_port=xray_socks_port,
                timeout=30,
            )

        return Response(
            content=response["body"],
            status_code=response["status_code"],
            headers=response.get("headers", {}),
        )

    except asyncio.TimeoutError:
        raise HTTPException(status_code=504, detail=f"远程节点 '{peer_tag}' 请求超时")
    except Exception as e:
        logging.error(f"[remote-proxy] 代理请求到 '{peer_tag}' 失败: {e}")
        raise HTTPException(status_code=502, detail=f"代理请求失败: {str(e)}")


async def _proxy_request_direct(
    method: str,
    url: str,
    headers: Dict[str, str],
    body: Optional[bytes],
    timeout: int = 30,
) -> Dict:
    """直接 HTTP 请求（用于 WireGuard 隧道）"""
    import urllib.request
    import urllib.error

    req = urllib.request.Request(url, data=body, headers=headers, method=method)

    try:
        with urllib.request.urlopen(req, timeout=timeout) as response:
            return {
                "status_code": response.status,
                "body": response.read(),
                "headers": dict(response.headers),
            }
    except urllib.error.HTTPError as e:
        return {
            "status_code": e.code,
            "body": e.read(),
            "headers": dict(e.headers) if e.headers else {},
        }


async def _proxy_request_via_socks(
    method: str,
    url: str,
    headers: Dict[str, str],
    body: Optional[bytes],
    socks_port: int,
    timeout: int = 30,
) -> Dict:
    """通过 SOCKS5 代理发送请求（用于 Xray 隧道）"""
    import subprocess

    # 使用 curl 通过 SOCKS5 代理发送请求
    curl_cmd = [
        "curl", "-s", "-S",
        "--max-time", str(timeout),
        "--proxy", f"socks5://127.0.0.1:{socks_port}",
        "-X", method,
        "-w", "\n%{http_code}",  # 输出状态码
    ]

    # [安全] 添加请求头（过滤可能导致 HTTP 头注入的字符）
    for key, value in headers.items():
        # 过滤换行符防止 HTTP 头注入
        if '\r' in value or '\n' in value:
            logging.warning(f"[socks-proxy] 跳过包含换行符的请求头: {key}")
            continue
        curl_cmd.extend(["-H", f"{key}: {value}"])

    # 添加请求体
    if body:
        curl_cmd.extend(["-d", body.decode("utf-8", errors="replace")])

    curl_cmd.append(url)

    result = subprocess.run(
        curl_cmd,
        capture_output=True,
        timeout=timeout + 5,
    )

    if result.returncode != 0:
        error_msg = result.stderr.decode("utf-8", errors="replace")
        raise RuntimeError(f"SOCKS 代理请求失败: {error_msg}")

    # 解析响应（最后一行是状态码）
    output = result.stdout.decode("utf-8", errors="replace")
    lines = output.rsplit("\n", 1)
    response_body = lines[0] if len(lines) > 1 else ""
    status_code = int(lines[-1]) if lines[-1].isdigit() else 200

    return {
        "status_code": status_code,
        "body": response_body.encode("utf-8"),
        "headers": {"Content-Type": "application/json"},
    }


# ============ Batch Operations API ============

# 批量操作最大数量限制
MAX_BATCH_SIZE = 100


class BatchConnectRequest(BaseModel):
    """批量连接请求"""
    tags: List[str] = Field(...)


class BatchDisconnectRequest(BaseModel):
    """批量断开请求"""
    tags: List[str] = Field(...)


class BatchRulesRequest(BaseModel):
    """批量推送规则请求"""
    tags: List[str] = Field(...)
    rules: List[Dict[str, Any]] = Field(...)
    mode: str = "append"  # append | replace


@app.post("/api/batch/connect")
async def api_batch_connect(payload: BatchConnectRequest):
    """批量连接多个节点"""
    if not HAS_DATABASE or not USER_DB_PATH.exists():
        raise HTTPException(status_code=503, detail="Database unavailable")

    # [优化] 在循环外获取数据库连接和管理器
    db = _get_db()
    from peer_tunnel_manager import PeerTunnelManager
    manager = PeerTunnelManager()

    results = []
    for tag in payload.tags:
        try:
            node = db.get_peer_node(tag)

            if not node:
                results.append({"tag": tag, "success": False, "error": "节点不存在"})
                continue

            if not node.get("enabled"):
                results.append({"tag": tag, "success": False, "error": "节点已禁用"})
                continue

            success = manager.connect_node(tag)

            if success:
                results.append({"tag": tag, "success": True})
            else:
                node = db.get_peer_node(tag)
                results.append({
                    "tag": tag,
                    "success": False,
                    "error": node.get("last_error", "连接失败") if node else "连接失败"
                })
        except Exception as e:
            logging.exception(f"[batch-connect] 连接节点 '{tag}' 失败")
            results.append({"tag": tag, "success": False, "error": "Internal error"})

    success_count = sum(1 for r in results if r["success"])
    return {
        "total": len(payload.tags),
        "success": success_count,
        "failed": len(payload.tags) - success_count,
        "results": results,
    }


@app.post("/api/batch/disconnect")
async def api_batch_disconnect(payload: BatchDisconnectRequest):
    """批量断开多个节点"""
    if not HAS_DATABASE or not USER_DB_PATH.exists():
        raise HTTPException(status_code=503, detail="Database unavailable")

    # [优化] 在循环外获取管理器
    from peer_tunnel_manager import PeerTunnelManager
    manager = PeerTunnelManager()

    results = []
    for tag in payload.tags:
        try:
            success = manager.disconnect_node(tag)

            if success:
                results.append({"tag": tag, "success": True})
            else:
                results.append({"tag": tag, "success": False, "error": "断开失败"})
        except Exception as e:
            logging.exception(f"[batch-disconnect] 断开节点 '{tag}' 失败")
            results.append({"tag": tag, "success": False, "error": "Internal error"})

    success_count = sum(1 for r in results if r["success"])
    return {
        "total": len(payload.tags),
        "success": success_count,
        "failed": len(payload.tags) - success_count,
        "results": results,
    }


@app.post("/api/batch/rules")
async def api_batch_push_rules(
    payload: BatchRulesRequest,
    request: Request,
    authorization: Optional[str] = Header(None),
):
    """批量推送路由规则到多个节点

    通过远程代理向多个节点推送路由规则。
    mode: "append" 追加规则，"replace" 替换所有规则
    """
    if not HAS_DATABASE or not USER_DB_PATH.exists():
        raise HTTPException(status_code=503, detail="Database unavailable")

    results = []
    db = _get_db()

    for tag in payload.tags:
        try:
            node = db.get_peer_node(tag)

            if not node:
                results.append({"tag": tag, "success": False, "error": "节点不存在"})
                continue

            if node.get("tunnel_status") != "connected":
                results.append({"tag": tag, "success": False, "error": "隧道未连接"})
                continue

            # 构建远程 API 请求
            tunnel_type = node.get("tunnel_type", "wireguard")
            tunnel_remote_ip = node.get("tunnel_remote_ip")
            xray_socks_port = node.get("xray_socks_port")

            # Phase A: 动态构建隧道 API 端点
            tunnel_api_endpoint = _get_peer_tunnel_endpoint(node)
            if not tunnel_api_endpoint:
                continue  # 无法构建端点，跳过此节点
            target_url = f"http://{tunnel_api_endpoint}/api/rules"

            headers = {"Content-Type": "application/json"}
            if authorization:
                headers["Authorization"] = authorization

            body = json.dumps({
                "rules": payload.rules,
                "mode": payload.mode,
            }).encode("utf-8")

            if tunnel_type == "wireguard":
                response = await _proxy_request_direct(
                    method="PUT",
                    url=target_url,
                    headers=headers,
                    body=body,
                    timeout=30,
                )
            else:
                response = await _proxy_request_via_socks(
                    method="PUT",
                    url=target_url,
                    headers=headers,
                    body=body,
                    socks_port=xray_socks_port,
                    timeout=30,
                )

            if response["status_code"] in (200, 201):
                results.append({"tag": tag, "success": True})
            else:
                error_body = response["body"].decode("utf-8", errors="replace")
                results.append({
                    "tag": tag,
                    "success": False,
                    "error": f"HTTP {response['status_code']}: {error_body[:200]}"
                })
        except Exception as e:
            results.append({"tag": tag, "success": False, "error": str(e)})

    success_count = sum(1 for r in results if r["success"])
    return {
        "total": len(payload.tags),
        "success": success_count,
        "failed": len(payload.tags) - success_count,
        "results": results,
    }


@app.post("/api/batch/reload")
async def api_batch_reload(
    payload: BatchConnectRequest,  # 使用相同的 tags 格式
    authorization: Optional[str] = Header(None),
):
    """批量重载多个节点配置"""
    if not HAS_DATABASE or not USER_DB_PATH.exists():
        raise HTTPException(status_code=503, detail="Database unavailable")

    results = []
    db = _get_db()

    for tag in payload.tags:
        try:
            node = db.get_peer_node(tag)

            if not node:
                results.append({"tag": tag, "success": False, "error": "节点不存在"})
                continue

            if node.get("tunnel_status") != "connected":
                results.append({"tag": tag, "success": False, "error": "隧道未连接"})
                continue

            tunnel_type = node.get("tunnel_type", "wireguard")
            tunnel_remote_ip = node.get("tunnel_remote_ip")
            xray_socks_port = node.get("xray_socks_port")

            # Phase A: 动态构建隧道 API 端点
            tunnel_api_endpoint = _get_peer_tunnel_endpoint(node)
            if not tunnel_api_endpoint:
                continue  # 无法构建端点，跳过此节点
            target_url = f"http://{tunnel_api_endpoint}/api/config/reload"

            headers = {}
            if authorization:
                headers["Authorization"] = authorization

            if tunnel_type == "wireguard":
                response = await _proxy_request_direct(
                    method="POST",
                    url=target_url,
                    headers=headers,
                    body=None,
                    timeout=30,
                )
            else:
                response = await _proxy_request_via_socks(
                    method="POST",
                    url=target_url,
                    headers=headers,
                    body=None,
                    socks_port=xray_socks_port,
                    timeout=30,
                )

            if response["status_code"] in (200, 201):
                results.append({"tag": tag, "success": True})
            else:
                error_body = response["body"].decode("utf-8", errors="replace")
                results.append({
                    "tag": tag,
                    "success": False,
                    "error": f"HTTP {response['status_code']}: {error_body[:200]}"
                })
        except Exception as e:
            results.append({"tag": tag, "success": False, "error": str(e)})

    success_count = sum(1 for r in results if r["success"])
    return {
        "total": len(payload.tags),
        "success": success_count,
        "failed": len(payload.tags) - success_count,
        "results": results,
    }


# ============ Peer/Chain Traffic Stats API ============

@app.get("/api/stats/peers")
def api_stats_peers():
    """获取所有节点隧道流量统计"""
    if not HAS_DATABASE or not USER_DB_PATH.exists():
        raise HTTPException(status_code=503, detail="Database unavailable")

    db = _get_db()
    nodes = db.get_peer_nodes()

    stats = []
    for node in nodes:
        tag = node.get("tag")
        tunnel_status = node.get("tunnel_status", "disconnected")
        tunnel_interface = node.get("tunnel_interface")

        # 从 V2Ray Stats API 获取流量数据
        traffic = {"upload": 0, "download": 0}
        if tunnel_status == "connected" and tunnel_interface:
            try:
                outbound_stats = _v2ray_client.get_outbound_stats() if _v2ray_client else {}
                if tag in outbound_stats:
                    traffic = outbound_stats[tag]
            except Exception:
                pass

        stats.append({
            "tag": tag,
            "name": node.get("name", tag),
            "status": tunnel_status,
            "upload": traffic.get("upload", 0),
            "download": traffic.get("download", 0),
            "last_seen": node.get("last_seen"),
        })

    return {"peers": stats, "count": len(stats)}


@app.get("/api/stats/peers/{tag}")
def api_stats_peer_detail(tag: str):
    """获取单个节点流量详情"""
    if not HAS_DATABASE or not USER_DB_PATH.exists():
        raise HTTPException(status_code=503, detail="Database unavailable")

    db = _get_db()
    node = db.get_peer_node(tag)

    if not node:
        raise HTTPException(status_code=404, detail=f"节点 '{tag}' 不存在")

    tunnel_status = node.get("tunnel_status", "disconnected")
    tunnel_interface = node.get("tunnel_interface")

    # 从 V2Ray Stats API 获取流量数据
    traffic = {"upload": 0, "download": 0}
    if tunnel_status == "connected" and tunnel_interface:
        try:
            outbound_stats = _v2ray_client.get_outbound_stats() if _v2ray_client else {}
            if tag in outbound_stats:
                traffic = outbound_stats[tag]
        except Exception:
            pass

    return {
        "tag": tag,
        "name": node.get("name", tag),
        "status": tunnel_status,
        "upload": traffic.get("upload", 0),
        "download": traffic.get("download", 0),
        "last_seen": node.get("last_seen"),
        "endpoint": node.get("endpoint"),
        "tunnel_type": node.get("tunnel_type"),
        "tunnel_local_ip": node.get("tunnel_local_ip"),
        "tunnel_remote_ip": node.get("tunnel_remote_ip"),
    }


@app.get("/api/stats/chains")
def api_stats_chains():
    """获取所有链路流量统计"""
    if not HAS_DATABASE or not USER_DB_PATH.exists():
        raise HTTPException(status_code=503, detail="Database unavailable")

    db = _get_db()
    chains = db.get_node_chains()

    stats = []
    for chain in chains:
        tag = chain.get("tag")
        # Issue 11/12 修复：使用统一的 hops 解析函数
        hops = _parse_chain_hops(chain, raise_on_error=False)

        # 检查链路健康状态（所有跳转节点都连接）
        all_connected = True
        for hop in hops:
            node = db.get_peer_node(hop)
            if not node or node.get("tunnel_status") != "connected":
                all_connected = False
                break

        # 链路流量 = 第一跳的流量
        traffic = {"upload": 0, "download": 0}
        if hops and all_connected:
            try:
                outbound_stats = _v2ray_client.get_outbound_stats() if _v2ray_client else {}
                if tag in outbound_stats:
                    traffic = outbound_stats[tag]
            except Exception:
                pass

        stats.append({
            "tag": tag,
            "name": chain.get("name", tag),
            "hops": hops,
            "status": "healthy" if all_connected else "unhealthy",
            "upload": traffic.get("upload", 0),
            "download": traffic.get("download", 0),
        })

    return {"chains": stats, "count": len(stats)}


@app.get("/api/stats/chains/{tag}")
def api_stats_chain_detail(tag: str):
    """获取单个链路流量详情"""
    if not HAS_DATABASE or not USER_DB_PATH.exists():
        raise HTTPException(status_code=503, detail="Database unavailable")

    db = _get_db()
    chain = db.get_node_chain(tag)

    if not chain:
        raise HTTPException(status_code=404, detail=f"链路 '{tag}' 不存在")

    # Issue 11/12 修复：使用统一的 hops 解析函数
    hops = _parse_chain_hops(chain, raise_on_error=True)

    # 获取每个跳转节点的状态
    hop_details = []
    all_connected = True
    for hop in hops:
        node = db.get_peer_node(hop)
        if node:
            status = node.get("tunnel_status", "disconnected")
            if status != "connected":
                all_connected = False
            hop_details.append({
                "tag": hop,
                "name": node.get("name", hop),
                "status": status,
            })
        else:
            all_connected = False
            hop_details.append({
                "tag": hop,
                "name": hop,
                "status": "missing",
            })

    # 链路流量
    traffic = {"upload": 0, "download": 0}
    if all_connected:
        try:
            outbound_stats = _v2ray_client.get_outbound_stats() if _v2ray_client else {}
            if tag in outbound_stats:
                traffic = outbound_stats[tag]
        except Exception:
            pass

    return {
        "tag": tag,
        "name": chain.get("name", tag),
        "hops": hop_details,
        "status": "healthy" if all_connected else "unhealthy",
        "upload": traffic.get("upload", 0),
        "download": traffic.get("download", 0),
    }


# ============================================================================
# DNS API Endpoints (Phase 7.7)
# ============================================================================

# Global rust-router client instance (reused across requests)
_rust_router_client: Optional["RustRouterClient"] = None


async def _get_rust_router_client() -> Optional["RustRouterClient"]:
    """Get rust-router client if available.

    Uses a singleton pattern with connection validation.
    Returns None if rust-router is not available.
    """
    global _rust_router_client

    if not HAS_RUST_ROUTER_CLIENT:
        return None

    try:
        if _rust_router_client is None:
            _rust_router_client = RustRouterClient()

        # Test connection with a ping
        ping_response = await _rust_router_client.ping()
        if ping_response.success:
            return _rust_router_client
        else:
            # Connection failed, reset client for next attempt
            _rust_router_client = None
            return None
    except Exception as e:
        logging.warning(f"Failed to connect to rust-router: {e}")
        _rust_router_client = None
        return None


class FlushCacheRequest(BaseModel):
    """Request to flush DNS cache

    Patterns are matched as domain suffixes (e.g., "example.com" matches "sub.example.com").
    Maximum pattern length is 253 characters (RFC 1035 DNS label limit).
    """
    pattern: Optional[str] = None

    @validator('pattern')
    def validate_pattern(cls, v):
        if v is None:
            return v
        # Max DNS domain length (RFC 1035)
        if len(v) > 253:
            raise ValueError('Pattern exceeds maximum DNS domain length (253 characters)')
        # Basic sanitization - only allow valid DNS label characters
        import re
        if not re.match(r'^[a-zA-Z0-9._-]+$', v):
            raise ValueError('Pattern contains invalid characters. Only alphanumeric, dots, hyphens, and underscores allowed')
        return v


class AddUpstreamRequest(BaseModel):
    """Request to add a DNS upstream server"""
    tag: str
    address: str
    protocol: str  # "udp", "tcp", "doh", "dot"
    bootstrap: Optional[List[str]] = None
    timeout_secs: Optional[int] = None


class AddRouteRequest(BaseModel):
    """Request to add a DNS routing rule"""
    pattern: str
    match_type: str  # "exact", "suffix", "keyword", "regex"
    upstream_tag: str


class DnsQueryRequest(BaseModel):
    """Request to perform a DNS query"""
    domain: str
    qtype: int = 1  # Default: A record
    upstream: Optional[str] = None


@app.get("/api/dns/stats")
async def api_get_dns_stats():
    """Get overall DNS statistics"""
    client = await _get_rust_router_client()
    if not client:
        raise HTTPException(status_code=503, detail="rust-router not available")

    stats = await client.get_dns_stats()
    if not stats:
        raise HTTPException(status_code=500, detail="Failed to get DNS stats")

    return {
        "enabled": stats.enabled,
        "uptime_secs": stats.uptime_secs,
        "total_queries": stats.total_queries,
        "cache_hits": stats.cache_hits,
        "cache_misses": stats.cache_misses,
        "blocked_queries": stats.blocked_queries,
        "upstream_queries": stats.upstream_queries,
        "avg_latency_us": stats.avg_latency_us,
    }


@app.get("/api/dns/config")
async def api_get_dns_config():
    """Get current DNS configuration"""
    client = await _get_rust_router_client()
    if not client:
        raise HTTPException(status_code=503, detail="rust-router not available")

    config = await client.get_dns_config()
    if not config:
        raise HTTPException(status_code=500, detail="Failed to get DNS config")

    return {
        "enabled": config.enabled,
        "listen_udp": config.listen_udp,
        "listen_tcp": config.listen_tcp,
        "upstreams": [
            {
                "tag": u.tag,
                "address": u.address,
                "protocol": u.protocol,
                "healthy": u.healthy,
            }
            for u in config.upstreams
        ],
        "cache_enabled": config.cache_enabled,
        "cache_max_entries": config.cache_max_entries,
        "blocking_enabled": config.blocking_enabled,
        "blocking_response_type": config.blocking_response_type,
        "logging_enabled": config.logging_enabled,
        "logging_format": config.logging_format,
        # Feature availability status for clients to determine what's implemented
        "available_features": config.available_features,
    }


@app.get("/api/dns/cache/stats")
async def api_get_dns_cache_stats():
    """Get DNS cache statistics"""
    client = await _get_rust_router_client()
    if not client:
        raise HTTPException(status_code=503, detail="rust-router not available")

    stats = await client.get_dns_cache_stats()
    if not stats:
        raise HTTPException(status_code=500, detail="Failed to get cache stats")

    return {
        "enabled": stats.enabled,
        "max_entries": stats.max_entries,
        "current_entries": stats.current_entries,
        "hits": stats.hits,
        "misses": stats.misses,
        "hit_rate": stats.hit_rate,
        "negative_hits": stats.negative_hits,
        "inserts": stats.inserts,
        "evictions": stats.evictions,
    }


@app.post("/api/dns/cache/flush")
async def api_flush_dns_cache(request: FlushCacheRequest = None):
    """Flush DNS cache (optional pattern for selective flush)"""
    client = await _get_rust_router_client()
    if not client:
        raise HTTPException(status_code=503, detail="rust-router not available")

    pattern = request.pattern if request else None
    response = await client.flush_dns_cache(pattern)

    if not response.success:
        raise HTTPException(status_code=500, detail=response.error or "Failed to flush cache")

    return {"success": True, "message": f"Cache flushed{' for pattern: ' + pattern if pattern else ''}"}


@app.get("/api/dns/block/stats")
async def api_get_dns_block_stats():
    """Get DNS blocking statistics"""
    client = await _get_rust_router_client()
    if not client:
        raise HTTPException(status_code=503, detail="rust-router not available")

    stats = await client.get_dns_block_stats()
    if not stats:
        raise HTTPException(status_code=500, detail="Failed to get block stats")

    return {
        "enabled": stats.enabled,
        "rule_count": stats.rule_count,
        "blocked_queries": stats.blocked_queries,
        "total_queries": stats.total_queries,
        "block_rate": stats.block_rate,
        "last_reload": stats.last_reload,
    }


@app.post("/api/dns/blocklist/reload")
async def api_reload_dns_blocklist():
    """Reload DNS blocklist from database"""
    client = await _get_rust_router_client()
    if not client:
        raise HTTPException(status_code=503, detail="rust-router not available")

    response = await client.reload_dns_blocklist()

    if not response.success:
        raise HTTPException(status_code=500, detail=response.error or "Failed to reload blocklist")

    return {"success": True, "message": "Blocklist reloaded"}


@app.get("/api/dns/upstreams")
async def api_get_dns_upstreams(tag: Optional[str] = None):
    """Get DNS upstream server status"""
    client = await _get_rust_router_client()
    if not client:
        raise HTTPException(status_code=503, detail="rust-router not available")

    upstreams = await client.get_dns_upstream_status(tag)

    return {
        "upstreams": [
            {
                "tag": u.tag,
                "address": u.address,
                "protocol": u.protocol,
                "healthy": u.healthy,
                "total_queries": u.total_queries,
                "failed_queries": u.failed_queries,
                "avg_latency_us": u.avg_latency_us,
                "last_success": u.last_success,
                "last_failure": u.last_failure,
            }
            for u in upstreams
        ]
    }


@app.post("/api/dns/upstreams")
async def api_add_dns_upstream(request: AddUpstreamRequest):
    """Add a DNS upstream server"""
    client = await _get_rust_router_client()
    if not client:
        raise HTTPException(status_code=503, detail="rust-router not available")

    response = await client.add_dns_upstream(
        tag=request.tag,
        address=request.address,
        protocol=request.protocol,
        bootstrap=request.bootstrap,
        timeout_secs=request.timeout_secs,
    )

    if not response.success:
        raise HTTPException(status_code=400, detail=response.error or "Failed to add upstream")

    return {"success": True, "message": f"Upstream '{request.tag}' added"}


@app.delete("/api/dns/upstreams/{tag}")
async def api_remove_dns_upstream(tag: str):
    """Remove a DNS upstream server"""
    client = await _get_rust_router_client()
    if not client:
        raise HTTPException(status_code=503, detail="rust-router not available")

    response = await client.remove_dns_upstream(tag)

    if not response.success:
        raise HTTPException(status_code=400, detail=response.error or "Failed to remove upstream")

    return {"success": True, "message": f"Upstream '{tag}' removed"}


@app.post("/api/dns/routes")
async def api_add_dns_route(request: AddRouteRequest):
    """Add a DNS routing rule"""
    client = await _get_rust_router_client()
    if not client:
        raise HTTPException(status_code=503, detail="rust-router not available")

    response = await client.add_dns_route(
        pattern=request.pattern,
        match_type=request.match_type,
        upstream_tag=request.upstream_tag,
    )

    if not response.success:
        raise HTTPException(status_code=400, detail=response.error or "Failed to add route")

    return {"success": True, "message": f"Route for '{request.pattern}' added"}


@app.delete("/api/dns/routes/{pattern:path}")
async def api_remove_dns_route(pattern: str):
    """Remove a DNS routing rule"""
    client = await _get_rust_router_client()
    if not client:
        raise HTTPException(status_code=503, detail="rust-router not available")

    response = await client.remove_dns_route(pattern)

    if not response.success:
        raise HTTPException(status_code=400, detail=response.error or "Failed to remove route")

    return {"success": True, "message": f"Route for '{pattern}' removed"}


@app.get("/api/dns/query-log")
async def api_get_dns_query_log(limit: int = 100, offset: int = 0):
    """Get DNS query log entries"""
    client = await _get_rust_router_client()
    if not client:
        raise HTTPException(status_code=503, detail="rust-router not available")

    entries = await client.get_dns_query_log(limit=limit, offset=offset)

    return {
        "entries": [
            {
                "timestamp": e.timestamp,
                "domain": e.domain,
                "qtype": e.qtype,
                "qtype_str": e.qtype_str,
                "upstream": e.upstream,
                "response_code": e.response_code,
                "rcode_str": e.rcode_str,
                "latency_us": e.latency_us,
                "blocked": e.blocked,
                "cached": e.cached,
            }
            for e in entries
        ],
        "limit": limit,
        "offset": offset,
    }


@app.get("/api/dns/query")
async def api_dns_query_get(
    domain: str,
    qtype: int = 1,
    upstream: Optional[str] = None,
):
    """Perform a test DNS query (GET method)"""
    client = await _get_rust_router_client()
    if not client:
        raise HTTPException(status_code=503, detail="rust-router not available")

    result = await client.dns_query(domain=domain, qtype=qtype, upstream=upstream)

    if not result:
        raise HTTPException(status_code=500, detail="Failed to perform DNS query")

    return {
        "success": result.success,
        "domain": result.domain,
        "qtype": result.qtype,
        "response_code": result.response_code,
        "answers": result.answers,
        "latency_us": result.latency_us,
        "cached": result.cached,
        "blocked": result.blocked,
        "upstream_used": result.upstream_used,
    }


@app.post("/api/dns/query")
async def api_dns_query_post(request: DnsQueryRequest):
    """Perform a test DNS query (POST method)"""
    client = await _get_rust_router_client()
    if not client:
        raise HTTPException(status_code=503, detail="rust-router not available")

    result = await client.dns_query(
        domain=request.domain,
        qtype=request.qtype,
        upstream=request.upstream,
    )

    if not result:
        raise HTTPException(status_code=500, detail="Failed to perform DNS query")

    return {
        "success": result.success,
        "domain": result.domain,
        "qtype": result.qtype,
        "response_code": result.response_code,
        "answers": result.answers,
        "latency_us": result.latency_us,
        "cached": result.cached,
        "blocked": result.blocked,
        "upstream_used": result.upstream_used,
    }


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        "api_server:app",
        host=os.environ.get("API_HOST", "0.0.0.0"),
        port=_safe_int_env("API_PORT", DEFAULT_API_BACKEND_PORT),
        reload=False,
        factory=False,
    )

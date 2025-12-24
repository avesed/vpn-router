#!/usr/bin/env python3
"""FastAPI 服务：为前端提供 sing-box 网关管理接口"""
import hashlib
import json
import os
import secrets
import shutil
import socket
import subprocess
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

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
from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import PlainTextResponse, Response
from pydantic import BaseModel, Field
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
    from v2ray_uri_parser import parse_v2ray_uri, generate_vmess_uri, generate_vless_uri, generate_trojan_uri
    HAS_V2RAY_PARSER = True
except ImportError:
    HAS_V2RAY_PARSER = False
    print("WARNING: V2Ray URI parser not available")

CONFIG_PATH = Path(os.environ.get("SING_BOX_CONFIG", "/etc/sing-box/sing-box.json"))
GENERATED_CONFIG_PATH = Path(os.environ.get("SING_BOX_GENERATED_CONFIG", "/etc/sing-box/sing-box.generated.json"))
GEODATA_DB_PATH = Path(os.environ.get("GEODATA_DB_PATH", "/etc/sing-box/geoip-geodata.db"))
USER_DB_PATH = Path(os.environ.get("USER_DB_PATH", "/etc/sing-box/user-config.db"))
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

# Port and subnet configuration from environment
DEFAULT_WG_PORT = int(os.environ.get("WG_LISTEN_PORT", "36100"))
DEFAULT_WEB_PORT = int(os.environ.get("WEB_PORT", "36000"))
DEFAULT_WG_SUBNET = os.environ.get("WG_INGRESS_SUBNET", "10.25.0.1/24")

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
        db = get_db(str(GEODATA_DB_PATH), str(USER_DB_PATH))
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
class _CredentialStore:
    """
    安全的凭据存储类。

    凭据存储在进程内存中，而不是环境变量，
    避免通过 /proc/<pid>/environ 暴露。
    """
    _credentials: Dict[str, str] = {}
    _lock = threading.Lock()

    @classmethod
    def set(cls, key: str, value: str) -> None:
        """设置凭据"""
        with cls._lock:
            cls._credentials[key] = value

    @classmethod
    def get(cls, key: str, default: Optional[str] = None) -> Optional[str]:
        """获取凭据"""
        with cls._lock:
            # 优先从内存存储获取，回退到环境变量（兼容容器启动时的环境变量）
            return cls._credentials.get(key) or os.environ.get(key, default)

    @classmethod
    def delete(cls, key: str) -> None:
        """删除凭据"""
        with cls._lock:
            cls._credentials.pop(key, None)

    @classmethod
    def clear(cls) -> None:
        """清除所有凭据"""
        with cls._lock:
            cls._credentials.clear()

    @classmethod
    def has(cls, key: str) -> bool:
        """检查凭据是否存在"""
        with cls._lock:
            return bool(cls._credentials.get(key) or os.environ.get(key))

    @classmethod
    def get_env_for_subprocess(cls) -> Dict[str, str]:
        """
        获取用于 subprocess 的环境变量字典。
        将内存中的凭据合并到环境变量中供子进程使用。
        """
        env = os.environ.copy()
        with cls._lock:
            env.update(cls._credentials)
        return env


# 便捷访问函数
def get_pia_credentials() -> tuple[Optional[str], Optional[str]]:
    """获取 PIA 凭据"""
    return _CredentialStore.get("PIA_USERNAME"), _CredentialStore.get("PIA_PASSWORD")


def set_pia_credentials(username: str, password: str) -> None:
    """设置 PIA 凭据"""
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
_RATE_LIMIT_GENERAL = 60  # 一般 API: 每分钟 60 次
_RATE_LIMIT_LOGIN = 5  # 登录 API: 每分钟 5 次
_RATE_LIMIT_WINDOW = 60  # 时间窗口（秒）


def _get_client_ip(request: Request) -> str:
    """获取客户端 IP 地址"""
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

# Peer activity cache: {ip: {"last_seen": timestamp, "rx": bytes, "tx": bytes}}
# Used to track peer online status even when no active connections exist
_peer_activity_cache: Dict[str, Dict[str, Any]] = {}
_peer_activity_lock = threading.Lock()
_PEER_ONLINE_GRACE_PERIOD = 120  # Consider peer online for 120s after last activity


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


class ProfileUpdateRequest(BaseModel):
    """更新 VPN 线路配置"""
    description: Optional[str] = None
    region_id: Optional[str] = None


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


class IngressPeerUpdateRequest(BaseModel):
    """更新入口 WireGuard peer"""
    name: Optional[str] = Field(None, description="客户端名称")


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
    """导出配置备份"""
    password: Optional[str] = Field(None, description="加密密码（可选，不填则不加密敏感数据）")
    include_pia_credentials: bool = Field(True, description="是否包含 PIA 凭证")


class BackupImportRequest(BaseModel):
    """导入配置备份"""
    data: str = Field(..., description="备份数据（JSON 字符串）")
    password: Optional[str] = Field(None, description="解密密码")
    merge_mode: str = Field("replace", description="合并模式: replace(替换) 或 merge(合并)")


# ============ V2Ray Egress/Inbound Models ============

class V2RayEgressCreateRequest(BaseModel):
    """创建 V2Ray 出口 (VMess/VLESS/Trojan)"""
    tag: str = Field(..., pattern=r"^[a-z][a-z0-9-]*$", description="出口标识符")
    description: str = Field("", description="描述")
    protocol: str = Field(..., description="协议 (vmess/vless/trojan)")
    server: str = Field(..., description="服务器地址")
    server_port: int = Field(443, ge=1, le=65535, description="服务器端口")
    # Auth
    uuid: Optional[str] = Field(None, description="UUID (VMess/VLESS)")
    password: Optional[str] = Field(None, description="密码 (Trojan)")
    # VMess specific
    security: str = Field("auto", description="VMess 加密方式")
    alter_id: int = Field(0, ge=0, description="VMess alterId")
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
    """更新 V2Ray 出口"""
    description: Optional[str] = None
    protocol: Optional[str] = None
    server: Optional[str] = None
    server_port: Optional[int] = Field(None, ge=1, le=65535)
    uuid: Optional[str] = None
    password: Optional[str] = None
    security: Optional[str] = None
    alter_id: Optional[int] = Field(None, ge=0)
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
    """解析 V2Ray URI (vmess://, vless://, trojan://)"""
    uri: str = Field(..., description="V2Ray 分享链接")


class V2RayInboundUpdateRequest(BaseModel):
    """更新 V2Ray 入口配置（使用 Xray + TUN + TPROXY 架构）"""
    protocol: str = Field("vless", description="协议 (vmess/vless/trojan)")
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
    """创建 V2Ray 用户"""
    name: str = Field(..., pattern=r"^[a-zA-Z][a-zA-Z0-9_-]*$", description="用户名")
    email: Optional[str] = Field(None, description="邮箱")
    uuid: Optional[str] = Field(None, description="UUID (VMess/VLESS，不填自动生成)")
    password: Optional[str] = Field(None, description="密码 (Trojan)")
    alter_id: int = Field(0, ge=0, description="VMess alterId")
    flow: Optional[str] = Field(None, description="VLESS flow")


class V2RayUserUpdateRequest(BaseModel):
    """更新 V2Ray 用户"""
    email: Optional[str] = None
    uuid: Optional[str] = None
    password: Optional[str] = None
    alter_id: Optional[int] = Field(None, ge=0)
    flow: Optional[str] = None
    enabled: Optional[int] = Field(None, ge=0, le=1)


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
}


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

        # 公开端点不需要认证
        if path in PUBLIC_PATHS:
            return await call_next(request)

        # 非 API 端点（前端静态文件）不需要认证
        if not path.startswith("/api/"):
            return await call_next(request)

        # 检查是否已设置密码，未设置则允许访问
        try:
            db = get_db(str(GEODATA_DB_PATH), str(USER_DB_PATH))
            if not db.user.is_admin_setup():
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
        secret = db.user.get_or_create_jwt_secret()

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
            db = get_db(str(GEODATA_DB_PATH), str(USER_DB_PATH))

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

            # 从路由规则中获取出口（包括协议规则、端口规则等）
            for rule in db.get_routing_rules():
                outbound = rule.get("outbound")
                if outbound and outbound not in outbounds:
                    outbounds.append(outbound)
        except Exception:
            pass

    return outbounds


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
            db = get_db(GEODATA_DB_PATH, USER_DB_PATH)
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
            db = get_db(GEODATA_DB_PATH, USER_DB_PATH)
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
                    all_outbounds = _get_all_outbounds()
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

        except Exception as e:
            # M5 修复: 使用 logging 而不是 print，记录完整异常信息
            logging.exception(f"Traffic stats thread error: {type(e).__name__}: {e}")

        time.sleep(_POLL_INTERVAL)


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
            db = get_db(str(GEODATA_DB_PATH), str(USER_DB_PATH))
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

    db = get_db(str(GEODATA_DB_PATH), str(USER_DB_PATH))
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
            db = get_db(str(GEODATA_DB_PATH), str(USER_DB_PATH))
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
        db = get_db(str(GEODATA_DB_PATH), str(USER_DB_PATH))
        is_setup = db.user.is_admin_setup()
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
    db = get_db(str(GEODATA_DB_PATH), str(USER_DB_PATH))

    if db.user.is_admin_setup():
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
    db.user.set_admin_password(password_hash)

    # 创建并返回 token
    secret = db.user.get_or_create_jwt_secret()
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
    db = get_db(str(GEODATA_DB_PATH), str(USER_DB_PATH))

    if not db.user.is_admin_setup():
        raise HTTPException(
            status_code=400,
            detail="Admin password not set, use /api/auth/setup first"
        )

    password_hash = db.user.get_admin_password_hash()
    if not password_hash or not _verify_password(request.password, password_hash):
        raise HTTPException(
            status_code=401,
            detail="Invalid credentials"
        )

    secret = db.user.get_or_create_jwt_secret()
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
    db = get_db(str(GEODATA_DB_PATH), str(USER_DB_PATH))
    secret = db.user.get_or_create_jwt_secret()
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
            db = get_db(str(GEODATA_DB_PATH), str(USER_DB_PATH))
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
    db = get_db(str(GEODATA_DB_PATH), str(USER_DB_PATH))
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
        db = get_db(str(GEODATA_DB_PATH), str(USER_DB_PATH))
        peers = db.get_wireguard_peers()
        stats["total_clients"] = len(peers) if peers else 0
    except Exception:
        pass

    # 使用缓存的子网前缀（避免频繁数据库查询）
    wg_subnet_prefix = get_cached_wg_subnet_prefix()

    # 从 clash_api 获取活跃连接数和在线客户端
    try:
        with urllib.request.urlopen("http://127.0.0.1:9090/connections", timeout=2) as resp:
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

    # 从 sing-box 日志文件统计广告拦截
    # 使用专用的 adblock 出口，日志格式: outbound/block[adblock]: blocked connection to x.x.x.x:443
    try:
        log_file = Path("/var/log/sing-box.log")
        if log_file.exists():
            with open(log_file, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    if "outbound/block[adblock]: blocked connection" in line:
                        stats["adblock_connections"] += 1
    except Exception:
        pass

    return stats


@app.get("/api/endpoints")
def api_list_endpoints():
    """从数据库获取所有端点配置"""
    if not HAS_DATABASE or not USER_DB_PATH.exists():
        raise HTTPException(status_code=500, detail="Database not available")

    db = get_db(str(GEODATA_DB_PATH), str(USER_DB_PATH))
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

    db = get_db(str(GEODATA_DB_PATH), str(USER_DB_PATH))

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

    db = get_db(str(GEODATA_DB_PATH), str(USER_DB_PATH))
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
        db = get_db(str(GEODATA_DB_PATH), str(USER_DB_PATH))
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
            "dns_strategy": p.get("dns_strategy", "direct-dns"),
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

    db = get_db(str(GEODATA_DB_PATH), str(USER_DB_PATH))

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
        dns_strategy="direct-dns"
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

    db = get_db(str(GEODATA_DB_PATH), str(USER_DB_PATH))
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
        region_id=payload.region_id
    )
    return {"message": f"线路 {tag} 更新成功"}


@app.delete("/api/profiles/{tag}")
def api_delete_profile(tag: str):
    """删除 VPN 线路（数据库）"""
    if not HAS_DATABASE or not USER_DB_PATH.exists():
        raise HTTPException(status_code=500, detail="Database not available")

    db = get_db(str(GEODATA_DB_PATH), str(USER_DB_PATH))
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
            db = get_db(str(GEODATA_DB_PATH), str(USER_DB_PATH))
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
        db = get_db(str(GEODATA_DB_PATH), str(USER_DB_PATH))
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
        db = get_db(str(GEODATA_DB_PATH), str(USER_DB_PATH))

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

    db = get_db(str(GEODATA_DB_PATH), str(USER_DB_PATH))

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

    db = get_db(str(GEODATA_DB_PATH), str(USER_DB_PATH))
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
    db = get_db(str(GEODATA_DB_PATH), str(USER_DB_PATH))
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
        raise HTTPException(status_code=500, detail=result.get("message"))
    return result


@app.get("/api/profiles/status")
def api_profiles_status():
    """获取各 WireGuard 出口的连接状态（从数据库）"""
    # 从数据库获取 PIA profiles
    db = get_db(str(GEODATA_DB_PATH), str(USER_DB_PATH))
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
    db = get_db(str(GEODATA_DB_PATH), str(USER_DB_PATH))
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
        run_command(["python3", str(provision_script)], env=env)
        run_command(["python3", str(render_script)], env=env)
        reload_result = reload_singbox()
        # 同步内核 WireGuard 出口接口（PIA 使用 kernel WG）
        wg_sync_msg = _sync_kernel_wg_egress()
        return {
            "message": f"已重新连接 {payload.profile_tag}{wg_sync_msg}",
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
    db = get_db(str(GEODATA_DB_PATH), str(USER_DB_PATH))

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

    db = get_db(str(GEODATA_DB_PATH), str(USER_DB_PATH))

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
        db = get_db(str(GEODATA_DB_PATH), str(USER_DB_PATH))

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
    """
    global _peer_activity_cache
    import time
    peer_status = {}  # ip -> {"active": bool, "last_seen": timestamp, "rx": int, "tx": int}

    # 使用缓存的子网前缀（避免频繁数据库查询）
    wg_subnet_prefix = get_cached_wg_subnet_prefix()

    try:
        # 查询 sing-box clash_api 获取活跃连接
        import urllib.request
        with urllib.request.urlopen("http://127.0.0.1:9090/connections", timeout=2) as resp:
            data = json.loads(resp.read().decode())

        now = int(time.time())
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
            start_time = conn.get("start", "")

            if src_ip not in peer_status:
                peer_status[src_ip] = {
                    "active": True,
                    "last_seen": now,
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
                    _peer_activity_cache[ip]["last_seen"] = now
                    _peer_activity_cache[ip]["rx"] = status["rx"]
                    _peer_activity_cache[ip]["tx"] = status["tx"]

    except Exception as e:
        # clash_api 不可用时静默失败
        pass

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

    使用内核 WireGuard 模式：通过 wg set 命令直接管理 peer，
    无需重载 sing-box（流量通过 TUN 入口，与 peer 管理解耦）。
    """
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
        db = get_db(str(GEODATA_DB_PATH), str(USER_DB_PATH))
        peer_id = db.add_wireguard_peer(
            name=payload.name,
            public_key=client_public_key,
            allowed_ips=f"{peer_ip}/32",
            allow_lan=payload.allow_lan,
            lan_subnet=lan_subnet
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
        db = get_db(str(GEODATA_DB_PATH), str(USER_DB_PATH))
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

    # 客户端 IP
    client_ip = peer.get("allowed_ips", [get_default_peer_ip()])[0]

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
        raise HTTPException(status_code=500, detail=result.get("message"))
    return result


class SubnetUpdateRequest(BaseModel):
    """更新入口子网"""
    address: str = Field(..., description="新的子网地址，如 10.25.0.1/24")
    migrate_peers: bool = Field(True, description="是否自动迁移现有客户端 IP 到新子网")


@app.get("/api/ingress/subnet")
def api_get_ingress_subnet():
    """获取入口子网配置"""
    import ipaddress
    db = get_db(str(GEODATA_DB_PATH), str(USER_DB_PATH))
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
    db = get_db(str(GEODATA_DB_PATH), str(USER_DB_PATH))
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


# ============ Settings APIs ============

class SettingsUpdateRequest(BaseModel):
    """更新系统设置"""
    server_endpoint: Optional[str] = Field(None, description="服务器公网地址，如 1.2.3.4 或 vpn.example.com")


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
    db = get_db(str(GEODATA_DB_PATH), str(USER_DB_PATH))
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
            "socks_port": eg.get("socks_port"),
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
    db = get_db(str(GEODATA_DB_PATH), str(USER_DB_PATH))

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

    db = get_db(str(GEODATA_DB_PATH), str(USER_DB_PATH))
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
    db = get_db(str(GEODATA_DB_PATH), str(USER_DB_PATH))
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
    db = get_db(str(GEODATA_DB_PATH), str(USER_DB_PATH))

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
    db = get_db(str(GEODATA_DB_PATH), str(USER_DB_PATH))

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
    db = get_db(str(GEODATA_DB_PATH), str(USER_DB_PATH))

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
    db = get_db(str(GEODATA_DB_PATH), str(USER_DB_PATH))
    egress_list = db.get_direct_egress_list(enabled_only=False)
    return {"egress": egress_list}


@app.get("/api/egress/direct/{tag}")
def api_get_direct_egress(tag: str):
    """获取单个 direct 出口"""
    db = get_db(str(GEODATA_DB_PATH), str(USER_DB_PATH))
    egress = db.get_direct_egress(tag)
    if not egress:
        raise HTTPException(status_code=404, detail=f"Direct 出口 '{tag}' 不存在")
    return egress


@app.post("/api/egress/direct")
def api_create_direct_egress(payload: DirectEgressCreateRequest):
    """创建 direct 出口"""
    db = get_db(str(GEODATA_DB_PATH), str(USER_DB_PATH))

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
    db = get_db(str(GEODATA_DB_PATH), str(USER_DB_PATH))

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
    db = get_db(str(GEODATA_DB_PATH), str(USER_DB_PATH))

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
    db = get_db(str(GEODATA_DB_PATH), str(USER_DB_PATH))
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
    db = get_db(str(GEODATA_DB_PATH), str(USER_DB_PATH))
    egress = db.get_openvpn_egress(tag)
    if not egress:
        raise HTTPException(status_code=404, detail=f"OpenVPN 出口 '{tag}' 不存在")
    return egress


@app.post("/api/egress/openvpn")
def api_create_openvpn_egress(payload: OpenVPNEgressCreateRequest):
    """创建 OpenVPN 出口"""
    db = get_db(str(GEODATA_DB_PATH), str(USER_DB_PATH))

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

    # 获取分配的 SOCKS 端口
    egress = db.get_openvpn_egress(payload.tag)
    socks_port = egress.get("socks_port") if egress else None

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
        "socks_port": socks_port,
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
    db = get_db(str(GEODATA_DB_PATH), str(USER_DB_PATH))

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
    db = get_db(str(GEODATA_DB_PATH), str(USER_DB_PATH))

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
    db = get_db(str(GEODATA_DB_PATH), str(USER_DB_PATH))

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
    db = get_db(str(GEODATA_DB_PATH), str(USER_DB_PATH))
    egress_list = db.get_v2ray_egress_list(enabled_only=False)
    # 隐藏敏感信息
    for egress in egress_list:
        if egress.get("password"):
            egress["password"] = "***"
    return {"egress": egress_list}


@app.get("/api/egress/v2ray/{tag}")
def api_get_v2ray_egress(tag: str):
    """获取单个 V2Ray 出口（包含完整配置）"""
    db = get_db(str(GEODATA_DB_PATH), str(USER_DB_PATH))
    egress = db.get_v2ray_egress(tag)
    if not egress:
        raise HTTPException(status_code=404, detail=f"V2Ray egress '{tag}' not found")
    return egress


@app.post("/api/egress/v2ray")
def api_create_v2ray_egress(payload: V2RayEgressCreateRequest):
    """创建 V2Ray 出口"""
    db = get_db(str(GEODATA_DB_PATH), str(USER_DB_PATH))

    # 验证协议
    if payload.protocol not in ("vmess", "vless", "trojan"):
        raise HTTPException(status_code=400, detail=f"Invalid protocol: {payload.protocol}")

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

    # 验证认证信息
    if payload.protocol in ("vmess", "vless") and not payload.uuid:
        raise HTTPException(status_code=400, detail=f"{payload.protocol.upper()} requires UUID")
    if payload.protocol == "trojan" and not payload.password:
        raise HTTPException(status_code=400, detail="Trojan requires password")

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
    db = get_db(str(GEODATA_DB_PATH), str(USER_DB_PATH))

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
    db = get_db(str(GEODATA_DB_PATH), str(USER_DB_PATH))

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


# ============ V2Ray Inbound APIs ============

@app.get("/api/ingress/v2ray")
def api_get_v2ray_inbound():
    """获取 V2Ray 入口配置和用户列表"""
    db = get_db(str(GEODATA_DB_PATH), str(USER_DB_PATH))

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
    """更新 V2Ray 入口配置（使用 Xray + TUN + TPROXY 架构）"""
    db = get_db(str(GEODATA_DB_PATH), str(USER_DB_PATH))

    # 验证协议
    if payload.protocol not in ("vmess", "vless", "trojan"):
        raise HTTPException(status_code=400, detail=f"Invalid protocol: {payload.protocol}")

    # XTLS-Vision 只支持 VLESS
    if payload.xtls_vision_enabled and payload.protocol != "vless":
        raise HTTPException(status_code=400, detail="XTLS-Vision is only available for VLESS protocol")

    # REALITY 只支持 VLESS
    if payload.reality_enabled and payload.protocol != "vless":
        raise HTTPException(status_code=400, detail="REALITY is only available for VLESS protocol")

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
    db = get_db(str(GEODATA_DB_PATH), str(USER_DB_PATH))
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

    db = get_db(str(GEODATA_DB_PATH), str(USER_DB_PATH))

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
    db = get_db(str(GEODATA_DB_PATH), str(USER_DB_PATH))

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
    db = get_db(str(GEODATA_DB_PATH), str(USER_DB_PATH))

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

    db = get_db(str(GEODATA_DB_PATH), str(USER_DB_PATH))

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

    # 构建分享链接
    if protocol == "vmess":
        share_config["uuid"] = user.get("uuid")
        share_config["alter_id"] = user.get("alter_id", 0)
        share_config["security"] = user.get("security", "auto")
        uri = generate_vmess_uri(share_config)
    elif protocol == "vless":
        share_config["uuid"] = user.get("uuid")
        # Flow 从服务端配置获取，不再从用户配置获取
        share_config["flow"] = server_flow
        uri = generate_vless_uri(share_config)
    elif protocol == "trojan":
        share_config["password"] = user.get("password")
        uri = generate_trojan_uri(share_config)
    else:
        raise HTTPException(status_code=400, detail=f"Unsupported protocol: {protocol}")

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
            _db = get_db(str(GEODATA_DB_PATH), str(USER_DB_PATH))
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


@app.post("/api/ingress/v2ray/reality/generate-keys")
def api_generate_reality_keys():
    """生成 REALITY 密钥对"""
    import subprocess
    try:
        result = subprocess.run(
            ["python3", "/usr/local/bin/xray_manager.py", "generate-keys"],
            capture_output=True, text=True, timeout=10
        )
        if result.returncode == 0:
            keys = json.loads(result.stdout)
            return keys
        else:
            # 尝试解析错误信息
            try:
                error = json.loads(result.stderr)
                raise HTTPException(status_code=500, detail=error.get("error", "Unknown error"))
            except json.JSONDecodeError:
                raise HTTPException(status_code=500, detail=f"Failed to generate keys: {result.stderr}")
    except subprocess.TimeoutExpired:
        raise HTTPException(status_code=500, detail="Key generation timeout")
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


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
        clash_proxy_url = f"http://127.0.0.1:9090/proxies/{urllib.parse.quote(tag)}"
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
        if tag.startswith("direct-") and HAS_DATABASE:
            db = get_db(GEODATA_DB_PATH, USER_DB_PATH)
            direct_egress = db.get_direct_egress_by_tag(tag)
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
    """使用 curl + SOCKS 代理测试 SOCKS 类型出口"""
    try:
        # 从数据库获取 SOCKS 端口
        socks_port = None
        if HAS_DATABASE:
            db = get_db(GEODATA_DB_PATH, USER_DB_PATH)
            openvpn_egress = db.get_openvpn_egress(tag)
            if openvpn_egress:
                socks_port = openvpn_egress.get("socks_port")

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
        with urllib.request.urlopen("http://127.0.0.1:9090/connections", timeout=3) as resp:
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
        clash_url = f"http://127.0.0.1:9090/proxies/{urllib.parse.quote(tag)}/delay?url={urllib.parse.quote(test_url)}&timeout={timeout}"
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
        db = get_db(GEODATA_DB_PATH, USER_DB_PATH)
        egress = db.get_openvpn_egress(tag)
        return egress is not None
    except Exception:
        return False


def _get_openvpn_socks_port(tag: str) -> Optional[int]:
    """获取 OpenVPN 出口的 SOCKS 端口（仅当端口正在监听时返回）"""
    if not HAS_DATABASE:
        return None
    try:
        db = get_db(GEODATA_DB_PATH, USER_DB_PATH)
        egress = db.get_openvpn_egress(tag)
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
        if HAS_DATABASE:
            db = get_db(GEODATA_DB_PATH, USER_DB_PATH)
            direct_egress = db.get_direct_egress_by_tag(tag)
            if direct_egress:
                if direct_egress.get("bind_interface"):
                    curl_cmd.extend(["--interface", direct_egress["bind_interface"]])
                    proxy_info = f"接口 {direct_egress['bind_interface']}"
                elif direct_egress.get("inet4_bind_address"):
                    curl_cmd.extend(["--interface", direct_egress["inet4_bind_address"]])
                    proxy_info = f"IP {direct_egress['inet4_bind_address']}"
    elif _is_openvpn_egress(tag):
        # OpenVPN：使用已有 SOCKS 端口
        socks_port = _get_openvpn_socks_port(tag)
        if socks_port:
            curl_cmd.extend(["--proxy", f"socks5://127.0.0.1:{socks_port}"])
            proxy_info = f"SOCKS5 :{socks_port}"
        else:
            return {"success": False, "speed_mbps": 0, "message": "OpenVPN tunnel not connected"}
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
    db = get_db(str(GEODATA_DB_PATH), str(USER_DB_PATH))
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
    db = get_db(str(GEODATA_DB_PATH), str(USER_DB_PATH))
    rule = db.get_remote_rule_set(tag)
    if not rule:
        raise HTTPException(status_code=404, detail=f"规则集 '{tag}' 不存在")
    return rule


@app.put("/api/adblock/rules/{tag}/toggle")
def api_toggle_adblock_rule(tag: str):
    """切换广告拦截规则集启用状态"""
    db = get_db(str(GEODATA_DB_PATH), str(USER_DB_PATH))

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
    db = get_db(str(GEODATA_DB_PATH), str(USER_DB_PATH))

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
    db = get_db(str(GEODATA_DB_PATH), str(USER_DB_PATH))

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
    db = get_db(str(GEODATA_DB_PATH), str(USER_DB_PATH))

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
    """重载 OpenVPN 管理器守护进程（同步数据库变更）

    通过 SIGHUP 信号通知守护进程重载配置，避免创建新进程导致状态丢失。

    Returns:
        状态消息
    """
    import signal as sig_module

    pid_file = Path("/run/openvpn-manager.pid")

    if not pid_file.exists():
        print("[api] OpenVPN manager not running (no PID file)")
        return ""

    try:
        daemon_pid = int(pid_file.read_text().strip())
        os.kill(daemon_pid, sig_module.SIGHUP)
        print(f"[api] Sent SIGHUP to OpenVPN manager (PID: {daemon_pid})")
        return ", OpenVPN manager reloaded"
    except ValueError:
        print("[api] Invalid PID file content")
        return ""
    except ProcessLookupError:
        print("[api] OpenVPN manager process not found, removing stale PID file")
        pid_file.unlink(missing_ok=True)
        return ""
    except PermissionError:
        print("[api] Permission denied sending signal to OpenVPN manager")
        return ""
    except Exception as e:
        print(f"[api] OpenVPN manager reload error: {e}")
        return ""


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
            print(f"[api] WireGuard sync failed: {result.stderr.strip()}")
            return ", WireGuard sync failed"
    except subprocess.TimeoutExpired:
        print("[api] WireGuard sync timeout")
        return ", WireGuard sync timeout"
    except Exception as e:
        print(f"[api] WireGuard sync error: {e}")
        return ""


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
            print(f"[api] WireGuard ingress sync failed: {result.stderr.strip()}")
            return ", WireGuard ingress sync failed"
    except subprocess.TimeoutExpired:
        print("[api] WireGuard ingress sync timeout")
        return ", WireGuard ingress sync timeout"
    except Exception as e:
        print(f"[api] WireGuard ingress sync error: {e}")
        return ""


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

    db = get_db(str(GEODATA_DB_PATH), str(USER_DB_PATH))

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
        db = get_db(str(GEODATA_DB_PATH), str(USER_DB_PATH))

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
        db = get_db(str(GEODATA_DB_PATH), str(USER_DB_PATH))

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

    db = get_db(str(GEODATA_DB_PATH), str(USER_DB_PATH))

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

BACKUP_VERSION = "1.0"


@app.post("/api/backup/export")
def api_export_backup(payload: BackupExportRequest):
    """导出配置备份"""
    backup_data = {
        "version": BACKUP_VERSION,
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
    db = get_db(str(GEODATA_DB_PATH), str(USER_DB_PATH))
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
            "dns_strategy": p.get("dns_strategy", "direct-dns"),
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
        db = get_db(str(GEODATA_DB_PATH), str(USER_DB_PATH))
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
    """导入配置备份"""
    try:
        backup_data = json.loads(payload.data)
    except json.JSONDecodeError as exc:
        raise HTTPException(status_code=400, detail=f"无效的备份数据格式: {exc}") from exc

    # 验证备份格式
    if backup_data.get("type") != "vpn-gateway-backup":
        raise HTTPException(status_code=400, detail="无效的备份文件类型")

    version = backup_data.get("version", "")
    if not version:
        raise HTTPException(status_code=400, detail="备份文件缺少版本信息")

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
            db = get_db(str(GEODATA_DB_PATH), str(USER_DB_PATH))
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
            db = get_db(str(GEODATA_DB_PATH), str(USER_DB_PATH))

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
                        dns_strategy=p.get("dns_strategy", "direct-dns")
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
                db = get_db(str(GEODATA_DB_PATH), str(USER_DB_PATH))

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
            db = get_db(str(GEODATA_DB_PATH), str(USER_DB_PATH))

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
            for eg in backup_data["v2ray_egress"]:
                tag = eg.get("tag", "")
                if tag and tag not in existing_tags:
                    sens = sensitive_by_tag.get(tag, {})
                    db.add_v2ray_egress(
                        tag=tag,
                        protocol=eg.get("protocol", "vless"),
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
            db = get_db(str(GEODATA_DB_PATH), str(USER_DB_PATH))
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
            db = get_db(str(GEODATA_DB_PATH), str(USER_DB_PATH))

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

    # 重新生成配置
    reload_status = ""
    try:
        _regenerate_and_reload()
        reload_status = "，已重载配置"
    except Exception as exc:
        print(f"[backup] 重载配置失败: {exc}")
        reload_status = f"，重载失败: {exc}"

    imported_count = sum(1 for v in results.values() if v)
    return {
        "message": f"已导入 {imported_count} 项配置{reload_status}",
        "results": results,
    }


@app.get("/api/backup/status")
def api_backup_status():
    """获取备份相关状态"""
    ingress = load_ingress_config()
    settings = load_settings()

    # 从数据库获取数据
    db = get_db(str(GEODATA_DB_PATH), str(USER_DB_PATH))
    pia_profiles = db.get_pia_profiles(enabled_only=False)
    custom_egress = db.get_custom_egress_list()

    return {
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

    db = get_db(str(GEODATA_DB_PATH), str(USER_DB_PATH))
    return db.get_statistics()


@app.get("/api/db/rules")
def api_get_db_rules(enabled_only: bool = True):
    """获取数据库中的所有路由规则"""
    if not HAS_DATABASE or not USER_DB_PATH.exists():
        raise HTTPException(status_code=503, detail="数据库不可用")

    db = get_db(str(GEODATA_DB_PATH), str(USER_DB_PATH))
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

    db = get_db(str(GEODATA_DB_PATH), str(USER_DB_PATH))
    success = db.update_routing_rule(rule_id, outbound, priority, enabled)

    if not success:
        raise HTTPException(status_code=404, detail=f"规则 ID {rule_id} 不存在")

    return {"message": f"规则 ID {rule_id} 已更新"}


# Legacy /api/db/* endpoints removed - GeoIP data now served from JSON catalogs via /api/ip-catalog
# Domain data served from JSON catalog via /api/domain-catalog


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


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        "api_server:app",
        host=os.environ.get("API_HOST", "0.0.0.0"),
        port=int(os.environ.get("API_PORT", "8000")),
        reload=False,
        factory=False,
    )

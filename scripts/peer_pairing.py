#!/usr/bin/env python3
"""离线配对系统

支持空气隔离部署的 base64 配对码方案。

配对流程：
1. A 节点生成请求码（包含本节点完整信息）
2. B 节点导入请求码 → 自动创建 peer_node → 生成响应码
3. A 节点导入响应码 → 自动创建 peer_node → 配对完成
4. 双方可建立隧道连接

配对码格式（JSON + base64）：
- pair_request: 请求码，包含发起方信息
- pair_response: 响应码，包含接收方信息和分配的隧道参数
"""

import base64
import hashlib
import json
import logging
import os
import re
import secrets
import sqlite3
import subprocess
import time
from dataclasses import dataclass
from typing import Optional, Dict, Any, Tuple

# Default Web API port (configurable via environment)
DEFAULT_WEB_PORT = int(os.environ.get("WEB_PORT", "36000"))

# 配对码版本
PAIRING_VERSION = 1

# 配对码过期时间（秒）- 7 天
PAIRING_CODE_TTL = 7 * 24 * 60 * 60

# ============================================
# 安全验证常量（修复 Phase 2 审查发现的问题）
# ============================================

# 配对码最大长度（16KB）- 防止内存/CPU 耗尽攻击
MAX_PAIRING_CODE_SIZE = 16384

# node_tag 格式验证：小写字母开头，后跟小写字母/数字/连字符，最长 63 字符
TAG_PATTERN = re.compile(r'^[a-z][a-z0-9-]{0,62}$')

# WireGuard 公钥格式：base64 编码的 32 字节 Curve25519 密钥（44 字符含 padding）
WG_KEY_PATTERN = re.compile(r'^[A-Za-z0-9+/]{43}=$')

# Xray REALITY X25519 公钥格式：base64url 编码（无 padding）
XRAY_X25519_PATTERN = re.compile(r'^[A-Za-z0-9_-]{43}$')

# REALITY Short ID 格式：1-16 位十六进制字符
XRAY_SHORT_ID_PATTERN = re.compile(r'^[0-9a-fA-F]{1,16}$')

# 时间戳允许的未来偏移（秒）- 允许 5 分钟时钟偏差
MAX_TIMESTAMP_FUTURE_OFFSET = 300

# 隧道 IP 基础网段
TUNNEL_IP_BASE = "10.200.200"

# Phase 6: 隧道端口范围（支持环境变量配置）
TUNNEL_PORT_BASE = int(os.environ.get("PEER_TUNNEL_PORT_MIN", "36200"))
TUNNEL_PORT_MAX = int(os.environ.get("PEER_TUNNEL_PORT_MAX", "36299"))

# 节点描述最大长度
MAX_DESCRIPTION_LENGTH = 256

# Issue 15: 隧道 IP 验证网段
TUNNEL_IP_SUBNET = "10.200.200.0/24"


def _validate_tunnel_ip_in_subnet(ip: str, subnet: str = TUNNEL_IP_SUBNET) -> bool:
    """
    验证隧道 IP 是否在预期范围内。

    Issue 15 修复：在导入配对信息时验证隧道 IP 地址合法性，
    确保 IP 在 10.200.200.0/24 范围内。

    Args:
        ip: 要验证的 IP 地址
        subnet: 预期的子网范围

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


@dataclass
class PairingRequest:
    """配对请求数据"""
    type: str  # "pair_request"
    version: int
    node_tag: str
    node_description: str
    endpoint: str  # IP:port 格式 (WireGuard 端口)
    tunnel_type: str  # "wireguard" 或 "xray"

    # Phase 11-Fix.K: API 端口（用于通过外部 IP 访问 API）
    # endpoint 包含 WireGuard 端口，api_port 是 Web API 端口（默认 36000）
    api_port: Optional[int] = None

    # PSK 认证（已废弃 - WireGuard 用 IP 认证，Xray 用 UUID 认证）
    psk_hash: str = ""  # 保留兼容，不再使用

    # WireGuard 参数
    wg_public_key: Optional[str] = None

    # Xray REALITY 参数
    xray_reality_public_key: Optional[str] = None
    xray_reality_short_id: Optional[str] = None

    # Phase 11.2: 双向自动连接参数
    # 预生成的密钥对，用于远程节点直接使用（无需密钥交换）
    # 注意：request code 包含私钥，必须保密处理！
    remote_wg_private_key: Optional[str] = None  # 为远程节点预生成的私钥
    remote_wg_public_key: Optional[str] = None  # 对应的公钥
    bidirectional: bool = True  # 是否启用双向连接

    # Phase 11-Tunnel: 隧道 IP 信息（用于隧道优先配对）
    # 在配对码中包含 IP，确保双方使用一致的地址
    tunnel_local_ip: Optional[str] = None  # 生成方的隧道 IP
    tunnel_remote_ip: Optional[str] = None  # 为远程节点预分配的 IP

    # 时间戳
    timestamp: int = 0

    def to_dict(self) -> Dict[str, Any]:
        """转换为字典"""
        d = {
            "type": self.type,
            "version": self.version,
            "node_tag": self.node_tag,
            "node_description": self.node_description,
            "endpoint": self.endpoint,
            "tunnel_type": self.tunnel_type,
            "psk_hash": self.psk_hash,
            "timestamp": self.timestamp,
            "bidirectional": self.bidirectional,
        }
        if self.wg_public_key:
            d["wg_public_key"] = self.wg_public_key
        if self.xray_reality_public_key:
            d["xray_reality_public_key"] = self.xray_reality_public_key
        if self.xray_reality_short_id:
            d["xray_reality_short_id"] = self.xray_reality_short_id
        # Phase 11.2: 双向自动连接密钥（需保密！）
        if self.remote_wg_private_key:
            d["remote_wg_private_key"] = self.remote_wg_private_key
        if self.remote_wg_public_key:
            d["remote_wg_public_key"] = self.remote_wg_public_key
        # Phase 11-Tunnel: 隧道 IP
        if self.tunnel_local_ip:
            d["tunnel_local_ip"] = self.tunnel_local_ip
        if self.tunnel_remote_ip:
            d["tunnel_remote_ip"] = self.tunnel_remote_ip
        # Phase 11-Fix.K: API 端口
        if self.api_port:
            d["api_port"] = self.api_port
        return d

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "PairingRequest":
        """从字典创建"""
        return cls(
            type=d.get("type", "pair_request"),
            version=d.get("version", PAIRING_VERSION),
            node_tag=d["node_tag"],
            node_description=d.get("node_description", ""),
            endpoint=d["endpoint"],
            tunnel_type=d["tunnel_type"],
            api_port=d.get("api_port"),  # Phase 11-Fix.K
            psk_hash=d.get("psk_hash", ""),  # 已废弃，兼容旧配对码
            wg_public_key=d.get("wg_public_key"),
            xray_reality_public_key=d.get("xray_reality_public_key"),
            xray_reality_short_id=d.get("xray_reality_short_id"),
            remote_wg_private_key=d.get("remote_wg_private_key"),
            remote_wg_public_key=d.get("remote_wg_public_key"),
            bidirectional=d.get("bidirectional", True),
            tunnel_local_ip=d.get("tunnel_local_ip"),
            tunnel_remote_ip=d.get("tunnel_remote_ip"),
            timestamp=d.get("timestamp", 0),
        )


@dataclass
class PairingResponse:
    """配对响应数据"""
    type: str  # "pair_response"
    version: int
    request_node_tag: str  # 请求方的 tag
    node_tag: str  # 本节点 tag
    node_description: str
    endpoint: str  # IP:port 格式 (WireGuard 端口)

    # 分配的隧道参数（必需字段）
    tunnel_local_ip: str  # 分配给请求方的 IP
    tunnel_remote_ip: str  # 本节点的隧道 IP

    # Phase 11-Fix.K: API 端口（用于通过外部 IP 访问 API）
    api_port: Optional[int] = None

    # PSK 认证（已废弃 - WireGuard 用 IP 认证，Xray 用 UUID 认证）
    psk_hash: str = ""  # 保留兼容，不再使用

    # WireGuard 参数
    wg_public_key: Optional[str] = None

    # Xray REALITY 参数
    xray_reality_public_key: Optional[str] = None
    xray_reality_short_id: Optional[str] = None
    xray_uuid: Optional[str] = None  # Phase 11-Fix.Xray: UUID for inbound authentication

    # 隧道 API 端点
    tunnel_api_endpoint: Optional[str] = None

    # 时间戳
    timestamp: int = 0

    def to_dict(self) -> Dict[str, Any]:
        """转换为字典"""
        d = {
            "type": self.type,
            "version": self.version,
            "request_node_tag": self.request_node_tag,
            "node_tag": self.node_tag,
            "node_description": self.node_description,
            "endpoint": self.endpoint,
            "psk_hash": self.psk_hash,
            "tunnel_local_ip": self.tunnel_local_ip,
            "tunnel_remote_ip": self.tunnel_remote_ip,
            "timestamp": self.timestamp,
        }
        if self.wg_public_key:
            d["wg_public_key"] = self.wg_public_key
        if self.xray_reality_public_key:
            d["xray_reality_public_key"] = self.xray_reality_public_key
        if self.xray_reality_short_id:
            d["xray_reality_short_id"] = self.xray_reality_short_id
        if self.xray_uuid:
            d["xray_uuid"] = self.xray_uuid
        if self.tunnel_api_endpoint:
            d["tunnel_api_endpoint"] = self.tunnel_api_endpoint
        # Phase 11-Fix.K: API 端口
        if self.api_port:
            d["api_port"] = self.api_port
        return d

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "PairingResponse":
        """从字典创建"""
        return cls(
            type=d.get("type", "pair_response"),
            version=d.get("version", PAIRING_VERSION),
            request_node_tag=d["request_node_tag"],
            node_tag=d["node_tag"],
            node_description=d.get("node_description", ""),
            endpoint=d["endpoint"],
            api_port=d.get("api_port"),  # Phase 11-Fix.K
            psk_hash=d.get("psk_hash", ""),  # 已废弃，兼容旧配对码
            tunnel_local_ip=d["tunnel_local_ip"],
            tunnel_remote_ip=d["tunnel_remote_ip"],
            wg_public_key=d.get("wg_public_key"),
            xray_reality_public_key=d.get("xray_reality_public_key"),
            xray_reality_short_id=d.get("xray_reality_short_id"),
            xray_uuid=d.get("xray_uuid"),  # Phase 11-Fix.Xray: UUID for inbound auth
            tunnel_api_endpoint=d.get("tunnel_api_endpoint"),
            timestamp=d.get("timestamp", 0),
        )


class PairingCodeGenerator:
    """配对码生成器"""

    def __init__(self, db):
        """
        Args:
            db: DatabaseManager 实例
        """
        self.db = db

    # NOTE: generate_psk(), hash_psk(), verify_psk() methods have been removed.
    # PSK authentication is deprecated. Use tunnel IP authentication (WireGuard) or UUID authentication (Xray).

    def generate_wireguard_keypair(self) -> Tuple[str, str]:
        """生成 WireGuard 密钥对

        Returns:
            (private_key, public_key)
        """
        try:
            # 生成私钥
            result = subprocess.run(
                ["wg", "genkey"],
                capture_output=True,
                text=True,
                check=True
            )
            private_key = result.stdout.strip()

            # 从私钥派生公钥
            result = subprocess.run(
                ["wg", "pubkey"],
                input=private_key,
                capture_output=True,
                text=True,
                check=True
            )
            public_key = result.stdout.strip()

            return private_key, public_key
        except Exception as e:
            logging.error(f"[pairing] 生成 WireGuard 密钥对失败: {e}")
            raise

    def generate_xray_reality_keypair(self) -> Tuple[str, str]:
        """生成 Xray REALITY X25519 密钥对

        Returns:
            (private_key, public_key)
        """
        try:
            result = subprocess.run(
                ["xray", "x25519"],
                capture_output=True,
                text=True,
                check=True
            )
            output = result.stdout.strip()

            # 解析输出格式 - 支持新旧两种格式：
            # 旧格式 (Xray < 25.x):
            #   Private key: xxx
            #   Public key: xxx
            # 新格式 (Xray 25.x+):
            #   PrivateKey: xxx
            #   Password: xxx  (这实际是 public key)
            #   Hash32: xxx
            lines = output.split('\n')
            private_key = None
            public_key = None

            for line in lines:
                # 支持旧格式
                if line.startswith("Private key:"):
                    private_key = line.split(":", 1)[1].strip()
                elif line.startswith("Public key:"):
                    public_key = line.split(":", 1)[1].strip()
                # 支持新格式 (Xray 25.x+)
                elif line.startswith("PrivateKey:"):
                    private_key = line.split(":", 1)[1].strip()
                elif line.startswith("Password:"):
                    # 新版 Xray 中 "Password" 字段实际是 public key
                    public_key = line.split(":", 1)[1].strip()

            if not private_key or not public_key:
                logging.error(f"[pairing] xray x25519 输出解析失败，原始输出: {output}")
                raise ValueError("Failed to parse xray x25519 output")

            return private_key, public_key
        except Exception as e:
            logging.error(f"[pairing] 生成 Xray REALITY 密钥对失败: {e}")
            raise

    def generate_short_id(self) -> str:
        """生成 REALITY Short ID"""
        return secrets.token_hex(4)

    def encode_pairing_code(self, data: Dict[str, Any]) -> str:
        """将数据编码为 base64 配对码"""
        json_str = json.dumps(data, ensure_ascii=False, separators=(',', ':'))
        return base64.urlsafe_b64encode(json_str.encode('utf-8')).decode('ascii')

    def decode_pairing_code(self, code: str) -> Dict[str, Any]:
        """解码 base64 配对码

        Raises:
            ValueError: 无效的配对码
        """
        try:
            # 清理可能的空白字符
            code = code.strip()

            # 安全检查：配对码大小限制（防止 DoS 攻击）
            if len(code) > MAX_PAIRING_CODE_SIZE:
                raise ValueError(f"Pairing code too large: {len(code)} > {MAX_PAIRING_CODE_SIZE}")

            # base64 解码
            json_str = base64.urlsafe_b64decode(code).decode('utf-8')
            # JSON 解析
            return json.loads(json_str)
        except ValueError:
            # 重新抛出 ValueError（包括我们自己的大小检查错误）
            raise
        except Exception as e:
            raise ValueError(f"Invalid pairing code: {e}")

    def generate_pair_request(
        self,
        node_tag: str,
        node_description: str,
        endpoint: str,
        tunnel_type: str = "wireguard",
        psk: Optional[str] = None,  # 已废弃，保留兼容
        bidirectional: bool = True,
        tunnel_local_ip: Optional[str] = None,  # Phase 11-Tunnel
        tunnel_remote_ip: Optional[str] = None,  # Phase 11-Tunnel
        api_port: Optional[int] = None,  # Phase 11-Fix.K: API 端口
    ) -> Tuple[str, str, "PairingRequest"]:
        """生成配对请求码

        Args:
            node_tag: 本节点标识
            node_description: 节点描述
            endpoint: 隧道端点 (IP:port)
            tunnel_type: 隧道类型 ("wireguard" 或 "xray")
            psk: [已废弃] 不再使用，保留参数兼容
            bidirectional: 是否启用双向自动连接 (Phase 11.2)
            tunnel_local_ip: 本节点隧道 IP (Phase 11-Tunnel)
            tunnel_remote_ip: 为远程节点预分配的隧道 IP (Phase 11-Tunnel)
            api_port: 本节点 API 端口 (Phase 11-Fix.K)

        Returns:
            (pairing_code, "", request) - 配对码、空字符串（兼容）和请求对象
        """
        # PSK 已废弃 - WireGuard 用 IP 认证，Xray 用 UUID 认证
        # 保留空值兼容旧版本

        # Phase 12-Fix.F: 分配本地监听端口，并用它构造 endpoint
        # 这样响应方才知道连接到哪个端口
        tunnel_port = self.get_next_tunnel_port()
        endpoint_ip = endpoint.rsplit(":", 1)[0] if ":" in endpoint else endpoint
        request_endpoint = f"{endpoint_ip}:{tunnel_port}"

        request = PairingRequest(
            type="pair_request",
            version=PAIRING_VERSION,
            node_tag=node_tag,
            node_description=node_description,
            endpoint=request_endpoint,  # Phase 12-Fix.F: 使用分配的 tunnel_port
            tunnel_type=tunnel_type,
            api_port=api_port,  # Phase 11-Fix.K
            psk_hash="",  # 已废弃
            bidirectional=bidirectional,
            tunnel_local_ip=tunnel_local_ip,
            tunnel_remote_ip=tunnel_remote_ip,
            timestamp=int(time.time()),
        )
        # Phase 12-Fix.F: 保存 tunnel_port 供 complete_pairing 使用
        request._tunnel_port = tunnel_port

        # 根据隧道类型生成密钥
        if tunnel_type == "wireguard":
            private_key, public_key = self.generate_wireguard_keypair()
            request.wg_public_key = public_key
            # 保存私钥到临时存储（调用者需要处理）
            request._private_key = private_key

            # Phase 11.2: 为远程节点预生成密钥对（双向自动连接）
            # 注意：密钥对会包含在 request code 中，必须保密处理！
            if bidirectional:
                remote_private, remote_public = self.generate_wireguard_keypair()
                request.remote_wg_private_key = remote_private  # 包含在 request code 中
                request.remote_wg_public_key = remote_public

        elif tunnel_type == "xray":
            private_key, public_key = self.generate_xray_reality_keypair()
            request.xray_reality_public_key = public_key
            request.xray_reality_short_id = self.generate_short_id()
            request._private_key = private_key

        return self.encode_pairing_code(request.to_dict()), "", request  # psk 已废弃

    def validate_pair_request(self, code: str) -> Tuple[bool, str, Optional[PairingRequest]]:
        """验证配对请求码

        包含完整的安全验证（修复 Phase 2 审查发现的问题）：
        - node_tag 格式验证（防止注入和 WireGuard 接口名问题）
        - endpoint 格式验证（防止 SSRF 和无效地址）
        - WireGuard/Xray 密钥格式验证
        - 时间戳未来值检查（防止永不过期的配对码）
        - 描述长度限制（防止 DoS）

        Returns:
            (is_valid, error_message, request)
        """
        try:
            data = self.decode_pairing_code(code)
        except ValueError as e:
            logging.warning(f"[pairing] 配对请求码解码失败: {e}")
            return False, str(e), None

        # 检查类型
        if data.get("type") != "pair_request":
            return False, "Invalid code type, expected pair_request", None

        # 检查版本
        version = data.get("version", 0)
        if version < 1:
            return False, f"Unsupported version: {version}", None

        # 检查必需字段（psk_hash 已废弃，不再必需）
        required_fields = ["node_tag", "endpoint", "tunnel_type"]
        for field in required_fields:
            if not data.get(field):
                return False, f"Missing required field: {field}", None

        # ========================================
        # CRITICAL-1 修复：验证 node_tag 格式
        # ========================================
        node_tag = data.get("node_tag", "")
        if not TAG_PATTERN.match(node_tag):
            logging.warning(f"[pairing] 无效的 node_tag 格式: {node_tag[:50]}")
            return False, "Invalid node_tag format (must be lowercase letters, numbers, hyphens, starting with letter)", None

        # 截断并清理描述（防止 DoS）
        if "node_description" in data:
            data["node_description"] = str(data["node_description"])[:MAX_DESCRIPTION_LENGTH]

        # ========================================
        # HIGH-1 修复：验证 endpoint 格式
        # ========================================
        endpoint = data.get("endpoint", "")
        if not self._validate_endpoint(endpoint):
            logging.warning(f"[pairing] 无效的 endpoint 格式: {endpoint[:100]}")
            return False, "Invalid endpoint format (expected host:port)", None

        # 检查隧道类型
        tunnel_type = data.get("tunnel_type")
        if tunnel_type not in ("wireguard", "xray"):
            return False, f"Invalid tunnel type: {tunnel_type}", None

        # ========================================
        # HIGH-4 修复：时间戳验证（包括未来值检查）
        # ========================================
        timestamp = data.get("timestamp", 0)
        if timestamp > 0:
            now = int(time.time())
            # 检查未来时间戳（允许 5 分钟时钟偏差）
            if timestamp > now + MAX_TIMESTAMP_FUTURE_OFFSET:
                logging.warning(f"[pairing] 时间戳在未来: {timestamp} > {now}")
                return False, "Pairing code timestamp is in the future", None
            # 检查过期
            age = now - timestamp
            if age > PAIRING_CODE_TTL:
                return False, f"Pairing code expired (age: {age}s)", None

        # ========================================
        # HIGH-3 修复：WireGuard 密钥格式验证
        # ========================================
        if tunnel_type == "wireguard":
            wg_public_key = data.get("wg_public_key", "")
            if not wg_public_key:
                return False, "Missing WireGuard public key", None
            if not WG_KEY_PATTERN.match(wg_public_key):
                logging.warning(f"[pairing] 无效的 WireGuard 公钥格式")
                return False, "Invalid WireGuard public key format", None

            # ========================================
            # CRITICAL-1 修复：预生成密钥格式验证 (Phase 11.2)
            # ========================================
            remote_wg_private_key = data.get("remote_wg_private_key", "")
            remote_wg_public_key = data.get("remote_wg_public_key", "")
            if remote_wg_private_key:
                # WireGuard 私钥和公钥格式相同 (base64 编码的 32 字节 Curve25519)
                if not WG_KEY_PATTERN.match(remote_wg_private_key):
                    logging.warning(f"[pairing] 无效的预生成 WireGuard 私钥格式")
                    return False, "Invalid pre-generated WireGuard private key format", None
            if remote_wg_public_key:
                if not WG_KEY_PATTERN.match(remote_wg_public_key):
                    logging.warning(f"[pairing] 无效的预生成 WireGuard 公钥格式")
                    return False, "Invalid pre-generated WireGuard public key format", None
            # 如果两者都存在，验证私钥和公钥是否匹配
            if remote_wg_private_key and remote_wg_public_key:
                try:
                    derived_public = subprocess.run(
                        ["wg", "pubkey"],
                        input=remote_wg_private_key,
                        capture_output=True,
                        text=True,
                        timeout=5,
                        check=True
                    ).stdout.strip()
                    if derived_public != remote_wg_public_key:
                        logging.warning(f"[pairing] 预生成密钥对不匹配")
                        return False, "Pre-generated WireGuard keypair does not match", None
                except subprocess.SubprocessError as e:
                    logging.warning(f"[pairing] 验证预生成密钥对失败: {e}")
                    return False, "Failed to verify pre-generated keypair", None

        # ========================================
        # HIGH-3 修复：Xray REALITY 密钥格式验证
        # ========================================
        if tunnel_type == "xray":
            xray_public_key = data.get("xray_reality_public_key", "")
            if not xray_public_key:
                return False, "Missing Xray REALITY public key", None
            if not XRAY_X25519_PATTERN.match(xray_public_key):
                logging.warning(f"[pairing] 无效的 Xray REALITY 公钥格式")
                return False, "Invalid Xray REALITY public key format", None

            # 验证 short_id（如果存在）
            short_id = data.get("xray_reality_short_id", "")
            if short_id and not XRAY_SHORT_ID_PATTERN.match(short_id):
                logging.warning(f"[pairing] 无效的 Xray REALITY short_id 格式")
                return False, "Invalid Xray REALITY short_id format", None

        return True, "", PairingRequest.from_dict(data)

    def _validate_endpoint(self, endpoint: str) -> bool:
        """验证 endpoint 格式（host:port）

        Args:
            endpoint: 端点字符串

        Returns:
            是否有效
        """
        if not endpoint or ':' not in endpoint:
            return False

        # 分割 host 和 port
        parts = endpoint.rsplit(':', 1)
        if len(parts) != 2:
            return False

        host, port_str = parts

        # 验证端口
        try:
            port = int(port_str)
            if not (1 <= port <= 65535):
                return False
        except ValueError:
            return False

        # 验证 host（IP 或域名）
        if not host:
            return False

        # 简单的 host 验证（IP 地址或域名格式）
        # IPv4 地址
        ip_pattern = re.compile(r'^(\d{1,3}\.){3}\d{1,3}$')
        if ip_pattern.match(host):
            # 验证每个 octet
            octets = host.split('.')
            for octet in octets:
                if int(octet) > 255:
                    return False
            return True

        # 域名格式（简单验证）
        hostname_pattern = re.compile(r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$')
        if hostname_pattern.match(host) and len(host) <= 253:
            return True

        return False

    def validate_pair_response(self, code: str) -> Tuple[bool, str, Optional[PairingResponse]]:
        """验证配对响应码

        包含完整的安全验证（修复 Phase 2 审查发现的问题）：
        - node_tag 格式验证
        - endpoint 格式验证
        - 隧道 IP 格式验证
        - WireGuard/Xray 密钥格式验证
        - 时间戳未来值检查

        Returns:
            (is_valid, error_message, response)
        """
        try:
            data = self.decode_pairing_code(code)
        except ValueError as e:
            logging.warning(f"[pairing] 配对响应码解码失败: {e}")
            return False, str(e), None

        # 检查类型
        if data.get("type") != "pair_response":
            return False, "Invalid code type, expected pair_response", None

        # 检查版本
        version = data.get("version", 0)
        if version < 1:
            return False, f"Unsupported version: {version}", None

        # 检查必需字段（psk_hash 已废弃，不再必需）
        required_fields = [
            "request_node_tag", "node_tag", "endpoint",
            "tunnel_local_ip", "tunnel_remote_ip"
        ]
        for field in required_fields:
            if not data.get(field):
                return False, f"Missing required field: {field}", None

        # ========================================
        # CRITICAL-1 修复：验证 node_tag 格式
        # ========================================
        node_tag = data.get("node_tag", "")
        if not TAG_PATTERN.match(node_tag):
            logging.warning(f"[pairing] 无效的 node_tag 格式: {node_tag[:50]}")
            return False, "Invalid node_tag format", None

        request_node_tag = data.get("request_node_tag", "")
        if not TAG_PATTERN.match(request_node_tag):
            logging.warning(f"[pairing] 无效的 request_node_tag 格式: {request_node_tag[:50]}")
            return False, "Invalid request_node_tag format", None

        # 截断并清理描述
        if "node_description" in data:
            data["node_description"] = str(data["node_description"])[:MAX_DESCRIPTION_LENGTH]

        # ========================================
        # HIGH-1 修复：验证 endpoint 格式
        # ========================================
        endpoint = data.get("endpoint", "")
        if not self._validate_endpoint(endpoint):
            logging.warning(f"[pairing] 无效的 endpoint 格式: {endpoint[:100]}")
            return False, "Invalid endpoint format", None

        # 验证隧道 IP 格式
        tunnel_local_ip = data.get("tunnel_local_ip", "")
        tunnel_remote_ip = data.get("tunnel_remote_ip", "")
        ip_pattern = re.compile(r'^(\d{1,3}\.){3}\d{1,3}$')

        if not ip_pattern.match(tunnel_local_ip):
            return False, "Invalid tunnel_local_ip format", None
        if not ip_pattern.match(tunnel_remote_ip):
            return False, "Invalid tunnel_remote_ip format", None

        # Issue 15 修复：验证隧道 IP 在预期子网范围内
        if not _validate_tunnel_ip_in_subnet(tunnel_local_ip):
            logging.warning(f"[pairing] tunnel_local_ip '{tunnel_local_ip}' 不在预期范围 {TUNNEL_IP_SUBNET}")
            return False, f"tunnel_local_ip '{tunnel_local_ip}' is not in expected subnet {TUNNEL_IP_SUBNET}", None
        if not _validate_tunnel_ip_in_subnet(tunnel_remote_ip):
            logging.warning(f"[pairing] tunnel_remote_ip '{tunnel_remote_ip}' 不在预期范围 {TUNNEL_IP_SUBNET}")
            return False, f"tunnel_remote_ip '{tunnel_remote_ip}' is not in expected subnet {TUNNEL_IP_SUBNET}", None

        # ========================================
        # HIGH-4 修复：时间戳验证（包括未来值检查）
        # ========================================
        timestamp = data.get("timestamp", 0)
        if timestamp > 0:
            now = int(time.time())
            # 检查未来时间戳
            if timestamp > now + MAX_TIMESTAMP_FUTURE_OFFSET:
                logging.warning(f"[pairing] 时间戳在未来: {timestamp} > {now}")
                return False, "Pairing code timestamp is in the future", None
            # 检查过期
            age = now - timestamp
            if age > PAIRING_CODE_TTL:
                return False, f"Pairing code expired (age: {age}s)", None

        # ========================================
        # HIGH-3 修复：验证可选的 WireGuard 公钥格式
        # ========================================
        wg_public_key = data.get("wg_public_key", "")
        if wg_public_key and not WG_KEY_PATTERN.match(wg_public_key):
            logging.warning(f"[pairing] 无效的 WireGuard 公钥格式")
            return False, "Invalid WireGuard public key format", None

        # ========================================
        # HIGH-3 修复：验证可选的 Xray REALITY 公钥格式
        # ========================================
        xray_public_key = data.get("xray_reality_public_key", "")
        if xray_public_key and not XRAY_X25519_PATTERN.match(xray_public_key):
            logging.warning(f"[pairing] 无效的 Xray REALITY 公钥格式")
            return False, "Invalid Xray REALITY public key format", None

        short_id = data.get("xray_reality_short_id", "")
        if short_id and not XRAY_SHORT_ID_PATTERN.match(short_id):
            logging.warning(f"[pairing] 无效的 Xray REALITY short_id 格式")
            return False, "Invalid Xray REALITY short_id format", None

        return True, "", PairingResponse.from_dict(data)


class PairingManager:
    """配对管理器 - 处理配对流程

    注意：IP/端口分配存在竞态条件风险。数据库使用 UNIQUE 索引检测：
    - idx_peer_nodes_tunnel_local_ip
    - idx_peer_nodes_tunnel_port

    如果发生冲突，add_peer_node() 会抛出 IntegrityError，调用者应捕获并重试。
    """

    def __init__(self, db):
        """
        Args:
            db: DatabaseManager 实例
        """
        self.db = db
        self.generator = PairingCodeGenerator(db)

    def get_next_tunnel_ip_pair(self) -> Tuple[str, str]:
        """获取下一对可用的隧道 IP

        注意：存在 TOCTOU 竞态条件风险。调用者应处理 IntegrityError。

        Returns:
            (local_ip, remote_ip)

        Raises:
            ValueError: 没有可用的 IP 地址
        """
        # 获取已使用的 IP
        used_ips = set()
        peer_nodes = self.db.get_peer_nodes()
        for node in peer_nodes:
            if node.get("tunnel_local_ip"):
                used_ips.add(node["tunnel_local_ip"])
            if node.get("tunnel_remote_ip"):
                used_ips.add(node["tunnel_remote_ip"])

        # 从 1 开始分配 IP 对（成对分配：1-2, 3-4, 5-6...）
        for i in range(1, 254, 2):
            local_ip = f"{TUNNEL_IP_BASE}.{i}"
            remote_ip = f"{TUNNEL_IP_BASE}.{i + 1}"
            if local_ip not in used_ips and remote_ip not in used_ips:
                return local_ip, remote_ip

        raise ValueError("No available tunnel IP addresses")

    def get_next_tunnel_port(self) -> int:
        """获取下一个可用的隧道端口

        注意：存在 TOCTOU 竞态条件风险。调用者应处理 IntegrityError。

        Returns:
            可用的端口号

        Raises:
            ValueError: 没有可用的端口
        """
        used_ports = set()

        peer_nodes = self.db.get_peer_nodes()
        for node in peer_nodes:
            if node.get("tunnel_port"):
                used_ports.add(node["tunnel_port"])

        for port in range(TUNNEL_PORT_BASE, TUNNEL_PORT_MAX + 1):
            if port not in used_ports:
                return port

        raise ValueError("No available tunnel ports")

    def import_pair_request(
        self,
        code: str,
        local_node_tag: str,
        local_node_description: str,
        local_endpoint: str,
        psk: str = "",  # 已废弃，保留参数兼容
        api_port: Optional[int] = None,  # Phase 11-Fix.K: 本节点 API 端口
    ) -> Tuple[bool, str, Optional[str]]:
        """导入配对请求码

        处理流程：
        1. 验证请求码
        2. 自动创建 peer_node（使用请求方信息）
        3. 生成响应码

        Args:
            code: 配对请求码
            local_node_tag: 本节点标识
            local_node_description: 本节点描述
            local_endpoint: 本节点端点
            psk: [已废弃] 不再使用，保留参数兼容
            api_port: 本节点 API 端口 (Phase 11-Fix.K)

        Returns:
            (success, message, response_code)
        """
        # 验证请求码
        is_valid, error, request = self.generator.validate_pair_request(code)
        if not is_valid:
            return False, f"Invalid request code: {error}", None

        # 检查是否已存在同名节点
        existing = self.db.get_peer_node(request.node_tag)
        if existing:
            return False, f"Peer node '{request.node_tag}' already exists", None

        # PSK 验证已废弃 - WireGuard 用隧道 IP 认证，Xray 用 UUID 认证

        # 分配隧道参数
        try:
            # local_ip 是本节点使用的 IP，remote_ip 是分配给对方的
            local_ip, remote_ip = self.get_next_tunnel_ip_pair()
            tunnel_port = self.get_next_tunnel_port()
        except ValueError as e:
            return False, str(e), None

        try:
            # 生成本节点密钥
            if request.tunnel_type == "wireguard":
                # Phase 11.2: 使用预生成的密钥对（如果请求中包含）
                # 这允许请求方无需密钥交换即可知道本节点的公钥
                if request.remote_wg_private_key and request.remote_wg_public_key:
                    # 使用请求方预生成的密钥对
                    private_key = request.remote_wg_private_key
                    public_key = request.remote_wg_public_key
                    bidirectional_status = "pending"  # 等待自动连接
                    logging.info(f"[pairing] 使用预生成密钥对进行双向配对: {request.node_tag}")
                else:
                    # 向后兼容：生成新密钥对
                    private_key, public_key = self.generator.generate_wireguard_keypair()
                    bidirectional_status = None

                # Phase 11-Fix.K: 保存 api_port 并正确设置 tunnel_api_endpoint
                remote_api_port = request.api_port or DEFAULT_WEB_PORT
                self.db.add_peer_node(
                    tag=request.node_tag,
                    name=request.node_tag,
                    description=request.node_description or f"Paired from {request.endpoint}",
                    endpoint=request.endpoint,
                    api_port=request.api_port,  # Phase 11-Fix.K: 保存 API 端口
                    # psk_hash/psk_encrypted 已废弃
                    tunnel_type="wireguard",
                    tunnel_status="disconnected",
                    tunnel_local_ip=local_ip,
                    tunnel_remote_ip=remote_ip,
                    tunnel_port=tunnel_port,
                    wg_private_key=private_key,
                    wg_public_key=public_key,
                    wg_peer_public_key=request.wg_public_key,
                    tunnel_api_endpoint=f"{remote_ip}:{remote_api_port}",
                )

                # Phase 11.2: 设置双向连接状态
                if bidirectional_status:
                    self.db.update_peer_node(
                        request.node_tag,
                        bidirectional_status=bidirectional_status
                    )
            elif request.tunnel_type == "xray":
                private_key, public_key = self.generator.generate_xray_reality_keypair()
                short_id = self.generator.generate_short_id()

                # Phase 6 Issue 21: 为 Xray peer 生成 xray_uuid
                # 这个 UUID 用于隧道 API 认证
                import uuid
                xray_uuid = str(uuid.uuid4())

                # Phase 11-Fix.K: 保存 api_port 并正确设置 tunnel_api_endpoint
                remote_api_port = request.api_port or DEFAULT_WEB_PORT
                self.db.add_peer_node(
                    tag=request.node_tag,
                    name=request.node_tag,
                    description=request.node_description or f"Paired from {request.endpoint}",
                    endpoint=request.endpoint,
                    api_port=request.api_port,  # Phase 11-Fix.K: 保存 API 端口
                    # psk_hash/psk_encrypted 已废弃
                    tunnel_type="xray",
                    tunnel_status="disconnected",
                    tunnel_local_ip=local_ip,
                    tunnel_remote_ip=remote_ip,
                    tunnel_port=tunnel_port,
                    xray_reality_private_key=private_key,
                    xray_reality_public_key=public_key,
                    xray_reality_short_id=short_id,
                    xray_peer_reality_public_key=request.xray_reality_public_key,
                    xray_peer_reality_short_id=request.xray_reality_short_id,
                    xray_uuid=xray_uuid,  # Phase 6 Issue 21: 存储 xray_uuid
                    tunnel_api_endpoint=f"{remote_ip}:{remote_api_port}",
                )
        except sqlite3.IntegrityError as e:
            # CRITICAL-2 修复：处理 IP/端口分配竞态条件
            logging.warning(f"[pairing] 资源冲突（竞态条件）: {e}")
            return False, "Resource allocation conflict - please retry", None
        except Exception as e:
            logging.error(f"[pairing] 创建 peer_node 失败: {e}")
            return False, "Failed to create peer node", None

        # 生成响应码
        # Phase 11-Fix.K: 使用 api_port 或默认端口
        local_api_port = api_port or DEFAULT_WEB_PORT

        # Phase 12-Fix.F: 响应码的 endpoint 必须使用分配的 tunnel_port
        # 从 local_endpoint 提取 IP，然后用分配的 tunnel_port 构造新 endpoint
        # 这样请求方才知道连接到哪个端口
        endpoint_ip = local_endpoint.rsplit(":", 1)[0] if ":" in local_endpoint else local_endpoint
        response_endpoint = f"{endpoint_ip}:{tunnel_port}"

        response = PairingResponse(
            type="pair_response",
            version=PAIRING_VERSION,
            request_node_tag=request.node_tag,
            node_tag=local_node_tag,
            node_description=local_node_description,
            endpoint=response_endpoint,  # Phase 12-Fix.F: 使用分配的 tunnel_port
            api_port=api_port,  # Phase 11-Fix.K: 包含 API 端口
            psk_hash="",  # 已废弃
            tunnel_local_ip=remote_ip,  # 分配给请求方的 IP
            tunnel_remote_ip=local_ip,  # 本节点的 IP
            timestamp=int(time.time()),
            tunnel_api_endpoint=f"{local_ip}:{local_api_port}",  # Phase 11-Fix.K: 使用实际端口
        )

        if request.tunnel_type == "wireguard":
            response.wg_public_key = public_key
        elif request.tunnel_type == "xray":
            response.xray_reality_public_key = public_key
            response.xray_reality_short_id = short_id
            response.xray_uuid = xray_uuid  # Phase 11-Fix.Xray: Include UUID for inbound auth

        response_code = self.generator.encode_pairing_code(response.to_dict())

        logging.info(f"[pairing] 成功导入请求码并创建节点 '{request.node_tag}'")
        return True, "Peer node created successfully", response_code

    def complete_pairing(
        self,
        code: str,
        pending_request: dict,
    ) -> Tuple[bool, str]:
        """完成配对（导入响应码）

        处理流程：
        1. 验证响应码
        2. 使用响应信息创建 peer_node

        Args:
            code: 配对响应码
            pending_request: 待处理的请求信息（包含私钥等）
                - node_tag: 请求时使用的 tag
                - tunnel_type: 隧道类型
                - wg_private_key / xray_private_key: 本节点私钥

        Returns:
            (success, message)
        """
        # 验证响应码
        is_valid, error, response = self.generator.validate_pair_response(code)
        if not is_valid:
            return False, f"Invalid response code: {error}"

        # 验证 request_node_tag 匹配
        if response.request_node_tag != pending_request.get("node_tag"):
            return False, f"Response is for node '{response.request_node_tag}', expected '{pending_request.get('node_tag')}'"

        # 检查是否已存在同名节点
        existing = self.db.get_peer_node(response.node_tag)
        if existing:
            return False, f"Peer node '{response.node_tag}' already exists"

        # PSK 已废弃 - WireGuard 用隧道 IP 认证，Xray 用 UUID 认证

        # Issue 15 修复：验证隧道 IP 在预期范围内
        if response.tunnel_local_ip and not _validate_tunnel_ip_in_subnet(response.tunnel_local_ip):
            logging.warning(f"[pairing] tunnel_local_ip '{response.tunnel_local_ip}' 不在预期范围 {TUNNEL_IP_SUBNET}")
            return False, f"Invalid tunnel_local_ip: '{response.tunnel_local_ip}' is not in expected subnet {TUNNEL_IP_SUBNET}"
        if response.tunnel_remote_ip and not _validate_tunnel_ip_in_subnet(response.tunnel_remote_ip):
            logging.warning(f"[pairing] tunnel_remote_ip '{response.tunnel_remote_ip}' 不在预期范围 {TUNNEL_IP_SUBNET}")
            return False, f"Invalid tunnel_remote_ip: '{response.tunnel_remote_ip}' is not in expected subnet {TUNNEL_IP_SUBNET}"

        # Issue 14 修复：如果 tunnel_api_endpoint 缺失，从 tunnel_remote_ip 和 api_port 计算
        tunnel_api_endpoint = response.tunnel_api_endpoint
        if not tunnel_api_endpoint and response.tunnel_remote_ip:
            api_port = response.api_port or DEFAULT_WEB_PORT
            tunnel_api_endpoint = f"{response.tunnel_remote_ip}:{api_port}"
            logging.info(f"[pairing] 计算 tunnel_api_endpoint: {tunnel_api_endpoint}")

        # 创建 peer_node
        try:
            tunnel_type = pending_request.get("tunnel_type", "wireguard")

            if tunnel_type == "wireguard":
                self.db.add_peer_node(
                    tag=response.node_tag,
                    name=response.node_tag,
                    description=response.node_description or f"Paired from {response.endpoint}",
                    endpoint=response.endpoint,
                    api_port=response.api_port,  # Phase 11-Fix.K: 保存 API 端口
                    # psk_hash/psk_encrypted 已废弃
                    tunnel_type="wireguard",
                    tunnel_status="disconnected",
                    tunnel_local_ip=response.tunnel_local_ip,
                    tunnel_remote_ip=response.tunnel_remote_ip,
                    # Phase 12-Fix.F: 保存本地监听端口
                    tunnel_port=pending_request.get("tunnel_port"),
                    wg_private_key=pending_request.get("wg_private_key"),
                    wg_public_key=pending_request.get("wg_public_key"),
                    wg_peer_public_key=response.wg_public_key,
                    tunnel_api_endpoint=tunnel_api_endpoint,  # Issue 14: 使用计算后的值
                )
                # Phase 11.2: 保存双向连接参数
                if pending_request.get("bidirectional"):
                    self.db.update_peer_node(
                        response.node_tag,
                        remote_wg_private_key=pending_request.get("remote_wg_private_key"),
                        remote_wg_public_key=pending_request.get("remote_wg_public_key"),
                        bidirectional_status="pending",
                    )
            elif tunnel_type == "xray":
                # Phase 11.3: Xray 双向自动连接
                # Phase 11-Fix.Xray: Use xray_uuid from response for inbound authentication
                # The response contains the peer's UUID that they will use when connecting to us
                import uuid
                xray_uuid = response.xray_uuid if hasattr(response, 'xray_uuid') and response.xray_uuid else str(uuid.uuid4())

                self.db.add_peer_node(
                    tag=response.node_tag,
                    name=response.node_tag,
                    description=response.node_description or f"Paired from {response.endpoint}",
                    endpoint=response.endpoint,
                    api_port=response.api_port,  # Phase 11-Fix.K: 保存 API 端口
                    # psk_hash/psk_encrypted 已废弃
                    tunnel_type="xray",
                    tunnel_status="disconnected",
                    tunnel_local_ip=response.tunnel_local_ip,
                    tunnel_remote_ip=response.tunnel_remote_ip,
                    xray_reality_private_key=pending_request.get("xray_private_key"),
                    xray_reality_public_key=pending_request.get("xray_public_key"),
                    xray_reality_short_id=pending_request.get("xray_short_id"),
                    xray_peer_reality_public_key=response.xray_reality_public_key,
                    xray_peer_reality_short_id=response.xray_reality_short_id,
                    xray_uuid=xray_uuid,  # Phase 11-Fix.Xray: Use peer's UUID for inbound auth
                    tunnel_api_endpoint=tunnel_api_endpoint,  # Issue 14: 使用计算后的值
                    bidirectional_status="pending",  # Phase 11.3: 标记待双向连接
                )
        except Exception as e:
            logging.error(f"[pairing] 完成配对失败: {e}")
            return False, f"Failed to complete pairing: {e}"

        logging.info(f"[pairing] 配对完成，创建节点 '{response.node_tag}'")
        return True, "Pairing completed successfully"

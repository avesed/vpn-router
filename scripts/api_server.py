#!/usr/bin/env python3
"""FastAPI 服务：为前端提供 sing-box 网关管理接口"""
import hashlib
import json
import os
import secrets
import shutil
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
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import PlainTextResponse, Response
from pydantic import BaseModel, Field

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

# Port configuration from environment
DEFAULT_WG_PORT = int(os.environ.get("WG_LISTEN_PORT", "DEFAULT_WG_PORT"))
DEFAULT_WEB_PORT = int(os.environ.get("WEB_PORT", "36000"))

PIA_SERVERLIST_URL = "https://serverlist.piaservers.net/vpninfo/servers/v6"

CONFIG_LOCK = threading.Lock()

# 缓存 PIA 地区列表（有效期 1 小时）
_pia_regions_cache: Dict[str, Any] = {"data": None, "timestamp": 0}

# ============ 流量统计 ============
# 累计流量统计（按出口分组）
_traffic_stats: Dict[str, Dict[str, int]] = {}  # {outbound: {download: int, upload: int}}
# 已知连接的流量快照（用于计算增量）
_known_connections: Dict[str, Dict[str, int]] = {}  # {conn_id: {download: int, upload: int, outbound: str}}
# 上一次的流量快照（用于计算速率）
_prev_traffic_stats: Dict[str, Dict[str, int]] = {}
# 当前速率（bytes/s）
_traffic_rates: Dict[str, Dict[str, float]] = {}  # {outbound: {download_rate: float, upload_rate: float}}
# 速率历史记录（保留24小时）
_rate_history: List[Dict[str, Any]] = []  # [{timestamp: int, rates: {outbound: rate_kb}}]
_traffic_stats_lock = threading.Lock()
_RATE_INTERVAL = 5  # 速率计算间隔（秒）
_MAX_HISTORY_SECONDS = 24 * 60 * 60  # 保留24小时历史


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


class CustomCategoryItemRequest(BaseModel):
    """在分类中添加自定义域名列表项"""
    name: str = Field(..., description="列表名称，如 my-streaming")
    domains: List[str] = Field(..., description="域名列表")


class IngressPeerCreateRequest(BaseModel):
    """添加入口 WireGuard peer"""
    name: str = Field(..., description="客户端名称，如 laptop, phone")
    public_key: Optional[str] = Field(None, description="客户端公钥（可选，不填则服务端生成密钥对）")


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
        raise HTTPException(status_code=400, detail=f"解密失败，密码可能不正确: {exc}") from exc


app = FastAPI(title="VPN Gateway API", version="0.1.0")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


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
        # 从 SQLite 加载国家列表
        print(f"[Catalog] GeoIP JSON 不存在，从 SQLite 加载...")
        try:
            db = get_db()
            countries = db.get_countries(limit=500)
            _GEOIP_CATALOG = {
                "countries": countries,
                "total_countries": len(countries),
                "total_ipv4_ranges": sum(c.get("ipv4_count", 0) for c in countries),
                "total_ipv6_ranges": sum(c.get("ipv6_count", 0) for c in countries),
                "source": "sqlite"
            }
            print(f"[Catalog] 已加载 GeoIP 目录: {len(countries)} 国家 (SQLite)")
        except Exception as e:
            print(f"[Catalog] 加载 GeoIP 目录失败: {e}")
            _GEOIP_CATALOG = {"countries": []}


def _get_all_outbounds() -> List[str]:
    """获取所有配置的出口（用于图表显示）"""
    outbounds = ["direct"]  # 始终包含 direct

    if HAS_DATABASE and USER_DB_PATH.exists() and GEODATA_DB_PATH.exists():
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
        except Exception:
            pass

    return outbounds


def _update_traffic_stats():
    """后台线程：定期更新累计流量统计和实时速率"""
    import urllib.request
    global _traffic_stats, _known_connections, _prev_traffic_stats, _traffic_rates, _rate_history

    while True:
        try:
            with urllib.request.urlopen("http://127.0.0.1:9090/connections", timeout=2) as resp:
                data = json.loads(resp.read().decode())

            connections = data.get("connections", [])
            current_conn_ids = set()

            with _traffic_stats_lock:
                for conn in connections:
                    conn_id = conn.get("id", "")
                    if not conn_id:
                        continue

                    current_conn_ids.add(conn_id)
                    download = conn.get("download", 0)
                    upload = conn.get("upload", 0)
                    chains = conn.get("chains", [])
                    outbound = chains[-1] if chains else "unknown"

                    # 初始化出口统计
                    if outbound not in _traffic_stats:
                        _traffic_stats[outbound] = {"download": 0, "upload": 0}

                    if conn_id in _known_connections:
                        # 已知连接：计算增量
                        prev = _known_connections[conn_id]
                        dl_delta = download - prev["download"]
                        ul_delta = upload - prev["upload"]
                        if dl_delta > 0:
                            _traffic_stats[outbound]["download"] += dl_delta
                        if ul_delta > 0:
                            _traffic_stats[outbound]["upload"] += ul_delta
                    else:
                        # 新连接：累加全部流量
                        _traffic_stats[outbound]["download"] += download
                        _traffic_stats[outbound]["upload"] += upload

                    # 更新快照
                    _known_connections[conn_id] = {
                        "download": download,
                        "upload": upload,
                        "outbound": outbound
                    }

                # 清理已关闭的连接
                closed_ids = set(_known_connections.keys()) - current_conn_ids
                for conn_id in closed_ids:
                    del _known_connections[conn_id]

                # 计算速率（bytes/s）
                for outbound, stats in _traffic_stats.items():
                    prev = _prev_traffic_stats.get(outbound, {"download": 0, "upload": 0})
                    dl_rate = (stats["download"] - prev["download"]) / _RATE_INTERVAL
                    ul_rate = (stats["upload"] - prev["upload"]) / _RATE_INTERVAL
                    _traffic_rates[outbound] = {
                        "download_rate": max(0, dl_rate),
                        "upload_rate": max(0, ul_rate)
                    }

                # 保存当前流量作为下次计算的基准
                _prev_traffic_stats = {k: dict(v) for k, v in _traffic_stats.items()}

                # 记录速率历史（KB/s）- 包含所有配置的出口
                now = int(time.time())
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

                # 清理24小时前的历史数据
                cutoff = now - _MAX_HISTORY_SECONDS
                _rate_history[:] = [p for p in _rate_history if p["timestamp"] > cutoff]

        except Exception:
            pass

        time.sleep(_RATE_INTERVAL)


@app.on_event("startup")
async def startup_event():
    """应用启动时加载数据"""
    load_catalogs()
    # 启动流量统计后台线程
    traffic_thread = threading.Thread(target=_update_traffic_stats, daemon=True)
    traffic_thread.start()
    print("[Traffic] 流量统计后台线程已启动")


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
        raise HTTPException(status_code=500, detail=f"获取 PIA 地区列表失败: {exc}") from exc


def save_pia_profiles_yaml(profiles: List[Dict[str, Any]]) -> None:
    """保存 PIA profiles 配置"""
    data = {"profiles": profiles}
    PIA_PROFILES_FILE.parent.mkdir(parents=True, exist_ok=True)
    PIA_PROFILES_FILE.write_text(yaml.dump(data, allow_unicode=True, default_flow_style=False))


def load_custom_rules() -> Dict[str, Any]:
    """加载自定义路由规则（数据库优先，降级到 JSON）"""
    if HAS_DATABASE and USER_DB_PATH.exists() and GEODATA_DB_PATH.exists():
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
    if not HAS_DATABASE or not USER_DB_PATH.exists() and GEODATA_DB_PATH.exists():
        return []

    db = get_db(str(GEODATA_DB_PATH), str(USER_DB_PATH))
    rules_db = db.get_routing_rules(enabled_only=True)

    # 按优先级排序（高优先级在前）
    rules_db.sort(key=lambda r: r.get("priority", 0), reverse=True)

    singbox_rules = []

    # 按规则类型和出口分组
    domain_rules = {}  # outbound -> [domains]
    ip_rules = {}      # outbound -> [cidrs]

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

    return singbox_rules


def load_custom_category_items() -> Dict[str, List[Dict]]:
    """加载分类自定义项目（数据库优先，降级到 JSON）"""
    if HAS_DATABASE and USER_DB_PATH.exists() and GEODATA_DB_PATH.exists():
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
def api_stats_dashboard():
    """获取 Dashboard 可视化统计数据

    返回：
    - online_clients: 在线客户端数量（有活跃连接的 WireGuard peer）
    - total_clients: 总客户端数量（所有配置的 WireGuard peer）
    - traffic_by_outbound: 按出口分组的流量 {tag: {download, upload}}
    - adblock_connections: 匹配广告拦截规则的连接数
    - active_connections: 总活跃连接数
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
            if src_ip.startswith("10.23.0."):
                online_ips.add(src_ip)

        stats["online_clients"] = len(online_ips)

    except Exception as e:
        # clash_api 不可用时返回空数据
        pass

    # 使用累计流量统计和实时速率（由后台线程更新）
    # 包含所有配置的出口，没有流量的显示为 0
    all_outbounds = _get_all_outbounds()
    with _traffic_stats_lock:
        stats["traffic_by_outbound"] = {k: dict(v) for k, v in _traffic_stats.items()}
        # 确保所有出口都有速率数据
        traffic_rates = {}
        for outbound in all_outbounds:
            if outbound in _traffic_rates:
                traffic_rates[outbound] = dict(_traffic_rates[outbound])
            else:
                traffic_rates[outbound] = {"download_rate": 0.0, "upload_rate": 0.0}
        stats["traffic_rates"] = traffic_rates
        stats["rate_history"] = list(_rate_history)  # 24小时速率历史

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
            "address": [server.get("address", "10.23.0.1/24")],
            "private_key": server.get("private_key", ""),
            "listen_port": server.get("listen_port", DEFAULT_WG_PORT),
            "peers": [
                {
                    "public_key": p.get("public_key", ""),
                    "allowed_ips": [p.get("allowed_ips", "10.23.0.2/32")]
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
        return {"message": f"endpoint {tag} updated"}

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
            return {"message": f"endpoint {tag} updated"}

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
    username = os.environ.get("PIA_USERNAME")
    password = os.environ.get("PIA_PASSWORD")
    has_credentials = bool(username and password)
    return {
        "has_credentials": has_credentials,
        "message": "已登录" if has_credentials else "未登录，需要重新登录 PIA"
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
    username = os.environ.get("PIA_USERNAME")
    password = os.environ.get("PIA_PASSWORD")
    provision_result = None

    if username and password:
        env = os.environ.copy()
        generated_config = Path("/etc/sing-box/sing-box.generated.json")
        env.update({
            "PIA_USERNAME": username,
            "PIA_PASSWORD": password,
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
            provision_result = {"success": True, "reload": reload_result}
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
    return {"message": f"线路 {tag} 已删除"}


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
    if HAS_DATABASE and USER_DB_PATH.exists() and GEODATA_DB_PATH.exists():
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
    if HAS_DATABASE and USER_DB_PATH.exists() and GEODATA_DB_PATH.exists():
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
                    "type": "custom"
                }

            # 根据规则类型添加到对应字段
            if rule_type == "domain":
                rules_by_tag[tag]["domains"].append(target)
            elif rule_type == "domain_keyword":
                rules_by_tag[tag]["domain_keywords"].append(target)
            elif rule_type == "ip":
                rules_by_tag[tag]["ip_cidrs"].append(target)

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
    if HAS_DATABASE and USER_DB_PATH.exists() and GEODATA_DB_PATH.exists():
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
    if not payload.domains and not payload.domain_keywords and not payload.ip_cidrs:
        raise HTTPException(status_code=400, detail="至少需要提供一种匹配规则（域名、关键词或 IP）")

    if not HAS_DATABASE or not USER_DB_PATH.exists() and GEODATA_DB_PATH.exists():
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
    if not HAS_DATABASE or not USER_DB_PATH.exists() and GEODATA_DB_PATH.exists():
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
    if not HAS_DATABASE or not USER_DB_PATH.exists() and GEODATA_DB_PATH.exists():
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
            raise HTTPException(
                status_code=401,
                detail=f"PIA 登录失败: {token_resp.text}"
            )
        token_data = token_resp.json()
        if not token_data.get("token"):
            raise HTTPException(status_code=401, detail="PIA 登录失败: 无效的响应")
    except requests.RequestException as exc:
        raise HTTPException(status_code=500, detail=f"无法连接 PIA 服务器: {exc}") from exc

    # 保存凭证到当前进程的环境变量
    os.environ["PIA_USERNAME"] = payload.username
    os.environ["PIA_PASSWORD"] = payload.password

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
    env = os.environ.copy()
    generated_config = Path("/etc/sing-box/sing-box.generated.json")
    env.update(
        {
            "PIA_USERNAME": payload.username,
            "PIA_PASSWORD": payload.password,
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
        return {
            "message": "PIA 登录成功，配置已生成并重载",
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
    需要先登录 PIA（凭证存储在环境变量中或之前的会话中）。
    """
    # 检查环境变量中是否有 PIA 凭证
    username = os.environ.get("PIA_USERNAME")
    password = os.environ.get("PIA_PASSWORD")
    if not username or not password:
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
    env = os.environ.copy()
    generated_config = Path("/etc/sing-box/sing-box.generated.json")
    env.update({
        "PIA_USERNAME": username,
        "PIA_PASSWORD": password,
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
        return {
            "message": f"已重新连接 {payload.profile_tag}",
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
                    "address": "10.23.0.1/24",
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
                address="10.23.0.1/24",
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
        "address": server.get("address", "10.23.0.1/24") if server else "10.23.0.1/24",
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
        address=interface.get("address", "10.23.0.1/24"),
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
    """获取下一个可用的 peer IP"""
    interface_addr = config.get("interface", {}).get("address", "10.23.0.1/24")
    # 解析网段
    base_ip = interface_addr.split("/")[0]
    parts = base_ip.rsplit(".", 1)
    base = parts[0]

    # 收集已用的 IP
    used_ips = {1}  # 1 是网关自己
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
    """从 sing-box clash_api 获取 peer 连接状态"""
    import time
    peer_status = {}  # ip -> {"active": bool, "last_seen": timestamp, "rx": int, "tx": int}

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

            # 只处理来自 WireGuard 网段的连接 (10.23.0.x)
            if not src_ip.startswith("10.23.0."):
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

    except Exception as e:
        # clash_api 不可用时静默失败
        pass

    return peer_status


def get_peer_handshake_info() -> dict:
    """获取 peer 握手状态（从 clash_api 活跃连接推断）"""
    import time
    handshakes = {}

    # 从 clash_api 获取连接状态
    peer_status = get_peer_status_from_clash_api()

    # 加载 peer 配置以获取 allowed_ips 到 public_key 的映射
    config = load_ingress_config()
    peers = config.get("peers", [])

    now = int(time.time())

    for peer in peers:
        pubkey = peer.get("public_key", "")
        allowed_ips = peer.get("allowed_ips", [])

        # 处理 allowed_ips（可能是字符串或列表）
        if isinstance(allowed_ips, str):
            allowed_ips = [allowed_ips]

        # 检查该 peer 的任意 IP 是否有活跃连接
        is_active = False
        for ip_cidr in allowed_ips:
            # 提取 IP（去掉 CIDR 后缀）
            ip = ip_cidr.split("/")[0] if "/" in ip_cidr else ip_cidr
            if ip in peer_status and peer_status[ip]["active"]:
                is_active = True
                break

        # 如果有活跃连接，设置 last_handshake 为当前时间
        # 这样 is_online 检查（180秒内）会返回 True
        if is_active:
            handshakes[pubkey] = now
        else:
            handshakes[pubkey] = 0

    return handshakes


def get_peer_transfer_info() -> dict:
    """获取 peer 流量统计（从 clash_api）"""
    transfers = {}

    # 从 clash_api 获取连接状态
    peer_status = get_peer_status_from_clash_api()

    # 加载 peer 配置
    config = load_ingress_config()
    peers = config.get("peers", [])

    for peer in peers:
        pubkey = peer.get("public_key", "")
        allowed_ips = peer.get("allowed_ips", [])

        if isinstance(allowed_ips, str):
            allowed_ips = [allowed_ips]

        total_rx = 0
        total_tx = 0

        for ip_cidr in allowed_ips:
            ip = ip_cidr.split("/")[0] if "/" in ip_cidr else ip_cidr
            if ip in peer_status:
                total_rx += peer_status[ip]["rx"]
                total_tx += peer_status[ip]["tx"]

        transfers[pubkey] = {"rx": total_rx, "tx": total_tx}

    return transfers


def apply_ingress_config(config: dict) -> dict:
    """应用入口 WireGuard 配置到系统

    sing-box 1.12+ 使用 userspace WireGuard endpoint，因此主要通过
    regenerate sing-box config 和 reload sing-box 来应用配置。
    """
    try:
        # 重新生成 sing-box 配置（包含 wg-server endpoint 和 peers）
        render_script = ENTRY_DIR / "render_singbox.py"
        result = subprocess.run(
            ["python3", str(render_script)],
            capture_output=True,
            text=True,
        )
        if result.returncode != 0:
            error_msg = f"配置生成失败: {result.stderr.strip() or result.stdout.strip()}"
            print(f"[api] render_singbox.py 失败: {result.stderr}")
            return {"success": False, "message": error_msg}

        print(f"[api] render_singbox.py 成功: {result.stdout.strip()}")

        # 重载 sing-box 使配置生效
        reload_result = reload_singbox()
        if not reload_result.get("success", False):
            return {"success": False, "message": f"重载失败: {reload_result.get('message', 'unknown error')}"}

        return {"success": True, "message": "配置已应用", "reload": reload_result}
    except subprocess.CalledProcessError as exc:
        return {"success": False, "message": f"应用配置失败: {exc}"}
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

        # 判断是否在线（最近 3 分钟有握手）
        import time
        now = int(time.time())
        is_online = last_handshake > 0 and (now - last_handshake) < 180

        peers.append({
            "name": peer.get("name", "unknown"),
            "public_key": pubkey,
            "allowed_ips": peer.get("allowed_ips", []),
            "last_handshake": last_handshake,
            "is_online": is_online,
            "rx_bytes": transfer.get("rx", 0),
            "tx_bytes": transfer.get("tx", 0),
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

    # 添加到数据库
    if HAS_DATABASE and USER_DB_PATH.exists():
        db = get_db(str(GEODATA_DB_PATH), str(USER_DB_PATH))
        peer_id = db.add_wireguard_peer(
            name=payload.name,
            public_key=client_public_key,
            allowed_ips=f"{peer_ip}/32"
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
    client_ip = peer.get("allowed_ips", ["10.23.0.2/32"])[0]

    # 服务端地址（优先使用设置文件，其次使用环境变量）
    settings = load_settings()
    listen_port = interface.get("listen_port", DEFAULT_WG_PORT)
    server_endpoint = settings.get("server_endpoint", "") or os.environ.get("WG_SERVER_ENDPOINT", "")
    if server_endpoint:
        if ":" not in server_endpoint:
            server_endpoint = f"{server_endpoint}:{listen_port}"
    else:
        server_endpoint = f"YOUR_SERVER_IP:{listen_port}"

    # 构建配置
    client_config = f"""[Interface]
PrivateKey = {private_key or 'YOUR_PRIVATE_KEY'}
Address = {client_ip}
DNS = 1.1.1.1

[Peer]
PublicKey = {server_public_key}
Endpoint = {server_endpoint}
AllowedIPs = 0.0.0.0/0
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
    """列出所有出口（PIA + 自定义 + Direct）"""
    pia_result = []
    custom_result = []
    direct_result = []

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

    return {"pia": pia_result, "custom": custom_result, "direct": direct_result}


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

    # 重新渲染配置并重载
    reload_status = ""
    try:
        _regenerate_and_reload()
        reload_status = "，已重载配置"
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

    # 构建更新字段
    updates = {}
    if payload.description is not None:
        updates["description"] = payload.description
    if payload.server is not None:
        updates["server"] = payload.server
    if payload.port is not None:
        updates["port"] = payload.port
    if payload.private_key is not None:
        updates["private_key"] = payload.private_key
    if payload.public_key is not None:
        updates["public_key"] = payload.public_key
    if payload.address is not None:
        updates["address"] = payload.address
    if payload.mtu is not None:
        updates["mtu"] = payload.mtu
    if payload.dns is not None:
        updates["dns"] = payload.dns
    if payload.pre_shared_key is not None:
        updates["pre_shared_key"] = payload.pre_shared_key
    if payload.reserved is not None:
        updates["reserved"] = payload.reserved

    db.update_custom_egress(tag, **updates)

    # 重新渲染配置并重载
    reload_status = ""
    try:
        _regenerate_and_reload()
        reload_status = "，已重载配置"
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

    # 重新渲染配置并重载
    reload_status = ""
    try:
        _regenerate_and_reload()
        reload_status = "，已重载配置"
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

    # 构建更新字段
    updates = {}
    if payload.description is not None:
        updates["description"] = payload.description
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
        print(f"[api] 应用广告拦截规则失败: {exc}")
        raise HTTPException(status_code=500, detail=f"应用失败: {exc}")

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
    if not HAS_DATABASE or not USER_DB_PATH.exists() and GEODATA_DB_PATH.exists():
        raise HTTPException(status_code=503, detail="数据库不可用")

    db = get_db(str(GEODATA_DB_PATH), str(USER_DB_PATH))

    # 收集所有域名
    all_domains = []
    for list_id in payload.list_ids:
        # 直接从数据库读取域名
        try:
            domains = db.geodata.get_domains_by_list(list_id, limit=100000)
            all_domains.extend(domains)
        except Exception as e:
            # 如果数据库中找不到，尝试从文件解析
            try:
                data = parse_domain_list_file(list_id)
                all_domains.extend(data.get("domains", []))
            except Exception:
                print(f"跳过列表 {list_id}: {e}")

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
    if HAS_DATABASE and USER_DB_PATH.exists() and GEODATA_DB_PATH.exists():
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
    if HAS_DATABASE and USER_DB_PATH.exists() and GEODATA_DB_PATH.exists():
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

    # 如果 JSON 不存在或为空，从 SQLite 加载
    if not ipv4_cidrs and not ipv6_cidrs:
        try:
            db = get_db()
            ipv4_cidrs = db.get_country_ips(cc.upper(), ip_version=4)
            ipv6_cidrs = db.get_country_ips(cc.upper(), ip_version=6)
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
    if not HAS_DATABASE or not USER_DB_PATH.exists() and GEODATA_DB_PATH.exists():
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
            "address": ingress_config.get("interface", {}).get("address", "10.23.0.1/24"),
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
        pia_username = os.environ.get("PIA_USERNAME", "")
        pia_password = os.environ.get("PIA_PASSWORD", "")
        if pia_username and pia_password:
            pia_creds = {"username": pia_username, "password": pia_password}
            backup_data["pia_credentials"] = encrypt_sensitive_data(
                json.dumps(pia_creds), payload.password
            )

    # 6. 导出路由规则（从数据库）
    if HAS_DATABASE and USER_DB_PATH.exists() and GEODATA_DB_PATH.exists():
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
                    "address": ingress_public.get("interface", {}).get("address", "10.23.0.1/24"),
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
                os.environ["PIA_USERNAME"] = creds["username"]
                os.environ["PIA_PASSWORD"] = creds["password"]
                results["pia_credentials"] = True
        except Exception as exc:
            print(f"[backup] 导入 PIA 凭证失败: {exc}")

    # 6. 导入路由规则（到数据库）- 使用批量处理
    if "custom_rules" in backup_data:
        try:
            rules_data = backup_data["custom_rules"]
            rules_list = rules_data.get("rules", [])

            if HAS_DATABASE and USER_DB_PATH.exists() and GEODATA_DB_PATH.exists():
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
        "has_pia_credentials": bool(os.environ.get("PIA_USERNAME")),
        "has_settings": bool(settings.get("server_endpoint")),
    }


# ============ Database API Endpoints ============

@app.get("/api/db/stats")
def api_get_db_stats():
    """获取数据库统计信息"""
    if not HAS_DATABASE or not USER_DB_PATH.exists() and GEODATA_DB_PATH.exists():
        raise HTTPException(status_code=503, detail="数据库不可用")

    db = get_db(str(GEODATA_DB_PATH), str(USER_DB_PATH))
    return db.get_statistics()


@app.get("/api/db/rules")
def api_get_db_rules(enabled_only: bool = True):
    """获取数据库中的所有路由规则"""
    if not HAS_DATABASE or not USER_DB_PATH.exists() and GEODATA_DB_PATH.exists():
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
    if not HAS_DATABASE or not USER_DB_PATH.exists() and GEODATA_DB_PATH.exists():
        raise HTTPException(status_code=503, detail="数据库不可用")

    db = get_db(str(GEODATA_DB_PATH), str(USER_DB_PATH))
    success = db.update_routing_rule(rule_id, outbound, priority, enabled)

    if not success:
        raise HTTPException(status_code=404, detail=f"规则 ID {rule_id} 不存在")

    return {"message": f"规则 ID {rule_id} 已更新"}


@app.get("/api/db/countries")
def api_get_countries(limit: int = 100):
    """获取国家列表"""
    if not HAS_DATABASE or not USER_DB_PATH.exists() and GEODATA_DB_PATH.exists():
        raise HTTPException(status_code=503, detail="数据库不可用")

    db = get_db(str(GEODATA_DB_PATH), str(USER_DB_PATH))
    countries = db.get_countries(limit=limit)
    return {"countries": countries, "count": len(countries)}


@app.get("/api/db/countries/{country_code}")
def api_get_country(country_code: str):
    """获取国家详情"""
    if not HAS_DATABASE or not USER_DB_PATH.exists() and GEODATA_DB_PATH.exists():
        raise HTTPException(status_code=503, detail="数据库不可用")

    db = get_db(str(GEODATA_DB_PATH), str(USER_DB_PATH))
    country = db.get_country(country_code)

    if not country:
        raise HTTPException(status_code=404, detail=f"国家 {country_code} 不存在")

    return country


@app.get("/api/db/countries/{country_code}/ips")
def api_get_country_ips(
    country_code: str,
    ip_version: Optional[int] = None,
    limit: int = 1000
):
    """获取国家的 IP 范围"""
    if not HAS_DATABASE or not USER_DB_PATH.exists() and GEODATA_DB_PATH.exists():
        raise HTTPException(status_code=503, detail="数据库不可用")

    db = get_db(str(GEODATA_DB_PATH), str(USER_DB_PATH))
    country = db.get_country(country_code)

    if not country:
        raise HTTPException(status_code=404, detail=f"国家 {country_code} 不存在")

    ips = db.get_country_ips(country_code, ip_version=ip_version, limit=limit)
    return {
        "country": country,
        "ip_count": len(ips),
        "ips": ips
    }


@app.get("/api/db/domain-categories")
def api_get_domain_categories(group_type: Optional[str] = None):
    """获取域名分类"""
    if not HAS_DATABASE or not USER_DB_PATH.exists() and GEODATA_DB_PATH.exists():
        raise HTTPException(status_code=503, detail="数据库不可用")

    db = get_db(str(GEODATA_DB_PATH), str(USER_DB_PATH))
    categories = db.get_domain_categories(group_type=group_type)
    return {"categories": categories, "count": len(categories)}


@app.get("/api/db/domain-lists/{list_id}")
def api_get_domain_list(list_id: str, include_domains: bool = False):
    """获取域名列表详情"""
    if not HAS_DATABASE or not USER_DB_PATH.exists() and GEODATA_DB_PATH.exists():
        raise HTTPException(status_code=503, detail="数据库不可用")

    db = get_db(str(GEODATA_DB_PATH), str(USER_DB_PATH))

    if include_domains:
        list_data = db.get_domain_list_with_domains(list_id, limit=5000)
    else:
        list_data = db.get_domain_list(list_id)

    if not list_data:
        raise HTTPException(status_code=404, detail=f"域名列表 {list_id} 不存在")

    return list_data


@app.post("/api/config/regenerate")
def api_regenerate_config():
    """重新生成 sing-box 配置（包含数据库规则）"""
    if not HAS_DATABASE or not USER_DB_PATH.exists() and GEODATA_DB_PATH.exists():
        raise HTTPException(status_code=503, detail="数据库不可用")

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

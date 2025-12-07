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
GEODATA_DB_PATH = Path(os.environ.get("GEODATA_DB_PATH", "/etc/sing-box/geoip-geodata.db"))
USER_DB_PATH = Path(os.environ.get("USER_DB_PATH", "/etc/sing-box/user-config.db"))
PIA_PROFILES_FILE = Path(os.environ.get("PIA_PROFILES_FILE", "/etc/sing-box/pia/profiles.yml"))
PIA_PROFILES_OUTPUT = Path(os.environ.get("PIA_PROFILES_OUTPUT", "/etc/sing-box/pia-profiles.json"))
WG_CONFIG_PATH = Path(os.environ.get("WG_CONFIG_PATH", "/etc/sing-box/wireguard/server.json"))
CUSTOM_RULES_FILE = Path(os.environ.get("CUSTOM_RULES_FILE", "/etc/sing-box/custom-rules.json"))
DOMAIN_CATALOG_FILE = Path(os.environ.get("DOMAIN_CATALOG_FILE", "/etc/sing-box/domain-catalog.json"))
DOMAIN_LIST_DIR = Path(os.environ.get("DOMAIN_LIST_DIR", "/etc/sing-box/domain-list/data"))
IP_CATALOG_FILE = Path(os.environ.get("IP_CATALOG_FILE", "/etc/sing-box/ip-catalog.json"))
IP_LIST_DIR = Path(os.environ.get("IP_LIST_DIR", "/etc/sing-box/ip-list/country"))
CUSTOM_CATEGORY_ITEMS_FILE = Path(os.environ.get("CUSTOM_CATEGORY_ITEMS_FILE", "/etc/sing-box/custom-category-items.json"))
SETTINGS_FILE = Path(os.environ.get("SETTINGS_FILE", "/etc/sing-box/settings.json"))
CUSTOM_EGRESS_FILE = Path(os.environ.get("CUSTOM_EGRESS_FILE", "/etc/sing-box/custom-egress.json"))
ENTRY_DIR = Path("/usr/local/bin")

PIA_SERVERLIST_URL = "https://serverlist.piaservers.net/vpninfo/servers/v6"

CONFIG_LOCK = threading.Lock()

# 缓存 PIA 地区列表（有效期 1 小时）
_pia_regions_cache: Dict[str, Any] = {"data": None, "timestamp": 0}


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


def load_json_config() -> dict:
    if not CONFIG_PATH.exists():
        raise HTTPException(status_code=500, detail="配置文件不存在")
    with CONFIG_LOCK:
        data = json.loads(CONFIG_PATH.read_text())
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
        return {"server_endpoint": "", "listen_port": 36100}
    return json.loads(SETTINGS_FILE.read_text())


def save_settings(data: Dict[str, Any]) -> None:
    """保存系统设置"""
    SETTINGS_FILE.parent.mkdir(parents=True, exist_ok=True)
    SETTINGS_FILE.write_text(json.dumps(data, indent=2, ensure_ascii=False))


def load_custom_egress() -> Dict[str, Any]:
    """加载自定义出口配置"""
    if not CUSTOM_EGRESS_FILE.exists():
        return {"egress": []}
    return json.loads(CUSTOM_EGRESS_FILE.read_text())


def save_custom_egress(data: Dict[str, Any]) -> None:
    """保存自定义出口配置"""
    CUSTOM_EGRESS_FILE.parent.mkdir(parents=True, exist_ok=True)
    CUSTOM_EGRESS_FILE.write_text(json.dumps(data, indent=2, ensure_ascii=False))


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


@app.get("/api/endpoints")
def api_list_endpoints():
    config = load_json_config()
    return {"endpoints": config.get("endpoints", [])}


@app.put("/api/endpoints/{tag}")
def api_update_endpoint(tag: str, payload: EndpointUpdateRequest):
    config = load_json_config()
    endpoints = config.get("endpoints", [])
    for endpoint in endpoints:
        if endpoint.get("tag") != tag:
            continue
        if payload.address is not None:
            endpoint["address"] = payload.address
        if payload.private_key is not None:
            endpoint["private_key"] = payload.private_key
        if payload.mtu is not None:
            endpoint["mtu"] = payload.mtu
        if payload.workers is not None:
            endpoint["workers"] = payload.workers
        if payload.peers is not None:
            endpoint["peers"] = [peer.dict(exclude_none=True) for peer in payload.peers]
        save_json_config(config)
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
        tag = name.replace("_", "-")
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

    available_outbounds = ["direct"]
    default_outbound = "direct"

    if config_path.exists():
        config = json.loads(config_path.read_text())
        route = config.get("route", {})
        default_outbound = route.get("final", "direct")

        # 提取可用出口
        for endpoint in config.get("endpoints", []):
            if endpoint.get("type") == "wireguard":
                available_outbounds.append(endpoint.get("tag"))

    # 从数据库读取自定义规则
    if HAS_DATABASE and USER_DB_PATH.exists() and GEODATA_DB_PATH.exists():
        db = get_db(str(GEODATA_DB_PATH), str(USER_DB_PATH))
        db_rules = db.get_routing_rules(enabled_only=True)

        # 按 outbound 分组规则
        rules_by_tag = {}
        for rule in db_rules:
            rule_type = rule["rule_type"]
            target = rule["target"]
            outbound = rule["outbound"]

            # 使用 outbound 作为 tag（或创建唯一 tag）
            tag = f"custom-{outbound}"

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
    """更新路由规则（数据库版本）"""
    if HAS_DATABASE and USER_DB_PATH.exists() and GEODATA_DB_PATH.exists():
        # 使用数据库存储（方案 B）
        db = get_db(str(GEODATA_DB_PATH), str(USER_DB_PATH))

        # 先删除所有现有的自定义规则（type == "custom"）
        # 注意：只删除 type 为 custom 的规则，保留其他规则
        all_rules = db.get_routing_rules(enabled_only=False)
        for rule in all_rules:
            # 删除所有规则以重新创建（简化实现）
            db.delete_routing_rule(rule["id"])

        # 添加新规则到数据库
        for rule in payload.rules:
            # 为每个域名创建一条规则
            if rule.domains:
                for domain in rule.domains:
                    db.add_routing_rule("domain", domain, rule.outbound, priority=0)

            # 为每个关键词创建一条规则
            if rule.domain_keywords:
                for keyword in rule.domain_keywords:
                    db.add_routing_rule("domain_keyword", keyword, rule.outbound, priority=0)

            # 为每个 IP 创建一条规则
            if rule.ip_cidrs:
                for cidr in rule.ip_cidrs:
                    db.add_routing_rule("ip", cidr, rule.outbound, priority=0)

        # 保存到 JSON 作为备份
        custom_data = {
            "rules": [r.dict(exclude_none=True) for r in payload.rules],
            "default_outbound": payload.default_outbound,
        }
        save_custom_rules(custom_data)

        return {"message": "路由规则已保存到数据库"}
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
    """添加自定义路由规则（数据库版本）"""
    # 验证至少有一种匹配规则
    if not payload.domains and not payload.domain_keywords and not payload.ip_cidrs:
        raise HTTPException(status_code=400, detail="至少需要提供一种匹配规则（域名、关键词或 IP）")

    if not HAS_DATABASE or not USER_DB_PATH.exists() and GEODATA_DB_PATH.exists():
        raise HTTPException(status_code=500, detail="数据库不可用")

    db = get_db(str(GEODATA_DB_PATH), str(USER_DB_PATH))
    added_count = 0

    try:
        # 添加域名规则
        if payload.domains:
            for domain in payload.domains:
                db.add_routing_rule("domain", domain, payload.outbound, priority=0)
                added_count += 1

        # 添加域名关键词规则
        if payload.domain_keywords:
            for keyword in payload.domain_keywords:
                db.add_routing_rule("domain_keyword", keyword, payload.outbound, priority=0)
                added_count += 1

        # 添加 IP 规则
        if payload.ip_cidrs:
            for cidr in payload.ip_cidrs:
                db.add_routing_rule("ip", cidr, payload.outbound, priority=0)
                added_count += 1

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

        # 将生成的配置复制到基础配置路径，以便 SIGHUP 能加载到新配置
        shutil.copy(generated_config, CONFIG_PATH)

        # 尝试 SIGHUP 热重载
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
        tag = name.replace("_", "-")
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
                    "listen_port": 36100,
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
                listen_port=36100,
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
        "listen_port": server.get("listen_port", 36100) if server else 36100,
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
        listen_port=interface.get("listen_port", 36100),
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


def get_peer_handshake_info() -> dict:
    """获取 peer 握手状态（从 wg show）"""
    handshakes = {}
    try:
        result = subprocess.run(
            ["wg", "show", "wg-ingress", "latest-handshakes"],
            capture_output=True, text=True, check=True
        )
        for line in result.stdout.strip().split("\n"):
            if "\t" in line:
                pubkey, timestamp = line.split("\t")
                handshakes[pubkey] = int(timestamp) if timestamp != "0" else 0
    except Exception:
        pass
    return handshakes


def get_peer_transfer_info() -> dict:
    """获取 peer 流量统计（从 wg show）"""
    transfers = {}
    try:
        result = subprocess.run(
            ["wg", "show", "wg-ingress", "transfer"],
            capture_output=True, text=True, check=True
        )
        for line in result.stdout.strip().split("\n"):
            parts = line.split("\t")
            if len(parts) >= 3:
                pubkey, rx, tx = parts[0], int(parts[1]), int(parts[2])
                transfers[pubkey] = {"rx": rx, "tx": tx}
    except Exception:
        pass
    return transfers


def apply_ingress_config(config: dict) -> dict:
    """应用入口 WireGuard 配置到系统"""
    interface = config.get("interface", {})
    iface_name = interface.get("name", "wg-ingress")

    try:
        # 检查接口是否存在
        result = subprocess.run(["ip", "link", "show", iface_name], capture_output=True)
        iface_exists = result.returncode == 0

        if not iface_exists:
            # 创建接口
            subprocess.run(["ip", "link", "add", iface_name, "type", "wireguard"], check=True)

        # 配置接口
        private_key = interface.get("private_key", "")
        listen_port = interface.get("listen_port", 36100)

        # 设置私钥（通过临时文件）
        import tempfile
        with tempfile.NamedTemporaryFile(mode='w', delete=False) as f:
            f.write(private_key)
            key_file = f.name
        try:
            subprocess.run(["wg", "set", iface_name, "private-key", key_file, "listen-port", str(listen_port)], check=True)
        finally:
            os.unlink(key_file)

        # 清除现有 peers
        existing_peers = subprocess.run(
            ["wg", "show", iface_name, "peers"],
            capture_output=True, text=True
        ).stdout.strip().split("\n")

        for peer_key in existing_peers:
            if peer_key:
                subprocess.run(["wg", "set", iface_name, "peer", peer_key, "remove"], capture_output=True)

        # 添加 peers
        for peer in config.get("peers", []):
            cmd = ["wg", "set", iface_name, "peer", peer["public_key"]]
            allowed_ips = ",".join(peer.get("allowed_ips", []))
            if allowed_ips:
                cmd.extend(["allowed-ips", allowed_ips])
            subprocess.run(cmd, check=True)

        # 配置 IP 地址
        address = interface.get("address", "10.23.0.1/24")
        # 先删除旧地址
        subprocess.run(["ip", "addr", "flush", "dev", iface_name], capture_output=True)
        subprocess.run(["ip", "addr", "add", address, "dev", iface_name], check=True)

        # 启动接口
        subprocess.run(["ip", "link", "set", iface_name, "up"], check=True)

        # 设置 MTU
        mtu = interface.get("mtu", 1420)
        subprocess.run(["ip", "link", "set", iface_name, "mtu", str(mtu)], check=True)

        return {"success": True, "message": "配置已应用"}
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
    listen_port = interface.get("listen_port", 36100)
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
        "listen_port": interface.get("listen_port", 36100),
    }


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
    """列出所有出口（PIA + 自定义）"""
    pia_result = []
    custom_result = []

    # 从数据库获取 PIA profiles
    db = get_db(str(GEODATA_DB_PATH), str(USER_DB_PATH))
    pia_profiles = db.get_pia_profiles(enabled_only=False)

    for p in pia_profiles:
        name = p.get("name", "")
        tag = name.replace("_", "-")
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
    custom_egress = load_custom_egress().get("egress", [])
    for eg in custom_egress:
        custom_result.append({
            "tag": eg.get("tag", ""),
            "type": "custom",
            "description": eg.get("description", ""),
            "server": eg.get("server", ""),
            "port": eg.get("port", 51820),
            "is_configured": True,
        })

    return {"pia": pia_result, "custom": custom_result}


@app.get("/api/egress/custom")
def api_list_custom_egress():
    """列出所有自定义出口"""
    data = load_custom_egress()
    # 不返回敏感信息（私钥）
    result = []
    for eg in data.get("egress", []):
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
    data = load_custom_egress()
    egress_list = data.get("egress", [])

    # 检查 tag 是否已存在
    existing_tags = {eg.get("tag") for eg in egress_list}
    if payload.tag in existing_tags:
        raise HTTPException(status_code=400, detail=f"出口 '{payload.tag}' 已存在")

    # 检查是否与 PIA profiles 冲突（从数据库检查）
    db = get_db(str(GEODATA_DB_PATH), str(USER_DB_PATH))
    pia_profiles = db.get_pia_profiles(enabled_only=False)
    pia_tags = {p.get("name", "").replace("_", "-") for p in pia_profiles}
    if payload.tag in pia_tags:
        raise HTTPException(status_code=400, detail=f"出口 '{payload.tag}' 与 PIA 线路冲突")

    # 添加新出口
    new_egress = {
        "tag": payload.tag,
        "description": payload.description,
        "server": payload.server,
        "port": payload.port,
        "private_key": payload.private_key,
        "public_key": payload.public_key,
        "address": payload.address,
        "mtu": payload.mtu,
        "dns": payload.dns,
    }
    if payload.pre_shared_key:
        new_egress["pre_shared_key"] = payload.pre_shared_key
    if payload.reserved:
        new_egress["reserved"] = payload.reserved

    egress_list.append(new_egress)
    data["egress"] = egress_list
    save_custom_egress(data)

    # 重新渲染配置并重载
    try:
        _regenerate_and_reload()
    except Exception as exc:
        print(f"[api] 重载配置失败: {exc}")

    return {
        "message": f"出口 '{payload.tag}' 已创建",
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

        return {
            "parsed": result,
            "valid": len(errors) == 0,
            "errors": errors,
        }
    except Exception as exc:
        raise HTTPException(status_code=400, detail=f"解析失败: {exc}")


@app.put("/api/egress/custom/{tag}")
def api_update_custom_egress(tag: str, payload: CustomEgressUpdateRequest):
    """更新自定义出口"""
    data = load_custom_egress()
    egress_list = data.get("egress", [])

    # 查找出口
    found_idx = None
    for i, eg in enumerate(egress_list):
        if eg.get("tag") == tag:
            found_idx = i
            break

    if found_idx is None:
        raise HTTPException(status_code=404, detail=f"出口 '{tag}' 不存在")

    # 更新字段
    eg = egress_list[found_idx]
    if payload.description is not None:
        eg["description"] = payload.description
    if payload.server is not None:
        eg["server"] = payload.server
    if payload.port is not None:
        eg["port"] = payload.port
    if payload.private_key is not None:
        eg["private_key"] = payload.private_key
    if payload.public_key is not None:
        eg["public_key"] = payload.public_key
    if payload.address is not None:
        eg["address"] = payload.address
    if payload.mtu is not None:
        eg["mtu"] = payload.mtu
    if payload.dns is not None:
        eg["dns"] = payload.dns
    if payload.pre_shared_key is not None:
        eg["pre_shared_key"] = payload.pre_shared_key
    if payload.reserved is not None:
        eg["reserved"] = payload.reserved

    save_custom_egress(data)

    # 重新渲染配置并重载
    try:
        _regenerate_and_reload()
    except Exception as exc:
        print(f"[api] 重载配置失败: {exc}")

    return {"message": f"出口 '{tag}' 已更新"}


@app.delete("/api/egress/custom/{tag}")
def api_delete_custom_egress(tag: str):
    """删除自定义出口"""
    data = load_custom_egress()
    egress_list = data.get("egress", [])

    # 查找出口
    found_idx = None
    for i, eg in enumerate(egress_list):
        if eg.get("tag") == tag:
            found_idx = i
            break

    if found_idx is None:
        raise HTTPException(status_code=404, detail=f"出口 '{tag}' 不存在")

    # 删除
    egress_list.pop(found_idx)
    data["egress"] = egress_list
    save_custom_egress(data)

    # 重新渲染配置并重载
    try:
        _regenerate_and_reload()
    except Exception as exc:
        print(f"[api] 重载配置失败: {exc}")

    return {"message": f"出口 '{tag}' 已删除"}


def _regenerate_and_reload():
    """重新生成配置并重载 sing-box"""
    # 检查是否有 PIA 配置
    if PIA_PROFILES_OUTPUT.exists():
        # 调用 render_singbox.py
        result = subprocess.run(
            ["python3", str(ENTRY_DIR / "render_singbox.py")],
            capture_output=True,
            text=True,
        )
        if result.returncode != 0:
            print(f"[api] render_singbox.py 失败: {result.stderr}")
    # 重载 sing-box
    reload_singbox()


# ============ Domain List Catalog APIs ============

def load_domain_catalog() -> dict:
    """加载域名列表目录（从数据库读取）"""
    db = get_db(str(GEODATA_DB_PATH), str(USER_DB_PATH))

    # 获取所有分类
    categories = {}
    db_categories = db.geodata.get_domain_categories()
    for cat in db_categories:
        categories[cat["id"]] = {
            "name": cat["name"],
            "description": cat.get("description", ""),
            "group": cat.get("group_type", "type"),
            "recommended_exit": cat.get("recommended_exit", "direct"),
            "lists": []
        }

    # 获取所有域名列表
    domain_lists = db.geodata.get_domain_lists()

    # 为每个列表获取样本域名
    for dlist in domain_lists:
        list_id = dlist["id"]
        domain_count = dlist["domain_count"]

        # 获取样本域名（最多10个）
        sample_domains = db.geodata.get_domains_by_list(list_id, limit=10)

        # 获取该列表所属的分类
        list_categories = db.geodata.get_list_categories(list_id)

        # 添加到相应分类
        for cat_id in list_categories:
            if cat_id in categories:
                categories[cat_id]["lists"].append({
                    "id": list_id,
                    "domain_count": domain_count,
                    "sample_domains": sample_domains
                })

    return {"categories": categories}


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
def api_get_domain_list(list_id: str):
    """获取指定域名列表的完整域名"""
    # 先尝试从缓存的 catalog 获取
    catalog = load_domain_catalog()
    lists = catalog.get("lists", {})

    if list_id in lists:
        return {
            "id": list_id,
            "domains": lists[list_id].get("domains", []),
            "full_domains": lists[list_id].get("full_domains", []),
        }

    # 如果不在 catalog 中，尝试直接解析文件
    if not DOMAIN_LIST_DIR.exists():
        raise HTTPException(status_code=404, detail="域名列表目录不存在")

    data = parse_domain_list_file(list_id)
    if not data["domains"] and not data["full_domains"]:
        raise HTTPException(status_code=404, detail=f"域名列表 {list_id} 不存在或为空")

    return {
        "id": list_id,
        "domains": data["domains"],
        "full_domains": data["full_domains"],
    }


@app.get("/api/domain-catalog/search")
def api_search_domain_lists(q: str):
    """搜索域名列表（从数据库）"""
    db = get_db(str(GEODATA_DB_PATH), str(USER_DB_PATH))
    results = db.search_domain_lists(q, limit=50)
    return {"results": [{"id": r["id"], "name": r["id"]} for r in results]}


class QuickRuleRequest(BaseModel):
    """快速创建规则请求"""
    list_ids: List[str] = Field(..., description="域名列表 ID 列表")
    outbound: str = Field(..., description="出口线路 tag")
    tag: Optional[str] = Field(None, description="规则集标签，不填则自动生成")


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

    # 生成规则标签
    tag = payload.tag or f"custom-{'-'.join(payload.list_ids[:3])}"
    if not tag.startswith("custom-"):
        tag = f"custom-{tag}"

    # 将所有域名添加到数据库
    added_count = 0
    for domain in all_domains:
        try:
            db.add_routing_rule("domain", domain, payload.outbound, priority=0)
            added_count += 1
        except Exception as e:
            # 可能是重复规则，跳过
            print(f"跳过域名 {domain}: {e}")

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
    """加载 IP 列表目录（从数据库读取）"""
    db = get_db(str(GEODATA_DB_PATH), str(USER_DB_PATH))

    # 获取所有国家
    all_countries = db.geodata.get_countries(limit=500)

    countries = {}
    for country in all_countries:
        code = country["code"]
        countries[code] = {
            "country_code": code.upper(),
            "country_name": country["name"],
            "display_name": COUNTRY_NAMES.get(code, country["display_name"]),
            "ipv4_count": country.get("ipv4_count", 0),
            "ipv6_count": country.get("ipv6_count", 0),
            "recommended_exit": RECOMMENDED_IP_EXITS.get(code, country.get("recommended_exit", "direct"))
        }

    stats = {
        "total_countries": len(countries),
        "total_ipv4": sum(c.get("ipv4_count", 0) for c in countries.values()),
        "total_ipv6": sum(c.get("ipv6_count", 0) for c in countries.values())
    }

    return {"countries": countries, "stats": stats}


def get_country_ip_info(country_code: str) -> dict:
    """获取国家 IP 信息（从数据库读取）"""
    db = get_db(str(GEODATA_DB_PATH), str(USER_DB_PATH))

    # 获取国家信息
    country_info = db.geodata.get_country(country_code.lower())
    if not country_info:
        return {}

    # 获取该国家的 IP 范围
    ipv4_cidrs = db.geodata.get_country_ips(country_code.lower(), ip_version=4, limit=100000)
    ipv6_cidrs = db.geodata.get_country_ips(country_code.lower(), ip_version=6, limit=100000)

    return {
        "country_code": country_code.upper(),
        "country_name": country_info["name"],
        "display_name": COUNTRY_NAMES.get(country_code.lower(), country_info["display_name"]),
        "ipv4_cidrs": ipv4_cidrs,
        "ipv6_cidrs": ipv6_cidrs,
        "ipv4_count": len(ipv4_cidrs),
        "ipv6_count": len(ipv6_cidrs),
        "recommended_exit": RECOMMENDED_IP_EXITS.get(country_code.lower(), country_info.get("recommended_exit", "direct")),
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
    """搜索国家/地区"""
    q_lower = q.lower()
    results = []
    db = get_db(str(GEODATA_DB_PATH), str(USER_DB_PATH))

    # 从数据库获取所有国家
    all_countries = db.geodata.get_countries(limit=500)

    # 搜索国家代码和名称
    for country in all_countries:
        cc = country["code"].lower()
        name = country["name"]
        display_name = COUNTRY_NAMES.get(cc, country["display_name"])

        if q_lower in cc or q_lower in name.lower() or q_lower in display_name.lower():
            results.append({"country_code": cc.upper(), "display_name": display_name})

    return {"results": results[:30]}


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

    # 生成规则标签
    tag = payload.tag or f"ip-{'-'.join(payload.country_codes[:3])}"
    if not tag.startswith("ip-"):
        tag = f"ip-{tag}"

    # 使用数据库存储
    if not HAS_DATABASE or not USER_DB_PATH.exists() and GEODATA_DB_PATH.exists():
        raise HTTPException(status_code=503, detail="数据库不可用")

    db = get_db(str(GEODATA_DB_PATH), str(USER_DB_PATH))

    # 将所有 IP CIDR 添加到数据库
    added_count = 0
    for cidr in all_cidrs:
        try:
            db.add_routing_rule("ip", cidr, payload.outbound, priority=0)
            added_count += 1
        except Exception as e:
            # 可能是重复规则，跳过
            print(f"跳过 CIDR {cidr}: {e}")

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
            "listen_port": ingress_config.get("interface", {}).get("listen_port", 36100),
            "mtu": ingress_config.get("interface", {}).get("mtu", 1420),
        },
        "peer_count": len(ingress_config.get("peers", [])),
    }
    backup_data["ingress"] = ingress_public
    backup_data["ingress_sensitive"] = encrypt_sensitive_data(
        json.dumps(ingress_sensitive), payload.password
    )

    # 3. 导出自定义出口配置
    custom_egress = load_custom_egress()
    egress_list = custom_egress.get("egress", [])

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
    db = get_db(str(GEODATA_DB_PATH), str(USER_DB_PATH))
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
                    "listen_port": ingress_public.get("interface", {}).get("listen_port", 36100),
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

    # 3. 导入自定义出口
    if "custom_egress" in backup_data and "custom_egress_sensitive" in backup_data:
        try:
            sensitive_json = decrypt_sensitive_data(
                backup_data["custom_egress_sensitive"], payload.password
            )
            sensitive_list = json.loads(sensitive_json)
            sensitive_map = {s["tag"]: s for s in sensitive_list}

            # 合并公开和敏感数据
            egress_list = []
            for eg in backup_data["custom_egress"]:
                tag = eg.get("tag", "")
                sens = sensitive_map.get(tag, {})
                egress_list.append({
                    "tag": tag,
                    "description": eg.get("description", ""),
                    "server": eg.get("server", ""),
                    "port": eg.get("port", 51820),
                    "address": eg.get("address", ""),
                    "mtu": eg.get("mtu", 1420),
                    "dns": eg.get("dns", "1.1.1.1"),
                    "private_key": sens.get("private_key", ""),
                    "public_key": sens.get("public_key", ""),
                    "pre_shared_key": sens.get("pre_shared_key", ""),
                    "reserved": sens.get("reserved"),
                })

            if payload.merge_mode == "merge":
                existing = load_custom_egress()
                existing_tags = {e.get("tag") for e in existing.get("egress", [])}
                for eg in egress_list:
                    if eg.get("tag") not in existing_tags:
                        existing.setdefault("egress", []).append(eg)
                egress_list = existing.get("egress", [])

            save_custom_egress({"egress": egress_list})
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

    # 6. 导入路由规则（到数据库）
    if "custom_rules" in backup_data:
        try:
            rules_data = backup_data["custom_rules"]
            rules_list = rules_data.get("rules", [])

            if HAS_DATABASE and USER_DB_PATH.exists() and GEODATA_DB_PATH.exists():
                db = get_db(str(GEODATA_DB_PATH), str(USER_DB_PATH))

                # 如果是替换模式，先删除所有规则
                if payload.merge_mode == "replace":
                    existing_rules = db.get_routing_rules(enabled_only=False)
                    for rule in existing_rules:
                        db.delete_routing_rule(rule["id"])

                # 导入规则到数据库
                imported_count = 0
                for rule in rules_list:
                    outbound = rule.get("outbound", "direct")

                    # 导入域名规则
                    for domain in rule.get("domains", []):
                        try:
                            db.add_routing_rule("domain", domain, outbound, priority=0)
                            imported_count += 1
                        except Exception as e:
                            print(f"跳过域名 {domain}: {e}")

                    # 导入域名关键词规则
                    for keyword in rule.get("domain_keywords", []):
                        try:
                            db.add_routing_rule("domain_keyword", keyword, outbound, priority=0)
                            imported_count += 1
                        except Exception as e:
                            print(f"跳过关键词 {keyword}: {e}")

                    # 导入 IP 规则
                    for cidr in rule.get("ip_cidrs", []):
                        try:
                            db.add_routing_rule("ip", cidr, outbound, priority=0)
                            imported_count += 1
                        except Exception as e:
                            print(f"跳过 IP {cidr}: {e}")

                print(f"[backup] 成功导入 {imported_count} 条规则到数据库")
                results["custom_rules"] = True
            else:
                # 降级到 JSON 文件
                save_custom_rules(rules_data)
                results["custom_rules"] = True
        except Exception as exc:
            print(f"[backup] 导入路由规则失败: {exc}")

    # 重新生成配置
    try:
        _regenerate_and_reload()
    except Exception as exc:
        print(f"[backup] 重载配置失败: {exc}")

    imported_count = sum(1 for v in results.values() if v)
    return {
        "message": f"已导入 {imported_count} 项配置",
        "results": results,
    }


@app.get("/api/backup/status")
def api_backup_status():
    """获取备份相关状态"""
    ingress = load_ingress_config()
    custom_egress = load_custom_egress()
    settings = load_settings()

    # 从数据库获取 PIA profile 数量
    db = get_db(str(GEODATA_DB_PATH), str(USER_DB_PATH))
    pia_profiles = db.get_pia_profiles(enabled_only=False)

    return {
        "encryption_available": HAS_CRYPTO,
        "has_ingress": bool(ingress.get("interface", {}).get("private_key")),
        "ingress_peer_count": len(ingress.get("peers", [])),
        "custom_egress_count": len(custom_egress.get("egress", [])),
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

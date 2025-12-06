#!/usr/bin/env python3
"""
从数据库读取 PIA profiles，调用 PIA 的 API (参考 desktop-pia)
以用户名/密码登录并为每个地区生成 WireGuard 配置。
凭证存储到数据库，供 sing-box 使用。
"""
import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, List, Tuple
from urllib.parse import quote

import requests

# 尝试导入数据库模块（如果可用）
try:
    sys.path.insert(0, '/usr/local/bin')
    from db_helper import get_db
    HAS_DATABASE = True
except ImportError:
    HAS_DATABASE = False

TOKEN_URL = os.environ.get(
    "PIA_TOKEN_URL",
    "https://www.privateinternetaccess.com/api/client/v2/token",
)
SERVERLIST_URL = os.environ.get(
    "PIA_SERVERLIST_URL",
    "https://serverlist.piaservers.net/vpninfo/servers/v6",
)
CA_CERT = os.environ.get(
    "PIA_CA_CERT", "/opt/pia/ca/rsa_4096.crt"
)
GEODATA_DB_PATH = os.environ.get(
    "GEODATA_DB_PATH", "/etc/sing-box/geoip-geodata.db"
)
USER_DB_PATH = os.environ.get(
    "USER_DB_PATH", "/etc/sing-box/user-config.db"
)


class ProvisionError(RuntimeError):
    pass


def require_env(name: str) -> str:
    value = os.environ.get(name)
    if not value:
        raise ProvisionError(f"环境变量 {name} 未设置")
    return value


def load_profiles_from_db() -> List[Dict[str, Any]]:
    """从数据库加载 PIA profiles"""
    if not HAS_DATABASE:
        raise ProvisionError("数据库模块不可用")

    if not Path(USER_DB_PATH).exists():
        raise ProvisionError(f"数据库文件不存在: {USER_DB_PATH}")

    db = get_db(str(GEODATA_DB_PATH), str(USER_DB_PATH))
    profiles = db.get_pia_profiles()

    if not profiles:
        raise ProvisionError("数据库中没有 PIA profiles，请先通过 API 或前端添加")

    return profiles


def fetch_token(username: str, password: str) -> str:
    resp = requests.post(TOKEN_URL, json={"username": username, "password": password}, timeout=10)
    if resp.status_code != 200:
        raise ProvisionError(f"PIA 登陆接口返回 {resp.status_code}: {resp.text}")
    payload = resp.json()
    token = payload.get("token")
    if not token:
        raise ProvisionError(f"登陆响应缺少 token: {payload}")
    return token


def fetch_serverlist() -> Dict[str, Any]:
    resp = requests.get(SERVERLIST_URL, timeout=10)
    resp.raise_for_status()
    # PIA serverlist 响应格式为: JSON数据 + 换行 + base64签名
    # 只解析第一行的 JSON
    text = resp.text
    # 找到 JSON 结束位置 (最后一个 } 或 ])
    json_end = max(text.rfind("}"), text.rfind("]"))
    if json_end == -1:
        raise ProvisionError("无法解析 serverlist 响应")
    json_text = text[:json_end + 1]
    return json.loads(json_text)


def parse_wireguard_groups(serverlist: Dict[str, Any]) -> Dict[str, List[int]]:
    groups: Dict[str, List[int]] = {}
    if "service_configs" in serverlist:
        for group in serverlist["service_configs"]:
            name = group.get("name")
            services = group.get("services", [])
            for svc in services:
                svc_name = svc.get("service") or svc.get("name")
                if svc_name == "wireguard":
                    groups[name] = [int(p) for p in svc.get("ports", [])]
    elif "groups" in serverlist:
        for name, services in serverlist["groups"].items():
            for svc in services:
                svc_name = svc.get("service") or svc.get("name")
                if svc_name == "wireguard":
                    groups[name] = [int(p) for p in svc.get("ports", [])]
    return {k: v for k, v in groups.items() if v}


def find_region(serverlist: Dict[str, Any], region_id: str) -> Dict[str, Any]:
    for region in serverlist.get("regions", []):
        if region.get("id") == region_id:
            return region
    raise ProvisionError(f"地区 {region_id} 不存在于 serverlist")


def pick_server(region: Dict[str, Any], wg_groups: Dict[str, List[int]]) -> Tuple[Dict[str, Any], int]:
    servers = region.get("servers")
    if isinstance(servers, list):
        for entry in servers:
            group_name = entry.get("service_config")
            if group_name in wg_groups:
                return entry, wg_groups[group_name][0]
    elif isinstance(servers, dict):
        for group_name, entries in servers.items():
            if group_name not in wg_groups:
                continue
            entries = entries or []
            if entries:
                return entries[0], wg_groups[group_name][0]
    raise ProvisionError(f"地区 {region.get('id')} 没有可用的 WireGuard 服务组")


def gen_keypair() -> Tuple[str, str]:
    priv = subprocess.run(["wg", "genkey"], check=True, capture_output=True, text=True).stdout.strip()
    pub = subprocess.run(["wg", "pubkey"], check=True, capture_output=True, text=True, input=priv).stdout.strip()
    return priv, pub


def add_key(server: Dict[str, Any], port: int, token: str, public_key: str) -> Dict[str, Any]:
    ip = server.get("ip")
    cn = server.get("cn") or server.get("fqdn")
    if not ip or not cn:
        raise ProvisionError(f"服务器信息不完整: {server}")
    url = f"https://{cn}:{port}/addKey"
    resolve = f"{cn}:{port}:{ip}"
    # URL encode the public key (contains + and / characters)
    encoded_pubkey = quote(public_key, safe='')
    query = f"pubkey={encoded_pubkey}&pt={token}"
    cmd = [
        "curl", "-sS", "--fail", "--retry", "3", "--connect-timeout", "10",
        "--cacert", CA_CERT,
        "--resolve", resolve,
        f"{url}?{query}"
    ]
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        raise ProvisionError(f"向 {cn} 注册 WireGuard key 失败: {result.stderr.strip()}")
    try:
        return json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        raise ProvisionError(f"无法解析 addKey 响应: {result.stdout}") from exc


def main() -> None:
    try:
        profiles = load_profiles_from_db()
        username = require_env("PIA_USERNAME")
        password = require_env("PIA_PASSWORD")
        token = fetch_token(username, password)
        serverlist = fetch_serverlist()
        wg_groups = parse_wireguard_groups(serverlist)
        if not wg_groups:
            raise ProvisionError("serverlist 中未找到 WireGuard 服务组")

        output: Dict[str, Any] = {"profiles": {}}
        for profile in profiles:
            name = profile.get("name")
            region_id = profile.get("region_id")
            if not name or not region_id:
                raise ProvisionError(f"非法 profile 配置: {profile}")
            region = find_region(serverlist, region_id)
            server, port = pick_server(region, wg_groups)
            priv, pub = gen_keypair()
            auth = add_key(server, port, token, pub)
            output["profiles"][name] = {
                "region_id": region_id,
                "description": profile.get("description", name),
                "server_cn": server.get("cn") or server.get("fqdn"),
                "server_ip": auth.get("server_ip"),
                "server_port": auth.get("server_port", port),
                "server_public_key": auth.get("server_key"),
                "peer_ip": auth.get("peer_ip"),
                "server_virtual_ip": auth.get("server_vip"),
                "private_key": priv,
                "public_key": pub,
            }

        # 保存到数据库
        if not HAS_DATABASE or not Path(USER_DB_PATH).exists():
            raise ProvisionError("数据库不可用，无法保存 PIA 凭证")

        db = get_db(str(GEODATA_DB_PATH), str(USER_DB_PATH))
        updated_count = 0
        for name, creds in output["profiles"].items():
            # 更新凭证到数据库
            updated = db.update_pia_credentials(name, creds)
            if updated:
                print(f"[pia] ✓ 已更新 {name} 凭证到数据库")
                updated_count += 1
            else:
                print(f"[pia] 警告: 未找到 profile {name}，请先在数据库中创建")

        if updated_count == 0:
            raise ProvisionError("没有成功更新任何 profile，请检查数据库配置")

        print(f"[pia] 成功更新 {updated_count}/{len(output['profiles'])} 个 profiles")
    except ProvisionError as exc:
        print(f"[pia] 错误: {exc}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()

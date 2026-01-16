#!/usr/bin/env python3
"""
从数据库读取 PIA profiles，调用 PIA 的 API (参考 desktop-pia)
以用户名/密码登录并为每个地区生成 WireGuard 配置。
凭证存储到数据库，供 sing-box 使用。

支持 --profile <name> 参数只重连单个 profile。
"""
import argparse
import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
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


def load_profiles_from_db(profile_name: Optional[str] = None) -> List[Dict[str, Any]]:
    """从数据库加载 PIA profiles

    Args:
        profile_name: 如果指定，只加载该 profile；否则加载所有 profiles
    """
    if not HAS_DATABASE:
        raise ProvisionError("数据库模块不可用")

    if not Path(USER_DB_PATH).exists():
        raise ProvisionError(f"数据库文件不存在: {USER_DB_PATH}")

    db = get_db(str(GEODATA_DB_PATH), str(USER_DB_PATH))
    profiles = db.get_pia_profiles()

    if not profiles:
        raise ProvisionError("数据库中没有 PIA profiles，请先通过 API 或前端添加")

    # 如果指定了 profile_name，只返回匹配的 profile
    if profile_name:
        # 支持 tag 格式（用 - 分隔）和 name 格式（用 _ 分隔）
        profile_key = profile_name.replace("-", "_")
        matching = [p for p in profiles if p.get("name") == profile_key]
        if not matching:
            raise ProvisionError(f"未找到 profile: {profile_name}")
        return matching

    return profiles


def fetch_token(username: str, password: str) -> str:
    resp = requests.get(TOKEN_URL, auth=(username, password), timeout=10)
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


def get_all_servers(region: Dict[str, Any], wg_groups: Dict[str, List[int]]) -> List[Tuple[Dict[str, Any], int]]:
    """获取 region 中所有可用的 WireGuard 服务器

    Returns:
        List of (server, port) tuples
    """
    result = []
    servers = region.get("servers")
    if isinstance(servers, list):
        for entry in servers:
            group_name = entry.get("service_config")
            if group_name in wg_groups:
                result.append((entry, wg_groups[group_name][0]))
    elif isinstance(servers, dict):
        for group_name, entries in servers.items():
            if group_name not in wg_groups:
                continue
            for entry in (entries or []):
                result.append((entry, wg_groups[group_name][0]))
    return result


def pick_server(
    region: Dict[str, Any],
    wg_groups: Dict[str, List[int]],
    exclude_ips: set = None
) -> Tuple[Dict[str, Any], int]:
    """选择一个 WireGuard 服务器，排除已使用的 IP

    PIA 的 addKey API 会覆盖同一 token 对同一服务器注册的公钥，
    所以同一 region 的多个 profile 需要请求不同的服务器。

    Args:
        region: 地区配置
        wg_groups: WireGuard 服务组配置
        exclude_ips: 要排除的服务器 IP 集合

    Returns:
        (server, port) tuple
    """
    exclude_ips = exclude_ips or set()
    all_servers = get_all_servers(region, wg_groups)

    # 优先选择未使用的服务器
    for server, port in all_servers:
        if server.get("ip") not in exclude_ips:
            return server, port

    # 如果所有服务器都已使用，选择第一个（由于使用独立 token，不会导致冲突）
    if all_servers:
        print(f"[pia] 提示: {region.get('id')} 的所有 {len(all_servers)} 个服务器都已被使用，将复用服务器（使用独立 token，不会冲突）")
        return all_servers[0]

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
    parser = argparse.ArgumentParser(description="PIA WireGuard 配置工具")
    parser.add_argument(
        "--profile",
        type=str,
        default=None,
        help="只重连指定的 profile（不指定则重连所有）"
    )
    args = parser.parse_args()

    try:
        profiles = load_profiles_from_db(args.profile)
        username = require_env("PIA_USERNAME")
        password = require_env("PIA_PASSWORD")
        serverlist = fetch_serverlist()
        wg_groups = parse_wireguard_groups(serverlist)
        if not wg_groups:
            raise ProvisionError("serverlist 中未找到 WireGuard 服务组")

        output: Dict[str, Any] = {"profiles": {}}
        # 跟踪每个 region 已使用的服务器 IP，用于负载均衡（分散到不同服务器）
        used_servers: Dict[str, set] = {}
        for profile in profiles:
            name = profile.get("name")
            region_id = profile.get("region_id")
            if not name or not region_id:
                raise ProvisionError(f"非法 profile 配置: {profile}")

            # 每个 profile 获取独立的 token，避免 PIA 的 addKey 覆盖问题
            # PIA 通过 token + server_ip 识别会话，相同 token 请求同一服务器会覆盖之前的注册
            print(f"[pia] {name}: 获取独立 token...")
            token = fetch_token(username, password)

            region = find_region(serverlist, region_id)
            # 获取该 region 已使用的服务器 IP（用于负载均衡，即使有独立 token 也尽量分散）
            exclude_ips = used_servers.get(region_id, set())
            server, port = pick_server(region, wg_groups, exclude_ips)
            # 记录使用的服务器 IP
            server_ip = server.get("ip")
            if region_id not in used_servers:
                used_servers[region_id] = set()
            used_servers[region_id].add(server_ip)
            print(f"[pia] {name}: 请求服务器 {server_ip} (region {region_id} 已使用 {len(used_servers[region_id])} 个服务器)")
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

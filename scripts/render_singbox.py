#!/usr/bin/env python3
"""根据 PIA 生成的 WireGuard 参数，渲染 sing-box 最终配置

支持动态 profiles：
- 读取 profiles.yml 中定义的所有 profiles
- 为每个 profile 创建或更新对应的 WireGuard endpoint（sing-box 1.11+ 格式）
- 路由规则可直接引用 endpoint tag 作为出口
- 应用自定义路由规则（如果有）
"""
import json
import os
import sys
from pathlib import Path
from typing import Any, Dict, List

import yaml

# 尝试导入数据库模块（如果可用）
try:
    sys.path.insert(0, '/usr/local/bin')
    from db_helper import get_db
    HAS_DATABASE = True
except ImportError:
    HAS_DATABASE = False

BASE_CONFIG = Path(os.environ.get("SING_BOX_BASE_CONFIG", "/etc/sing-box/sing-box.json"))
PIA_PROFILES_FILE = Path(os.environ.get("PIA_PROFILES_FILE", "/etc/sing-box/pia/profiles.yml"))
CUSTOM_RULES_FILE = Path(os.environ.get("CUSTOM_RULES_FILE", "/etc/sing-box/custom-rules.json"))
OUTPUT = Path(os.environ.get("SING_BOX_GENERATED_CONFIG", "/etc/sing-box/sing-box.generated.json"))
GEODATA_DB_PATH = os.environ.get("GEODATA_DB_PATH", "/etc/sing-box/geoip-geodata.db")
USER_DB_PATH = os.environ.get("USER_DB_PATH", "/etc/sing-box/user-config.db")


def load_json(path: Path) -> dict:
    if not path.exists():
        raise FileNotFoundError(f"找不到 {path}")
    return json.loads(path.read_text())


def load_yaml(path: Path) -> dict:
    if not path.exists():
        return {}
    return yaml.safe_load(path.read_text()) or {}


def _normalize_peer_ip(peer_ip: str | None) -> str | None:
    if not peer_ip:
        return None
    if "/" not in peer_ip:
        return f"{peer_ip}/32"
    return peer_ip


def load_wireguard_server_config() -> dict | None:
    """从数据库加载 WireGuard 服务器配置"""
    if not HAS_DATABASE or not Path(USER_DB_PATH).exists():
        return None

    db = get_db(str(GEODATA_DB_PATH), str(USER_DB_PATH))

    # 获取服务器配置
    server = db.get_wireguard_server()
    if not server or not server.get("private_key"):
        return None

    # 获取对等端列表
    peers = db.get_wireguard_peers()
    if not peers:
        print("[render] 警告: 没有配置 WireGuard 客户端对等端")
        return None

    return {
        "server": server,
        "peers": peers
    }


def create_wireguard_server_endpoint(wg_config: dict) -> dict:
    """创建 WireGuard 服务器端点（接受客户端连接）"""
    server = wg_config["server"]
    peers = wg_config["peers"]

    # 使用环境变量作为默认端口
    default_wg_port = int(os.environ.get("WG_LISTEN_PORT", "36100"))
    endpoint = {
        "type": "wireguard",
        "tag": "wg-server",
        "system": False,
        "mtu": server.get("mtu", 1420),
        "address": [server.get("address", "10.23.0.1/24")],
        "private_key": server.get("private_key", ""),
        "listen_port": server.get("listen_port", default_wg_port),
        "peers": []
    }

    for peer in peers:
        peer_config = {
            "public_key": peer.get("public_key", ""),
            "allowed_ips": [peer.get("allowed_ips", "10.23.0.2/32")]
        }
        if peer.get("preshared_key"):
            peer_config["pre_shared_key"] = peer["preshared_key"]
        endpoint["peers"].append(peer_config)

    return endpoint


def ensure_wireguard_server_endpoint(config: dict) -> bool:
    """确保 WireGuard 服务器端点存在

    返回 True 如果成功添加/更新，False 如果无配置
    """
    wg_config = load_wireguard_server_config()
    if not wg_config:
        return False

    endpoints = config.setdefault("endpoints", [])

    # 移除旧的 wg-server endpoint
    endpoints[:] = [ep for ep in endpoints if ep.get("tag") != "wg-server"]

    # 创建新的 wg-server endpoint
    wg_endpoint = create_wireguard_server_endpoint(wg_config)
    endpoints.insert(0, wg_endpoint)  # 放在列表开头
    print(f"[render] 创建 WireGuard 服务器端点: wg-server ({len(wg_config['peers'])} 个客户端)")
    return True


def ensure_sniff_action(config: dict) -> None:
    """确保路由规则中有 sniff 动作以支持域名匹配"""
    route = config.setdefault("route", {})
    rules = route.setdefault("rules", [])

    # 检查是否已有 sniff 动作
    has_sniff = any(r.get("action") == "sniff" for r in rules)
    if has_sniff:
        return

    # 在规则列表开头添加 sniff 动作
    sniff_rule = {
        "action": "sniff",
        "sniffer": ["tls", "http"],
        "timeout": "300ms"
    }
    rules.insert(0, sniff_rule)
    print("[render] 添加 sniff 动作以支持域名匹配")


def _create_wireguard_endpoint(tag: str, profile: dict, index: int) -> dict:
    """为 profile 创建新的 WireGuard endpoint（sing-box 1.11+ 格式）

    新格式使用 endpoints 数组，路由可直接引用 endpoint tag 作为出口。
    字段映射：
    - local_address -> address
    - peers[].server -> peers[].address
    - peers[].server_port -> peers[].port
    """
    peer_ip = _normalize_peer_ip(profile.get("peer_ip"))
    # 使用不同的内网地址段
    fallback_address = f"172.31.{30 + index}.2/32"

    return {
        "type": "wireguard",
        "tag": tag,
        "address": [peer_ip] if peer_ip else [fallback_address],
        "private_key": profile.get("private_key", ""),
        "mtu": 1300,
        "peers": [
            {
                "address": profile.get("server_ip", "198.51.100.1"),
                "port": profile.get("server_port", 51820),
                "public_key": profile.get("server_public_key", ""),
                "allowed_ips": ["0.0.0.0/0", "::/0"],
                "persistent_keepalive_interval": 25
            }
        ]
    }


def _patch_wireguard_endpoint(endpoint: dict, profile: dict) -> None:
    """更新现有 WireGuard endpoint（sing-box 1.11+ 格式）"""
    peer_ip = _normalize_peer_ip(profile.get("peer_ip"))
    if peer_ip:
        endpoint["address"] = [peer_ip]
    endpoint["private_key"] = profile.get("private_key")

    peers = endpoint.get("peers") or [{}]
    if not isinstance(peers, list) or not peers:
        peers = [{}]
    peer_conf = peers[0]
    peer_conf["address"] = profile.get("server_ip")
    peer_conf["port"] = profile.get("server_port")
    peer_conf["public_key"] = profile.get("server_public_key")
    if not peer_conf.get("allowed_ips"):
        peer_conf["allowed_ips"] = ["0.0.0.0/0", "::/0"]
    if "persistent_keepalive_interval" not in peer_conf:
        peer_conf["persistent_keepalive_interval"] = 25
    endpoint["peers"] = peers


def build_profile_map(profiles_config: dict) -> Dict[str, str]:
    """从 profiles.yml 构建 tag -> name 的映射"""
    profile_map = {}
    for p in profiles_config.get("profiles", []):
        name = p.get("name", "")
        # tag 使用 - 分隔，name 使用 _ 分隔
        tag = name.replace("_", "-")
        profile_map[tag] = name
    return profile_map


def load_pia_profiles_from_db() -> dict:
    """从数据库加载 PIA profiles"""
    if not HAS_DATABASE or not Path(USER_DB_PATH).exists():
        raise RuntimeError("数据库不可用，无法加载 PIA profiles")

    db = get_db(str(GEODATA_DB_PATH), str(USER_DB_PATH))
    profiles_list = db.get_pia_profiles(enabled_only=True)

    # 转换为 endpoint 配置所需的格式
    profiles = {"profiles": {}}
    for profile in profiles_list:
        name = profile["name"]
        # 只包含有凭证的 profiles
        if profile.get("private_key"):
            profiles["profiles"][name] = {
                "region_id": profile["region_id"],
                "description": profile.get("description", name),
                "server_cn": profile.get("server_cn"),
                "server_ip": profile.get("server_ip"),
                "server_port": profile.get("server_port"),
                "server_public_key": profile.get("server_public_key"),
                "peer_ip": profile.get("peer_ip"),
                "server_virtual_ip": profile.get("server_virtual_ip"),
                "private_key": profile.get("private_key"),
                "public_key": profile.get("public_key"),
            }

    if profiles["profiles"]:
        print(f"[render] 从数据库加载了 {len(profiles['profiles'])} 个 PIA profiles")
        return profiles

    print("[render] 警告: 数据库中没有已配置凭证的 PIA profiles")
    return None


def ensure_endpoints(config: dict, pia_profiles: dict, profile_map: Dict[str, str]) -> None:
    """确保每个 profile 都有对应的 endpoint（sing-box 1.11+ 格式）

    在 sing-box 1.11+ 中，WireGuard 应配置为 endpoint。
    路由规则可直接引用 endpoint tag 作为出口目标。
    """
    endpoints = config.setdefault("endpoints", [])
    existing_tags = {ep.get("tag") for ep in endpoints}

    # 移除旧的 WireGuard outbounds（sing-box 不能同时有同名的 endpoint 和 outbound）
    profile_tags = set(profile_map.keys())
    if "outbounds" in config:
        old_count = len(config["outbounds"])
        config["outbounds"] = [
            ob for ob in config["outbounds"]
            if ob.get("tag") not in profile_tags or ob.get("type") != "wireguard"
        ]
        removed = old_count - len(config["outbounds"])
        if removed > 0:
            print(f"[render] 移除了 {removed} 个旧的 WireGuard outbounds（已迁移到 endpoints）")

    profiles_data = pia_profiles.get("profiles", {})

    for idx, (tag, name) in enumerate(profile_map.items()):
        profile = profiles_data.get(name)
        if not profile:
            print(f"[render] 警告: profile {name} 未生成，跳过")
            continue

        if tag in existing_tags:
            # 更新现有 endpoint
            for ep in endpoints:
                if ep.get("tag") == tag and ep.get("type") == "wireguard":
                    _patch_wireguard_endpoint(ep, profile)
                    break
        else:
            # 创建新 endpoint
            new_ep = _create_wireguard_endpoint(tag, profile, idx)
            endpoints.append(new_ep)
            print(f"[render] 创建新 endpoint: {tag}")


def ensure_dns_servers(config: dict, profile_map: Dict[str, str]) -> None:
    """确保每个 profile 都有对应的 DNS 服务器"""
    dns = config.setdefault("dns", {})
    servers = dns.setdefault("servers", [])
    existing_tags = {s.get("tag") for s in servers}

    for tag in profile_map.keys():
        dns_tag = f"{tag}-dns"
        if dns_tag not in existing_tags:
            # 添加新的 DNS 服务器（通过对应的 VPN 出口）
            servers.append({
                "type": "tls",
                "tag": dns_tag,
                "server": "1.1.1.1",
                "detour": tag
            })


def ensure_outbound_selector(config: dict, all_egress_tags: List[str]) -> None:
    """更新 default-exit selector 包含所有出口"""
    outbounds = config.setdefault("outbounds", [])

    for ob in outbounds:
        if ob.get("tag") == "default-exit" and ob.get("type") == "selector":
            available = ["direct"] + all_egress_tags
            ob["outbounds"] = available
            break


def load_custom_egress() -> List[dict]:
    """从数据库加载自定义出口配置"""
    if not HAS_DATABASE:
        return []
    try:
        db = get_db(GEODATA_DB_PATH, USER_DB_PATH)
        egress_list = db.get_custom_egress_list(enabled_only=True)
        return egress_list
    except Exception as e:
        print(f"[render] 从数据库加载自定义出口配置失败: {e}")
        return []


def _create_custom_egress_endpoint(egress: dict, index: int) -> dict:
    """为自定义出口创建 WireGuard endpoint"""
    address = egress.get("address", "")
    if "/" not in address:
        address = f"{address}/32"

    endpoint = {
        "type": "wireguard",
        "tag": egress.get("tag", f"custom-{index}"),
        "address": [address],
        "private_key": egress.get("private_key", ""),
        "mtu": egress.get("mtu", 1420),
        "peers": [
            {
                "address": egress.get("server", ""),
                "port": egress.get("port", 51820),
                "public_key": egress.get("public_key", ""),
                "allowed_ips": ["0.0.0.0/0", "::/0"],
                "persistent_keepalive_interval": 25
            }
        ]
    }

    # 添加可选字段
    if egress.get("pre_shared_key"):
        endpoint["peers"][0]["pre_shared_key"] = egress["pre_shared_key"]
    if egress.get("reserved"):
        endpoint["peers"][0]["reserved"] = egress["reserved"]

    return endpoint


def ensure_custom_egress_endpoints(config: dict, custom_egress: List[dict]) -> List[str]:
    """确保每个自定义出口都有对应的 endpoint

    返回所有自定义出口的 tag 列表
    """
    if not custom_egress:
        return []

    endpoints = config.setdefault("endpoints", [])
    existing_tags = {ep.get("tag") for ep in endpoints}
    custom_tags = []

    for idx, egress in enumerate(custom_egress):
        tag = egress.get("tag", f"custom-{idx}")
        custom_tags.append(tag)

        if tag in existing_tags:
            # 更新现有 endpoint
            for ep in endpoints:
                if ep.get("tag") == tag and ep.get("type") == "wireguard":
                    # 更新配置
                    address = egress.get("address", "")
                    if "/" not in address:
                        address = f"{address}/32"
                    ep["address"] = [address]
                    ep["private_key"] = egress.get("private_key", "")
                    ep["mtu"] = egress.get("mtu", 1420)

                    peers = ep.get("peers") or [{}]
                    peer = peers[0]
                    peer["address"] = egress.get("server", "")
                    peer["port"] = egress.get("port", 51820)
                    peer["public_key"] = egress.get("public_key", "")
                    if egress.get("pre_shared_key"):
                        peer["pre_shared_key"] = egress["pre_shared_key"]
                    if egress.get("reserved"):
                        peer["reserved"] = egress["reserved"]
                    break
        else:
            # 创建新 endpoint
            new_ep = _create_custom_egress_endpoint(egress, idx)
            endpoints.append(new_ep)
            print(f"[render] 创建自定义出口 endpoint: {tag}")

    return custom_tags


def ensure_custom_dns_servers(config: dict, custom_tags: List[str]) -> None:
    """为自定义出口添加 DNS 服务器"""
    if not custom_tags:
        return

    dns = config.setdefault("dns", {})
    servers = dns.setdefault("servers", [])
    existing_tags = {s.get("tag") for s in servers}

    for tag in custom_tags:
        dns_tag = f"{tag}-dns"
        if dns_tag not in existing_tags:
            servers.append({
                "type": "tls",
                "tag": dns_tag,
                "server": "1.1.1.1",
                "detour": tag
            })


def cleanup_stale_endpoints(config: dict, valid_tags: List[str]) -> None:
    """移除不再存在于数据库中的旧端点

    valid_tags: 所有有效的端点标签列表（PIA profiles + custom egress）
    wg-server 端点始终保留
    """
    endpoints = config.get("endpoints", [])
    if not endpoints:
        return

    # 保留的端点: wg-server + 所有有效的出口端点
    keep_tags = {"wg-server"} | set(valid_tags)

    # 找出需要移除的端点
    stale_endpoints = [
        ep.get("tag") for ep in endpoints
        if ep.get("tag") not in keep_tags and ep.get("type") == "wireguard"
    ]

    if stale_endpoints:
        print(f"[render] 移除过期端点: {stale_endpoints}")
        config["endpoints"] = [
            ep for ep in endpoints
            if ep.get("tag") in keep_tags or ep.get("type") != "wireguard"
        ]

    # 同时清理对应的 DNS 服务器
    dns = config.get("dns", {})
    servers = dns.get("servers", [])
    if servers:
        stale_dns_tags = {f"{tag}-dns" for tag in stale_endpoints}
        if stale_dns_tags:
            dns["servers"] = [
                s for s in servers
                if s.get("tag") not in stale_dns_tags
            ]




def load_custom_rules() -> Dict[str, Any]:
    """从数据库加载自定义路由规则和默认出口"""
    result = {"rules": [], "default_outbound": "direct"}

    if not HAS_DATABASE:
        # 降级到 JSON 文件
        if CUSTOM_RULES_FILE.exists():
            return json.loads(CUSTOM_RULES_FILE.read_text())
        return result

    try:
        db = get_db(GEODATA_DB_PATH, USER_DB_PATH)

        # 读取默认出口
        default_outbound = db.get_setting("default_outbound", "direct")
        result["default_outbound"] = default_outbound

        # 读取路由规则并按 tag 分组
        db_rules = db.get_routing_rules(enabled_only=True)
        rules_by_tag = {}

        for rule in db_rules:
            tag = rule.get("tag") or f"custom-{rule['outbound']}"
            if tag not in rules_by_tag:
                rules_by_tag[tag] = {
                    "tag": tag,
                    "outbound": rule["outbound"],
                    "domains": [],
                    "domain_keywords": [],
                    "ip_cidrs": []
                }

            rule_type = rule["rule_type"]
            target = rule["target"]

            if rule_type == "domain":
                rules_by_tag[tag]["domains"].append(target)
            elif rule_type == "domain_keyword":
                rules_by_tag[tag]["domain_keywords"].append(target)
            elif rule_type == "ip":
                rules_by_tag[tag]["ip_cidrs"].append(target)

        result["rules"] = list(rules_by_tag.values())
        return result

    except Exception as e:
        print(f"[render] 警告: 从数据库加载规则失败: {e}")
        # 降级到 JSON 文件
        if CUSTOM_RULES_FILE.exists():
            return json.loads(CUSTOM_RULES_FILE.read_text())
        return result


def apply_custom_rules(config: dict, custom_rules: Dict[str, Any]) -> None:
    """应用自定义路由规则到配置"""
    route = config.setdefault("route", {})
    rule_set = route.setdefault("rule_set", [])
    rules = route.setdefault("rules", [])

    # 获取现有的 custom rule_set tags
    existing_custom_tags = set()
    for rs in rule_set:
        if rs.get("tag", "").startswith("custom-"):
            existing_custom_tags.add(rs.get("tag"))

    # 移除旧的 custom 规则
    rule_set[:] = [rs for rs in rule_set if not rs.get("tag", "").startswith("custom-")]
    rules[:] = [r for r in rules if not any(
        t.startswith("custom-") for t in r.get("rule_set", [])
    )]

    # 添加新的自定义规则
    for custom_rule in custom_rules.get("rules", []):
        rule_tag = custom_rule.get("tag", "")
        if not rule_tag.startswith("custom-"):
            rule_tag = f"custom-{rule_tag}"

        domains = custom_rule.get("domains", [])
        domain_keywords = custom_rule.get("domain_keywords", [])
        ip_cidrs = custom_rule.get("ip_cidrs", [])
        outbound = custom_rule.get("outbound", "direct")

        if domains or domain_keywords or ip_cidrs:
            # 创建 inline rule_set
            inline_rules = []
            if domains:
                inline_rules.append({"domain_suffix": domains})
            if domain_keywords:
                inline_rules.append({"domain_keyword": domain_keywords})
            if ip_cidrs:
                inline_rules.append({"ip_cidr": ip_cidrs})

            rule_set.append({
                "tag": rule_tag,
                "type": "inline",
                "rules": inline_rules
            })

            # 添加路由规则
            rules.insert(0, {
                "rule_set": [rule_tag],
                "outbound": outbound
            })

    # 更新默认出口
    if custom_rules.get("default_outbound"):
        route["final"] = custom_rules["default_outbound"]


def main() -> None:
    config = load_json(BASE_CONFIG)

    all_egress_tags = []

    # 确保 WireGuard 服务器端点存在（用于接受客户端连接）
    if ensure_wireguard_server_endpoint(config):
        print("[render] WireGuard 服务器端点已配置")

    # 从数据库加载 PIA profiles
    pia_profiles = load_pia_profiles_from_db()

    if pia_profiles and pia_profiles.get("profiles"):
        # 从数据库构建 profile_map (tag -> name)
        profile_map = {}
        for name in pia_profiles["profiles"].keys():
            tag = name.replace("_", "-")
            profile_map[tag] = name

        print(f"[render] 处理 {len(profile_map)} 个 PIA profiles: {list(profile_map.keys())}")

        # 确保 PIA endpoints 存在
        ensure_endpoints(config, pia_profiles, profile_map)

        # 确保 PIA DNS 服务器存在
        ensure_dns_servers(config, profile_map)

        all_egress_tags.extend(profile_map.keys())

    # 加载并处理自定义出口
    custom_egress = load_custom_egress()
    if custom_egress:
        print(f"[render] 处理 {len(custom_egress)} 个自定义出口")
        custom_tags = ensure_custom_egress_endpoints(config, custom_egress)
        ensure_custom_dns_servers(config, custom_tags)
        all_egress_tags.extend(custom_tags)

    # 清理不再存在于数据库中的旧端点
    cleanup_stale_endpoints(config, all_egress_tags)

    # 检查是否有任何出口配置
    if not all_egress_tags:
        print("[render] 警告: 没有找到任何出口配置（PIA 或自定义）")
        # 仍然生成配置，只是没有 VPN 出口

    # 更新 selector outbound（如果有的话）
    if all_egress_tags:
        ensure_outbound_selector(config, all_egress_tags)

    # 应用自定义规则
    custom_rules = load_custom_rules()
    if custom_rules.get("rules") or custom_rules.get("default_outbound"):
        apply_custom_rules(config, custom_rules)
        if custom_rules.get("rules"):
            print(f"[render] 应用了 {len(custom_rules['rules'])} 条自定义规则")
        if custom_rules.get("default_outbound"):
            print(f"[render] 默认出口设置为: {custom_rules['default_outbound']}")

    # 确保路由规则中有 sniff 动作（放在最后以确保它在规则列表开头）
    ensure_sniff_action(config)

    # 添加 experimental API 用于获取连接状态
    config["experimental"] = {
        "clash_api": {
            "external_controller": "127.0.0.1:9090",
            "secret": ""
        },
        "cache_file": {
            "enabled": True,
            "path": "/etc/sing-box/cache.db"
        }
    }
    print("[render] 已启用 clash_api (127.0.0.1:9090)")

    OUTPUT.write_text(json.dumps(config, indent=2))
    print(f"[sing-box] 已写入 {OUTPUT}")


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:  # pylint: disable=broad-except
        print(f"[sing-box] 渲染失败: {exc}", file=sys.stderr)
        sys.exit(1)

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
CUSTOM_EGRESS_FILE = Path(os.environ.get("CUSTOM_EGRESS_FILE", "/etc/sing-box/custom-egress.json"))
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
    """加载自定义出口配置"""
    if not CUSTOM_EGRESS_FILE.exists():
        return []
    try:
        data = json.loads(CUSTOM_EGRESS_FILE.read_text())
        return data.get("egress", [])
    except Exception as e:
        print(f"[render] 加载自定义出口配置失败: {e}")
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


def load_custom_rules() -> Dict[str, Any]:
    """加载自定义路由规则"""
    if not CUSTOM_RULES_FILE.exists():
        return {"rules": [], "default_outbound": "direct"}
    return json.loads(CUSTOM_RULES_FILE.read_text())


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

    # 加载 PIA profiles（如果存在）
    profiles_config = load_yaml(PIA_PROFILES_FILE)
    profile_map = build_profile_map(profiles_config)

    if profile_map:
        # 从数据库加载 PIA profiles
        pia_profiles = load_pia_profiles_from_db()

        if pia_profiles:
            print(f"[render] 处理 {len(profile_map)} 个 PIA profiles: {list(profile_map.keys())}")

            # 确保 PIA endpoints 存在
            ensure_endpoints(config, pia_profiles, profile_map)

            # 确保 PIA DNS 服务器存在
            ensure_dns_servers(config, profile_map)

            all_egress_tags.extend(profile_map.keys())
        else:
            print("[render] 跳过 PIA profiles（数据库中没有已配置凭证的 profiles）")

    # 加载并处理自定义出口
    custom_egress = load_custom_egress()
    if custom_egress:
        print(f"[render] 处理 {len(custom_egress)} 个自定义出口")
        custom_tags = ensure_custom_egress_endpoints(config, custom_egress)
        ensure_custom_dns_servers(config, custom_tags)
        all_egress_tags.extend(custom_tags)

    # 检查是否有任何出口配置
    if not all_egress_tags:
        print("[render] 警告: 没有找到任何出口配置（PIA 或自定义）")
        # 仍然生成配置，只是没有 VPN 出口

    # 更新 selector outbound（如果有的话）
    if all_egress_tags:
        ensure_outbound_selector(config, all_egress_tags)

    # 应用自定义规则
    custom_rules = load_custom_rules()
    if custom_rules.get("rules"):
        apply_custom_rules(config, custom_rules)
        print(f"[render] 应用了 {len(custom_rules['rules'])} 条自定义规则")

    OUTPUT.write_text(json.dumps(config, indent=2))
    print(f"[sing-box] 已写入 {OUTPUT}")


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:  # pylint: disable=broad-except
        print(f"[sing-box] 渲染失败: {exc}", file=sys.stderr)
        sys.exit(1)

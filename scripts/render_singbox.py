#!/usr/bin/env python3
"""根据 PIA 生成的 WireGuard 参数，渲染 sing-box 最终配置

支持动态 profiles：
- 读取 profiles.yml 中定义的所有 profiles
- 为每个 profile 创建或更新对应的 WireGuard endpoint（sing-box 1.11+ 格式）
- 路由规则可直接引用 endpoint tag 作为出口
- 应用自定义路由规则（如果有）
- 支持广告拦截 rule_set（从 ABP/hosts 列表转换）
"""
import json
import os
import shutil
import sys
import tempfile
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Set

import yaml

# 尝试导入数据库模块（如果可用）
try:
    sys.path.insert(0, '/usr/local/bin')
    from db_helper import get_db, get_egress_interface_name
    HAS_DATABASE = True
except ImportError:
    HAS_DATABASE = False

    # Fallback if db_helper not available (H12: with hash for uniqueness)
    def get_egress_interface_name(tag: str, is_pia: bool) -> str:
        import hashlib
        prefix = "wg-pia-" if is_pia else "wg-eg-"
        max_tag_len = 15 - len(prefix)
        if len(tag) <= max_tag_len:
            return f"{prefix}{tag}"
        else:
            tag_hash = hashlib.md5(tag.encode('utf-8')).hexdigest()[:max_tag_len]
            return f"{prefix}{tag_hash}"

# 尝试导入 ABP 转换模块
try:
    from convert_adblock import download_and_convert, save_singbox_ruleset
    HAS_ADBLOCK_CONVERTER = True
except ImportError:
    HAS_ADBLOCK_CONVERTER = False

BASE_CONFIG = Path(os.environ.get("SING_BOX_BASE_CONFIG", "/etc/sing-box/sing-box.json"))
PIA_PROFILES_FILE = Path(os.environ.get("PIA_PROFILES_FILE", "/etc/sing-box/pia/profiles.yml"))
CUSTOM_RULES_FILE = Path(os.environ.get("CUSTOM_RULES_FILE", "/etc/sing-box/custom-rules.json"))
OUTPUT = Path(os.environ.get("SING_BOX_GENERATED_CONFIG", "/etc/sing-box/sing-box.generated.json"))
GEODATA_DB_PATH = os.environ.get("GEODATA_DB_PATH", "/etc/sing-box/geoip-geodata.db")
USER_DB_PATH = os.environ.get("USER_DB_PATH", "/etc/sing-box/user-config.db")
# RULESETS_DIR is for adblock rule_set JSON files (subdirectory of config)
# Note: RULESET_DIR (in Dockerfile/entrypoint) is different - it's the base config directory
RULESETS_DIR = Path(os.environ.get("RULESETS_DIR", "/etc/sing-box/rulesets"))


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

    # 获取对等端列表（可以为空，不影响 TPROXY 入口创建）
    peers = db.get_wireguard_peers()
    if not peers:
        print("[render] 警告: 没有配置 WireGuard 客户端对等端（仍创建 TPROXY 入口）")
        peers = []

    return {
        "server": server,
        "peers": peers
    }


def create_tproxy_inbound(wg_config: dict) -> dict:
    """创建 TPROXY 入口，接收来自内核 WireGuard 的转发流量

    内核 WireGuard (wg-ingress) 解密流量后，通过 iptables TPROXY 规则
    透明代理到此端口，然后进入 sing-box 路由引擎进行分流。

    流量路径:
    Client -> kernel WireGuard (wg-ingress:36100) -> iptables TPROXY -> sing-box tproxy -> routing

    TPROXY 优势（相比 TUN）:
    - 专为转发流量设计（TUN 主要用于本地流量）
    - 不修改源/目标地址
    - 更高效的内核集成
    """
    server = wg_config["server"]

    # TPROXY 入口配置
    # 监听 TCP 和 UDP 流量
    # 使用 0.0.0.0 而不是 :: 确保 IPv4 TPROXY 流量正确接收
    tproxy_inbound = {
        "type": "tproxy",
        "tag": "tproxy-in",
        "listen": "0.0.0.0",
        "listen_port": 7893,  # TPROXY 监听端口
        "sniff": True,
        "sniff_override_destination": False
    }

    return tproxy_inbound


def ensure_tproxy_inbound(config: dict) -> bool:
    """确保 TPROXY 入口存在，用于接收内核 WireGuard 转发流量

    返回 True 如果成功添加/更新，False 如果无配置
    """
    wg_config = load_wireguard_server_config()
    if not wg_config:
        return False

    inbounds = config.setdefault("inbounds", [])
    endpoints = config.get("endpoints", [])

    # 移除旧的 tproxy-in / tun-in inbound (如果存在)
    inbounds[:] = [ib for ib in inbounds if ib.get("tag") not in ("tproxy-in", "tun-in")]

    # 移除旧的 wg-server endpoint (迁移: userspace -> kernel)
    endpoints[:] = [ep for ep in endpoints if ep.get("tag") != "wg-server"]

    # 创建 TPROXY inbound
    tproxy_inbound = create_tproxy_inbound(wg_config)
    inbounds.insert(0, tproxy_inbound)
    print(f"[render] 创建 TPROXY 入口: tproxy-in (内核 WireGuard -> iptables TPROXY)")
    return True


# 保留旧函数名作为别名，兼容可能的外部调用
def create_tun_inbound(wg_config: dict) -> dict:
    """[已弃用] 使用 create_tproxy_inbound 替代"""
    return create_tproxy_inbound(wg_config)


def ensure_tun_inbound(config: dict) -> bool:
    """[已弃用] 使用 ensure_tproxy_inbound 替代"""
    return ensure_tproxy_inbound(config)


def create_wireguard_server_endpoint(wg_config: dict) -> dict:
    """[已弃用] 使用 create_tproxy_inbound 替代"""
    return create_tproxy_inbound(wg_config)


def ensure_wireguard_server_endpoint(config: dict) -> bool:
    """[已弃用] 使用 ensure_tproxy_inbound 替代"""
    return ensure_tproxy_inbound(config)


def ensure_sniff_action(config: dict) -> None:
    """确保路由规则中有 sniff 动作和 DNS 劫持，支持域名匹配和协议检测

    支持的嗅探器:
    - tls, http, quic: 域名检测 (TLS SNI, HTTP Host, QUIC SNI)
    - bittorrent: 种子下载流量检测
    - stun: VoIP/WebRTC 流量检测
    - dtls: 安全 UDP 流量检测
    """
    route = config.setdefault("route", {})
    rules = route.setdefault("rules", [])

    # sniff 规则 - 支持域名检测和协议检测
    sniff_rule = {
        "action": "sniff",
        "sniffer": ["tls", "http", "quic", "bittorrent", "stun", "dtls"],
        "timeout": "300ms"
    }

    # DNS 劫持规则 - 让 sing-box 接管 DNS 解析
    # 这样可以通过 VPN 隧道解析 DNS，防止 DNS 泄露
    hijack_dns_rule = {
        "action": "hijack-dns",
        "protocol": "dns"
    }

    # 移除所有现有的 sniff 和 hijack-dns 动作
    rules[:] = [r for r in rules if r.get("action") not in ("sniff", "hijack-dns")]

    # 在规则列表开头添加：先 sniff，再 hijack-dns
    rules.insert(0, hijack_dns_rule)
    rules.insert(0, sniff_rule)
    print("[render] sniff 和 hijack-dns 动作已置于规则列表开头")


def generate_lan_access_rules(config: dict) -> None:
    """为启用 LAN 访问的 peer 生成路由规则

    收集所有启用了 allow_lan 的 peer 的 LAN 子网，
    添加一条规则将 LAN 流量路由到 direct 出口。
    """
    if not HAS_DATABASE or not Path(USER_DB_PATH).exists():
        return

    try:
        db = get_db(str(GEODATA_DB_PATH), str(USER_DB_PATH))
        peers = db.get_wireguard_peers(enabled_only=True)
    except Exception as e:
        print(f"[render] 警告: 无法加载 WireGuard peers: {e}")
        return

    # 收集所有需要 LAN 访问的子网
    lan_subnets = set()
    for peer in peers:
        if peer.get("allow_lan") and peer.get("lan_subnet"):
            lan_subnets.add(peer["lan_subnet"])

    if not lan_subnets:
        return

    # 添加路由规则: LAN 子网 → direct
    route = config.setdefault("route", {})
    rules = route.setdefault("rules", [])

    lan_rule = {
        "ip_cidr": list(lan_subnets),
        "outbound": "direct"
    }

    # 找到合适的插入位置（在 sniff 和 hijack-dns 之后）
    insert_pos = 0
    for i, rule in enumerate(rules):
        if rule.get("action") in ("sniff", "hijack-dns"):
            insert_pos = i + 1
        else:
            break

    rules.insert(insert_pos, lan_rule)
    print(f"[render] 已添加 LAN 访问规则: {list(lan_subnets)} → direct")


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
        # tag 和 name 保持一致，不做转换
        profile_map[name] = name
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


# ============ 内核 WireGuard 出口 (Kernel WireGuard Egress) ============
#
# 使用内核 WireGuard 模块而不是 sing-box 用户空间实现：
# - 更好的性能（内核 vs 用户空间）
# - wg show 可用于调试
# - 标准 WireGuard 工具支持
# - 与入站架构一致
#
# 架构：
# sing-box routing → direct outbound (bind_interface: wg-pia-xxx) → 内核 WireGuard → 远程服务器


def ensure_kernel_wg_egress_outbounds(config: dict, pia_profiles: dict, custom_egress: List[dict]) -> List[str]:
    """为 PIA 和自定义 WireGuard 出口创建 direct outbound（绑定到内核接口）

    替代之前的 sing-box WireGuard endpoints，现在使用：
    - 内核 WireGuard 接口由 setup_kernel_wg_egress.py 创建
    - sing-box 使用 direct outbound + bind_interface 将流量发送到内核接口

    Args:
        config: sing-box 配置
        pia_profiles: PIA profiles 配置（从数据库加载）
        custom_egress: 自定义 WireGuard 出口列表

    Returns:
        所有创建的出口 tag 列表
    """
    outbounds = config.setdefault("outbounds", [])
    endpoints = config.get("endpoints", [])
    all_tags = []

    # 获取现有的 outbound tags
    existing_outbound_tags = {ob.get("tag") for ob in outbounds}

    # 获取所有将要创建的 WireGuard 出口 tags
    wg_egress_tags = set()

    # 处理 PIA profiles
    profiles_data = pia_profiles.get("profiles", {}) if pia_profiles else {}
    for name, profile in profiles_data.items():
        if not profile.get("private_key"):
            continue  # 跳过没有凭证的 profile

        tag = name  # PIA profile 使用 name 作为 tag
        interface = get_egress_interface_name(tag, is_pia=True)
        wg_egress_tags.add(tag)
        all_tags.append(tag)

        if tag in existing_outbound_tags:
            # 更新现有 outbound
            for i, ob in enumerate(outbounds):
                if ob.get("tag") == tag:
                    outbounds[i] = {
                        "type": "direct",
                        "tag": tag,
                        "bind_interface": interface
                    }
                    break
        else:
            # 创建新 outbound（在 block/adblock 之前插入）
            block_idx = next(
                (i for i, ob in enumerate(outbounds) if ob.get("tag") in ("block", "adblock")),
                len(outbounds)
            )
            outbounds.insert(block_idx, {
                "type": "direct",
                "tag": tag,
                "bind_interface": interface
            })
            print(f"[render] 创建内核 WireGuard 出口: {tag} (接口: {interface})")

    # 处理自定义 WireGuard 出口
    for egress in custom_egress:
        tag = egress.get("tag")
        if not tag:
            continue

        interface = get_egress_interface_name(tag, is_pia=False)
        wg_egress_tags.add(tag)
        all_tags.append(tag)

        if tag in existing_outbound_tags:
            # 更新现有 outbound
            for i, ob in enumerate(outbounds):
                if ob.get("tag") == tag:
                    outbounds[i] = {
                        "type": "direct",
                        "tag": tag,
                        "bind_interface": interface
                    }
                    break
        else:
            # 创建新 outbound
            block_idx = next(
                (i for i, ob in enumerate(outbounds) if ob.get("tag") in ("block", "adblock")),
                len(outbounds)
            )
            outbounds.insert(block_idx, {
                "type": "direct",
                "tag": tag,
                "bind_interface": interface
            })
            print(f"[render] 创建内核 WireGuard 出口: {tag} (接口: {interface})")

    # 移除旧的 WireGuard endpoints（如果有的话）
    # 这些是从旧架构遗留的，现在使用 direct outbound + bind_interface
    if endpoints:
        old_count = len(endpoints)
        config["endpoints"] = [
            ep for ep in endpoints
            if ep.get("tag") not in wg_egress_tags or ep.get("type") != "wireguard"
        ]
        removed = old_count - len(config.get("endpoints", []))
        if removed > 0:
            print(f"[render] 移除了 {removed} 个旧的 WireGuard endpoints（已迁移到内核 WireGuard）")

    # 同时移除旧的 WireGuard outbounds（类型为 wireguard 的）
    old_count = len(outbounds)
    config["outbounds"] = [
        ob for ob in outbounds
        if ob.get("tag") not in wg_egress_tags or ob.get("type") != "wireguard"
    ]
    removed = old_count - len(config["outbounds"])
    if removed > 0:
        print(f"[render] 移除了 {removed} 个旧的 WireGuard outbounds（已迁移到内核 WireGuard）")

    return all_tags


# ========== Xray V2Ray 出站（SOCKS5 → Xray → 远程 V2Ray 服务器）==========
# 架构：
# sing-box routing → SOCKS5 outbound (127.0.0.1:37101) → Xray → 远程 V2Ray 服务器
#
# Xray 提供 sing-box 不支持的功能：
# - XHTTP 传输
# - REALITY 客户端
# - XTLS-Vision


def ensure_xray_egress_outbounds(config: dict, v2ray_egress: List[dict]) -> List[str]:
    """为 V2Ray 出口创建 SOCKS5 outbound（连接到 Xray 管理的 SOCKS5 入站）

    Args:
        config: sing-box 配置
        v2ray_egress: V2Ray 出口列表（从数据库加载，包含 socks_port）

    Returns:
        所有创建的出口 tag 列表
    """
    outbounds = config.setdefault("outbounds", [])
    all_tags = []

    # 获取现有的 outbound tags
    existing_outbound_tags = {ob.get("tag") for ob in outbounds}

    for egress in v2ray_egress:
        tag = egress.get("tag")
        socks_port = egress.get("socks_port")

        if not tag or not socks_port:
            print(f"[render] 跳过无效 V2Ray 出口: {egress}")
            continue

        all_tags.append(tag)

        socks_outbound = {
            "type": "socks",
            "tag": tag,
            "server": "127.0.0.1",
            "server_port": socks_port
        }

        if tag in existing_outbound_tags:
            # 更新现有 outbound
            for i, ob in enumerate(outbounds):
                if ob.get("tag") == tag:
                    outbounds[i] = socks_outbound
                    break
        else:
            # 创建新 outbound（在 block/adblock 之前插入）
            block_idx = next(
                (i for i, ob in enumerate(outbounds) if ob.get("tag") in ("block", "adblock")),
                len(outbounds)
            )
            outbounds.insert(block_idx, socks_outbound)
            print(f"[render] 创建 Xray 出口: {tag} (SOCKS5 127.0.0.1:{socks_port})")

    return all_tags


def _parse_dns_server(server: str) -> dict:
    """解析 DNS 服务器配置，返回 sing-box DNS server 配置字典

    sing-box 1.12+ DNS 配置规则:
    - local: type=local（使用系统 DNS，无 server 字段）
    - UDP: type=udp, server=IP或域名
    - DoT: type=tls, server=域名（不含 tls://）
    - DoH: type=https, server=域名, path=/dns-query
    - DoQ: type=quic, server=域名
    - H3:  type=h3, server=域名, path=/dns-query

    Examples:
    - "local" → {"type": "local"}
    - "8.8.8.8" → {"type": "udp", "server": "8.8.8.8"}
    - "dns.google" → {"type": "udp", "server": "dns.google"}
    - "https://dns.google/dns-query" → {"type": "https", "server": "dns.google", "path": "/dns-query"}
    - "tls://dns.google" → {"type": "tls", "server": "dns.google"}
    - "quic://dns.adguard.com" → {"type": "quic", "server": "dns.adguard.com"}
    - "h3://dns.google/dns-query" → {"type": "h3", "server": "dns.google", "path": "/dns-query"}
    """
    from urllib.parse import urlparse

    # 特殊关键字: local 使用系统 DNS
    if server.lower() == 'local':
        return {"type": "local"}

    if server.startswith('https://'):
        parsed = urlparse(server)
        result = {
            "type": "https",
            "server": parsed.hostname or parsed.netloc,
        }
        if parsed.path and parsed.path != '/':
            result["path"] = parsed.path
        if parsed.port:
            result["server_port"] = parsed.port
        return result

    elif server.startswith('tls://'):
        # tls://host:port 格式
        rest = server[6:]
        if ':' in rest:
            host, port = rest.rsplit(':', 1)
            return {"type": "tls", "server": host, "server_port": int(port)}
        return {"type": "tls", "server": rest}

    elif server.startswith('quic://'):
        # quic://host:port 格式
        rest = server[7:]
        if ':' in rest:
            host, port = rest.rsplit(':', 1)
            return {"type": "quic", "server": host, "server_port": int(port)}
        return {"type": "quic", "server": rest}

    elif server.startswith('h3://'):
        # h3://host:port/path 格式 (HTTP/3 DNS)
        parsed = urlparse(server)
        result = {
            "type": "h3",
            "server": parsed.hostname or parsed.netloc,
        }
        if parsed.path and parsed.path != '/':
            result["path"] = parsed.path
        if parsed.port:
            result["server_port"] = parsed.port
        return result

    else:
        # 普通 UDP DNS（IP 或域名）
        return {"type": "udp", "server": server}


def ensure_direct_dns_config(config: dict) -> None:
    """根据数据库设置更新 direct-dns 服务器配置

    从数据库 settings 表读取 direct_dns_servers 设置，
    更新 sing-box 配置中的 direct-dns 服务器。
    """
    if not HAS_DATABASE or not Path(USER_DB_PATH).exists():
        print("[render] 数据库不可用，使用默认 DNS 配置")
        return

    db = get_db(str(GEODATA_DB_PATH), str(USER_DB_PATH))

    # 从 settings 表读取 DNS 配置
    dns_servers_json = db.get_setting("direct_dns_servers", "[]")
    try:
        dns_servers = json.loads(dns_servers_json)
    except json.JSONDecodeError:
        dns_servers = []

    # 如果没有配置，使用默认值
    if not dns_servers:
        return  # 使用模板中的默认配置

    dns = config.setdefault("dns", {})
    servers = dns.setdefault("servers", [])

    # sing-box DNS 不支持每个 tag 多个服务器，仅使用第一个
    # 其余服务器会被忽略（记录警告日志）
    primary_dns = dns_servers[0]
    dns_config = _parse_dns_server(primary_dns)

    # 查找并更新 direct-dns 服务器
    found = False
    for server in servers:
        if server.get("tag") == "direct-dns":
            # 清除旧字段，避免残留
            keys_to_remove = [k for k in server if k not in ("tag",)]
            for k in keys_to_remove:
                del server[k]
            # 应用新配置
            server.update(dns_config)
            found = True
            break

    # 如果没有找到，添加新的 direct-dns 服务器
    if not found:
        new_server = {"tag": "direct-dns"}
        new_server.update(dns_config)
        servers.insert(0, new_server)

    print(f"[render] direct-dns 已配置: {primary_dns} (type={dns_config['type']})")
    if len(dns_servers) > 1:
        print(f"[render] 注意: sing-box 不支持 DNS 回退，仅使用第一个服务器，其余 {len(dns_servers)-1} 个被忽略")


def ensure_dns_servers(config: dict, profile_map: Dict[str, str]) -> None:
    """确保每个 profile 都有对应的 DNS 服务器

    使用 PIA 的私有 DNS 服务器 10.0.0.241 (DNS+Streaming+MACE)
    这些 DNS 必须通过 VPN 隧道访问，可以防止 DNS 泄露

    sing-box 1.12+ 使用新的 DNS 服务器格式（type + server）
    """
    dns = config.setdefault("dns", {})
    servers = dns.setdefault("servers", [])

    # PIA 私有 DNS: 10.0.0.241 (DNS+Streaming+MACE)
    PIA_DNS = "10.0.0.241"

    for tag in profile_map.keys():
        dns_tag = f"{tag}-dns"

        # 移除旧的同名 DNS 服务器
        servers[:] = [s for s in servers if s.get("tag") != dns_tag]

        # sing-box 1.12+ 新格式
        servers.append({
            "tag": dns_tag,
            "type": "udp",
            "server": PIA_DNS,
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


def load_direct_egress() -> List[dict]:
    """从数据库加载 direct 出口配置（绑定特定接口/IP）"""
    if not HAS_DATABASE:
        return []
    try:
        db = get_db(GEODATA_DB_PATH, USER_DB_PATH)
        egress_list = db.get_direct_egress_list(enabled_only=True)
        return egress_list
    except Exception as e:
        print(f"[render] 从数据库加载 direct 出口配置失败: {e}")
        return []


def load_openvpn_egress() -> List[dict]:
    """从数据库加载 OpenVPN 出口配置"""
    if not HAS_DATABASE:
        return []
    try:
        db = get_db(GEODATA_DB_PATH, USER_DB_PATH)
        egress_list = db.get_openvpn_egress_list(enabled_only=True)
        return egress_list
    except Exception as e:
        print(f"[render] 从数据库加载 OpenVPN 出口配置失败: {e}")
        return []


def ensure_openvpn_egress_outbounds(config: dict, openvpn_egress: List[dict]) -> List[str]:
    """确保每个 OpenVPN 出口都有对应的 SOCKS5 outbound

    OpenVPN 隧道通过 SOCKS5 代理桥接到 sing-box:
    - 每个 OpenVPN 隧道运行独立进程
    - 每个隧道有对应的 SOCKS5 代理（监听 127.0.0.1:socks_port）
    - sing-box 通过 SOCKS outbound 连接到 OpenVPN 隧道

    Args:
        config: sing-box 配置
        openvpn_egress: OpenVPN 出口列表

    Returns:
        所有 OpenVPN 出口的 tag 列表
    """
    if not openvpn_egress:
        return []

    outbounds = config.setdefault("outbounds", [])
    existing_tags = {ob.get("tag") for ob in outbounds}
    openvpn_tags = []

    for egress in openvpn_egress:
        tag = egress.get("tag")
        socks_port = egress.get("socks_port")

        if not tag or not socks_port:
            print(f"[render] 警告: OpenVPN 出口缺少 tag 或 socks_port，跳过")
            continue

        openvpn_tags.append(tag)

        # 构建 SOCKS outbound
        outbound = {
            "type": "socks",
            "tag": tag,
            "server": "127.0.0.1",
            "server_port": socks_port
        }

        if tag in existing_tags:
            # 更新现有 outbound
            for i, ob in enumerate(outbounds):
                if ob.get("tag") == tag and ob.get("type") == "socks":
                    outbounds[i] = outbound
                    break
        else:
            # 在 block 之前插入
            block_idx = next((i for i, ob in enumerate(outbounds) if ob.get("tag") == "block"), len(outbounds))
            outbounds.insert(block_idx, outbound)
            print(f"[render] 创建 OpenVPN 出口 (SOCKS): {tag} -> 127.0.0.1:{socks_port}")

    return openvpn_tags


def ensure_openvpn_dns_servers(config: dict, openvpn_tags: List[str]) -> None:
    """为 OpenVPN 出口添加 DNS 服务器

    由于 OpenVPN 隧道可能有自己的 DNS 服务器，
    这里使用 Cloudflare DNS 通过 SOCKS 代理访问。

    sing-box 1.12+ 使用新的 DNS 服务器格式（type + server）
    """
    if not openvpn_tags:
        return

    dns = config.setdefault("dns", {})
    servers = dns.setdefault("servers", [])
    existing_tags = {s.get("tag") for s in servers}

    for tag in openvpn_tags:
        dns_tag = f"{tag}-dns"
        if dns_tag not in existing_tags:
            # sing-box 1.12+ 新格式
            servers.append({
                "tag": dns_tag,
                "type": "tls",
                "server": "1.1.1.1",
                "detour": tag
            })


def ensure_direct_egress_outbounds(config: dict, direct_egress: List[dict]) -> List[str]:
    """确保每个 direct 出口都有对应的 outbound

    Args:
        config: sing-box 配置
        direct_egress: direct 出口列表

    Returns:
        所有 direct 出口的 tag 列表（不含默认 'direct'）
    """
    if not direct_egress:
        return []

    outbounds = config.setdefault("outbounds", [])
    existing_tags = {ob.get("tag") for ob in outbounds}
    direct_tags = []

    for egress in direct_egress:
        tag = egress.get("tag")
        if not tag or tag == "direct":
            # 不允许覆盖默认 direct
            continue

        direct_tags.append(tag)

        # 构建 direct outbound
        outbound = {
            "type": "direct",
            "tag": tag
        }

        # 添加绑定配置
        if egress.get("bind_interface"):
            outbound["bind_interface"] = egress["bind_interface"]
        if egress.get("inet4_bind_address"):
            outbound["inet4_bind_address"] = egress["inet4_bind_address"]
        if egress.get("inet6_bind_address"):
            outbound["inet6_bind_address"] = egress["inet6_bind_address"]

        if tag in existing_tags:
            # 更新现有 outbound
            for i, ob in enumerate(outbounds):
                if ob.get("tag") == tag and ob.get("type") == "direct":
                    outbounds[i] = outbound
                    break
        else:
            # 在 block 之前插入（保持 direct, direct-xxx, block 的顺序）
            block_idx = next((i for i, ob in enumerate(outbounds) if ob.get("tag") == "block"), len(outbounds))
            outbounds.insert(block_idx, outbound)
            print(f"[render] 创建 direct 出口: {tag}")

    return direct_tags


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
    """为自定义出口添加 DNS 服务器

    sing-box 1.12+ 使用新的 DNS 服务器格式（type + server）
    """
    if not custom_tags:
        return

    dns = config.setdefault("dns", {})
    servers = dns.setdefault("servers", [])
    existing_tags = {s.get("tag") for s in servers}

    for tag in custom_tags:
        dns_tag = f"{tag}-dns"
        if dns_tag not in existing_tags:
            # sing-box 1.12+ 新格式
            servers.append({
                "tag": dns_tag,
                "type": "tls",
                "server": "1.1.1.1",
                "detour": tag
            })


# ============ V2Ray Egress 支持 ============


def load_v2ray_egress() -> List[dict]:
    """从数据库加载 V2Ray 出口配置"""
    if not HAS_DATABASE:
        return []
    try:
        db = get_db(str(GEODATA_DB_PATH), str(USER_DB_PATH))
        egress_list = db.get_v2ray_egress_list(enabled_only=True)
        return egress_list
    except Exception as e:
        print(f"[render] 从数据库加载 V2Ray 出口配置失败: {e}")
        return []


def _build_v2ray_outbound(egress: dict) -> dict:
    """构建 V2Ray outbound 配置（支持 VMess, VLESS, Trojan）"""
    protocol = egress.get("protocol")
    tag = egress.get("tag")

    outbound = {
        "type": protocol,
        "tag": tag,
        "server": egress.get("server"),
        "server_port": egress.get("server_port", 443),
    }

    # Protocol-specific auth
    if protocol == "vmess":
        outbound["uuid"] = egress.get("uuid")
        outbound["security"] = egress.get("security", "auto")
        if egress.get("alter_id"):
            outbound["alter_id"] = egress.get("alter_id")
    elif protocol == "vless":
        outbound["uuid"] = egress.get("uuid")
        if egress.get("flow"):
            outbound["flow"] = egress.get("flow")
    elif protocol == "trojan":
        outbound["password"] = egress.get("password")

    # TLS configuration
    if egress.get("tls_enabled"):
        tls_config = {"enabled": True}
        if egress.get("tls_sni"):
            tls_config["server_name"] = egress.get("tls_sni")
        if egress.get("tls_alpn"):
            alpn = egress.get("tls_alpn")
            if isinstance(alpn, str):
                alpn = [a.strip() for a in alpn.split(",")]
            tls_config["alpn"] = alpn
        if egress.get("tls_allow_insecure"):
            tls_config["insecure"] = True
        if egress.get("tls_fingerprint"):
            tls_config["utls"] = {"enabled": True, "fingerprint": egress.get("tls_fingerprint")}

        # REALITY (VLESS only)
        if egress.get("reality_enabled") and protocol == "vless":
            tls_config["reality"] = {
                "enabled": True,
                "public_key": egress.get("reality_public_key"),
                "short_id": egress.get("reality_short_id")
            }

        outbound["tls"] = tls_config

    # Transport configuration
    transport_type = egress.get("transport_type", "tcp")
    transport_config = egress.get("transport_config")
    if transport_type and transport_type != "tcp":
        transport = {"type": transport_type}
        if transport_config:
            if isinstance(transport_config, str):
                import json
                transport_config = json.loads(transport_config)
            transport.update(transport_config)
        outbound["transport"] = transport

    # Multiplex
    if egress.get("multiplex_enabled"):
        multiplex = {"enabled": True}
        if egress.get("multiplex_protocol"):
            multiplex["protocol"] = egress.get("multiplex_protocol")
        if egress.get("multiplex_max_connections"):
            multiplex["max_connections"] = egress.get("multiplex_max_connections")
        if egress.get("multiplex_min_streams"):
            multiplex["min_streams"] = egress.get("multiplex_min_streams")
        if egress.get("multiplex_max_streams"):
            multiplex["max_streams"] = egress.get("multiplex_max_streams")
        outbound["multiplex"] = multiplex

    return outbound


def ensure_v2ray_egress_outbounds(config: dict, v2ray_egress: List[dict]) -> List[str]:
    """确保每个 V2Ray 出口都有对应的 outbound

    Returns:
        所有 V2Ray 出口的 tag 列表
    """
    if not v2ray_egress:
        return []

    outbounds = config.setdefault("outbounds", [])
    existing_tags = {ob.get("tag") for ob in outbounds}
    v2ray_tags = []

    for egress in v2ray_egress:
        tag = egress.get("tag")
        if not tag:
            continue

        v2ray_tags.append(tag)
        outbound = _build_v2ray_outbound(egress)

        if tag in existing_tags:
            # Update existing
            for i, ob in enumerate(outbounds):
                if ob.get("tag") == tag:
                    outbounds[i] = outbound
                    break
        else:
            # Insert before block
            block_idx = next((i for i, ob in enumerate(outbounds) if ob.get("tag") == "block"), len(outbounds))
            outbounds.insert(block_idx, outbound)
            print(f"[render] 创建 V2Ray 出口 ({egress.get('protocol')}): {tag}")

    return v2ray_tags


def ensure_v2ray_dns_servers(config: dict, v2ray_tags: List[str]) -> None:
    """为 V2Ray 出口添加 DNS 服务器"""
    if not v2ray_tags:
        return

    dns = config.setdefault("dns", {})
    servers = dns.setdefault("servers", [])
    existing_tags = {s.get("tag") for s in servers}

    for tag in v2ray_tags:
        dns_tag = f"{tag}-dns"
        if dns_tag not in existing_tags:
            servers.append({
                "tag": dns_tag,
                "type": "tls",
                "server": "1.1.1.1",
                "detour": tag
            })


# ============ WARP Egress 支持 ============
# Cloudflare WARP 通过 usque (MASQUE 协议) 提供出口
# - 每个 WARP 出口运行独立的 usque SOCKS5 代理
# - sing-box 通过 SOCKS outbound 连接到 usque


def load_warp_egress() -> List[dict]:
    """从数据库加载 WARP 出口配置"""
    if not HAS_DATABASE:
        return []
    try:
        db = get_db(str(GEODATA_DB_PATH), str(USER_DB_PATH))
        egress_list = db.get_warp_egress_list(enabled_only=True)
        return egress_list
    except Exception as e:
        print(f"[render] 从数据库加载 WARP 出口配置失败: {e}")
        return []


def ensure_warp_egress_outbounds(config: dict, warp_egress: List[dict]) -> List[str]:
    """确保每个 WARP 出口都有对应的 outbound

    WARP 支持两种协议:
    - MASQUE: 通过 usque SOCKS5 代理桥接 (sing-box SOCKS outbound)
    - WireGuard: 通过内核 WireGuard 接口 (sing-box direct outbound + bind_interface)

    Args:
        config: sing-box 配置
        warp_egress: WARP 出口列表

    Returns:
        所有 WARP 出口的 tag 列表
    """
    if not warp_egress:
        return []

    # Import here to avoid circular dependency
    from setup_kernel_wg_egress import get_egress_interface_name

    outbounds = config.setdefault("outbounds", [])
    existing_tags = {ob.get("tag") for ob in outbounds}
    warp_tags = []

    for egress in warp_egress:
        tag = egress.get("tag")
        protocol = egress.get("protocol", "masque")

        if not tag:
            print(f"[render] 警告: WARP 出口缺少 tag，跳过")
            continue

        warp_tags.append(tag)

        if protocol == "wireguard":
            # WireGuard 协议: 使用内核 WireGuard 接口
            interface = get_egress_interface_name(tag, egress_type="warp")
            outbound = {
                "type": "direct",
                "tag": tag,
                "bind_interface": interface
            }
            outbound_type = f"direct -> {interface}"
        else:
            # MASQUE 协议: 使用 usque SOCKS5 代理
            socks_port = egress.get("socks_port")
            if not socks_port:
                print(f"[render] 警告: WARP MASQUE 出口 {tag} 缺少 socks_port，跳过")
                continue
            outbound = {
                "type": "socks",
                "tag": tag,
                "server": "127.0.0.1",
                "server_port": socks_port
            }
            outbound_type = f"SOCKS -> 127.0.0.1:{socks_port}"

        if tag in existing_tags:
            # 更新现有 outbound
            for i, ob in enumerate(outbounds):
                if ob.get("tag") == tag:
                    outbounds[i] = outbound
                    break
        else:
            # 在 block 之前插入
            block_idx = next((i for i, ob in enumerate(outbounds) if ob.get("tag") == "block"), len(outbounds))
            outbounds.insert(block_idx, outbound)
            print(f"[render] 创建 WARP 出口 ({protocol}): {tag} -> {outbound_type}")

    return warp_tags


def ensure_warp_dns_servers(config: dict, warp_tags: List[str]) -> None:
    """为 WARP 出口添加 DNS 服务器

    WARP 使用 Cloudflare 的 1.1.1.1 DNS，通过 SOCKS 代理访问。
    这确保 DNS 查询也通过 WARP 隧道，防止 DNS 泄露。

    sing-box 1.12+ 使用新的 DNS 服务器格式（type + server）
    """
    if not warp_tags:
        return

    dns = config.setdefault("dns", {})
    servers = dns.setdefault("servers", [])
    existing_tags = {s.get("tag") for s in servers}

    for tag in warp_tags:
        dns_tag = f"{tag}-dns"
        if dns_tag not in existing_tags:
            servers.append({
                "tag": dns_tag,
                "type": "tls",
                "server": "1.1.1.1",  # Cloudflare DNS
                "detour": tag
            })


# ============ V2Ray Inbound 支持 ============


def load_v2ray_inbound_config() -> Optional[dict]:
    """从数据库加载 V2Ray 入口配置"""
    if not HAS_DATABASE:
        return None
    try:
        db = get_db(str(GEODATA_DB_PATH), str(USER_DB_PATH))
        config = db.get_v2ray_inbound_config()
        if not config or not config.get("enabled"):
            return None

        users = db.get_v2ray_users(enabled_only=True)
        if not users:
            print("[render] 警告: V2Ray 入口没有配置用户")
            return None

        return {"config": config, "users": users}
    except Exception as e:
        print(f"[render] 从数据库加载 V2Ray 入口配置失败: {e}")
        return None


def ensure_v2ray_inbound(config: dict) -> bool:
    """确保 V2Ray 入口存在

    注意: 当启用 Xray 模式（V2Ray 入口配置已启用）时，
    V2Ray 流量由独立的 Xray 进程处理，不需要在 sing-box 中创建 inbound。
    Xray 通过 TUN 设备将解密后的流量发送到 sing-box 的 TPROXY 入口。

    Returns:
        True if V2Ray inbound was created, False otherwise
    """
    v2ray_config = load_v2ray_inbound_config()
    if not v2ray_config:
        return False

    cfg = v2ray_config["config"]

    # 当 V2Ray 入口启用时，Xray 进程会处理 V2Ray 流量
    # 不需要在 sing-box 中创建 V2Ray inbound
    # Xray 解密后的流量通过 TUN + TPROXY 进入 sing-box
    if cfg.get("enabled"):
        print(f"[render] V2Ray 入口由 Xray 进程处理 (TUN + TPROXY 模式)")
        # 移除任何旧的 v2ray-in inbound
        inbounds = config.setdefault("inbounds", [])
        inbounds[:] = [ib for ib in inbounds if ib.get("tag") != "v2ray-in"]
        return False

    # 以下是旧的 sing-box 内置 V2Ray 支持（保留供参考但不再使用）
    inbounds = config.setdefault("inbounds", [])
    users = v2ray_config["users"]
    protocol = cfg.get("protocol")

    # Build users list
    users_config = []
    for user in users:
        user_cfg = {"name": user.get("name")}
        if protocol in ("vmess", "vless"):
            user_cfg["uuid"] = user.get("uuid")
        elif protocol == "trojan":
            user_cfg["password"] = user.get("password")
        if protocol == "vmess" and user.get("alter_id"):
            user_cfg["alter_id"] = user.get("alter_id")
        if protocol == "vless" and user.get("flow"):
            user_cfg["flow"] = user.get("flow")
        users_config.append(user_cfg)

    inbound = {
        "type": protocol,
        "tag": "v2ray-in",
        "listen": cfg.get("listen_address", "0.0.0.0"),
        "listen_port": cfg.get("listen_port", 443),
        "users": users_config
    }

    # TLS
    if cfg.get("tls_enabled"):
        tls = {"enabled": True}
        if cfg.get("tls_cert_content"):
            tls["certificate"] = cfg.get("tls_cert_content")
            tls["key"] = cfg.get("tls_key_content")
        elif cfg.get("tls_cert_path"):
            tls["certificate_path"] = cfg.get("tls_cert_path")
            tls["key_path"] = cfg.get("tls_key_path")
        inbound["tls"] = tls

    # Transport
    transport_type = cfg.get("transport_type", "tcp")
    if transport_type != "tcp":
        transport = {"type": transport_type}
        transport_config = cfg.get("transport_config")
        if transport_config:
            if isinstance(transport_config, str):
                import json
                transport_config = json.loads(transport_config)
            transport.update(transport_config)
        inbound["transport"] = transport

    # VLESS fallback
    if protocol == "vless" and cfg.get("fallback_server"):
        inbound["fallback"] = {
            "server": cfg.get("fallback_server"),
            "server_port": cfg.get("fallback_port", 80)
        }

    # Remove old v2ray-in
    inbounds[:] = [ib for ib in inbounds if ib.get("tag") != "v2ray-in"]
    inbounds.insert(0, inbound)

    print(f"[render] 创建 V2Ray 入口: {protocol} (端口 {cfg.get('listen_port')})")
    return True


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


# 合并后的广告拦截规则集固定 tag（用于 Dashboard 统计）
ADBLOCK_COMBINED_TAG = "__adblock_combined__"


def generate_adblock_rule_sets() -> Tuple[List[Dict], List[Dict]]:
    """生成广告拦截 rule_set 配置

    从数据库读取已启用的远程规则集，下载并合并为单个 sing-box rule_set。
    使用固定的 tag "__adblock_combined__" 方便 Dashboard 统计。

    Returns:
        (rule_set_configs, route_rules): rule_set 配置和对应的路由规则
    """
    if not HAS_DATABASE or not HAS_ADBLOCK_CONVERTER:
        if not HAS_ADBLOCK_CONVERTER:
            print("[render] 警告: convert_adblock 模块不可用，跳过广告拦截规则")
        return [], []

    try:
        db = get_db(str(GEODATA_DB_PATH), str(USER_DB_PATH))
        rules = db.get_remote_rule_sets(enabled_only=True)
    except Exception as e:
        print(f"[render] 警告: 无法加载远程规则集: {e}")
        return [], []

    if not rules:
        return [], []

    # 确保 rulesets 目录存在
    RULESETS_DIR.mkdir(parents=True, exist_ok=True)

    # 合并所有规则的域名
    all_domains: Set[str] = set()
    processed_sources = []

    for rule in rules:
        tag = rule["tag"]
        url = rule["url"]
        format_type = rule.get("format", "adblock")

        try:
            # 下载并转换
            print(f"[render] 下载广告规则: {tag} ({url[:50]}...)")
            domains = download_and_convert(url, format_type)

            if not domains:
                print(f"[render] 警告: {tag} 未获取到任何域名，跳过")
                continue

            # 更新数据库中的域名数量和更新时间
            try:
                db.update_remote_rule_set(
                    tag,
                    domain_count=len(domains),
                    last_updated=datetime.now().isoformat()
                )
            except Exception:
                pass  # 更新失败不影响配置生成

            # 合并域名
            before_count = len(all_domains)
            all_domains.update(domains)
            new_count = len(all_domains) - before_count

            processed_sources.append(tag)
            print(f"[render] 已处理 {tag}: {len(domains):,} 个域名 (+{new_count:,} 新增)")

        except Exception as e:
            print(f"[render] 警告: 处理 {tag} 失败: {e}")
            continue

    if not all_domains:
        return [], []

    # 保存合并后的 rule_set
    combined_path = RULESETS_DIR / f"{ADBLOCK_COMBINED_TAG}.json"
    save_singbox_ruleset(list(all_domains), combined_path)

    print(f"[render] 广告拦截规则已合并: {len(processed_sources)} 个来源, {len(all_domains):,} 个唯一域名")

    # 返回单个合并的 rule_set 配置
    rule_set_configs = [{
        "tag": ADBLOCK_COMBINED_TAG,
        "type": "local",
        "format": "source",
        "path": str(combined_path)
    }]

    route_rules = [{
        "rule_set": [ADBLOCK_COMBINED_TAG],
        "outbound": "adblock"
    }]

    return rule_set_configs, route_rules


def load_custom_rules() -> Dict[str, Any]:
    """从数据库加载自定义路由规则和默认出口

    支持的规则类型:
    - domain, domain_keyword, ip: 传统域名/IP 规则
    - protocol: 协议匹配 (bittorrent, stun, ssh, etc.)
    - network: 网络类型 (tcp, udp)
    - port: 端口匹配
    - port_range: 端口范围匹配
    """
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
                    "ip_cidrs": [],
                    # 新增类型
                    "protocols": [],
                    "network": None,
                    "ports": [],
                    "port_ranges": []
                }

            rule_type = rule["rule_type"]
            target = rule["target"]

            if rule_type == "domain":
                rules_by_tag[tag]["domains"].append(target)
            elif rule_type == "domain_keyword":
                rules_by_tag[tag]["domain_keywords"].append(target)
            elif rule_type == "ip":
                rules_by_tag[tag]["ip_cidrs"].append(target)
            # 新增规则类型
            elif rule_type == "protocol":
                rules_by_tag[tag]["protocols"].append(target)
            elif rule_type == "network":
                rules_by_tag[tag]["network"] = target
            elif rule_type == "port":
                try:
                    rules_by_tag[tag]["ports"].append(int(target))
                except ValueError:
                    print(f"[render] 警告: 无效端口值 '{target}'，跳过")
            elif rule_type == "port_range":
                rules_by_tag[tag]["port_ranges"].append(target)

        result["rules"] = list(rules_by_tag.values())
        return result

    except Exception as e:
        print(f"[render] 警告: 从数据库加载规则失败: {e}")
        # 降级到 JSON 文件
        if CUSTOM_RULES_FILE.exists():
            return json.loads(CUSTOM_RULES_FILE.read_text())
        return result


def apply_custom_rules(config: dict, custom_rules: Dict[str, Any], valid_outbounds: List[str]) -> None:
    """应用自定义路由规则到配置

    支持的规则类型:
    - domain/domain_keyword/ip: 使用 rule_set
    - protocol/network/port/port_range: 直接添加路由规则

    Args:
        config: sing-box 配置
        custom_rules: 自定义规则配置
        valid_outbounds: 有效的出口标签列表（用于过滤无效规则）
    """
    route = config.setdefault("route", {})
    rule_set = route.setdefault("rule_set", [])
    rules = route.setdefault("rules", [])

    # 始终有效的出口：direct, block, adblock
    always_valid = {"direct", "block", "adblock"}
    all_valid = always_valid | set(valid_outbounds)

    # 获取现有的 custom rule_set tags
    existing_custom_tags = set()
    for rs in rule_set:
        if rs.get("tag", "").startswith("custom-"):
            existing_custom_tags.add(rs.get("tag"))

    # 移除旧的 custom 规则（包括 rule_set 和直接规则）
    rule_set[:] = [rs for rs in rule_set if not rs.get("tag", "").startswith("custom-")]
    rules[:] = [r for r in rules if not any(
        t.startswith("custom-") for t in r.get("rule_set", [])
    ) and not r.get("_custom_tag", "").startswith("custom-")]

    # 添加新的自定义规则
    skipped_rules = []
    for custom_rule in custom_rules.get("rules", []):
        rule_tag = custom_rule.get("tag", "")
        if not rule_tag.startswith("custom-") and not rule_tag.startswith("__adblock__"):
            rule_tag = f"custom-{rule_tag}"

        domains = custom_rule.get("domains", [])
        domain_keywords = custom_rule.get("domain_keywords", [])
        ip_cidrs = custom_rule.get("ip_cidrs", [])
        # 新增类型
        protocols = custom_rule.get("protocols", [])
        network = custom_rule.get("network")
        ports = custom_rule.get("ports", [])
        port_ranges = custom_rule.get("port_ranges", [])

        outbound = custom_rule.get("outbound", "direct")

        # 过滤掉指向不存在出口的规则
        if outbound not in all_valid:
            skipped_rules.append(f"{rule_tag} -> {outbound}")
            continue

        # 检查是否有域名/IP 类规则（使用 rule_set）
        has_domain_ip_rules = domains or domain_keywords or ip_cidrs

        # 检查是否有协议/端口类规则（直接路由规则）
        has_protocol_port_rules = protocols or network or ports or port_ranges

        # 处理域名/IP 规则（使用 inline rule_set）
        if has_domain_ip_rules:
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

        # 处理协议/端口规则（直接添加路由规则）
        if has_protocol_port_rules:
            protocol_rule = {"outbound": outbound, "_custom_tag": rule_tag}

            if protocols:
                protocol_rule["protocol"] = protocols
            if network:
                protocol_rule["network"] = network
            if ports:
                protocol_rule["port"] = ports
            if port_ranges:
                # sing-box 需要 "start:end" 格式，转换 "start-end" 格式
                converted_ranges = [pr.replace("-", ":") for pr in port_ranges]
                protocol_rule["port_range"] = converted_ranges

            # 协议/端口规则优先级较低，插入到列表后面（在 domain 规则之后）
            rules.append(protocol_rule)

    # 清理临时标记字段（sing-box 不认识 _custom_tag）
    for r in rules:
        if "_custom_tag" in r:
            del r["_custom_tag"]

    # 输出跳过的规则警告
    if skipped_rules:
        print(f"[render] 警告: 跳过 {len(skipped_rules)} 条指向无效出口的规则: {skipped_rules}")

    # 更新默认出口（验证是否有效）
    default_outbound = custom_rules.get("default_outbound")
    if default_outbound:
        if default_outbound in all_valid:
            route["final"] = default_outbound
            # 同时设置 DNS final，使用对应的 DNS 服务器
            dns = config.setdefault("dns", {})
            dns_servers = dns.get("servers", [])
            dns_tag = f"{default_outbound}-dns"
            # 检查对应的 DNS 服务器是否存在
            if any(s.get("tag") == dns_tag for s in dns_servers):
                dns["final"] = dns_tag
                print(f"[render] DNS final 设置为: {dns_tag}")
            elif default_outbound == "direct":
                dns["final"] = "direct-dns"
                print(f"[render] DNS final 设置为: direct-dns")
            else:
                # 如果没有对应的 DNS 服务器，使用 direct-dns
                dns["final"] = "direct-dns"
                print(f"[render] 警告: 未找到 {dns_tag}，DNS final 使用 direct-dns")
        else:
            print(f"[render] 警告: 默认出口 '{default_outbound}' 无效，使用 'direct'")
            route["final"] = "direct"
            dns = config.setdefault("dns", {})
            dns["final"] = "direct-dns"


def ensure_log_config(config: dict) -> None:
    """确保日志配置正确（包含 output 路径用于 adblock 统计）"""
    log_config = config.setdefault("log", {})
    if "output" not in log_config:
        log_config["output"] = "/var/log/sing-box.log"
        print("[render] 已添加日志输出路径: /var/log/sing-box.log")
    if "timestamp" not in log_config:
        log_config["timestamp"] = True
    if "level" not in log_config:
        log_config["level"] = "debug"  # 临时调试


def ensure_required_outbounds(config: dict) -> None:
    """确保必需的 outbounds 存在（direct, block, adblock）"""
    outbounds = config.setdefault("outbounds", [])
    existing_tags = {o.get("tag") for o in outbounds}

    required_outbounds = [
        {"type": "direct", "tag": "direct"},
        {"type": "block", "tag": "block"},
        {"type": "block", "tag": "adblock"}
    ]

    for outbound in required_outbounds:
        if outbound["tag"] not in existing_tags:
            outbounds.append(outbound)
            print(f"[render] 已添加缺失的 outbound: {outbound['tag']}")


def ensure_xray_socks_inbound(config: dict) -> bool:
    """为 Xray 流量添加 SOCKS5 入口

    当 V2Ray 入口启用时，Xray 需要一个方式将解密后的流量发送到 sing-box。
    这个 SOCKS5 入口允许 Xray 使用 SOCKS 协议连接到 sing-box，
    比 TUN + TPROXY 方式更简单可靠。

    端口: 38501 (固定，避免与 WARP SOCKS 38001+ 冲突)

    Returns:
        True if inbound was added, False otherwise
    """
    v2ray_config = load_v2ray_inbound_config()
    if not v2ray_config:
        return False

    cfg = v2ray_config.get("config", {})
    if not cfg.get("enabled"):
        return False

    inbounds = config.setdefault("inbounds", [])

    # 检查是否已存在
    for ib in inbounds:
        if ib.get("tag") == "xray-in":
            return False

    # 添加 SOCKS5 入口
    # 端口 38501 避免与 WARP SOCKS (38001+) 冲突
    inbound = {
        "type": "socks",
        "tag": "xray-in",
        "listen": "127.0.0.1",
        "listen_port": 38501,
        # 启用流量嗅探以支持域名路由
        "sniff": True,
        "sniff_override_destination": False
    }
    inbounds.append(inbound)
    print("[render] 已添加 Xray SOCKS 入口 (127.0.0.1:38501, sniff=true)")
    return True


def ensure_speed_test_inbounds(config: dict, egress_tags: List[str]) -> None:
    """为 WireGuard/V2Ray 出口添加测速用 SOCKS inbound

    每个出口（PIA WireGuard + 自定义 WireGuard + V2Ray）都会获得一个专用的 SOCKS inbound，
    用于测速时强制流量通过该出口。

    端口映射:
    - 第1个出口 -> socks://127.0.0.1:39001
    - 第2个出口 -> socks://127.0.0.1:39002
    - ...

    Args:
        config: sing-box 配置
        egress_tags: 出口 tag 列表 (WireGuard + V2Ray)
    """
    if not egress_tags:
        return

    inbounds = config.setdefault("inbounds", [])
    route = config.setdefault("route", {})
    rules = route.setdefault("rules", [])

    # 获取已存在的 inbound tags
    existing_inbound_tags = {ib.get("tag") for ib in inbounds}

    base_port = 39001  # 测速 SOCKS 端口起始
    added_count = 0

    for i, tag in enumerate(sorted(egress_tags)):
        socks_port = base_port + i
        inbound_tag = f"speedtest-{tag}"

        # 跳过已存在的 inbound
        if inbound_tag in existing_inbound_tags:
            continue

        # 添加 SOCKS inbound
        inbound = {
            "type": "socks",
            "tag": inbound_tag,
            "listen": "127.0.0.1",
            "listen_port": socks_port
        }
        inbounds.append(inbound)

        # 添加路由规则：从该 inbound 的流量直接走对应出口
        # 这个规则需要高优先级，插入到 rules 的前面
        route_rule = {
            "inbound": inbound_tag,
            "outbound": tag
        }
        rules.insert(0, route_rule)

        added_count += 1

    if added_count > 0:
        print(f"[render] 已添加 {added_count} 个测速 SOCKS inbound (端口 {base_port}-{base_port + len(egress_tags) - 1})")


def main() -> None:
    config = load_json(BASE_CONFIG)

    # 确保日志配置正确（用于 adblock 统计）
    ensure_log_config(config)

    # 确保必需的 outbounds 存在（direct, block, adblock）
    ensure_required_outbounds(config)

    # 根据数据库设置更新 direct-dns 配置
    ensure_direct_dns_config(config)

    all_egress_tags = []

    # 确保 TPROXY 入口存在（接收内核 WireGuard 转发流量）
    if ensure_tproxy_inbound(config):
        print("[render] TPROXY 入口已配置 (内核 WireGuard 模式)")

    # 确保 V2Ray 入口存在（如果配置启用）
    if ensure_v2ray_inbound(config):
        pass  # 日志已在函数内打印

    # 确保 Xray SOCKS5 入口存在（Xray 通过 SOCKS5 连接 sing-box）
    # 使用 SOCKS5 代替 WireGuard，避免复杂的路由问题
    ensure_xray_socks_inbound(config)

    # 从数据库加载 PIA profiles 和自定义 WireGuard 出口
    pia_profiles = load_pia_profiles_from_db()
    custom_egress = load_custom_egress()

    # 使用内核 WireGuard 模块处理所有 WireGuard 出口
    # 这些接口由 setup_kernel_wg_egress.py 在容器启动时创建
    # sing-box 使用 direct outbound + bind_interface 将流量发送到内核接口
    wg_egress_tags = ensure_kernel_wg_egress_outbounds(config, pia_profiles, custom_egress)

    if wg_egress_tags:
        print(f"[render] 内核 WireGuard 出口: {wg_egress_tags}")
        all_egress_tags.extend(wg_egress_tags)

        # 确保 DNS 服务器存在
        if pia_profiles and pia_profiles.get("profiles"):
            profile_map = {name: name for name in pia_profiles["profiles"].keys()
                          if pia_profiles["profiles"][name].get("private_key")}
            ensure_dns_servers(config, profile_map)

        if custom_egress:
            custom_tags = [e.get("tag") for e in custom_egress if e.get("tag")]
            ensure_custom_dns_servers(config, custom_tags)

    # 加载并处理 direct 出口（绑定特定接口/IP）
    direct_egress = load_direct_egress()
    if direct_egress:
        print(f"[render] 处理 {len(direct_egress)} 个 direct 出口")
        direct_tags = ensure_direct_egress_outbounds(config, direct_egress)
        all_egress_tags.extend(direct_tags)

    # 加载并处理 OpenVPN 出口（通过 SOCKS5 代理桥接）
    openvpn_egress = load_openvpn_egress()
    if openvpn_egress:
        print(f"[render] 处理 {len(openvpn_egress)} 个 OpenVPN 出口")
        openvpn_tags = ensure_openvpn_egress_outbounds(config, openvpn_egress)
        ensure_openvpn_dns_servers(config, openvpn_tags)
        all_egress_tags.extend(openvpn_tags)

    # 加载并处理 V2Ray 出口（支持 VMess, VLESS, Trojan）
    # 使用 Xray 进程处理所有 V2Ray 出口，通过 SOCKS5 代理桥接
    # Xray 提供 sing-box 不支持的功能：XHTTP, REALITY, XTLS-Vision
    v2ray_egress = load_v2ray_egress()
    if v2ray_egress:
        print(f"[render] 处理 {len(v2ray_egress)} 个 V2Ray 出口 (通过 Xray SOCKS5)")
        v2ray_tags = ensure_xray_egress_outbounds(config, v2ray_egress)
        ensure_v2ray_dns_servers(config, v2ray_tags)
        all_egress_tags.extend(v2ray_tags)

    # 加载并处理 WARP 出口（Cloudflare WARP 通过 usque MASQUE 协议）
    # 每个 WARP 出口运行独立的 usque SOCKS5 代理
    warp_egress = load_warp_egress()
    if warp_egress:
        print(f"[render] 处理 {len(warp_egress)} 个 WARP 出口 (通过 usque SOCKS5)")
        warp_tags = ensure_warp_egress_outbounds(config, warp_egress)
        ensure_warp_dns_servers(config, warp_tags)
        all_egress_tags.extend(warp_tags)

    # 收集需要测速 SOCKS inbound 的出口 tags（WireGuard + V2Ray + WARP）
    # wg_egress_tags 已包含 PIA 和自定义 WireGuard 出口
    speedtest_tags = list(wg_egress_tags) if wg_egress_tags else []
    if v2ray_egress:
        speedtest_tags.extend([e.get("tag") for e in v2ray_egress if e.get("tag") and e.get("enabled", 1)])

    # 为 WireGuard/V2Ray 出口添加测速 SOCKS inbound
    if speedtest_tags:
        ensure_speed_test_inbounds(config, speedtest_tags)

    # 清理不再存在于数据库中的旧端点
    cleanup_stale_endpoints(config, all_egress_tags)

    # 检查是否有任何出口配置
    if not all_egress_tags:
        print("[render] 警告: 没有找到任何出口配置（PIA 或自定义）")
        # 仍然生成配置，只是没有 VPN 出口

    # 更新 selector outbound（如果有的话）
    if all_egress_tags:
        ensure_outbound_selector(config, all_egress_tags)

    # 应用自定义规则（传入有效出口列表用于验证）
    custom_rules = load_custom_rules()
    if custom_rules.get("rules") or custom_rules.get("default_outbound"):
        apply_custom_rules(config, custom_rules, all_egress_tags)
        if custom_rules.get("rules"):
            print(f"[render] 应用了 {len(custom_rules['rules'])} 条自定义规则")
        if custom_rules.get("default_outbound"):
            print(f"[render] 默认出口设置为: {custom_rules['default_outbound']}")

    # 生成广告拦截 rule_set
    adblock_rule_sets, adblock_route_rules = generate_adblock_rule_sets()
    if adblock_rule_sets:
        route = config.setdefault("route", {})
        rule_set = route.setdefault("rule_set", [])
        rules = route.setdefault("rules", [])

        # 添加 rule_set 配置
        rule_set.extend(adblock_rule_sets)

        # 添加路由规则（广告拦截规则应该在较低优先级，排在 sniff/hijack-dns 和自定义规则之后）
        # 但排在 final 之前
        rules.extend(adblock_route_rules)

        print(f"[render] 已添加 {len(adblock_rule_sets)} 个广告拦截 rule_set")

    # 确保路由规则中有 sniff 动作（放在最后以确保它在规则列表开头）
    ensure_sniff_action(config)

    # 生成 LAN 访问规则（在 sniff 之后，其他规则之前）
    generate_lan_access_rules(config)

    # 添加 experimental API 用于获取连接状态
    # 收集所有需要统计的出口（包括 direct, block, adblock 和所有 egress）
    stats_outbounds = ["direct", "block", "adblock"] + all_egress_tags

    config["experimental"] = {
        "clash_api": {
            "external_controller": "127.0.0.1:9090",
            "secret": ""
        },
        "v2ray_api": {
            "listen": "127.0.0.1:10085",
            "stats": {
                "enabled": True,
                "outbounds": stats_outbounds
            }
        },
        "cache_file": {
            "enabled": True,
            "path": "/etc/sing-box/cache.db"
        }
    }
    print("[render] 已启用 clash_api (127.0.0.1:9090)")
    print(f"[render] 已启用 v2ray_api (127.0.0.1:10085) 统计 {len(stats_outbounds)} 个出口")

    # H7: 原子写入配置文件，防止 sing-box 读取到不完整配置
    config_json = json.dumps(config, indent=2)
    tmp_fd, tmp_path = tempfile.mkstemp(dir=OUTPUT.parent, suffix=".tmp")
    try:
        os.write(tmp_fd, config_json.encode('utf-8'))
        os.close(tmp_fd)
        shutil.move(tmp_path, OUTPUT)
        print(f"[sing-box] 已写入 {OUTPUT} (原子写入)")
    except Exception as e:
        os.close(tmp_fd)
        if os.path.exists(tmp_path):
            os.unlink(tmp_path)
        raise e


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:  # pylint: disable=broad-except
        print(f"[sing-box] 渲染失败: {exc}", file=sys.stderr)
        sys.exit(1)

#!/usr/bin/env python3
"""从数据库读取 WireGuard 配置并输出 JSON 格式"""
import json
import sys
from pathlib import Path

# 添加模块搜索路径
sys.path.insert(0, str(Path(__file__).parent))

from db_helper import get_db

GEODATA_DB_PATH = Path("/etc/sing-box/geoip-geodata.db")
USER_DB_PATH = Path("/etc/sing-box/user-config.db")

def get_wg_config_from_db():
    """从数据库读取 WireGuard 配置"""
    if not USER_DB_PATH.exists():
        return None

    db = get_db(str(GEODATA_DB_PATH), str(USER_DB_PATH))

    # 获取服务器配置
    server = db.get_wireguard_server()
    if not server:
        return None

    # 获取对等点配置
    peers = db.get_wireguard_peers(enabled_only=True)

    # 构造配置
    config = {
        "interface": {
            "name": server.get("interface_name", "wg-ingress"),
            "address": server.get("address", "10.23.0.1/24"),
            "listen_port": server.get("listen_port", 36100),
            "mtu": server.get("mtu", 1420),
            "private_key": server.get("private_key", "")
        },
        "peers": []
    }

    for peer in peers:
        allowed_ips = peer.get("allowed_ips", "")
        if isinstance(allowed_ips, str):
            allowed_ips = [ip.strip() for ip in allowed_ips.split(",")]

        peer_config = {
            "name": peer.get("name"),
            "public_key": peer.get("public_key"),
            "allowed_ips": allowed_ips
        }

        if peer.get("preshared_key"):
            peer_config["preshared_key"] = peer["preshared_key"]

        config["peers"].append(peer_config)

    return config

if __name__ == "__main__":
    config = get_wg_config_from_db()
    if config:
        print(json.dumps(config, indent=2))
        sys.exit(0)
    else:
        print("{}", file=sys.stderr)
        sys.exit(1)

#!/usr/bin/env python3
"""
VMess/Trojan 协议检测脚本

检测数据库中使用 VMess 或 Trojan 协议的配置，
帮助用户迁移到 VLESS 协议以兼容 Xray-lite。

使用方法:
    python3 detect_vmess_trojan.py [--fix]

选项:
    --fix    自动将 VMess/Trojan 配置标记为禁用
"""

import argparse
import json
import os
import sys
from pathlib import Path

# 添加脚本目录到 Python 路径
sys.path.insert(0, str(Path(__file__).parent))

from db_helper import get_db

GEODATA_DB_PATH = os.environ.get("GEODATA_DB_PATH", "/etc/sing-box/geoip-geodata.db")
USER_DB_PATH = os.environ.get("USER_DB_PATH", "/etc/sing-box/user-config.db")


def detect_deprecated_protocols(db) -> dict:
    """检测使用弃用协议的配置

    Returns:
        dict: {
            "v2ray_inbound": {"protocol": str, "enabled": bool} or None,
            "v2ray_egress": [{"tag": str, "protocol": str, "enabled": bool}, ...],
            "peer_nodes": [{"tag": str, "xray_protocol": str}, ...]
        }
    """
    results = {
        "v2ray_inbound": None,
        "v2ray_egress": [],
        "peer_nodes": []
    }

    # 检查 V2Ray 入站配置
    inbound_config = db.get_v2ray_inbound_config()
    if inbound_config:
        protocol = inbound_config.get("protocol", "vless")
        if protocol in ("vmess", "trojan"):
            results["v2ray_inbound"] = {
                "protocol": protocol,
                "enabled": inbound_config.get("enabled", False)
            }

    # 检查 V2Ray 出站配置
    egress_list = db.get_v2ray_egress_list()
    for egress in egress_list:
        protocol = egress.get("protocol", "vless")
        if protocol in ("vmess", "trojan"):
            results["v2ray_egress"].append({
                "tag": egress.get("tag"),
                "protocol": protocol,
                "enabled": egress.get("enabled", False)
            })

    # 检查 Peer 节点配置
    peers = db.get_peer_nodes()
    for peer in peers:
        xray_protocol = peer.get("xray_protocol")
        if xray_protocol in ("vmess", "trojan"):
            results["peer_nodes"].append({
                "tag": peer.get("tag"),
                "xray_protocol": xray_protocol
            })

    return results


def print_report(results: dict) -> bool:
    """打印检测报告

    Returns:
        bool: True 如果发现弃用协议
    """
    found_deprecated = False

    print("\n" + "=" * 60)
    print("VMess/Trojan 协议弃用检测报告")
    print("=" * 60)

    # V2Ray 入站
    if results["v2ray_inbound"]:
        found_deprecated = True
        inbound = results["v2ray_inbound"]
        status = "启用" if inbound["enabled"] else "禁用"
        print(f"\n[!] V2Ray 入站配置使用弃用协议:")
        print(f"    协议: {inbound['protocol'].upper()}")
        print(f"    状态: {status}")
        print(f"    建议: 迁移到 VLESS 协议")

    # V2Ray 出站
    if results["v2ray_egress"]:
        found_deprecated = True
        print(f"\n[!] 发现 {len(results['v2ray_egress'])} 个使用弃用协议的 V2Ray 出站:")
        for egress in results["v2ray_egress"]:
            status = "启用" if egress["enabled"] else "禁用"
            print(f"    - {egress['tag']}: {egress['protocol'].upper()} ({status})")

    # Peer 节点
    if results["peer_nodes"]:
        found_deprecated = True
        print(f"\n[!] 发现 {len(results['peer_nodes'])} 个使用弃用协议的 Peer 节点:")
        for peer in results["peer_nodes"]:
            print(f"    - {peer['tag']}: {peer['xray_protocol'].upper()}")

    if not found_deprecated:
        print("\n[OK] 未发现使用 VMess/Trojan 协议的配置")
        print("     您的配置已兼容 Xray-lite")
    else:
        print("\n" + "-" * 60)
        print("迁移指南: docs/VMESS_TROJAN_MIGRATION.md")
        print("-" * 60)

    print()
    return found_deprecated


def disable_deprecated_configs(db, results: dict, force: bool = False) -> bool:
    """禁用使用弃用协议的配置

    Args:
        db: 数据库连接
        results: detect_deprecated_protocols() 的返回结果
        force: 跳过确认提示

    Returns:
        bool: True 如果成功禁用所有配置，False 如果有错误
    """
    # 统计需要禁用的配置数量
    to_disable = []
    if results["v2ray_inbound"] and results["v2ray_inbound"]["enabled"]:
        to_disable.append(f"V2Ray 入站 ({results['v2ray_inbound']['protocol']})")
    for egress in results["v2ray_egress"]:
        if egress["enabled"]:
            to_disable.append(f"V2Ray 出站: {egress['tag']} ({egress['protocol']})")

    if not to_disable:
        print("[OK] 没有需要禁用的配置")
        return True

    # 显示将要禁用的配置
    print(f"\n将要禁用 {len(to_disable)} 个配置:")
    for item in to_disable:
        print(f"  - {item}")

    # 确认提示（除非 --yes）
    if not force:
        print("\n警告: 此操作将禁用上述配置，但不会删除它们。")
        try:
            confirm = input("是否继续? (y/N): ").strip().lower()
            if confirm not in ("y", "yes"):
                print("[取消] 操作已取消")
                return False
        except (EOFError, KeyboardInterrupt):
            print("\n[取消] 操作已取消")
            return False

    # 执行禁用操作，带错误处理
    errors = []

    # 禁用 V2Ray 入站
    if results["v2ray_inbound"] and results["v2ray_inbound"]["enabled"]:
        try:
            print(f"[FIX] 禁用 V2Ray 入站 ({results['v2ray_inbound']['protocol']})")
            db.update_v2ray_inbound_config(enabled=False)
        except Exception as e:
            errors.append(f"V2Ray 入站: {e}")
            print(f"[错误] 禁用 V2Ray 入站失败: {e}")

    # 禁用 V2Ray 出站
    for egress in results["v2ray_egress"]:
        if egress["enabled"]:
            try:
                print(f"[FIX] 禁用 V2Ray 出站: {egress['tag']} ({egress['protocol']})")
                db.update_v2ray_egress(egress["tag"], enabled=False)
            except Exception as e:
                errors.append(f"V2Ray 出站 {egress['tag']}: {e}")
                print(f"[错误] 禁用 V2Ray 出站 {egress['tag']} 失败: {e}")

    # 注意: Peer 节点的 xray_protocol 字段不能单独禁用，需要用户手动修改
    if results["peer_nodes"]:
        print("\n[注意] Peer 节点使用的 Xray 协议需要手动迁移:")
        for peer in results["peer_nodes"]:
            print(f"  - {peer['tag']}: {peer['xray_protocol'].upper()}")
        print("        请在 Web UI 中编辑 Peer 节点配置")

    if errors:
        print(f"\n[警告] 部分配置禁用失败 ({len(errors)} 个错误)")
        return False

    print("\n[OK] 弃用配置已禁用")
    print("     请创建新的 VLESS 配置替代这些弃用配置")
    return True


def main() -> int:
    """主函数

    Returns:
        int: 退出码 (0=无弃用配置, 1=有弃用配置, 2=错误)
    """
    parser = argparse.ArgumentParser(
        description="检测使用弃用协议 (VMess/Trojan) 的配置"
    )
    parser.add_argument(
        "--fix",
        action="store_true",
        help="自动禁用使用弃用协议的配置"
    )
    parser.add_argument(
        "--yes", "-y",
        action="store_true",
        help="跳过确认提示（与 --fix 一起使用）"
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="以 JSON 格式输出结果"
    )
    args = parser.parse_args()

    try:
        # 获取数据库连接
        db = get_db(GEODATA_DB_PATH, USER_DB_PATH)

        # 检测弃用协议
        results = detect_deprecated_protocols(db)

        if args.json:
            print(json.dumps(results, indent=2, ensure_ascii=False))
            return 0

        # 打印报告
        found_deprecated = print_report(results)

        # 如果指定了 --fix，禁用弃用配置
        if args.fix and found_deprecated:
            success = disable_deprecated_configs(db, results, force=args.yes)
            if not success:
                return 2

        return 1 if found_deprecated else 0

    except Exception as e:
        print(f"[错误] 执行失败: {e}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())

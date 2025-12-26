#!/usr/bin/env python3
"""ECMP 多路径路由管理器

管理出口组的 Linux ECMP 路由表，实现内核级负载均衡。

架构：
    sing-box → direct (routing_mark) → ip rule → ECMP 路由表 → 多个 WireGuard 接口

核心原理：
    - 每个出口组对应一个 Linux 路由表（table 200+）
    - 路由表包含 ECMP 多路径路由
    - sing-box 使用 routing_mark 将流量导向对应路由表
    - 内核基于 5-tuple 哈希自动分散流量

使用方法：
    # 同步所有出口组的 ECMP 路由
    python3 ecmp_manager.py --sync-all

    # 同步单个出口组
    python3 ecmp_manager.py --sync-group <tag>

    # 删除出口组路由
    python3 ecmp_manager.py --teardown-group <tag>

    # 显示路由状态
    python3 ecmp_manager.py --status
"""

import argparse
import json
import logging
import os
import subprocess
import sys
from pathlib import Path
from typing import Dict, List, Optional, Tuple

# 配置日志
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger(__name__)

# 路由表起始号（避免与系统表冲突）
ROUTING_TABLE_START = 200

# 数据库路径
USER_DB_PATH = os.environ.get("USER_DB_PATH", "/etc/sing-box/user-config.db")


def run_command(cmd: List[str], check: bool = True, capture: bool = True) -> Tuple[bool, str, str]:
    """执行系统命令

    Args:
        cmd: 命令列表
        check: 是否检查返回值
        capture: 是否捕获输出

    Returns:
        (success, stdout, stderr)
    """
    try:
        result = subprocess.run(
            cmd,
            capture_output=capture,
            text=True,
            timeout=30
        )
        success = result.returncode == 0
        if not success and check:
            logger.warning(f"Command failed: {' '.join(cmd)}")
            logger.warning(f"stderr: {result.stderr}")
        return success, result.stdout.strip(), result.stderr.strip()
    except subprocess.TimeoutExpired:
        logger.error(f"Command timed out: {' '.join(cmd)}")
        return False, "", "timeout"
    except Exception as e:
        logger.error(f"Command error: {' '.join(cmd)} - {e}")
        return False, "", str(e)


def get_interface_for_egress(db, tag: str) -> Optional[str]:
    """获取出口 tag 对应的内核网络接口名

    支持的出口类型：
    - PIA profiles: wg-pia-{tag}
    - Custom WireGuard: wg-eg-{tag}
    - Direct egress: bind_interface 字段
    - WARP WireGuard: wg-warp-{tag}
    - OpenVPN: tun_device 字段 (tun10, tun11, ...)

    Args:
        db: 数据库管理器
        tag: 出口 tag

    Returns:
        接口名，如果无法确定则返回 None
    """
    # 导入接口名生成函数
    try:
        from db_helper import get_egress_interface_name
    except ImportError:
        from setup_kernel_wg_egress import get_egress_interface_name

    # 检查 PIA profile
    profile = db.get_pia_profile_by_name(tag)
    if profile:
        return get_egress_interface_name(tag, is_pia=True)

    # 检查 Custom WireGuard egress
    custom = db.get_custom_egress(tag)
    if custom:
        return get_egress_interface_name(tag, is_pia=False)

    # 检查 Direct egress（使用绑定接口）
    direct = db.get_direct_egress(tag)
    if direct and direct.get("bind_interface"):
        return direct["bind_interface"]

    # 检查 WARP egress
    warp = db.get_warp_egress(tag)
    if warp:
        # WARP WireGuard 协议使用内核接口
        if warp.get("protocol") == "wireguard":
            # 使用 setup_kernel_wg_egress 的版本（支持 egress_type 参数）
            from setup_kernel_wg_egress import get_egress_interface_name as get_warp_iface
            return get_warp_iface(tag, egress_type="warp")
        else:
            # WARP MASQUE 使用 SOCKS 代理，不是内核接口
            logger.warning(f"WARP egress '{tag}' uses SOCKS proxy, not kernel interface")
            return None

    # 检查 OpenVPN egress（使用 TUN 设备）
    openvpn = db.get_openvpn_egress(tag)
    if openvpn and openvpn.get("tun_device"):
        return openvpn["tun_device"]

    # 检查其他出口组（嵌套）
    group = db.get_outbound_group(tag)
    if group:
        # 嵌套组使用其路由表的 fwmark
        logger.warning(f"Nested group '{tag}' should use routing_mark, not interface")
        return None

    logger.warning(f"Unknown egress type for tag: {tag}")
    return None


def get_all_egress_interfaces(db, members: List[str]) -> Dict[str, str]:
    """获取所有成员出口的接口映射

    Args:
        db: 数据库管理器
        members: 成员 tag 列表

    Returns:
        {tag: interface_name} 映射
    """
    interfaces = {}
    for tag in members:
        iface = get_interface_for_egress(db, tag)
        if iface:
            interfaces[tag] = iface
        else:
            logger.warning(f"Could not determine interface for member: {tag}")
    return interfaces


def setup_ecmp_route(
    table_id: int,
    interfaces: Dict[str, str],
    weights: Optional[Dict[str, int]] = None
) -> bool:
    """创建 ECMP 多路径路由

    Args:
        table_id: 路由表号 (200+)
        interfaces: {tag: interface_name} 映射
        weights: {tag: weight} 权重配置，默认均等

    Returns:
        是否成功

    Example:
        ip route add default table 200 \
            nexthop dev wg-pia-us weight 2 \
            nexthop dev wg-pia-jp weight 1
    """
    if not interfaces:
        logger.error("No interfaces provided for ECMP route")
        return False

    # 先清理现有路由
    teardown_ecmp_route(table_id)

    # 构建 ECMP 路由命令
    cmd = ["ip", "route", "add", "default", "table", str(table_id)]

    for tag, iface in interfaces.items():
        weight = weights.get(tag, 1) if weights else 1
        cmd.extend(["nexthop", "dev", iface, "weight", str(weight)])

    logger.info(f"Setting up ECMP route: {' '.join(cmd)}")
    success, stdout, stderr = run_command(cmd, check=False)

    if not success:
        # 如果接口不存在，可能需要等待 WireGuard 启动
        if "Cannot find device" in stderr:
            logger.warning(f"Interface not found, ECMP route not created: {stderr}")
        else:
            logger.error(f"Failed to create ECMP route: {stderr}")
        return False

    logger.info(f"ECMP route created for table {table_id}")
    return True


def teardown_ecmp_route(table_id: int) -> bool:
    """删除 ECMP 路由表中的默认路由

    Args:
        table_id: 路由表号

    Returns:
        是否成功（如果路由不存在也返回 True）
    """
    cmd = ["ip", "route", "del", "default", "table", str(table_id)]
    success, stdout, stderr = run_command(cmd, check=False)

    if not success and "No such process" not in stderr:
        # "No such process" 表示路由不存在，这不是错误
        logger.debug(f"Route deletion note: {stderr}")

    return True


def setup_ip_rule(mark: int, table_id: int) -> bool:
    """设置 fwmark 到路由表的映射

    Args:
        mark: fwmark 值（与 table_id 相同简化管理）
        table_id: 路由表号

    Returns:
        是否成功

    Example:
        ip rule add fwmark 200 table 200
    """
    # 先检查规则是否已存在
    check_cmd = ["ip", "rule", "show"]
    success, stdout, stderr = run_command(check_cmd)

    if success:
        # 查找现有规则
        rule_pattern = f"fwmark 0x{mark:x}"
        if rule_pattern in stdout or f"fwmark {mark}" in stdout:
            logger.debug(f"IP rule for mark {mark} already exists")
            return True

    # 添加规则
    cmd = ["ip", "rule", "add", "fwmark", str(mark), "table", str(table_id)]
    success, stdout, stderr = run_command(cmd, check=False)

    if not success:
        if "File exists" in stderr:
            logger.debug(f"IP rule for mark {mark} already exists")
            return True
        logger.error(f"Failed to add IP rule: {stderr}")
        return False

    logger.info(f"IP rule added: fwmark {mark} -> table {table_id}")
    return True


def teardown_ip_rule(mark: int, table_id: int) -> bool:
    """删除 fwmark 到路由表的映射

    Args:
        mark: fwmark 值
        table_id: 路由表号

    Returns:
        是否成功
    """
    cmd = ["ip", "rule", "del", "fwmark", str(mark), "table", str(table_id)]
    success, stdout, stderr = run_command(cmd, check=False)

    if not success and "No such file" not in stderr:
        logger.debug(f"Rule deletion note: {stderr}")

    return True


def get_route_status(table_id: int) -> Dict:
    """获取路由表状态

    Args:
        table_id: 路由表号

    Returns:
        {
            "table_id": 200,
            "exists": True,
            "routes": ["default nexthop dev wg-pia-us weight 2 ..."],
            "rule_exists": True
        }
    """
    result = {
        "table_id": table_id,
        "exists": False,
        "routes": [],
        "rule_exists": False
    }

    # 检查路由表
    cmd = ["ip", "route", "show", "table", str(table_id)]
    success, stdout, stderr = run_command(cmd, check=False)
    if success and stdout:
        result["exists"] = True
        result["routes"] = stdout.split("\n")

    # 检查 ip rule
    cmd = ["ip", "rule", "show"]
    success, stdout, stderr = run_command(cmd)
    if success:
        if f"fwmark 0x{table_id:x}" in stdout or f"fwmark {table_id}" in stdout:
            result["rule_exists"] = True

    return result


def sync_group(db, group: Dict) -> bool:
    """同步单个出口组的 ECMP 路由

    Args:
        db: 数据库管理器
        group: 出口组配置

    Returns:
        是否成功
    """
    tag = group["tag"]
    table_id = group["routing_table"]
    members = group["members"]
    weights = group.get("weights")
    enabled = group.get("enabled", True)

    logger.info(f"Syncing outbound group: {tag} (table: {table_id}, members: {len(members)})")

    if not enabled:
        logger.info(f"Group {tag} is disabled, tearing down routes")
        teardown_ecmp_route(table_id)
        teardown_ip_rule(table_id, table_id)
        return True

    # 获取成员接口
    interfaces = get_all_egress_interfaces(db, members)

    if not interfaces:
        logger.warning(f"No valid interfaces found for group {tag}")
        # 可能接口尚未创建，不报错但标记失败
        return False

    # 设置 IP rule
    if not setup_ip_rule(table_id, table_id):
        logger.error(f"Failed to setup IP rule for group {tag}")
        return False

    # 设置 ECMP 路由
    if not setup_ecmp_route(table_id, interfaces, weights):
        logger.error(f"Failed to setup ECMP route for group {tag}")
        return False

    logger.info(f"Group {tag} synced successfully")
    return True


def sync_all_groups(db) -> Dict[str, bool]:
    """同步所有出口组的 ECMP 路由

    Args:
        db: 数据库管理器

    Returns:
        {tag: success} 映射
    """
    results = {}
    groups = db.get_outbound_groups(enabled_only=False)

    if not groups:
        logger.info("No outbound groups found")
        return results

    logger.info(f"Syncing {len(groups)} outbound groups")

    for group in groups:
        tag = group["tag"]
        try:
            results[tag] = sync_group(db, group)
        except Exception as e:
            logger.error(f"Error syncing group {tag}: {e}")
            results[tag] = False

    # 统计
    success_count = sum(1 for v in results.values() if v)
    logger.info(f"Sync complete: {success_count}/{len(groups)} groups successful")

    return results


def teardown_group(db, tag: str) -> bool:
    """删除出口组的 ECMP 路由

    Args:
        db: 数据库管理器
        tag: 出口组 tag

    Returns:
        是否成功
    """
    group = db.get_outbound_group(tag)
    if not group:
        logger.warning(f"Group not found: {tag}")
        return False

    table_id = group["routing_table"]
    logger.info(f"Tearing down group {tag} (table: {table_id})")

    teardown_ecmp_route(table_id)
    teardown_ip_rule(table_id, table_id)

    logger.info(f"Group {tag} torn down")
    return True


def cleanup_stale_routes(db) -> int:
    """清理孤立的路由表（对应的组已删除）

    Args:
        db: 数据库管理器

    Returns:
        清理的路由表数量
    """
    # 获取当前所有组使用的路由表
    groups = db.get_outbound_groups(enabled_only=False)
    active_tables = {g["routing_table"] for g in groups if g.get("routing_table")}

    cleaned = 0

    # 检查 200-299 范围的路由表
    for table_id in range(ROUTING_TABLE_START, ROUTING_TABLE_START + 100):
        if table_id in active_tables:
            continue

        # 检查路由表是否存在路由
        cmd = ["ip", "route", "show", "table", str(table_id)]
        success, stdout, stderr = run_command(cmd, check=False)

        if success and stdout:
            # 存在路由但不在活跃组中，清理
            logger.info(f"Cleaning up stale routing table {table_id}")
            teardown_ecmp_route(table_id)
            teardown_ip_rule(table_id, table_id)
            cleaned += 1

    if cleaned:
        logger.info(f"Cleaned up {cleaned} stale routing tables")

    return cleaned


def show_status(db) -> None:
    """显示所有出口组的路由状态"""
    groups = db.get_outbound_groups(enabled_only=False)

    if not groups:
        print("No outbound groups configured")
        return

    print(f"\n{'='*60}")
    print("Outbound Groups ECMP Status")
    print(f"{'='*60}\n")

    for group in groups:
        tag = group["tag"]
        table_id = group["routing_table"]
        members = group["members"]
        enabled = group.get("enabled", True)
        group_type = group.get("type", "loadbalance")

        status = get_route_status(table_id)

        print(f"Group: {tag}")
        print(f"  Type: {group_type}")
        print(f"  Enabled: {'Yes' if enabled else 'No'}")
        print(f"  Routing Table: {table_id}")
        print(f"  Members: {', '.join(members)}")
        print(f"  Route Exists: {'Yes' if status['exists'] else 'No'}")
        print(f"  Rule Exists: {'Yes' if status['rule_exists'] else 'No'}")

        if status["routes"]:
            print(f"  Routes:")
            for route in status["routes"]:
                print(f"    {route}")

        print()


def get_db_manager():
    """获取数据库管理器"""
    # 添加脚本目录到路径
    script_dir = Path(__file__).parent
    if str(script_dir) not in sys.path:
        sys.path.insert(0, str(script_dir))

    from db_helper import get_db

    # 获取加密密钥
    encryption_key = os.environ.get("SQLCIPHER_KEY")
    if not encryption_key:
        key_file = Path("/etc/sing-box/encryption.key")
        if key_file.exists():
            encryption_key = key_file.read_text().strip()

    return get_db(
        geodata_path="/etc/sing-box",
        user_path=USER_DB_PATH,
        encryption_key=encryption_key
    )


def main():
    parser = argparse.ArgumentParser(
        description="ECMP 多路径路由管理器",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
示例:
  python3 ecmp_manager.py --sync-all        同步所有出口组
  python3 ecmp_manager.py --sync-group lb1  同步单个出口组
  python3 ecmp_manager.py --teardown-group lb1  删除出口组路由
  python3 ecmp_manager.py --status          显示状态
  python3 ecmp_manager.py --cleanup         清理孤立路由
        """
    )

    parser.add_argument("--sync-all", action="store_true",
                        help="同步所有出口组的 ECMP 路由")
    parser.add_argument("--sync-group", metavar="TAG",
                        help="同步单个出口组")
    parser.add_argument("--teardown-group", metavar="TAG",
                        help="删除出口组的路由")
    parser.add_argument("--status", action="store_true",
                        help="显示所有出口组状态")
    parser.add_argument("--cleanup", action="store_true",
                        help="清理孤立的路由表")
    parser.add_argument("--debug", action="store_true",
                        help="启用调试日志")

    args = parser.parse_args()

    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)

    # 如果没有指定任何操作，显示帮助
    if not any([args.sync_all, args.sync_group, args.teardown_group,
                args.status, args.cleanup]):
        parser.print_help()
        return 1

    try:
        db = get_db_manager()
    except Exception as e:
        logger.error(f"Failed to connect to database: {e}")
        return 1

    exit_code = 0

    if args.sync_all:
        results = sync_all_groups(db)
        if not all(results.values()):
            exit_code = 1

    if args.sync_group:
        group = db.get_outbound_group(args.sync_group)
        if group:
            if not sync_group(db, group):
                exit_code = 1
        else:
            logger.error(f"Group not found: {args.sync_group}")
            exit_code = 1

    if args.teardown_group:
        if not teardown_group(db, args.teardown_group):
            exit_code = 1

    if args.status:
        show_status(db)

    if args.cleanup:
        cleanup_stale_routes(db)

    return exit_code


if __name__ == "__main__":
    sys.exit(main())

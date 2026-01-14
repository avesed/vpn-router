#!/usr/bin/env python3
"""出口健康检查器

定期检查出口可用性，自动从 ECMP 路由中移除故障出口。

功能：
    - 通过 HTTP 请求检查出口健康状态
    - 自动更新 ECMP 路由（移除故障节点）
    - 支持后台守护进程模式
    - 提供健康状态 API 接口

使用方法：
    # 单次检查所有组
    python3 health_checker.py --check-all

    # 检查单个出口
    python3 health_checker.py --check-egress <tag>

    # 后台守护进程模式
    python3 health_checker.py --daemon

    # 显示健康状态
    python3 health_checker.py --status
"""

import argparse
import json
import logging
import os
import signal
import subprocess
import sys
import threading
import time
from pathlib import Path
from typing import Dict, List, Optional, Tuple

# 配置日志
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger(__name__)

# 数据库路径
USER_DB_PATH = os.environ.get("USER_DB_PATH", "/etc/sing-box/user-config.db")

# 健康状态存储（内存中）
# 格式: {group_tag: {member_tag: {"healthy": bool, "last_check": float, "latency_ms": int, "error": str}}}
_health_status: Dict[str, Dict[str, Dict]] = {}
_health_status_lock = threading.Lock()

# 守护进程控制
_shutdown_event = threading.Event()


def get_interface_for_egress(db, tag: str) -> Optional[str]:
    """获取出口 tag 对应的内核网络接口名"""
    from db_helper import get_egress_interface_name

    # 检查 PIA profile
    profile = db.get_pia_profile_by_name(tag)
    if profile:
        return get_egress_interface_name(tag, is_pia=True)

    # 检查 Custom WireGuard egress
    custom = db.get_custom_egress(tag)
    if custom:
        return get_egress_interface_name(tag, is_pia=False)

    # 检查 Direct egress
    direct = db.get_direct_egress(tag)
    if direct and direct.get("bind_interface"):
        return direct["bind_interface"]

    # 检查 OpenVPN egress（使用 TUN 设备）
    openvpn = db.get_openvpn_egress(tag)
    if openvpn and openvpn.get("tun_device"):
        return openvpn["tun_device"]

    return None


def get_warp_interface_name(tag: str) -> Optional[str]:
    """获取 WARP WireGuard 出口的内核接口名"""
    from db_helper import get_egress_interface_name
    return get_egress_interface_name(tag, egress_type="warp")


def check_egress_health(
    interface: str,
    url: str = "http://www.gstatic.com/generate_204",
    timeout: int = 5
) -> Tuple[bool, int, str]:
    """检查单个出口的健康状态

    通过指定接口发送 HTTP 请求来检测连通性。

    Args:
        interface: 网络接口名
        url: 健康检查 URL
        timeout: 超时时间（秒）

    Returns:
        (healthy: bool, latency_ms: int, error: str)
    """
    try:
        # 使用 curl 通过指定接口发送请求
        cmd = [
            "curl",
            "-s",  # 静默模式
            "-o", "/dev/null",  # 丢弃输出
            "-w", "%{http_code},%{time_total}",  # 输出状态码和时间
            "--interface", interface,  # 绑定接口
            "--connect-timeout", str(timeout),
            "--max-time", str(timeout + 2),
            url
        ]

        start_time = time.time()
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout + 5
        )

        if result.returncode == 0:
            # 解析输出
            parts = result.stdout.strip().split(",")
            if len(parts) >= 2:
                http_code = int(parts[0])
                time_total = float(parts[1])
                latency_ms = int(time_total * 1000)

                # 检查 HTTP 状态码（2xx 或 204 表示成功）
                if 200 <= http_code < 300 or http_code == 204:
                    return True, latency_ms, ""
                else:
                    return False, latency_ms, f"HTTP {http_code}"

        # curl 失败
        error_msg = result.stderr.strip() if result.stderr else f"curl exit code {result.returncode}"
        return False, 0, error_msg

    except subprocess.TimeoutExpired:
        return False, timeout * 1000, "timeout"
    except Exception as e:
        return False, 0, str(e)


def check_egress_health_via_socks(
    socks_port: int,
    url: str = "http://www.gstatic.com/generate_204",
    timeout: int = 5
) -> Tuple[bool, int, str]:
    """通过 SOCKS 代理检查出口健康状态

    用于 OpenVPN、V2Ray、WARP 等使用 SOCKS 桥接的出口。

    Args:
        socks_port: 本地 SOCKS5 代理端口
        url: 健康检查 URL
        timeout: 超时时间（秒）

    Returns:
        (healthy: bool, latency_ms: int, error: str)
    """
    try:
        cmd = [
            "curl",
            "-s",
            "-o", "/dev/null",
            "-w", "%{http_code},%{time_total}",
            "--proxy", f"socks5://127.0.0.1:{socks_port}",
            "--connect-timeout", str(timeout),
            "--max-time", str(timeout + 2),
            url
        ]

        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout + 5
        )

        if result.returncode == 0:
            parts = result.stdout.strip().split(",")
            if len(parts) >= 2:
                http_code = int(parts[0])
                time_total = float(parts[1])
                latency_ms = int(time_total * 1000)

                if 200 <= http_code < 300 or http_code == 204:
                    return True, latency_ms, ""
                else:
                    return False, latency_ms, f"HTTP {http_code}"

        error_msg = result.stderr.strip() if result.stderr else f"curl exit code {result.returncode}"
        return False, 0, error_msg

    except subprocess.TimeoutExpired:
        return False, timeout * 1000, "timeout"
    except Exception as e:
        return False, 0, str(e)


def check_member_health(db, member_tag: str, url: str, timeout: int) -> Tuple[bool, int, str]:
    """检查组成员的健康状态

    根据成员类型选择合适的检查方法。

    Args:
        db: 数据库管理器
        member_tag: 成员出口 tag
        url: 健康检查 URL
        timeout: 超时时间

    Returns:
        (healthy: bool, latency_ms: int, error: str)
    """
    # 检查 OpenVPN（使用 TUN 设备，direct + bind_interface）
    openvpn = db.get_openvpn_egress(member_tag)
    if openvpn and openvpn.get("tun_device"):
        return check_egress_health(openvpn["tun_device"], url, timeout)

    # 检查是否有 SOCKS 端口（V2Ray、WARP MASQUE）
    v2ray = db.get_v2ray_egress(member_tag)
    if v2ray and v2ray.get("socks_port"):
        return check_egress_health_via_socks(v2ray["socks_port"], url, timeout)

    warp = db.get_warp_egress(member_tag)
    if warp:
        # WARP WireGuard 协议使用内核接口
        if warp.get("protocol") == "wireguard":
            interface = get_warp_interface_name(member_tag)
            if interface:
                return check_egress_health(interface, url, timeout)
            else:
                return False, 0, "WARP WireGuard interface not found"
        # WARP MASQUE 协议使用 SOCKS 代理
        elif warp.get("socks_port"):
            return check_egress_health_via_socks(warp["socks_port"], url, timeout)

    # 使用接口检查（PIA、Custom WireGuard、Direct）
    interface = get_interface_for_egress(db, member_tag)
    if interface:
        return check_egress_health(interface, url, timeout)

    # 检查是否是嵌套组
    group = db.get_outbound_group(member_tag)
    if group:
        # 对于嵌套组，检查其任意一个成员是否健康
        for nested_member in group.get("members", []):
            healthy, latency, error = check_member_health(
                db, nested_member, url, timeout
            )
            if healthy:
                return True, latency, ""
        return False, 0, "all nested members unhealthy"

    return False, 0, f"unknown egress type: {member_tag}"


def check_group_health(db, group: Dict) -> Dict[str, Dict]:
    """检查组内所有成员的健康状态

    Args:
        db: 数据库管理器
        group: 出口组配置

    Returns:
        {member_tag: {"healthy": bool, "latency_ms": int, "error": str, "last_check": float}}
    """
    tag = group["tag"]
    members = group["members"]
    url = group.get("health_check_url", "http://www.gstatic.com/generate_204")
    timeout = group.get("health_check_timeout", 5)

    results = {}

    for member in members:
        logger.debug(f"Checking health of {member} in group {tag}")
        healthy, latency, error = check_member_health(db, member, url, timeout)

        results[member] = {
            "healthy": healthy,
            "latency_ms": latency,
            "error": error,
            "last_check": time.time()
        }

        status = "healthy" if healthy else f"unhealthy ({error})"
        logger.debug(f"  {member}: {status}, latency: {latency}ms")

    return results


def update_health_status(group_tag: str, member_status: Dict[str, Dict]) -> None:
    """更新内存中的健康状态"""
    with _health_status_lock:
        _health_status[group_tag] = member_status


def get_health_status(group_tag: Optional[str] = None) -> Dict:
    """获取健康状态

    Args:
        group_tag: 可选，指定组的 tag。如果为 None 返回所有组的状态

    Returns:
        健康状态字典
    """
    with _health_status_lock:
        if group_tag:
            return _health_status.get(group_tag, {})
        return dict(_health_status)


def update_ecmp_for_health(db, group: Dict, member_status: Dict[str, Dict]) -> bool:
    """根据健康状态更新 ECMP 路由

    Args:
        db: 数据库管理器
        group: 出口组配置
        member_status: 成员健康状态

    Returns:
        是否成功更新路由
    """
    # 导入 ECMP 管理器
    from ecmp_manager import setup_ecmp_route, get_all_egress_interfaces

    tag = group["tag"]
    table_id = group["routing_table"]
    weights = group.get("weights")

    # 获取健康的成员
    healthy_members = [
        member for member, status in member_status.items()
        if status.get("healthy", False)
    ]

    if not healthy_members:
        logger.warning(f"All members of group {tag} are unhealthy, keeping existing routes")
        # 保留现有路由以防止完全断开
        return False

    # 获取健康成员的接口
    interfaces = get_all_egress_interfaces(db, healthy_members)

    if not interfaces:
        logger.warning(f"No valid interfaces for healthy members of group {tag}")
        return False

    # 更新 ECMP 路由（仅使用健康成员）
    healthy_weights = None
    if weights:
        healthy_weights = {k: v for k, v in weights.items() if k in healthy_members}

    logger.info(f"Updating ECMP for group {tag}: {len(healthy_members)}/{len(group['members'])} healthy")
    return setup_ecmp_route(table_id, interfaces, healthy_weights)


def check_and_update_group(db, group: Dict) -> Dict[str, Dict]:
    """检查组健康并更新路由

    Args:
        db: 数据库管理器
        group: 出口组配置

    Returns:
        成员健康状态
    """
    tag = group["tag"]

    # 检查健康状态
    member_status = check_group_health(db, group)

    # 更新内存状态
    update_health_status(tag, member_status)

    # 获取之前的状态进行比较
    with _health_status_lock:
        prev_status = _health_status.get(f"{tag}_prev", {})

    # 检查是否有状态变化
    status_changed = False
    for member, status in member_status.items():
        prev = prev_status.get(member, {})
        if status.get("healthy") != prev.get("healthy"):
            status_changed = True
            action = "recovered" if status.get("healthy") else "failed"
            logger.info(f"Member {member} in group {tag} {action}")

    # 如果有变化，更新 ECMP 路由
    if status_changed:
        update_ecmp_for_health(db, group, member_status)

    # 保存当前状态用于下次比较
    with _health_status_lock:
        _health_status[f"{tag}_prev"] = member_status

    return member_status


def check_all_groups(db) -> Dict[str, Dict[str, Dict]]:
    """检查所有组的健康状态

    Args:
        db: 数据库管理器

    Returns:
        {group_tag: {member_tag: status}}
    """
    groups = db.get_outbound_groups(enabled_only=True)
    results = {}

    for group in groups:
        tag = group["tag"]
        try:
            results[tag] = check_and_update_group(db, group)
        except Exception as e:
            logger.error(f"Error checking group {tag}: {e}")

    return results


def daemon_loop(db, default_interval: int = 60):
    """守护进程主循环

    Args:
        db: 数据库管理器
        default_interval: 默认检查间隔（秒）
    """
    logger.info("Health checker daemon started")

    while not _shutdown_event.is_set():
        try:
            groups = db.get_outbound_groups(enabled_only=True)

            if not groups:
                logger.debug("No enabled outbound groups, sleeping...")
                _shutdown_event.wait(default_interval)
                continue

            # 检查每个组
            for group in groups:
                if _shutdown_event.is_set():
                    break

                tag = group["tag"]
                interval = group.get("health_check_interval", default_interval)

                # 检查是否到了检查时间
                with _health_status_lock:
                    last_check = 0
                    if tag in _health_status:
                        # 使用任意成员的 last_check
                        for member_status in _health_status[tag].values():
                            last_check = member_status.get("last_check", 0)
                            break

                    elapsed = time.time() - last_check

                if elapsed >= interval:
                    logger.debug(f"Checking group {tag} (interval: {interval}s)")
                    try:
                        check_and_update_group(db, group)
                    except Exception as e:
                        logger.error(f"Error checking group {tag}: {e}")

            # 短暂休眠后继续
            _shutdown_event.wait(5)

        except Exception as e:
            logger.error(f"Error in daemon loop: {e}")
            _shutdown_event.wait(10)

    logger.info("Health checker daemon stopped")


def run_daemon(db, interval: int = 60):
    """运行守护进程

    Args:
        db: 数据库管理器
        interval: 默认检查间隔
    """
    # 信号处理
    def handle_signal(signum, frame):
        logger.info(f"Received signal {signum}, shutting down...")
        _shutdown_event.set()

    signal.signal(signal.SIGTERM, handle_signal)
    signal.signal(signal.SIGINT, handle_signal)

    # PID 文件
    pid_file = Path("/run/health_checker.pid")
    try:
        pid_file.write_text(str(os.getpid()))
    except Exception as e:
        logger.warning(f"Could not write PID file: {e}")

    try:
        daemon_loop(db, interval)
    finally:
        try:
            pid_file.unlink(missing_ok=True)
        except Exception:
            pass


def show_status(db):
    """显示健康状态"""
    groups = db.get_outbound_groups(enabled_only=False)

    if not groups:
        print("No outbound groups configured")
        return

    print(f"\n{'='*60}")
    print("Outbound Groups Health Status")
    print(f"{'='*60}\n")

    with _health_status_lock:
        for group in groups:
            tag = group["tag"]
            members = group["members"]
            enabled = group.get("enabled", True)

            print(f"Group: {tag}")
            print(f"  Enabled: {'Yes' if enabled else 'No'}")
            print(f"  Members:")

            status = _health_status.get(tag, {})
            for member in members:
                member_status = status.get(member, {})
                healthy = member_status.get("healthy")
                latency = member_status.get("latency_ms", 0)
                error = member_status.get("error", "")
                last_check = member_status.get("last_check", 0)

                if healthy is None:
                    state = "unknown"
                elif healthy:
                    state = f"healthy ({latency}ms)"
                else:
                    state = f"unhealthy: {error}"

                check_time = ""
                if last_check:
                    elapsed = int(time.time() - last_check)
                    check_time = f" (checked {elapsed}s ago)"

                print(f"    - {member}: {state}{check_time}")

            print()


def get_db_manager():
    """获取数据库管理器"""
    script_dir = Path(__file__).parent
    if str(script_dir) not in sys.path:
        sys.path.insert(0, str(script_dir))

    from db_helper import get_db

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
        description="出口健康检查器",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )

    parser.add_argument("--check-all", action="store_true",
                        help="检查所有组的健康状态")
    parser.add_argument("--check-group", metavar="TAG",
                        help="检查单个组")
    parser.add_argument("--check-egress", metavar="TAG",
                        help="检查单个出口")
    parser.add_argument("--daemon", action="store_true",
                        help="后台守护进程模式")
    parser.add_argument("--interval", type=int, default=60,
                        help="检查间隔（秒，默认 60）")
    parser.add_argument("--status", action="store_true",
                        help="显示健康状态")
    parser.add_argument("--debug", action="store_true",
                        help="启用调试日志")

    args = parser.parse_args()

    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)

    if not any([args.check_all, args.check_group, args.check_egress,
                args.daemon, args.status]):
        parser.print_help()
        return 1

    try:
        db = get_db_manager()
    except Exception as e:
        logger.error(f"Failed to connect to database: {e}")
        return 1

    if args.daemon:
        run_daemon(db, args.interval)
        return 0

    if args.check_all:
        results = check_all_groups(db)
        for group_tag, members in results.items():
            print(f"\nGroup: {group_tag}")
            for member, status in members.items():
                state = "healthy" if status.get("healthy") else f"unhealthy: {status.get('error')}"
                print(f"  {member}: {state} ({status.get('latency_ms', 0)}ms)")

    if args.check_group:
        group = db.get_outbound_group(args.check_group)
        if group:
            status = check_and_update_group(db, group)
            print(f"\nGroup: {args.check_group}")
            for member, s in status.items():
                state = "healthy" if s.get("healthy") else f"unhealthy: {s.get('error')}"
                print(f"  {member}: {state} ({s.get('latency_ms', 0)}ms)")
        else:
            logger.error(f"Group not found: {args.check_group}")
            return 1

    if args.check_egress:
        # 简单的出口检查
        url = "http://www.gstatic.com/generate_204"
        healthy, latency, error = check_member_health(db, args.check_egress, url, 5)
        state = "healthy" if healthy else f"unhealthy: {error}"
        print(f"{args.check_egress}: {state} ({latency}ms)")

    if args.status:
        show_status(db)

    return 0


if __name__ == "__main__":
    sys.exit(main())

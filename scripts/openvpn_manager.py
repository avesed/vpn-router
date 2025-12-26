#!/usr/bin/env python3
"""
OpenVPN 隧道管理器

管理多个 OpenVPN 进程，支持：
- 从数据库读取配置
- 生成 OpenVPN 配置文件
- 启动/停止 OpenVPN 进程
- 监控隧道状态

每个 OpenVPN 隧道创建一个 TUN 设备（如 tun10, tun11），
sing-box 通过 direct outbound + bind_interface 直接路由流量，
无需中间 SOCKS5 代理层。

使用方法:
    python3 openvpn_manager.py start     # 启动所有启用的隧道
    python3 openvpn_manager.py stop      # 停止所有隧道
    python3 openvpn_manager.py reload    # 重载配置（停止已删除，启动新增）
    python3 openvpn_manager.py status    # 显示所有隧道状态
"""

import argparse
import asyncio
import fcntl
import json
import logging
import os
import signal
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional

# 添加脚本目录到 Python 路径
sys.path.insert(0, str(Path(__file__).parent))

from db_helper import get_db

# C2 修复: OpenVPN extra_options 白名单验证
# 只允许安全的、不会导致命令执行或文件访问的选项
ALLOWED_OPENVPN_OPTIONS = frozenset({
    # 连接相关
    "ping", "ping-restart", "ping-exit", "ping-timer-rem",
    "keepalive", "connect-retry", "connect-retry-max", "connect-timeout",
    "resolv-retry", "float", "remote-random", "remote-random-hostname",
    # 持久化
    "persist-tun", "persist-key", "persist-local-ip", "persist-remote-ip",
    # 日志和调试
    "mute", "mute-replay-warnings", "verb", "suppress-timestamps",
    # 缓冲区
    "sndbuf", "rcvbuf", "tcp-queue-limit", "bcast-buffers",
    # MTU 相关
    "mtu-disc", "mtu-test", "link-mtu", "tun-mtu", "tun-mtu-extra",
    "fragment", "mssfix",
    # 路由相关（安全的选项）
    "route-delay", "route-method", "route-metric",
    # 重放保护
    "replay-window", "no-replay", "replay-persist",
    # 安全选项
    "auth-nocache", "remote-cert-tls", "verify-x509-name",
    "tls-timeout", "tls-version-min", "tls-version-max",
    "hand-window", "tran-window", "reneg-sec", "reneg-bytes", "reneg-pkts",
    # 其他安全选项
    "single-session", "tls-exit", "opt-verify",
    # 性能选项
    "fast-io", "nice", "txqueuelen",
})

# 危险选项（绝对禁止）- 用于日志警告
DANGEROUS_OPENVPN_OPTIONS = frozenset({
    "up", "down", "ipchange", "route-up", "route-pre-down",  # 脚本执行
    "client-connect", "client-disconnect", "learn-address",  # 脚本执行
    "auth-user-pass-verify", "tls-verify",  # 脚本/程序执行
    "config", "cd",  # 文件访问
    "writepid", "log", "log-append", "status",  # 文件写入（由管理器控制）
    "plugin", "setenv", "setenv-safe",  # 插件/环境变量
    "script-security", "daemon", "syslog",  # 系统级
    "iproute", "ifconfig", "route",  # 网络配置
    "user", "group", "chroot",  # 权限相关
    "dev", "dev-type", "dev-node",  # 设备（由管理器控制）
    "management", "management-query-passwords",  # 管理接口
})


def write_secure_file(path: Path, content: str, mode: int = 0o600) -> None:
    """
    C4 修复: 原子创建具有正确权限的敏感文件

    使用 os.open() 以指定权限创建文件，避免先创建再 chmod 的竞态条件。

    Args:
        path: 文件路径
        content: 文件内容
        mode: 文件权限 (默认 0o600 = rw-------)
    """
    path_str = str(path)
    # 如果文件已存在，先删除（避免 O_EXCL 失败）
    if path.exists():
        path.unlink()

    # 使用 O_CREAT | O_EXCL | O_WRONLY 确保原子创建
    # O_EXCL: 如果文件存在则失败（我们已经删除了，但这是额外的安全保证）
    fd = os.open(path_str, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
    try:
        os.write(fd, content.encode('utf-8'))
    finally:
        os.close(fd)


def sanitize_auth_string(value: str) -> str:
    """
    M3 修复: 清理 OpenVPN 认证字符串（用户名/密码）

    OpenVPN auth-user-pass 文件格式为每行一个值，
    因此必须移除换行符和其他可能破坏格式的字符。

    Args:
        value: 原始用户名或密码

    Returns:
        清理后的字符串
    """
    if not value:
        return ""
    # 移除换行符（可能破坏文件格式）
    sanitized = value.replace('\r', '').replace('\n', '')
    # 移除 null 字节
    sanitized = sanitized.replace('\x00', '')
    return sanitized


def validate_extra_options(options: list) -> list:
    """
    验证 OpenVPN extra_options，只允许白名单中的安全选项

    Args:
        options: 原始选项列表

    Returns:
        验证通过的选项列表
    """
    if not options:
        return []

    validated = []
    for opt in options:
        if not isinstance(opt, str):
            logging.warning(f"[extra_options] 跳过非字符串选项: {type(opt)}")
            continue

        # 去除前导空格和破折号，获取指令名
        opt_stripped = opt.strip()
        if not opt_stripped:
            continue

        # 提取指令名（第一个空格前的部分，去除前导破折号）
        parts = opt_stripped.split(None, 1)
        directive = parts[0].lstrip("-").lower()

        # 检查是否在危险列表中
        if directive in DANGEROUS_OPENVPN_OPTIONS:
            logging.warning(f"[extra_options] 阻止危险选项: {opt_stripped}")
            continue

        # 检查是否在白名单中
        if directive in ALLOWED_OPENVPN_OPTIONS:
            validated.append(opt_stripped)
        else:
            logging.warning(f"[extra_options] 跳过未知选项: {opt_stripped}")

    return validated


logging.basicConfig(
    level=logging.INFO,
    format='[openvpn-mgr] %(asctime)s %(levelname)s: %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger(__name__)

# 配置路径
OPENVPN_RUN_DIR = Path("/run/openvpn")
OPENVPN_LOG_DIR = Path("/var/log/openvpn")
OPENVPN_PID_FILE = Path("/run/openvpn-manager.pid")
GEODATA_DB_PATH = os.environ.get("GEODATA_DB_PATH", "/etc/sing-box/geoip-geodata.db")
USER_DB_PATH = os.environ.get("USER_DB_PATH", "/etc/sing-box/user-config.db")


def write_pid_file_atomic(pid_path: Path, pid: int) -> None:
    """
    原子写入 PID 文件，使用文件锁防止竞态条件 (H6)
    """
    pid_path.parent.mkdir(parents=True, exist_ok=True)
    lock_path = pid_path.with_suffix(".lock")

    with open(lock_path, 'w') as lock_file:
        fcntl.flock(lock_file.fileno(), fcntl.LOCK_EX)
        try:
            tmp_path = pid_path.with_suffix(".tmp")
            tmp_path.write_text(str(pid))
            tmp_path.rename(pid_path)
        finally:
            fcntl.flock(lock_file.fileno(), fcntl.LOCK_UN)


def cleanup_stale_pid_file(pid_path: Path) -> None:
    """
    清理无效的 PID 文件 (H6)
    """
    if not pid_path.exists():
        return

    try:
        pid_str = pid_path.read_text().strip()
        pid = int(pid_str)
        os.kill(pid, 0)  # 检查进程是否存在
    except (ValueError, ProcessLookupError, PermissionError):
        try:
            pid_path.unlink()
            logger.debug(f"已清理无效 PID 文件: {pid_path}")
        except Exception as e:
            logger.warning(f"清理 PID 文件失败: {e}")
    except Exception as e:
        logger.warning(f"检查 PID 文件时出错: {e}")


@dataclass
class TunnelProcess:
    """存储隧道进程信息"""
    tag: str
    openvpn_pid: Optional[int] = None
    tun_device: Optional[str] = None
    status: str = "stopped"  # stopped, starting, connected, error


def _get_tunnel_status_from_system(tag: str) -> Dict:
    """
    从系统状态检查隧道状态（用于独立的 status 命令）

    由于 status 命令创建新的 manager 实例，无法访问运行中守护进程的内存状态。
    因此需要直接检查系统状态：
    1. 从数据库读取 tun_device
    2. 检查 TUN 接口是否存在
    3. 查找对应的 openvpn 进程

    Args:
        tag: 隧道标签

    Returns:
        状态字典，格式与 _tunnel_to_dict 一致
    """
    db = get_db(GEODATA_DB_PATH, USER_DB_PATH)
    egress = db.get_openvpn_egress(tag)

    if not egress:
        return {
            "tag": tag,
            "status": "not_found",
            "openvpn_pid": None,
            "tun_device": None,
            "error": f"OpenVPN egress '{tag}' not found in database"
        }

    tun_device = egress.get("tun_device")
    if not tun_device:
        return {
            "tag": tag,
            "status": "error",
            "openvpn_pid": None,
            "tun_device": None,
            "error": "No tun_device configured"
        }

    # 检查 TUN 接口是否存在
    tun_exists = Path(f"/sys/class/net/{tun_device}").exists()

    # 查找 openvpn 进程
    openvpn_pid = None
    config_path = str(OPENVPN_RUN_DIR / tag / "client.conf")
    try:
        # 使用 pgrep 查找包含配置文件路径的 openvpn 进程
        result = subprocess.run(
            ["pgrep", "-f", f"openvpn.*{config_path}"],
            capture_output=True,
            text=True,
            timeout=5
        )
        if result.returncode == 0 and result.stdout.strip():
            # 可能有多个匹配，取第一个
            pids = result.stdout.strip().split('\n')
            if pids:
                openvpn_pid = int(pids[0])
    except (subprocess.TimeoutExpired, ValueError, Exception) as e:
        logger.debug(f"查找 openvpn 进程时出错: {e}")

    # 确定状态
    if tun_exists and openvpn_pid:
        status = "connected"
    elif openvpn_pid:
        # 进程存在但 TUN 还未创建，可能正在启动
        status = "starting"
    else:
        status = "disconnected"

    return {
        "tag": tag,
        "status": status,
        "openvpn_pid": openvpn_pid,
        "tun_device": tun_device
    }


class OpenVPNManager:
    """OpenVPN 隧道管理器"""

    def __init__(self):
        self.tunnels: Dict[str, TunnelProcess] = {}
        self.db = get_db(GEODATA_DB_PATH, USER_DB_PATH)
        self._running = False
        self._reload_event: Optional[asyncio.Event] = None  # 用于立即响应 SIGHUP

    def _generate_config(self, egress: dict) -> Path:
        """生成 OpenVPN 配置文件"""
        tag = egress["tag"]
        config_dir = OPENVPN_RUN_DIR / tag
        config_dir.mkdir(parents=True, exist_ok=True)

        # 从数据库获取 tun 设备
        tun_device = egress.get("tun_device")
        if not tun_device:
            raise ValueError(f"OpenVPN egress '{tag}' 缺少 tun_device 配置")

        # 生成配置文件
        config_lines = [
            "client",
            f"dev {tun_device}",
            "dev-type tun",
            f"proto {egress.get('protocol', 'udp')}",
            f"remote {egress['remote_host']} {egress.get('remote_port', 1194)}",
            "resolv-retry infinite",
            "nobind",
            "persist-key",
            "persist-tun",
            "remote-cert-tls server",
            f"cipher {egress.get('cipher', 'AES-256-GCM')}",
            f"auth {egress.get('auth', 'SHA256')}",
            "verb 3",
            "mute 20",
            # 重要：不要拉取服务器推送的路由，避免影响默认路由
            "route-nopull",
            # 日志
            f"log {OPENVPN_LOG_DIR / tag}.log",
            "status /dev/null",
            # 脚本安全
            "script-security 2",
        ]

        # 压缩
        compress = egress.get("compress")
        if compress:
            # 修正无效的 compress 值
            valid_compress = {"stub", "lzo", "lz4", "lz4-v2"}
            if compress.lower() in valid_compress:
                config_lines.append(f"compress {compress}")
            elif compress.lower() == "yes":
                # "yes" 不是有效的 compress 参数，转换为 stub
                config_lines.append("compress stub")

        # 写入 CA 证书
        ca_path = config_dir / "ca.crt"
        ca_path.write_text(egress["ca_cert"])
        config_lines.append(f"ca {ca_path}")

        # 客户端证书（可选）
        if egress.get("client_cert"):
            cert_path = config_dir / "client.crt"
            cert_path.write_text(egress["client_cert"])
            config_lines.append(f"cert {cert_path}")

        # 客户端私钥（可选）- C4 修复: 使用安全写入
        if egress.get("client_key"):
            key_path = config_dir / "client.key"
            write_secure_file(key_path, egress["client_key"])
            config_lines.append(f"key {key_path}")

        # TLS Auth（可选）- C4 修复: 使用安全写入
        if egress.get("tls_auth"):
            ta_path = config_dir / "ta.key"
            write_secure_file(ta_path, egress["tls_auth"])
            config_lines.append(f"tls-auth {ta_path} 1")

        # TLS Crypt（可选，与 tls_auth 二选一）- C4 修复: 使用安全写入
        if egress.get("tls_crypt") and not egress.get("tls_auth"):
            tc_path = config_dir / "tls-crypt.key"
            write_secure_file(tc_path, egress["tls_crypt"])
            config_lines.append(f"tls-crypt {tc_path}")

        # CRL 验证（可选）
        if egress.get("crl_verify"):
            crl_path = config_dir / "crl.pem"
            crl_path.write_text(egress["crl_verify"])
            config_lines.append(f"crl-verify {crl_path}")

        # 用户名/密码认证（可选）- C4 修复: 使用安全写入, M3 修复: 清理特殊字符
        if egress.get("auth_user") and egress.get("auth_pass"):
            auth_path = config_dir / "auth.txt"
            safe_user = sanitize_auth_string(egress['auth_user'])
            safe_pass = sanitize_auth_string(egress['auth_pass'])
            write_secure_file(auth_path, f"{safe_user}\n{safe_pass}\n")
            config_lines.append(f"auth-user-pass {auth_path}")

        # 额外选项 - 使用白名单验证 (C2 修复)
        if egress.get("extra_options"):
            validated_options = validate_extra_options(egress["extra_options"])
            for opt in validated_options:
                config_lines.append(opt)

        # 写入配置文件
        config_path = config_dir / "client.conf"
        config_path.write_text("\n".join(config_lines) + "\n")

        # 记录 tun 设备
        if tag in self.tunnels:
            self.tunnels[tag].tun_device = tun_device
        else:
            self.tunnels[tag] = TunnelProcess(
                tag=tag,
                tun_device=tun_device
            )

        return config_path

    async def start_tunnel(self, tag: str) -> bool:
        """启动单个隧道（仅 OpenVPN，无需 SOCKS5 代理）"""
        egress = self.db.get_openvpn_egress(tag)
        if not egress:
            logger.error(f"[{tag}] OpenVPN 配置不存在")
            return False

        if not egress.get("enabled"):
            logger.info(f"[{tag}] 已禁用，跳过")
            return False

        logger.info(f"[{tag}] 启动隧道...")

        # 生成配置
        try:
            config_path = self._generate_config(egress)
        except Exception as e:
            logger.error(f"[{tag}] 生成配置失败: {e}")
            return False

        tunnel = self.tunnels[tag]
        tunnel.status = "starting"

        # 启动 OpenVPN
        try:
            openvpn_proc = subprocess.Popen(
                ["openvpn", "--config", str(config_path)],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL
            )
            tunnel.openvpn_pid = openvpn_proc.pid
            logger.info(f"[{tag}] OpenVPN 已启动 (PID: {openvpn_proc.pid}, tun: {tunnel.tun_device})")
        except Exception as e:
            logger.error(f"[{tag}] 启动 OpenVPN 失败: {e}")
            tunnel.status = "error"
            return False

        # 等待 tun 设备就绪
        tun_ready = await self._wait_for_tun(tunnel.tun_device, timeout=30)
        if tun_ready:
            tunnel.status = "connected"
            logger.info(f"[{tag}] 隧道已连接 (tun: {tunnel.tun_device})")
        else:
            tunnel.status = "error"
            logger.error(f"[{tag}] tun 设备未就绪")
            return False

        return True

    async def _wait_for_tun(self, tun_device: str, timeout: int = 30):
        """等待 tun 设备就绪"""
        tun_path = Path(f"/sys/class/net/{tun_device}")
        start_time = time.time()

        while time.time() - start_time < timeout:
            if tun_path.exists():
                logger.debug(f"tun 设备 {tun_device} 已就绪")
                return True
            await asyncio.sleep(0.5)

        logger.warning(f"等待 tun 设备 {tun_device} 超时")
        return False

    async def stop_tunnel(self, tag: str) -> bool:
        """停止单个隧道"""
        if tag not in self.tunnels:
            return False

        tunnel = self.tunnels[tag]
        logger.info(f"[{tag}] 停止隧道...")

        # 停止 OpenVPN
        if tunnel.openvpn_pid:
            try:
                os.kill(tunnel.openvpn_pid, signal.SIGTERM)
                logger.debug(f"[{tag}] 已发送 SIGTERM 到 OpenVPN (PID: {tunnel.openvpn_pid})")
                # 等待进程退出
                for _ in range(10):
                    try:
                        os.kill(tunnel.openvpn_pid, 0)
                        await asyncio.sleep(0.5)
                    except ProcessLookupError:
                        break
                else:
                    # 强制杀死
                    try:
                        os.kill(tunnel.openvpn_pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
            except ProcessLookupError:
                pass
            tunnel.openvpn_pid = None

        # 清理配置目录
        config_dir = OPENVPN_RUN_DIR / tag
        if config_dir.exists():
            import shutil
            shutil.rmtree(config_dir, ignore_errors=True)

        tunnel.status = "stopped"
        logger.info(f"[{tag}] 隧道已停止")
        return True

    async def start_all(self):
        """启动所有启用的隧道"""
        OPENVPN_RUN_DIR.mkdir(parents=True, exist_ok=True)
        OPENVPN_LOG_DIR.mkdir(parents=True, exist_ok=True)

        egress_list = self.db.get_openvpn_egress_list(enabled_only=True)
        if not egress_list:
            logger.info("没有启用的 OpenVPN 出口")
            return

        logger.info(f"启动 {len(egress_list)} 个 OpenVPN 隧道...")

        for egress in egress_list:
            tag = egress["tag"]
            try:
                await self.start_tunnel(tag)
            except Exception as e:
                logger.error(f"[{tag}] 启动失败: {e}")

    async def stop_all(self):
        """停止所有隧道"""
        tags = list(self.tunnels.keys())
        for tag in tags:
            try:
                await self.stop_tunnel(tag)
            except Exception as e:
                logger.error(f"[{tag}] 停止失败: {e}")
        self.tunnels.clear()

    async def reload(self):
        """重载配置（同步数据库状态）"""
        logger.info("重载 OpenVPN 配置...")

        # 获取当前数据库中启用的出口
        enabled_egress = {e["tag"]: e for e in self.db.get_openvpn_egress_list(enabled_only=True)}
        enabled_tags = set(enabled_egress.keys())
        running_tags = set(self.tunnels.keys())

        # 停止已删除或禁用的隧道
        to_stop = running_tags - enabled_tags
        for tag in to_stop:
            logger.info(f"[{tag}] 配置已删除/禁用，停止隧道")
            await self.stop_tunnel(tag)
            del self.tunnels[tag]

        # 启动新增的隧道
        to_start = enabled_tags - running_tags
        for tag in to_start:
            logger.info(f"[{tag}] 新配置，启动隧道")
            await self.start_tunnel(tag)

        # 检查配置变更（简单重启）
        for tag in enabled_tags & running_tags:
            # 这里可以添加配置比对逻辑
            # 目前简单处理：不重启正在运行的隧道
            pass

        logger.info("配置重载完成")

    def get_status(self, tag: Optional[str] = None) -> Dict:
        """获取隧道状态"""
        if tag:
            tunnel = self.tunnels.get(tag)
            if not tunnel:
                return {"tag": tag, "status": "not_found"}
            return self._tunnel_to_dict(tunnel)
        else:
            return {tag: self._tunnel_to_dict(t) for tag, t in self.tunnels.items()}

    def _tunnel_to_dict(self, tunnel: TunnelProcess) -> Dict:
        """转换隧道信息为字典"""
        # 检查 OpenVPN 进程是否存活
        openvpn_alive = False

        if tunnel.openvpn_pid:
            try:
                os.kill(tunnel.openvpn_pid, 0)
                openvpn_alive = True
            except ProcessLookupError:
                pass

        # 确定状态
        if openvpn_alive:
            status = "connected"
        elif tunnel.status == "starting":
            status = "starting"
        else:
            status = "disconnected"

        return {
            "tag": tunnel.tag,
            "status": status,
            "openvpn_pid": tunnel.openvpn_pid if openvpn_alive else None,
            "tun_device": tunnel.tun_device
        }

    async def run_daemon(self):
        """以守护进程模式运行"""
        self._running = True
        self._reload_requested = False
        logger.info("OpenVPN 管理器启动（守护模式）")

        # 写入 PID 文件 (H6: 使用原子写入)
        write_pid_file_atomic(OPENVPN_PID_FILE, os.getpid())
        logger.info(f"PID 文件写入: {OPENVPN_PID_FILE}")

        # 启动所有隧道
        await self.start_all()

        # 初始化 reload event
        self._reload_event = asyncio.Event()

        # 监控循环
        while self._running:
            # 等待 reload 事件或 10 秒超时（用于健康检查）
            try:
                await asyncio.wait_for(self._reload_event.wait(), timeout=10)
                self._reload_event.clear()
            except asyncio.TimeoutError:
                pass  # 正常超时，继续健康检查

            # 检查是否需要重载
            if self._reload_requested:
                self._reload_requested = False
                logger.info("执行配置重载...")
                await self.reload()

            # 检查进程健康
            for tag, tunnel in list(self.tunnels.items()):
                if tunnel.status != "connected":
                    continue

                # 检查 OpenVPN 进程
                if tunnel.openvpn_pid:
                    try:
                        os.kill(tunnel.openvpn_pid, 0)
                    except ProcessLookupError:
                        logger.warning(f"[{tag}] OpenVPN 进程已退出，尝试重启")
                        await self.stop_tunnel(tag)
                        await self.start_tunnel(tag)

        # 清理
        await self.stop_all()
        # 删除 PID 文件
        if OPENVPN_PID_FILE.exists():
            OPENVPN_PID_FILE.unlink()
        logger.info("OpenVPN 管理器已停止")

    def request_reload(self):
        """请求重载配置（由 SIGHUP 信号触发）"""
        logger.info("收到重载请求 (SIGHUP)")
        self._reload_requested = True
        # 立即唤醒监控循环
        if self._reload_event:
            self._reload_event.set()

    def stop_daemon(self):
        """停止守护进程"""
        self._running = False


async def main():
    parser = argparse.ArgumentParser(description='OpenVPN 隧道管理器')
    parser.add_argument('command', choices=['start', 'stop', 'reload', 'status', 'daemon'],
                       help='操作命令')
    parser.add_argument('--tag', help='指定隧道标签（用于 start/stop/status）')
    parser.add_argument('--verbose', '-v', action='store_true', help='详细输出')
    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    manager = OpenVPNManager()

    if args.command == 'start':
        if args.tag:
            await manager.start_tunnel(args.tag)
        else:
            await manager.start_all()

    elif args.command == 'stop':
        if args.tag:
            await manager.stop_tunnel(args.tag)
        else:
            await manager.stop_all()

    elif args.command == 'reload':
        # 优先使用信号通知运行中的守护进程
        if OPENVPN_PID_FILE.exists():
            try:
                daemon_pid = int(OPENVPN_PID_FILE.read_text().strip())
                os.kill(daemon_pid, signal.SIGHUP)
                logger.info(f"已发送 SIGHUP 到守护进程 (PID: {daemon_pid})")
                return
            except (ValueError, ProcessLookupError, PermissionError) as e:
                logger.warning(f"无法通知守护进程: {e}，执行本地重载")
                # PID 文件无效，删除它
                OPENVPN_PID_FILE.unlink(missing_ok=True)
        # 没有守护进程运行，执行本地重载
        await manager.reload()

    elif args.command == 'status':
        # status 命令需要检查实际状态，而非依赖内存中的状态
        if args.tag:
            status = _get_tunnel_status_from_system(args.tag)
        else:
            # 获取所有隧道状态
            db = get_db()
            egress_list = db.get_openvpn_egress_list()
            status = {}
            for eg in egress_list:
                tag = eg.get("tag")
                if tag:
                    status[tag] = _get_tunnel_status_from_system(tag)
        print(json.dumps(status, indent=2, ensure_ascii=False))

    elif args.command == 'daemon':
        # 检查是否已有守护进程运行
        if OPENVPN_PID_FILE.exists():
            try:
                existing_pid = int(OPENVPN_PID_FILE.read_text().strip())
                os.kill(existing_pid, 0)  # 检查进程是否存在
                logger.error(f"守护进程已在运行 (PID: {existing_pid})")
                sys.exit(1)
            except (ValueError, ProcessLookupError):
                # PID 文件无效，删除它
                OPENVPN_PID_FILE.unlink(missing_ok=True)

        # 设置信号处理
        loop = asyncio.get_event_loop()

        def stop_handler():
            logger.info("收到停止信号")
            manager.stop_daemon()

        def reload_handler():
            manager.request_reload()

        for sig in (signal.SIGTERM, signal.SIGINT):
            loop.add_signal_handler(sig, stop_handler)
        loop.add_signal_handler(signal.SIGHUP, reload_handler)

        await manager.run_daemon()


if __name__ == '__main__':
    asyncio.run(main())

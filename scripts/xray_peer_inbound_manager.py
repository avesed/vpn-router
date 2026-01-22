#!/usr/bin/env python3
"""
Xray 对等节点入站管理器

管理每个对等节点的 Xray 入站监听器，支持双向对等连接和中继功能。

架构:
    Remote Peer → Xray Inbound (VLESS+XHTTP+REALITY) → SOCKS5 → sing-box → routing

每个启用入站的对等节点会有一个独立的 Xray 进程监听在 36500+ 端口。

使用方法:
    python3 xray_peer_inbound_manager.py start <tag>   # 启动指定节点的入站
    python3 xray_peer_inbound_manager.py stop <tag>    # 停止指定节点的入站
    python3 xray_peer_inbound_manager.py status        # 显示所有入站状态
    python3 xray_peer_inbound_manager.py daemon        # 守护进程模式
"""

import argparse
import fcntl
import json
import logging
import os
import re
import secrets
import signal
import subprocess
import sys
import time
import uuid as uuid_module
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Any

# 添加脚本目录到 Python 路径
sys.path.insert(0, str(Path(__file__).parent))

from db_helper import get_db

# 配置日志（统一日志配置，通过 LOG_LEVEL 环境变量控制）
try:
    from log_config import setup_logging, get_logger
    setup_logging()
    logger = get_logger(__name__)
except ImportError:
    _log_level = os.environ.get("LOG_LEVEL", "INFO").upper()
    logging.basicConfig(
        level=getattr(logging, _log_level, logging.INFO),
        format='[xray-peer-in] %(asctime)s %(levelname)s: %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    logger = logging.getLogger(__name__)

# 配置路径
XRAY_PEER_INBOUND_RUN_DIR = Path("/run/xray-peer-inbound")
XRAY_PEER_INBOUND_LOG_DIR = Path("/var/log")
GEODATA_DB_PATH = os.environ.get("GEODATA_DB_PATH", "/etc/sing-box/geoip-geodata.db")
USER_DB_PATH = os.environ.get("USER_DB_PATH", "/etc/sing-box/user-config.db")

# SOCKS5 输出端口基准（入站流量输出到 sing-box）
# 使用 38601+ 端口范围，避免与其他服务冲突
PEER_INBOUND_SOCKS_BASE_PORT = 38601

def is_valid_uuid(value: str) -> bool:
    """验证 UUID 格式是否正确

    Args:
        value: 待验证的 UUID 字符串

    Returns:
        True 如果 UUID 格式正确，否则 False
    """
    if not value:
        return False
    try:
        # 使用 Python 标准库验证
        uuid_module.UUID(value)
        return True
    except (ValueError, AttributeError):
        return False


def write_pid_file_atomic(pid_path: Path, pid: int) -> None:
    """原子写入 PID 文件，使用文件锁防止竞态条件"""
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
    """清理无效的 PID 文件"""
    if not pid_path.exists():
        return

    try:
        pid_str = pid_path.read_text().strip()
        pid = int(pid_str)
        os.kill(pid, 0)
    except (ValueError, ProcessLookupError, PermissionError):
        try:
            pid_path.unlink()
            logger.debug(f"已清理无效 PID 文件: {pid_path}")
        except Exception as e:
            logger.warning(f"清理 PID 文件失败: {e}")
    except Exception as e:
        logger.warning(f"检查 PID 文件时出错: {e}")


@dataclass
class PeerInboundProcess:
    """存储单个对等节点入站进程信息"""
    tag: str
    pid: Optional[int] = None
    inbound_port: int = 0
    socks_port: int = 0
    status: str = "stopped"  # stopped, starting, running, error
    last_error: Optional[str] = None


class XrayPeerInboundManager:
    """Xray 对等节点入站管理器"""

    def __init__(self):
        self.processes: Dict[str, PeerInboundProcess] = {}
        self.db = get_db(GEODATA_DB_PATH, USER_DB_PATH)
        self._running = False

        # 创建运行目录
        XRAY_PEER_INBOUND_RUN_DIR.mkdir(parents=True, exist_ok=True)

        # 清理可能存在的无效 PID 文件
        self._cleanup_stale_pids()

    def _cleanup_stale_pids(self) -> None:
        """清理所有无效的 PID 文件"""
        for pid_file in XRAY_PEER_INBOUND_RUN_DIR.glob("*.pid"):
            cleanup_stale_pid_file(pid_file)

    def _get_pid_path(self, tag: str) -> Path:
        """获取指定节点的 PID 文件路径"""
        return XRAY_PEER_INBOUND_RUN_DIR / f"peer-{tag}.pid"

    def _get_config_path(self, tag: str) -> Path:
        """获取指定节点的配置文件路径"""
        return XRAY_PEER_INBOUND_RUN_DIR / f"peer-{tag}.json"

    def _get_log_path(self, tag: str) -> Path:
        """获取指定节点的日志文件路径"""
        return XRAY_PEER_INBOUND_LOG_DIR / f"xray-peer-{tag}.log"

    def _allocate_socks_port(self, tag: str) -> int:
        """为入站分配 SOCKS5 输出端口

        使用数据库分配的端口，如果没有则分配新端口
        端口存储在数据库中确保一致性和避免竞态条件
        """
        node = self.db.get_peer_node(tag)
        if node and node.get("inbound_socks_port"):
            return node.get("inbound_socks_port")

        # 分配新端口并存储到数据库
        nodes = self.db.get_peer_nodes_with_inbound()
        used_ports = set()
        for n in nodes:
            if n.get("inbound_socks_port"):
                used_ports.add(n.get("inbound_socks_port"))

        # 找到下一个可用端口
        port = PEER_INBOUND_SOCKS_BASE_PORT
        while port in used_ports or port > 65535:
            port += 1
            if port > 65535:
                raise RuntimeError("没有可用的 SOCKS 端口")

        # 存储到数据库
        self.db.update_peer_node(tag, inbound_socks_port=port)
        return port

    def _build_inbound_config(self, node: Dict) -> Dict:
        """构建 Xray 入站配置

        Args:
            node: 对等节点数据库记录

        Returns:
            Xray 入站配置字典
        """
        tag = node.get("tag")
        inbound_port = node.get("inbound_port")
        inbound_uuid = node.get("inbound_uuid")

        # REALITY 配置（使用节点的 REALITY 密钥）
        reality_private_key = node.get("xray_reality_private_key")
        reality_short_id = node.get("xray_reality_short_id")
        reality_dest = node.get("xray_reality_dest", "www.microsoft.com:443")

        # 解析 server_names
        server_names_raw = node.get("xray_reality_server_names", '["www.microsoft.com"]')
        try:
            server_names = json.loads(server_names_raw) if isinstance(server_names_raw, str) else server_names_raw
        except (json.JSONDecodeError, TypeError):
            server_names = ["www.microsoft.com"]

        # XHTTP 配置
        xhttp_path = node.get("xray_xhttp_path", "/")

        # SOCKS5 输出端口
        socks_port = self._allocate_socks_port(tag)

        # 构建 Xray 配置
        config = {
            "log": {
                "loglevel": "warning",
                "error": str(self._get_log_path(tag))
            },
            "inbounds": [
                {
                    "tag": f"peer-in-{tag}",
                    "listen": "0.0.0.0",
                    "port": inbound_port,
                    "protocol": "vless",
                    "settings": {
                        "clients": [
                            {
                                "id": inbound_uuid
                            }
                        ],
                        "decryption": "none"
                    },
                    "streamSettings": {
                        "network": "xhttp",
                        "xhttpSettings": {
                            "path": xhttp_path
                        },
                        "security": "reality",
                        "realitySettings": {
                            "dest": reality_dest,
                            "serverNames": server_names,
                            "privateKey": reality_private_key,
                            "shortIds": [reality_short_id] if reality_short_id else []
                        }
                    }
                }
            ],
            "outbounds": [
                {
                    "tag": "socks-to-singbox",
                    "protocol": "socks",
                    "settings": {
                        "servers": [
                            {
                                "address": "127.0.0.1",
                                "port": socks_port  # sing-box SOCKS 入站（由 render_singbox.py 生成）
                            }
                        ]
                    }
                },
                {
                    "tag": "direct",
                    "protocol": "freedom"
                }
            ],
            "routing": {
                "rules": [
                    {
                        "type": "field",
                        "inboundTag": [f"peer-in-{tag}"],
                        "outboundTag": "socks-to-singbox"
                    }
                ]
            }
        }

        return config

    def start_inbound(self, tag: str) -> bool:
        """启动指定节点的入站监听器

        Args:
            tag: 对等节点标识

        Returns:
            是否成功启动
        """
        # 获取节点配置
        node = self.db.get_peer_node(tag)
        if not node:
            logger.error(f"节点不存在: {tag}")
            return False

        if not node.get("inbound_enabled"):
            logger.error(f"节点未启用入站: {tag}")
            return False

        if not node.get("inbound_port"):
            logger.error(f"节点未分配入站端口: {tag}")
            return False

        inbound_uuid = node.get("inbound_uuid")
        if not inbound_uuid:
            logger.error(f"节点未配置入站 UUID: {tag}")
            return False

        # 验证 UUID 格式
        if not is_valid_uuid(inbound_uuid):
            logger.error(f"节点入站 UUID 格式无效: {tag}, uuid={inbound_uuid}")
            return False

        # 检查 REALITY 密钥
        if not node.get("xray_reality_private_key"):
            logger.error(f"节点未配置 REALITY 私钥: {tag}")
            return False

        # 检查是否已在运行
        pid_path = self._get_pid_path(tag)
        if pid_path.exists():
            try:
                pid = int(pid_path.read_text().strip())
                os.kill(pid, 0)
                logger.info(f"节点 {tag} 入站已在运行 (PID: {pid})")
                return True
            except (ValueError, ProcessLookupError, PermissionError):
                pid_path.unlink(missing_ok=True)

        # 生成配置
        config = self._build_inbound_config(node)
        config_path = self._get_config_path(tag)

        try:
            # 使用原子写入防止配置文件损坏
            tmp_path = config_path.with_suffix(".tmp")
            tmp_path.write_text(json.dumps(config, indent=2))
            tmp_path.rename(config_path)
            logger.info(f"已生成入站配置: {config_path}")
        except Exception as e:
            logger.error(f"写入配置文件失败: {e}")
            return False

        # 启动 Xray 进程
        log_file = None
        try:
            log_path = self._get_log_path(tag)
            log_file = open(log_path, 'a')

            process = subprocess.Popen(
                ["xray", "run", "-c", str(config_path)],
                stdout=log_file,
                stderr=subprocess.STDOUT,
                start_new_session=True
            )

            # 等待进程启动
            time.sleep(0.5)

            if process.poll() is not None:
                logger.error(f"Xray 进程启动后立即退出: {tag}")
                return False

            # 写入 PID 文件
            write_pid_file_atomic(pid_path, process.pid)

            # 更新进程信息
            socks_port = self._allocate_socks_port(tag)
            self.processes[tag] = PeerInboundProcess(
                tag=tag,
                pid=process.pid,
                inbound_port=node.get("inbound_port"),
                socks_port=socks_port,
                status="running"
            )

            logger.info(f"节点 {tag} 入站启动成功 (PID: {process.pid}, Port: {node.get('inbound_port')}, SOCKS: {socks_port})")
            return True

        except Exception as e:
            logger.error(f"启动 Xray 进程失败: {e}")
            return False
        finally:
            # 确保日志文件句柄关闭（进程已启动后不需要保持打开）
            if log_file is not None:
                try:
                    log_file.close()
                except Exception:
                    pass

    def stop_inbound(self, tag: str) -> bool:
        """停止指定节点的入站监听器

        Args:
            tag: 对等节点标识

        Returns:
            是否成功停止
        """
        pid_path = self._get_pid_path(tag)

        if not pid_path.exists():
            logger.info(f"节点 {tag} 入站未运行")
            if tag in self.processes:
                del self.processes[tag]
            return True

        try:
            pid = int(pid_path.read_text().strip())

            # 发送 SIGTERM
            os.kill(pid, signal.SIGTERM)
            logger.info(f"已发送 SIGTERM 到进程 {pid}")

            # 等待进程退出
            for _ in range(30):  # 最多等待 3 秒
                try:
                    os.kill(pid, 0)
                    time.sleep(0.1)
                except ProcessLookupError:
                    break
            else:
                # 进程未退出，发送 SIGKILL
                try:
                    os.kill(pid, signal.SIGKILL)
                    logger.warning(f"进程 {pid} 未响应 SIGTERM，已发送 SIGKILL")
                except ProcessLookupError:
                    pass

            # 清理 PID 文件
            pid_path.unlink(missing_ok=True)

            # 清理配置文件
            config_path = self._get_config_path(tag)
            config_path.unlink(missing_ok=True)

            # 更新进程信息
            if tag in self.processes:
                del self.processes[tag]

            logger.info(f"节点 {tag} 入站已停止")
            return True

        except ValueError:
            logger.error(f"无效的 PID 文件: {pid_path}")
            pid_path.unlink(missing_ok=True)
            return False
        except Exception as e:
            logger.error(f"停止入站失败: {e}")
            return False

    def get_inbound_status(self, tag: str) -> Dict:
        """获取指定节点入站状态

        Args:
            tag: 对等节点标识

        Returns:
            状态信息字典
        """
        pid_path = self._get_pid_path(tag)

        if not pid_path.exists():
            return {
                "tag": tag,
                "status": "stopped",
                "pid": None,
                "port": None
            }

        try:
            pid = int(pid_path.read_text().strip())
            os.kill(pid, 0)

            # 获取节点信息
            node = self.db.get_peer_node(tag)
            port = node.get("inbound_port") if node else None

            return {
                "tag": tag,
                "status": "running",
                "pid": pid,
                "port": port
            }
        except (ValueError, ProcessLookupError, PermissionError):
            # 进程已退出
            pid_path.unlink(missing_ok=True)
            return {
                "tag": tag,
                "status": "stopped",
                "pid": None,
                "port": None
            }

    def get_all_status(self) -> List[Dict]:
        """获取所有启用入站的节点状态"""
        nodes = self.db.get_peer_nodes_with_inbound()
        statuses = []

        for node in nodes:
            tag = node.get("tag")
            status = self.get_inbound_status(tag)
            status["inbound_enabled"] = node.get("inbound_enabled", 0)
            status["inbound_uuid"] = node.get("inbound_uuid")
            statuses.append(status)

        return statuses

    def start_all(self) -> int:
        """启动所有启用入站的节点

        Returns:
            成功启动的节点数
        """
        nodes = self.db.get_peer_nodes_with_inbound()
        started = 0

        for node in nodes:
            tag = node.get("tag")
            if self.start_inbound(tag):
                started += 1

        return started

    def stop_all(self) -> int:
        """停止所有入站

        Returns:
            成功停止的节点数
        """
        stopped = 0

        for pid_file in XRAY_PEER_INBOUND_RUN_DIR.glob("peer-*.pid"):
            tag = pid_file.stem.replace("peer-", "")
            if self.stop_inbound(tag):
                stopped += 1

        return stopped

    def reload_all(self) -> None:
        """重新加载所有入站配置"""
        self.stop_all()
        time.sleep(0.5)
        self.start_all()

    def daemon_loop(self) -> None:
        """守护进程循环，监控并重启崩溃的入站"""
        self._running = True

        def signal_handler(signum, frame):
            logger.info("收到退出信号，正在停止...")
            self._running = False

        signal.signal(signal.SIGTERM, signal_handler)
        signal.signal(signal.SIGINT, signal_handler)

        logger.info("Xray 对等节点入站守护进程已启动")

        # 首次启动所有入站
        self.start_all()

        while self._running:
            try:
                # 检查所有应该运行的入站
                nodes = self.db.get_peer_nodes_with_inbound()

                for node in nodes:
                    tag = node.get("tag")
                    status = self.get_inbound_status(tag)

                    if status["status"] != "running":
                        logger.warning(f"检测到节点 {tag} 入站未运行，尝试重启...")
                        self.start_inbound(tag)

                # 每 30 秒检查一次
                for _ in range(30):
                    if not self._running:
                        break
                    time.sleep(1)

            except Exception as e:
                logger.exception(f"守护进程循环错误: {e}")
                time.sleep(5)

        # 停止所有入站
        self.stop_all()
        logger.info("守护进程已退出")


def main():
    parser = argparse.ArgumentParser(description="Xray 对等节点入站管理器")
    parser.add_argument(
        "action",
        choices=["start", "stop", "status", "daemon", "start-all", "stop-all", "reload"],
        help="操作类型"
    )
    parser.add_argument("tag", nargs="?", help="节点标识（start/stop 操作需要）")
    args = parser.parse_args()

    # 加载 SQLCipher 加密密钥
    try:
        from key_manager import KeyManager
        km = KeyManager()
        key = km.get_or_create_key()
        if key:
            os.environ["SQLCIPHER_KEY"] = key
    except ImportError:
        logger.warning("无法导入 KeyManager，数据库可能无法访问")
    except Exception as e:
        logger.warning(f"加载加密密钥失败: {e}")

    manager = XrayPeerInboundManager()

    if args.action == "start":
        if not args.tag:
            print("错误: start 操作需要指定节点标识")
            sys.exit(1)
        success = manager.start_inbound(args.tag)
        sys.exit(0 if success else 1)

    elif args.action == "stop":
        if not args.tag:
            print("错误: stop 操作需要指定节点标识")
            sys.exit(1)
        success = manager.stop_inbound(args.tag)
        sys.exit(0 if success else 1)

    elif args.action == "status":
        statuses = manager.get_all_status()
        if not statuses:
            print("没有启用入站的节点")
        else:
            print(f"{'节点':<20} {'状态':<12} {'PID':<10} {'端口':<10}")
            print("-" * 52)
            for status in statuses:
                tag = status["tag"]
                state = status["status"]
                pid = status.get("pid") or "-"
                port = status.get("port") or "-"
                print(f"{tag:<20} {state:<12} {pid:<10} {port:<10}")

    elif args.action == "start-all":
        count = manager.start_all()
        print(f"启动了 {count} 个入站")

    elif args.action == "stop-all":
        count = manager.stop_all()
        print(f"停止了 {count} 个入站")

    elif args.action == "reload":
        manager.reload_all()
        print("已重新加载所有入站")

    elif args.action == "daemon":
        manager.daemon_loop()


if __name__ == "__main__":
    main()

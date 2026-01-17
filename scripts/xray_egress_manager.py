#!/usr/bin/env python3
"""
Xray 出站管理器

管理 Xray 出站进程，支持 sing-box 无法实现的功能：
- XHTTP 传输
- REALITY 客户端
- XTLS-Vision

架构:
    sing-box → SOCKS5 (127.0.0.1:37101) → Xray → 远程 V2Ray 服务器
           → SOCKS5 (127.0.0.1:37102) → Xray → 远程 V2Ray 服务器
           ...

使用方法:
    python3 xray_egress_manager.py start     # 启动 Xray 出站
    python3 xray_egress_manager.py stop      # 停止 Xray 出站
    python3 xray_egress_manager.py reload    # 重载配置
    python3 xray_egress_manager.py status    # 显示状态
    python3 xray_egress_manager.py daemon    # 守护进程模式
"""

import argparse
import asyncio
import json
import logging
import os
import signal
import subprocess
import sys
import time
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
        format='[xray-egress] %(asctime)s %(levelname)s: %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    logger = logging.getLogger(__name__)

# 配置路径
XRAY_EGRESS_RUN_DIR = Path("/run/xray-egress")
XRAY_EGRESS_LOG_DIR = Path("/var/log")
XRAY_EGRESS_CONFIG_PATH = XRAY_EGRESS_RUN_DIR / "config.json"
XRAY_EGRESS_PID_FILE = XRAY_EGRESS_RUN_DIR / "xray-egress.pid"
GEODATA_DB_PATH = os.environ.get("GEODATA_DB_PATH", "/etc/sing-box/geoip-geodata.db")
USER_DB_PATH = os.environ.get("USER_DB_PATH", "/etc/sing-box/user-config.db")

# Xray 出站 V2Ray API 端口 (gRPC StatsService)
# 用于查询各出口的流量统计，与 sing-box 的 10085 区分
XRAY_EGRESS_API_PORT = 10086


def cleanup_stale_pid_file(pid_path: Path) -> None:
    """
    清理无效的 PID 文件 (L18 修复)
    """
    if not pid_path.exists():
        return

    try:
        pid_str = pid_path.read_text().strip()
        pid = int(pid_str)
        # 检查进程是否存在
        os.kill(pid, 0)
    except (ValueError, ProcessLookupError, PermissionError):
        # PID 无效或进程不存在，清理文件
        try:
            pid_path.unlink()
            logger.debug(f"已清理无效 PID 文件: {pid_path}")
        except Exception as e:
            logger.warning(f"清理 PID 文件失败: {e}")
    except Exception as e:
        logger.warning(f"检查 PID 文件时出错: {e}")


@dataclass
class XrayEgressProcess:
    """存储 Xray 出站进程信息"""
    pid: Optional[int] = None
    status: str = "stopped"  # stopped, starting, running, error
    egress_count: int = 0
    socks_ports: List[int] = field(default_factory=list)
    config: Dict[str, Any] = field(default_factory=dict)


class XrayEgressManager:
    """Xray 出站进程管理器"""

    def __init__(self):
        self.process = XrayEgressProcess()
        self.db = get_db(GEODATA_DB_PATH, USER_DB_PATH)
        self._running = False
        # L18: 清理可能存在的无效 PID 文件
        cleanup_stale_pid_file(XRAY_EGRESS_PID_FILE)

    def _get_v2ray_egress_list(self) -> List[Dict]:
        """从数据库读取启用的 V2Ray 出口列表"""
        try:
            return self.db.get_v2ray_egress_list(enabled_only=True)
        except Exception as e:
            logger.error(f"读取 V2Ray 出口列表失败: {e}")
            return []

    def _build_xray_outbound(self, egress: Dict) -> Dict:
        """构建单个 Xray 出站配置

        Args:
            egress: V2Ray 出口配置字典

        Returns:
            Xray 出站配置
        """
        protocol = egress.get("protocol", "vless")
        tag = egress.get("tag")
        server = egress.get("server")
        server_port = egress.get("server_port", 443)

        # 基础出站配置
        outbound = {
            "tag": tag,
            "protocol": protocol,
            "settings": {}
        }

        # 根据协议配置
        if protocol == "vless":
            outbound["settings"] = {
                "vnext": [{
                    "address": server,
                    "port": server_port,
                    "users": [{
                        "id": egress.get("uuid"),
                        "encryption": "none"
                    }]
                }]
            }
            # XTLS-Vision flow
            if egress.get("flow"):
                outbound["settings"]["vnext"][0]["users"][0]["flow"] = egress["flow"]

        elif protocol == "vmess":
            # [REMOVED in Xray-lite] VMess 协议已从 Xray-lite 中移除
            raise ValueError(
                f"VMess protocol is no longer supported in Xray-lite. "
                f"Egress '{tag}' uses VMess. Please migrate to VLESS protocol. "
                "See docs/VMESS_TROJAN_MIGRATION.md"
            )

        elif protocol == "trojan":
            # [REMOVED in Xray-lite] Trojan 协议已从 Xray-lite 中移除
            raise ValueError(
                f"Trojan protocol is no longer supported in Xray-lite. "
                f"Egress '{tag}' uses Trojan. Please migrate to VLESS protocol. "
                "See docs/VMESS_TROJAN_MIGRATION.md"
            )

        # 流设置
        transport_type = egress.get("transport_type", "tcp")
        stream_settings = {
            "network": transport_type
        }

        # 传输层配置
        transport_config_raw = egress.get("transport_config")
        if transport_config_raw:
            try:
                # Handle both dict (already parsed) and string (JSON) formats
                if isinstance(transport_config_raw, dict):
                    transport_config = transport_config_raw
                else:
                    transport_config = json.loads(transport_config_raw)

                if transport_type == "tcp" and transport_config:
                    # TCP header settings
                    if transport_config.get("header_type"):
                        stream_settings["tcpSettings"] = {
                            "header": {"type": transport_config["header_type"]}
                        }

                elif transport_type == "ws" and transport_config:
                    stream_settings["wsSettings"] = {
                        "path": transport_config.get("path", "/"),
                        "headers": transport_config.get("headers", {})
                    }

                elif transport_type == "grpc" and transport_config:
                    grpc_settings = {
                        "serviceName": transport_config.get("service_name", "")
                    }
                    if transport_config.get("authority"):
                        grpc_settings["authority"] = transport_config["authority"]
                    stream_settings["grpcSettings"] = grpc_settings

                elif transport_type == "h2" and transport_config:
                    stream_settings["httpSettings"] = {
                        "path": transport_config.get("path", "/"),
                        "host": transport_config.get("host", [])
                    }

                elif transport_type == "quic" and transport_config:
                    stream_settings["quicSettings"] = {
                        "security": transport_config.get("security", "none"),
                        "key": transport_config.get("key", ""),
                        "header": {
                            "type": transport_config.get("header_type", "none")
                        }
                    }

                elif transport_type == "httpupgrade" and transport_config:
                    stream_settings["httpupgradeSettings"] = {
                        "path": transport_config.get("path", "/"),
                        "host": transport_config.get("host", "")
                    }

                elif transport_type == "xhttp" and transport_config:
                    xhttp_settings = {
                        "path": transport_config.get("path", "/")
                    }
                    # Mode: auto, packet-up, stream-up, stream-one
                    if transport_config.get("mode"):
                        xhttp_settings["mode"] = transport_config["mode"]
                    # Host header (optional)
                    if transport_config.get("host"):
                        xhttp_settings["host"] = transport_config["host"]
                    stream_settings["xhttpSettings"] = xhttp_settings

            except (json.JSONDecodeError, TypeError) as e:
                logger.warning(f"解析传输层配置失败 ({tag}): {e}")

        # REALITY 配置（优先于 TLS）
        if egress.get("reality_enabled"):
            stream_settings["security"] = "reality"
            reality_settings = {
                "serverName": egress.get("tls_sni") or server,
                "fingerprint": egress.get("tls_fingerprint") or "chrome",
                "publicKey": egress.get("reality_public_key") or "",
                "shortId": egress.get("reality_short_id") or ""
            }
            stream_settings["realitySettings"] = reality_settings

        elif egress.get("tls_enabled"):
            stream_settings["security"] = "tls"
            tls_settings = {
                "serverName": egress.get("tls_sni") or server
            }

            # uTLS fingerprint
            if egress.get("tls_fingerprint"):
                tls_settings["fingerprint"] = egress["tls_fingerprint"]

            # ALPN
            alpn = egress.get("tls_alpn")
            if alpn:
                if isinstance(alpn, str):
                    try:
                        alpn = json.loads(alpn)
                    except:
                        alpn = [alpn]
                tls_settings["alpn"] = alpn

            # Allow insecure
            if egress.get("tls_allow_insecure"):
                tls_settings["allowInsecure"] = True

            stream_settings["tlsSettings"] = tls_settings

        outbound["streamSettings"] = stream_settings
        return outbound

    def _generate_xray_config(self, egress_list: List[Dict]) -> Dict:
        """生成 Xray 出站配置

        每个出口有一个 SOCKS5 入站和对应的出站，
        通过路由规则将 SOCKS 入站流量路由到对应出站。

        Args:
            egress_list: 启用的 V2Ray 出口列表

        Returns:
            完整的 Xray 配置
        """
        xray_config = {
            "log": {
                "loglevel": "warning",
                "access": str(XRAY_EGRESS_LOG_DIR / "xray-egress-access.log"),
                "error": str(XRAY_EGRESS_LOG_DIR / "xray-egress-error.log")
            },
            # 启用统计功能
            "stats": {},
            # V2Ray API 用于查询统计数据
            "api": {
                "tag": "api",
                "services": ["StatsService"]
            },
            # 策略配置：启用入站/出站统计
            "policy": {
                "system": {
                    "statsInboundUplink": True,
                    "statsInboundDownlink": True,
                    "statsOutboundUplink": True,
                    "statsOutboundDownlink": True
                }
            },
            "inbounds": [
                # API 入站 (gRPC 端口)
                {
                    "tag": "api",
                    "port": XRAY_EGRESS_API_PORT,
                    "listen": "127.0.0.1",
                    "protocol": "dokodemo-door",
                    "settings": {
                        "address": "127.0.0.1"
                    }
                }
            ],
            "outbounds": [],
            "routing": {
                "domainStrategy": "AsIs",
                "rules": [
                    # API 路由规则
                    {
                        "type": "field",
                        "inboundTag": ["api"],
                        "outboundTag": "api"
                    }
                ]
            }
        }

        socks_ports = []

        for egress in egress_list:
            tag = egress.get("tag")
            socks_port = egress.get("socks_port")

            if not tag or not socks_port:
                logger.warning(f"跳过无效出口配置: {egress}")
                continue

            socks_ports.append(socks_port)

            # SOCKS5 入站（sing-box 连接到这里）
            xray_config["inbounds"].append({
                "tag": f"socks-{tag}",
                "port": socks_port,
                "listen": "127.0.0.1",
                "protocol": "socks",
                "settings": {
                    "udp": True
                }
            })

            # V2Ray 出站
            try:
                outbound = self._build_xray_outbound(egress)
                xray_config["outbounds"].append(outbound)
            except Exception as e:
                logger.error(f"构建出站配置失败 ({tag}): {e}")
                continue

            # 路由规则：SOCKS 入站 → 对应出站
            xray_config["routing"]["rules"].append({
                "type": "field",
                "inboundTag": [f"socks-{tag}"],
                "outboundTag": tag
            })

        # 添加直连出站（备用）
        xray_config["outbounds"].append({
            "tag": "freedom",
            "protocol": "freedom",
            "settings": {}
        })

        self.process.socks_ports = socks_ports
        return xray_config

    async def start(self) -> bool:
        """启动 Xray 出站"""
        egress_list = self._get_v2ray_egress_list()

        if not egress_list:
            logger.info("没有启用的 V2Ray 出口，跳过启动")
            return True

        logger.info(f"启动 Xray 出站... ({len(egress_list)} 个出口)")
        self.process.status = "starting"
        self.process.egress_count = len(egress_list)

        # 创建运行目录
        XRAY_EGRESS_RUN_DIR.mkdir(parents=True, exist_ok=True)

        # 生成配置
        try:
            xray_config = self._generate_xray_config(egress_list)
            if not xray_config["inbounds"]:
                logger.warning("没有有效的出口配置")
                return True

            XRAY_EGRESS_CONFIG_PATH.write_text(json.dumps(xray_config, indent=2))
            self.process.config = xray_config
            logger.info(f"Xray 出站配置已生成: {XRAY_EGRESS_CONFIG_PATH}")
        except Exception as e:
            logger.error(f"生成 Xray 出站配置失败: {e}")
            self.process.status = "error"
            return False

        # 启动 Xray 进程
        try:
            proc = subprocess.Popen(
                ["xray", "run", "-c", str(XRAY_EGRESS_CONFIG_PATH)],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL
            )
            self.process.pid = proc.pid
            logger.info(f"Xray 出站已启动 (PID: {proc.pid})")
        except Exception as e:
            logger.error(f"启动 Xray 出站失败: {e}")
            self.process.status = "error"
            return False

        # 等待进程稳定
        await asyncio.sleep(1)

        # 检查进程是否仍在运行
        if self._is_process_alive():
            self.process.status = "running"
            # 写入 PID 文件
            try:
                XRAY_EGRESS_PID_FILE.write_text(str(self.process.pid))
                logger.debug(f"PID 文件已写入: {XRAY_EGRESS_PID_FILE}")
            except Exception as e:
                logger.warning(f"写入 PID 文件失败: {e}")

            # 打印 SOCKS 端口信息
            for egress in egress_list:
                logger.info(f"  {egress['tag']}: SOCKS5 127.0.0.1:{egress['socks_port']}")

            logger.info("Xray 出站启动成功")
            return True
        else:
            self.process.status = "error"
            logger.error("Xray 出站启动后立即退出")
            # 尝试读取错误日志
            try:
                error_log = XRAY_EGRESS_LOG_DIR / "xray-egress-error.log"
                if error_log.exists():
                    content = error_log.read_text()
                    if content:
                        logger.error(f"Xray 错误日志:\n{content[-1000:]}")
            except:
                pass
            return False

    async def stop(self) -> bool:
        """停止 Xray 出站"""
        logger.info("停止 Xray 出站...")

        # 停止 Xray 进程
        pid = self.process.pid or self._read_pid_from_file()
        if pid:
            try:
                os.kill(pid, signal.SIGTERM)
                logger.debug(f"已发送 SIGTERM 到 Xray 出站 (PID: {pid})")

                # 等待进程退出
                for _ in range(10):
                    try:
                        os.kill(pid, 0)
                        await asyncio.sleep(0.5)
                    except ProcessLookupError:
                        break
                else:
                    # 强制杀死
                    try:
                        os.kill(pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
            except ProcessLookupError:
                pass

            self.process.pid = None

        # 清理配置文件
        if XRAY_EGRESS_CONFIG_PATH.exists():
            XRAY_EGRESS_CONFIG_PATH.unlink()

        # 删除 PID 文件
        if XRAY_EGRESS_PID_FILE.exists():
            try:
                XRAY_EGRESS_PID_FILE.unlink()
            except Exception as e:
                logger.warning(f"删除 PID 文件失败: {e}")

        self.process.status = "stopped"
        self.process.egress_count = 0
        self.process.socks_ports = []
        logger.info("Xray 出站已停止")
        return True

    async def reload(self) -> bool:
        """重载配置"""
        logger.info("重载 Xray 出站配置...")

        # 读取新配置
        egress_list = self._get_v2ray_egress_list()

        if not egress_list:
            # 没有出口，停止 Xray
            if self._is_process_alive():
                await self.stop()
            return True

        # 生成新配置
        try:
            xray_config = self._generate_xray_config(egress_list)
            XRAY_EGRESS_CONFIG_PATH.write_text(json.dumps(xray_config, indent=2))
            self.process.config = xray_config
            self.process.egress_count = len(egress_list)
        except Exception as e:
            logger.error(f"生成 Xray 出站配置失败: {e}")
            return False

        # 如果进程不在运行，启动它
        if not self._is_process_alive():
            return await self.start()

        # Xray 不支持 SIGHUP 热重载，需要重启
        logger.info("重启 Xray 出站以应用新配置")
        await self.stop()
        return await self.start()

    def _read_pid_from_file(self) -> Optional[int]:
        """从 PID 文件读取 PID"""
        if XRAY_EGRESS_PID_FILE.exists():
            try:
                pid_str = XRAY_EGRESS_PID_FILE.read_text().strip()
                return int(pid_str)
            except (ValueError, IOError):
                pass
        return None

    def _is_process_alive(self) -> bool:
        """检查 Xray 出站进程是否存活"""
        pid = self.process.pid or self._read_pid_from_file()
        if not pid:
            return False
        try:
            os.kill(pid, 0)
            return True
        except ProcessLookupError:
            return False

    def get_status(self) -> Dict:
        """获取状态信息"""
        alive = self._is_process_alive()
        pid = self.process.pid or self._read_pid_from_file()

        if alive:
            status = "running"
        elif self.process.status == "starting":
            status = "starting"
        elif self.process.status == "error":
            status = "error"
        else:
            status = "stopped"

        # 从数据库获取实际的 egress 信息（而不是依赖内存状态）
        egress_list = self._get_v2ray_egress_list()
        egress_count = len(egress_list)
        socks_ports = [e.get("socks_port") for e in egress_list if e.get("socks_port")]

        return {
            "status": status,
            "pid": pid if alive else None,
            "egress_count": egress_count,
            "socks_ports": socks_ports
        }

    async def run_daemon(self):
        """以守护进程模式运行"""
        self._running = True
        logger.info("Xray 出站管理器启动（守护模式）")

        # 启动 Xray 出站
        await self.start()

        # 监控循环
        while self._running:
            await asyncio.sleep(10)

            # 检查进程健康
            if self.process.status == "running" and not self._is_process_alive():
                logger.warning("Xray 出站进程已退出，尝试重启")
                await self.start()

        # 清理
        await self.stop()
        logger.info("Xray 出站管理器已停止")

    def stop_daemon(self):
        """停止守护进程"""
        self._running = False


async def main():
    parser = argparse.ArgumentParser(description='Xray 出站进程管理器')
    parser.add_argument('command', choices=['start', 'stop', 'reload', 'status', 'daemon'],
                        help='操作命令')
    parser.add_argument('--verbose', '-v', action='store_true', help='详细输出')
    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    manager = XrayEgressManager()

    if args.command == 'start':
        success = await manager.start()
        sys.exit(0 if success else 1)

    elif args.command == 'stop':
        success = await manager.stop()
        sys.exit(0 if success else 1)

    elif args.command == 'reload':
        success = await manager.reload()
        sys.exit(0 if success else 1)

    elif args.command == 'status':
        status = manager.get_status()
        print(json.dumps(status, indent=2, ensure_ascii=False))

    elif args.command == 'daemon':
        # 设置信号处理
        loop = asyncio.get_event_loop()

        def signal_handler():
            logger.info("收到停止信号")
            manager.stop_daemon()

        for sig in (signal.SIGTERM, signal.SIGINT):
            loop.add_signal_handler(sig, signal_handler)

        await manager.run_daemon()


if __name__ == '__main__':
    asyncio.run(main())

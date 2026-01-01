#!/usr/bin/env python3
"""
WARP 管理器 - Cloudflare WARP MASQUE 协议支持

使用 usque 工具管理 WARP 设备注册和 SOCKS5 代理：
- 设备注册（调用 usque register）
- SOCKS5 代理启动/停止
- WARP+ License 应用
- 自定义 Endpoint 设置
- 进程生命周期管理

使用方法:
    python3 warp_manager.py start     # 启动所有启用的 WARP 代理
    python3 warp_manager.py stop      # 停止所有代理
    python3 warp_manager.py reload    # 重载配置
    python3 warp_manager.py status    # 显示状态
    python3 warp_manager.py daemon    # 守护进程模式
"""

import argparse
import asyncio
import fcntl
import json
import logging
import os
import shutil
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
from setup_kernel_wg_egress import get_egress_interface_name

logging.basicConfig(
    level=logging.INFO,
    format='[warp-mgr] %(asctime)s %(levelname)s: %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger(__name__)

# 配置路径
WARP_BASE_DIR = Path("/etc/sing-box/warp")
WARP_RUN_DIR = Path("/run/warp")
WARP_PID_FILE = Path("/run/warp-manager.pid")
USQUE_BIN = Path("/usr/local/bin/usque")
GEODATA_DB_PATH = os.environ.get("GEODATA_DB_PATH", "/etc/sing-box/geoip-geodata.db")
USER_DB_PATH = os.environ.get("USER_DB_PATH", "/etc/sing-box/user-config.db")

# SOCKS5 端口范围（可通过环境变量配置，与 OpenVPN 37001+ 和 V2Ray 37101+ 分开）
WARP_SOCKS_PORT_START = int(os.environ.get("WARP_MASQUE_PORT_BASE", "38001"))


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
        os.kill(pid, 0)  # 检查进程是否存在
    except (ValueError, ProcessLookupError, PermissionError):
        try:
            pid_path.unlink()
            logger.debug(f"已清理无效 PID 文件: {pid_path}")
        except Exception as e:
            logger.warning(f"清理 PID 文件失败: {e}")


def write_config_atomic(config_path: Path, config: dict) -> None:
    """原子写入配置文件"""
    config_path.parent.mkdir(parents=True, exist_ok=True)
    tmp_path = config_path.with_suffix(".tmp")
    tmp_path.write_text(json.dumps(config, indent=2))
    tmp_path.rename(config_path)


@dataclass
class WarpProcess:
    """存储 WARP 代理进程信息"""
    tag: str
    pid: Optional[int] = None
    socks_port: int = 0
    config_path: Optional[Path] = None
    status: str = "stopped"  # stopped, starting, running, error
    endpoint_v4: Optional[str] = None
    endpoint_v6: Optional[str] = None
    account_type: str = "free"


class WarpManager:
    """WARP 代理管理器"""

    def __init__(self):
        self.processes: Dict[str, WarpProcess] = {}
        self.db = get_db(GEODATA_DB_PATH, USER_DB_PATH)
        self._running = False
        self._reload_requested = False

    def _get_config_dir(self, tag: str) -> Path:
        """获取 WARP 出口的配置目录"""
        return WARP_BASE_DIR / tag

    def _get_pid_file(self, tag: str) -> Path:
        """获取 WARP 出口的 PID 文件路径"""
        return WARP_RUN_DIR / f"{tag}.pid"

    def register(self, tag: str, license_key: Optional[str] = None, protocol: str = "masque") -> dict:
        """
        注册新的 WARP 设备

        Args:
            tag: 出口标识
            license_key: WARP+ license key（可选）
            protocol: 协议类型 ("masque" 或 "wireguard")

        Returns:
            包含注册结果的字典
        """
        if protocol == "wireguard":
            return self._register_wireguard(tag, license_key)
        else:
            return self._register_masque(tag, license_key)

    def _register_masque(self, tag: str, license_key: Optional[str] = None) -> dict:
        """使用 MASQUE 协议注册 WARP 设备（通过 usque）"""
        config_dir = self._get_config_dir(tag)
        config_dir.mkdir(parents=True, exist_ok=True)
        config_path = config_dir / "config.json"

        logger.info(f"[{tag}] 注册 WARP 设备 (MASQUE)...")

        # 检查 usque 是否存在
        if not USQUE_BIN.exists():
            return {
                "success": False,
                "error": f"usque 二进制不存在: {USQUE_BIN}"
            }

        try:
            # 调用 usque register (必须使用 --accept-tos 进行非交互式注册)
            result = subprocess.run(
                [
                    str(USQUE_BIN), "register",
                    "--config", str(config_path),
                    "--accept-tos",  # 自动接受服务条款
                    "--name", tag  # 使用 tag 作为设备名称
                ],
                capture_output=True,
                text=True,
                timeout=60
            )

            if result.returncode != 0:
                error_msg = result.stderr.strip() or result.stdout.strip() or "未知错误"
                logger.error(f"[{tag}] 注册失败: {error_msg}")
                return {
                    "success": False,
                    "error": f"usque register 失败: {error_msg}"
                }

            logger.info(f"[{tag}] WARP 设备注册成功")

            # 如果提供了 license key，应用它
            if license_key:
                license_result = self.apply_license(tag, license_key)
                if not license_result.get("success"):
                    logger.warning(f"[{tag}] License 应用失败: {license_result.get('error')}")

            # 读取生成的配置
            if config_path.exists():
                with open(config_path, 'r') as f:
                    config = json.load(f)

                return {
                    "success": True,
                    "config_path": str(config_path),
                    "device_id": config.get("device_id", ""),
                    "account_type": "warp+" if license_key else "free"
                }
            else:
                return {
                    "success": False,
                    "error": "配置文件未生成"
                }

        except subprocess.TimeoutExpired:
            logger.error(f"[{tag}] 注册超时")
            return {"success": False, "error": "注册超时"}
        except Exception as e:
            logger.error(f"[{tag}] 注册异常: {e}")
            return {"success": False, "error": str(e)}

    def _register_wireguard(self, tag: str, license_key: Optional[str] = None,
                            custom_endpoint: Optional[str] = None) -> dict:
        """使用 WireGuard 协议注册 WARP 设备"""
        import uuid
        config_dir = self._get_config_dir(tag)
        config_dir.mkdir(parents=True, exist_ok=True)
        config_path = config_dir / "wg.conf"

        logger.info(f"[{tag}] 注册 WARP 设备 (WireGuard)...")

        try:
            # 使用 WARP API 注册设备并获取 WireGuard 配置
            import requests

            # 生成 WireGuard 密钥对
            wg_result = subprocess.run(["wg", "genkey"], capture_output=True, text=True)
            if wg_result.returncode != 0:
                return {"success": False, "error": "Failed to generate WireGuard key"}
            private_key = wg_result.stdout.strip()

            pubkey_result = subprocess.run(
                ["wg", "pubkey"],
                input=private_key,
                capture_output=True,
                text=True
            )
            if pubkey_result.returncode != 0:
                return {"success": False, "error": "Failed to derive public key"}
            public_key = pubkey_result.stdout.strip()

            # 生成设备 ID (UUID)
            install_id = str(uuid.uuid4())

            # 注册设备到 Cloudflare WARP API
            # 使用 wgcf 项目验证过的 API 版本和格式
            from datetime import datetime
            api_url = "https://api.cloudflareclient.com/v0i2109031238/reg"
            headers = {
                "Content-Type": "application/json",
            }
            payload = {
                "key": public_key,
                "install_id": install_id,
                "fcm_token": "",
                "tos": datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%S.000Z'),
                "type": "Linux",
                "model": "",
                "locale": "en_US"
            }

            logger.debug(f"[{tag}] WARP API request: {api_url}")
            resp = requests.post(api_url, json=payload, headers=headers, timeout=30)
            if resp.status_code != 200:
                return {
                    "success": False,
                    "error": f"WARP API error: {resp.status_code} - {resp.text[:200]}"
                }

            resp_data = resp.json()

            # 新版 API 返回格式: {"result": {...}, "success": true}
            if not resp_data.get("success", False):
                errors = resp_data.get("errors", [])
                error_msg = errors[0].get("message", "Unknown error") if errors else "Unknown error"
                return {"success": False, "error": f"WARP API error: {error_msg}"}

            data = resp_data.get("result", {})
            device_id = data.get("id", "")
            token = data.get("token", "")
            account = data.get("account", {})
            warp_config = data.get("config", {})
            peers = warp_config.get("peers", [])

            if not peers:
                return {"success": False, "error": "No peers returned from API"}

            peer = peers[0]
            endpoint = peer.get("endpoint", {})
            peer_public_key = peer.get("public_key", "")

            # 解析客户端 IP 地址
            interface = warp_config.get("interface", {})
            addresses = interface.get("addresses", {})
            client_ipv4 = addresses.get("v4", "172.16.0.2")
            client_ipv6 = addresses.get("v6", "2606:4700:110:8a67:2a4c:24dc:73d3:7f03")

            # 使用自定义 endpoint 或 API 返回的默认值
            if custom_endpoint:
                endpoint_host = custom_endpoint
            else:
                endpoint_host = endpoint.get("host", "engage.cloudflareclient.com:2408")

            # 生成 WireGuard 配置文件
            wg_conf = f"""[Interface]
PrivateKey = {private_key}
Address = {client_ipv4}/32, {client_ipv6}/128
DNS = 1.1.1.1

[Peer]
PublicKey = {peer_public_key}
AllowedIPs = 0.0.0.0/0, ::/0
Endpoint = {endpoint_host}
PersistentKeepalive = 25
"""

            with open(config_path, 'w') as f:
                f.write(wg_conf)

            # 保存元数据
            meta_path = config_dir / "meta.json"
            with open(meta_path, 'w') as f:
                json.dump({
                    "device_id": device_id,
                    "token": token,
                    "account_id": account.get("id", ""),
                    "private_key": private_key,
                    "public_key": public_key,
                    "protocol": "wireguard"
                }, f, indent=2)

            # 如果有 license key，尝试应用
            if license_key and token:
                try:
                    license_url = f"https://api.cloudflareclient.com/v0i2109031238/reg/{device_id}/account"
                    license_headers = {
                        "Content-Type": "application/json",
                        "Authorization": f"Bearer {token}"
                    }
                    license_resp = requests.put(
                        license_url,
                        json={"license": license_key},
                        headers=license_headers,
                        timeout=30
                    )
                    if license_resp.status_code == 200:
                        logger.info(f"[{tag}] WARP+ License 应用成功")
                except Exception as e:
                    logger.warning(f"[{tag}] License 应用失败: {e}")

            logger.info(f"[{tag}] WARP WireGuard 配置生成成功")

            return {
                "success": True,
                "config_path": str(config_path),
                "device_id": device_id,
                "account_type": "warp+" if license_key else "free"
            }

        except Exception as e:
            logger.error(f"[{tag}] WireGuard 注册异常: {e}")
            return {"success": False, "error": str(e)}

    def apply_license(self, tag: str, license_key: str) -> dict:
        """
        应用 WARP+ License（通过 Cloudflare API）

        Args:
            tag: 出口标识
            license_key: WARP+ license key

        Returns:
            包含结果的字典
        """
        import requests

        config_dir = self._get_config_dir(tag)
        config_path = config_dir / "config.json"

        if not config_path.exists():
            return {"success": False, "error": "配置文件不存在，请先注册"}

        logger.info(f"[{tag}] 应用 WARP+ License...")

        try:
            # 读取配置获取 device_id 和 access_token
            with open(config_path, 'r') as f:
                config = json.load(f)

            device_id = config.get("id")
            access_token = config.get("access_token")

            if not device_id or not access_token:
                return {"success": False, "error": "配置文件缺少 device_id 或 access_token"}

            # 调用 Cloudflare API 更新 license
            license_url = f"https://api.cloudflareclient.com/v0i2109031238/reg/{device_id}/account"
            headers = {
                "Content-Type": "application/json",
                "Authorization": f"Bearer {access_token}"
            }

            resp = requests.put(
                license_url,
                json={"license": license_key},
                headers=headers,
                timeout=30
            )

            if resp.status_code == 200:
                # 更新配置文件中的 license
                config["license"] = license_key
                write_config_atomic(config_path, config)
                logger.info(f"[{tag}] WARP+ License 应用成功")
                return {"success": True, "account_type": "warp+"}
            else:
                error_msg = resp.text or f"HTTP {resp.status_code}"
                logger.error(f"[{tag}] License 应用失败: {error_msg}")
                return {"success": False, "error": error_msg}

        except requests.Timeout:
            return {"success": False, "error": "操作超时"}
        except json.JSONDecodeError:
            return {"success": False, "error": "配置文件格式错误"}
        except Exception as e:
            logger.error(f"[{tag}] License 应用异常: {e}")
            return {"success": False, "error": str(e)}

    def set_endpoint(self, tag: str, endpoint_v4: Optional[str] = None,
                     endpoint_v6: Optional[str] = None) -> dict:
        """
        设置自定义 Endpoint（指定地区节点）

        Args:
            tag: 出口标识
            endpoint_v4: IPv4 endpoint (仅 IP 地址，端口由协议自动确定)
                         MASQUE: 443, WireGuard: 2408
            endpoint_v6: IPv6 endpoint (可选，仅 IP 地址)

        Returns:
            包含结果的字典
        """
        # 检查协议类型
        egress = self.db.get_warp_egress(tag)
        if not egress:
            return {"success": False, "error": "WARP 配置不存在"}

        protocol = egress.get("protocol", "masque")
        config_dir = self._get_config_dir(tag)

        try:
            if protocol == "wireguard":
                return self._set_endpoint_wireguard(tag, config_dir, endpoint_v4, endpoint_v6)
            else:
                return self._set_endpoint_masque(tag, config_dir, endpoint_v4, endpoint_v6)
        except Exception as e:
            logger.error(f"[{tag}] 设置 Endpoint 失败: {e}")
            return {"success": False, "error": str(e)}

    def _set_endpoint_masque(self, tag: str, config_dir: Path,
                              endpoint_v4: Optional[str], endpoint_v6: Optional[str]) -> dict:
        """设置 MASQUE 协议的 Endpoint"""
        config_path = config_dir / "config.json"

        if not config_path.exists():
            return {"success": False, "error": "配置文件不存在，请先注册"}

        try:
            # 读取现有配置
            with open(config_path, 'r') as f:
                config = json.load(f)

            # usque 配置文件中 endpoint 只存储 IP 地址（不含端口）
            # 端口由 usque 命令行参数 --connect-port 控制（默认 443）
            if endpoint_v4:
                # 如果用户输入了端口，移除它（只保留 IP）
                if ":" in endpoint_v4 and not endpoint_v4.startswith("["):
                    ip = endpoint_v4.rsplit(":", 1)[0]
                    config["endpoint_v4"] = ip
                else:
                    config["endpoint_v4"] = endpoint_v4

            if endpoint_v6:
                # IPv6 格式处理
                if endpoint_v6.startswith("[") and "]:" in endpoint_v6:
                    # 移除端口
                    ip = endpoint_v6.split("]:")[0].strip("[")
                    config["endpoint_v6"] = ip
                else:
                    config["endpoint_v6"] = endpoint_v6.strip("[]")

            # 原子写入
            write_config_atomic(config_path, config)

            final_v4 = config.get("endpoint_v4")
            final_v6 = config.get("endpoint_v6")
            logger.info(f"[{tag}] MASQUE Endpoint 已更新: v4={final_v4}, v6={final_v6}")

            # 如果代理正在运行，需要重启以应用新 endpoint
            if tag in self.processes and self.processes[tag].status == "running":
                logger.info(f"[{tag}] 重启代理以应用新 Endpoint...")
                asyncio.create_task(self._restart_proxy(tag))

            return {"success": True, "endpoint_v4": final_v4, "endpoint_v6": final_v6}

        except json.JSONDecodeError as e:
            return {"success": False, "error": f"配置文件格式错误: {e}"}

    def _set_endpoint_wireguard(self, tag: str, config_dir: Path,
                                 endpoint_v4: Optional[str], endpoint_v6: Optional[str]) -> dict:
        """保存 = 用设置的 endpoint 重新注册 WARP

        每次保存都会重新注册 WARP 设备，使用用户指定的 endpoint。
        """
        # 1. 格式化 endpoint - WireGuard 需要 IP:port 格式，默认端口 2408
        if endpoint_v4:
            if ":" in endpoint_v4 and not endpoint_v4.startswith("["):
                new_endpoint = endpoint_v4  # 已包含端口
            else:
                new_endpoint = f"{endpoint_v4}:2408"
        elif endpoint_v6:
            if endpoint_v6.startswith("[") and "]:" in endpoint_v6:
                new_endpoint = endpoint_v6  # 已包含端口
            else:
                new_endpoint = f"[{endpoint_v6.strip('[]')}]:2408"
        else:
            return {"success": False, "error": "必须提供 endpoint_v4 或 endpoint_v6"}

        # 2. 获取配置（包括 license key）
        egress = self.db.get_warp_egress(tag)
        license_key = egress.get("license_key") if egress else None

        # 3. 停止旧内核接口
        interface = get_egress_interface_name(tag, egress_type="warp")
        subprocess.run(["ip", "link", "delete", interface], capture_output=True)
        logger.info(f"[{tag}] 已删除旧内核接口 {interface}")

        # 4. 重新注册 WARP（使用自定义 endpoint）
        logger.info(f"[{tag}] 重新注册 WARP WireGuard 设备，使用 endpoint: {new_endpoint}")
        reg_result = self._register_wireguard(tag, license_key, custom_endpoint=new_endpoint)
        if not reg_result.get("success"):
            return {"success": False, "error": f"注册失败: {reg_result.get('error')}"}

        # 5. 更新数据库中的 config_path
        config_path = reg_result.get("config_path", "")
        if config_path:
            self.db.update_warp_egress(tag, config_path=config_path)

        # 6. 创建新内核接口
        egress = self.db.get_warp_egress(tag)
        if not self._start_wireguard_interface(tag, egress):
            return {"success": False, "error": "内核接口创建失败"}

        logger.info(f"[{tag}] WARP WireGuard 设备已重新注册并创建内核接口")
        return {"success": True, "endpoint_v4": endpoint_v4, "endpoint_v6": endpoint_v6}

    def _update_wg_interface_endpoint(self, interface: str, endpoint: str):
        """更新内核 WireGuard 接口的 Endpoint"""
        try:
            # 获取 peer 的 public key
            result = subprocess.run(
                ["wg", "show", interface, "peers"],
                capture_output=True, text=True, timeout=5
            )
            if result.returncode != 0:
                logger.warning(f"无法获取接口 {interface} 的 peer 信息")
                return

            peer_pubkey = result.stdout.strip()
            if not peer_pubkey:
                logger.warning(f"接口 {interface} 没有 peer")
                return

            # 更新 endpoint
            result = subprocess.run(
                ["wg", "set", interface, "peer", peer_pubkey, "endpoint", endpoint],
                capture_output=True, text=True, timeout=5
            )
            if result.returncode == 0:
                logger.info(f"内核接口 {interface} Endpoint 已更新: {endpoint}")
            else:
                logger.warning(f"更新接口 {interface} Endpoint 失败: {result.stderr}")

        except subprocess.TimeoutExpired:
            logger.warning(f"更新接口 {interface} Endpoint 超时")
        except Exception as e:
            logger.warning(f"更新接口 {interface} Endpoint 异常: {e}")

    async def _restart_proxy(self, tag: str):
        """重启代理"""
        await self.stop_proxy(tag)
        await asyncio.sleep(1)
        await self.start_proxy(tag)

    async def start_proxy(self, tag: str) -> bool:
        """启动 WARP 代理（MASQUE 启动 SOCKS，WireGuard 设置内核接口）"""
        egress = self.db.get_warp_egress(tag)
        if not egress:
            logger.error(f"[{tag}] WARP 配置不存在")
            return False

        if not egress.get("enabled"):
            logger.info(f"[{tag}] 已禁用，跳过")
            return False

        protocol = egress.get("protocol", "masque")

        if protocol == "wireguard":
            return self._start_wireguard_interface(tag, egress)

        # MASQUE 协议：启动 SOCKS5 代理
        config_dir = self._get_config_dir(tag)
        config_path = config_dir / "config.json"

        if not config_path.exists():
            logger.error(f"[{tag}] 配置文件不存在: {config_path}")
            return False

        socks_port = egress.get("socks_port", 0)
        if not socks_port:
            logger.error(f"[{tag}] 未分配 SOCKS 端口")
            return False

        logger.info(f"[{tag}] 启动 WARP SOCKS5 代理 (端口: {socks_port})...")

        # 创建运行目录
        WARP_RUN_DIR.mkdir(parents=True, exist_ok=True)

        try:
            # 启动 usque socks
            # 注意: --config 是全局参数，必须放在 socks 子命令之前
            # usque -c <config> socks --bind <addr> --port <port>
            proc = subprocess.Popen(
                [
                    str(USQUE_BIN),
                    "-c", str(config_path),
                    "socks",
                    "--bind", "127.0.0.1",
                    "--port", str(socks_port)
                ],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL
            )

            # 记录进程信息
            process = WarpProcess(
                tag=tag,
                pid=proc.pid,
                socks_port=socks_port,
                config_path=config_path,
                status="running",
                endpoint_v4=egress.get("endpoint_v4"),
                endpoint_v6=egress.get("endpoint_v6"),
                account_type=egress.get("account_type", "free")
            )
            self.processes[tag] = process

            # 写入 PID 文件
            write_pid_file_atomic(self._get_pid_file(tag), proc.pid)

            logger.info(f"[{tag}] WARP 代理已启动 (PID: {proc.pid}, 端口: {socks_port})")
            return True

        except Exception as e:
            logger.error(f"[{tag}] 启动失败: {e}")
            return False

    def _start_wireguard_interface(self, tag: str, egress: dict) -> bool:
        """启动 WireGuard 内核接口"""
        from setup_kernel_wg_egress import (
            get_egress_interface_name,
            create_egress_interface,
            parse_warp_wg_conf
        )

        config_path = egress.get("config_path", "")
        if not config_path or not os.path.exists(config_path):
            logger.error(f"[{tag}] WireGuard 配置文件不存在: {config_path}")
            return False

        # 解析 wg.conf 文件
        wg_config = parse_warp_wg_conf(config_path)
        if not wg_config:
            logger.error(f"[{tag}] 无法解析 WireGuard 配置")
            return False

        interface = get_egress_interface_name(tag, egress_type="warp")
        logger.info(f"[{tag}] 设置 WireGuard 内核接口: {interface}")

        try:
            success = create_egress_interface(
                interface=interface,
                private_key=wg_config.get("private_key"),
                peer_ip=wg_config.get("address"),
                server=wg_config.get("endpoint_host"),
                server_port=wg_config.get("endpoint_port", 2408),
                public_key=wg_config.get("peer_public_key"),
                mtu=1420
            )

            if success:
                logger.info(f"[{tag}] WireGuard 接口已设置: {interface}")
                return True
            else:
                logger.error(f"[{tag}] WireGuard 接口设置失败")
                return False

        except Exception as e:
            logger.error(f"[{tag}] WireGuard 接口设置异常: {e}")
            return False

    async def stop_proxy(self, tag: str) -> bool:
        """停止 WARP SOCKS5 代理"""
        process = self.processes.get(tag)
        pid_file = self._get_pid_file(tag)

        # 尝试从 PID 文件获取 PID
        pid = None
        if process and process.pid:
            pid = process.pid
        elif pid_file.exists():
            try:
                pid = int(pid_file.read_text().strip())
            except (ValueError, IOError):
                pass

        if pid:
            logger.info(f"[{tag}] 停止代理 (PID: {pid})...")
            try:
                os.kill(pid, signal.SIGTERM)
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

        # 清理 PID 文件
        if pid_file.exists():
            try:
                pid_file.unlink()
            except Exception:
                pass

        # 更新状态
        if tag in self.processes:
            self.processes[tag].pid = None
            self.processes[tag].status = "stopped"

        logger.info(f"[{tag}] 代理已停止")
        return True

    async def start_all(self):
        """启动所有启用的 WARP 代理"""
        WARP_BASE_DIR.mkdir(parents=True, exist_ok=True)
        WARP_RUN_DIR.mkdir(parents=True, exist_ok=True)

        egress_list = self.db.get_warp_egress_list(enabled_only=True)
        if not egress_list:
            logger.info("没有启用的 WARP 出口")
            return

        logger.info(f"启动 {len(egress_list)} 个 WARP 代理...")

        for egress in egress_list:
            tag = egress["tag"]
            try:
                await self.start_proxy(tag)
            except Exception as e:
                logger.error(f"[{tag}] 启动失败: {e}")

    async def stop_all(self):
        """停止所有代理"""
        tags = list(self.processes.keys())
        for tag in tags:
            try:
                await self.stop_proxy(tag)
            except Exception as e:
                logger.error(f"[{tag}] 停止失败: {e}")
        self.processes.clear()

    async def reload(self):
        """重载配置（同步数据库状态）"""
        logger.info("重载 WARP 配置...")

        # 获取当前数据库中启用的出口
        enabled_egress = {e["tag"]: e for e in self.db.get_warp_egress_list(enabled_only=True)}
        enabled_tags = set(enabled_egress.keys())

        # 检查哪些进程实际在运行（不仅仅在 dict 中）
        actually_running_tags = set()
        for tag, process in list(self.processes.items()):
            if process.pid:
                try:
                    os.kill(process.pid, 0)
                    actually_running_tags.add(tag)
                except ProcessLookupError:
                    # 进程已死，从 dict 中移除
                    logger.info(f"[{tag}] 进程已退出，清理状态")
                    del self.processes[tag]

        # 停止已删除或禁用的代理
        to_stop = actually_running_tags - enabled_tags
        for tag in to_stop:
            logger.info(f"[{tag}] 配置已删除/禁用，停止代理")
            await self.stop_proxy(tag)
            if tag in self.processes:
                del self.processes[tag]

        # 启动新增或已死亡的代理
        to_start = enabled_tags - actually_running_tags
        for tag in to_start:
            logger.info(f"[{tag}] 需要启动代理")
            await self.start_proxy(tag)

        logger.info("配置重载完成")

    def _check_wg_interface_status(self, interface: str) -> str:
        """检查 WireGuard 内核接口状态

        Returns:
            "running" - 接口存在且有最近的握手
            "connecting" - 接口存在但没有握手
            "stopped" - 接口不存在
        """
        try:
            # 检查接口是否存在
            result = subprocess.run(
                ["wg", "show", interface],
                capture_output=True,
                text=True,
                timeout=5
            )

            if result.returncode != 0:
                return "stopped"

            # 检查是否有最近的握手（2 分钟内）
            output = result.stdout
            if "latest handshake:" in output:
                # 解析握手时间
                for line in output.split("\n"):
                    if "latest handshake:" in line:
                        # 格式: "latest handshake: X seconds ago" 或 "X minutes ago" 等
                        if "second" in line or "minute" in line:
                            return "running"
                        # 如果显示 hour/day，说明太久没有握手
                        return "connecting"

            # 有接口但没有握手
            return "connecting"

        except subprocess.TimeoutExpired:
            return "stopped"
        except Exception as e:
            logger.debug(f"检查接口 {interface} 状态失败: {e}")
            return "stopped"

    def get_status(self, tag: Optional[str] = None) -> Dict[str, Any]:
        """获取代理状态"""
        if tag:
            process = self.processes.get(tag)
            if not process:
                # 检查数据库中是否存在
                egress = self.db.get_warp_egress(tag)
                if egress:
                    protocol = egress.get("protocol", "masque")
                    socks_port = egress.get("socks_port")

                    if protocol == "wireguard":
                        # WireGuard 协议: 检查内核接口状态
                        interface = get_egress_interface_name(tag, egress_type="warp")
                        status = self._check_wg_interface_status(interface)
                    else:
                        # MASQUE 协议: 检查 SOCKS 端口是否在监听
                        status = "stopped"
                        if socks_port:
                            try:
                                import socket
                                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                                sock.settimeout(1)
                                result = sock.connect_ex(("127.0.0.1", socks_port))
                                sock.close()
                                if result == 0:
                                    status = "running"
                            except Exception:
                                pass

                    return {
                        "tag": tag,
                        "status": status,
                        "protocol": protocol,
                        "socks_port": socks_port,
                        "endpoint_v4": egress.get("endpoint_v4"),
                        "account_type": egress.get("account_type", "free")
                    }
                return {"tag": tag, "status": "not_found"}
            return self._process_to_dict(process)
        else:
            result = {}
            # 包含正在运行的
            for tag, proc in self.processes.items():
                result[tag] = self._process_to_dict(proc)
            # 包含已配置但未运行的
            for egress in self.db.get_warp_egress_list(enabled_only=False):
                egress_tag = egress["tag"]
                if egress_tag not in result:
                    protocol = egress.get("protocol", "masque")
                    socks_port = egress.get("socks_port")

                    if protocol == "wireguard":
                        # WireGuard 协议: 检查内核接口状态
                        interface = get_egress_interface_name(egress_tag, egress_type="warp")
                        status = self._check_wg_interface_status(interface)
                    else:
                        # MASQUE 协议: 检查 SOCKS 端口是否在监听
                        status = "stopped"
                        if socks_port:
                            try:
                                import socket
                                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                                sock.settimeout(1)
                                port_result = sock.connect_ex(("127.0.0.1", socks_port))
                                sock.close()
                                if port_result == 0:
                                    status = "running"
                            except Exception:
                                pass

                    result[egress_tag] = {
                        "tag": egress_tag,
                        "status": status,
                        "protocol": protocol,
                        "socks_port": socks_port,
                        "endpoint_v4": egress.get("endpoint_v4"),
                        "account_type": egress.get("account_type", "free"),
                        "enabled": egress.get("enabled", False)
                    }
            return result

    def _process_to_dict(self, process: WarpProcess) -> Dict[str, Any]:
        """转换进程信息为字典"""
        # 检查进程是否存活
        alive = False
        if process.pid:
            try:
                os.kill(process.pid, 0)
                alive = True
            except ProcessLookupError:
                pass

        status = "running" if alive else "stopped"

        return {
            "tag": process.tag,
            "status": status,
            "protocol": "masque",  # 只有 MASQUE 协议使用 usque 进程
            "pid": process.pid if alive else None,
            "socks_port": process.socks_port,
            "config_path": str(process.config_path) if process.config_path else None,
            "endpoint_v4": process.endpoint_v4,
            "endpoint_v6": process.endpoint_v6,
            "account_type": process.account_type
        }

    def delete_config(self, tag: str) -> bool:
        """删除 WARP 配置目录"""
        config_dir = self._get_config_dir(tag)
        if config_dir.exists():
            try:
                shutil.rmtree(config_dir)
                logger.info(f"[{tag}] 配置目录已删除")
                return True
            except Exception as e:
                logger.error(f"[{tag}] 删除配置目录失败: {e}")
                return False
        return True

    async def run_daemon(self):
        """以守护进程模式运行"""
        self._running = True
        self._reload_requested = False
        logger.info("WARP 管理器启动（守护模式）")

        # 清理过期 PID 文件
        cleanup_stale_pid_file(WARP_PID_FILE)

        # 写入 PID 文件
        write_pid_file_atomic(WARP_PID_FILE, os.getpid())
        logger.info(f"PID 文件写入: {WARP_PID_FILE}")

        # 启动所有代理
        await self.start_all()

        # 监控循环
        while self._running:
            await asyncio.sleep(10)

            # 检查是否需要重载
            if self._reload_requested:
                self._reload_requested = False
                logger.info("执行配置重载...")
                await self.reload()

            # 检查进程健康
            for tag, process in list(self.processes.items()):
                if process.status != "running":
                    continue

                if process.pid:
                    try:
                        os.kill(process.pid, 0)
                        # 检查是否为僵尸进程
                        stat_path = f"/proc/{process.pid}/stat"
                        if os.path.exists(stat_path):
                            with open(stat_path, 'r') as f:
                                stat = f.read()
                                # stat 格式: pid (comm) state ...
                                # Z = zombie, X = dead
                                if ') Z' in stat or ') X' in stat:
                                    logger.warning(f"[{tag}] 检测到僵尸进程，尝试重启")
                                    await self.stop_proxy(tag)
                                    await self.start_proxy(tag)
                    except ProcessLookupError:
                        logger.warning(f"[{tag}] 代理进程已退出，尝试重启")
                        await self.stop_proxy(tag)
                        await self.start_proxy(tag)

        # 清理
        await self.stop_all()
        if WARP_PID_FILE.exists():
            WARP_PID_FILE.unlink()
        logger.info("WARP 管理器已停止")

    def request_reload(self):
        """请求重载配置（由 SIGHUP 信号触发）"""
        logger.info("收到重载请求 (SIGHUP)")
        self._reload_requested = True

    def stop_daemon(self):
        """停止守护进程"""
        self._running = False


async def main():
    parser = argparse.ArgumentParser(description='WARP 代理管理器')
    parser.add_argument('command', choices=['start', 'stop', 'reload', 'status', 'daemon', 'register'],
                       help='操作命令')
    parser.add_argument('--tag', help='指定出口标签')
    parser.add_argument('--license', help='WARP+ License Key')
    parser.add_argument('--endpoint-v4', help='自定义 IPv4 Endpoint')
    parser.add_argument('--endpoint-v6', help='自定义 IPv6 Endpoint')
    parser.add_argument('--verbose', '-v', action='store_true', help='详细输出')
    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    manager = WarpManager()

    if args.command == 'register':
        if not args.tag:
            print("错误: 注册需要指定 --tag")
            sys.exit(1)
        result = manager.register(args.tag, args.license)
        print(json.dumps(result, indent=2, ensure_ascii=False))

    elif args.command == 'start':
        if args.tag:
            await manager.start_proxy(args.tag)
        else:
            await manager.start_all()

    elif args.command == 'stop':
        if args.tag:
            await manager.stop_proxy(args.tag)
        else:
            await manager.stop_all()

    elif args.command == 'reload':
        # 优先使用信号通知运行中的守护进程
        if WARP_PID_FILE.exists():
            try:
                daemon_pid = int(WARP_PID_FILE.read_text().strip())
                os.kill(daemon_pid, signal.SIGHUP)
                logger.info(f"已发送 SIGHUP 到守护进程 (PID: {daemon_pid})")
                return
            except (ValueError, ProcessLookupError, PermissionError) as e:
                logger.warning(f"无法通知守护进程: {e}，执行本地重载")
                WARP_PID_FILE.unlink(missing_ok=True)
        await manager.reload()

    elif args.command == 'status':
        status = manager.get_status(args.tag)
        print(json.dumps(status, indent=2, ensure_ascii=False))

    elif args.command == 'daemon':
        # 检查是否已有守护进程运行
        if WARP_PID_FILE.exists():
            try:
                existing_pid = int(WARP_PID_FILE.read_text().strip())
                os.kill(existing_pid, 0)
                # 验证进程确实是 warp_manager（防止 PID 重用导致误判）
                cmdline_path = Path(f"/proc/{existing_pid}/cmdline")
                if cmdline_path.exists():
                    cmdline = cmdline_path.read_text()
                    if "warp_manager" in cmdline:
                        logger.error(f"守护进程已在运行 (PID: {existing_pid})")
                        sys.exit(1)
                    else:
                        # PID 被其他进程重用，清理旧 PID 文件
                        logger.warning(f"PID {existing_pid} 已被其他进程重用，清理旧 PID 文件")
                        WARP_PID_FILE.unlink(missing_ok=True)
                else:
                    WARP_PID_FILE.unlink(missing_ok=True)
            except (ValueError, ProcessLookupError):
                WARP_PID_FILE.unlink(missing_ok=True)

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

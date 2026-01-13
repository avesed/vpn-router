#!/usr/bin/env python3
"""
V2Ray/Xray API Stats Client - 通过 gRPC 查询 xray-lite 的精确流量统计

统计名称格式:
- outbound>>>TAG>>>traffic>>>downlink (下载字节数)
- outbound>>>TAG>>>traffic>>>uplink (上传字节数)
- user>>>EMAIL>>>traffic>>>downlink (用户下载字节数)
- user>>>EMAIL>>>traffic>>>uplink (用户上传字节数)

支持的 API:
- GetStats: 获取单个统计值
- GetStatsOnline: 获取在线会话统计
- QueryStats: 批量查询统计
- GetSysStats: 获取系统统计
- GetStatsOnlineIpList: 获取在线用户 IP 列表
"""

import logging
from typing import Dict, Optional

import grpc

import v2ray_stats_pb2
import v2ray_stats_pb2_grpc

# 配置 logger
logger = logging.getLogger(__name__)

# Xray API 默认地址 (xray-lite 使用 xray.app.stats.command 命名空间)
XRAY_API_ADDR = "127.0.0.1:10085"


class V2RayStatsClient:
    """V2Ray/Xray Stats API 客户端
    
    支持连接到 xray-lite 或 sing-box 的 V2Ray API 端点。
    使用 xray.app.stats.command gRPC 服务。
    """

    def __init__(self, addr: str = XRAY_API_ADDR):
        """初始化客户端
        
        Args:
            addr: gRPC 服务地址，格式为 "host:port"
        """
        self.addr = addr
        self._channel: Optional[grpc.Channel] = None
        self._stub: Optional[v2ray_stats_pb2_grpc.StatsServiceStub] = None

    def _ensure_connected(self) -> bool:
        """确保 gRPC 连接已建立
        
        Returns:
            连接是否成功
        """
        if self._channel is None:
            try:
                self._channel = grpc.insecure_channel(self.addr)
                self._stub = v2ray_stats_pb2_grpc.StatsServiceStub(self._channel)
                return True
            except Exception as e:
                logger.warning(f"Failed to connect to {self.addr}: {e}")
                return False
        return True

    def close(self):
        """关闭连接"""
        if self._channel:
            try:
                self._channel.close()
            except Exception as e:
                logger.debug(f"Error closing channel: {e}")
            finally:
                self._channel = None
                self._stub = None

    def get_stat(self, name: str, reset: bool = False) -> int:
        """获取单个统计值

        Args:
            name: 统计名称，如 "outbound>>>direct>>>traffic>>>downlink"
            reset: 是否在读取后重置计数器

        Returns:
            统计值（字节数），失败返回 0
        """
        if not self._ensure_connected():
            return 0
        try:
            request = v2ray_stats_pb2.GetStatsRequest(name=name, reset=reset)
            response = self._stub.GetStats(request, timeout=3)
            return response.stat.value if response.stat else 0
        except grpc.RpcError as e:
            logger.debug(f"GetStats RPC failed for '{name}': {e.code()} - {e.details()}")
            return 0
        except Exception as e:
            logger.warning(f"GetStats unexpected error: {e}")
            return 0

    def get_stat_online(self, name: str, reset: bool = False) -> int:
        """获取在线会话统计值

        Args:
            name: 统计名称，如 "user>>>email@example.com>>>online"
            reset: 是否在读取后重置计数器

        Returns:
            在线会话数，失败返回 0
        """
        if not self._ensure_connected():
            return 0
        try:
            request = v2ray_stats_pb2.GetStatsRequest(name=name, reset=reset)
            response = self._stub.GetStatsOnline(request, timeout=3)
            return response.stat.value if response.stat else 0
        except grpc.RpcError as e:
            logger.debug(f"GetStatsOnline RPC failed for '{name}': {e.code()} - {e.details()}")
            return 0
        except Exception as e:
            logger.warning(f"GetStatsOnline unexpected error: {e}")
            return 0

    def query_stats(self, pattern: str = "", reset: bool = False) -> Dict[str, int]:
        """查询匹配模式的所有统计

        Args:
            pattern: 匹配模式（使用 >>> 分隔），留空返回所有统计
            reset: 是否在读取后重置计数器

        Returns:
            {统计名称: 值} 的字典
        """
        if not self._ensure_connected():
            return {}
        try:
            request = v2ray_stats_pb2.QueryStatsRequest(
                pattern=pattern,
                reset=reset
            )
            response = self._stub.QueryStats(request, timeout=5)
            return {stat.name: stat.value for stat in response.stat}
        except grpc.RpcError as e:
            logger.debug(f"QueryStats RPC failed for pattern '{pattern}': {e.code()} - {e.details()}")
            return {}
        except Exception as e:
            logger.warning(f"QueryStats unexpected error: {e}")
            return {}

    def get_online_ip_list(self, name: str) -> Dict[str, int]:
        """获取在线用户的 IP 列表

        Args:
            name: 用户统计名称，如 "user>>>email@example.com"

        Returns:
            {IP地址: 连接数} 的字典
        """
        if not self._ensure_connected():
            return {}
        try:
            request = v2ray_stats_pb2.GetStatsRequest(name=name, reset=False)
            response = self._stub.GetStatsOnlineIpList(request, timeout=3)
            return dict(response.ips) if response.ips else {}
        except grpc.RpcError as e:
            logger.debug(f"GetStatsOnlineIpList RPC failed for '{name}': {e.code()} - {e.details()}")
            return {}
        except Exception as e:
            logger.warning(f"GetStatsOnlineIpList unexpected error: {e}")
            return {}

    def get_outbound_stats(self, reset: bool = False) -> Dict[str, Dict[str, int]]:
        """获取所有出口的流量统计

        Args:
            reset: 是否在读取后重置计数器

        Returns:
            {出口名称: {"download": bytes, "upload": bytes}}
        """
        # 查询所有 outbound 统计
        all_stats = self.query_stats("outbound>>>", reset=reset)

        # 解析统计结果
        result: Dict[str, Dict[str, int]] = {}
        for name, value in all_stats.items():
            # 格式: outbound>>>TAG>>>traffic>>>downlink/uplink
            parts = name.split(">>>")
            if len(parts) >= 4 and parts[0] == "outbound" and parts[2] == "traffic":
                tag = parts[1]
                direction = parts[3]

                if tag not in result:
                    result[tag] = {"download": 0, "upload": 0}

                if direction == "downlink":
                    result[tag]["download"] = value
                elif direction == "uplink":
                    result[tag]["upload"] = value

        return result

    def get_user_stats(self, reset: bool = False) -> Dict[str, Dict[str, int]]:
        """获取所有用户的流量统计

        Args:
            reset: 是否在读取后重置计数器

        Returns:
            {用户email: {"download": bytes, "upload": bytes}}
        """
        # 查询所有 user 统计
        all_stats = self.query_stats("user>>>", reset=reset)

        # 解析统计结果
        result: Dict[str, Dict[str, int]] = {}
        for name, value in all_stats.items():
            # 格式: user>>>EMAIL>>>traffic>>>downlink/uplink
            parts = name.split(">>>")
            if len(parts) >= 4 and parts[0] == "user" and parts[2] == "traffic":
                email = parts[1]
                direction = parts[3]

                if email not in result:
                    result[email] = {"download": 0, "upload": 0}

                if direction == "downlink":
                    result[email]["download"] = value
                elif direction == "uplink":
                    result[email]["upload"] = value

        return result

    def get_user_online_stats(self) -> Dict[str, int]:
        """获取所有用户的在线会话数

        Returns:
            {用户email: 在线会话数}
        """
        # 查询所有 user online 统计
        all_stats = self.query_stats("user>>>", reset=False)

        # 解析统计结果
        result: Dict[str, int] = {}
        for name, value in all_stats.items():
            # 格式: user>>>EMAIL>>>online>>>count (或类似)
            parts = name.split(">>>")
            if len(parts) >= 3 and parts[0] == "user":
                email = parts[1]
                # 检查是否是 online 相关统计
                if "online" in name.lower():
                    result[email] = value

        return result

    def get_sys_stats(self) -> Dict[str, int]:
        """获取系统统计信息

        Returns:
            系统统计字典，包含:
            - num_goroutine: goroutine 数量
            - num_gc: GC 次数
            - alloc: 当前分配内存
            - total_alloc: 总分配内存
            - sys: 系统内存
            - mallocs: malloc 次数
            - frees: free 次数
            - live_objects: 存活对象数
            - pause_total_ns: GC 暂停总时间
            - uptime: 运行时间（秒）
        """
        if not self._ensure_connected():
            return {}
        try:
            request = v2ray_stats_pb2.SysStatsRequest()
            response = self._stub.GetSysStats(request, timeout=3)
            return {
                "num_goroutine": response.NumGoroutine,
                "num_gc": response.NumGC,
                "alloc": response.Alloc,
                "total_alloc": response.TotalAlloc,
                "sys": response.Sys,
                "mallocs": response.Mallocs,
                "frees": response.Frees,
                "live_objects": response.LiveObjects,
                "pause_total_ns": response.PauseTotalNs,
                "uptime": response.Uptime
            }
        except grpc.RpcError as e:
            logger.debug(f"GetSysStats RPC failed: {e.code()} - {e.details()}")
            return {}
        except Exception as e:
            logger.warning(f"GetSysStats unexpected error: {e}")
            return {}

    def is_connected(self) -> bool:
        """检查是否可以连接到 API 服务
        
        Returns:
            True 如果可以成功调用 API，否则 False
        """
        try:
            # 尝试获取系统统计来验证连接
            stats = self.get_sys_stats()
            return len(stats) > 0
        except Exception:
            return False


# 全局客户端实例（懒加载）
_client: Optional[V2RayStatsClient] = None


def get_client() -> V2RayStatsClient:
    """获取全局客户端实例"""
    global _client
    if _client is None:
        _client = V2RayStatsClient()
    return _client


def get_outbound_traffic() -> Dict[str, Dict[str, int]]:
    """
    获取所有出口的流量统计（便捷函数）

    Returns:
        {出口名称: {"download": bytes, "upload": bytes}}
    """
    return get_client().get_outbound_stats()


def get_sys_stats() -> Dict[str, int]:
    """获取系统统计（便捷函数）"""
    return get_client().get_sys_stats()


# 测试代码
if __name__ == "__main__":
    import sys
    
    # 配置日志
    logging.basicConfig(
        level=logging.DEBUG,
        format='%(asctime)s %(levelname)s: %(message)s'
    )
    
    # 支持指定地址
    addr = sys.argv[1] if len(sys.argv) > 1 else XRAY_API_ADDR
    print(f"测试 Xray Stats API @ {addr}...")

    client = V2RayStatsClient(addr)

    print("\n=== 连接测试 ===")
    if client.is_connected():
        print("  连接成功!")
    else:
        print("  无法连接到 API 服务")
        sys.exit(1)

    print("\n=== 出口流量统计 ===")
    traffic = client.get_outbound_stats()
    if traffic:
        for tag, stats in sorted(traffic.items()):
            dl_mb = stats["download"] / 1024 / 1024
            ul_mb = stats["upload"] / 1024 / 1024
            print(f"  {tag}: 下载 {dl_mb:.2f} MB, 上传 {ul_mb:.2f} MB")
    else:
        print("  无出口流量数据")

    print("\n=== 用户流量统计 ===")
    user_traffic = client.get_user_stats()
    if user_traffic:
        for email, stats in sorted(user_traffic.items()):
            dl_mb = stats["download"] / 1024 / 1024
            ul_mb = stats["upload"] / 1024 / 1024
            print(f"  {email}: 下载 {dl_mb:.2f} MB, 上传 {ul_mb:.2f} MB")
    else:
        print("  无用户流量数据")

    print("\n=== 系统统计 ===")
    sys_stats = client.get_sys_stats()
    if sys_stats:
        print(f"  Goroutines: {sys_stats.get('num_goroutine', 0)}")
        print(f"  内存分配: {sys_stats.get('alloc', 0) / 1024 / 1024:.2f} MB")
        print(f"  运行时间: {sys_stats.get('uptime', 0)} 秒")
    else:
        print("  无系统统计数据")

    client.close()
    print("\n测试完成")

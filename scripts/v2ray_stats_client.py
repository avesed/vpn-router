#!/usr/bin/env python3
"""
V2Ray API Stats Client - 通过 gRPC 查询 sing-box 的精确流量统计

统计名称格式:
- outbound>>>TAG>>>traffic>>>downlink (下载字节数)
- outbound>>>TAG>>>traffic>>>uplink (上传字节数)
"""

import grpc
from typing import Dict, Tuple, Optional
import v2ray_stats_pb2
import v2ray_stats_pb2_grpc

# V2Ray API 默认地址
V2RAY_API_ADDR = "127.0.0.1:10085"


class V2RayStatsClient:
    """V2Ray Stats API 客户端"""

    def __init__(self, addr: str = V2RAY_API_ADDR):
        self.addr = addr
        self._channel: Optional[grpc.Channel] = None
        self._stub: Optional[v2ray_stats_pb2_grpc.StatsServiceStub] = None

    def _ensure_connected(self):
        """确保 gRPC 连接已建立"""
        if self._channel is None:
            self._channel = grpc.insecure_channel(self.addr)
            self._stub = v2ray_stats_pb2_grpc.StatsServiceStub(self._channel)

    def close(self):
        """关闭连接"""
        if self._channel:
            self._channel.close()
            self._channel = None
            self._stub = None

    def get_stat(self, name: str, reset: bool = False) -> int:
        """
        获取单个统计值

        Args:
            name: 统计名称，如 "outbound>>>direct>>>traffic>>>downlink"
            reset: 是否在读取后重置计数器

        Returns:
            统计值（字节数）
        """
        self._ensure_connected()
        try:
            request = v2ray_stats_pb2.GetStatsRequest(name=name, reset=reset)
            response = self._stub.GetStats(request)
            return response.stat.value if response.stat else 0
        except grpc.RpcError:
            return 0

    def query_stats(self, pattern: str = "", reset: bool = False) -> Dict[str, int]:
        """
        查询匹配模式的所有统计

        Args:
            pattern: 匹配模式（使用 >>> 分隔），留空返回所有统计
            reset: 是否在读取后重置计数器

        Returns:
            {统计名称: 值} 的字典
        """
        self._ensure_connected()
        try:
            request = v2ray_stats_pb2.QueryStatsRequest(
                patterns=[pattern] if pattern else [],
                reset=reset
            )
            response = self._stub.QueryStats(request)
            return {stat.name: stat.value for stat in response.stat}
        except grpc.RpcError:
            return {}

    def get_outbound_stats(self, reset: bool = False) -> Dict[str, Dict[str, int]]:
        """
        获取所有出口的流量统计

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
        """
        获取所有用户的流量统计

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

    def get_sys_stats(self) -> Dict[str, int]:
        """
        获取系统统计信息

        Returns:
            系统统计字典
        """
        self._ensure_connected()
        try:
            request = v2ray_stats_pb2.SysStatsRequest()
            response = self._stub.GetSysStats(request)
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
        except grpc.RpcError:
            return {}


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
    print("测试 V2Ray Stats API...")

    client = V2RayStatsClient()

    print("\n=== 出口流量统计 ===")
    traffic = client.get_outbound_stats()
    for tag, stats in sorted(traffic.items()):
        dl_mb = stats["download"] / 1024 / 1024
        ul_mb = stats["upload"] / 1024 / 1024
        print(f"  {tag}: 下载 {dl_mb:.2f} MB, 上传 {ul_mb:.2f} MB")

    print("\n=== 系统统计 ===")
    sys_stats = client.get_sys_stats()
    for key, value in sys_stats.items():
        print(f"  {key}: {value}")

    client.close()

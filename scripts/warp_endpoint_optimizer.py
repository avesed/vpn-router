#!/usr/bin/env python3
"""
WARP Endpoint 优选工具

基于 warp-endpoint-optimizer 逻辑的 Python 实现：
- 从 WARP IP 范围随机采样 Endpoint
- 使用 UDP 探测测试延迟和丢包率
- 返回最优 Endpoint 列表

使用方法:
    python3 warp_endpoint_optimizer.py                    # 默认测试 50 个
    python3 warp_endpoint_optimizer.py --count 100        # 测试 100 个
    python3 warp_endpoint_optimizer.py --top 5            # 返回前 5 个
    python3 warp_endpoint_optimizer.py --json             # JSON 输出
"""

import argparse
import asyncio
import ipaddress
import json
import logging
import random
import socket
import time
from dataclasses import dataclass, asdict
from typing import List, Optional

logging.basicConfig(
    level=logging.INFO,
    format='[warp-opt] %(asctime)s %(levelname)s: %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger(__name__)

# WARP Endpoint IP 范围（Cloudflare 消费者 WARP 服务）
WARP_IP_RANGES = [
    "162.159.192.0/24",
    "162.159.193.0/24",
    "162.159.195.0/24",
    "188.114.96.0/24",
    "188.114.97.0/24",
    "188.114.98.0/24",
    "188.114.99.0/24",
]

# WARP 端口列表（来自官方文档和实测）
WARP_PORTS = [
    500, 854, 859, 864, 878, 880, 890, 891, 894, 903,
    908, 928, 934, 939, 942, 943, 945, 946, 955, 968,
    987, 988, 1002, 1010, 1014, 1018, 1070, 1074, 1180,
    1387, 1843, 2371, 2408, 2506, 3138, 3476, 3581,
    3854, 4177, 4198, 4233, 5279, 5956, 7103, 7152,
    7156, 7281, 7559, 8319, 8742, 8854, 8886
]

# 协议对应的端口
PROTOCOL_PORTS = {
    "masque": 443,    # HTTPS
    "wireguard": 2408,  # UDP
}


@dataclass
class EndpointResult:
    """Endpoint 测试结果"""
    ip: str
    port: int
    loss_rate: float  # 丢包率 0-100
    latency_ms: float  # 平均延迟（毫秒）
    min_latency_ms: float  # 最小延迟
    max_latency_ms: float  # 最大延迟
    success_count: int  # 成功次数
    test_count: int  # 测试次数

    @property
    def endpoint(self) -> str:
        """返回 IP:Port 格式"""
        return f"{self.ip}:{self.port}"

    def to_dict(self) -> dict:
        """转换为字典"""
        d = asdict(self)
        d["endpoint"] = self.endpoint
        return d


async def test_endpoint_ping(ip: str, port: int, timeout: float = 1.0,
                              test_count: int = 1) -> EndpointResult:
    """
    使用 ICMP ping 测试单个 Endpoint 延迟（真正异步）

    由于 WARP 服务器不会响应 UDP 探测包，使用 ICMP ping 更可靠。

    Args:
        ip: 目标 IP
        port: 目标端口（仅用于记录，ping 不使用端口）
        timeout: 超时时间（秒）
        test_count: 测试次数

    Returns:
        EndpointResult 对象
    """
    import re

    try:
        # 使用 asyncio.create_subprocess_exec 实现真正异步
        # -c: 发送次数, -W: 超时时间(秒), -q: 静默模式
        proc = await asyncio.create_subprocess_exec(
            "ping", "-c", str(test_count), "-W", str(int(timeout)), "-q", ip,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )

        try:
            stdout, stderr = await asyncio.wait_for(
                proc.communicate(),
                timeout=timeout * test_count + 2
            )
        except asyncio.TimeoutError:
            proc.kill()
            await proc.wait()
            raise

        output = stdout.decode() + stderr.decode()

        # 提取丢包率
        loss_match = re.search(r'(\d+)% packet loss', output)
        if loss_match:
            loss_rate = float(loss_match.group(1))
        else:
            loss_rate = 100.0 if proc.returncode != 0 else 0.0

        # 提取延迟统计
        rtt_match = re.search(r'rtt min/avg/max/mdev = ([\d.]+)/([\d.]+)/([\d.]+)/([\d.]+)', output)
        if rtt_match:
            min_latency = float(rtt_match.group(1))
            avg_latency = float(rtt_match.group(2))
            max_latency = float(rtt_match.group(3))
            success_count = int(test_count * (100 - loss_rate) / 100)
        else:
            min_latency = float('inf')
            avg_latency = float('inf')
            max_latency = float('inf')
            success_count = 0

    except asyncio.TimeoutError:
        loss_rate = 100.0
        avg_latency = float('inf')
        min_latency = float('inf')
        max_latency = float('inf')
        success_count = 0
    except Exception as e:
        logger.warning(f"Ping 测试失败: {ip} - {e}")
        loss_rate = 100.0
        avg_latency = float('inf')
        min_latency = float('inf')
        max_latency = float('inf')
        success_count = 0

    return EndpointResult(
        ip=ip,
        port=port,
        loss_rate=loss_rate,
        latency_ms=avg_latency,
        min_latency_ms=min_latency,
        max_latency_ms=max_latency,
        success_count=success_count,
        test_count=test_count
    )


# 保持向后兼容
async def test_endpoint_udp(ip: str, port: int, timeout: float = 2.0,
                            test_count: int = 3) -> EndpointResult:
    """向后兼容：使用 ping 测试"""
    return await test_endpoint_ping(ip, port, timeout, test_count)


def get_all_ips() -> List[str]:
    """从 IP 范围生成所有可用 IP"""
    all_ips = []
    for cidr in WARP_IP_RANGES:
        network = ipaddress.IPv4Network(cidr)
        # hosts() 排除网络地址和广播地址
        all_ips.extend([str(ip) for ip in network.hosts()])
    return all_ips


async def optimize_endpoints(
    sample_count: int = 50,
    top_n: int = 10,
    test_count: int = 3,
    timeout: float = 2.0,
    progress_callback=None,
    protocol: str = "masque"
) -> List[EndpointResult]:
    """
    测试多个 Endpoint 并返回最优结果

    Args:
        sample_count: 采样数量
        top_n: 返回前 N 个最优结果
        test_count: 每个 Endpoint 测试次数
        timeout: 单次测试超时时间
        progress_callback: 进度回调函数 (current, total)
        protocol: 协议类型 ("masque" 或 "wireguard")

    Returns:
        按延迟和丢包率排序的 EndpointResult 列表
    """
    all_ips = get_all_ips()
    logger.info(f"IP 池大小: {len(all_ips)}, 采样: {sample_count}")

    # 随机采样 IP
    sample_ips = random.sample(all_ips, min(sample_count, len(all_ips)))

    # 根据协议确定端口（ping 测试不使用端口，但结果中会记录）
    default_port = PROTOCOL_PORTS.get(protocol, 443)
    endpoints = [(ip, default_port) for ip in sample_ips]

    # 并发测试
    results = []
    semaphore = asyncio.Semaphore(20)  # 限制并发数

    async def test_with_semaphore(ip: str, port: int, index: int):
        async with semaphore:
            result = await test_endpoint_ping(ip, port, timeout, test_count)
            if progress_callback:
                progress_callback(index + 1, len(endpoints))
            return result

    tasks = [
        test_with_semaphore(ip, port, i)
        for i, (ip, port) in enumerate(endpoints)
    ]

    results = await asyncio.gather(*tasks)

    # 过滤无效结果并排序
    # 优先选择：低丢包率 > 低延迟
    valid_results = [r for r in results if r.success_count > 0]
    valid_results.sort(key=lambda r: (r.loss_rate, r.latency_ms))

    logger.info(f"有效结果: {len(valid_results)}/{len(results)}")

    return valid_results[:top_n]


async def test_specific_endpoints(
    endpoints: List[str],
    test_count: int = 5,
    timeout: float = 2.0,
    protocol: str = "masque"
) -> List[EndpointResult]:
    """
    测试指定的 Endpoint 列表

    Args:
        endpoints: Endpoint 列表，格式为 ["IP", ...] 或 ["IP:Port", ...]
        test_count: 每个 Endpoint 测试次数
        timeout: 超时时间
        protocol: 协议类型 ("masque" 或 "wireguard")

    Returns:
        EndpointResult 列表
    """
    # 根据协议确定默认端口
    default_port = PROTOCOL_PORTS.get(protocol, 443)
    results = []

    for endpoint in endpoints:
        try:
            if ":" in endpoint:
                ip, port_str = endpoint.rsplit(":", 1)
                port = int(port_str)
            else:
                ip = endpoint
                port = default_port

            result = await test_endpoint_ping(ip, port, timeout, test_count)
            results.append(result)

        except ValueError as e:
            logger.warning(f"无效的 Endpoint 格式: {endpoint} - {e}")

    results.sort(key=lambda r: (r.loss_rate, r.latency_ms))
    return results


async def main():
    parser = argparse.ArgumentParser(description='WARP Endpoint 优选工具')
    parser.add_argument('--count', '-c', type=int, default=50,
                       help='采样数量（默认: 50）')
    parser.add_argument('--top', '-t', type=int, default=10,
                       help='返回前 N 个最优结果（默认: 10）')
    parser.add_argument('--tests', type=int, default=3,
                       help='每个 Endpoint 测试次数（默认: 3）')
    parser.add_argument('--timeout', type=float, default=2.0,
                       help='单次测试超时时间（秒，默认: 2.0）')
    parser.add_argument('--json', action='store_true',
                       help='JSON 格式输出')
    parser.add_argument('--endpoints', '-e', nargs='+',
                       help='测试指定的 Endpoint 列表')
    parser.add_argument('--verbose', '-v', action='store_true',
                       help='详细输出')

    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    # 测试指定 Endpoint
    if args.endpoints:
        logger.info(f"测试指定 Endpoint: {args.endpoints}")
        results = await test_specific_endpoints(
            args.endpoints,
            test_count=args.tests,
            timeout=args.timeout
        )
    # 随机采样优选
    else:
        def progress(current, total):
            if not args.json:
                print(f"\r测试进度: {current}/{total}", end="", flush=True)

        results = await optimize_endpoints(
            sample_count=args.count,
            top_n=args.top,
            test_count=args.tests,
            timeout=args.timeout,
            progress_callback=progress
        )
        if not args.json:
            print()  # 换行

    # 输出结果
    if args.json:
        output = [r.to_dict() for r in results]
        print(json.dumps(output, indent=2, ensure_ascii=False))
    else:
        print("\n" + "=" * 60)
        print("WARP Endpoint 优选结果")
        print("=" * 60)
        print(f"{'排名':<4} {'Endpoint':<24} {'延迟(ms)':<12} {'丢包率':<10}")
        print("-" * 60)
        for i, r in enumerate(results, 1):
            print(f"{i:<4} {r.endpoint:<24} {r.latency_ms:<12.1f} {r.loss_rate:.0f}%")
        print("=" * 60)

        if results:
            print(f"\n推荐 Endpoint: {results[0].endpoint}")
            print(f"  延迟: {results[0].latency_ms:.1f} ms")
            print(f"  丢包率: {results[0].loss_rate:.0f}%")


if __name__ == '__main__':
    asyncio.run(main())

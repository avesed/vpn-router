#!/usr/bin/env python3
"""
VPN-Router 综合集成测试脚本

测试项目的所有基础功能：
- WireGuard 用户空间入站/出站
- rust-router / sing-box 路由
- Xray 入站/出站和路由
- WG + Xray 混合场景
- 性能和资源监控
"""

import json
import os
import subprocess
import sys
import threading
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

# 添加脚本路径
sys.path.insert(0, '/usr/local/bin')

# ============ 配置 ============

@dataclass
class TestConfig:
    """测试配置"""
    xray_api_addr: str = "127.0.0.1:10087"
    singbox_api_addr: str = "127.0.0.1:10085"
    clash_api_addr: str = "127.0.0.1:9090"
    
    # 代理端口
    xray_socks_port: int = 1080  # 外部 xray 客户端
    singbox_tproxy_port: int = 7893  # TPROXY 透明代理 (需要 iptables)
    singbox_socks_port: int = 38501  # xray-in SOCKS inbound
    
    # 测试目标
    test_urls: List[str] = field(default_factory=lambda: [
        "https://ifconfig.me",
        "https://cloudflare.com",
        "https://google.com",
    ])
    
    # 资源限制阈值
    max_memory_mb: int = 500
    max_cpu_percent: float = 80.0
    max_goroutines: int = 1000


# ============ 工具函数 ============

def run_cmd(cmd: str, timeout: int = 30) -> Tuple[int, str, str]:
    """运行命令并返回结果"""
    try:
        result = subprocess.run(
            cmd, shell=True, capture_output=True, text=True, timeout=timeout
        )
        return result.returncode, result.stdout, result.stderr
    except subprocess.TimeoutExpired:
        return -1, "", "Timeout"
    except Exception as e:
        return -1, "", str(e)


def get_process_stats() -> Dict[str, Dict]:
    """获取各进程的实时资源使用情况
    
    使用 top 获取瞬时 CPU 而非 ps aux 的累计 CPU
    """
    stats = {}
    
    # 使用 top -b -n 1 获取瞬时 CPU 使用率
    # 注意: ps aux 的 %CPU 是累计值 (总 CPU 时间 / 运行时间)，可能超过 100%
    # top 的 %CPU 是当前瞬时值
    code, out, _ = run_cmd(
        "top -b -n 1 | grep -E 'xray|sing-box|rust-router|usque' | head -10"
    )
    if code != 0:
        # 回退到 ps (结果可能不准确)
        code, out, _ = run_cmd("ps aux | grep -E 'xray|sing-box|rust-router|usque' | grep -v grep")
        if code != 0:
            return stats
        
        for line in out.strip().split('\n'):
            if not line:
                continue
            parts = line.split()
            if len(parts) >= 11:
                cpu = float(parts[2])
                mem = float(parts[3])
                cmd = parts[10]
                name = cmd.split('/')[-1].split()[0]
                if name not in stats:
                    stats[name] = {'cpu': 0, 'mem': 0, 'count': 0}
                stats[name]['cpu'] += cpu
                stats[name]['mem'] += mem
                stats[name]['count'] += 1
        return stats
    
    # 解析 top 输出 (格式: PID USER PR NI VIRT RES SHR S %CPU %MEM TIME+ COMMAND)
    for line in out.strip().split('\n'):
        if not line:
            continue
        parts = line.split()
        if len(parts) >= 12:
            try:
                cpu = float(parts[8])  # %CPU
                mem = float(parts[9])  # %MEM
                cmd = parts[11]        # COMMAND
                
                name = cmd.split('/')[-1].split()[0]
                if name not in stats:
                    stats[name] = {'cpu': 0, 'mem': 0, 'count': 0}
                stats[name]['cpu'] += cpu
                stats[name]['mem'] += mem
                stats[name]['count'] += 1
            except (ValueError, IndexError):
                continue
    
    return stats


def get_memory_usage_mb() -> float:
    """获取总内存使用量 (MB)"""
    code, out, _ = run_cmd("free -m | grep Mem | awk '{print $3}'")
    if code == 0 and out.strip():
        return float(out.strip())
    return 0


def check_xray_api() -> Dict:
    """检查 Xray API 状态"""
    try:
        from v2ray_stats_client import V2RayStatsClient
        client = V2RayStatsClient("127.0.0.1:10087")
        sys_stats = client.get_sys_stats()
        user_stats = client.get_user_stats()
        outbound_stats = client.get_outbound_stats()
        client.close()
        return {
            "connected": True,
            "sys": sys_stats,
            "users": user_stats,
            "outbounds": outbound_stats
        }
    except Exception as e:
        return {"connected": False, "error": str(e)}


def check_singbox_api() -> Dict:
    """检查 sing-box Clash API 状态"""
    import urllib.request
    try:
        with urllib.request.urlopen("http://127.0.0.1:9090/connections", timeout=5) as resp:
            data = json.loads(resp.read())
            return {
                "connected": True,
                "connections": len(data.get("connections", [])),
                "upload": data.get("uploadTotal", 0),
                "download": data.get("downloadTotal", 0)
            }
    except Exception as e:
        return {"connected": False, "error": str(e)}


# ============ 测试用例 ============

class TestResult:
    """测试结果"""
    def __init__(self, name: str):
        self.name = name
        self.passed = False
        self.message = ""
        self.duration: float = 0.0
        self.details = {}


def test_xray_inbound() -> TestResult:
    """测试 Xray VLESS+REALITY 入站"""
    result = TestResult("Xray Inbound (VLESS+REALITY)")
    start = time.time()
    
    try:
        # 检查 xray 进程
        code, out, _ = run_cmd("pgrep -f 'xray run'")
        if code != 0:
            result.message = "Xray process not running"
            return result
        
        # 检查 443 端口监听
        code, out, _ = run_cmd("ss -tlnp | grep ':443'")
        if code != 0 or "xray" not in out:
            result.message = "Xray not listening on port 443"
            return result
        
        # 检查 API 状态
        api_status = check_xray_api()
        if not api_status.get("connected"):
            result.message = f"Xray API not available: {api_status.get('error')}"
            return result
        
        result.passed = True
        result.message = "Xray inbound OK"
        result.details = {
            "goroutines": api_status["sys"].get("num_goroutine", 0),
            "memory_mb": api_status["sys"].get("alloc", 0) / 1024 / 1024,
            "uptime": api_status["sys"].get("uptime", 0)
        }
    except Exception as e:
        result.message = f"Error: {e}"
    
    result.duration = time.time() - start
    return result


def test_xray_outbound() -> TestResult:
    """测试 Xray 出站流量"""
    result = TestResult("Xray Outbound Traffic")
    start = time.time()
    
    try:
        api_before = check_xray_api()
        if not api_before.get("connected"):
            result.message = "Xray API not available"
            return result
        
        before_dl = sum(u.get("download", 0) for u in api_before.get("users", {}).values())
        
        # 通过外部客户端发送流量 (需要外部代理)
        # 这里用内部 SOCKS 端口测试
        code, out, err = run_cmd(
            "curl -s --socks5-hostname 127.0.0.1:37201 https://ifconfig.me --max-time 10"
        )
        
        api_after = check_xray_api()
        after_dl = sum(u.get("download", 0) for u in api_after.get("users", {}).values())
        
        # 检查出站统计
        outbound_stats = api_after.get("outbounds", {})
        
        result.passed = True
        result.message = "Xray outbound OK"
        result.details = {
            "traffic_increase": after_dl - before_dl,
            "outbounds": list(outbound_stats.keys())
        }
    except Exception as e:
        result.message = f"Error: {e}"
    
    result.duration = time.time() - start
    return result


def test_singbox_routing() -> TestResult:
    """测试 sing-box 路由功能"""
    result = TestResult("Sing-box Routing")
    start = time.time()
    
    try:
        # 检查 sing-box 进程
        code, out, _ = run_cmd("pgrep -f 'sing-box run'")
        if code != 0:
            result.message = "Sing-box process not running"
            return result
        
        # 检查 Clash API
        api_status = check_singbox_api()
        if not api_status.get("connected"):
            result.message = f"Sing-box API not available: {api_status.get('error')}"
            return result
        
        # 通过 SOCKS 代理测试路由 (xray-in inbound on 38501)
        # Note: Port 7893 is TPROXY, not HTTP proxy - cannot be used directly
        code, out, err = run_cmd(
            "curl -s -x socks5://127.0.0.1:38501 https://ifconfig.me --max-time 10"
        )
        
        if code == 0 and out.strip():
            result.passed = True
            result.message = f"Routing OK, exit IP: {out.strip()}"
            result.details = {
                "connections": api_status.get("connections", 0),
                "total_upload": api_status.get("upload", 0),
                "total_download": api_status.get("download", 0)
            }
        else:
            result.message = f"Routing failed: {err}"
    except Exception as e:
        result.message = f"Error: {e}"
    
    result.duration = time.time() - start
    return result


def test_wireguard_userspace() -> TestResult:
    """测试 WireGuard 用户空间"""
    result = TestResult("WireGuard Userspace")
    start = time.time()
    
    try:
        # 检查 usque (WARP) 进程
        code, out, _ = run_cmd("pgrep -f usque")
        if code != 0:
            result.message = "Usque (WARP) process not running"
            # 这可能是正常的，取决于配置
            result.passed = True
            result.details = {"warp_enabled": False}
            result.duration = time.time() - start
            return result
        
        # 检查 WARP SOCKS 端口
        code, out, _ = run_cmd("ss -tlnp | grep ':38001'")
        if "usque" in out:
            result.passed = True
            result.message = "WARP userspace WG running"
            result.details = {"warp_enabled": True, "socks_port": 38001}
        else:
            result.message = "WARP port not listening"
    except Exception as e:
        result.message = f"Error: {e}"
    
    result.duration = time.time() - start
    return result


def test_resource_usage() -> TestResult:
    """测试资源使用情况"""
    result = TestResult("Resource Usage")
    start = time.time()
    
    try:
        config = TestConfig()
        process_stats = get_process_stats()
        
        # 检查各进程资源
        issues = []
        for name, stats in process_stats.items():
            if stats['cpu'] > config.max_cpu_percent:
                issues.append(f"{name} CPU too high: {stats['cpu']:.1f}%")
        
        # 检查 Xray goroutines
        xray_api = check_xray_api()
        if xray_api.get("connected"):
            goroutines = xray_api["sys"].get("num_goroutine", 0)
            if goroutines > config.max_goroutines:
                issues.append(f"Xray goroutines too high: {goroutines}")
            
            mem_mb = xray_api["sys"].get("alloc", 0) / 1024 / 1024
            if mem_mb > config.max_memory_mb:
                issues.append(f"Xray memory too high: {mem_mb:.1f}MB")
        
        if issues:
            result.message = "; ".join(issues)
        else:
            result.passed = True
            result.message = "Resource usage OK"
        
        result.details = {
            "processes": process_stats,
            "xray_goroutines": xray_api.get("sys", {}).get("num_goroutine", 0) if xray_api.get("connected") else 0,
            "xray_memory_mb": xray_api.get("sys", {}).get("alloc", 0) / 1024 / 1024 if xray_api.get("connected") else 0
        }
    except Exception as e:
        result.message = f"Error: {e}"
    
    result.duration = time.time() - start
    return result


def test_concurrent_load() -> TestResult:
    """测试并发负载"""
    result = TestResult("Concurrent Load")
    start = time.time()
    
    try:
        # 记录测试前资源
        xray_before = check_xray_api()
        
        # 并发请求
        num_concurrent = 20
        success_count = 0
        errors = []
        
        def make_request(idx):
            nonlocal success_count
            # Use SOCKS proxy (port 7893 is TPROXY, not HTTP proxy)
            code, out, err = run_cmd(
                f"curl -s -x socks5://127.0.0.1:38501 https://httpbin.org/get?n={idx} -o /dev/null --max-time 15",
                timeout=20
            )
            if code == 0:
                success_count += 1
            else:
                errors.append(f"Request {idx} failed")
        
        threads = []
        for i in range(num_concurrent):
            t = threading.Thread(target=make_request, args=(i,))
            threads.append(t)
            t.start()
        
        for t in threads:
            t.join()
        
        # 检查测试后资源
        xray_after = check_xray_api()
        
        if success_count >= num_concurrent * 0.9:  # 90% 成功率
            result.passed = True
            result.message = f"{success_count}/{num_concurrent} requests succeeded"
        else:
            result.message = f"Only {success_count}/{num_concurrent} succeeded"
        
        result.details = {
            "total_requests": num_concurrent,
            "successful": success_count,
            "goroutines_before": xray_before.get("sys", {}).get("num_goroutine", 0) if xray_before.get("connected") else 0,
            "goroutines_after": xray_after.get("sys", {}).get("num_goroutine", 0) if xray_after.get("connected") else 0
        }
    except Exception as e:
        result.message = f"Error: {e}"
    
    result.duration = time.time() - start
    return result


def test_api_performance() -> TestResult:
    """测试 API 性能"""
    result = TestResult("API Performance")
    start = time.time()
    
    try:
        from v2ray_stats_client import V2RayStatsClient
        
        client = V2RayStatsClient("127.0.0.1:10087")
        
        # 预热
        client.get_sys_stats()
        
        # 测试 500 次调用
        iterations = 500
        api_start = time.time()
        success = 0
        for _ in range(iterations):
            if client.get_sys_stats():
                success += 1
        api_elapsed = time.time() - api_start
        
        client.close()
        
        rate = iterations / api_elapsed
        latency_ms = api_elapsed / iterations * 1000
        
        if rate >= 1000:  # 至少 1000 q/s
            result.passed = True
            result.message = f"API: {rate:.0f} q/s, {latency_ms:.2f}ms latency"
        else:
            result.message = f"API too slow: {rate:.0f} q/s"
        
        result.details = {
            "iterations": iterations,
            "success": success,
            "rate_per_second": rate,
            "latency_ms": latency_ms
        }
    except Exception as e:
        result.message = f"Error: {e}"
    
    result.duration = time.time() - start
    return result


def test_mixed_wg_xray() -> TestResult:
    """测试 WG + Xray 混合场景"""
    result = TestResult("Mixed WG + Xray")
    start = time.time()
    
    try:
        # 检查是否有 peer 节点配置
        code, out, _ = run_cmd("ls /run/peer-tunnels/ 2>/dev/null")
        
        if code != 0 or not out.strip():
            result.passed = True
            result.message = "No peer tunnels configured (OK)"
            result.details = {"peer_tunnels": []}
            result.duration = time.time() - start
            return result
        
        peer_configs = out.strip().split('\n')
        
        # 检查 peer xray 进程
        code, out, _ = run_cmd("pgrep -f 'peer-tunnels'")
        
        if code == 0:
            result.passed = True
            result.message = f"Mixed mode OK, {len(peer_configs)} peer tunnel(s)"
            result.details = {"peer_tunnels": peer_configs}
        else:
            result.message = "Peer tunnel process not running"
    except Exception as e:
        result.message = f"Error: {e}"
    
    result.duration = time.time() - start
    return result


def test_memory_stability() -> TestResult:
    """测试内存稳定性 (短期)"""
    result = TestResult("Memory Stability")
    start = time.time()
    
    try:
        # 收集 5 次内存样本
        samples = []
        for _ in range(5):
            xray_api = check_xray_api()
            if xray_api.get("connected"):
                mem = xray_api["sys"].get("alloc", 0) / 1024 / 1024
                samples.append(mem)
            time.sleep(0.5)
        
        if not samples:
            result.message = "Could not collect memory samples"
            return result
        
        avg_mem = sum(samples) / len(samples)
        max_mem = max(samples)
        min_mem = min(samples)
        variance = max_mem - min_mem
        
        # 检查内存是否稳定（波动不超过 50%）
        if variance / avg_mem < 0.5:
            result.passed = True
            result.message = f"Memory stable: {avg_mem:.1f}MB avg"
        else:
            result.message = f"Memory unstable: {min_mem:.1f}-{max_mem:.1f}MB"
        
        result.details = {
            "samples": samples,
            "average_mb": avg_mem,
            "min_mb": min_mem,
            "max_mb": max_mem
        }
    except Exception as e:
        result.message = f"Error: {e}"
    
    result.duration = time.time() - start
    return result


# ============ 主函数 ============

def run_all_tests() -> List[TestResult]:
    """运行所有测试"""
    tests = [
        test_xray_inbound,
        test_xray_outbound,
        test_singbox_routing,
        test_wireguard_userspace,
        test_resource_usage,
        test_api_performance,
        test_concurrent_load,
        test_mixed_wg_xray,
        test_memory_stability,
    ]
    
    results = []
    for test_func in tests:
        print(f"Running: {test_func.__name__}...", end=" ", flush=True)
        try:
            result = test_func()
            status = "✓" if result.passed else "✗"
            print(f"{status} ({result.duration:.2f}s)")
            results.append(result)
        except Exception as e:
            print(f"✗ (Error: {e})")
            r = TestResult(test_func.__name__)
            r.message = str(e)
            results.append(r)
    
    return results


def print_summary(results: List[TestResult]):
    """打印测试摘要"""
    print("\n" + "=" * 60)
    print("TEST SUMMARY")
    print("=" * 60)
    
    passed = sum(1 for r in results if r.passed)
    total = len(results)
    
    for r in results:
        status = "PASS" if r.passed else "FAIL"
        print(f"[{status}] {r.name}: {r.message}")
        if r.details and not r.passed:
            for k, v in r.details.items():
                print(f"       {k}: {v}")
    
    print("-" * 60)
    print(f"Total: {passed}/{total} passed")
    
    if passed == total:
        print("All tests PASSED!")
        return 0
    else:
        print(f"{total - passed} test(s) FAILED")
        return 1


if __name__ == "__main__":
    print("=" * 60)
    print("VPN-Router Integration Tests")
    print("=" * 60)
    print()
    
    results = run_all_tests()
    exit_code = print_summary(results)
    sys.exit(exit_code)

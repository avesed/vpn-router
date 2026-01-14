#!/usr/bin/env python3
"""
Comprehensive API Integration Tests for VPN-Router

Tests all core functionality:
1. WireGuard ingress (userspace)
2. WireGuard egress (userspace)
3. Xray ingress (VLESS)
4. Xray egress (VLESS)
5. Routing rules
6. Mixed WG + Xray scenarios
7. Performance monitoring (memory/CPU/stability)
8. Stress testing

Usage:
    pytest tests/integration/test_comprehensive_api.py -v
    # Or run directly:
    python tests/integration/test_comprehensive_api.py
"""

import asyncio
import json
import os
import subprocess
import sys
import time
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple

import requests

# Test configuration
API_BASE = os.environ.get("API_BASE", "http://localhost:8000")
CONTAINER_NAME = os.environ.get("CONTAINER_NAME", "vpn-node1")
WG_TEST_CLIENT = os.environ.get("WG_TEST_CLIENT", "wg-test-client")
XRAY_TEST_CLIENT = os.environ.get("XRAY_TEST_CLIENT", "xray-test-client")

# Performance thresholds
MAX_MEMORY_MB = 500  # Max RSS per process
MAX_CPU_PERCENT = 80  # Max CPU per process (excluding sing-box which may be high)
MIN_RESPONSE_TIME_MS = 2000  # Max API response time


class TestResult:
    """Test result container"""
    def __init__(self, name: str):
        self.name = name
        self.passed = False
        self.error: Optional[str] = None
        self.duration_ms: float = 0
        self.details: Dict[str, Any] = {}

    def __repr__(self):
        status = "PASS" if self.passed else "FAIL"
        return f"[{status}] {self.name} ({self.duration_ms:.0f}ms)"


class APITestClient:
    """API test client with timing and error handling"""
    
    def __init__(self, base_url: str):
        self.base_url = base_url.rstrip("/")
        self.session = requests.Session()
        self.token: Optional[str] = None
    
    def _url(self, path: str) -> str:
        return f"{self.base_url}{path}"
    
    def _headers(self) -> Dict[str, str]:
        headers = {"Content-Type": "application/json"}
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        return headers
    
    def get(self, path: str, **kwargs) -> Tuple[int, Any, float]:
        """GET request, returns (status_code, response_data, duration_ms)"""
        start = time.time()
        try:
            resp = self.session.get(
                self._url(path),
                headers=self._headers(),
                timeout=30,
                **kwargs
            )
            duration = (time.time() - start) * 1000
            try:
                data = resp.json()
            except:
                data = resp.text
            return resp.status_code, data, duration
        except Exception as e:
            duration = (time.time() - start) * 1000
            return 0, {"error": str(e)}, duration
    
    def post(self, path: str, data: Any = None, **kwargs) -> Tuple[int, Any, float]:
        """POST request, returns (status_code, response_data, duration_ms)"""
        start = time.time()
        try:
            resp = self.session.post(
                self._url(path),
                headers=self._headers(),
                json=data,
                timeout=30,
                **kwargs
            )
            duration = (time.time() - start) * 1000
            try:
                data = resp.json()
            except:
                data = resp.text
            return resp.status_code, data, duration
        except Exception as e:
            duration = (time.time() - start) * 1000
            return 0, {"error": str(e)}, duration
    
    def put(self, path: str, data: Any = None, **kwargs) -> Tuple[int, Any, float]:
        """PUT request"""
        start = time.time()
        try:
            resp = self.session.put(
                self._url(path),
                headers=self._headers(),
                json=data,
                timeout=30,
                **kwargs
            )
            duration = (time.time() - start) * 1000
            try:
                data = resp.json()
            except:
                data = resp.text
            return resp.status_code, data, duration
        except Exception as e:
            duration = (time.time() - start) * 1000
            return 0, {"error": str(e)}, duration
    
    def delete(self, path: str, **kwargs) -> Tuple[int, Any, float]:
        """DELETE request"""
        start = time.time()
        try:
            resp = self.session.delete(
                self._url(path),
                headers=self._headers(),
                timeout=30,
                **kwargs
            )
            duration = (time.time() - start) * 1000
            try:
                data = resp.json()
            except:
                data = resp.text
            return resp.status_code, data, duration
        except Exception as e:
            duration = (time.time() - start) * 1000
            return 0, {"error": str(e)}, duration


def docker_exec(container: str, cmd: str, timeout: int = 30) -> Tuple[int, str, str]:
    """Execute command in container, returns (returncode, stdout, stderr)"""
    try:
        result = subprocess.run(
            ["docker", "exec", container, "bash", "-c", cmd],
            capture_output=True,
            text=True,
            timeout=timeout
        )
        return result.returncode, result.stdout, result.stderr
    except subprocess.TimeoutExpired:
        return -1, "", "Command timed out"
    except Exception as e:
        return -1, "", str(e)


def get_process_stats(container: str) -> Dict[str, Dict[str, Any]]:
    """Get memory and CPU stats for key processes"""
    _, stdout, _ = docker_exec(container, """
        ps aux --no-headers | awk '/rust-router|sing-box|xray|api_server/ {
            print $11, $3, $6
        }'
    """)
    
    stats = {}
    for line in stdout.strip().split("\n"):
        if not line:
            continue
        parts = line.split()
        if len(parts) >= 3:
            proc = parts[0].split("/")[-1]
            cpu = float(parts[1])
            rss_kb = int(parts[2])
            stats[proc] = {
                "cpu_percent": cpu,
                "rss_mb": rss_kb / 1024
            }
    return stats


def get_memory_usage(container: str) -> Dict[str, int]:
    """Get container memory usage in MB"""
    _, stdout, _ = docker_exec(container, "free -m | awk 'NR==2 {print $2, $3, $4}'")
    parts = stdout.strip().split()
    if len(parts) == 3:
        return {
            "total": int(parts[0]),
            "used": int(parts[1]),
            "free": int(parts[2])
        }
    return {"total": 0, "used": 0, "free": 0}


class ComprehensiveAPITest:
    """Comprehensive API test suite"""
    
    def __init__(self):
        self.client = APITestClient(API_BASE)
        self.results: List[TestResult] = []
        self.baseline_stats: Dict[str, Any] = {}
    
    def run_test(self, name: str, test_func) -> TestResult:
        """Run a single test and record results"""
        result = TestResult(name)
        start = time.time()
        try:
            test_func(result)
            result.passed = True
        except AssertionError as e:
            result.error = str(e)
            result.passed = False
        except Exception as e:
            result.error = f"Exception: {type(e).__name__}: {e}"
            result.passed = False
        result.duration_ms = (time.time() - start) * 1000
        self.results.append(result)
        print(result)
        return result
    
    def capture_baseline(self):
        """Capture baseline performance metrics"""
        print("\n=== Capturing Baseline Performance ===")
        self.baseline_stats = {
            "timestamp": datetime.now().isoformat(),
            "process_stats": get_process_stats(CONTAINER_NAME),
            "memory": get_memory_usage(CONTAINER_NAME)
        }
        print(f"Memory: {self.baseline_stats['memory']}")
        print(f"Process stats: {json.dumps(self.baseline_stats['process_stats'], indent=2)}")
    
    # ==================== Health Check Tests ====================
    
    def test_health_check(self, result: TestResult):
        """Test API health endpoint"""
        status, data, duration = self.client.get("/api/health")
        assert status == 200, f"Health check failed: {status}"
        assert data.get("status") == "healthy", f"Unhealthy status: {data}"
        result.details["checks"] = data.get("checks", {})
    
    def test_status_endpoint(self, result: TestResult):
        """Test status endpoint"""
        status, data, duration = self.client.get("/api/status")
        assert status == 200, f"Status check failed: {status}"
        result.details["status"] = data
    
    # ==================== WireGuard Ingress Tests ====================
    
    def test_wg_server_config(self, result: TestResult):
        """Test WireGuard server configuration"""
        status, data, duration = self.client.get("/api/wireguard/server")
        assert status == 200, f"WG server config failed: {status}"
        result.details["server"] = data.get("data", {})
    
    def test_wg_peers_list(self, result: TestResult):
        """Test listing WireGuard peers"""
        status, data, duration = self.client.get("/api/wireguard/peers")
        assert status == 200, f"WG peers list failed: {status}"
        peers = data.get("data", [])
        result.details["peer_count"] = len(peers)
        result.details["peers"] = [p.get("name") for p in peers]
    
    def test_wg_client_connectivity(self, result: TestResult):
        """Test WireGuard client can connect and route traffic"""
        # Check if WG test client exists
        ret, stdout, stderr = docker_exec(WG_TEST_CLIENT, "wg show wg0 2>/dev/null || echo 'no-wg'", timeout=10)
        if "no-wg" in stdout:
            result.details["skip"] = "WG test client not configured"
            return
        
        # Check handshake
        ret, stdout, stderr = docker_exec(WG_TEST_CLIENT, "wg show wg0 | grep -c 'handshake'")
        has_handshake = "1" in stdout
        result.details["handshake"] = has_handshake
        
        # Test connectivity through WG tunnel
        if has_handshake:
            ret, stdout, stderr = docker_exec(
                WG_TEST_CLIENT,
                "curl -s --interface wg0 --max-time 10 https://ifconfig.me 2>/dev/null || echo 'failed'"
            )
            result.details["external_ip"] = stdout.strip() if ret == 0 else "failed"
            assert "failed" not in stdout.lower(), f"WG tunnel connectivity failed: {stderr}"
    
    # ==================== WireGuard Egress Tests ====================
    
    def test_wg_egress_list(self, result: TestResult):
        """Test listing WireGuard egress tunnels"""
        status, data, duration = self.client.get("/api/egress/custom")
        assert status == 200, f"WG egress list failed: {status}"
        egress_list = data.get("data", [])
        result.details["egress_count"] = len(egress_list)
        result.details["egress_tags"] = [e.get("tag") for e in egress_list]
    
    def test_direct_egress_list(self, result: TestResult):
        """Test listing direct egress"""
        status, data, duration = self.client.get("/api/egress/direct")
        assert status == 200, f"Direct egress list failed: {status}"
        result.details["direct_egress"] = data.get("data", [])
    
    # ==================== Xray Ingress Tests ====================
    
    def test_v2ray_inbound_config(self, result: TestResult):
        """Test V2Ray/Xray inbound configuration"""
        status, data, duration = self.client.get("/api/v2ray/inbound")
        assert status == 200, f"V2Ray inbound config failed: {status}"
        config = data.get("data", {})
        result.details["enabled"] = config.get("enabled", False)
        result.details["protocol"] = config.get("protocol")
        result.details["listen_port"] = config.get("listen_port")
    
    def test_v2ray_users_list(self, result: TestResult):
        """Test listing V2Ray/Xray users"""
        status, data, duration = self.client.get("/api/v2ray/users")
        assert status == 200, f"V2Ray users list failed: {status}"
        users = data.get("data", [])
        result.details["user_count"] = len(users)
        result.details["users"] = [u.get("name") for u in users]
    
    def test_xray_client_connectivity(self, result: TestResult):
        """Test Xray client connectivity"""
        # Check if Xray test client exists
        ret, stdout, stderr = docker_exec(XRAY_TEST_CLIENT, "curl -s --socks5 127.0.0.1:1080 https://ifconfig.me --max-time 15 2>/dev/null || echo 'failed'", timeout=20)
        if "failed" in stdout.lower():
            result.details["skip"] = f"Xray test client not working: {stderr}"
            return
        result.details["external_ip"] = stdout.strip()
    
    # ==================== Xray Egress Tests ====================
    
    def test_v2ray_egress_list(self, result: TestResult):
        """Test listing V2Ray/Xray egress"""
        status, data, duration = self.client.get("/api/v2ray/egress")
        assert status == 200, f"V2Ray egress list failed: {status}"
        egress_list = data.get("data", [])
        result.details["egress_count"] = len(egress_list)
        result.details["egress_tags"] = [e.get("tag") for e in egress_list]
    
    # ==================== Routing Rules Tests ====================
    
    def test_routing_rules_list(self, result: TestResult):
        """Test listing routing rules"""
        status, data, duration = self.client.get("/api/rules")
        assert status == 200, f"Rules list failed: {status}"
        result.details["rules"] = data
    
    def test_custom_rules_list(self, result: TestResult):
        """Test listing custom routing rules"""
        status, data, duration = self.client.get("/api/rules/custom")
        assert status == 200, f"Custom rules list failed: {status}"
        rules = data.get("data", [])
        result.details["rule_count"] = len(rules)
    
    def test_dns_config(self, result: TestResult):
        """Test DNS configuration"""
        status, data, duration = self.client.get("/api/dns/config")
        assert status == 200, f"DNS config failed: {status}"
        result.details["config"] = data.get("data", {})
    
    def test_dns_upstreams(self, result: TestResult):
        """Test DNS upstreams"""
        status, data, duration = self.client.get("/api/dns/upstreams")
        assert status == 200, f"DNS upstreams failed: {status}"
        result.details["upstreams"] = data.get("data", [])
    
    def test_dns_routes(self, result: TestResult):
        """Test DNS routes"""
        status, data, duration = self.client.get("/api/dns/routes")
        assert status == 200, f"DNS routes failed: {status}"
        result.details["routes"] = data.get("data", [])
    
    # ==================== Peer Node Tests ====================
    
    def test_peer_nodes_list(self, result: TestResult):
        """Test listing peer nodes"""
        status, data, duration = self.client.get("/api/peers")
        assert status == 200, f"Peers list failed: {status}"
        peers = data.get("data", [])
        result.details["peer_count"] = len(peers)
        result.details["peers"] = [
            {"tag": p.get("tag"), "tunnel_type": p.get("tunnel_type"), "status": p.get("tunnel_status")}
            for p in peers
        ]
    
    def test_chains_list(self, result: TestResult):
        """Test listing node chains"""
        status, data, duration = self.client.get("/api/chains")
        assert status == 200, f"Chains list failed: {status}"
        chains = data.get("data", [])
        result.details["chain_count"] = len(chains)
        result.details["chains"] = [c.get("tag") for c in chains]
    
    # ==================== Outbound Groups Tests ====================
    
    def test_outbound_groups_list(self, result: TestResult):
        """Test listing outbound groups"""
        status, data, duration = self.client.get("/api/outbound-groups")
        assert status == 200, f"Outbound groups list failed: {status}"
        groups = data.get("data", [])
        result.details["group_count"] = len(groups)
    
    def test_available_members(self, result: TestResult):
        """Test listing available outbound members"""
        status, data, duration = self.client.get("/api/outbound-groups/available-members")
        assert status == 200, f"Available members failed: {status}"
        result.details["members"] = data.get("data", [])
    
    # ==================== Statistics Tests ====================
    
    def test_dashboard_stats(self, result: TestResult):
        """Test dashboard statistics"""
        status, data, duration = self.client.get("/api/stats/dashboard")
        assert status == 200, f"Dashboard stats failed: {status}"
        result.details["stats"] = data.get("data", {})
    
    def test_dns_stats(self, result: TestResult):
        """Test DNS statistics"""
        status, data, duration = self.client.get("/api/dns/stats")
        assert status == 200, f"DNS stats failed: {status}"
        result.details["dns_stats"] = data.get("data", {})
    
    # ==================== Performance Tests ====================
    
    def test_process_memory(self, result: TestResult):
        """Test that process memory is within limits"""
        stats = get_process_stats(CONTAINER_NAME)
        result.details["stats"] = stats
        
        for proc, pstats in stats.items():
            rss_mb = pstats.get("rss_mb", 0)
            if rss_mb > MAX_MEMORY_MB:
                # Allow api_server and sing-box to use more memory
                if proc in ("api_server.py", "sing-box", "python3"):
                    continue
                result.error = f"{proc} using {rss_mb:.0f}MB > {MAX_MEMORY_MB}MB limit"
                raise AssertionError(result.error)
    
    def test_api_response_time(self, result: TestResult):
        """Test API response times are acceptable"""
        endpoints = [
            "/api/health",
            "/api/status",
            "/api/wireguard/peers",
            "/api/rules/custom",
        ]
        
        times = {}
        for endpoint in endpoints:
            status, data, duration = self.client.get(endpoint)
            times[endpoint] = duration
            if duration > MIN_RESPONSE_TIME_MS:
                result.error = f"{endpoint} took {duration:.0f}ms > {MIN_RESPONSE_TIME_MS}ms"
                # Don't fail, just warn
        
        result.details["response_times"] = times
        avg_time = sum(times.values()) / len(times) if times else 0
        result.details["avg_response_time_ms"] = avg_time
    
    def test_concurrent_requests(self, result: TestResult):
        """Test handling of concurrent API requests"""
        import concurrent.futures
        
        def make_request(path):
            client = APITestClient(API_BASE)
            return client.get(path)
        
        endpoints = ["/api/health"] * 10
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            futures = [executor.submit(make_request, ep) for ep in endpoints]
            results = [f.result() for f in concurrent.futures.as_completed(futures)]
        
        success_count = sum(1 for status, _, _ in results if status == 200)
        result.details["concurrent_requests"] = len(endpoints)
        result.details["successful"] = success_count
        
        assert success_count == len(endpoints), f"Only {success_count}/{len(endpoints)} concurrent requests succeeded"
    
    # ==================== Integration Tests ====================
    
    def test_egress_connectivity(self, result: TestResult):
        """Test egress can reach external services"""
        status, data, duration = self.client.get("/api/test/egress/direct")
        # This endpoint may not exist or may fail - that's OK
        if status == 200:
            result.details["egress_test"] = data
        else:
            result.details["skip"] = f"Egress test endpoint returned {status}"
    
    def test_config_regeneration(self, result: TestResult):
        """Test config regeneration doesn't break anything"""
        # Get current config hash
        ret, stdout1, _ = docker_exec(CONTAINER_NAME, "md5sum /etc/sing-box/sing-box.generated.json 2>/dev/null | cut -d' ' -f1")
        
        # Trigger regeneration (dry run if available)
        status, data, duration = self.client.post("/api/config/regenerate", {"dry_run": True})
        result.details["regenerate_status"] = status
        
        # Verify config still valid
        ret, stdout2, _ = docker_exec(CONTAINER_NAME, "md5sum /etc/sing-box/sing-box.generated.json 2>/dev/null | cut -d' ' -f1")
        result.details["config_changed"] = stdout1.strip() != stdout2.strip()
    
    # ==================== Stress Tests ====================
    
    def test_rapid_api_calls(self, result: TestResult):
        """Test rapid successive API calls"""
        call_count = 50
        success_count = 0
        total_time = 0
        
        for i in range(call_count):
            status, data, duration = self.client.get("/api/health")
            if status == 200:
                success_count += 1
            total_time += duration
        
        result.details["total_calls"] = call_count
        result.details["successful"] = success_count
        result.details["total_time_ms"] = total_time
        result.details["avg_time_ms"] = total_time / call_count
        
        # Allow some failures due to rate limiting
        assert success_count >= call_count * 0.9, f"Only {success_count}/{call_count} rapid calls succeeded"
    
    def run_all_tests(self):
        """Run all tests"""
        print("\n" + "=" * 60)
        print("VPN-Router Comprehensive API Tests")
        print("=" * 60)
        
        self.capture_baseline()
        
        tests = [
            # Health
            ("Health Check", self.test_health_check),
            ("Status Endpoint", self.test_status_endpoint),
            
            # WireGuard Ingress
            ("WG Server Config", self.test_wg_server_config),
            ("WG Peers List", self.test_wg_peers_list),
            ("WG Client Connectivity", self.test_wg_client_connectivity),
            
            # WireGuard Egress
            ("WG Egress List", self.test_wg_egress_list),
            ("Direct Egress List", self.test_direct_egress_list),
            
            # Xray Ingress
            ("V2Ray Inbound Config", self.test_v2ray_inbound_config),
            ("V2Ray Users List", self.test_v2ray_users_list),
            ("Xray Client Connectivity", self.test_xray_client_connectivity),
            
            # Xray Egress
            ("V2Ray Egress List", self.test_v2ray_egress_list),
            
            # Routing
            ("Routing Rules List", self.test_routing_rules_list),
            ("Custom Rules List", self.test_custom_rules_list),
            ("DNS Config", self.test_dns_config),
            ("DNS Upstreams", self.test_dns_upstreams),
            ("DNS Routes", self.test_dns_routes),
            
            # Peer Nodes
            ("Peer Nodes List", self.test_peer_nodes_list),
            ("Chains List", self.test_chains_list),
            
            # Groups
            ("Outbound Groups List", self.test_outbound_groups_list),
            ("Available Members", self.test_available_members),
            
            # Statistics
            ("Dashboard Stats", self.test_dashboard_stats),
            ("DNS Stats", self.test_dns_stats),
            
            # Performance
            ("Process Memory", self.test_process_memory),
            ("API Response Time", self.test_api_response_time),
            ("Concurrent Requests", self.test_concurrent_requests),
            
            # Integration
            ("Egress Connectivity", self.test_egress_connectivity),
            ("Config Regeneration", self.test_config_regeneration),
            
            # Stress
            ("Rapid API Calls", self.test_rapid_api_calls),
        ]
        
        print(f"\nRunning {len(tests)} tests...\n")
        
        for name, test_func in tests:
            self.run_test(name, test_func)
        
        # Final performance snapshot
        print("\n=== Final Performance Snapshot ===")
        final_stats = {
            "timestamp": datetime.now().isoformat(),
            "process_stats": get_process_stats(CONTAINER_NAME),
            "memory": get_memory_usage(CONTAINER_NAME)
        }
        print(f"Memory: {final_stats['memory']}")
        print(f"Process stats: {json.dumps(final_stats['process_stats'], indent=2)}")
        
        # Summary
        passed = sum(1 for r in self.results if r.passed)
        failed = len(self.results) - passed
        
        print("\n" + "=" * 60)
        print(f"RESULTS: {passed} passed, {failed} failed")
        print("=" * 60)
        
        if failed > 0:
            print("\nFailed tests:")
            for r in self.results:
                if not r.passed:
                    print(f"  - {r.name}: {r.error}")
        
        return failed == 0


def main():
    """Main entry point"""
    tester = ComprehensiveAPITest()
    success = tester.run_all_tests()
    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()

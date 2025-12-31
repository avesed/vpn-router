#!/usr/bin/env python3
"""隧道 API 客户端

用于通过已建立的隧道与远程节点进行安全通信。

特点：
- 使用隧道内 IP 地址通信（如 10.200.200.2:8000）
- WireGuard 隧道：通过 tunnel_remote_ip 验证（IP 即身份）
- Xray 隧道：通过 X-Peer-UUID header 验证
- 支持获取远程节点出口列表
- 支持在终端节点注册/注销链路路由

使用示例：
    # WireGuard 隧道（无需额外认证参数）
    client = TunnelAPIClient("node-tokyo", "10.200.200.2:8000")

    # Xray 隧道（需要 UUID 认证）
    client = TunnelAPIClient(
        "node-tokyo", "10.200.200.2:8000",
        tunnel_type="xray", socks_port=37201, peer_uuid="xxx-xxx"
    )

    # 获取远程节点可用出口
    egress_list = client.get_egress_list()

    # 在终端节点注册链路路由
    success = client.register_chain_route("us-stream", dscp=3, egress="pia-us")
"""

import json
import logging
import socket
from collections import OrderedDict
from dataclasses import dataclass
from typing import Dict, List, Optional, Any
from urllib.parse import urljoin

import requests


# 默认超时时间（秒）
DEFAULT_TIMEOUT = 10
DEFAULT_CONNECT_TIMEOUT = 5


@dataclass
class EgressInfo:
    """出口信息"""
    tag: str
    name: str
    type: str  # "pia", "custom", "direct", "warp", "v2ray", "openvpn"
    enabled: bool
    description: Optional[str] = None


@dataclass
class ChainRouteInfo:
    """链路路由信息"""
    chain_tag: str
    mark_value: int
    mark_type: str
    egress_tag: str
    source_node: Optional[str] = None


class TunnelAPIError(Exception):
    """隧道 API 错误"""

    def __init__(self, message: str, status_code: Optional[int] = None, response_body: Optional[str] = None):
        self.message = message
        self.status_code = status_code
        self.response_body = response_body
        super().__init__(self.message)


class TunnelAuthError(TunnelAPIError):
    """认证错误 (401/403) - PSK 不匹配或节点配置错误"""
    pass


class TunnelNotFoundError(TunnelAPIError):
    """资源不存在 (404)"""
    pass


class TunnelServiceError(TunnelAPIError):
    """服务错误 (5xx) - 可重试"""
    pass


class TunnelProxyError(TunnelAPIError):
    """SOCKS 代理错误 - 隧道未连接或代理端口不可用"""
    pass


def _validate_socks_port(port: Optional[int]) -> bool:
    """验证 SOCKS 端口有效性

    Args:
        port: 端口号

    Returns:
        True 如果端口有效
    """
    return port is not None and 1 <= port <= 65535


class TunnelAPIClient:
    """隧道 API 客户端

    通过已建立的隧道与远程节点进行 API 通信。

    认证方式：
    - WireGuard 隧道：通过 tunnel_remote_ip 验证（IP 即身份，无需额外 header）
    - Xray 隧道：通过 X-Peer-UUID header 验证
    """

    def __init__(
        self,
        node_tag: str,
        tunnel_endpoint: str,
        timeout: float = DEFAULT_TIMEOUT,
        connect_timeout: float = DEFAULT_CONNECT_TIMEOUT,
        tunnel_type: str = "wireguard",
        socks_port: Optional[int] = None,
        peer_uuid: Optional[str] = None,
    ):
        """初始化客户端

        Args:
            node_tag: 远程节点标识
            tunnel_endpoint: 隧道内 API 地址 (如 10.200.200.2:8000)
            timeout: 请求超时时间（秒）
            connect_timeout: 连接超时时间（秒）
            tunnel_type: 隧道类型 ("wireguard" 或 "xray")
            socks_port: Xray 隧道的 SOCKS5 代理端口 (仅 tunnel_type="xray" 时使用)
            peer_uuid: Xray 隧道的身份标识 UUID (仅 tunnel_type="xray" 时使用)
        """
        self.node_tag = node_tag
        self.tunnel_endpoint = tunnel_endpoint
        self.tunnel_type = tunnel_type
        self.socks_port = socks_port
        self.peer_uuid = peer_uuid  # Xray 隧道身份标识

        # SOCKS 代理增加超时时间（额外延迟）
        if tunnel_type == "xray" and socks_port:
            self.timeout = timeout + 10  # +10s 总超时
            self.connect_timeout = connect_timeout + 5  # +5s 连接超时
        else:
            self.timeout = timeout
            self.connect_timeout = connect_timeout

        # 构建基础 URL
        if not tunnel_endpoint.startswith("http"):
            self.base_url = f"http://{tunnel_endpoint}"
        else:
            self.base_url = tunnel_endpoint

        # 确保没有尾部斜杠
        self.base_url = self.base_url.rstrip("/")

        # 配置 SOCKS5 代理（仅 Xray 隧道）
        # 使用 socks5h:// 确保 DNS 解析也通过代理，防止 DNS 泄露
        self._proxies: Optional[Dict[str, str]] = None
        if tunnel_type == "xray" and socks_port and _validate_socks_port(socks_port):
            self._proxies = {
                "http": f"socks5h://127.0.0.1:{socks_port}",
                "https": f"socks5h://127.0.0.1:{socks_port}",
            }

        # 记录路由方式
        route_via = f"via SOCKS5:{socks_port}" if self._proxies else "via direct"
        logging.debug(f"[tunnel-api] 初始化客户端: node={node_tag}, endpoint={tunnel_endpoint} ({route_via})")

    def _get_headers(self) -> Dict[str, str]:
        """获取请求头

        WireGuard 隧道：无需额外认证 header（IP 即身份）
        Xray 隧道：添加 X-Peer-UUID header
        """
        headers = {
            "Content-Type": "application/json",
        }

        # Xray 隧道需要 UUID 认证
        if self.tunnel_type == "xray" and self.peer_uuid:
            headers["X-Peer-UUID"] = self.peer_uuid

        return headers

    def _make_request(
        self,
        method: str,
        path: str,
        data: Optional[Dict[str, Any]] = None,
        params: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """发送 API 请求

        Args:
            method: HTTP 方法 (GET, POST, PUT, DELETE)
            path: API 路径 (如 /api/peer-info/egress)
            data: 请求体数据
            params: URL 参数

        Returns:
            响应 JSON 数据

        Raises:
            TunnelAPIError: API 调用失败
            TunnelAuthError: 认证失败 (401/403)
            TunnelNotFoundError: 资源不存在 (404)
            TunnelServiceError: 服务错误 (5xx)
            TunnelProxyError: SOCKS 代理错误
        """
        url = f"{self.base_url}{path}"
        headers = self._get_headers()
        timeout = (self.connect_timeout, self.timeout)

        # 日志记录路由方式
        route_via = f"via SOCKS5:{self.socks_port}" if self._proxies else "via direct"

        try:
            logging.debug(f"[tunnel-api] {method} {url} ({route_via})")

            # 公共请求参数
            request_kwargs = {
                "headers": headers,
                "timeout": timeout,
                "proxies": self._proxies,
            }

            if method.upper() == "GET":
                response = requests.get(url, params=params, **request_kwargs)
            elif method.upper() == "POST":
                response = requests.post(url, json=data, params=params, **request_kwargs)
            elif method.upper() == "PUT":
                response = requests.put(url, json=data, params=params, **request_kwargs)
            elif method.upper() == "DELETE":
                response = requests.delete(url, params=params, **request_kwargs)
            else:
                raise TunnelAPIError(f"Unsupported HTTP method: {method}")

            # 检查响应状态并分类错误
            if response.status_code >= 400:
                error_body = response.text[:500] if response.text else None
                status = response.status_code

                # 认证错误 - 不重试
                if status in (401, 403):
                    raise TunnelAuthError(
                        f"Authentication failed: {status}",
                        status_code=status,
                        response_body=error_body
                    )
                # 资源不存在
                elif status == 404:
                    raise TunnelNotFoundError(
                        f"Resource not found: {status}",
                        status_code=status,
                        response_body=error_body
                    )
                # 服务错误 - 可重试
                elif status >= 500:
                    raise TunnelServiceError(
                        f"Service error: {status}",
                        status_code=status,
                        response_body=error_body
                    )
                # 其他客户端错误
                else:
                    raise TunnelAPIError(
                        f"API request failed: {status}",
                        status_code=status,
                        response_body=error_body
                    )

            # 解析 JSON 响应
            if response.text:
                return response.json()
            return {}

        except requests.exceptions.ProxyError as e:
            # SOCKS 代理错误 - 隧道可能未连接
            logging.debug(f"[tunnel-api] SOCKS proxy error details: {e}")
            raise TunnelProxyError(
                f"SOCKS proxy error (port {self.socks_port}). "
                f"Tunnel may not be connected or Xray is not running."
            )
        except requests.exceptions.Timeout as e:
            logging.debug(f"[tunnel-api] Timeout details: {e}")
            raise TunnelAPIError(f"Request timeout ({route_via})")
        except requests.exceptions.ConnectionError as e:
            # 区分直连和代理的连接错误
            logging.debug(f"[tunnel-api] Connection error details: {e}")
            if self._proxies:
                raise TunnelProxyError(
                    f"Connection error via SOCKS5:{self.socks_port}. "
                    f"Check if Xray is running and tunnel is connected."
                )
            raise TunnelAPIError(f"Connection error ({route_via})")
        except json.JSONDecodeError as e:
            raise TunnelAPIError(f"Invalid JSON response: {e}")

    def ping(self) -> bool:
        """测试隧道连通性

        Returns:
            True 如果隧道连通
        """
        try:
            result = self._make_request("GET", "/api/health")
            return result.get("status") == "healthy"
        except TunnelAPIError as e:
            logging.warning(f"[tunnel-api] Ping failed for {self.node_tag}: {e}")
            return False

    def get_egress_list(self) -> List[EgressInfo]:
        """获取远程节点的可用出口列表

        Returns:
            出口信息列表
        """
        try:
            result = self._make_request("GET", "/api/peer-info/egress")
            egress_list = []

            for item in result.get("egress", []):
                egress_list.append(EgressInfo(
                    tag=item["tag"],
                    name=item.get("name", item["tag"]),
                    type=item.get("type", "unknown"),
                    enabled=item.get("enabled", True),
                    description=item.get("description"),
                ))

            logging.info(f"[tunnel-api] 获取 {self.node_tag} 出口列表: {len(egress_list)} 个")
            return egress_list

        except TunnelAPIError as e:
            logging.error(f"[tunnel-api] 获取出口列表失败 ({self.node_tag}): {e}")
            raise

    def register_chain_route(
        self,
        chain_tag: str,
        mark_value: int,
        egress_tag: str,
        mark_type: str = "dscp",
        source_node: Optional[str] = None,
        target_node: Optional[str] = None,  # Phase 11-Fix.E: 支持转发注册
    ) -> bool:
        """在终端节点注册链路路由

        当一个多跳链路被激活时，需要在终端节点注册 DSCP/email 到出口的映射。
        这样终端节点才能根据标记选择正确的本地出口。

        Args:
            chain_tag: 链路标识
            mark_value: 标记值（DSCP 1-63 或 routing mark）
            egress_tag: 终端节点的本地出口 tag
            mark_type: 标记类型 ('dscp' 或 'xray_email')
            source_node: 注册来源节点（通常是入口节点）
            target_node: 目标节点（如果指定，接收节点将转发注册到该目标）

        Returns:
            是否成功注册
        """
        try:
            data = {
                "chain_tag": chain_tag,
                "mark_value": mark_value,
                "mark_type": mark_type,
                "egress_tag": egress_tag,
            }
            if source_node:
                data["source_node"] = source_node
            # Phase 11-Fix.E: 如果指定了 target_node，接收节点将转发注册
            if target_node:
                data["target_node"] = target_node

            result = self._make_request("POST", "/api/chain-routing/register", data=data)
            success = result.get("success", False)

            if success:
                logging.info(
                    f"[tunnel-api] 注册链路路由成功: chain={chain_tag}, "
                    f"mark={mark_value}, egress={egress_tag} @ {self.node_tag}"
                )
            else:
                logging.warning(
                    f"[tunnel-api] 注册链路路由失败: {result.get('message', 'Unknown error')}"
                )

            return success

        except TunnelAPIError as e:
            logging.error(f"[tunnel-api] 注册链路路由异常 ({self.node_tag}): {e}")
            return False

    def unregister_chain_route(
        self,
        chain_tag: str,
        mark_value: int,
        mark_type: str = "dscp",
        target_node: Optional[str] = None,  # Phase 11-Fix.E: 支持转发注销
    ) -> bool:
        """在终端节点注销链路路由

        当链路被停用时，需要清理终端节点的路由映射。

        Args:
            chain_tag: 链路标识
            mark_value: 标记值
            mark_type: 标记类型 ('dscp' 或 'xray_email')
            target_node: 可选的目标节点（用于传递模式，让中继转发注销请求）

        Returns:
            是否成功注销
        """
        try:
            params = {
                "chain_tag": chain_tag,
                "mark_value": mark_value,
                "mark_type": mark_type,
            }
            # Phase 11-Fix.E: 传递模式下，通过中继转发注销请求
            if target_node:
                params["target_node"] = target_node

            result = self._make_request("DELETE", "/api/chain-routing/unregister", params=params)
            success = result.get("success", False)

            if success:
                logging.info(
                    f"[tunnel-api] 注销链路路由成功: chain={chain_tag}, "
                    f"mark={mark_value} @ {self.node_tag}"
                )

            return success

        except TunnelAPIError as e:
            logging.error(f"[tunnel-api] 注销链路路由异常 ({self.node_tag}): {e}")
            return False

    def get_chain_routes(self) -> List[ChainRouteInfo]:
        """获取终端节点的链路路由列表

        Returns:
            链路路由信息列表
        """
        try:
            result = self._make_request("GET", "/api/chain-routing")
            routes = []

            for item in result.get("routes", []):
                routes.append(ChainRouteInfo(
                    chain_tag=item["chain_tag"],
                    mark_value=item["mark_value"],
                    mark_type=item.get("mark_type", "dscp"),
                    egress_tag=item["egress_tag"],
                    source_node=item.get("source_node"),
                ))

            logging.debug(f"[tunnel-api] 获取 {self.node_tag} 链路路由: {len(routes)} 条")
            return routes

        except TunnelAPIError as e:
            logging.error(f"[tunnel-api] 获取链路路由失败 ({self.node_tag}): {e}")
            raise

    def get_peers(self) -> List[Dict[str, Any]]:
        """Phase 11-Fix.C: 获取远程节点的 peer 列表

        用于验证多跳链路中的后续跳点是否存在于中间节点。

        Returns:
            peer 节点列表，包含 tag, name, tunnel_status 等信息
        """
        try:
            result = self._make_request("GET", "/api/peers")
            peers = result.get("peers", [])
            logging.debug(f"[tunnel-api] 获取 {self.node_tag} peer 列表: {len(peers)} 个")
            return peers
        except TunnelAPIError as e:
            logging.error(f"[tunnel-api] 获取 peer 列表失败 ({self.node_tag}): {e}")
            raise

    def validate_chain_hops(
        self,
        hops: List[str],
        allow_transitive: bool = False,
    ) -> Dict[str, Any]:
        """Phase 11-Fix.C: 在远程节点验证链路跳点

        用于递归验证多跳链路中后续跳点的有效性。
        例如 A→B→C 链路，A 调用 B 的此方法验证 [C] 是否有效。

        Args:
            hops: 跳点列表（从调用节点视角的后续跳点）
            allow_transitive: 是否允许传递模式

        Returns:
            {"valid": bool, "error": str|None}
        """
        try:
            data = {
                "hops": hops,
                "allow_transitive": allow_transitive,
            }
            result = self._make_request("POST", "/api/chains/validate-hops", data=data)

            valid = result.get("valid", False)
            error = result.get("error")

            if valid:
                logging.debug(f"[tunnel-api] 跳点验证通过 @ {self.node_tag}: hops={hops}")
            else:
                logging.warning(f"[tunnel-api] 跳点验证失败 @ {self.node_tag}: {error}")

            return {"valid": valid, "error": error}

        except TunnelAPIError as e:
            logging.error(f"[tunnel-api] 跳点验证异常 ({self.node_tag}): {e}")
            return {"valid": False, "error": str(e)}

    def notify_chain_status(
        self,
        chain_tag: str,
        status: str,
        message: Optional[str] = None,
    ) -> bool:
        """通知链路状态变更

        用于在链路状态变更时通知相关节点。

        Args:
            chain_tag: 链路标识
            status: 新状态 ('active', 'inactive', 'error')
            message: 可选的状态消息

        Returns:
            是否成功通知
        """
        try:
            data = {
                "chain_tag": chain_tag,
                "status": status,
            }
            if message:
                data["message"] = message

            result = self._make_request("POST", "/api/chain-routing/status", data=data)
            return result.get("success", False)

        except TunnelAPIError as e:
            logging.error(f"[tunnel-api] 通知链路状态失败 ({self.node_tag}): {e}")
            return False

    def request_reverse_setup(
        self,
        psk: str,
        node_id: str,
        endpoint: str,
        wg_public_key: str,
        tunnel_local_ip: str,
    ) -> bool:
        """Phase 11.3: 请求远程节点建立反向连接

        在配对完成后，通过隧道调用远程节点的 reverse-setup API，
        请求远程节点也建立到本节点的隧道连接，实现双向通信。

        Args:
            psk: 预共享密钥
            node_id: 本节点标识
            endpoint: 本节点的隧道监听端点 (IP:port)
            wg_public_key: 本节点的 WireGuard 公钥
            tunnel_local_ip: 本节点的隧道 IP

        Returns:
            是否成功请求反向连接
        """
        try:
            data = {
                "psk": psk,
                "node_id": node_id,
                "endpoint": endpoint,
                "wg_public_key": wg_public_key,
                "tunnel_local_ip": tunnel_local_ip,
            }

            result = self._make_request("POST", "/api/peer-tunnel/reverse-setup", data=data)
            success = result.get("success", False)

            if success:
                logging.info(f"[tunnel-api] 反向连接请求成功 ({self.node_tag})")
            else:
                logging.warning(f"[tunnel-api] 反向连接请求失败 ({self.node_tag}): {result.get('message')}")

            return success

        except TunnelAPIError as e:
            logging.error(f"[tunnel-api] 请求反向连接失败 ({self.node_tag}): {e}")
            return False

    def register_relay_route(
        self,
        psk: Optional[str],  # Phase 11-Fix.D: PSK 改为可选，支持 IP 认证
        chain_tag: str,
        source_node: str,
        target_node: str,
        dscp_value: int,
        mark_type: str = "dscp",
    ) -> bool:
        """Phase 11.4: 在远程节点注册中继转发规则

        用于多跳链路激活：请求中间节点配置 DSCP 匹配 + 策略路由。

        Args:
            psk: 预共享密钥（可选，为 None 时使用 IP 认证）
            chain_tag: 链路标识
            source_node: 流量来源节点 tag（上游）
            target_node: 流量目标节点 tag（下游）
            dscp_value: DSCP 标记值 (0-63)
            mark_type: 标记类型 ('dscp' 或 'xray_email')

        Returns:
            是否成功配置
        """
        try:
            data = {
                "chain_tag": chain_tag,
                "source_node": source_node,
                "target_node": target_node,
                "dscp_value": dscp_value,
                "mark_type": mark_type,
            }
            # Phase 11-Fix.D: 仅在提供 PSK 时包含
            if psk:
                data["psk"] = psk
            result = self._make_request("POST", "/api/relay-routing/register", data=data)
            success = result.get("success", False)

            if success:
                logging.info(f"[tunnel-api] 中继路由已注册: 链路='{chain_tag}' ({self.node_tag})")
            else:
                logging.warning(f"[tunnel-api] 中继路由注册失败 ({self.node_tag}): {result.get('message')}")

            return success

        except TunnelAPIError as e:
            logging.error(f"[tunnel-api] 注册中继路由失败 ({self.node_tag}): {e}")
            return False

    def unregister_relay_route(self, psk: Optional[str], chain_tag: str) -> bool:
        """Phase 11.4: 在远程节点注销中继转发规则

        用于多跳链路停用：请求中间节点清理转发规则。

        Args:
            psk: 预共享密钥（可选，为 None 时使用 IP 认证）
            chain_tag: 链路标识

        Returns:
            是否成功清理
        """
        try:
            data = {
                "chain_tag": chain_tag,
            }
            # Phase 11-Fix.D: 仅在提供 PSK 时包含
            if psk:
                data["psk"] = psk
            result = self._make_request("POST", "/api/relay-routing/unregister", data=data)
            success = result.get("success", False)

            if success:
                logging.info(f"[tunnel-api] 中继路由已注销: 链路='{chain_tag}' ({self.node_tag})")
            else:
                logging.warning(f"[tunnel-api] 中继路由注销失败 ({self.node_tag}): {result.get('message')}")

            return success

        except TunnelAPIError as e:
            logging.error(f"[tunnel-api] 注销中继路由失败 ({self.node_tag}): {e}")
            return False

    def request_complete_handshake(
        self,
        pairing_id: str,
        local_node_tag: str,
        local_node_description: str,
        local_endpoint: str,
        local_tunnel_ip: str,
        wg_public_key: str,
        api_port: Optional[int] = None,  # Phase 11-Fix.K
    ) -> dict:
        """Phase 11-Tunnel: 请求完成配对握手

        通过已建立的隧道调用远程节点的 complete-handshake API，
        通知远程节点完成配对流程。

        Args:
            pairing_id: 配对 ID（用于匹配 pending_pairing）
            local_node_tag: 本节点标识
            local_node_description: 本节点描述
            local_endpoint: 本节点端点（对方可连接的地址）
            local_tunnel_ip: 本节点隧道 IP
            wg_public_key: 本节点 WireGuard 公钥
            api_port: 本节点 API 端口（Phase 11-Fix.K，默认 36000）

        Returns:
            API 响应字典，包含 success 和 message 字段
        """
        try:
            data = {
                "pairing_id": pairing_id,
                "node_tag": local_node_tag,
                "node_description": local_node_description,
                "endpoint": local_endpoint,
                "tunnel_ip": local_tunnel_ip,
                "wg_public_key": wg_public_key,
                "api_port": api_port,  # Phase 11-Fix.K: 传递 API 端口
            }

            result = self._make_request("POST", "/api/peer-tunnel/complete-handshake", data=data)
            success = result.get("success", False)

            if success:
                logging.info(f"[tunnel-api] 握手完成成功 ({self.node_tag})")
            else:
                logging.warning(f"[tunnel-api] 握手完成失败 ({self.node_tag}): {result.get('message')}")

            return result

        except TunnelAPIError as e:
            logging.error(f"[tunnel-api] 完成握手失败 ({self.node_tag}): {e}")
            return {"success": False, "message": str(e)}

    # ============ Phase 11-Cascade: 对等节点事件通知 ============

    def send_peer_event(
        self,
        event_id: str,
        event_type: str,
        source_node: str,
        target_node: Optional[str] = None,
        ttl: int = 3,
        reason: str = "",
        details: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Phase 11-Cascade: 发送对等节点事件通知

        通用方法，用于发送 delete/disconnect/broadcast 事件。

        Args:
            event_id: 事件唯一 ID (UUID v4)，用于幂等性去重
            event_type: 事件类型 ('delete', 'disconnect', 'broadcast')
            source_node: 事件发起节点标识
            target_node: 目标节点标识 (broadcast 必填)
            ttl: 广播跳数限制 (0 表示不转发)
            reason: 事件原因描述
            details: 附加信息

        Returns:
            API 响应字典，包含 success、message、idempotent 等字段
        """
        try:
            data = {
                "event_id": event_id,
                "event_type": event_type,
                "source_node": source_node,
                "ttl": ttl,
                "reason": reason,
            }
            if target_node:
                data["target_node"] = target_node
            if details:
                data["details"] = details

            result = self._make_request("POST", "/api/peer-tunnel/peer-event", data=data)
            success = result.get("success", False)
            idempotent = result.get("idempotent", False)

            if success:
                if idempotent:
                    logging.debug(f"[tunnel-api] 事件已处理 (幂等): {event_type} -> {self.node_tag}")
                else:
                    logging.info(f"[tunnel-api] 事件通知成功: {event_type} -> {self.node_tag}")
            else:
                logging.warning(
                    f"[tunnel-api] 事件通知失败: {event_type} -> {self.node_tag}: {result.get('message')}"
                )

            return result

        except TunnelAPIError as e:
            logging.error(f"[tunnel-api] 发送事件失败 ({self.node_tag}): {e}")
            return {"success": False, "message": str(e)}

    def send_delete_event(
        self,
        event_id: str,
        source_node: str,
        reason: str = "deleted",
        ttl: int = 3,
    ) -> bool:
        """Phase 11-Cascade: 发送删除通知

        通知远程节点：我们已删除它，它应该清理与我们的连接。

        Args:
            event_id: 事件唯一 ID (UUID v4)
            source_node: 事件发起节点（通常是本节点）
            reason: 删除原因
            ttl: 广播跳数

        Returns:
            是否成功发送
        """
        result = self.send_peer_event(
            event_id=event_id,
            event_type="delete",
            source_node=source_node,
            reason=reason,
            ttl=ttl,
        )
        return result.get("success", False)

    def send_disconnect_event(
        self,
        event_id: str,
        source_node: str,
        reason: str = "disconnected",
    ) -> bool:
        """Phase 11-Cascade: 发送断开通知

        通知远程节点：我们临时断开隧道（可能会重连）。

        Args:
            event_id: 事件唯一 ID (UUID v4)
            source_node: 事件发起节点
            reason: 断开原因

        Returns:
            是否成功发送
        """
        result = self.send_peer_event(
            event_id=event_id,
            event_type="disconnect",
            source_node=source_node,
            reason=reason,
            ttl=0,  # 断开事件不需要广播
        )
        return result.get("success", False)

    def send_broadcast_event(
        self,
        event_id: str,
        source_node: str,
        target_node: str,
        reason: str = "node_unavailable",
        ttl: int = 2,
    ) -> bool:
        """Phase 11-Cascade: 发送广播通知

        通知远程节点：某个节点已不可用（级联通知）。

        Args:
            event_id: 事件唯一 ID (UUID v4)
            source_node: 原始事件来源节点
            target_node: 不可用的节点标识
            reason: 原因描述
            ttl: 剩余广播跳数

        Returns:
            是否成功发送
        """
        result = self.send_peer_event(
            event_id=event_id,
            event_type="broadcast",
            source_node=source_node,
            target_node=target_node,
            reason=reason,
            ttl=ttl,
        )
        return result.get("success", False)

    def send_port_change(
        self,
        event_id: str,
        source_node: str,
        new_port: int,
    ) -> bool:
        """Phase C (端口变更通知): 发送端口变更通知

        通知远程节点：我们的 API 端口即将更改。

        Args:
            event_id: 事件唯一 ID (UUID v4)
            source_node: 事件发起节点（通常是本节点）
            new_port: 新的 API 端口号 (1-65535)

        Returns:
            是否成功发送
        """
        # 验证端口有效性（bool 是 int 子类，需显式排除）
        if not isinstance(new_port, int) or isinstance(new_port, bool) or new_port < 1 or new_port > 65535:
            logging.warning(f"[tunnel-api] 无效的端口号: {new_port}")
            return False

        result = self.send_peer_event(
            event_id=event_id,
            event_type="port_change",
            source_node=source_node,
            reason="api_port_change",
            details={"new_port": new_port},
            ttl=0,  # 端口变更事件不需要级联广播
        )
        return result.get("success", False)


class TunnelAPIClientManager:
    """隧道 API 客户端管理器

    管理到多个节点的 API 客户端连接，支持缓存和重用。
    使用 LRU (Least Recently Used) 策略限制缓存大小。
    """

    # 最大缓存客户端数量
    MAX_CACHE_SIZE = 100

    def __init__(self, db):
        """初始化管理器

        Args:
            db: DatabaseManager 实例
        """
        self.db = db
        # 使用 OrderedDict 实现 LRU 缓存
        self._clients: OrderedDict[str, TunnelAPIClient] = OrderedDict()

    def get_client(self, node_tag: str) -> Optional[TunnelAPIClient]:
        """获取指定节点的 API 客户端

        如果客户端不存在，会从数据库加载节点信息并创建。
        使用 LRU 策略管理缓存：访问时移到末尾，新增时检查大小限制。

        Phase 10.2: 根据隧道类型选择连接方式：
        - WireGuard 隧道：直接 HTTP 连接到隧道 IP
        - Xray 隧道：通过 SOCKS5 代理连接

        Args:
            node_tag: 节点标识

        Returns:
            TunnelAPIClient 实例，或 None 如果节点不存在或配置无效
        """
        # 检查缓存，如果存在则移到末尾（标记为最近使用）
        if node_tag in self._clients:
            self._clients.move_to_end(node_tag)
            return self._clients[node_tag]

        # 从数据库加载节点信息
        node = self.db.get_peer_node(node_tag)
        if not node:
            logging.warning(f"[tunnel-api-mgr] 节点不存在: {node_tag}")
            return None

        # 检查隧道是否已连接
        if node.get("tunnel_status") != "connected":
            logging.warning(f"[tunnel-api-mgr] 隧道未连接: {node_tag}")
            return None

        # Phase A (端口变更通知): 动态构建隧道 API 端点
        # 不再依赖存储的 tunnel_api_endpoint，而是从 tunnel_remote_ip + api_port 动态构建
        # 这解决了当节点更改 api_port 后，缓存的 tunnel_api_endpoint 过时的问题
        tunnel_remote_ip = node.get("tunnel_remote_ip")
        if not tunnel_remote_ip:
            logging.warning(f"[tunnel-api-mgr] 节点缺少 tunnel_remote_ip: {node_tag}")
            return None
        # Phase A 审核修复: 验证端口范围 (注意: bool 是 int 子类，需显式排除)
        api_port = node.get("api_port")
        if not isinstance(api_port, int) or isinstance(api_port, bool) or api_port < 1 or api_port > 65535:
            api_port = 36000
        tunnel_api_endpoint = f"{tunnel_remote_ip}:{api_port}"

        # 获取隧道类型（默认 wireguard）
        tunnel_type = node.get("tunnel_type", "wireguard")

        # 获取 Xray SOCKS 端口和 UUID（仅 Xray 隧道需要）
        socks_port: Optional[int] = None
        peer_uuid: Optional[str] = None
        if tunnel_type == "xray":
            socks_port = node.get("xray_socks_port")
            if not socks_port or not _validate_socks_port(socks_port):
                logging.warning(
                    f"[tunnel-api-mgr] Xray 隧道 {node_tag} 缺少有效的 SOCKS 端口 "
                    f"(xray_socks_port={socks_port})，无法创建客户端"
                )
                return None
            # 获取用于身份标识的 UUID（我们用来连接对方的 UUID）
            peer_uuid = node.get("xray_uuid")

        # 创建客户端
        client = TunnelAPIClient(
            node_tag=node_tag,
            tunnel_endpoint=tunnel_api_endpoint,
            tunnel_type=tunnel_type,
            socks_port=socks_port,
            peer_uuid=peer_uuid,
        )

        # LRU 缓存清理：如果达到上限，移除最久未使用的客户端
        while len(self._clients) >= self.MAX_CACHE_SIZE:
            oldest_key, _ = self._clients.popitem(last=False)
            logging.debug(f"[tunnel-api-mgr] LRU 缓存清理: 移除 {oldest_key}")

        # 缓存客户端
        self._clients[node_tag] = client

        route_via = f"SOCKS5:{socks_port}" if socks_port else "direct"
        logging.info(f"[tunnel-api-mgr] 创建客户端: {node_tag} -> {tunnel_api_endpoint} ({route_via})")
        return client

    def invalidate_client(self, node_tag: str):
        """使客户端缓存失效

        当节点断开或配置变更时调用。

        Args:
            node_tag: 节点标识
        """
        if node_tag in self._clients:
            del self._clients[node_tag]
            logging.debug(f"[tunnel-api-mgr] 客户端缓存失效: {node_tag}")

    def invalidate_all(self):
        """使所有客户端缓存失效"""
        self._clients.clear()
        logging.debug("[tunnel-api-mgr] 所有客户端缓存已清除")

    def get_terminal_egress_list(self, chain_hops: List[str]) -> List[EgressInfo]:
        """获取链路终端节点的出口列表

        Args:
            chain_hops: 链路节点列表（最后一个是终端节点）

        Returns:
            终端节点的出口列表
        """
        if not chain_hops:
            return []

        terminal_node = chain_hops[-1]
        client = self.get_client(terminal_node)

        if not client:
            logging.warning(f"[tunnel-api-mgr] 无法获取终端节点客户端: {terminal_node}")
            return []

        try:
            return client.get_egress_list()
        except TunnelAPIError as e:
            logging.error(f"[tunnel-api-mgr] 获取终端出口列表失败: {e}")
            return []

    # ============ Phase 11-Cascade: 广播事件到所有连接的 peer ============

    def broadcast_delete_event(
        self,
        deleted_node: str,
        source_node: str,
        reason: str = "deleted",
        ttl: int = 3,
        exclude_nodes: Optional[List[str]] = None,
    ) -> Dict[str, bool]:
        """Phase 11-Cascade: 向所有连接的 peer 广播删除事件

        当删除一个节点时，通知所有其他连接的节点该节点已不可用。

        Args:
            deleted_node: 被删除的节点标识
            source_node: 事件发起节点（通常是本节点）
            reason: 删除原因
            ttl: 广播跳数限制
            exclude_nodes: 要排除的节点列表（不向这些节点发送）

        Returns:
            字典，key 为节点标识，value 为是否成功发送
        """
        import uuid as uuid_module

        results: Dict[str, bool] = {}
        exclude_set = set(exclude_nodes or [])
        exclude_set.add(deleted_node)  # 不向被删除的节点发送
        exclude_set.add(source_node)   # 不向自己发送

        # 获取所有已连接的 peer
        peers = self.db.get_peer_nodes()

        for peer in peers:
            peer_tag = peer.get("tag")

            # 跳过排除的节点
            if peer_tag in exclude_set:
                continue

            # 跳过未连接的节点
            if peer.get("tunnel_status") != "connected":
                continue

            # 获取客户端
            client = self.get_client(peer_tag)
            if not client:
                results[peer_tag] = False
                continue

            # 发送广播事件
            event_id = str(uuid_module.uuid4())
            try:
                success = client.send_broadcast_event(
                    event_id=event_id,
                    source_node=source_node,
                    target_node=deleted_node,
                    reason=reason,
                    ttl=ttl,
                )
                results[peer_tag] = success
            except Exception as e:
                logging.error(f"[tunnel-api-mgr] 广播到 {peer_tag} 失败: {e}")
                results[peer_tag] = False

        # 统计结果
        success_count = sum(1 for v in results.values() if v)
        total_count = len(results)
        logging.info(
            f"[tunnel-api-mgr] 广播删除事件完成: {deleted_node}, "
            f"成功 {success_count}/{total_count}"
        )

        return results

    def notify_peer_delete(
        self,
        peer_tag: str,
        source_node: str,
        reason: str = "deleted",
    ) -> bool:
        """Phase 11-Cascade: 通知单个 peer 删除事件

        在删除节点前通过隧道通知对方，让对方清理连接。

        Args:
            peer_tag: 要通知的节点
            source_node: 事件发起节点
            reason: 删除原因

        Returns:
            是否成功通知
        """
        import uuid as uuid_module

        client = self.get_client(peer_tag)
        if not client:
            logging.warning(f"[tunnel-api-mgr] 无法获取客户端通知 {peer_tag}")
            return False

        event_id = str(uuid_module.uuid4())
        try:
            return client.send_delete_event(
                event_id=event_id,
                source_node=source_node,
                reason=reason,
                ttl=3,
            )
        except Exception as e:
            logging.error(f"[tunnel-api-mgr] 通知 {peer_tag} 失败: {e}")
            return False

    def broadcast_port_change(
        self,
        source_node: str,
        new_port: int,
        exclude_nodes: Optional[List[str]] = None,
    ) -> Dict[str, bool]:
        """Phase C (端口变更通知): 广播端口变更到所有已连接的 peer

        遍历所有隧道状态为 connected 的 peer，通知它们本节点的 API 端口即将更改。

        Args:
            source_node: 事件发起节点（通常是本节点）
            new_port: 新的 API 端口号 (1-65535)
            exclude_nodes: 排除的节点列表（可选）

        Returns:
            每个节点的通知结果字典 {node_tag: success}
        """
        import uuid as uuid_module

        # 验证端口有效性（bool 是 int 子类，需显式排除）
        if not isinstance(new_port, int) or isinstance(new_port, bool) or new_port < 1 or new_port > 65535:
            logging.warning(f"[tunnel-api-mgr] 无效的端口号，取消广播: {new_port}")
            return {}

        results: Dict[str, bool] = {}
        exclude_set = set(exclude_nodes or [])

        # 获取所有 peer 节点
        peers = self.db.get_peer_nodes()

        for peer in peers:
            peer_tag = peer.get("tag")

            # 跳过排除的节点
            if peer_tag in exclude_set:
                continue

            # 跳过未连接的节点
            if peer.get("tunnel_status") != "connected":
                continue

            # 获取客户端
            client = self.get_client(peer_tag)
            if not client:
                results[peer_tag] = False
                continue

            # 发送端口变更事件
            event_id = str(uuid_module.uuid4())
            try:
                success = client.send_port_change(
                    event_id=event_id,
                    source_node=source_node,
                    new_port=new_port,
                )
                results[peer_tag] = success
            except Exception as e:
                logging.error(f"[tunnel-api-mgr] 通知 {peer_tag} 端口变更失败: {e}")
                results[peer_tag] = False

        # 统计结果
        success_count = sum(1 for v in results.values() if v)
        total_count = len(results)
        logging.info(
            f"[tunnel-api-mgr] 广播端口变更完成: new_port={new_port}, "
            f"成功 {success_count}/{total_count}"
        )

        return results

#!/usr/bin/env python3
"""V2Ray URI Parser - Parse vmess://, vless://, trojan:// share links"""

import base64
import json
import re
from typing import Dict, Optional, Any, List
from urllib.parse import urlparse, parse_qs, unquote


def parse_vmess_uri(uri: str) -> Dict[str, Any]:
    """Parse vmess://base64(json) URI

    VMess URI format: vmess://base64(json)
    JSON structure: {
        "v": "2",
        "ps": "remark",
        "add": "server.com",
        "port": "443",
        "id": "uuid",
        "aid": "0",
        "scy": "auto",
        "net": "ws",
        "type": "none",
        "host": "example.com",
        "path": "/path",
        "tls": "tls",
        "sni": "example.com",
        "alpn": "h2,http/1.1",
        "fp": "chrome"
    }
    """
    if not uri.startswith("vmess://"):
        raise ValueError("Invalid VMess URI: must start with vmess://")

    b64_data = uri[8:]

    # Handle URL-safe base64 and padding
    b64_data = b64_data.replace("-", "+").replace("_", "/")
    # Add padding if needed
    padding = 4 - len(b64_data) % 4
    if padding != 4:
        b64_data += "=" * padding

    try:
        json_str = base64.b64decode(b64_data).decode("utf-8")
    except Exception as e:
        raise ValueError(f"Failed to decode VMess base64: {e}")

    try:
        data = json.loads(json_str)
    except json.JSONDecodeError as e:
        raise ValueError(f"Failed to parse VMess JSON: {e}")

    result = {
        "protocol": "vmess",
        "server": data.get("add"),
        "server_port": int(data.get("port", 443)),
        "uuid": data.get("id"),
        "alter_id": int(data.get("aid", 0)),
        "security": data.get("scy", "auto"),
        "description": data.get("ps", ""),
    }

    if not result["server"]:
        raise ValueError("VMess URI missing server address")
    if not result["uuid"]:
        raise ValueError("VMess URI missing UUID")

    # TLS
    tls_type = data.get("tls", "")
    result["tls_enabled"] = tls_type in ("tls", "xtls")
    result["tls_sni"] = data.get("sni") or data.get("host") or result["server"]

    # ALPN
    alpn_str = data.get("alpn", "")
    if alpn_str:
        result["tls_alpn"] = [a.strip() for a in alpn_str.split(",") if a.strip()]

    # uTLS fingerprint
    if data.get("fp"):
        result["tls_fingerprint"] = data.get("fp")

    # Transport
    net = data.get("net", "tcp")
    result["transport_type"] = _normalize_transport_type(net)
    result["transport_config"] = _build_transport_config_from_vmess(net, data)

    return result


def parse_vless_uri(uri: str) -> Dict[str, Any]:
    """Parse vless://uuid@server:port?params#remark URI

    Example: vless://uuid@server:443?type=ws&security=tls&path=/path&host=example.com&sni=example.com&fp=chrome#remark
    """
    if not uri.startswith("vless://"):
        raise ValueError("Invalid VLESS URI: must start with vless://")

    # Parse: vless://uuid@server:port?params#remark
    parsed = urlparse(uri)

    uuid = parsed.username
    server = parsed.hostname
    port = parsed.port or 443
    params = parse_qs(parsed.query)
    remark = unquote(parsed.fragment) if parsed.fragment else ""

    if not uuid:
        raise ValueError("VLESS URI missing UUID")
    if not server:
        raise ValueError("VLESS URI missing server")

    result = {
        "protocol": "vless",
        "server": server,
        "server_port": port,
        "uuid": uuid,
        "description": remark,
        "flow": _get_param(params, "flow"),
    }

    # TLS/REALITY
    security = _get_param(params, "security", "none")
    result["tls_enabled"] = security in ("tls", "xtls")
    result["reality_enabled"] = security == "reality"
    result["tls_sni"] = _get_param(params, "sni") or server
    result["tls_fingerprint"] = _get_param(params, "fp")
    result["tls_allow_insecure"] = _get_param(params, "allowInsecure") == "1"

    # ALPN
    alpn_str = _get_param(params, "alpn", "")
    if alpn_str:
        result["tls_alpn"] = [a.strip() for a in alpn_str.split(",") if a.strip()]

    # REALITY
    if result["reality_enabled"]:
        result["reality_public_key"] = _get_param(params, "pbk")
        result["reality_short_id"] = _get_param(params, "sid")

    # Transport
    transport_type = _get_param(params, "type", "tcp")
    result["transport_type"] = _normalize_transport_type(transport_type)
    result["transport_config"] = _build_transport_config_from_params(transport_type, params)

    return result


def parse_trojan_uri(uri: str) -> Dict[str, Any]:
    """Parse trojan://password@server:port?params#remark URI

    Example: trojan://password@server:443?sni=example.com&type=ws&path=/path#remark
    """
    if not uri.startswith("trojan://"):
        raise ValueError("Invalid Trojan URI: must start with trojan://")

    parsed = urlparse(uri)

    password = unquote(parsed.username) if parsed.username else ""
    server = parsed.hostname
    port = parsed.port or 443
    params = parse_qs(parsed.query)
    remark = unquote(parsed.fragment) if parsed.fragment else ""

    if not password:
        raise ValueError("Trojan URI missing password")
    if not server:
        raise ValueError("Trojan URI missing server")

    result = {
        "protocol": "trojan",
        "server": server,
        "server_port": port,
        "password": password,
        "description": remark,
        "tls_enabled": True,  # Trojan requires TLS
    }

    result["tls_sni"] = _get_param(params, "sni") or _get_param(params, "peer") or server
    result["tls_fingerprint"] = _get_param(params, "fp")
    result["tls_allow_insecure"] = _get_param(params, "allowInsecure") == "1"

    # ALPN
    alpn_str = _get_param(params, "alpn", "")
    if alpn_str:
        result["tls_alpn"] = [a.strip() for a in alpn_str.split(",") if a.strip()]

    # Transport
    transport_type = _get_param(params, "type", "tcp")
    result["transport_type"] = _normalize_transport_type(transport_type)
    result["transport_config"] = _build_transport_config_from_params(transport_type, params)

    return result


def parse_v2ray_uri(uri: str) -> Dict[str, Any]:
    """Auto-detect and parse V2Ray URI

    Supports: vmess://, vless://, trojan://
    """
    uri = uri.strip()

    if uri.startswith("vmess://"):
        return parse_vmess_uri(uri)
    elif uri.startswith("vless://"):
        return parse_vless_uri(uri)
    elif uri.startswith("trojan://"):
        return parse_trojan_uri(uri)
    else:
        raise ValueError(f"Unsupported URI scheme. Expected vmess://, vless://, or trojan://")


def generate_vmess_uri(config: Dict[str, Any]) -> str:
    """Generate vmess:// URI from config

    Args:
        config: Dict with protocol, server, server_port, uuid, etc.

    Returns:
        vmess://base64 URI
    """
    vmess_obj = {
        "v": "2",
        "ps": config.get("description", ""),
        "add": config.get("server", ""),
        "port": str(config.get("server_port", 443)),
        "id": config.get("uuid", ""),
        "aid": str(config.get("alter_id", 0)),
        "scy": config.get("security", "auto"),
        "net": config.get("transport_type", "tcp"),
        "type": "none",
        "host": "",
        "path": "",
        "tls": "tls" if config.get("tls_enabled") else "",
        "sni": config.get("tls_sni", ""),
        "alpn": ",".join(config.get("tls_alpn", [])) if config.get("tls_alpn") else "",
        "fp": config.get("tls_fingerprint", ""),
    }

    # Transport config
    transport_config = config.get("transport_config", {})
    if transport_config:
        if config.get("transport_type") == "ws":
            vmess_obj["path"] = transport_config.get("path", "/")
            if transport_config.get("headers", {}).get("Host"):
                vmess_obj["host"] = transport_config["headers"]["Host"]
        elif config.get("transport_type") == "grpc":
            vmess_obj["path"] = transport_config.get("service_name", "")
            if transport_config.get("authority"):
                vmess_obj["host"] = transport_config["authority"]
        elif config.get("transport_type") == "h2":
            vmess_obj["path"] = transport_config.get("path", "/")
            if transport_config.get("host"):
                vmess_obj["host"] = transport_config["host"][0] if isinstance(transport_config["host"], list) else transport_config["host"]

    json_str = json.dumps(vmess_obj, separators=(",", ":"))
    b64_str = base64.urlsafe_b64encode(json_str.encode()).decode().rstrip("=")

    return f"vmess://{b64_str}"


def generate_vless_uri(config: Dict[str, Any]) -> str:
    """Generate vless:// URI from config"""
    uuid = config.get("uuid", "")
    server = config.get("server", "")
    port = config.get("server_port", 443)
    remark = config.get("description", "")

    params = []

    # Security
    if config.get("reality_enabled"):
        params.append("security=reality")
        if config.get("reality_public_key"):
            params.append(f"pbk={config['reality_public_key']}")
        if config.get("reality_short_id"):
            params.append(f"sid={config['reality_short_id']}")
    elif config.get("tls_enabled"):
        params.append("security=tls")
    else:
        params.append("security=none")

    # Transport
    transport_type = config.get("transport_type", "tcp")
    if transport_type != "tcp":
        params.append(f"type={transport_type}")

    # Transport config
    transport_config = config.get("transport_config", {})
    if transport_config:
        if transport_type == "ws":
            if transport_config.get("path"):
                params.append(f"path={transport_config['path']}")
            if transport_config.get("headers", {}).get("Host"):
                params.append(f"host={transport_config['headers']['Host']}")
        elif transport_type == "grpc":
            if transport_config.get("service_name"):
                params.append(f"serviceName={transport_config['service_name']}")
            if transport_config.get("authority"):
                params.append(f"authority={transport_config['authority']}")
        elif transport_type == "h2":
            if transport_config.get("path"):
                params.append(f"path={transport_config['path']}")
            if transport_config.get("host"):
                host = transport_config["host"]
                if isinstance(host, list):
                    host = host[0] if host else ""
                if host:
                    params.append(f"host={host}")
        elif transport_type == "httpupgrade":
            if transport_config.get("path"):
                params.append(f"path={transport_config['path']}")
            if transport_config.get("host"):
                params.append(f"host={transport_config['host']}")
        elif transport_type == "xhttp":
            if transport_config.get("path"):
                params.append(f"path={transport_config['path']}")
            if transport_config.get("mode"):
                params.append(f"mode={transport_config['mode']}")
            if transport_config.get("host"):
                params.append(f"host={transport_config['host']}")

    # TLS options
    if config.get("tls_sni"):
        params.append(f"sni={config['tls_sni']}")
    if config.get("tls_fingerprint"):
        params.append(f"fp={config['tls_fingerprint']}")
    if config.get("tls_alpn"):
        params.append(f"alpn={','.join(config['tls_alpn'])}")

    # Flow
    if config.get("flow"):
        params.append(f"flow={config['flow']}")

    query = "&".join(params)
    fragment = f"#{remark}" if remark else ""

    return f"vless://{uuid}@{server}:{port}?{query}{fragment}"


def generate_trojan_uri(config: Dict[str, Any]) -> str:
    """Generate trojan:// URI from config"""
    password = config.get("password", "")
    server = config.get("server", "")
    port = config.get("server_port", 443)
    remark = config.get("description", "")

    params = []

    # Transport
    transport_type = config.get("transport_type", "tcp")
    if transport_type != "tcp":
        params.append(f"type={transport_type}")

    # Transport config
    transport_config = config.get("transport_config", {})
    if transport_config:
        if transport_type == "ws":
            if transport_config.get("path"):
                params.append(f"path={transport_config['path']}")
            if transport_config.get("headers", {}).get("Host"):
                params.append(f"host={transport_config['headers']['Host']}")
        elif transport_type == "grpc":
            if transport_config.get("service_name"):
                params.append(f"serviceName={transport_config['service_name']}")
            if transport_config.get("authority"):
                params.append(f"authority={transport_config['authority']}")
        elif transport_type == "h2":
            if transport_config.get("path"):
                params.append(f"path={transport_config['path']}")
            if transport_config.get("host"):
                host = transport_config["host"]
                if isinstance(host, list):
                    host = host[0] if host else ""
                if host:
                    params.append(f"host={host}")
        elif transport_type == "httpupgrade":
            if transport_config.get("path"):
                params.append(f"path={transport_config['path']}")
            if transport_config.get("host"):
                params.append(f"host={transport_config['host']}")
        elif transport_type == "xhttp":
            if transport_config.get("path"):
                params.append(f"path={transport_config['path']}")
            if transport_config.get("mode"):
                params.append(f"mode={transport_config['mode']}")
            if transport_config.get("host"):
                params.append(f"host={transport_config['host']}")

    # TLS options
    if config.get("tls_sni"):
        params.append(f"sni={config['tls_sni']}")
    if config.get("tls_fingerprint"):
        params.append(f"fp={config['tls_fingerprint']}")
    if config.get("tls_alpn"):
        params.append(f"alpn={','.join(config['tls_alpn'])}")
    if config.get("tls_allow_insecure"):
        params.append("allowInsecure=1")

    query = "&".join(params) if params else ""
    query_str = f"?{query}" if query else ""
    fragment = f"#{remark}" if remark else ""

    return f"trojan://{password}@{server}:{port}{query_str}{fragment}"


def generate_v2ray_uri(config: Dict[str, Any]) -> str:
    """Generate share URI based on protocol type"""
    protocol = config.get("protocol", "")

    if protocol == "vmess":
        return generate_vmess_uri(config)
    elif protocol == "vless":
        return generate_vless_uri(config)
    elif protocol == "trojan":
        return generate_trojan_uri(config)
    else:
        raise ValueError(f"Unsupported protocol: {protocol}")


# ============ Helper Functions ============


def _get_param(params: Dict, key: str, default: str = None) -> Optional[str]:
    """Get first value from query params"""
    values = params.get(key, [])
    return values[0] if values else default


def _normalize_transport_type(net: str) -> str:
    """Normalize transport type name"""
    mapping = {
        "tcp": "tcp",
        "ws": "ws",
        "websocket": "ws",
        "grpc": "grpc",
        "gun": "grpc",
        "h2": "h2",
        "http": "http",
        "quic": "quic",
        "httpupgrade": "httpupgrade",
        "splithttp": "splithttp",
        "xhttp": "xhttp",
    }
    return mapping.get(net.lower(), "tcp")


def _build_transport_config_from_vmess(net: str, data: Dict) -> Optional[Dict]:
    """Build transport config from VMess JSON data"""
    net = net.lower()

    if net in ("ws", "websocket"):
        config = {"path": data.get("path", "/")}
        host = data.get("host", "")
        if host:
            config["headers"] = {"Host": host}
        return config

    elif net in ("grpc", "gun"):
        service_name = data.get("path", "") or data.get("serviceName", "")
        # In VMess JSON, gRPC authority is typically in the "host" field
        authority = data.get("host", "") or data.get("authority", "")
        config = {}
        if service_name:
            config["service_name"] = service_name
        if authority:
            config["authority"] = authority
        return config if config else None

    elif net == "h2":
        config = {"path": data.get("path", "/")}
        host = data.get("host", "")
        if host:
            config["host"] = [host]
        return config

    elif net == "http":
        config = {}
        host = data.get("host", "")
        if host:
            config["host"] = [host]
        path = data.get("path", "")
        if path:
            config["path"] = path
        return config if config else None

    elif net == "quic":
        config = {}
        quic_security = data.get("quicSecurity") or data.get("type", "none")
        if quic_security and quic_security != "none":
            config["security"] = quic_security
            if data.get("key"):
                config["key"] = data["key"]
        return config if config else None

    return None


def _build_transport_config_from_params(transport_type: str, params: Dict) -> Optional[Dict]:
    """Build transport config from URI query params"""
    transport_type = transport_type.lower()

    if transport_type in ("ws", "websocket"):
        config = {"path": _get_param(params, "path", "/")}
        host = _get_param(params, "host")
        if host:
            config["headers"] = {"Host": host}
        return config

    elif transport_type in ("grpc", "gun"):
        service_name = _get_param(params, "serviceName") or _get_param(params, "path", "")
        mode = _get_param(params, "mode")
        # authority is the gRPC Authority header (伪装域名/host)
        authority = _get_param(params, "authority") or _get_param(params, "host")
        if service_name or mode or authority:
            config = {}
            if service_name:
                config["service_name"] = service_name
            if mode:
                config["mode"] = mode
            if authority:
                config["authority"] = authority
            return config
        return None

    elif transport_type == "h2":
        config = {"path": _get_param(params, "path", "/")}
        host = _get_param(params, "host")
        if host:
            config["host"] = [host]
        return config

    elif transport_type == "quic":
        config = {}
        security = _get_param(params, "quicSecurity") or _get_param(params, "headerType", "none")
        if security and security != "none":
            config["security"] = security
            key = _get_param(params, "key")
            if key:
                config["key"] = key
        return config if config else None

    elif transport_type == "httpupgrade":
        config = {"path": _get_param(params, "path", "/")}
        host = _get_param(params, "host")
        if host:
            config["host"] = host
        return config

    elif transport_type == "xhttp":
        config = {"path": _get_param(params, "path", "/")}
        mode = _get_param(params, "mode")
        if mode and mode in ("auto", "packet-up", "stream-up", "stream-one"):
            config["mode"] = mode
        host = _get_param(params, "host")
        if host:
            config["host"] = host
        return config

    return None


# ============ Testing ============


if __name__ == "__main__":
    # Test URIs
    test_uris = [
        # VMess
        "vmess://eyJ2IjoiMiIsInBzIjoidGVzdCIsImFkZCI6InRlc3Quc2VydmVyLmNvbSIsInBvcnQiOiI0NDMiLCJpZCI6IjEyMzQ1Njc4LTEyMzQtMTIzNC0xMjM0LTEyMzQ1Njc4OTBhYiIsImFpZCI6IjAiLCJzY3kiOiJhdXRvIiwibmV0Ijoid3MiLCJ0eXBlIjoibm9uZSIsImhvc3QiOiJleGFtcGxlLmNvbSIsInBhdGgiOiIvcGF0aCIsInRscyI6InRscyIsInNuaSI6ImV4YW1wbGUuY29tIn0=",
        # VLESS
        "vless://12345678-1234-1234-1234-1234567890ab@test.server.com:443?type=ws&security=tls&path=/path&host=example.com&sni=example.com&fp=chrome#test",
        # Trojan
        "trojan://password123@test.server.com:443?sni=example.com&type=ws&path=/path#test",
    ]

    print("=== V2Ray URI Parser Test ===\n")

    for uri in test_uris:
        try:
            result = parse_v2ray_uri(uri)
            print(f"Protocol: {result['protocol']}")
            print(f"Server: {result['server']}:{result['server_port']}")
            print(f"Description: {result.get('description', '')}")
            print(f"TLS: {result.get('tls_enabled', False)}")
            print(f"Transport: {result.get('transport_type', 'tcp')}")
            print(f"Transport Config: {result.get('transport_config', {})}")
            print()

            # Test round-trip
            regenerated = generate_v2ray_uri(result)
            print(f"Regenerated URI: {regenerated[:80]}...")
            print("-" * 60)
            print()
        except Exception as e:
            print(f"Error parsing: {e}")
            print()

    print("Done!")

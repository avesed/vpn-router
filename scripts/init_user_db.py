#!/usr/bin/env python3
"""初始化用户配置数据库（用户数据）- 支持 SQLCipher 加密"""
import argparse
import json
import os
import subprocess
from pathlib import Path
import sys
import yaml

# SQLCipher 加密数据库支持
try:
    from pysqlcipher3 import dbapi2 as sqlite3
    HAS_SQLCIPHER = True
except ImportError:
    import sqlite3
    HAS_SQLCIPHER = False


# 用户数据库结构
USER_DB_SCHEMA = """
-- 路由规则表（用户自定义）
CREATE TABLE IF NOT EXISTS routing_rules (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    rule_type TEXT NOT NULL,  -- 'domain', 'domain_keyword', 'ip', 'domain_list', 'country'
    target TEXT NOT NULL,      -- 目标值（域名、IP CIDR、列表ID、国家代码等）
    outbound TEXT NOT NULL,    -- 出口标签
    tag TEXT,                  -- 规则组标签/名称
    priority INTEGER DEFAULT 0,
    enabled INTEGER DEFAULT 1,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_rule_enabled ON routing_rules(enabled, priority);
CREATE INDEX IF NOT EXISTS idx_rule_outbound ON routing_rules(outbound);
CREATE INDEX IF NOT EXISTS idx_rule_tag ON routing_rules(tag);

-- 出口配置表
CREATE TABLE IF NOT EXISTS outbounds (
    tag TEXT PRIMARY KEY,
    type TEXT NOT NULL,  -- 'wireguard', 'direct', 'block'
    description TEXT,
    config TEXT,         -- JSON 格式配置
    enabled INTEGER DEFAULT 1,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_outbound_enabled ON outbounds(enabled);

-- WireGuard 服务器配置表（入口）
CREATE TABLE IF NOT EXISTS wireguard_server (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    interface_name TEXT NOT NULL DEFAULT 'wg-ingress',
    address TEXT NOT NULL,
    listen_port INTEGER NOT NULL DEFAULT 36100,
    mtu INTEGER DEFAULT 1420,
    private_key TEXT NOT NULL,
    default_outbound TEXT,                -- 此入口的默认出口（NULL=使用全局默认）
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- WireGuard 对等点（客户端）表
CREATE TABLE IF NOT EXISTS wireguard_peers (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL UNIQUE,
    public_key TEXT NOT NULL UNIQUE,
    allowed_ips TEXT NOT NULL,
    preshared_key TEXT,
    allow_lan INTEGER DEFAULT 0,      -- 是否允许访问本地局域网
    lan_subnet TEXT,                  -- 局域网子网 (如 192.168.1.0/24)
    default_outbound TEXT,            -- 此客户端的默认出口（NULL=使用入口默认或全局默认）
    enabled INTEGER DEFAULT 1,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
-- [DB-001] 添加 enabled 索引以优化查询性能
CREATE INDEX IF NOT EXISTS idx_wireguard_peers_enabled ON wireguard_peers(enabled);

-- PIA profiles 表
CREATE TABLE IF NOT EXISTS pia_profiles (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL UNIQUE,
    description TEXT,
    region_id TEXT NOT NULL,
    custom_dns TEXT,          -- 自定义 DNS (空=PIA DNS 10.0.0.241, 或如 1.1.1.1, tls://dns.google)
    -- WireGuard 凭证字段
    server_cn TEXT,           -- 服务器域名/CN
    server_ip TEXT,           -- 服务器 IP
    server_port INTEGER,      -- 服务器端口
    server_public_key TEXT,   -- 服务器公钥
    peer_ip TEXT,             -- 分配的对等点 IP
    server_virtual_ip TEXT,   -- 服务器虚拟 IP
    private_key TEXT,         -- 客户端私钥
    public_key TEXT,          -- 客户端公钥
    enabled INTEGER DEFAULT 1,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
-- [DB-001] 添加 enabled 索引和覆盖索引以优化查询性能
CREATE INDEX IF NOT EXISTS idx_pia_profiles_enabled ON pia_profiles(enabled);
CREATE INDEX IF NOT EXISTS idx_pia_profiles_enabled_name ON pia_profiles(enabled, name);

-- 自定义分类项目表（域名列表）
CREATE TABLE IF NOT EXISTS custom_category_items (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    category_id TEXT NOT NULL,
    item_id TEXT NOT NULL UNIQUE,
    name TEXT NOT NULL,
    domains TEXT NOT NULL,  -- JSON 数组格式
    domain_count INTEGER DEFAULT 0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_category_items_category ON custom_category_items(category_id);
CREATE INDEX IF NOT EXISTS idx_category_items_item_id ON custom_category_items(item_id);

-- 用户设置表
CREATE TABLE IF NOT EXISTS settings (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- 自定义出口表（WireGuard 出口）
CREATE TABLE IF NOT EXISTS custom_egress (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    tag TEXT NOT NULL UNIQUE,
    description TEXT DEFAULT '',
    server TEXT NOT NULL,
    port INTEGER DEFAULT 51820,
    private_key TEXT NOT NULL,
    public_key TEXT NOT NULL,
    address TEXT NOT NULL,
    mtu INTEGER DEFAULT 1420,
    dns TEXT DEFAULT '1.1.1.1',
    pre_shared_key TEXT,
    reserved TEXT,  -- JSON 数组格式，如 [0, 0, 0]
    enabled INTEGER DEFAULT 1,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_custom_egress_tag ON custom_egress(tag);
-- [DB-001] 添加 enabled 索引和覆盖索引以优化查询性能
CREATE INDEX IF NOT EXISTS idx_custom_egress_enabled ON custom_egress(enabled);
CREATE INDEX IF NOT EXISTS idx_custom_egress_enabled_tag ON custom_egress(enabled, tag);

-- Direct 出口表（绑定特定接口/IP 的直连出口）
CREATE TABLE IF NOT EXISTS direct_egress (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    tag TEXT NOT NULL UNIQUE,
    description TEXT DEFAULT '',
    bind_interface TEXT,              -- 绑定的网络接口 (eth0, eth1, macvlan0, etc.)
    inet4_bind_address TEXT,          -- 绑定的 IPv4 地址
    inet6_bind_address TEXT,          -- 绑定的 IPv6 地址
    enabled INTEGER DEFAULT 1,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_direct_egress_tag ON direct_egress(tag);
-- [DB-001] 添加 enabled 索引以优化查询性能
CREATE INDEX IF NOT EXISTS idx_direct_egress_enabled ON direct_egress(enabled);

-- OpenVPN 出口表（通过 SOCKS5 代理桥接）
CREATE TABLE IF NOT EXISTS openvpn_egress (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    tag TEXT NOT NULL UNIQUE,
    description TEXT DEFAULT '',

    -- 连接配置
    protocol TEXT DEFAULT 'udp',      -- udp 或 tcp
    remote_host TEXT NOT NULL,        -- 远程服务器地址
    remote_port INTEGER DEFAULT 1194, -- 远程服务器端口

    -- 证书和认证（PEM 格式）
    ca_cert TEXT NOT NULL,            -- CA 证书
    client_cert TEXT,                 -- 客户端证书（可选）
    client_key TEXT,                  -- 客户端私钥（可选）
    tls_auth TEXT,                    -- TLS Auth 密钥（可选）
    tls_crypt TEXT,                   -- TLS Crypt 密钥（可选，与 tls_auth 二选一）
    crl_verify TEXT,                  -- CRL 证书吊销列表（可选）
    auth_user TEXT,                   -- 用户名认证（可选）
    auth_pass TEXT,                   -- 密码认证（可选）

    -- OpenVPN 选项
    cipher TEXT DEFAULT 'AES-256-GCM',
    auth TEXT DEFAULT 'SHA256',
    compress TEXT,                    -- 压缩算法（lzo, lz4, etc.）
    extra_options TEXT,               -- 额外的 OpenVPN 选项（JSON 数组）

    -- TUN 设备（直接绑定接口，无需 SOCKS5 代理）
    tun_device TEXT UNIQUE,           -- TUN 设备名 (tun10, tun11, ...)

    -- 遗留字段（保留用于回滚，下个版本删除）
    socks_port INTEGER UNIQUE,        -- 本地 SOCKS5 代理端口（已废弃）

    -- 状态
    enabled INTEGER DEFAULT 1,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_openvpn_egress_tag ON openvpn_egress(tag);
CREATE INDEX IF NOT EXISTS idx_openvpn_egress_enabled ON openvpn_egress(enabled);

-- V2Ray 出口表（支持 VMess, VLESS, Trojan）
CREATE TABLE IF NOT EXISTS v2ray_egress (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    tag TEXT NOT NULL UNIQUE,
    description TEXT DEFAULT '',

    -- 协议类型
    protocol TEXT NOT NULL CHECK(protocol IN ('vmess', 'vless', 'trojan')),

    -- 连接配置
    server TEXT NOT NULL,
    server_port INTEGER NOT NULL DEFAULT 443,

    -- 认证（根据协议使用不同字段）
    uuid TEXT,                            -- VMess/VLESS 的 UUID
    password TEXT,                        -- Trojan 的密码

    -- VMess 特定
    security TEXT DEFAULT 'auto',         -- auto, aes-128-gcm, chacha20-poly1305, none
    alter_id INTEGER DEFAULT 0,           -- 0 = AEAD (推荐)

    -- VLESS 特定
    flow TEXT,                            -- xtls-rprx-vision 等

    -- TLS 配置
    tls_enabled INTEGER DEFAULT 1,
    tls_sni TEXT,                         -- Server Name Indication
    tls_alpn TEXT,                        -- JSON 数组格式，如 ["h2", "http/1.1"]
    tls_allow_insecure INTEGER DEFAULT 0,
    tls_fingerprint TEXT,                 -- uTLS 指纹（chrome, firefox, safari 等）

    -- REALITY 配置（VLESS 专用）
    reality_enabled INTEGER DEFAULT 0,
    reality_public_key TEXT,
    reality_short_id TEXT,

    -- 传输层配置 (JSON 存储完整配置)
    transport_type TEXT DEFAULT 'tcp',    -- tcp, ws, grpc, h2, http, quic, httpupgrade
    transport_config TEXT,                -- JSON 格式的传输层配置

    -- 多路复用
    multiplex_enabled INTEGER DEFAULT 0,
    multiplex_protocol TEXT,              -- smux, yamux, h2mux
    multiplex_max_connections INTEGER,
    multiplex_min_streams INTEGER,
    multiplex_max_streams INTEGER,

    -- SOCKS5 代理（由 Xray 提供，sing-box 连接）
    socks_port INTEGER UNIQUE,            -- 本地 SOCKS5 代理端口 (37101, 37102, ...)

    -- 其他
    enabled INTEGER DEFAULT 1,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_v2ray_egress_tag ON v2ray_egress(tag);
CREATE INDEX IF NOT EXISTS idx_v2ray_egress_protocol ON v2ray_egress(protocol);
CREATE INDEX IF NOT EXISTS idx_v2ray_egress_enabled ON v2ray_egress(enabled);

-- WARP 出口表（Cloudflare WARP via MASQUE 协议）
CREATE TABLE IF NOT EXISTS warp_egress (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    tag TEXT NOT NULL UNIQUE,                 -- 出口标识，如 "warp-main"
    description TEXT DEFAULT '',               -- 描述

    -- 协议配置
    protocol TEXT DEFAULT 'masque',            -- masque / wireguard
    config_path TEXT,                          -- usque/wgcf config 路径
    license_key TEXT,                          -- WARP+ license key（可选）
    account_type TEXT DEFAULT 'free',          -- free / warp+ / teams

    -- 运行模式
    mode TEXT DEFAULT 'socks',                 -- socks / tun
    socks_port INTEGER UNIQUE,                 -- SOCKS5 端口（38001+）

    -- 自定义 Endpoint（指定地区）
    endpoint_v4 TEXT,                          -- 自定义 IPv4 endpoint (如 162.159.193.10:2408)
    endpoint_v6 TEXT,                          -- 自定义 IPv6 endpoint

    -- 状态
    enabled INTEGER DEFAULT 1,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_warp_egress_tag ON warp_egress(tag);
CREATE INDEX IF NOT EXISTS idx_warp_egress_enabled ON warp_egress(enabled);

-- V2Ray 入口服务器配置表（单行，类似 wireguard_server）
-- 使用独立的 Xray 进程 + TUN + TPROXY 架构
CREATE TABLE IF NOT EXISTS v2ray_inbound_config (
    id INTEGER PRIMARY KEY CHECK (id = 1),

    -- 协议类型
    protocol TEXT NOT NULL DEFAULT 'vless' CHECK(protocol IN ('vmess', 'vless', 'trojan')),

    -- 监听配置
    listen_address TEXT DEFAULT '0.0.0.0',
    listen_port INTEGER NOT NULL DEFAULT 443,

    -- TLS 配置（传统 TLS，当 reality_enabled=0 时使用）
    tls_enabled INTEGER DEFAULT 1,
    tls_cert_path TEXT,           -- 证书路径
    tls_key_path TEXT,            -- 私钥路径
    tls_cert_content TEXT,        -- 证书内容（PEM 格式）
    tls_key_content TEXT,         -- 私钥内容（PEM 格式）

    -- XTLS-Vision 配置（VLESS 专用，高性能）
    xtls_vision_enabled INTEGER DEFAULT 0,

    -- REALITY 配置（Xray 专有，无需证书）
    reality_enabled INTEGER DEFAULT 0,
    reality_private_key TEXT,     -- REALITY 服务器私钥
    reality_public_key TEXT,      -- REALITY 服务器公钥（用于客户端配置）
    reality_short_ids TEXT,       -- REALITY Short ID 列表（JSON 数组）
    reality_dest TEXT,            -- REALITY 目标服务器（如 www.microsoft.com:443）
    reality_server_names TEXT,    -- REALITY SNI 列表（JSON 数组）

    -- 传输层配置
    transport_type TEXT DEFAULT 'tcp',
    transport_config TEXT,        -- JSON 格式

    -- VLESS 特定
    fallback_server TEXT,         -- 回落服务器地址
    fallback_port INTEGER,        -- 回落端口

    -- Xray TUN 配置
    tun_device TEXT DEFAULT 'xray-tun0',  -- TUN 设备名
    tun_subnet TEXT DEFAULT '10.24.0.0/24',  -- TUN 子网

    -- 入口绑定出口
    default_outbound TEXT,                -- 此入口的默认出口（NULL=使用全局默认）

    enabled INTEGER DEFAULT 0,    -- 默认禁用
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- V2Ray 用户表（类似 wireguard_peers）
CREATE TABLE IF NOT EXISTS v2ray_users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL UNIQUE,
    email TEXT,                   -- 用于日志标识

    -- 认证信息（根据入口协议使用）
    uuid TEXT,                    -- VMess/VLESS 用户 UUID
    password TEXT,                -- Trojan 密码

    -- VMess 特定
    alter_id INTEGER DEFAULT 0,

    -- VLESS 特定
    flow TEXT,

    enabled INTEGER DEFAULT 1,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_v2ray_users_uuid ON v2ray_users(uuid);
CREATE INDEX IF NOT EXISTS idx_v2ray_users_enabled ON v2ray_users(enabled);

-- 远程规则集表（广告拦截等）
CREATE TABLE IF NOT EXISTS remote_rule_sets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    tag TEXT NOT NULL UNIQUE,
    name TEXT NOT NULL,
    description TEXT,
    url TEXT NOT NULL,
    format TEXT DEFAULT 'adblock',  -- adblock, hosts, domains
    outbound TEXT DEFAULT 'block',
    enabled INTEGER DEFAULT 0,
    priority INTEGER DEFAULT 0,
    category TEXT DEFAULT 'general',  -- general, privacy, regional, security, antiadblock
    region TEXT,  -- cn, de, fr, kr, ru, etc.
    last_updated TIMESTAMP,
    domain_count INTEGER DEFAULT 0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_remote_rule_sets_enabled ON remote_rule_sets(enabled);
CREATE INDEX IF NOT EXISTS idx_remote_rule_sets_category ON remote_rule_sets(category);

-- 管理员认证表（单行）
CREATE TABLE IF NOT EXISTS admin_auth (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    password_hash TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- PIA 凭据表（单行，数据库已加密，无需额外加密）
CREATE TABLE IF NOT EXISTS pia_credentials (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    username TEXT NOT NULL,
    password TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- 出口组表（负载均衡/故障转移）
CREATE TABLE IF NOT EXISTS outbound_groups (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    tag TEXT NOT NULL UNIQUE,
    description TEXT DEFAULT '',
    type TEXT NOT NULL CHECK(type IN ('loadbalance', 'failover')),
    members TEXT NOT NULL,                 -- JSON 数组 ["us-stream", "jp-stream"]
    -- 负载均衡参数
    weights TEXT,                          -- JSON 对象 {"us-stream": 2, "jp-stream": 1}
    -- 健康检查参数
    health_check_url TEXT DEFAULT 'http://www.gstatic.com/generate_204',
    health_check_interval INTEGER DEFAULT 60,   -- 秒
    health_check_timeout INTEGER DEFAULT 5,     -- 秒
    -- 路由表配置（Linux ECMP）
    routing_table INTEGER,                 -- Linux 路由表号 (200+)
    -- 状态
    enabled INTEGER DEFAULT 1,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_outbound_groups_tag ON outbound_groups(tag);
CREATE INDEX IF NOT EXISTS idx_outbound_groups_enabled ON outbound_groups(enabled);

-- 对等节点表（主从服务器管理）
CREATE TABLE IF NOT EXISTS peer_nodes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    tag TEXT NOT NULL UNIQUE,              -- 唯一标识 (node-tokyo)
    name TEXT NOT NULL,                    -- 显示名称
    description TEXT DEFAULT '',

    -- 连接信息
    endpoint TEXT NOT NULL,                -- IP:port 或 域名:port (WireGuard/Xray 隧道端口)
    api_port INTEGER,                      -- API 端口（默认 36000，用于端口映射场景）

    -- PSK 认证（已废弃，保留字段兼容旧数据）
    psk_hash TEXT DEFAULT '',              -- bcrypt 哈希（不再使用，WireGuard 用 IP 认证，Xray 用 UUID 认证）
    psk_encrypted TEXT,                    -- Fernet 加密后的 PSK（不再使用）

    -- 隧道配置
    tunnel_type TEXT DEFAULT 'wireguard' CHECK(tunnel_type IN ('wireguard', 'xray')),
    tunnel_status TEXT DEFAULT 'disconnected' CHECK(tunnel_status IN ('disconnected', 'connecting', 'connected', 'error')),
    tunnel_interface TEXT,                 -- wg-peer-{tag} 或 xray-peer-{tag}
    tunnel_local_ip TEXT,                  -- 本端隧道 IP (10.200.200.1)
    tunnel_remote_ip TEXT,                 -- 对端隧道 IP (10.200.200.2)
    tunnel_port INTEGER,                   -- 本地监听端口
    tunnel_api_endpoint TEXT,              -- 隧道内 API 地址 (如 10.200.200.2:36000)，用于多跳链路通信

    -- WireGuard 专用
    wg_private_key TEXT,
    wg_public_key TEXT,
    wg_peer_public_key TEXT,

    -- Xray 专用
    xray_protocol TEXT DEFAULT 'vless' CHECK(xray_protocol IN ('vless', 'vmess', 'trojan')),
    xray_uuid TEXT,
    xray_socks_port INTEGER,               -- SOCKS5 代理端口

    -- Xray REALITY 配置（本节点作为服务端）
    xray_reality_private_key TEXT,         -- 本节点私钥（x25519）
    xray_reality_public_key TEXT,          -- 本节点公钥（发送给客户端）
    xray_reality_short_id TEXT,            -- Short ID（hex 格式）
    xray_reality_dest TEXT DEFAULT 'www.microsoft.com:443',  -- Dest Server（伪装目标）
    xray_reality_server_names TEXT DEFAULT '["www.microsoft.com"]',  -- Server Names SNI（JSON 数组）

    -- 对端 REALITY 配置（本节点作为客户端连接对端时使用）
    xray_peer_reality_public_key TEXT,     -- 对端公钥（从交换获得）
    xray_peer_reality_short_id TEXT,       -- 对端 Short ID
    xray_peer_reality_dest TEXT,           -- 对端 Dest Server
    xray_peer_reality_server_names TEXT,   -- 对端 Server Names（JSON 数组）

    -- XHTTP 传输配置
    xray_xhttp_path TEXT DEFAULT '/',
    xray_xhttp_mode TEXT DEFAULT 'auto',   -- auto, packet-up, stream-up, stream-one
    xray_xhttp_host TEXT,

    -- 入站监听配置（本节点作为服务端接收对方连接）
    inbound_enabled INTEGER DEFAULT 0,      -- 是否启用入站监听
    inbound_port INTEGER,                   -- 入站监听端口 (36500+)
    inbound_uuid TEXT,                      -- 允许连接的 UUID（对方的 UUID）
    inbound_socks_port INTEGER,             -- SOCKS5 输出端口 (38601+)，sing-box 监听

    -- 对方的入站信息（用于连接到对方的入站）
    peer_inbound_enabled INTEGER DEFAULT 0, -- 对方是否有入站
    peer_inbound_port INTEGER,              -- 对方的入站端口
    peer_inbound_uuid TEXT,                 -- 对方入站的 UUID（用于认证）
    peer_inbound_reality_public_key TEXT,   -- 对方入站的 REALITY 公钥
    peer_inbound_reality_short_id TEXT,     -- 对方入站的 Short ID

    -- 连接模式
    connection_mode TEXT DEFAULT 'outbound' CHECK(connection_mode IN ('outbound', 'inbound')),
    -- outbound: 连接到对端的主隧道端点（默认）
    -- inbound: 连接到对端的入站监听器（需要 peer_inbound_enabled=1）

    -- 双向连接状态 (Phase 11.1)
    bidirectional_status TEXT DEFAULT 'pending' CHECK(bidirectional_status IN ('pending', 'outbound_only', 'bidirectional')),
    -- pending: 等待双向连接
    -- outbound_only: 仅出站连接
    -- bidirectional: 双向连接已建立

    -- 预生成 WireGuard 密钥（用于双向自动连接）
    remote_wg_private_key TEXT,              -- 为远程节点预生成的私钥
    remote_wg_public_key TEXT,               -- 对应的公钥（放入 request code）

    -- 入口绑定出口（来自此节点隧道的流量默认出口）
    default_outbound TEXT,

    -- 状态
    last_seen TIMESTAMP,
    last_error TEXT,
    auto_reconnect INTEGER DEFAULT 1,
    enabled INTEGER DEFAULT 1,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_peer_nodes_tag ON peer_nodes(tag);
CREATE INDEX IF NOT EXISTS idx_peer_nodes_enabled ON peer_nodes(enabled);
CREATE INDEX IF NOT EXISTS idx_peer_nodes_tunnel_status ON peer_nodes(tunnel_status);
-- 注: idx_peer_nodes_enabled_bidirectional 索引在迁移函数中创建（Phase 11.1）
-- 避免现有数据库缺少 bidirectional_status 列时出错
-- 唯一索引防止资源分配竞态条件
CREATE UNIQUE INDEX IF NOT EXISTS idx_peer_nodes_tunnel_local_ip ON peer_nodes(tunnel_local_ip) WHERE tunnel_local_ip IS NOT NULL;
CREATE UNIQUE INDEX IF NOT EXISTS idx_peer_nodes_tunnel_port ON peer_nodes(tunnel_port) WHERE tunnel_port IS NOT NULL;
CREATE UNIQUE INDEX IF NOT EXISTS idx_peer_nodes_xray_socks_port ON peer_nodes(xray_socks_port) WHERE xray_socks_port IS NOT NULL;
-- 注意：inbound_port 和 inbound_socks_port 索引在 migrate_peer_nodes_inbound_fields() 中创建
-- 因为这些是新添加的列，需要先迁移后才能创建索引

-- 待处理配对表（用于离线配对流程）
-- A 节点 generate-pair-request 时创建，B 节点通过隧道 complete-handshake 后删除
CREATE TABLE IF NOT EXISTS pending_pairings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    pairing_id TEXT NOT NULL UNIQUE,       -- 配对标识（base64 hash，用于匹配）
    local_tag TEXT NOT NULL,               -- 本节点标识
    local_endpoint TEXT NOT NULL,          -- 本节点端点 (IP:port)
    tunnel_type TEXT NOT NULL DEFAULT 'wireguard',
    tunnel_local_ip TEXT,                  -- 本端隧道 IP
    tunnel_remote_ip TEXT,                 -- 对端隧道 IP
    tunnel_port INTEGER,                   -- 监听端口
    wg_private_key TEXT,                   -- 本节点私钥
    wg_public_key TEXT,                    -- 本节点公钥
    remote_wg_private_key TEXT,            -- 预生成的对端私钥
    remote_wg_public_key TEXT,             -- 预生成的对端公钥
    interface_name TEXT,                   -- WireGuard 接口名 (wg-pending-xxx)
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP                   -- 过期时间（默认 7 天）
);
CREATE INDEX IF NOT EXISTS idx_pending_pairings_expires ON pending_pairings(expires_at);

-- 多跳链路表
CREATE TABLE IF NOT EXISTS node_chains (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    tag TEXT NOT NULL UNIQUE,              -- 链路标识 (us-via-tokyo)
    name TEXT NOT NULL,
    description TEXT DEFAULT '',

    -- 链路定义 (JSON 数组，按顺序)
    hops TEXT NOT NULL,                    -- ["node-tokyo", "node-us"]

    -- 每跳协议 (JSON)
    hop_protocols TEXT,                    -- {"node-tokyo": "wireguard", "node-us": "xray"}

    -- 入口分流规则 (JSON) - 哪些流量走这条链
    entry_rules TEXT,                      -- {"domain_suffix": ["google.com"], "geoip": ["us"]}

    -- 中继分流规则 (JSON) - 在哪个节点出去
    relay_rules TEXT,                      -- {"node-tokyo": {"exit_domains": ["*.jp"]}}

    -- 终端出口配置（多跳链路架构 v2）
    exit_egress TEXT,                      -- 终端节点的本地出口 tag (如 "us-stream")
    dscp_value INTEGER,                    -- DSCP 标记值 (1-63)，用于 WireGuard 链路流量识别
    chain_mark_type TEXT DEFAULT 'dscp' CHECK(chain_mark_type IN ('dscp', 'xray_email')),
    chain_state TEXT DEFAULT 'inactive' CHECK(chain_state IN ('inactive', 'activating', 'active', 'error')),
    allow_transitive INTEGER DEFAULT 0,    -- Phase 11-Fix.Q: 传递模式验证（只验证第一跳）
    last_error TEXT,                       -- Phase 5: 最后错误信息

    -- 健康状态
    health_status TEXT DEFAULT 'unknown' CHECK(health_status IN ('unknown', 'healthy', 'degraded', 'unhealthy')),
    last_health_check TIMESTAMP,

    -- 下游节点状态（级联通知用）
    downstream_status TEXT DEFAULT 'unknown' CHECK(downstream_status IN ('unknown', 'connected', 'disconnected')),
    disconnected_node TEXT,                -- 记录断开的下游节点 tag

    enabled INTEGER DEFAULT 1,
    priority INTEGER DEFAULT 0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_node_chains_tag ON node_chains(tag);
CREATE INDEX IF NOT EXISTS idx_node_chains_enabled ON node_chains(enabled);
-- 注: idx_node_chains_dscp_value_unique 索引在 migrate_node_chains_chain_fields() 中创建
-- 避免现有数据库缺少 dscp_value 列时出错

-- 链路注册表（记录哪些链经过当前节点，用于级联通知）
CREATE TABLE IF NOT EXISTS chain_registrations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    chain_id TEXT NOT NULL,                -- 链标识（来自上游节点）
    upstream_node_tag TEXT NOT NULL,       -- 上游节点标签
    upstream_endpoint TEXT NOT NULL,       -- 上游节点端点（用于发送通知）
    upstream_psk TEXT NOT NULL,            -- 上游节点 PSK（用于向上游发送通知时的认证）
    downstream_node_tag TEXT NOT NULL,     -- 下游节点标签
    registered_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(chain_id, upstream_node_tag)
);
CREATE INDEX IF NOT EXISTS idx_chain_registrations_chain_id ON chain_registrations(chain_id);
CREATE INDEX IF NOT EXISTS idx_chain_registrations_downstream ON chain_registrations(downstream_node_tag);

-- 中继路由表（链路中的流量转发规则）
CREATE TABLE IF NOT EXISTS relay_routes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    chain_tag TEXT NOT NULL,                    -- 所属链路
    source_peer_tag TEXT NOT NULL,              -- 流量来源节点
    target_peer_tag TEXT NOT NULL,              -- 转发目标节点
    enabled INTEGER DEFAULT 1,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (chain_tag) REFERENCES node_chains(tag),
    UNIQUE(chain_tag, source_peer_tag, target_peer_tag)
);
CREATE INDEX IF NOT EXISTS idx_relay_routes_chain_tag ON relay_routes(chain_tag);
CREATE INDEX IF NOT EXISTS idx_relay_routes_enabled ON relay_routes(enabled);

-- 链路路由表（终端节点的 DSCP/email 到出口映射）
-- 用于多跳链路架构：入口节点标记流量，终端节点根据标记选择出口
CREATE TABLE IF NOT EXISTS chain_routing (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    chain_tag TEXT NOT NULL,               -- 链路标识（与 node_chains.tag 对应）
    mark_value INTEGER NOT NULL,           -- 标记值：DSCP (1-63) 或 routing mark
    mark_type TEXT NOT NULL DEFAULT 'dscp' CHECK(mark_type IN ('dscp', 'xray_email')),
    egress_tag TEXT NOT NULL,              -- 本地出口 tag（如 "us-stream"）
    source_node TEXT,                      -- 注册来源节点 tag（谁注册了这条路由）
    registered_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(chain_tag, mark_value, mark_type)
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_chain_routing_unique_mark ON chain_routing(mark_value, mark_type);
CREATE INDEX IF NOT EXISTS idx_chain_routing_mark ON chain_routing(mark_value, mark_type);
CREATE INDEX IF NOT EXISTS idx_chain_routing_chain_tag ON chain_routing(chain_tag);
CREATE INDEX IF NOT EXISTS idx_chain_routing_egress ON chain_routing(egress_tag);
CREATE INDEX IF NOT EXISTS idx_chain_routing_source_node ON chain_routing(source_node);

-- 终端出口缓存表 (Phase 11.1)
-- 入口节点缓存终端节点的出口列表，避免每次都通过隧道查询
CREATE TABLE IF NOT EXISTS terminal_egress_cache (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    chain_tag TEXT NOT NULL UNIQUE,          -- 链路标识（与 node_chains.tag 对应）
    terminal_node TEXT NOT NULL,             -- 终端节点 tag
    egress_list TEXT NOT NULL,               -- JSON 数组，终端节点的可用出口
    cached_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP                     -- 过期时间（默认 5 分钟）
);
-- 注: chain_tag 上的 UNIQUE 约束已自动创建隐式索引，无需额外索引
CREATE INDEX IF NOT EXISTS idx_terminal_egress_cache_expires ON terminal_egress_cache(expires_at);

-- ============ Phase 11-Cascade: 级联删除通知支持 ============

-- 对等节点事件审计日志
-- 记录所有节点生命周期事件（删除、断开、广播等）
CREATE TABLE IF NOT EXISTS peer_event_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    event_type TEXT NOT NULL CHECK (event_type IN ('delete', 'disconnect', 'broadcast', 'received', 'port_change')),
    peer_tag TEXT NOT NULL,                      -- 相关节点 tag
    event_id TEXT,                               -- 事件唯一 ID (用于幂等性追踪)
    from_node TEXT,                              -- 事件来源节点
    details TEXT,                                -- JSON 格式的额外信息
    source_ip TEXT,                              -- 请求来源 IP
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
);
-- 注: 移除 event_type 索引 (低基数字段，只有 4 种值，索引效率低)
CREATE INDEX IF NOT EXISTS idx_peer_event_log_created_at ON peer_event_log(created_at);
CREATE INDEX IF NOT EXISTS idx_peer_event_log_peer_tag ON peer_event_log(peer_tag);

-- 已删除节点墓碑记录
-- 防止刚删除的节点短期内重新连接
CREATE TABLE IF NOT EXISTS peer_tombstones (
    tag TEXT PRIMARY KEY,                        -- 节点 tag (唯一)
    deleted_at TEXT NOT NULL,                    -- 删除时间 (ISO 8601)
    expires_at TEXT NOT NULL,                    -- 墓碑过期时间 (默认 24 小时后)
    deleted_by TEXT,                             -- 删除来源: 'local' 或远程节点 tag
    reason TEXT,                                 -- 删除原因
    CHECK (expires_at > deleted_at)              -- 确保过期时间晚于删除时间
);
CREATE INDEX IF NOT EXISTS idx_peer_tombstones_expires ON peer_tombstones(expires_at);

-- 已处理的对等事件 (用于幂等性)
-- 防止重复处理相同的事件
CREATE TABLE IF NOT EXISTS processed_peer_events (
    event_id TEXT PRIMARY KEY,                   -- 事件 UUID (唯一)
    processed_at TEXT NOT NULL,                  -- 处理时间 (ISO 8601)
    from_node TEXT NOT NULL,                     -- 事件来源节点
    action TEXT                                  -- 事件动作类型
);
CREATE INDEX IF NOT EXISTS idx_processed_peer_events_time ON processed_peer_events(processed_at)
"""


def init_user_db(db_path: Path, encryption_key: str = None) -> sqlite3.Connection:
    """初始化用户数据库结构

    Args:
        db_path: 数据库文件路径
        encryption_key: SQLCipher 加密密钥（64 字符 hex）

    Returns:
        数据库连接
    """
    print(f"初始化用户数据库: {db_path}")
    if encryption_key and HAS_SQLCIPHER:
        print(f"  使用 SQLCipher 加密 (密钥长度: {len(encryption_key)})")
    elif encryption_key and not HAS_SQLCIPHER:
        print("  警告: 请求加密但 SQLCipher 不可用，使用未加密数据库")

    conn = sqlite3.connect(str(db_path))

    # 应用 SQLCipher 加密密钥
    if encryption_key and HAS_SQLCIPHER:
        conn.execute(f"PRAGMA key = '{encryption_key}'")

    conn.executescript(USER_DB_SCHEMA)
    conn.commit()
    return conn


def migrate_wireguard_peers_lan_fields(conn: sqlite3.Connection):
    """为现有 wireguard_peers 表添加 LAN 访问字段"""
    cursor = conn.cursor()

    # 检查是否需要迁移（检查 allow_lan 列是否存在）
    cursor.execute("PRAGMA table_info(wireguard_peers)")
    columns = {row[1] for row in cursor.fetchall()}

    migrations_done = 0

    if "allow_lan" not in columns:
        cursor.execute("ALTER TABLE wireguard_peers ADD COLUMN allow_lan INTEGER DEFAULT 0")
        migrations_done += 1
        print("✓ 添加 wireguard_peers.allow_lan 字段")

    if "lan_subnet" not in columns:
        cursor.execute("ALTER TABLE wireguard_peers ADD COLUMN lan_subnet TEXT")
        migrations_done += 1
        print("✓ 添加 wireguard_peers.lan_subnet 字段")

    if "default_outbound" not in columns:
        cursor.execute("ALTER TABLE wireguard_peers ADD COLUMN default_outbound TEXT")
        migrations_done += 1
        print("✓ 添加 wireguard_peers.default_outbound 字段")

    if migrations_done > 0:
        conn.commit()
    else:
        print("⊘ wireguard_peers 字段已存在，跳过迁移")


def migrate_openvpn_egress_crl_verify(conn: sqlite3.Connection):
    """为现有 openvpn_egress 表添加 crl_verify 字段"""
    cursor = conn.cursor()

    # 检查 openvpn_egress 表是否存在
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='openvpn_egress'")
    if not cursor.fetchone():
        print("⊘ openvpn_egress 表不存在，跳过 crl_verify 迁移")
        return

    # 检查是否需要迁移（检查 crl_verify 列是否存在）
    cursor.execute("PRAGMA table_info(openvpn_egress)")
    columns = {row[1] for row in cursor.fetchall()}

    if "crl_verify" not in columns:
        cursor.execute("ALTER TABLE openvpn_egress ADD COLUMN crl_verify TEXT")
        conn.commit()
        print("✓ 添加 openvpn_egress.crl_verify 字段")
    else:
        print("⊘ openvpn_egress.crl_verify 字段已存在，跳过迁移")


def migrate_v2ray_inbound_xray_fields(conn: sqlite3.Connection):
    """为现有 v2ray_inbound_config 表添加 Xray/REALITY 相关字段"""
    cursor = conn.cursor()

    # 检查 v2ray_inbound_config 表是否存在
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='v2ray_inbound_config'")
    if not cursor.fetchone():
        print("⊘ v2ray_inbound_config 表不存在，跳过 Xray 字段迁移")
        return

    # 检查现有列
    cursor.execute("PRAGMA table_info(v2ray_inbound_config)")
    columns = {row[1] for row in cursor.fetchall()}

    migrations_done = 0

    # 新增字段列表
    new_fields = [
        ("xtls_vision_enabled", "INTEGER DEFAULT 0"),
        ("reality_enabled", "INTEGER DEFAULT 0"),
        ("reality_private_key", "TEXT"),
        ("reality_public_key", "TEXT"),
        ("reality_short_ids", "TEXT"),
        ("reality_dest", "TEXT"),
        ("reality_server_names", "TEXT"),
        ("tun_device", "TEXT DEFAULT 'xray-tun0'"),
        ("tun_subnet", "TEXT DEFAULT '10.24.0.0/24'"),
    ]

    for field_name, field_type in new_fields:
        if field_name not in columns:
            cursor.execute(f"ALTER TABLE v2ray_inbound_config ADD COLUMN {field_name} {field_type}")
            migrations_done += 1
            print(f"✓ 添加 v2ray_inbound_config.{field_name} 字段")

    if migrations_done > 0:
        conn.commit()
    else:
        print("⊘ v2ray_inbound_config Xray 字段已存在，跳过迁移")


def migrate_v2ray_egress_socks_port(conn: sqlite3.Connection):
    """为现有 v2ray_egress 表添加 socks_port 字段"""
    cursor = conn.cursor()

    # 检查 v2ray_egress 表是否存在
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='v2ray_egress'")
    if not cursor.fetchone():
        print("⊘ v2ray_egress 表不存在，跳过 socks_port 迁移")
        return

    # 检查是否需要迁移（检查 socks_port 列是否存在）
    cursor.execute("PRAGMA table_info(v2ray_egress)")
    columns = {row[1] for row in cursor.fetchall()}

    if "socks_port" not in columns:
        # 注意: SQLite 的 ALTER TABLE 不支持 UNIQUE 约束，只能添加普通列
        # 端口唯一性由 db_helper.get_next_v2ray_egress_socks_port() 保证
        cursor.execute("ALTER TABLE v2ray_egress ADD COLUMN socks_port INTEGER")
        conn.commit()
        print("✓ 添加 v2ray_egress.socks_port 字段")
    else:
        print("⊘ v2ray_egress.socks_port 字段已存在，跳过迁移")


def migrate_admin_auth(conn: sqlite3.Connection):
    """确保 admin_auth 表存在（用于现有数据库迁移）"""
    cursor = conn.cursor()

    # 检查 admin_auth 表是否存在
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='admin_auth'")
    if cursor.fetchone():
        print("⊘ admin_auth 表已存在，跳过迁移")
        return

    # 创建表
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS admin_auth (
            id INTEGER PRIMARY KEY CHECK (id = 1),
            password_hash TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    conn.commit()
    print("✓ 创建 admin_auth 表")


def migrate_warp_egress_protocol(conn: sqlite3.Connection):
    """为现有 warp_egress 表添加 protocol 字段"""
    cursor = conn.cursor()

    # 检查 warp_egress 表是否存在
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='warp_egress'")
    if not cursor.fetchone():
        print("⊘ warp_egress 表不存在，跳过 protocol 迁移")
        return

    # 检查是否需要迁移（检查 protocol 列是否存在）
    cursor.execute("PRAGMA table_info(warp_egress)")
    columns = {row[1] for row in cursor.fetchall()}

    if "protocol" not in columns:
        cursor.execute("ALTER TABLE warp_egress ADD COLUMN protocol TEXT DEFAULT 'masque'")
        conn.commit()
        print("✓ 添加 warp_egress.protocol 字段")
    else:
        print("⊘ warp_egress.protocol 字段已存在，跳过迁移")


def migrate_outbound_groups(conn: sqlite3.Connection):
    """为现有数据库添加 outbound_groups 表（负载均衡/故障转移）"""
    cursor = conn.cursor()

    # 检查 outbound_groups 表是否存在
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='outbound_groups'")
    if cursor.fetchone():
        print("⊘ outbound_groups 表已存在，跳过迁移")
        return

    # 创建表
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS outbound_groups (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            tag TEXT NOT NULL UNIQUE,
            description TEXT DEFAULT '',
            type TEXT NOT NULL CHECK(type IN ('loadbalance', 'failover')),
            members TEXT NOT NULL,
            weights TEXT,
            health_check_url TEXT DEFAULT 'http://www.gstatic.com/generate_204',
            health_check_interval INTEGER DEFAULT 60,
            health_check_timeout INTEGER DEFAULT 5,
            routing_table INTEGER,
            enabled INTEGER DEFAULT 1,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_outbound_groups_tag ON outbound_groups(tag)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_outbound_groups_enabled ON outbound_groups(enabled)")
    conn.commit()
    print("✓ 创建 outbound_groups 表")


def migrate_ingress_default_outbound(conn: sqlite3.Connection):
    """为入口表添加 default_outbound 字段（入口绑定出口）"""
    cursor = conn.cursor()
    migrations_done = 0

    # 1. wireguard_server 表
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='wireguard_server'")
    if cursor.fetchone():
        cursor.execute("PRAGMA table_info(wireguard_server)")
        columns = {row[1] for row in cursor.fetchall()}
        if "default_outbound" not in columns:
            cursor.execute("ALTER TABLE wireguard_server ADD COLUMN default_outbound TEXT")
            migrations_done += 1
            print("✓ 添加 wireguard_server.default_outbound 字段")

    # 2. v2ray_inbound_config 表
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='v2ray_inbound_config'")
    if cursor.fetchone():
        cursor.execute("PRAGMA table_info(v2ray_inbound_config)")
        columns = {row[1] for row in cursor.fetchall()}
        if "default_outbound" not in columns:
            cursor.execute("ALTER TABLE v2ray_inbound_config ADD COLUMN default_outbound TEXT")
            migrations_done += 1
            print("✓ 添加 v2ray_inbound_config.default_outbound 字段")

    if migrations_done > 0:
        conn.commit()
    else:
        print("⊘ 入口 default_outbound 字段已存在，跳过迁移")


def migrate_pia_profiles_custom_dns(conn: sqlite3.Connection):
    """为现有 pia_profiles 表添加 custom_dns 字段（替代 dns_strategy）"""
    cursor = conn.cursor()

    # 检查 pia_profiles 表是否存在
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='pia_profiles'")
    if not cursor.fetchone():
        print("⊘ pia_profiles 表不存在，跳过 custom_dns 迁移")
        return

    # 检查现有列
    cursor.execute("PRAGMA table_info(pia_profiles)")
    columns = {row[1] for row in cursor.fetchall()}

    if "custom_dns" in columns:
        print("⊘ pia_profiles.custom_dns 字段已存在，跳过迁移")
        return

    # 添加 custom_dns 列
    cursor.execute("ALTER TABLE pia_profiles ADD COLUMN custom_dns TEXT")
    print("✓ 添加 pia_profiles.custom_dns 字段")

    conn.commit()


def migrate_openvpn_socks_to_tun(conn: sqlite3.Connection):
    """迁移 OpenVPN 从 socks_port 到 tun_device（直接接口绑定）

    此迁移将 OpenVPN 出口从 SOCKS5 代理桥接架构改为直接 bind_interface 方式，
    与 WireGuard 内核出口架构一致。

    架构变更:
      旧: sing-box → SOCKS outbound (127.0.0.1:37001) → socks5_proxy.py → tun10 → OpenVPN
      新: sing-box → direct outbound (bind_interface: tun10) → tun10 → OpenVPN
    """
    cursor = conn.cursor()

    # 检查 openvpn_egress 表是否存在
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='openvpn_egress'")
    if not cursor.fetchone():
        print("⊘ openvpn_egress 表不存在，跳过 tun_device 迁移")
        return

    # 检查是否需要迁移（检查 tun_device 列是否存在）
    cursor.execute("PRAGMA table_info(openvpn_egress)")
    columns = {row[1] for row in cursor.fetchall()}

    if "tun_device" in columns:
        print("⊘ openvpn_egress.tun_device 字段已存在，跳过迁移")
        return

    # 1. 添加 tun_device 列
    cursor.execute("ALTER TABLE openvpn_egress ADD COLUMN tun_device TEXT")
    print("✓ 添加 openvpn_egress.tun_device 字段")

    # 2. 为现有行分配 tun_device（从 tun10 开始）
    cursor.execute("SELECT id FROM openvpn_egress ORDER BY id")
    rows = cursor.fetchall()

    if rows:
        for i, (row_id,) in enumerate(rows):
            tun_device = f"tun{10 + i}"
            cursor.execute(
                "UPDATE openvpn_egress SET tun_device = ? WHERE id = ?",
                (tun_device, row_id)
            )
        print(f"✓ 为 {len(rows)} 个 OpenVPN 出口分配 tun_device")

    conn.commit()


def migrate_peer_nodes_tables(conn: sqlite3.Connection):
    """为现有数据库添加 peer_nodes 和 node_chains 表"""
    cursor = conn.cursor()

    # 检查 peer_nodes 表是否存在
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='peer_nodes'")
    if not cursor.fetchone():
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS peer_nodes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                tag TEXT NOT NULL UNIQUE,
                name TEXT NOT NULL,
                description TEXT DEFAULT '',
                endpoint TEXT NOT NULL,
                psk_hash TEXT DEFAULT '',
                psk_encrypted TEXT,
                tunnel_type TEXT DEFAULT 'wireguard' CHECK(tunnel_type IN ('wireguard', 'xray')),
                tunnel_status TEXT DEFAULT 'disconnected' CHECK(tunnel_status IN ('disconnected', 'connecting', 'connected', 'error')),
                tunnel_interface TEXT,
                tunnel_local_ip TEXT,
                tunnel_remote_ip TEXT,
                tunnel_port INTEGER,
                wg_private_key TEXT,
                wg_public_key TEXT,
                wg_peer_public_key TEXT,
                xray_protocol TEXT DEFAULT 'vless' CHECK(xray_protocol IN ('vless', 'vmess', 'trojan')),
                xray_uuid TEXT,
                xray_socks_port INTEGER,
                default_outbound TEXT,
                last_seen TIMESTAMP,
                last_error TEXT,
                auto_reconnect INTEGER DEFAULT 1,
                enabled INTEGER DEFAULT 1,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_peer_nodes_tag ON peer_nodes(tag)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_peer_nodes_enabled ON peer_nodes(enabled)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_peer_nodes_tunnel_status ON peer_nodes(tunnel_status)")
        # 唯一索引防止资源分配竞态条件
        cursor.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_peer_nodes_tunnel_local_ip ON peer_nodes(tunnel_local_ip) WHERE tunnel_local_ip IS NOT NULL")
        cursor.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_peer_nodes_tunnel_port ON peer_nodes(tunnel_port) WHERE tunnel_port IS NOT NULL")
        cursor.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_peer_nodes_xray_socks_port ON peer_nodes(xray_socks_port) WHERE xray_socks_port IS NOT NULL")
        print("✓ 创建 peer_nodes 表")
    else:
        # 检查是否需要添加 psk_encrypted 列
        cursor.execute("PRAGMA table_info(peer_nodes)")
        columns = {row[1] for row in cursor.fetchall()}
        if "psk_encrypted" not in columns:
            cursor.execute("ALTER TABLE peer_nodes ADD COLUMN psk_encrypted TEXT")
            print("✓ 添加 peer_nodes.psk_encrypted 列")
        else:
            print("⊘ peer_nodes 表已存在，跳过")

    # 检查 node_chains 表是否存在
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='node_chains'")
    if not cursor.fetchone():
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS node_chains (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                tag TEXT NOT NULL UNIQUE,
                name TEXT NOT NULL,
                description TEXT DEFAULT '',
                hops TEXT NOT NULL,
                hop_protocols TEXT,
                entry_rules TEXT,
                relay_rules TEXT,
                health_status TEXT DEFAULT 'unknown' CHECK(health_status IN ('unknown', 'healthy', 'degraded', 'unhealthy')),
                last_health_check TIMESTAMP,
                downstream_status TEXT DEFAULT 'unknown' CHECK(downstream_status IN ('unknown', 'connected', 'disconnected')),
                disconnected_node TEXT,
                enabled INTEGER DEFAULT 1,
                priority INTEGER DEFAULT 0,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_node_chains_tag ON node_chains(tag)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_node_chains_enabled ON node_chains(enabled)")
        print("✓ 创建 node_chains 表")
    else:
        # 检查是否需要添加级联通知相关列
        cursor.execute("PRAGMA table_info(node_chains)")
        columns = {row[1] for row in cursor.fetchall()}
        if "downstream_status" not in columns:
            cursor.execute("ALTER TABLE node_chains ADD COLUMN downstream_status TEXT DEFAULT 'unknown'")
            print("✓ 添加 node_chains.downstream_status 列")
        if "disconnected_node" not in columns:
            cursor.execute("ALTER TABLE node_chains ADD COLUMN disconnected_node TEXT")
            print("✓ 添加 node_chains.disconnected_node 列")
        # Phase 5: last_error 列
        if "last_error" not in columns:
            cursor.execute("ALTER TABLE node_chains ADD COLUMN last_error TEXT")
            print("✓ 添加 node_chains.last_error 列")
        if "downstream_status" in columns and "disconnected_node" in columns:
            print("⊘ node_chains 表已存在，跳过")

    # 检查 chain_registrations 表是否存在
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='chain_registrations'")
    if not cursor.fetchone():
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS chain_registrations (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                chain_id TEXT NOT NULL,
                upstream_node_tag TEXT NOT NULL,
                upstream_endpoint TEXT NOT NULL,
                upstream_psk TEXT NOT NULL,
                downstream_node_tag TEXT NOT NULL,
                registered_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(chain_id, upstream_node_tag)
            )
        """)
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_chain_registrations_chain_id ON chain_registrations(chain_id)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_chain_registrations_downstream ON chain_registrations(downstream_node_tag)")
        print("✓ 创建 chain_registrations 表")
    else:
        # 检查是否需要添加 upstream_psk 列
        cursor.execute("PRAGMA table_info(chain_registrations)")
        columns = [row[1] for row in cursor.fetchall()]
        if "upstream_psk" not in columns:
            cursor.execute("ALTER TABLE chain_registrations ADD COLUMN upstream_psk TEXT DEFAULT ''")
            print("✓ 添加 chain_registrations.upstream_psk 字段")
        else:
            print("⊘ chain_registrations 表已存在，跳过")

    conn.commit()


def migrate_peer_nodes_inbound_fields(conn: sqlite3.Connection):
    """为 peer_nodes 表添加入站监听配置字段

    支持双向对等连接和中继功能:
    - 入站监听配置（本节点作为服务端）：启用标志、端口、允许的 UUID
    - 对方入站信息（用于连接到对方的入站）：对方端口、公钥、Short ID
    """
    cursor = conn.cursor()

    # 检查 peer_nodes 表是否存在
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='peer_nodes'")
    if not cursor.fetchone():
        print("⊘ peer_nodes 表不存在，跳过入站字段迁移")
        return

    # 检查现有列
    cursor.execute("PRAGMA table_info(peer_nodes)")
    columns = {row[1] for row in cursor.fetchall()}

    migrations_done = 0

    # 入站监听配置字段（本节点作为服务端）
    inbound_server_fields = [
        ("inbound_enabled", "INTEGER DEFAULT 0"),
        ("inbound_port", "INTEGER"),
        ("inbound_uuid", "TEXT"),
        ("inbound_socks_port", "INTEGER"),  # SOCKS5 输出端口，sing-box 监听
    ]

    # 对方入站信息字段（用于连接到对方的入站）
    peer_inbound_fields = [
        ("peer_inbound_enabled", "INTEGER DEFAULT 0"),
        ("peer_inbound_port", "INTEGER"),
        ("peer_inbound_uuid", "TEXT"),  # 对方入站的 UUID（用于认证）
        ("peer_inbound_reality_public_key", "TEXT"),
        ("peer_inbound_reality_short_id", "TEXT"),
    ]

    all_fields = inbound_server_fields + peer_inbound_fields

    for field_name, field_type in all_fields:
        if field_name not in columns:
            cursor.execute(f"ALTER TABLE peer_nodes ADD COLUMN {field_name} {field_type}")
            migrations_done += 1
            print(f"✓ 添加 peer_nodes.{field_name} 字段")

    if migrations_done > 0:
        # 创建唯一索引防止端口冲突
        try:
            cursor.execute("""
                CREATE UNIQUE INDEX IF NOT EXISTS idx_peer_nodes_inbound_port
                ON peer_nodes(inbound_port) WHERE inbound_port IS NOT NULL
            """)
            cursor.execute("""
                CREATE UNIQUE INDEX IF NOT EXISTS idx_peer_nodes_inbound_socks_port
                ON peer_nodes(inbound_socks_port) WHERE inbound_socks_port IS NOT NULL
            """)
            print("✓ 创建入站端口唯一索引")
        except Exception as e:
            print(f"⊘ 创建索引时出错（可能已存在）: {e}")

        conn.commit()
        print(f"✓ peer_nodes 入站字段迁移完成（{migrations_done} 个字段）")
    else:
        print("⊘ peer_nodes 入站字段已存在，跳过迁移")


def migrate_relay_routes_table(conn: sqlite3.Connection):
    """为现有数据库添加 relay_routes 表（中继路由）"""
    cursor = conn.cursor()

    # 检查 relay_routes 表是否存在
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='relay_routes'")
    if cursor.fetchone():
        print("⊘ relay_routes 表已存在，跳过迁移")
        return

    # 创建表
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS relay_routes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            chain_tag TEXT NOT NULL,
            source_peer_tag TEXT NOT NULL,
            target_peer_tag TEXT NOT NULL,
            enabled INTEGER DEFAULT 1,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            UNIQUE(chain_tag, source_peer_tag, target_peer_tag)
        )
    """)
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_relay_routes_chain_tag ON relay_routes(chain_tag)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_relay_routes_enabled ON relay_routes(enabled)")
    conn.commit()
    print("✓ 创建 relay_routes 表")


def migrate_peer_nodes_xray_reality_fields(conn: sqlite3.Connection):
    """为 peer_nodes 表添加 REALITY 和 XHTTP 配置字段

    支持 VLESS+XHTTP+REALITY 协议组合:
    - REALITY 配置（本节点作为服务端）：私钥、公钥、Short ID、Dest、ServerNames
    - 对端 REALITY 配置（本节点作为客户端）：对端公钥、Short ID、Dest、ServerNames
    - XHTTP 传输配置：Path、Mode、Host
    """
    cursor = conn.cursor()

    # 检查 peer_nodes 表是否存在
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='peer_nodes'")
    if not cursor.fetchone():
        print("⊘ peer_nodes 表不存在，跳过 REALITY 字段迁移")
        return

    # 检查现有列
    cursor.execute("PRAGMA table_info(peer_nodes)")
    columns = {row[1] for row in cursor.fetchall()}

    migrations_done = 0

    # REALITY 配置字段（本节点作为服务端）
    reality_server_fields = [
        ("xray_reality_private_key", "TEXT"),
        ("xray_reality_public_key", "TEXT"),
        ("xray_reality_short_id", "TEXT"),
        ("xray_reality_dest", "TEXT DEFAULT 'www.microsoft.com:443'"),
        ("xray_reality_server_names", "TEXT DEFAULT '[\"www.microsoft.com\"]'"),
    ]

    # 对端 REALITY 配置字段（本节点作为客户端）
    reality_peer_fields = [
        ("xray_peer_reality_public_key", "TEXT"),
        ("xray_peer_reality_short_id", "TEXT"),
        ("xray_peer_reality_dest", "TEXT"),
        ("xray_peer_reality_server_names", "TEXT"),
    ]

    # XHTTP 传输配置字段
    xhttp_fields = [
        ("xray_xhttp_path", "TEXT DEFAULT '/'"),
        ("xray_xhttp_mode", "TEXT DEFAULT 'auto'"),
        ("xray_xhttp_host", "TEXT"),
    ]

    all_fields = reality_server_fields + reality_peer_fields + xhttp_fields

    for field_name, field_type in all_fields:
        if field_name not in columns:
            cursor.execute(f"ALTER TABLE peer_nodes ADD COLUMN {field_name} {field_type}")
            migrations_done += 1
            print(f"✓ 添加 peer_nodes.{field_name} 字段")

    if migrations_done > 0:
        conn.commit()
        print(f"✓ peer_nodes REALITY/XHTTP 字段迁移完成（{migrations_done} 个字段）")
    else:
        print("⊘ peer_nodes REALITY/XHTTP 字段已存在，跳过迁移")


def migrate_peer_nodes_api_port(conn: sqlite3.Connection):
    """为 peer_nodes 表添加 api_port 字段

    用于支持端口映射场景，允许 API 端口与隧道端口不同
    """
    cursor = conn.cursor()

    # 检查 peer_nodes 表是否存在
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='peer_nodes'")
    if not cursor.fetchone():
        print("⊘ peer_nodes 表不存在，跳过 api_port 迁移")
        return

    # 检查 api_port 列是否存在
    cursor.execute("PRAGMA table_info(peer_nodes)")
    columns = {row[1] for row in cursor.fetchall()}

    if "api_port" not in columns:
        cursor.execute("ALTER TABLE peer_nodes ADD COLUMN api_port INTEGER")
        conn.commit()
        print("✓ 添加 peer_nodes.api_port 字段")
    else:
        print("⊘ peer_nodes.api_port 字段已存在，跳过迁移")


def migrate_peer_nodes_connection_mode(conn: sqlite3.Connection):
    """为 peer_nodes 表添加 connection_mode 字段

    用于支持双向连接：
    - outbound: 连接到对端的主隧道端点（默认行为）
    - inbound: 连接到对端的入站监听器（需要对端启用 inbound）
    """
    cursor = conn.cursor()

    # 检查 peer_nodes 表是否存在
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='peer_nodes'")
    if not cursor.fetchone():
        print("⊘ peer_nodes 表不存在，跳过 connection_mode 迁移")
        return

    # 检查 connection_mode 列是否存在
    cursor.execute("PRAGMA table_info(peer_nodes)")
    columns = {row[1] for row in cursor.fetchall()}

    if "connection_mode" not in columns:
        cursor.execute("""
            ALTER TABLE peer_nodes ADD COLUMN connection_mode TEXT DEFAULT 'outbound'
            CHECK(connection_mode IN ('outbound', 'inbound'))
        """)
        conn.commit()
        print("✓ 添加 peer_nodes.connection_mode 字段")
    else:
        print("⊘ peer_nodes.connection_mode 字段已存在，跳过迁移")


def migrate_peer_nodes_tunnel_api_endpoint(conn: sqlite3.Connection):
    """为 peer_nodes 表添加 tunnel_api_endpoint 字段

    用于多跳链路架构：隧道建立后，通过隧道内 IP 访问远程节点 API
    例如：10.200.200.2:36000（隧道对端的 API 地址）
    """
    cursor = conn.cursor()

    # 检查 peer_nodes 表是否存在
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='peer_nodes'")
    if not cursor.fetchone():
        print("⊘ peer_nodes 表不存在，跳过 tunnel_api_endpoint 迁移")
        return

    # 检查 tunnel_api_endpoint 列是否存在
    cursor.execute("PRAGMA table_info(peer_nodes)")
    columns = {row[1] for row in cursor.fetchall()}

    if "tunnel_api_endpoint" not in columns:
        cursor.execute("ALTER TABLE peer_nodes ADD COLUMN tunnel_api_endpoint TEXT")
        conn.commit()
        print("✓ 添加 peer_nodes.tunnel_api_endpoint 字段")
    else:
        print("⊘ peer_nodes.tunnel_api_endpoint 字段已存在，跳过迁移")


def migrate_node_chains_chain_fields(conn: sqlite3.Connection):
    """为 node_chains 表添加多跳链路架构 v2 字段

    新增字段支持：
    - exit_egress: 终端节点的本地出口 tag
    - dscp_value: DSCP 标记值 (1-63)
    - chain_mark_type: 标记类型 (dscp/xray_email)
    - chain_state: 链路状态 (inactive/activating/active/error)
    """
    cursor = conn.cursor()

    # 检查 node_chains 表是否存在
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='node_chains'")
    if not cursor.fetchone():
        print("⊘ node_chains 表不存在，跳过链路字段迁移")
        return

    # 检查现有列
    cursor.execute("PRAGMA table_info(node_chains)")
    columns = {row[1] for row in cursor.fetchall()}

    migrations_done = 0

    # 多跳链路架构 v2 字段
    chain_fields = [
        ("exit_egress", "TEXT"),
        ("dscp_value", "INTEGER"),
        ("chain_mark_type", "TEXT DEFAULT 'dscp'"),
        ("chain_state", "TEXT DEFAULT 'inactive'"),
        ("allow_transitive", "INTEGER DEFAULT 0"),  # Phase 11-Fix.Q: 传递模式验证
        ("last_error", "TEXT"),  # Phase 5: 错误原因记录
    ]

    for field_name, field_type in chain_fields:
        if field_name not in columns:
            cursor.execute(f"ALTER TABLE node_chains ADD COLUMN {field_name} {field_type}")
            migrations_done += 1
            print(f"✓ 添加 node_chains.{field_name} 字段")

    if migrations_done > 0:
        # 创建 DSCP 值 UNIQUE 索引（防止并发分配冲突）
        # 使用 partial index：仅对非 NULL 的 dscp_value 强制唯一约束
        # 这允许 xray_email 类型的链路不使用 DSCP（dscp_value=NULL）
        try:
            # 先删除旧的非唯一索引（如果存在）
            cursor.execute("DROP INDEX IF EXISTS idx_node_chains_dscp_value")
            # 创建新的 UNIQUE partial index
            cursor.execute("""
                CREATE UNIQUE INDEX IF NOT EXISTS idx_node_chains_dscp_value_unique
                ON node_chains(dscp_value) WHERE dscp_value IS NOT NULL
            """)
            print("✓ 创建 node_chains.dscp_value UNIQUE 索引")
        except Exception as e:
            print(f"⊘ 创建索引时出错: {e}")

        conn.commit()
        print(f"✓ node_chains 链路字段迁移完成（{migrations_done} 个字段）")
    else:
        # 字段已存在，但仍需确保索引是 UNIQUE 的
        # 处理从旧版非唯一索引升级的情况
        try:
            # 检查是否存在旧的非唯一索引
            cursor.execute("""
                SELECT name FROM sqlite_master
                WHERE type='index' AND name='idx_node_chains_dscp_value'
            """)
            if cursor.fetchone():
                cursor.execute("DROP INDEX idx_node_chains_dscp_value")
                cursor.execute("""
                    CREATE UNIQUE INDEX IF NOT EXISTS idx_node_chains_dscp_value_unique
                    ON node_chains(dscp_value) WHERE dscp_value IS NOT NULL
                """)
                conn.commit()
                print("✓ 升级 node_chains.dscp_value 索引为 UNIQUE")
            else:
                print("⊘ node_chains 链路字段已存在，跳过迁移")
        except Exception as e:
            print(f"⊘ 升级索引时出错: {e}")


def migrate_chain_routing_table(conn: sqlite3.Connection):
    """为现有数据库添加 chain_routing 表

    用于多跳链路架构：终端节点根据 DSCP/email 标记选择本地出口
    - 入口节点设置 DSCP 标记
    - 中继节点透传 DSCP（不修改）
    - 终端节点读取 DSCP 并路由到对应出口
    """
    cursor = conn.cursor()

    # 检查 chain_routing 表是否存在
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='chain_routing'")
    table_exists = cursor.fetchone() is not None
    if table_exists:
        print("⊘ chain_routing 表已存在，跳过创建")

    # 创建表
    if not table_exists:
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS chain_routing (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                chain_tag TEXT NOT NULL,
                mark_value INTEGER NOT NULL,
                mark_type TEXT NOT NULL DEFAULT 'dscp' CHECK(mark_type IN ('dscp', 'xray_email')),
                egress_tag TEXT NOT NULL,
                source_node TEXT,
                registered_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(chain_tag, mark_value, mark_type)
            )
        """)

    try:
        cursor.execute(
            "CREATE UNIQUE INDEX IF NOT EXISTS idx_chain_routing_unique_mark ON chain_routing(mark_value, mark_type)"
        )
        print("✓ 创建 chain_routing 唯一索引 (mark_value, mark_type)")
    except sqlite3.IntegrityError as e:
        raise RuntimeError(
            "Duplicate chain_routing marks detected; clean up duplicates before migration"
        ) from e

    cursor.execute("CREATE INDEX IF NOT EXISTS idx_chain_routing_mark ON chain_routing(mark_value, mark_type)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_chain_routing_chain_tag ON chain_routing(chain_tag)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_chain_routing_egress ON chain_routing(egress_tag)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_chain_routing_source_node ON chain_routing(source_node)")
    conn.commit()
    if table_exists:
        print("✓ 更新 chain_routing 索引")
    else:
        print("✓ 创建 chain_routing 表")


def migrate_peer_nodes_bidirectional_fields(conn: sqlite3.Connection):
    """为 peer_nodes 表添加双向连接字段 (Phase 11.1)

    支持离线配对后自动双向连接:
    - bidirectional_status: 双向连接状态 (pending/outbound_only/bidirectional)
    - remote_wg_private_key: 为远程节点预生成的 WireGuard 私钥
    - remote_wg_public_key: 对应的公钥（放入 request code）
    """
    cursor = conn.cursor()

    # 检查 peer_nodes 表是否存在
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='peer_nodes'")
    if not cursor.fetchone():
        print("⊘ peer_nodes 表不存在，跳过双向连接字段迁移")
        return

    # 检查现有列
    cursor.execute("PRAGMA table_info(peer_nodes)")
    columns = {row[1] for row in cursor.fetchall()}

    migrations_done = 0

    # 双向连接字段
    bidirectional_fields = [
        ("bidirectional_status", "TEXT DEFAULT 'pending'"),
        ("remote_wg_private_key", "TEXT"),
        ("remote_wg_public_key", "TEXT"),
    ]

    for field_name, field_type in bidirectional_fields:
        if field_name not in columns:
            cursor.execute(f"ALTER TABLE peer_nodes ADD COLUMN {field_name} {field_type}")
            migrations_done += 1
            print(f"✓ 添加 peer_nodes.{field_name} 字段")

    if migrations_done > 0:
        conn.commit()
        print(f"✓ peer_nodes 双向连接字段迁移完成（{migrations_done} 个字段）")

    # 创建复合索引优化双向连接查询 (enabled, bidirectional_status)
    # 用于 get_peers_pending_bidirectional() 等查询
    try:
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_peer_nodes_enabled_bidirectional
            ON peer_nodes(enabled, bidirectional_status)
        """)
        conn.commit()
        print("✓ 创建 peer_nodes (enabled, bidirectional_status) 复合索引")
    except Exception as e:
        print(f"⊘ 创建复合索引时出错: {e}")

    if migrations_done == 0:
        print("⊘ peer_nodes 双向连接字段已存在，跳过迁移")


def migrate_terminal_egress_cache_table(conn: sqlite3.Connection):
    """为现有数据库添加 terminal_egress_cache 表 (Phase 11.1)

    用于缓存终端节点的出口列表，避免每次都通过隧道查询远程 API
    - 缓存命中时直接返回本地数据
    - 缓存过期（默认 5 分钟）后重新获取
    - 支持强制刷新
    """
    cursor = conn.cursor()

    # 检查 terminal_egress_cache 表是否存在
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='terminal_egress_cache'")
    if cursor.fetchone():
        print("⊘ terminal_egress_cache 表已存在，跳过迁移")
        return

    # 创建表
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS terminal_egress_cache (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            chain_tag TEXT NOT NULL UNIQUE,
            terminal_node TEXT NOT NULL,
            egress_list TEXT NOT NULL,
            cached_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            expires_at TIMESTAMP
        )
    """)
    # 注: chain_tag 上的 UNIQUE 约束已自动创建隐式索引，无需额外索引
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_terminal_egress_cache_expires ON terminal_egress_cache(expires_at)")
    conn.commit()
    print("✓ 创建 terminal_egress_cache 表")


def migrate_pending_pairings_table(conn: sqlite3.Connection):
    """为现有数据库添加 pending_pairings 表

    用于存储 generate-pair-request 时创建的待处理配对信息：
    - A 节点生成配对码时创建记录和 WireGuard 接口
    - B 节点通过隧道调用 complete-handshake 后删除记录
    """
    cursor = conn.cursor()

    # 检查 pending_pairings 表是否存在
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='pending_pairings'")
    if cursor.fetchone():
        print("⊘ pending_pairings 表已存在，跳过迁移")
        return

    # 创建表
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS pending_pairings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            pairing_id TEXT NOT NULL UNIQUE,
            local_tag TEXT NOT NULL,
            local_endpoint TEXT NOT NULL,
            tunnel_type TEXT NOT NULL DEFAULT 'wireguard',
            tunnel_local_ip TEXT,
            tunnel_remote_ip TEXT,
            tunnel_port INTEGER,
            wg_private_key TEXT,
            wg_public_key TEXT,
            remote_wg_private_key TEXT,
            remote_wg_public_key TEXT,
            interface_name TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            expires_at TIMESTAMP
        )
    """)
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_pending_pairings_expires ON pending_pairings(expires_at)")
    conn.commit()
    print("✓ 创建 pending_pairings 表")


def migrate_cascade_delete_tables(conn: sqlite3.Connection):
    """Phase 11-Cascade: 添加级联删除通知支持表

    添加三个表:
    - peer_event_log: 审计日志，记录节点生命周期事件
    - peer_tombstones: 墓碑记录，防止删除后短期重连
    - processed_peer_events: 幂等性去重，防止重复处理事件
    """
    cursor = conn.cursor()
    tables_created = 0

    # 1. peer_event_log 表 (必须与 USER_DB_SCHEMA 保持一致)
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='peer_event_log'")
    if not cursor.fetchone():
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS peer_event_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                event_type TEXT NOT NULL CHECK (event_type IN ('delete', 'disconnect', 'broadcast', 'received', 'port_change')),
                peer_tag TEXT NOT NULL,
                event_id TEXT,
                from_node TEXT,
                details TEXT,
                source_ip TEXT,
                created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
            )
        """)
        # 注: 移除 event_type 索引 (低基数字段，只有 4 种值，索引效率低)
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_peer_event_log_created_at ON peer_event_log(created_at)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_peer_event_log_peer_tag ON peer_event_log(peer_tag)")
        tables_created += 1
        print("✓ 创建 peer_event_log 表")

    # 2. peer_tombstones 表 (必须与 USER_DB_SCHEMA 保持一致)
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='peer_tombstones'")
    if not cursor.fetchone():
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS peer_tombstones (
                tag TEXT PRIMARY KEY,
                deleted_at TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                deleted_by TEXT,
                reason TEXT,
                CHECK (expires_at > deleted_at)
            )
        """)
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_peer_tombstones_expires ON peer_tombstones(expires_at)")
        tables_created += 1
        print("✓ 创建 peer_tombstones 表")

    # 3. processed_peer_events 表 (必须与 USER_DB_SCHEMA 保持一致)
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='processed_peer_events'")
    if not cursor.fetchone():
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS processed_peer_events (
                event_id TEXT PRIMARY KEY,
                processed_at TEXT NOT NULL,
                from_node TEXT NOT NULL,
                action TEXT
            )
        """)
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_processed_peer_events_time ON processed_peer_events(processed_at)")
        tables_created += 1
        print("✓ 创建 processed_peer_events 表")

    if tables_created > 0:
        conn.commit()
    else:
        print("⊘ 级联删除通知表已存在，跳过迁移")


def generate_wireguard_private_key() -> str:
    """生成 WireGuard 私钥"""
    try:
        result = subprocess.run(
            ["wg", "genkey"],
            capture_output=True,
            text=True,
            check=True
        )
        return result.stdout.strip()
    except Exception as e:
        print(f"⚠ 无法生成 WireGuard 私钥: {e}")
        return ""


def init_wireguard_server(conn: sqlite3.Connection):
    """初始化默认 WireGuard 服务器配置"""
    cursor = conn.cursor()

    # 检查是否已存在
    cursor.execute("SELECT id FROM wireguard_server WHERE id = 1")
    if cursor.fetchone():
        print("⊘ WireGuard 服务器配置已存在，跳过")
        return

    # 生成私钥
    private_key = generate_wireguard_private_key()
    if not private_key:
        print("⚠ 未能生成私钥，WireGuard 服务器配置初始化失败")
        return

    # 插入默认配置（使用环境变量或默认端口）
    # 默认子网使用 10.25.0.0/24，避免与远程 vpn-router 服务器（通常使用 10.23.0.0/24）冲突
    wg_listen_port = int(os.environ.get("WG_LISTEN_PORT", "36100"))
    default_subnet = os.environ.get("WG_INGRESS_SUBNET", "10.25.0.1/24")
    cursor.execute("""
        INSERT INTO wireguard_server (id, interface_name, address, listen_port, mtu, private_key)
        VALUES (1, 'wg-ingress', ?, ?, 1420, ?)
    """, (default_subnet, wg_listen_port, private_key))

    conn.commit()
    print("✓ 初始化 WireGuard 服务器配置（已生成私钥）")


def add_default_outbounds(conn: sqlite3.Connection):
    """添加默认出口"""
    cursor = conn.cursor()

    default_outbounds = [
        ("direct", "direct", "直接连接（不走 VPN）", None),
        ("block", "block", "阻断连接", None),
    ]

    for tag, type_, description, config in default_outbounds:
        cursor.execute("""
            INSERT OR IGNORE INTO outbounds (tag, type, description, config, enabled)
            VALUES (?, ?, ?, ?, 1)
        """, (tag, type_, description, config))

    conn.commit()
    print(f"✓ 添加 {len(default_outbounds)} 个默认出口")


def init_default_settings(conn: sqlite3.Connection):
    """初始化默认设置"""
    cursor = conn.cursor()

    default_settings = [
        ("default_outbound", "direct"),
    ]

    for key, value in default_settings:
        cursor.execute("""
            INSERT OR IGNORE INTO settings (key, value)
            VALUES (?, ?)
        """, (key, value))

    conn.commit()
    print("✓ 初始化默认设置")


def init_remote_rule_sets(conn: sqlite3.Connection):
    """初始化预置广告拦截规则"""
    cursor = conn.cursor()

    # 预置规则列表
    preset_rules = [
        # === 通用规则 ===
        ("easylist", "EasyList", "国际通用广告拦截列表",
         "https://easylist.to/easylist/easylist.txt", "adblock", "general", None, 0),
        ("easyprivacy", "EasyPrivacy", "隐私追踪拦截列表",
         "https://easylist.to/easylist/easyprivacy.txt", "adblock", "privacy", None, 0),
        ("adguard-dns", "AdGuard DNS", "AdGuard DNS 过滤规则",
         "https://adguardteam.github.io/AdGuardSDNSFilter/Filters/filter.txt", "adblock", "general", None, 0),

        # === 地区规则 ===
        ("easylist-china", "EasyList China", "中国区广告拦截",
         "https://easylist-downloads.adblockplus.org/easylistchina.txt", "adblock", "regional", "cn", 0),
        ("easylist-germany", "EasyList Germany", "德国区广告拦截",
         "https://easylist.to/easylistgermany/easylistgermany.txt", "adblock", "regional", "de", 0),
        ("easylist-france", "Liste FR", "法国区广告拦截",
         "https://easylist-downloads.adblockplus.org/liste_fr.txt", "adblock", "regional", "fr", 0),
        ("easylist-korea", "KoreanList", "韩国区广告拦截",
         "https://easylist-downloads.adblockplus.org/koreanlist+easylist.txt", "adblock", "regional", "kr", 0),
        ("ruadlist", "RuAdList", "俄罗斯区广告拦截",
         "https://easylist-downloads.adblockplus.org/ruadlist+easylist.txt", "adblock", "regional", "ru", 0),

        # === 反反广告 ===
        ("antiadblock-chinese", "Anti-Adblock (中文)", "移除中文网站的反广告拦截提示",
         "https://raw.githubusercontent.com/easylist/antiadblockfilters/master/antiadblockfilters/antiadblock_chinese.txt", "adblock", "antiadblock", "cn", 0),
        ("antiadblock-english", "Anti-Adblock (英文)", "移除英文网站的反广告拦截提示",
         "https://raw.githubusercontent.com/easylist/antiadblockfilters/master/antiadblockfilters/antiadblock_english.txt", "adblock", "antiadblock", "en", 0),

        # === 安全规则 ===
        ("malware-domains", "Malware Domains", "恶意软件域名拦截",
         "https://malware-filter.gitlab.io/malware-filter/urlhaus-filter-hosts.txt", "hosts", "security", None, 0),
        ("phishing-army", "Phishing Army", "钓鱼网站拦截",
         "https://phishing.army/download/phishing_army_blocklist.txt", "domains", "security", None, 0),

        # === 精简列表 ===
        ("peter-lowe", "Peter Lowe's List", "精简广告服务器列表 (~3000 域名)",
         "https://pgl.yoyo.org/adservers/serverlist.php?hostformat=hosts", "hosts", "general", None, 0),
    ]

    inserted = 0
    for tag, name, description, url, format_, category, region, enabled in preset_rules:
        cursor.execute("""
            INSERT OR IGNORE INTO remote_rule_sets
            (tag, name, description, url, format, category, region, enabled, outbound, priority)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'block', 0)
        """, (tag, name, description, url, format_, category, region, enabled))
        if cursor.rowcount > 0:
            inserted += 1

    conn.commit()
    if inserted > 0:
        print(f"✓ 添加 {inserted} 个预置广告拦截规则")
    else:
        print("⊘ 预置广告拦截规则已存在")


def load_pia_profiles(conn: sqlite3.Connection, config_dir: Path):
    """从 YAML 加载 PIA profiles（如果存在）"""
    pia_profiles_yaml = config_dir / "pia" / "profiles.yml"

    if not pia_profiles_yaml.exists():
        print("⊘ PIA profiles.yml 不存在，跳过")
        return

    try:
        with open(pia_profiles_yaml, 'r', encoding='utf-8') as f:
            data = yaml.safe_load(f)

        profiles = data.get('profiles', [])
        if not profiles:
            print("⊘ PIA profiles.yml 中没有数据")
            return

        cursor = conn.cursor()
        loaded = 0

        for profile in profiles:
            name = profile.get('name')
            description = profile.get('description', '')
            region_id = profile.get('region_id')
            custom_dns = profile.get('custom_dns')  # 自定义 DNS，如 1.1.1.1, tls://dns.google

            if not name or not region_id:
                continue

            cursor.execute("""
                INSERT OR IGNORE INTO pia_profiles (name, description, region_id, custom_dns, enabled)
                VALUES (?, ?, ?, ?, 1)
            """, (name, description, region_id, custom_dns))

            if cursor.rowcount > 0:
                loaded += 1

        conn.commit()
        if loaded > 0:
            print(f"✓ 从 YAML 加载 {loaded} 个 PIA profiles")

    except Exception as e:
        print(f"⊘ 加载 PIA profiles 失败: {e}")


def main():
    parser = argparse.ArgumentParser(description="初始化用户配置数据库")
    parser.add_argument("config_dir", help="配置目录路径")
    parser.add_argument("--key", help="SQLCipher 加密密钥（64 字符 hex）")
    args = parser.parse_args()

    config_dir = Path(args.config_dir)
    user_db_path = config_dir / "user-config.db"

    # 从参数或环境变量获取密钥
    encryption_key = args.key or os.environ.get("SQLCIPHER_KEY")

    print("=" * 60)
    print("初始化用户配置数据库")
    print("=" * 60)
    print(f"配置目录: {config_dir}")
    print(f"数据库路径: {user_db_path}")
    print(f"SQLCipher: {'启用' if encryption_key and HAS_SQLCIPHER else '禁用'}")
    print()

    # 初始化数据库
    conn = init_user_db(user_db_path, encryption_key)

    # 迁移现有数据库（添加新字段）
    migrate_wireguard_peers_lan_fields(conn)
    migrate_openvpn_egress_crl_verify(conn)
    migrate_v2ray_inbound_xray_fields(conn)
    migrate_v2ray_egress_socks_port(conn)
    migrate_admin_auth(conn)
    migrate_warp_egress_protocol(conn)
    migrate_outbound_groups(conn)
    migrate_openvpn_socks_to_tun(conn)
    migrate_pia_profiles_custom_dns(conn)
    migrate_ingress_default_outbound(conn)
    migrate_peer_nodes_tables(conn)
    migrate_peer_nodes_xray_reality_fields(conn)
    migrate_peer_nodes_inbound_fields(conn)
    migrate_peer_nodes_api_port(conn)
    migrate_peer_nodes_connection_mode(conn)
    migrate_relay_routes_table(conn)

    # 多跳链路架构 v2 迁移
    migrate_peer_nodes_tunnel_api_endpoint(conn)
    migrate_node_chains_chain_fields(conn)
    migrate_chain_routing_table(conn)

    # Phase 11.1: 双向连接和终端出口缓存
    migrate_peer_nodes_bidirectional_fields(conn)
    migrate_terminal_egress_cache_table(conn)

    # Phase 11-Tunnel: 待处理配对表（用于隧道优先的配对流程）
    migrate_pending_pairings_table(conn)

    # Phase 11-Cascade: 级联删除通知支持表
    migrate_cascade_delete_tables(conn)

    # 添加默认数据
    add_default_outbounds(conn)

    # 初始化默认设置
    init_default_settings(conn)

    # 初始化预置广告拦截规则
    init_remote_rule_sets(conn)

    # 初始化 WireGuard 服务器配置
    init_wireguard_server(conn)

    # 加载 PIA profiles（如果存在）
    load_pia_profiles(conn, config_dir)

    # 优化数据库
    print("\n优化数据库...")
    conn.execute("VACUUM")
    conn.execute("ANALYZE")
    conn.commit()

    # 显示统计
    cursor = conn.cursor()
    stats = {
        "routing_rules": cursor.execute("SELECT COUNT(*) FROM routing_rules").fetchone()[0],
        "outbounds": cursor.execute("SELECT COUNT(*) FROM outbounds").fetchone()[0],
        "wireguard_server": cursor.execute("SELECT COUNT(*) FROM wireguard_server").fetchone()[0],
        "wireguard_peers": cursor.execute("SELECT COUNT(*) FROM wireguard_peers").fetchone()[0],
        "pia_profiles": cursor.execute("SELECT COUNT(*) FROM pia_profiles").fetchone()[0],
        "custom_egress": cursor.execute("SELECT COUNT(*) FROM custom_egress").fetchone()[0],
        "direct_egress": cursor.execute("SELECT COUNT(*) FROM direct_egress").fetchone()[0],
        "openvpn_egress": cursor.execute("SELECT COUNT(*) FROM openvpn_egress").fetchone()[0],
        "v2ray_egress": cursor.execute("SELECT COUNT(*) FROM v2ray_egress").fetchone()[0],
        "warp_egress": cursor.execute("SELECT COUNT(*) FROM warp_egress").fetchone()[0],
        "v2ray_users": cursor.execute("SELECT COUNT(*) FROM v2ray_users").fetchone()[0],
        "custom_category_items": cursor.execute("SELECT COUNT(*) FROM custom_category_items").fetchone()[0],
        "outbound_groups": cursor.execute("SELECT COUNT(*) FROM outbound_groups").fetchone()[0],
        "peer_nodes": cursor.execute("SELECT COUNT(*) FROM peer_nodes").fetchone()[0],
        "node_chains": cursor.execute("SELECT COUNT(*) FROM node_chains").fetchone()[0],
        "relay_routes": cursor.execute("SELECT COUNT(*) FROM relay_routes").fetchone()[0],
        "chain_routing": cursor.execute("SELECT COUNT(*) FROM chain_routing").fetchone()[0],
        "terminal_egress_cache": cursor.execute("SELECT COUNT(*) FROM terminal_egress_cache").fetchone()[0],
    }

    db_size_bytes = user_db_path.stat().st_size
    db_size_kb = db_size_bytes / 1024

    print("\n" + "=" * 60)
    print("✅ 用户数据库初始化完成")
    print("=" * 60)
    print(f"路由规则数:       {stats['routing_rules']:,}")
    print(f"出口配置数:       {stats['outbounds']:,}")
    print(f"WireGuard 服务器: {stats['wireguard_server']:,}")
    print(f"WireGuard 客户端: {stats['wireguard_peers']:,}")
    print(f"PIA Profiles:     {stats['pia_profiles']:,}")
    print(f"自定义 WG 出口:   {stats['custom_egress']:,}")
    print(f"Direct 出口:      {stats['direct_egress']:,}")
    print(f"OpenVPN 出口:     {stats['openvpn_egress']:,}")
    print(f"V2Ray 出口:       {stats['v2ray_egress']:,}")
    print(f"WARP 出口:        {stats['warp_egress']:,}")
    print(f"V2Ray 用户:       {stats['v2ray_users']:,}")
    print(f"出口组:           {stats['outbound_groups']:,}")
    print(f"对等节点:         {stats['peer_nodes']:,}")
    print(f"多跳链路:         {stats['node_chains']:,}")
    print(f"中继路由:         {stats['relay_routes']:,}")
    print(f"链路路由规则:     {stats['chain_routing']:,}")
    print(f"终端出口缓存:     {stats['terminal_egress_cache']:,}")
    print(f"自定义分类项目:   {stats['custom_category_items']:,}")
    print(f"数据库大小:       {db_size_kb:.2f} KB")
    print("=" * 60)

    conn.close()


if __name__ == "__main__":
    main()

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
    enabled INTEGER DEFAULT 1,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

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

    if migrations_done > 0:
        conn.commit()
    else:
        print("⊘ wireguard_peers LAN 字段已存在，跳过迁移")


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
    print(f"自定义分类项目:   {stats['custom_category_items']:,}")
    print(f"数据库大小:       {db_size_kb:.2f} KB")
    print("=" * 60)

    conn.close()


if __name__ == "__main__":
    main()

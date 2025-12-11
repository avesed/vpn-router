#!/usr/bin/env python3
"""初始化用户配置数据库（用户数据）"""
import sqlite3
import json
import os
import subprocess
from pathlib import Path
import sys
import yaml


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
    dns_strategy TEXT DEFAULT 'direct-dns',
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
"""


def init_user_db(db_path: Path) -> sqlite3.Connection:
    """初始化用户数据库结构"""
    print(f"初始化用户数据库: {db_path}")
    conn = sqlite3.Connection(db_path)
    conn.executescript(USER_DB_SCHEMA)
    conn.commit()
    return conn


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
    wg_listen_port = int(os.environ.get("WG_LISTEN_PORT", "36100"))
    cursor.execute("""
        INSERT INTO wireguard_server (id, interface_name, address, listen_port, mtu, private_key)
        VALUES (1, 'wg-ingress', '10.23.0.1/24', ?, 1420, ?)
    """, (wg_listen_port, private_key))

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
         "https://easylist.to/easylist/easylist.txt", "adblock", "general", None, 1),
        ("easyprivacy", "EasyPrivacy", "隐私追踪拦截列表",
         "https://easylist.to/easylist/easyprivacy.txt", "adblock", "privacy", None, 0),
        ("adguard-dns", "AdGuard DNS", "AdGuard DNS 过滤规则",
         "https://adguardteam.github.io/AdGuardSDNSFilter/Filters/filter.txt", "adblock", "general", None, 0),

        # === 地区规则 ===
        ("easylist-china", "EasyList China", "中国区广告拦截",
         "https://easylist-downloads.adblockplus.org/easylistchina.txt", "adblock", "regional", "cn", 1),
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
            dns_strategy = profile.get('dns_strategy', 'direct-dns')

            if not name or not region_id:
                continue

            cursor.execute("""
                INSERT OR IGNORE INTO pia_profiles (name, description, region_id, dns_strategy, enabled)
                VALUES (?, ?, ?, ?, 1)
            """, (name, description, region_id, dns_strategy))

            if cursor.rowcount > 0:
                loaded += 1

        conn.commit()
        if loaded > 0:
            print(f"✓ 从 YAML 加载 {loaded} 个 PIA profiles")

    except Exception as e:
        print(f"⊘ 加载 PIA profiles 失败: {e}")


def main():
    if len(sys.argv) < 2:
        print("用法: init_user_db.py <配置目录>")
        sys.exit(1)

    config_dir = Path(sys.argv[1])
    user_db_path = config_dir / "user-config.db"

    print("=" * 60)
    print("初始化用户配置数据库")
    print("=" * 60)
    print(f"配置目录: {config_dir}")
    print(f"数据库路径: {user_db_path}")
    print()

    # 初始化数据库
    conn = init_user_db(user_db_path)

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
        "custom_category_items": cursor.execute("SELECT COUNT(*) FROM custom_category_items").fetchone()[0],
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
    print(f"自定义分类项目:   {stats['custom_category_items']:,}")
    print(f"数据库大小:       {db_size_kb:.2f} KB")
    print("=" * 60)

    conn.close()


if __name__ == "__main__":
    main()

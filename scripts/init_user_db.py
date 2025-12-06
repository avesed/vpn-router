#!/usr/bin/env python3
"""初始化用户配置数据库（用户数据）"""
import sqlite3
import json
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
    priority INTEGER DEFAULT 0,
    enabled INTEGER DEFAULT 1,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_rule_enabled ON routing_rules(enabled, priority);
CREATE INDEX IF NOT EXISTS idx_rule_outbound ON routing_rules(outbound);

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
"""


def init_user_db(db_path: Path) -> sqlite3.Connection:
    """初始化用户数据库结构"""
    print(f"初始化用户数据库: {db_path}")
    conn = sqlite3.Connection(db_path)
    conn.executescript(USER_DB_SCHEMA)
    conn.commit()
    return conn


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
        "wireguard_peers": cursor.execute("SELECT COUNT(*) FROM wireguard_peers").fetchone()[0],
        "pia_profiles": cursor.execute("SELECT COUNT(*) FROM pia_profiles").fetchone()[0],
        "custom_category_items": cursor.execute("SELECT COUNT(*) FROM custom_category_items").fetchone()[0],
    }

    db_size_bytes = user_db_path.stat().st_size
    db_size_kb = db_size_bytes / 1024

    print("\n" + "=" * 60)
    print("✅ 用户数据库初始化完成")
    print("=" * 60)
    print(f"路由规则数:       {stats['routing_rules']:,}")
    print(f"出口配置数:       {stats['outbounds']:,}")
    print(f"WireGuard 客户端: {stats['wireguard_peers']:,}")
    print(f"PIA Profiles:     {stats['pia_profiles']:,}")
    print(f"自定义分类项目:   {stats['custom_category_items']:,}")
    print(f"数据库大小:       {db_size_kb:.2f} KB")
    print("=" * 60)

    conn.close()


if __name__ == "__main__":
    main()

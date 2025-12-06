#!/usr/bin/env python3
"""初始化地理位置和域名数据库（只读系统数据）"""
import sqlite3
import json
from pathlib import Path
from typing import List, Dict
import sys


# 系统数据库结构（只读）
GEODATA_SCHEMA = """
-- 国家信息表
CREATE TABLE IF NOT EXISTS countries (
    code TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    display_name TEXT NOT NULL,
    ipv4_count INTEGER DEFAULT 0,
    ipv6_count INTEGER DEFAULT 0,
    recommended_exit TEXT DEFAULT 'direct'
);

-- IP 范围表
CREATE TABLE IF NOT EXISTS ip_ranges (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    country_code TEXT NOT NULL,
    cidr TEXT NOT NULL,
    ip_version INTEGER NOT NULL,
    FOREIGN KEY (country_code) REFERENCES countries(code)
);
CREATE INDEX IF NOT EXISTS idx_ip_country ON ip_ranges(country_code);
CREATE INDEX IF NOT EXISTS idx_ip_version ON ip_ranges(ip_version);
CREATE INDEX IF NOT EXISTS idx_ip_cidr ON ip_ranges(cidr);

-- 域名分类表
CREATE TABLE IF NOT EXISTS domain_categories (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    description TEXT,
    group_type TEXT DEFAULT 'type',
    recommended_exit TEXT DEFAULT 'direct'
);

-- 域名列表表
CREATE TABLE IF NOT EXISTS domain_lists (
    id TEXT PRIMARY KEY,
    domain_count INTEGER DEFAULT 0
);

-- 域名列表与分类的多对多关系表
CREATE TABLE IF NOT EXISTS domain_list_categories (
    list_id TEXT NOT NULL,
    category_id TEXT NOT NULL,
    PRIMARY KEY (list_id, category_id),
    FOREIGN KEY (list_id) REFERENCES domain_lists(id),
    FOREIGN KEY (category_id) REFERENCES domain_categories(id)
);

-- 域名表
CREATE TABLE IF NOT EXISTS domains (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    list_id TEXT NOT NULL,
    domain TEXT NOT NULL,
    domain_type TEXT DEFAULT 'suffix',
    FOREIGN KEY (list_id) REFERENCES domain_lists(id)
);
CREATE INDEX IF NOT EXISTS idx_domain_list ON domains(list_id);
CREATE INDEX IF NOT EXISTS idx_domain_name ON domains(domain);
CREATE INDEX IF NOT EXISTS idx_domain_type ON domains(domain_type);
"""


def init_geodata_db(db_path: Path) -> sqlite3.Connection:
    """初始化地理数据库结构"""
    print(f"初始化地理数据库: {db_path}")
    conn = sqlite3.Connection(db_path)
    conn.executescript(GEODATA_SCHEMA)
    conn.commit()
    return conn


def import_ip_data(conn: sqlite3.Connection, ip_list_dir: Path):
    """导入 IP 地理数据"""
    print("\n导入 IP 数据...")

    country_files = list(ip_list_dir.glob("*.json"))
    if not country_files:
        print(f"  警告: 在 {ip_list_dir} 未找到 IP 数据文件")
        return

    cursor = conn.cursor()
    countries_added = 0
    ip_ranges_added = 0

    for country_file in country_files:
        try:
            data = json.loads(country_file.read_text())
            country_code = data.get("code", "").lower()

            if not country_code:
                continue

            # 插入国家信息
            cursor.execute("""
                INSERT OR REPLACE INTO countries (code, name, display_name, ipv4_count, ipv6_count)
                VALUES (?, ?, ?, ?, ?)
            """, (
                country_code,
                data.get("name", country_code.upper()),
                data.get("display_name", country_code.upper()),
                len(data.get("ipv4", [])),
                len(data.get("ipv6", []))
            ))
            countries_added += 1

            # 批量插入 IPv4
            ipv4_list = data.get("ipv4", [])
            if ipv4_list:
                cursor.executemany("""
                    INSERT INTO ip_ranges (country_code, cidr, ip_version)
                    VALUES (?, ?, 4)
                """, [(country_code, cidr) for cidr in ipv4_list])
                ip_ranges_added += len(ipv4_list)

            # 批量插入 IPv6
            ipv6_list = data.get("ipv6", [])
            if ipv6_list:
                cursor.executemany("""
                    INSERT INTO ip_ranges (country_code, cidr, ip_version)
                    VALUES (?, ?, 6)
                """, [(country_code, cidr) for cidr in ipv6_list])
                ip_ranges_added += len(ipv6_list)

            if countries_added % 50 == 0:
                conn.commit()
                print(f"  已导入 {countries_added} 个国家...")

        except Exception as e:
            print(f"  导入 {country_file.name} 失败: {e}")

    conn.commit()
    print(f"✓ 导入 {countries_added} 个国家")
    print(f"✓ 导入 {ip_ranges_added} 条 IP 范围")


def import_domain_data(conn: sqlite3.Connection, domain_catalog_file: Path):
    """导入域名分类和列表数据"""
    print("\n导入域名数据...")

    if not domain_catalog_file.exists():
        print(f"  警告: {domain_catalog_file} 不存在")
        return

    catalog = json.loads(domain_catalog_file.read_text())
    cursor = conn.cursor()

    # 导入分类
    categories = catalog.get("categories", {})
    for cat_id, cat_data in categories.items():
        cursor.execute("""
            INSERT OR REPLACE INTO domain_categories (id, name, description, group_type, recommended_exit)
            VALUES (?, ?, ?, ?, ?)
        """, (
            cat_id,
            cat_data.get("name", cat_id),
            cat_data.get("description"),
            cat_data.get("group_type", "type"),
            cat_data.get("recommended_exit", "direct")
        ))

    print(f"✓ 导入 {len(categories)} 个分类")

    # 导入域名列表
    lists = catalog.get("lists", {})
    domains_added = 0

    for list_id, list_data in lists.items():
        # 插入列表
        domain_list = list_data.get("domains", [])
        cursor.execute("""
            INSERT OR REPLACE INTO domain_lists (id, domain_count)
            VALUES (?, ?)
        """, (list_id, len(domain_list)))

        # 插入列表与分类的关系
        for category_id in list_data.get("categories", []):
            cursor.execute("""
                INSERT OR IGNORE INTO domain_list_categories (list_id, category_id)
                VALUES (?, ?)
            """, (list_id, category_id))

        # 批量插入域名
        if domain_list:
            cursor.executemany("""
                INSERT INTO domains (list_id, domain, domain_type)
                VALUES (?, ?, 'suffix')
            """, [(list_id, domain) for domain in domain_list])
            domains_added += len(domain_list)

        if len(lists) % 100 == 0:
            conn.commit()

    conn.commit()
    print(f"✓ 导入 {len(lists)} 个域名列表")
    print(f"✓ 导入 {domains_added} 个域名")


def main():
    if len(sys.argv) < 2:
        print("用法: init_geodata_db.py <配置目录>")
        sys.exit(1)

    config_dir = Path(sys.argv[1])

    # 确定数据文件路径
    project_root = config_dir.parent if config_dir.name == "config" else config_dir
    ip_list_dir = project_root / "ip-list" / "country"
    domain_catalog_file = config_dir / "domain-catalog.json"

    # 地理数据库路径
    geodata_db_path = config_dir / "geoip-geodata.db"

    print("=" * 60)
    print("初始化地理位置和域名数据库（只读系统数据）")
    print("=" * 60)
    print(f"配置目录: {config_dir}")
    print(f"IP 列表目录: {ip_list_dir}")
    print(f"域名目录: {domain_catalog_file}")
    print(f"数据库路径: {geodata_db_path}")
    print()

    # 初始化数据库
    conn = init_geodata_db(geodata_db_path)

    # 导入数据
    import_ip_data(conn, ip_list_dir)
    import_domain_data(conn, domain_catalog_file)

    # 优化数据库
    print("\n优化数据库...")
    conn.execute("VACUUM")
    conn.execute("ANALYZE")
    conn.commit()

    # 显示统计
    cursor = conn.cursor()
    stats = {
        "countries": cursor.execute("SELECT COUNT(*) FROM countries").fetchone()[0],
        "ip_ranges": cursor.execute("SELECT COUNT(*) FROM ip_ranges").fetchone()[0],
        "ipv4": cursor.execute("SELECT COUNT(*) FROM ip_ranges WHERE ip_version = 4").fetchone()[0],
        "ipv6": cursor.execute("SELECT COUNT(*) FROM ip_ranges WHERE ip_version = 6").fetchone()[0],
        "categories": cursor.execute("SELECT COUNT(*) FROM domain_categories").fetchone()[0],
        "lists": cursor.execute("SELECT COUNT(*) FROM domain_lists").fetchone()[0],
        "domains": cursor.execute("SELECT COUNT(*) FROM domains").fetchone()[0],
    }

    db_size_bytes = geodata_db_path.stat().st_size
    db_size_mb = db_size_bytes / (1024 * 1024)

    print("\n" + "=" * 60)
    print("✅ 地理数据库初始化完成")
    print("=" * 60)
    print(f"国家数量:     {stats['countries']:,}")
    print(f"IP 范围数:    {stats['ip_ranges']:,}")
    print(f"  - IPv4:     {stats['ipv4']:,}")
    print(f"  - IPv6:     {stats['ipv6']:,}")
    print(f"域名分类:     {stats['categories']:,}")
    print(f"域名列表:     {stats['lists']:,}")
    print(f"域名总数:     {stats['domains']:,}")
    print(f"数据库大小:   {db_size_mb:.2f} MB")
    print("=" * 60)

    conn.close()


if __name__ == "__main__":
    main()

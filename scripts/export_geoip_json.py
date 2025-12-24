#!/usr/bin/env python3
"""从 geoip-geodata.db 导出 GeoIP 数据到 JSON 文件

导出格式:
- geoip-catalog.json: 国家元数据列表
- geoip/{country}.json: 各国 IP 范围

用法:
    python3 export_geoip_json.py [db_path] [output_dir]

示例:
    python3 export_geoip_json.py geodata/geoip-geodata.db config/
"""
import json
import sqlite3
import sys
from pathlib import Path
from typing import Dict, List, Any


def export_geoip_to_json(db_path: str, output_dir: str) -> Dict[str, Any]:
    """导出 GeoIP 数据到 JSON 文件

    Args:
        db_path: geoip-geodata.db 路径
        output_dir: 输出目录 (将创建 geoip-catalog.json 和 geoip/ 子目录)

    Returns:
        导出统计信息
    """
    db_path = Path(db_path)
    output_dir = Path(output_dir)
    geoip_dir = output_dir / "geoip"

    if not db_path.exists():
        raise FileNotFoundError(f"数据库不存在: {db_path}")

    # 创建输出目录
    geoip_dir.mkdir(parents=True, exist_ok=True)

    conn = sqlite3.connect(str(db_path))
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()

    stats = {
        "countries": 0,
        "total_ipv4_ranges": 0,
        "total_ipv6_ranges": 0,
        "catalog_size_kb": 0,
        "geoip_dir_size_kb": 0,
    }

    # 1. 获取所有国家信息
    countries = cursor.execute("""
        SELECT code, name, display_name, ipv4_count, ipv6_count, recommended_exit
        FROM countries
        ORDER BY display_name
    """).fetchall()

    catalog = {
        "version": 1,
        "total_countries": len(countries),
        "total_ipv4_ranges": 0,
        "total_ipv6_ranges": 0,
        "countries": []
    }

    print(f"[export] 导出 {len(countries)} 个国家...")

    # 2. 导出每个国家的 IP 范围
    for country in countries:
        code = country["code"]

        # 获取 IPv4 范围
        ipv4_rows = cursor.execute("""
            SELECT cidr FROM ip_ranges
            WHERE country_code = ? AND ip_version = 4
        """, (code,)).fetchall()
        ipv4_ranges = [row[0] for row in ipv4_rows]

        # 获取 IPv6 范围
        ipv6_rows = cursor.execute("""
            SELECT cidr FROM ip_ranges
            WHERE country_code = ? AND ip_version = 6
        """, (code,)).fetchall()
        ipv6_ranges = [row[0] for row in ipv6_rows]

        # 添加到目录
        catalog["countries"].append({
            "code": code,
            "name": country["name"],
            "display_name": country["display_name"],
            "ipv4_count": len(ipv4_ranges),
            "ipv6_count": len(ipv6_ranges),
            "recommended_exit": country["recommended_exit"] or "direct"
        })

        catalog["total_ipv4_ranges"] += len(ipv4_ranges)
        catalog["total_ipv6_ranges"] += len(ipv6_ranges)

        # 写入国家 IP 文件
        country_file = geoip_dir / f"{code}.json"
        country_data = {
            "code": code,
            "name": country["name"],
            "ipv4_ranges": ipv4_ranges,
            "ipv6_ranges": ipv6_ranges
        }
        country_file.write_text(json.dumps(country_data, ensure_ascii=False))

        stats["geoip_dir_size_kb"] += country_file.stat().st_size / 1024

    conn.close()

    # 3. 写入目录文件
    catalog_file = output_dir / "geoip-catalog.json"
    catalog_file.write_text(json.dumps(catalog, indent=2, ensure_ascii=False))

    stats["countries"] = len(countries)
    stats["total_ipv4_ranges"] = catalog["total_ipv4_ranges"]
    stats["total_ipv6_ranges"] = catalog["total_ipv6_ranges"]
    stats["catalog_size_kb"] = catalog_file.stat().st_size / 1024

    print(f"[export] 完成!")
    print(f"  - 国家数: {stats['countries']}")
    print(f"  - IPv4 范围: {stats['total_ipv4_ranges']:,}")
    print(f"  - IPv6 范围: {stats['total_ipv6_ranges']:,}")
    print(f"  - 目录文件: {stats['catalog_size_kb']:.1f} KB")
    print(f"  - IP 文件目录: {stats['geoip_dir_size_kb']:.1f} KB")
    print(f"  - 总计: {(stats['catalog_size_kb'] + stats['geoip_dir_size_kb']) / 1024:.2f} MB")

    return stats


def main():
    if len(sys.argv) < 2:
        # 默认路径
        db_path = "geodata/geoip-geodata.db"
        output_dir = "config"
    else:
        db_path = sys.argv[1]
        output_dir = sys.argv[2] if len(sys.argv) > 2 else "config"

    try:
        stats = export_geoip_to_json(db_path, output_dir)
        print(f"\n导出成功! 文件位于:")
        print(f"  - {output_dir}/geoip-catalog.json")
        print(f"  - {output_dir}/geoip/*.json")
    except Exception as e:
        print(f"导出失败: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()

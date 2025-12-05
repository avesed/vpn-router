#!/usr/bin/env python3
"""解析 IP 列表（按国家/地区分类）

数据来源：ip-location-db 格式
每个国家目录包含：
- aggregated.json: JSON 格式，包含 ipv4 和 ipv6 子网
- ipv4-aggregated.txt: IPv4 CIDR 列表
- ipv6-aggregated.txt: IPv6 CIDR 列表
"""
import json
from pathlib import Path
from typing import Dict, List

# 国家代码到中文名称的映射（常用国家）
COUNTRY_NAMES = {
    "cn": "🇨🇳 中国",
    "hk": "🇭🇰 中国香港",
    "tw": "🇹🇼 中国台湾",
    "mo": "🇲🇴 中国澳门",
    "jp": "🇯🇵 日本",
    "kr": "🇰🇷 韩国",
    "sg": "🇸🇬 新加坡",
    "us": "🇺🇸 美国",
    "gb": "🇬🇧 英国",
    "de": "🇩🇪 德国",
    "fr": "🇫🇷 法国",
    "nl": "🇳🇱 荷兰",
    "au": "🇦🇺 澳大利亚",
    "ca": "🇨🇦 加拿大",
    "ru": "🇷🇺 俄罗斯",
    "in": "🇮🇳 印度",
    "br": "🇧🇷 巴西",
    "id": "🇮🇩 印度尼西亚",
    "th": "🇹🇭 泰国",
    "vn": "🇻🇳 越南",
    "my": "🇲🇾 马来西亚",
    "ph": "🇵🇭 菲律宾",
    "it": "🇮🇹 意大利",
    "es": "🇪🇸 西班牙",
    "ch": "🇨🇭 瑞士",
    "se": "🇸🇪 瑞典",
    "no": "🇳🇴 挪威",
    "fi": "🇫🇮 芬兰",
    "dk": "🇩🇰 丹麦",
    "at": "🇦🇹 奥地利",
    "be": "🇧🇪 比利时",
    "pl": "🇵🇱 波兰",
    "cz": "🇨🇿 捷克",
    "ie": "🇮🇪 爱尔兰",
    "pt": "🇵🇹 葡萄牙",
    "nz": "🇳🇿 新西兰",
    "za": "🇿🇦 南非",
    "mx": "🇲🇽 墨西哥",
    "ar": "🇦🇷 阿根廷",
    "cl": "🇨🇱 智利",
    "tr": "🇹🇷 土耳其",
    "ua": "🇺🇦 乌克兰",
    "il": "🇮🇱 以色列",
    "ae": "🇦🇪 阿联酋",
    "sa": "🇸🇦 沙特阿拉伯",
    "ir": "🇮🇷 伊朗",
    "pk": "🇵🇰 巴基斯坦",
    "bd": "🇧🇩 孟加拉国",
    "ng": "🇳🇬 尼日利亚",
    "eg": "🇪🇬 埃及",
    "ke": "🇰🇪 肯尼亚",
}

# 推荐的出口配置
RECOMMENDED_EXITS = {
    "cn": "direct",  # 中国 IP 直连
    "hk": "hk-stream",
    "tw": "tw-stream",
    "jp": "jp-stream",
    "kr": "kr-stream",
    "sg": "sg-stream",
    "us": "us-stream",
    "gb": "uk-stream",
    "de": "de-stream",
}

# 热门国家（优先显示）
POPULAR_COUNTRIES = [
    "cn", "hk", "tw", "jp", "kr", "sg", "us", "gb", "de", "fr",
    "nl", "au", "ca", "ru", "in", "br"
]


class IpListParser:
    def __init__(self, data_dir: Path):
        self.data_dir = data_dir / "country"
        self._cache: Dict[str, dict] = {}

    def list_countries(self) -> List[str]:
        """列出所有可用的国家代码"""
        if not self.data_dir.exists():
            return []
        return sorted([
            d.name for d in self.data_dir.iterdir()
            if d.is_dir() and (d / "aggregated.json").exists()
        ])

    def get_country_info(self, country_code: str) -> dict:
        """获取国家 IP 信息"""
        if country_code in self._cache:
            return self._cache[country_code]

        country_dir = self.data_dir / country_code
        json_file = country_dir / "aggregated.json"

        if not json_file.exists():
            return {}

        data = json.loads(json_file.read_text())
        subnets = data.get("subnets", {})

        result = {
            "country_code": country_code.upper(),
            "country_name": data.get("country", country_code.upper()),
            "display_name": COUNTRY_NAMES.get(country_code, data.get("country", country_code.upper())),
            "ipv4_count": len(subnets.get("ipv4", [])),
            "ipv6_count": len(subnets.get("ipv6", [])),
            "ipv4_cidrs": subnets.get("ipv4", []),
            "ipv6_cidrs": subnets.get("ipv6", []),
            "recommended_exit": RECOMMENDED_EXITS.get(country_code, "direct"),
        }
        self._cache[country_code] = result
        return result

    def get_ipv4_cidrs(self, country_code: str) -> List[str]:
        """获取 IPv4 CIDR 列表"""
        info = self.get_country_info(country_code)
        return info.get("ipv4_cidrs", [])

    def get_ipv6_cidrs(self, country_code: str) -> List[str]:
        """获取 IPv6 CIDR 列表"""
        info = self.get_country_info(country_code)
        return info.get("ipv6_cidrs", [])


def build_ip_catalog(data_dir: Path) -> dict:
    """构建 IP 列表目录"""
    parser = IpListParser(data_dir)
    countries = parser.list_countries()

    catalog = {
        "countries": {},
        "popular": [],
        "stats": {
            "total_countries": 0,
            "total_ipv4_cidrs": 0,
            "total_ipv6_cidrs": 0,
        }
    }

    total_ipv4 = 0
    total_ipv6 = 0

    for cc in countries:
        info = parser.get_country_info(cc)
        if not info:
            continue

        # 只存储摘要信息（不包含完整 CIDR 列表）
        catalog["countries"][cc] = {
            "country_code": info["country_code"],
            "country_name": info["country_name"],
            "display_name": info["display_name"],
            "ipv4_count": info["ipv4_count"],
            "ipv6_count": info["ipv6_count"],
            "recommended_exit": info["recommended_exit"],
            "sample_ipv4": info["ipv4_cidrs"][:5] if info["ipv4_cidrs"] else [],
        }

        total_ipv4 += info["ipv4_count"]
        total_ipv6 += info["ipv6_count"]

    # 热门国家
    catalog["popular"] = [
        cc for cc in POPULAR_COUNTRIES
        if cc in catalog["countries"]
    ]

    catalog["stats"] = {
        "total_countries": len(catalog["countries"]),
        "total_ipv4_cidrs": total_ipv4,
        "total_ipv6_cidrs": total_ipv6,
    }

    return catalog


if __name__ == "__main__":
    import sys

    data_dir = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("/etc/sing-box/ip-list")
    output_path = Path(sys.argv[2]) if len(sys.argv) > 2 else Path("/etc/sing-box/ip-catalog.json")

    if not data_dir.exists():
        print(f"IP 列表目录不存在: {data_dir}", file=sys.stderr)
        sys.exit(1)

    catalog = build_ip_catalog(data_dir)
    output_path.write_text(json.dumps(catalog, indent=2, ensure_ascii=False))
    print(f"已生成 IP 目录: {output_path}")
    print(f"国家/地区数量: {catalog['stats']['total_countries']}")
    print(f"IPv4 CIDR 总数: {catalog['stats']['total_ipv4_cidrs']}")
    print(f"IPv6 CIDR 总数: {catalog['stats']['total_ipv6_cidrs']}")

    # 打印热门国家
    print("\n热门国家:")
    for cc in catalog["popular"]:
        info = catalog["countries"][cc]
        print(f"  {info['display_name']}: {info['ipv4_count']} IPv4, {info['ipv6_count']} IPv6")

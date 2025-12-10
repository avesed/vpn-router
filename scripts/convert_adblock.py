#!/usr/bin/env python3
"""将 Adblock Plus 语法转换为 sing-box rule-set 格式

支持的输入格式:
- ABP 语法: ||domain^ (只提取域名规则，忽略元素隐藏)
- Hosts 格式: 0.0.0.0 domain / 127.0.0.1 domain
- 纯域名格式: domain.com

输出格式:
- sing-box rule-set JSON (source 格式)
"""
import json
import re
import urllib.request
from pathlib import Path
from typing import Set, Optional


def parse_adblock_rule(line: str) -> Optional[str]:
    """解析 ABP 规则，只提取域名 (忽略元素隐藏规则)"""
    line = line.strip()

    # 跳过空行和注释
    if not line or line.startswith(('!', '[', '#', '@')):
        return None

    # 跳过元素隐藏规则 (##, #@#, #?#, #$#)
    if '##' in line or '#@#' in line or '#?#' in line or '#$#' in line:
        return None

    # 跳过白名单规则
    if line.startswith('@@'):
        return None

    # 匹配 ||domain^ 格式 (可能带参数如 $third-party)
    match = re.match(r'^\|\|([a-zA-Z0-9][\w\-\.]*\.[a-zA-Z]{2,})\^?', line)
    if match:
        domain = match.group(1).lower()
        if is_valid_domain(domain):
            return domain

    return None


def parse_hosts_rule(line: str) -> Optional[str]:
    """解析 hosts 格式"""
    line = line.strip()

    # 跳过空行和注释
    if not line or line.startswith('#'):
        return None

    parts = line.split()
    if len(parts) >= 2 and parts[0] in ('0.0.0.0', '127.0.0.1'):
        domain = parts[1].lower()
        # 跳过本地域名
        if domain not in ('localhost', 'localhost.localdomain', 'local', 'broadcasthost'):
            if is_valid_domain(domain):
                return domain

    return None


def parse_domain_rule(line: str) -> Optional[str]:
    """解析纯域名格式"""
    line = line.strip()

    # 跳过空行和注释
    if not line or line.startswith('#'):
        return None

    # 移除通配符前缀
    if line.startswith('*.'):
        line = line[2:]

    domain = line.lower()
    if is_valid_domain(domain):
        return domain

    return None


def is_valid_domain(domain: str) -> bool:
    """验证域名格式"""
    # 基本长度检查
    if len(domain) < 4 or len(domain) > 253:
        return False

    # 必须有至少一个点
    if '.' not in domain:
        return False

    # 不能以点开头或结尾
    if domain.startswith('.') or domain.endswith('.'):
        return False

    # 检查每个标签
    labels = domain.split('.')
    for label in labels:
        if not label or len(label) > 63:
            return False
        # 不能以连字符开头或结尾
        if label.startswith('-') or label.endswith('-'):
            return False

    # TLD 不能是纯数字
    if labels[-1].isdigit():
        return False

    return True


def download_and_convert(url: str, format: str = 'adblock', timeout: int = 30) -> Set[str]:
    """下载并解析列表

    Args:
        url: 列表 URL
        format: 格式类型 (adblock, hosts, domains)
        timeout: 下载超时秒数

    Returns:
        解析出的域名集合
    """
    print(f"下载: {url}")

    try:
        req = urllib.request.Request(url, headers={
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
        })
        with urllib.request.urlopen(req, timeout=timeout) as response:
            content = response.read().decode("utf-8", errors="ignore")
    except Exception as e:
        print(f"下载失败: {e}")
        return set()

    # 选择解析器
    if format == 'adblock':
        parser = parse_adblock_rule
    elif format == 'hosts':
        parser = parse_hosts_rule
    else:  # domains
        parser = parse_domain_rule

    # 解析
    domains = set()
    for line in content.splitlines():
        domain = parser(line)
        if domain:
            domains.add(domain)

    print(f"解析完成: {len(domains):,} 个域名")
    return domains


def save_singbox_ruleset(domains: Set[str], output_path: Path):
    """保存为 sing-box rule-set 格式 (source JSON)"""
    ruleset = {
        "version": 1,
        "rules": [
            {"domain_suffix": sorted(domains)}
        ]
    }

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(ruleset, indent=2, ensure_ascii=False))

    file_size = output_path.stat().st_size / 1024
    print(f"已保存: {output_path} ({file_size:.1f} KB)")


def convert_rule_set(url: str, format: str, output_path: Path) -> int:
    """转换单个规则集

    Returns:
        域名数量
    """
    domains = download_and_convert(url, format)
    if domains:
        save_singbox_ruleset(domains, output_path)
    return len(domains)


def main():
    """命令行入口"""
    import argparse

    parser = argparse.ArgumentParser(
        description="将 Adblock Plus 语法转换为 sing-box rule-set 格式"
    )
    parser.add_argument(
        "url",
        help="规则列表 URL"
    )
    parser.add_argument(
        "-o", "--output",
        default="ruleset.json",
        help="输出文件路径 (默认: ruleset.json)"
    )
    parser.add_argument(
        "-f", "--format",
        choices=["adblock", "hosts", "domains"],
        default="adblock",
        help="输入格式 (默认: adblock)"
    )
    parser.add_argument(
        "-t", "--timeout",
        type=int,
        default=30,
        help="下载超时秒数 (默认: 30)"
    )

    args = parser.parse_args()

    domains = download_and_convert(args.url, args.format, args.timeout)
    if domains:
        save_singbox_ruleset(domains, Path(args.output))
        print(f"\n总计: {len(domains):,} 个域名")
    else:
        print("未获取到任何域名")
        exit(1)


if __name__ == "__main__":
    main()

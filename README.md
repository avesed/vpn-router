# Smart WireGuard VPN Gateway

[English](README.en.md) | 中文

Docker 容器，提供 WireGuard 入口 + sing-box 智能分流（按域名/IP/地区路由到不同出口）。

## Quick Start

```bash
mkdir vpn-router && cd vpn-router
curl -O https://raw.githubusercontent.com/avesed/vpn-router/main/docker-compose.yml
docker compose up -d
```

访问 `http://localhost:8080`

## 端口

| 端口 | 用途 |
|------|------|
| 8080 | Web UI + API |
| 36100/udp | WireGuard |

## 功能

- **Ingress Manager** - 管理 WireGuard 客户端，生成配置/二维码
- **Profile Manager** - PIA VPN 线路管理
- **Route Rules** - 自定义域名/IP 路由规则
- **Domain/IP Catalog** - 浏览 GeoSite/GeoIP 数据并创建规则
- **Egress Manager** - 自定义 WireGuard 出口
- **Backup/Restore** - 配置导入导出

## 环境变量

```yaml
environment:
  - PIA_USERNAME=xxx        # PIA 账号（可选）
  - PIA_PASSWORD=xxx        # PIA 密码（可选）
  - WG_SERVER_ENDPOINT=x.x.x.x  # WireGuard 服务器公网地址
```

```
Client Devices
     │
     ▼ WireGuard (UDP 36100)
┌─────────────────────────────────────────┐
│           vpn-gateway container          │
│  ┌─────────────────────────────────────┐ │
│  │  sing-box (wg-server endpoint)      │ │
│  │         ↓ sniff + route             │ │
│  │  ┌──────┴──────┬──────────┐        │ │
│  │  ▼             ▼          ▼        │ │
│  │ direct    PIA VPN    custom WG     │ │
│  └─────────────────────────────────────┘ │
│  ┌─────────────────────────────────────┐ │
│  │  nginx (port 80) → API + Frontend   │ │
│  └─────────────────────────────────────┘ │
└─────────────────────────────────────────┘
```

## License

MIT

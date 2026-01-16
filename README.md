# VPN Router

[English](README.en.md) | 中文

智能 VPN 网关 - 基于 Rust 高性能数据平面的透明代理路由器。

## 架构

```
                        Client Devices
                              │
                              ▼ WireGuard (UDP 36100)
┌─────────────────────────────────────────────────────────────────────┐
│                         vpn-gateway container                        │
│                                                                      │
│  ┌────────────────────────────────────────────────────────────────┐ │
│  │                    Rust Router (数据平面)                       │ │
│  │  ┌──────────────┐  ┌────────────┐  ┌───────────────────────┐  │ │
│  │  │ WireGuard    │  │ TPROXY     │  │ Rule Engine           │  │ │
│  │  │ Userspace    │→ │ 透明代理   │→ │ 域名/IP/GeoIP 匹配    │  │ │
│  │  │ (boringtun)  │  │ TCP + UDP  │  │ 链式路由/ECMP 负载均衡│  │ │
│  │  └──────────────┘  └────────────┘  └───────────────────────┘  │ │
│  │                                              │                  │ │
│  │                    ┌─────────────────────────┼─────────────┐   │ │
│  │                    ▼             ▼           ▼             ▼   │ │
│  │                 direct     WireGuard      Xray          WARP   │ │
│  │                 直连         出口       (VLESS/REALITY)  出口   │ │
│  └────────────────────────────────────────────────────────────────┘ │
│                                                                      │
│  ┌────────────────────────────────────────────────────────────────┐ │
│  │  Python API (控制平面)                    FastAPI :8000        │ │
│  │  • 配置管理   • 出口管理   • 规则管理   • 热重载              │ │
│  └────────────────────────────────────────────────────────────────┘ │
│                                                                      │
│  ┌────────────────────────────────────────────────────────────────┐ │
│  │  Web UI (React + shadcn/ui)               Nginx :36000         │ │
│  └────────────────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────────────┘
```

## 快速开始

```bash
mkdir vpn-router && cd vpn-router
curl -O https://raw.githubusercontent.com/avesed/vpn-router/main/docker-compose.yml
docker compose up -d
```

访问 `http://localhost:36000`

> 容器使用 `network_mode: host`，直接使用宿主机网络。

## 端口

| 端口 | 用途 |
|------|------|
| 36000 | Web UI + API |
| 36100/udp | WireGuard |

## 核心功能

### 入口管理
- WireGuard 客户端设备管理
- 自动生成配置 / 二维码
- 自定义 DNS 和 MTU

### 出口管理
- **PIA VPN** - 一键登录获取区域
- **自定义 WireGuard** - 上传 .conf 或手动配置
- **Xray** - 支持 VLESS + REALITY
- **Cloudflare WARP** - 自动注册

### 路由规则
- 按域名、域名后缀、关键词匹配
- 按 IP 地址 / CIDR 匹配
- 内置 675+ GeoSite 分类和 250+ GeoIP 区域
- 链式路由（多跳）
- ECMP 负载均衡

### 备份恢复
- 选择性备份（入口/出口/规则）
- 敏感数据加密
- 万级规则快速导入

## 环境变量

| 变量 | 说明 | 默认值 |
|------|------|--------|
| `WG_SERVER_ENDPOINT` | WireGuard 公网地址 | - |
| `WEB_PORT` | Web UI 端口 | 36000 |
| `WG_LISTEN_PORT` | WireGuard 端口 | 36100 |
| `PIA_USERNAME` | PIA 账号 (可选) | - |
| `PIA_PASSWORD` | PIA 密码 (可选) | - |

## 技术栈

| 组件 | 技术 |
|------|------|
| 数据平面 | Rust + Tokio + boringtun |
| 控制平面 | Python + FastAPI |
| 前端 | React + Vite + shadcn/ui |
| 数据库 | SQLite (SQLCipher 加密) |
| 协议 | WireGuard, VLESS/REALITY, WARP |

## License

[AGPL-3.0](LICENSE)

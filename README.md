# Smart WireGuard VPN Gateway

[English](README.en.md) | 中文

Docker 容器，提供 WireGuard 入口 + sing-box 智能分流（按域名/IP/地区路由到不同出口）。

## Quick Start

```bash
mkdir vpn-router && cd vpn-router
curl -O https://raw.githubusercontent.com/avesed/vpn-router/main/docker-compose.yml
docker compose up -d
```

访问 `http://localhost:36000`

> **注意**：使用 `network_mode: host`，容器直接使用宿主机网络，无需端口映射。

## 端口

| 端口 | 用途 |
|------|------|
| 36000 | Web UI + API |
| 36100/udp | WireGuard |

## 功能

### 入口管理 (Ingress Manager)
管理 WireGuard 客户端设备连接：
- 添加/编辑/删除客户端 Peer
- 自动生成客户端配置文件
- 扫码连接（生成二维码）
- 支持自定义 DNS 和 MTU

### 线路管理 (Profile Manager)
PIA VPN 出口线路管理：
- 一键登录 PIA 账号获取可用区域
- 添加/删除 VPN 线路
- 断线重连功能
- 支持流媒体优化区域

### 路由规则 (Route Rules)
灵活的流量分流配置：
- 按域名、域名后缀、域名关键词匹配
- 按 IP 地址/CIDR 匹配
- 自定义规则优先级
- 支持直连、阻断、VPN 出口等多种动作
- 设置默认出口

### 域名/IP 目录 (Domain/IP Catalog)
内置丰富的 GeoSite/GeoIP 数据：
- 浏览 675+ 域名分类（流媒体、社交、广告等）
- 浏览 250+ 国家/地区 IP 段
- 一键将分类添加到路由规则
- 支持自定义标签命名

### 出口管理 (Egress Manager)
自定义 WireGuard 出口配置：
- 上传 .conf 文件自动解析
- 粘贴配置文本导入
- 手动填写配置
- 支持 MTU、DNS、预共享密钥等高级选项

### 备份恢复 (Backup/Restore)
完整的配置导入导出：
- 选择性备份（入口配置、出口配置、PIA 线路、路由规则）
- 敏感数据加密（私钥等）
- 支持合并或替换模式导入
- 批量处理优化，支持万级规则快速导入

## 环境变量

```yaml
environment:
  - PIA_USERNAME=xxx           # PIA 账号（可选）
  - PIA_PASSWORD=xxx           # PIA 密码（可选）
  - WG_SERVER_ENDPOINT=x.x.x.x # WireGuard 服务器公网地址
  - WEB_PORT=36000             # Web UI 端口（可选）
  - WG_LISTEN_PORT=36100       # WireGuard 端口（可选）
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
│  │  nginx (port 36000) → API + Frontend│ │
│  └─────────────────────────────────────┘ │
└─────────────────────────────────────────┘
```

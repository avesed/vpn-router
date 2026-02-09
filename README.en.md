# VPN Router

English | [中文](README.md)

Smart VPN Gateway - High-performance transparent proxy router with Rust data plane.

## Architecture

```
                        Client Devices
                              │
                              ▼ WireGuard (UDP 36100)
┌─────────────────────────────────────────────────────────────────────┐
│                         vpn-gateway container                       │
│                                                                     │
│  ┌────────────────────────────────────────────────────────────────┐ │
│  │                    Rust Router (Data Plane)                    │ │
│  │                                                                │ │
│  │  ┌──────────────┐      ┌─────────────────────────────────────┐ │ │
│  │  │ WireGuard    │      │ Rule Engine                         │ │ │
│  │  │ Userspace    │ ───→ │ • DNS sniffing for domain extract   │ │ │
│  │  │ (boringtun)  │      │ • Domain/IP/GeoIP rule matching     │ │ │
│  │  └──────────────┘      │ • Chain routing / ECMP load balance │ │ │
│  │                        └─────────────────────────────────────┘ │ │
│  │                                        │                       │ │
│  │                 ┌──────────────────────┼──────────────┐        │ │
│  │                 ▼          ▼           ▼              ▼        │ │
│  │              direct    WireGuard     Xray           WARP       │ │
│  │                          Egress   (VLESS/REALITY)   Egress     │ │
│  └────────────────────────────────────────────────────────────────┘ │
│                                                                     │
│  ┌────────────────────────────────────────────────────────────────┐ │
│  │  Python API (Control Plane)               FastAPI :8000        │ │
│  │  • Config Mgmt  • Egress Mgmt  • Rules Mgmt  • Hot Reload      │ │
│  └────────────────────────────────────────────────────────────────┘ │
│                                                                     │
│  ┌────────────────────────────────────────────────────────────────┐ │
│  │  Web UI (React + shadcn/ui)               Nginx :36000         │ │
│  └────────────────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────────────┘
```

## Quick Start

```bash
mkdir vpn-router && cd vpn-router
curl -O https://raw.githubusercontent.com/avesed/vpn-router/main/docker-compose.yml
docker compose up -d
```

Open `http://localhost:36000`

> Container uses `network_mode: host`, sharing host network directly.

## Ports

| Port | Usage |
|------|-------|
| 36000 | Web UI + API |
| 36100/udp | WireGuard |

## Features

### Ingress Manager
- WireGuard client device management
- Auto-generate config / QR code
- Custom DNS and MTU

### Egress Manager
- **PIA VPN** - One-click login to fetch regions
- **Custom WireGuard** - Upload .conf or manual config
- **Xray** - VLESS + REALITY support
- **Cloudflare WARP** - Auto registration

### Route Rules
- Match by domain, suffix, or keyword
- Match by IP address / CIDR
- Built-in 675+ GeoSite categories and 250+ GeoIP regions
- Chain routing (multi-hop)
- ECMP load balancing

### Backup/Restore
- Selective backup (ingress/egress/rules)
- Sensitive data encryption
- Fast import for 10,000+ rules

## Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `WG_SERVER_ENDPOINT` | WireGuard public IP | - |
| `WEB_PORT` | Web UI port | 36000 |
| `WG_LISTEN_PORT` | WireGuard port | 36100 |
| `PIA_USERNAME` | PIA account (optional) | - |
| `PIA_PASSWORD` | PIA password (optional) | - |

## Tech Stack

| Component | Technology |
|-----------|------------|
| Data Plane | Rust + Tokio + boringtun |
| Control Plane | Python + FastAPI |
| Frontend | React + Vite + shadcn/ui |
| Database | SQLite (SQLCipher encrypted) |
| Protocols | WireGuard, VLESS/REALITY, WARP |

## License

[AGPL-3.0](LICENSE)

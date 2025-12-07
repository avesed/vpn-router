# Smart WireGuard VPN Gateway

English | [中文](README.md)

Docker container providing WireGuard ingress + sing-box smart routing (route traffic to different exits by domain/IP/region).

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

## Quick Start

```bash
mkdir vpn-router && cd vpn-router
curl -O https://raw.githubusercontent.com/avesed/vpn-router/main/docker-compose.yml
docker compose up -d
```

Open `http://localhost:8080`

## Ports

| Port | Usage |
|------|-------|
| 8080 | Web UI + API |
| 36100/udp | WireGuard |

## Features

- **Ingress Manager** - Manage WireGuard clients, generate config/QR code
- **Profile Manager** - PIA VPN line management
- **Route Rules** - Custom domain/IP routing rules
- **Domain/IP Catalog** - Browse GeoSite/GeoIP data and create rules
- **Egress Manager** - Custom WireGuard exits
- **Backup/Restore** - Configuration import/export

## Environment Variables

```yaml
environment:
  - PIA_USERNAME=xxx           # PIA account (optional)
  - PIA_PASSWORD=xxx           # PIA password (optional)
  - WG_SERVER_ENDPOINT=x.x.x.x # WireGuard server public IP
```

## License

MIT

# Smart WireGuard VPN Gateway

English | [中文](README.md)

Docker container providing WireGuard ingress + sing-box smart routing (route traffic to different exits by domain/IP/region).

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

## Quick Start

```bash
mkdir vpn-router && cd vpn-router
curl -O https://raw.githubusercontent.com/avesed/vpn-router/main/docker-compose.yml
docker compose up -d
```

Open `http://localhost:36000`

> **Note**: Uses `network_mode: host`, container shares host network directly without port mapping.

## Ports

| Port | Usage |
|------|-------|
| 36000 | Web UI + API |
| 36100/udp | WireGuard |

## Features

### Ingress Manager
Manage WireGuard client device connections:
- Add/edit/delete client peers
- Auto-generate client configuration files
- QR code for easy mobile setup
- Custom DNS and MTU support

### Profile Manager
PIA VPN exit line management:
- One-click PIA login to fetch available regions
- Add/remove VPN lines
- Reconnect on disconnect
- Streaming-optimized region support

### Route Rules
Flexible traffic routing configuration:
- Match by domain, domain suffix, or domain keyword
- Match by IP address/CIDR
- Custom rule priority
- Multiple actions: direct, block, VPN exit
- Set default outbound

### Domain/IP Catalog
Built-in rich GeoSite/GeoIP data:
- Browse 675+ domain categories (streaming, social, ads, etc.)
- Browse 250+ country/region IP ranges
- One-click add categories to routing rules
- Custom tag naming support

### Egress Manager
Custom WireGuard exit configuration:
- Upload .conf file with auto-parsing
- Paste configuration text to import
- Manual configuration input
- Advanced options: MTU, DNS, preshared key

### Backup/Restore
Complete configuration import/export:
- Selective backup (ingress, egress, PIA profiles, routing rules)
- Sensitive data encryption (private keys, etc.)
- Merge or replace import modes
- Batch processing optimized for 10,000+ rules

## Environment Variables

```yaml
environment:
  - PIA_USERNAME=xxx           # PIA account (optional)
  - PIA_PASSWORD=xxx           # PIA password (optional)
  - WG_SERVER_ENDPOINT=x.x.x.x # WireGuard server public IP
  - WEB_PORT=36000             # Web UI port (optional)
  - WG_LISTEN_PORT=36100       # WireGuard port (optional)
```

## License

MIT

# Smart WireGuard VPN Gateway

A centralized "smart gateway" Docker container that provides WireGuard ingress for client devices, with sing-box handling multi-exit routing based on geosite/geoip/domain classification for gaming, streaming, domestic/international traffic with DNS/IPv6 leak protection.

## Key Features

- **WireGuard Server**: sing-box 1.12+ endpoint mode accepts WireGuard client connections directly
- **Multi-Exit Routing**: Built-in direct, PIA VPN regions, custom WireGuard exits
- **Smart Traffic Splitting**: Domain/IP-based routing rules for streaming, gaming, regional content
- **DNS/IPv6 Leak Protection**: Encrypted DNS via VPN exits, IPv6 disabled by default
- **Web Management UI**: React-based dashboard for configuration and monitoring
- **Database-Driven Config**: All settings stored in SQLite, auto-generated sing-box config

## Architecture

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

### 1. Clone and Start

```bash
git clone <repository>
cd vpn-router
docker compose up -d
```

### 2. Access Web Interface

Open `http://localhost` in your browser.

### 3. Configure WireGuard Client

1. Go to **Ingress Manager** in the web UI
2. Add a new peer (client device)
3. Scan the QR code or download the config file

### 4. Optional: Add PIA VPN

1. Go to **Profile Manager**
2. Click "Add Profile" and select a PIA region
3. Enter your PIA credentials when prompted
4. The profile will be provisioned automatically

## Services

| Service | Port | Description |
|---------|------|-------------|
| Web UI | 80 | Dashboard, configuration |
| API | 80/api | Backend REST API |
| WireGuard | 36100/udp | Client VPN connections |

## Configuration

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `PIA_USERNAME` | - | PIA account username |
| `PIA_PASSWORD` | - | PIA account password |
| `DISABLE_IPV6` | `1` | Disable IPv6 to prevent leaks |
| `TZ` | `Asia/Shanghai` | Container timezone |

### Volume Mounts

```yaml
volumes:
  - ./config:/etc/sing-box
```

The `config/` directory contains:
- `geoip-geodata.db` - Pre-built GeoIP/domain data (49 MB)
- `user-config.db` - User settings (auto-created)
- `sing-box.generated.json` - Runtime config (auto-generated)

## Web UI Features

- **Dashboard**: Real-time status, sing-box metrics
- **Profile Manager**: PIA VPN line management
- **Route Rules**: Custom domain/IP routing rules
- **Domain Catalog**: Browse and create rules from geo data
- **IP Catalog**: Browse countries for IP-based rules
- **Egress Manager**: Custom WireGuard exit configuration
- **Ingress Manager**: WireGuard client peer management
- **Backup/Restore**: Export/import configuration

## API Endpoints

```bash
# Status
curl http://localhost/api/status

# List profiles
curl http://localhost/api/profiles

# List routing rules
curl http://localhost/api/rules

# WireGuard peers
curl http://localhost/api/ingress
```

## Traffic Routing

sing-box processes rules in order (first match wins):

1. **Sniff action** - Detect domain from TLS SNI
2. **Custom rules** - User-defined domain/IP rules
3. **GeoIP rules** - Country-based IP routing
4. **GeoSite rules** - Domain category routing
5. **Final** - Default outbound (fallback)

### Example Rules

| Traffic | Outbound |
|---------|----------|
| Steam, gaming domains | `direct` |
| Netflix, streaming | `us-stream` (PIA US) |
| China domains | `direct` |
| Default | Configurable |

## Development

### Frontend Development

```bash
cd frontend
npm install
npm run dev  # http://localhost:5173
```

### Container Shell

```bash
docker compose exec vpn-gateway bash
```

### Rebuild After Changes

```bash
docker compose up -d --build
```

### View Logs

```bash
docker compose logs -f vpn-gateway
```

## Technical Details

### sing-box 1.12+ Endpoint Mode

WireGuard is configured as an **endpoint** (not traditional inbound):

```json
{
  "endpoints": [{
    "type": "wireguard",
    "tag": "wg-server",
    "listen_port": 36100,
    "address": ["10.23.0.1/24"],
    "private_key": "...",
    "peers": [{"public_key": "...", "allowed_ips": ["10.23.0.2/32"]}]
  }]
}
```

### Database Architecture

- **geoip-geodata.db** (49 MB): Read-only GeoIP/domain data
- **user-config.db** (60 KB): User settings, routing rules, WireGuard config

### PIA Integration

When PIA credentials are provided:
1. Authenticates against PIA API
2. Generates WireGuard keys for each profile
3. Stores credentials in database
4. Auto-generates sing-box endpoints

## Security Notes

- API has no authentication (designed for local use only)
- PIA credentials stored in memory only, lost on restart
- IPv6 disabled by default to prevent leaks
- All DNS queries routed through VPN when using VPN exits

## License

MIT

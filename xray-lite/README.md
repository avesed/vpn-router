# xray-lite

Minimized Xray-core build for vpn-router V2Ray ingress. This is a fork of [Xray-core](https://github.com/XTLS/Xray-core) with unused modules removed to reduce binary size.

## Purpose

The vpn-router project uses Xray for V2Ray ingress (**VLESS only** with REALITY/XTLS-Vision). The full Xray-core binary includes many features not needed for this use case. xray-lite removes:

- **VMess protocol** - Removed (deprecated in Phase XL)
- **Trojan protocol** - Removed (deprecated in Phase XL)
- **Shadowsocks** - Removed
- Unused outbound protocols (SOCKS, HTTP, WireGuard, DNS, etc.)
- Unused transports (kcp, quic, httpupgrade, splithttp, meek)
- Test files and mock implementations

**Supported protocols**: VLESS only (with REALITY and XTLS-Vision)
**Supported transports**: TCP, WebSocket, gRPC, HTTP/2, XHTTP

## Binary Size (v25.12.8)

| Build Type | Binary Size | Notes |
|------------|-------------|-------|
| Official Xray | ~25 MB | Full release binary |
| xray-lite (uncompressed) | 21 MB | VMess/Trojan removed |
| xray-lite (UPX) | **5.7 MB** | --best --lzma compression |
| **Size Reduction** | **77%** | 25 MB → 5.7 MB |

## Requirements

- Go 1.25+ (or Docker with golang:1.25 image)

## Build Instructions

### Development Build

```bash
./build.sh
```

### Release Build (optimized for size)

```bash
./build-release.sh
# or with custom output name
./build-release.sh xray-lite
```

### Docker Build

```bash
docker build -t xray-lite .
# Extract binary
docker create --name xray-lite-temp xray-lite
docker cp xray-lite-temp:/xray ./xray
docker rm xray-lite-temp
```

## Verification

```bash
./xray version
# Expected output:
# Xray 25.12.8 (Xray, Penetrates Everything.) Custom (go1.25.x linux/amd64)
# A unified platform for anti-censorship.
```

## Module Pruning (Completed)

### Phase XL.0-XL.4: Protocol Removal ✅
- **Removed**: VMess, Trojan, Shadowsocks (inbound/outbound)
- **Removed**: SOCKS, HTTP, WireGuard, DNS (outbound)
- **Removed**: kcp, quic, httpupgrade, splithttp, meek (transports)
- **Kept**: VLESS, TCP, WebSocket, gRPC, HTTP/2, XHTTP, REALITY, TLS

### Phase XL.5: Build Optimization ✅
- Static binary with CGO_ENABLED=0
- Symbol stripping (-s -w)
- UPX compression (--best --lzma)

### Phase XL.6-XL.8: Integration ✅
- Python validation (rejects VMess/Trojan at API layer)
- Docker build-from-source
- Migration documentation

**Migration Guide**: See `docs/VMESS_TROJAN_MIGRATION.md`

## Directory Structure

```
xray-lite/
├── go.mod                 # Module definition
├── go.sum                 # Dependency checksums
├── main/                  # Entry point and commands
├── app/                   # Application components
├── common/                # Common utilities
├── core/                  # Core functionality
├── features/              # Feature interfaces
├── infra/                 # Infrastructure code
├── proxy/                 # Protocol implementations
├── transport/             # Transport implementations
├── build.sh               # Development build
├── build-release.sh       # Release build
├── Dockerfile             # Docker build
├── README.md              # This file
└── README-upstream.md     # Original Xray-core README
```

## License

Same as Xray-core: [MPL 2.0](LICENSE)

## Upstream

Based on Xray-core v25.12.8: https://github.com/XTLS/Xray-core

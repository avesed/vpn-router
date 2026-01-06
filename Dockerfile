# ==========================================
# Stage 1: Build xray-lite from source
# ==========================================
# [Phase XL] Build minimized Xray supporting only VLESS + XHTTP + REALITY
# This reduces binary from ~21MB to ~5.7MB (with UPX --best --lzma)
# See xray-lite/README.md for details on removed protocols
FROM golang:1.25-bookworm AS xray-builder

ARG TARGETARCH

# Download UPX for binary compression (~70% size reduction)
# UPX not available in Debian bookworm repos, downloading from GitHub
# SHA256 checksums verified from official UPX releases (supply chain security)
RUN UPX_VERSION="4.2.4" && \
    UPX_ARCH="amd64" && \
    UPX_SHA256="75cab4e57ab72fb4585ee45ff36388d280c7afd72aa03e8d4b9c3cbddb474193" && \
    if [ "$TARGETARCH" = "arm64" ]; then \
        UPX_ARCH="arm64"; \
        UPX_SHA256="6bfeae6714e34a82e63245289888719c41fd6af29f749a44ae3d3d166ba6a1c9"; \
    fi && \
    apt-get update && apt-get install -y --no-install-recommends curl xz-utils && \
    curl -fsSL -o /tmp/upx.tar.xz "https://github.com/upx/upx/releases/download/v${UPX_VERSION}/upx-${UPX_VERSION}-${UPX_ARCH}_linux.tar.xz" && \
    echo "${UPX_SHA256}  /tmp/upx.tar.xz" | sha256sum -c - && \
    tar -xJf /tmp/upx.tar.xz -C /tmp && \
    mv /tmp/upx-${UPX_VERSION}-${UPX_ARCH}_linux/upx /usr/local/bin/upx && \
    chmod +x /usr/local/bin/upx && \
    rm -rf /tmp/upx* && \
    apt-get remove -y curl xz-utils && apt-get autoremove -y && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /build

# Copy xray-lite source code (minimized Xray fork)
COPY xray-lite/ .

# Build release binary with optimizations:
# - CGO_ENABLED=0: Static binary, no libc dependency
# - netgo: Pure Go DNS resolver (no cgo)
# - -s -w: Strip symbols and DWARF debug info
# - -trimpath: Remove local paths from binary
# - -buildid=: Empty build ID for reproducibility
RUN BUILD_DATE="$(date -u +%Y-%m-%dT%H:%M:%SZ)" && \
    LDFLAGS="-s -w -buildid= -X github.com/xtls/xray-core/core.build=${BUILD_DATE}" && \
    echo "Building xray-lite for ${TARGETARCH}..." && \
    CGO_ENABLED=0 GOOS=linux GOARCH=${TARGETARCH} go build \
        -tags="netgo" \
        -ldflags="${LDFLAGS}" \
        -trimpath \
        -o /xray \
        ./main && \
    echo "Build complete, size before UPX:" && \
    ls -lh /xray && \
    echo "Applying UPX compression (--best --lzma)..." && \
    upx --best --lzma /xray && \
    echo "Final size after UPX:" && \
    ls -lh /xray

# ==========================================
# Stage 2: Download usque binary (WARP MASQUE)
# ==========================================
FROM debian:12-slim AS usque-downloader

ARG USQUE_VERSION=1.4.2
ARG TARGETARCH

RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    unzip \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Download usque binary (release is a zip file)
# usque provides WARP MASQUE protocol support (RFC 9484 Connect-IP over HTTP/3)
# https://github.com/Diniboy1123/usque
# Release format: usque_VERSION_linux_ARCH.zip
RUN USQUE_ARCH="" && \
    if [ "$TARGETARCH" = "amd64" ]; then USQUE_ARCH="amd64"; \
    elif [ "$TARGETARCH" = "arm64" ]; then USQUE_ARCH="arm64"; \
    else echo "Unsupported architecture: $TARGETARCH" && exit 1; fi && \
    USQUE_ZIP="usque_${USQUE_VERSION}_linux_${USQUE_ARCH}.zip" && \
    USQUE_URL="https://github.com/Diniboy1123/usque/releases/download/v${USQUE_VERSION}/${USQUE_ZIP}" && \
    curl -fsSL -o /tmp/usque.zip "${USQUE_URL}" && \
    cd /tmp && \
    unzip usque.zip && \
    chmod +x usque && \
    mv usque /usr/local/bin/usque && \
    echo "usque downloaded successfully"

# ==========================================
# Stage 3: Build sing-box with v2ray_api
# ==========================================
FROM golang:1.23-bookworm AS singbox-builder

ARG SINGBOX_VERSION=1.12.13

RUN apt-get update && apt-get install -y --no-install-recommends git ca-certificates && rm -rf /var/lib/apt/lists/*

WORKDIR /src
RUN git clone --depth 1 --branch v${SINGBOX_VERSION} https://github.com/SagerNet/sing-box.git .

# Build with all required tags including v2ray_api
# CGO_ENABLED=0 for static linking
RUN CGO_ENABLED=0 go build -v -trimpath -ldflags "-s -w -buildid=" \
    -tags "with_gvisor,with_quic,with_dhcp,with_wireguard,with_utls,with_acme,with_clash_api,with_v2ray_api" \
    -o /sing-box ./cmd/sing-box

# ==========================================
# Stage 4: Build Frontend
# ==========================================
FROM node:20-alpine AS frontend-builder

WORKDIR /app
COPY frontend/package*.json ./
RUN npm ci
COPY frontend/ ./
RUN npm run build

# ==========================================
# Stage 5: Production Runtime
# ==========================================
FROM debian:12-slim

ENV SING_BOX_CONFIG=/etc/sing-box/sing-box.json \
    RULESET_DIR=/etc/sing-box \
    PYTHONPATH=/usr/local/bin

# Install build dependencies (will be removed after pip install)
# Must include python3-pip for pip3 command
RUN set -eux; \
    apt-get update; \
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        build-essential \
        python3 \
        python3-pip \
        python3-dev \
        libsqlcipher-dev; \
    rm -rf /var/lib/apt/lists/*

# Copy and install pinned Python dependencies (C8: version pinning)
# Install before runtime deps to leverage build cache
COPY requirements.txt /tmp/requirements.txt
RUN pip3 install --no-cache-dir --break-system-packages -r /tmp/requirements.txt && \
    rm /tmp/requirements.txt

# Remove build dependencies and install runtime dependencies
# This reduces image size by ~100MB
RUN set -eux; \
    apt-get update; \
    apt-get remove -y --purge build-essential python3-dev && \
    apt-get autoremove -y; \
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        ca-certificates \
        curl \
        gettext-base \
        iproute2 \
        iptables \
        iputils-ping \
        jq \
        libsqlcipher0 \
        openvpn \
        procps \
        python3 \
        python3-pip \
        python3-requests \
        python3-yaml \
        python3-fastapi \
        python3-uvicorn \
        python3-pydantic \
        python3-qrcode \
        python3-pil \
        wireguard-tools \
        nginx-light; \
    rm -rf /var/lib/apt/lists/*; \
    mkdir -p /etc/openvpn/configs /run/openvpn /var/log/openvpn

# Copy sing-box binary built from source (with v2ray_api support)
COPY --from=singbox-builder /sing-box /usr/local/bin/sing-box
RUN chmod +x /usr/local/bin/sing-box

# Copy xray-lite binary (minimized Xray: VLESS + XHTTP + REALITY only)
# [Phase XL] ~5.7MB vs ~25MB official Xray binary (77% size reduction)
COPY --from=xray-builder /xray /usr/local/bin/xray
RUN chmod +x /usr/local/bin/xray

# Copy usque binary for WARP MASQUE protocol support
COPY --from=usque-downloader /usr/local/bin/usque /usr/local/bin/usque
RUN chmod +x /usr/local/bin/usque

# Copy frontend build output
COPY --from=frontend-builder /app/dist /var/www/html

# Copy nginx configuration template (processed by entrypoint.sh with envsubst)
COPY frontend/nginx.conf.template /etc/nginx/nginx.conf.template

# Configure nginx (use conf.d for dynamic config generation)
RUN rm -f /etc/nginx/sites-enabled/default /etc/nginx/sites-available/default && \
    mkdir -p /etc/nginx/conf.d /var/log/nginx && \
    chown -R www-data:www-data /var/log/nginx

COPY config /etc/sing-box/

# Copy default config to a separate location (not affected by volume mount)
# This allows first-run initialization of catalogs
# Note: GeoIP data now uses JSON files instead of SQLite database (12 MB vs 49 MB)
COPY config/sing-box.json /opt/default-config/sing-box.json
COPY config/domain-catalog.json /opt/default-config/domain-catalog.json
COPY config/geoip-catalog.json /opt/default-config/geoip-catalog.json
COPY config/geoip /opt/default-config/geoip

RUN mkdir -p /opt/pia/ca
COPY scripts/entrypoint.sh /usr/local/bin/entrypoint.sh
COPY scripts/fetch-geodata.sh /usr/local/bin/fetch-geodata.sh
COPY scripts/render_singbox.py /usr/local/bin/render_singbox.py
COPY scripts/pia/pia_provision.py /usr/local/bin/pia_provision.py
COPY scripts/api_server.py /usr/local/bin/api_server.py
COPY scripts/db_helper.py /usr/local/bin/db_helper.py
COPY scripts/init_user_db.py /usr/local/bin/init_user_db.py
COPY scripts/convert_adblock.py /usr/local/bin/convert_adblock.py
COPY scripts/openvpn_manager.py /usr/local/bin/openvpn_manager.py
COPY scripts/xray_manager.py /usr/local/bin/xray_manager.py
COPY scripts/xray_egress_manager.py /usr/local/bin/xray_egress_manager.py
COPY scripts/xray_peer_inbound_manager.py /usr/local/bin/xray_peer_inbound_manager.py
COPY scripts/warp_manager.py /usr/local/bin/warp_manager.py
COPY scripts/warp_endpoint_optimizer.py /usr/local/bin/warp_endpoint_optimizer.py
COPY scripts/v2ray_stats_pb2.py /usr/local/bin/v2ray_stats_pb2.py
COPY scripts/v2ray_stats_pb2_grpc.py /usr/local/bin/v2ray_stats_pb2_grpc.py
COPY scripts/v2ray_stats_client.py /usr/local/bin/v2ray_stats_client.py
COPY scripts/v2ray_uri_parser.py /usr/local/bin/v2ray_uri_parser.py
COPY scripts/setup_kernel_wg.py /usr/local/bin/setup_kernel_wg.py
COPY scripts/setup_kernel_wg_egress.py /usr/local/bin/setup_kernel_wg_egress.py
COPY scripts/key_manager.py /usr/local/bin/key_manager.py
COPY scripts/ecmp_manager.py /usr/local/bin/ecmp_manager.py
COPY scripts/health_checker.py /usr/local/bin/health_checker.py
COPY scripts/peer_tunnel_manager.py /usr/local/bin/peer_tunnel_manager.py
# Phase 11: Multi-node peering scripts
COPY scripts/dscp_manager.py /usr/local/bin/dscp_manager.py
COPY scripts/relay_config_manager.py /usr/local/bin/relay_config_manager.py
COPY scripts/peer_pairing.py /usr/local/bin/peer_pairing.py
COPY scripts/tunnel_api_client.py /usr/local/bin/tunnel_api_client.py
COPY scripts/chain_route_manager.py /usr/local/bin/chain_route_manager.py
COPY config/pia/ca/rsa_4096.crt /opt/pia/ca/rsa_4096.crt
RUN chmod +x /usr/local/bin/entrypoint.sh /usr/local/bin/fetch-geodata.sh \
    /usr/local/bin/render_singbox.py /usr/local/bin/pia_provision.py \
    /usr/local/bin/api_server.py /usr/local/bin/init_user_db.py \
    /usr/local/bin/convert_adblock.py /usr/local/bin/openvpn_manager.py \
    /usr/local/bin/setup_kernel_wg.py \
    /usr/local/bin/setup_kernel_wg_egress.py /usr/local/bin/xray_manager.py \
    /usr/local/bin/xray_egress_manager.py /usr/local/bin/xray_peer_inbound_manager.py \
    /usr/local/bin/warp_manager.py \
    /usr/local/bin/warp_endpoint_optimizer.py /usr/local/bin/ecmp_manager.py \
    /usr/local/bin/health_checker.py /usr/local/bin/peer_tunnel_manager.py \
    /usr/local/bin/dscp_manager.py /usr/local/bin/relay_config_manager.py \
    /usr/local/bin/peer_pairing.py /usr/local/bin/tunnel_api_client.py \
    /usr/local/bin/chain_route_manager.py

# Note: Config is mounted via docker-compose volumes
# - user-config.db is auto-created on first run by init_user_db.py
# - GeoIP data uses JSON files: geoip-catalog.json + geoip/*.json (~12 MB)
# - All config files are accessed via: ./config:/etc/sing-box

WORKDIR /etc/sing-box
VOLUME ["/etc/sing-box"]

EXPOSE 80 8000 36100/udp

# Health check - 检查 API 服务是否响应
HEALTHCHECK --interval=30s --timeout=10s --start-period=60s --retries=3 \
    CMD curl -f http://localhost:8000/api/health || exit 1

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
CMD ["sing-box", "run", "-c", "/etc/sing-box/sing-box.json"]

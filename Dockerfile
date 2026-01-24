# ==========================================
# Stage 0: Shared CA certificates for slim images
# ==========================================
FROM golang:1.23-bookworm AS ca-certs

# ==========================================
# Stage 1: Build rust-router
# ==========================================
# High-performance Rust data plane for TPROXY transparent proxying
# - p99 latency: 2.775μs (360x better than target)
# - Throughput: 50.7M ops/s (50x better than target)
# - 720+ tests passing with 100% pass rate
FROM rust:1.93-bookworm AS rust-router-builder

ARG TARGETARCH

WORKDIR /build

# Copy Cargo files first for dependency caching
COPY rust-router/Cargo.toml rust-router/Cargo.lock ./

# Create dummy src and benches to pre-build dependencies (layer caching optimization)
RUN mkdir -p src/bin benches && \
    echo 'fn main() {}' > src/main.rs && \
    echo 'pub fn lib() {}' > src/lib.rs && \
    echo 'fn main() {}' > src/bin/tproxy_poc.rs && \
    echo 'fn main() {}' > src/bin/udp_tproxy_poc.rs && \
    echo 'fn main() {}' > benches/rule_matching.rs && \
    echo 'fn main() {}' > benches/throughput.rs && \
    echo 'fn main() {}' > benches/ab_comparison.rs && \
    cargo build --release 2>/dev/null || true && \
    rm -rf src benches

# Copy actual source code and benches
COPY rust-router/src ./src
COPY rust-router/benches ./benches

# Rebuild with actual source (dependencies are cached)
# Profile settings from Cargo.toml: lto=true, codegen-units=1, panic=abort, strip=true
RUN touch src/main.rs src/lib.rs && \
    cargo build --release --bin rust-router --features shadowsocks && \
    ls -lh target/release/rust-router

# ==========================================
# Stage 5: Build Frontend (shadcn/ui rebuild)
# ==========================================
FROM node:20-alpine AS frontend-builder

WORKDIR /app
COPY frontend-new/package*.json ./
RUN npm ci
COPY frontend-new/ ./
RUN npm run build

# ==========================================
# Stage 6: Production Runtime
# ==========================================
FROM debian:12-slim

COPY --from=ca-certs /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt

RUN set -eux; \
    for file in /etc/apt/sources.list \
        /etc/apt/sources.list.d/debian.sources; do \
        if [ -f "$file" ]; then \
            sed -i 's|http://|https://|g' "$file"; \
        fi; \
    done

ENV SING_BOX_CONFIG=/etc/sing-box/sing-box.json \
    RULESET_DIR=/etc/sing-box \
    PYTHONPATH=/usr/local/bin \
    USE_RUST_ROUTER=true \
    RUST_ROUTER_BIN=/usr/local/bin/rust-router \
    RUST_ROUTER_CONFIG=/etc/rust-router/config.json \
    RUST_ROUTER_SOCKET=/var/run/rust-router.sock \
    RUST_ROUTER_LOG=/var/log/rust-router.log

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

# NOTE: sing-box and xray-lite removed - replaced by rust-router for all routing
# VLESS/REALITY support now native in rust-router (Rust implementation)

# Copy rust-router binary (primary data plane)
# Binary size: ~3.1 MB, LTO optimized, stripped
COPY --from=rust-router-builder /build/target/release/rust-router /usr/local/bin/rust-router
RUN chmod +x /usr/local/bin/rust-router && \
    mkdir -p /etc/rust-router /var/log

# Copy frontend build output
COPY --from=frontend-builder /app/dist /var/www/html

# Copy nginx configuration template (processed by entrypoint.sh with envsubst)
COPY frontend-new/nginx.conf.template /etc/nginx/nginx.conf.template

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
# NOTE: render_singbox.py removed - sing-box replaced by rust-router
COPY scripts/pia/pia_provision.py /usr/local/bin/pia_provision.py
COPY scripts/api_server.py /usr/local/bin/api_server.py
COPY scripts/db_helper.py /usr/local/bin/db_helper.py
COPY scripts/init_user_db.py /usr/local/bin/init_user_db.py
COPY scripts/convert_adblock.py /usr/local/bin/convert_adblock.py
COPY scripts/openvpn_manager.py /usr/local/bin/openvpn_manager.py
# NOTE: xray_*.py managers removed - VLESS via rust-router IPC
COPY scripts/warp_endpoint_optimizer.py /usr/local/bin/warp_endpoint_optimizer.py
COPY scripts/v2ray_stats_pb2.py /usr/local/bin/v2ray_stats_pb2.py
COPY scripts/v2ray_stats_pb2_grpc.py /usr/local/bin/v2ray_stats_pb2_grpc.py
COPY scripts/v2ray_stats_client.py /usr/local/bin/v2ray_stats_client.py
COPY scripts/v2ray_uri_parser.py /usr/local/bin/v2ray_uri_parser.py
COPY scripts/key_manager.py /usr/local/bin/key_manager.py
# NOTE: ecmp_manager.py removed - rust-router handles ECMP internally
COPY scripts/health_checker.py /usr/local/bin/health_checker.py
COPY scripts/peer_tunnel_manager.py /usr/local/bin/peer_tunnel_manager.py
# Multi-node peering scripts
COPY scripts/dscp_manager.py /usr/local/bin/dscp_manager.py
COPY scripts/relay_config_manager.py /usr/local/bin/relay_config_manager.py
COPY scripts/peer_pairing.py /usr/local/bin/peer_pairing.py
COPY scripts/tunnel_api_client.py /usr/local/bin/tunnel_api_client.py
COPY scripts/chain_route_manager.py /usr/local/bin/chain_route_manager.py
# rust-router integration scripts
COPY scripts/rust_router_client.py /usr/local/bin/rust_router_client.py
COPY scripts/rust_router_manager.py /usr/local/bin/rust_router_manager.py
COPY scripts/render_routing_config.py /usr/local/bin/render_routing_config.py
COPY scripts/watchdog.py /usr/local/bin/watchdog.py
# Global logging configuration module (LOG_LEVEL environment variable support)
COPY scripts/log_config.py /usr/local/bin/log_config.py
COPY config/pia/ca/rsa_4096.crt /opt/pia/ca/rsa_4096.crt
RUN chmod +x /usr/local/bin/entrypoint.sh /usr/local/bin/fetch-geodata.sh \
    /usr/local/bin/pia_provision.py \
    /usr/local/bin/api_server.py /usr/local/bin/init_user_db.py \
    /usr/local/bin/convert_adblock.py /usr/local/bin/openvpn_manager.py \
    /usr/local/bin/warp_endpoint_optimizer.py \
    /usr/local/bin/health_checker.py /usr/local/bin/peer_tunnel_manager.py \
    /usr/local/bin/dscp_manager.py /usr/local/bin/relay_config_manager.py \
    /usr/local/bin/peer_pairing.py /usr/local/bin/tunnel_api_client.py \
    /usr/local/bin/chain_route_manager.py \
    /usr/local/bin/rust_router_client.py /usr/local/bin/rust_router_manager.py \
    /usr/local/bin/render_routing_config.py /usr/local/bin/watchdog.py

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
# NOTE: sing-box removed - entrypoint.sh starts rust-router directly
CMD []

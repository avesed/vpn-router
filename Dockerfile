# ==========================================
# Stage 1: Download Xray binary
# ==========================================
FROM debian:12-slim AS xray-downloader

ARG XRAY_VERSION=25.12.8

RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    unzip \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Download and extract Xray
RUN curl -fsSL "https://github.com/XTLS/Xray-core/releases/download/v${XRAY_VERSION}/Xray-linux-64.zip" -o /tmp/xray.zip \
    && cd /tmp \
    && unzip xray.zip \
    && chmod +x xray \
    && mv xray /usr/local/bin/xray

# ==========================================
# Stage 2: Build sing-box with v2ray_api
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
# Stage 3: Build Frontend
# ==========================================
FROM node:20-alpine AS frontend-builder

WORKDIR /app
COPY frontend/package*.json ./
RUN npm ci
COPY frontend/ ./
RUN npm run build

# ==========================================
# Stage 4: Production Runtime
# ==========================================
FROM debian:12-slim

ENV SING_BOX_CONFIG=/etc/sing-box/sing-box.json \
    RULESET_DIR=/etc/sing-box \
    PYTHONPATH=/usr/local/bin

RUN set -eux; \
    apt-get update; \
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        ca-certificates \
        curl \
        gettext-base \
        iproute2 \
        iptables \
        iputils-ping \
        jq \
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
    pip3 install --no-cache-dir --break-system-packages cryptography grpcio grpcio-tools; \
    rm -rf /var/lib/apt/lists/*; \
    mkdir -p /etc/openvpn/configs /run/openvpn /var/log/openvpn

# Copy sing-box binary built from source (with v2ray_api support)
COPY --from=singbox-builder /sing-box /usr/local/bin/sing-box
RUN chmod +x /usr/local/bin/sing-box

# Copy Xray binary for V2Ray ingress (XTLS-Vision, REALITY support)
COPY --from=xray-downloader /usr/local/bin/xray /usr/local/bin/xray
RUN chmod +x /usr/local/bin/xray

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
# This allows first-run initialization of geodata database and catalogs
# Note: geoip-geodata.db moved to geodata/ to avoid duplication in COPY config /etc/sing-box/
COPY geodata/geoip-geodata.db /opt/default-config/geoip-geodata.db
COPY config/sing-box.json /opt/default-config/sing-box.json
COPY config/domain-catalog.json /opt/default-config/domain-catalog.json

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
COPY scripts/socks5_proxy.py /usr/local/bin/socks5_proxy.py
COPY scripts/xray_manager.py /usr/local/bin/xray_manager.py
COPY scripts/xray_egress_manager.py /usr/local/bin/xray_egress_manager.py
COPY scripts/v2ray_stats_pb2.py /usr/local/bin/v2ray_stats_pb2.py
COPY scripts/v2ray_stats_pb2_grpc.py /usr/local/bin/v2ray_stats_pb2_grpc.py
COPY scripts/v2ray_stats_client.py /usr/local/bin/v2ray_stats_client.py
COPY scripts/v2ray_uri_parser.py /usr/local/bin/v2ray_uri_parser.py
COPY scripts/setup_kernel_wg.py /usr/local/bin/setup_kernel_wg.py
COPY scripts/setup_kernel_wg_egress.py /usr/local/bin/setup_kernel_wg_egress.py
COPY config/pia/ca/rsa_4096.crt /opt/pia/ca/rsa_4096.crt
RUN chmod +x /usr/local/bin/entrypoint.sh /usr/local/bin/fetch-geodata.sh \
    /usr/local/bin/render_singbox.py /usr/local/bin/pia_provision.py \
    /usr/local/bin/api_server.py /usr/local/bin/init_user_db.py \
    /usr/local/bin/convert_adblock.py /usr/local/bin/openvpn_manager.py \
    /usr/local/bin/socks5_proxy.py /usr/local/bin/setup_kernel_wg.py \
    /usr/local/bin/setup_kernel_wg_egress.py /usr/local/bin/xray_manager.py \
    /usr/local/bin/xray_egress_manager.py

# Note: Databases and config are mounted via docker-compose volumes
# - geoip-geodata.db is pre-built and volume-mounted (49 MB, read-only)
# - user-config.db is auto-created on first run by init_user_db.py
# - All config files are accessed via: ./config:/etc/sing-box

WORKDIR /etc/sing-box
VOLUME ["/etc/sing-box"]

EXPOSE 80 8000 36100/udp

# Health check - 检查 API 服务是否响应
HEALTHCHECK --interval=30s --timeout=10s --start-period=60s --retries=3 \
    CMD curl -f http://localhost:8000/api/health || exit 1

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
CMD ["sing-box", "run", "-c", "/etc/sing-box/sing-box.json"]

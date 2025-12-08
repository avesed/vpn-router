# ==========================================
# Stage 1: Build Frontend
# ==========================================
FROM node:20-alpine AS frontend-builder

WORKDIR /app
COPY frontend/package*.json ./
RUN npm ci
COPY frontend/ ./
RUN npm run build

# ==========================================
# Stage 2: Extract sing-box Binary
# ==========================================
FROM ghcr.io/sagernet/sing-box:latest AS singbox-binary

# ==========================================
# Stage 3: Production Runtime
# ==========================================
FROM debian:12-slim

ENV SING_BOX_CONFIG=/etc/sing-box/sing-box.json \
    RULESET_DIR=/etc/sing-box

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
    pip3 install --no-cache-dir --break-system-packages cryptography; \
    rm -rf /var/lib/apt/lists/*

COPY --from=singbox-binary /usr/local/bin/sing-box /usr/local/bin/sing-box

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
# This allows first-run initialization of geodata database
COPY config/geoip-geodata.db /opt/default-config/geoip-geodata.db
COPY config/sing-box.json /opt/default-config/sing-box.json

RUN mkdir -p /opt/pia/ca
COPY scripts/entrypoint.sh /usr/local/bin/entrypoint.sh
COPY scripts/fetch-geodata.sh /usr/local/bin/fetch-geodata.sh
COPY scripts/render_singbox.py /usr/local/bin/render_singbox.py
COPY scripts/pia/pia_provision.py /usr/local/bin/pia_provision.py
COPY scripts/setup-wg.sh /usr/local/bin/setup-wg.sh
COPY scripts/api_server.py /usr/local/bin/api_server.py
COPY scripts/db_helper.py /usr/local/bin/db_helper.py
COPY scripts/init_user_db.py /usr/local/bin/init_user_db.py
COPY scripts/get_wg_config.py /usr/local/bin/get_wg_config.py
COPY config/pia/ca/rsa_4096.crt /opt/pia/ca/rsa_4096.crt
RUN chmod +x /usr/local/bin/entrypoint.sh /usr/local/bin/fetch-geodata.sh \
    /usr/local/bin/render_singbox.py /usr/local/bin/pia_provision.py \
    /usr/local/bin/setup-wg.sh /usr/local/bin/api_server.py \
    /usr/local/bin/init_user_db.py /usr/local/bin/get_wg_config.py

# Note: Databases and config are mounted via docker-compose volumes
# - geoip-geodata.db is pre-built and volume-mounted (49 MB, read-only)
# - user-config.db is auto-created on first run by init_user_db.py
# - All config files are accessed via: ./config:/etc/sing-box

WORKDIR /etc/sing-box
VOLUME ["/etc/sing-box"]

EXPOSE 80 8000 36100/udp

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
CMD ["sing-box", "run", "-c", "/etc/sing-box/sing-box.json"]

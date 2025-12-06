# Use official sing-box image
FROM ghcr.io/sagernet/sing-box:latest AS singbox-binary

FROM debian:12-slim

ENV SING_BOX_CONFIG=/etc/sing-box/sing-box.json \
    RULESET_DIR=/etc/sing-box

RUN set -eux; \
    apt-get update; \
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        ca-certificates \
        curl \
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
        wireguard-tools; \
    pip3 install --no-cache-dir --break-system-packages cryptography; \
    rm -rf /var/lib/apt/lists/*

COPY --from=singbox-binary /usr/local/bin/sing-box /usr/local/bin/sing-box
COPY config /etc/sing-box/
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

EXPOSE 36100/udp 8000

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
CMD ["sing-box", "run", "-c", "/etc/sing-box/sing-box.json"]

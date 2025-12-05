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
RUN mkdir -p /opt/pia/ca /etc/sing-box/domain-list
COPY scripts/entrypoint.sh /usr/local/bin/entrypoint.sh
COPY scripts/fetch-geodata.sh /usr/local/bin/fetch-geodata.sh
COPY scripts/render_singbox.py /usr/local/bin/render_singbox.py
COPY scripts/pia/pia_provision.py /usr/local/bin/pia_provision.py
COPY scripts/setup-wg.sh /usr/local/bin/setup-wg.sh
COPY scripts/api_server.py /usr/local/bin/api_server.py
COPY scripts/parse_domain_list.py /usr/local/bin/parse_domain_list.py
COPY config/pia/ca/rsa_4096.crt /opt/pia/ca/rsa_4096.crt
COPY domain-list/data /etc/sing-box/domain-list/data
RUN chmod +x /usr/local/bin/entrypoint.sh /usr/local/bin/fetch-geodata.sh \
    /usr/local/bin/render_singbox.py /usr/local/bin/pia_provision.py \
    /usr/local/bin/setup-wg.sh /usr/local/bin/api_server.py \
    /usr/local/bin/parse_domain_list.py && \
    python3 /usr/local/bin/parse_domain_list.py /etc/sing-box/domain-list/data /etc/sing-box/domain-catalog.json

WORKDIR /etc/sing-box
VOLUME ["/etc/sing-box"]

EXPOSE 36100/udp 8000

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
CMD ["sing-box", "run", "-c", "/etc/sing-box/sing-box.json"]

#!/bin/bash
# Setup WireGuard test clients for DestHash testing
#
# This script:
# 1. Creates WireGuard peers via API
# 2. Generates client configs
# 3. Starts the test client containers
#
# Usage: ./scripts/setup_wg_test_clients.sh [API_HOST]
#   API_HOST: vpn-gateway API host (default: localhost:36000)

set -e

API_HOST="${1:-localhost:36000}"
AUTH_HEADER="Authorization: Basic $(echo -n 'admin:Admin123' | base64)"
CLIENT_DIR="./wg-clients"
NUM_CLIENTS=3

echo "=== DestHash Test Client Setup ==="
echo "API Host: $API_HOST"
echo ""

# Check if vpn-gateway is running
echo "[1/5] Checking vpn-gateway API..."
if ! curl -sf "http://$API_HOST/api/health" > /dev/null 2>&1; then
    echo "ERROR: vpn-gateway API not reachable at http://$API_HOST"
    echo "Please start it first: docker compose -f docker-compose.local.yml up -d --build"
    exit 1
fi
echo "OK: API is reachable"

# Get WireGuard server info
echo ""
echo "[2/5] Getting WireGuard server info..."
WG_INFO=$(curl -sf "http://$API_HOST/api/wg/status" -H "$AUTH_HEADER" 2>/dev/null || echo "{}")
WG_PUBKEY=$(echo "$WG_INFO" | jq -r '.public_key // empty')
WG_ENDPOINT=$(echo "$WG_INFO" | jq -r '.endpoint // empty')
WG_PORT=$(echo "$WG_INFO" | jq -r '.listen_port // 36100')

if [ -z "$WG_PUBKEY" ]; then
    echo "WARNING: Could not get WireGuard server public key"
    echo "You may need to manually configure the clients"
    WG_PUBKEY="<SERVER_PUBLIC_KEY>"
fi

if [ -z "$WG_ENDPOINT" ]; then
    # Try to get host IP
    WG_ENDPOINT=$(hostname -I | awk '{print $1}')
fi

echo "Server Public Key: $WG_PUBKEY"
echo "Server Endpoint: $WG_ENDPOINT:$WG_PORT"

# Create client directories
echo ""
echo "[3/5] Creating client directories..."
mkdir -p "$CLIENT_DIR"

for i in $(seq 1 $NUM_CLIENTS); do
    CLIENT_NAME="client-$i"
    CLIENT_IP="10.10.0.$((i+1))"
    CLIENT_CONFIG_DIR="$CLIENT_DIR/$CLIENT_NAME"
    
    mkdir -p "$CLIENT_CONFIG_DIR"
    
    echo "Creating peer: $CLIENT_NAME ($CLIENT_IP)"
    
    # Generate keys
    PRIVATE_KEY=$(wg genkey 2>/dev/null || openssl rand -base64 32)
    PUBLIC_KEY=$(echo "$PRIVATE_KEY" | wg pubkey 2>/dev/null || echo "<GENERATE_MANUALLY>")
    
    # Try to add peer via API
    PEER_RESPONSE=$(curl -sf -X POST "http://$API_HOST/api/wg/peers" \
        -H "$AUTH_HEADER" \
        -H "Content-Type: application/json" \
        -d "{\"name\": \"$CLIENT_NAME\", \"allowed_ips\": [\"$CLIENT_IP/32\"], \"public_key\": \"$PUBLIC_KEY\"}" \
        2>/dev/null || echo "{}")
    
    # Create wg0.conf
    cat > "$CLIENT_CONFIG_DIR/wg0.conf" << EOF
[Interface]
PrivateKey = $PRIVATE_KEY
Address = $CLIENT_IP/24
DNS = 1.1.1.1

[Peer]
PublicKey = $WG_PUBKEY
Endpoint = $WG_ENDPOINT:$WG_PORT
AllowedIPs = 0.0.0.0/0
PersistentKeepalive = 25
EOF

    echo "  Config: $CLIENT_CONFIG_DIR/wg0.conf"
done

# Start containers
echo ""
echo "[4/5] Starting WireGuard client containers..."
docker compose -f docker-compose.wg-clients.yml up -d

# Wait for containers
echo ""
echo "[5/5] Waiting for containers to start..."
sleep 5

# Show status
echo ""
echo "=== Test Client Status ==="
for i in $(seq 1 $NUM_CLIENTS); do
    CONTAINER="wg-client-$i"
    STATUS=$(docker inspect -f '{{.State.Status}}' "$CONTAINER" 2>/dev/null || echo "not found")
    IP=$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$CONTAINER" 2>/dev/null || echo "N/A")
    echo "$CONTAINER: $STATUS (Docker IP: $IP)"
done

echo ""
echo "=== DestHash Testing Commands ==="
echo ""
echo "# Test session affinity (same client, same domain → same exit):"
echo "for i in 1 2 3; do docker exec wg-client-1 curl -s https://api.ipify.org; echo; done"
echo ""
echo "# Test load balancing (different clients, same domain → may differ):"
echo "docker exec wg-client-1 curl -s https://api.ipify.org"
echo "docker exec wg-client-2 curl -s https://api.ipify.org"
echo "docker exec wg-client-3 curl -s https://api.ipify.org"
echo ""
echo "# Check router logs for ECMP selection:"
echo "docker logs vpn-gateway 2>&1 | grep -i 'ecmp.*desthash'"
echo ""
echo "=== Setup Complete ==="

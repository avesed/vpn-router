#!/bin/bash
# Test PIA WireGuard connection using official scripts

set -e

# Check for credentials
if [ -z "$PIA_USER" ] || [ -z "$PIA_PASS" ]; then
    echo "Usage: PIA_USER=pXXXXXXX PIA_PASS=xxxxx $0 [region]"
    echo "Example: PIA_USER=p1234567 PIA_PASS=mypassword $0 ca_toronto"
    exit 1
fi

REGION=${1:-ca_toronto}
WORKDIR=/tmp/pia-test
mkdir -p $WORKDIR
cd $WORKDIR

# Clone PIA manual-connections if not exists
if [ ! -d "manual-connections" ]; then
    echo "Cloning PIA manual-connections..."
    git clone https://github.com/pia-foss/manual-connections.git
fi

cd manual-connections

echo "=== Step 1: Get Token ==="
# Get token
TOKEN_RESPONSE=$(curl -s -u "$PIA_USER:$PIA_PASS" \
    "https://privateinternetaccess.com/gtoken/generateToken")

if echo "$TOKEN_RESPONSE" | grep -q '"status":"OK"'; then
    TOKEN=$(echo "$TOKEN_RESPONSE" | jq -r '.token')
    echo "Token obtained successfully"
else
    echo "Failed to get token: $TOKEN_RESPONSE"
    exit 1
fi

echo "=== Step 2: Get Server List ==="
# Get server list
SERVERLIST=$(curl -s "https://serverlist.piaservers.net/vpninfo/servers/v6")

# Find the region
SERVER_INFO=$(echo "$SERVERLIST" | jq -r ".regions[] | select(.id==\"$REGION\")")

if [ -z "$SERVER_INFO" ]; then
    echo "Region $REGION not found. Available regions:"
    echo "$SERVERLIST" | jq -r '.regions[].id' | head -20
    exit 1
fi

WG_SERVER_IP=$(echo "$SERVER_INFO" | jq -r '.servers.wg[0].ip')
WG_SERVER_CN=$(echo "$SERVER_INFO" | jq -r '.servers.wg[0].cn')
WG_SERVER_PORT=1337

echo "Server: $WG_SERVER_CN ($WG_SERVER_IP:$WG_SERVER_PORT)"

echo "=== Step 3: Generate WireGuard Keys ==="
# Generate WireGuard keys
PRIVKEY=$(wg genkey)
PUBKEY=$(echo "$PRIVKEY" | wg pubkey)
echo "Public Key: $PUBKEY"

echo "=== Step 4: Register Key with PIA ==="
# Register the public key with PIA
ADDKEY_RESPONSE=$(curl -s -G \
    --connect-to "$WG_SERVER_CN::$WG_SERVER_IP:" \
    --cacert ca.rsa.4096.crt \
    --data-urlencode "pt=$TOKEN" \
    --data-urlencode "pubkey=$PUBKEY" \
    "https://$WG_SERVER_CN:1337/addKey")

echo "AddKey Response: $ADDKEY_RESPONSE"

if ! echo "$ADDKEY_RESPONSE" | grep -q '"status":"OK"'; then
    echo "Failed to register key"
    exit 1
fi

# Extract connection info
PEER_IP=$(echo "$ADDKEY_RESPONSE" | jq -r '.peer_ip')
SERVER_KEY=$(echo "$ADDKEY_RESPONSE" | jq -r '.server_key')
SERVER_PORT=$(echo "$ADDKEY_RESPONSE" | jq -r '.server_port')
SERVER_VIP=$(echo "$ADDKEY_RESPONSE" | jq -r '.server_vip')
DNS_SERVERS=$(echo "$ADDKEY_RESPONSE" | jq -r '.dns_servers | join(", ")')

echo ""
echo "=== PIA WireGuard Configuration ==="
echo "Assigned IP: $PEER_IP"
echo "Server Key: $SERVER_KEY"
echo "Server Port: $SERVER_PORT"
echo "Server VIP: $SERVER_VIP"
echo "DNS: $DNS_SERVERS"

# Create WireGuard config
CONFIG_FILE="$WORKDIR/pia-$REGION.conf"
cat > "$CONFIG_FILE" << EOF
[Interface]
PrivateKey = $PRIVKEY
Address = $PEER_IP/32
DNS = $DNS_SERVERS

[Peer]
PublicKey = $SERVER_KEY
Endpoint = $WG_SERVER_IP:$SERVER_PORT
AllowedIPs = 0.0.0.0/0
PersistentKeepalive = 25
EOF

echo ""
echo "=== Config saved to $CONFIG_FILE ==="
cat "$CONFIG_FILE"

echo ""
echo "=== Step 5: Test Connection ==="
# Try to bring up the interface
if command -v wg-quick &> /dev/null; then
    echo "Testing connection with wg-quick..."
    wg-quick up "$CONFIG_FILE" || true
    
    sleep 2
    
    # Check status
    wg show
    
    # Test connectivity
    echo ""
    echo "Testing connectivity..."
    curl -s --max-time 5 ifconfig.me && echo " (via VPN)" || echo "Connection failed"
    
    # Clean up
    wg-quick down "$CONFIG_FILE" || true
else
    echo "wg-quick not available. Config file created at $CONFIG_FILE"
    echo "You can test manually with: wg-quick up $CONFIG_FILE"
fi

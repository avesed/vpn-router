#!/bin/bash
# Simple PIA WireGuard connection test

set -e

if [ -z "$PIA_USER" ] || [ -z "$PIA_PASS" ]; then
    echo "Usage: PIA_USER=pXXXXXXX PIA_PASS=xxxxx $0 [region]"
    exit 1
fi

REGION=${1:-ca_toronto}

echo "=== Step 1: Get Token ==="
TOKEN_RESPONSE=$(curl -s -u "$PIA_USER:$PIA_PASS" \
    "https://privateinternetaccess.com/gtoken/generateToken")

if ! echo "$TOKEN_RESPONSE" | grep -q '"status":"OK"'; then
    echo "Failed to get token: $TOKEN_RESPONSE"
    exit 1
fi

TOKEN=$(echo "$TOKEN_RESPONSE" | jq -r '.token')
echo "Token obtained"

echo "=== Step 2: Get Server ==="
SERVERLIST=$(curl -s "https://serverlist.piaservers.net/vpninfo/servers/v6")
SERVER_INFO=$(echo "$SERVERLIST" | jq -r ".regions[] | select(.id==\"$REGION\")")

if [ -z "$SERVER_INFO" ]; then
    echo "Region $REGION not found"
    exit 1
fi

WG_SERVER_IP=$(echo "$SERVER_INFO" | jq -r '.servers.wg[0].ip')
WG_SERVER_CN=$(echo "$SERVER_INFO" | jq -r '.servers.wg[0].cn')
echo "Server: $WG_SERVER_CN ($WG_SERVER_IP)"

echo "=== Step 3: Generate Keys ==="
PRIVKEY=$(wg genkey)
PUBKEY=$(echo "$PRIVKEY" | wg pubkey)
echo "Public Key: $PUBKEY"

echo "=== Step 4: Register Key ==="
# Download CA cert
curl -s -o /tmp/pia-ca.crt https://raw.githubusercontent.com/pia-foss/manual-connections/master/ca.rsa.4096.crt

ADDKEY_RESPONSE=$(curl -s -G \
    --connect-to "$WG_SERVER_CN::$WG_SERVER_IP:" \
    --cacert /tmp/pia-ca.crt \
    --data-urlencode "pt=$TOKEN" \
    --data-urlencode "pubkey=$PUBKEY" \
    "https://$WG_SERVER_CN:1337/addKey")

echo "Response: $ADDKEY_RESPONSE"

if ! echo "$ADDKEY_RESPONSE" | grep -q '"status":"OK"'; then
    echo "Failed to register key"
    exit 1
fi

PEER_IP=$(echo "$ADDKEY_RESPONSE" | jq -r '.peer_ip')
SERVER_KEY=$(echo "$ADDKEY_RESPONSE" | jq -r '.server_key')
SERVER_PORT=$(echo "$ADDKEY_RESPONSE" | jq -r '.server_port')

echo ""
echo "=== WireGuard Config ==="
cat << EOF
[Interface]
PrivateKey = $PRIVKEY
Address = $PEER_IP/32

[Peer]
PublicKey = $SERVER_KEY
Endpoint = $WG_SERVER_IP:$SERVER_PORT
AllowedIPs = 0.0.0.0/0
PersistentKeepalive = 25
EOF

# Save config
cat > /tmp/pia-test.conf << EOF
[Interface]
PrivateKey = $PRIVKEY
Address = $PEER_IP/32

[Peer]
PublicKey = $SERVER_KEY
Endpoint = $WG_SERVER_IP:$SERVER_PORT
AllowedIPs = 0.0.0.0/0
PersistentKeepalive = 25
EOF

echo ""
echo "Config saved to /tmp/pia-test.conf"
echo ""
echo "=== Step 5: Test with wg-quick ==="

# Check if we can use wg-quick
if [ -f /proc/net/if_inet6 ] || [ -d /sys/class/net ]; then
    wg-quick up /tmp/pia-test.conf 2>&1 || echo "wg-quick failed (may need kernel module)"
    
    sleep 2
    wg show 2>/dev/null || true
    
    echo ""
    echo "Testing connectivity..."
    curl -s --max-time 5 ifconfig.me && echo " (VPN IP)" || echo "Connection test failed"
    
    wg-quick down /tmp/pia-test.conf 2>/dev/null || true
else
    echo "Cannot test - no network interfaces available"
fi

#!/bin/bash
# TCP Diagnostic Script - Run this while testing to see where the stall happens
# Usage: ./diagnose_tcp.sh [container_name]

CONTAINER=${1:-vpn-client}

echo "=== TCP Diagnostic Tool ==="
echo "Container: $CONTAINER"
echo "Press Ctrl+C to stop"
echo ""

# Function to get TCP stats via IPC
get_stats() {
    docker exec $CONTAINER sh -c 'echo "{\"type\":\"GetTcpStats\"}" | nc -U /run/rust-router.sock 2>/dev/null' | python3 -c "
import sys, json
try:
    data = json.load(sys.stdin)
    if 'tcp_write_halves' in data:
        print(f\"  TCP write_halves: {data.get('tcp_write_halves', 'N/A')}\")
        print(f\"  TCP pending_streams: {data.get('tcp_pending_streams', 'N/A')}\")
        print(f\"  TCP active_readers: {data.get('tcp_active_readers', 'N/A')}\")
        print(f\"  UDP sessions: {data.get('udp_sessions', 'N/A')}\")
        print(f\"  Ingress sessions: {data.get('ingress_sessions', 'N/A')}\")
    else:
        print(f\"  Response: {data}\")
except Exception as e:
    print(f\"  Error parsing: {e}\")
" 2>/dev/null || echo "  Failed to get stats"
}

# Function to get reply stats
get_reply_stats() {
    docker exec $CONTAINER sh -c 'echo "{\"type\":\"Status\"}" | nc -U /run/rust-router.sock 2>/dev/null' | python3 -c "
import sys, json
try:
    data = json.load(sys.stdin)
    if 'ingress_reply_stats' in data:
        rs = data['ingress_reply_stats']
        print(f\"  packets_received: {rs.get('packets_received', 0)}\")
        print(f\"  packets_forwarded: {rs.get('packets_forwarded', 0)}\")
        print(f\"  session_misses: {rs.get('session_misses', 0)}\")
        print(f\"  send_errors: {rs.get('send_errors', 0)}\")
        print(f\"  queue_full: {rs.get('queue_full', 0)}\")
except Exception as e:
    print(f\"  Error: {e}\")
" 2>/dev/null || echo "  Failed to get reply stats"
}

# Main loop
while true; do
    echo "----------------------------------------"
    echo "$(date '+%H:%M:%S') - TCP Stats:"
    get_stats
    echo ""
    echo "Reply Router Stats:"
    get_reply_stats
    echo ""

    # Check for recent log messages
    echo "Recent logs (last 3 lines with 'reader' or 'Reply router'):"
    docker logs --tail 100 $CONTAINER 2>&1 | grep -E "(TCP reader|Reply router stats)" | tail -3

    sleep 2
done

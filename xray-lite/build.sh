#!/bin/bash
# Development build script for xray-lite
# Usage: ./build.sh
#
# Requires Go 1.25+ or Docker

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

echo "Building xray-lite (development build)..."

# Check if Go is available locally
if command -v go &> /dev/null; then
    # Portable version extraction (works on Linux, macOS, BSD)
    GO_VERSION=$(go version | awk '{print $3}')
    echo "Using local Go: $GO_VERSION"
    go build -o xray ./main
else
    echo "Go not found, using Docker..."
    docker run --rm -v "$(pwd)":/build -w /build golang:1.25-alpine go build -o xray ./main
fi

echo ""
echo "Build complete: ./xray"
ls -lh xray

#!/bin/bash
# Release build script for xray-lite
# Usage: ./build-release.sh [output-name] [--upx|--upx-fast|--upx-best]
#
# Builds with:
#   - CGO disabled for static binary
#   - Symbol stripping (-s -w)
#   - Trimmed build paths
#   - Empty build ID for reproducibility
#   - Pure Go networking (netgo)
#   - Version information embedded
#
# UPX options:
#   --upx      : Apply UPX compression with -9 (good balance)
#   --upx-fast : Apply UPX compression with -1 (fastest)
#   --upx-best : Apply UPX compression with --best --lzma (smallest)
#
# Requires Go 1.25+ or Docker. UPX optional but recommended.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# Parse arguments
OUTPUT="${1:-xray}"
UPX_MODE=""
shift || true

for arg in "$@"; do
    case "$arg" in
        --upx)      UPX_MODE="standard" ;;
        --upx-fast) UPX_MODE="fast" ;;
        --upx-best) UPX_MODE="best" ;;
        *)          echo "Unknown option: $arg"; exit 1 ;;
    esac
done

VERSION="${XRAY_VERSION:-custom}"
BUILD_DATE="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

# Optimized ldflags for minimum binary size
# -s: strip symbol table
# -w: strip DWARF debug info
# -buildid=: empty build ID
LDFLAGS="-s -w -buildid= -X github.com/xtls/xray-core/core.build=${BUILD_DATE}"

# Build tags for pure Go networking (avoids cgo DNS resolver)
BUILD_TAGS="netgo"

echo "Building xray-lite (release build)..."
echo "  Version: $VERSION"
echo "  Build date: $BUILD_DATE"
echo "  Build tags: $BUILD_TAGS"

# Check if Go is available locally
if command -v go &> /dev/null; then
    # Portable version extraction (works on Linux, macOS, BSD)
    GO_VERSION=$(go version | awk '{print $3}')
    echo "Using local Go: $GO_VERSION"
    CGO_ENABLED=0 go build \
        -tags="$BUILD_TAGS" \
        -ldflags="$LDFLAGS" \
        -trimpath \
        -o "$OUTPUT" \
        ./main
else
    echo "Go not found, using Docker..."
    docker run --rm -v "$(pwd)":/build -w /build golang:1.25-alpine \
        sh -c "CGO_ENABLED=0 go build -tags='$BUILD_TAGS' -ldflags='$LDFLAGS' -trimpath -o ${OUTPUT} ./main"
fi

echo ""
echo "Build complete: ./$OUTPUT"
ORIG_SIZE=$(ls -lh "$OUTPUT" | awk '{print $5}')
ls -lh "$OUTPUT"

# Show binary info
echo ""
echo "Binary info:"
file "$OUTPUT"

# Apply UPX compression if requested
if [ -n "$UPX_MODE" ]; then
    echo ""
    if ! command -v upx &> /dev/null; then
        echo "ERROR: UPX not found. Install with: apt-get install upx"
        exit 1
    fi

    case "$UPX_MODE" in
        fast)
            echo "Applying UPX compression (fast mode: -1)..."
            upx -1 "$OUTPUT"
            ;;
        standard)
            echo "Applying UPX compression (standard mode: -9)..."
            upx -9 "$OUTPUT"
            ;;
        best)
            echo "Applying UPX compression (best mode: --best --lzma)..."
            upx --best --lzma "$OUTPUT"
            ;;
    esac

    UPX_SIZE=$(ls -lh "$OUTPUT" | awk '{print $5}')
    echo ""
    echo "Compression results:"
    echo "  Original: $ORIG_SIZE"
    echo "  Compressed: $UPX_SIZE"
fi

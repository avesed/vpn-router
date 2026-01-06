# Dockerfile for building xray-lite
# Multi-stage build for minimal final image

# Build stage
FROM golang:1.25-alpine AS builder

# Install build dependencies
RUN apk add --no-cache git

WORKDIR /build

# Copy go.mod and go.sum first for layer caching
COPY go.mod go.sum ./
RUN go mod download

# Copy source code
COPY . .

# Build release binary
ARG VERSION=custom
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build \
    -ldflags="-s -w -X github.com/xtls/xray-core/core.build=$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
    -trimpath \
    -o /xray \
    ./main

# Runtime stage
FROM scratch

COPY --from=builder /xray /xray

ENTRYPOINT ["/xray"]

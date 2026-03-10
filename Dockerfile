# =============================================================================
# SimpleAuth — Multi-stage Production Dockerfile
# =============================================================================
# Build:  docker build -t simpleauth .
# Run:    docker run -p 8080:8080 -v simpleauth-data:/data simpleauth
# =============================================================================

# ---------------------------------------------------------------------------
# Stage 1: Build the Go binary
# ---------------------------------------------------------------------------
FROM golang:1.24-alpine AS builder

WORKDIR /src

# Cache module downloads before copying full source
COPY go.mod go.sum ./
RUN go mod download

# Copy source and embedded UI assets
COPY . .

# Build args for version injection
ARG VERSION=docker
ARG BUILD_TIME=""

RUN if [ -z "$BUILD_TIME" ]; then BUILD_TIME=$(date -u '+%Y-%m-%dT%H:%M:%SZ'); fi && \
    CGO_ENABLED=0 go build \
      -trimpath \
      -ldflags "-s -w -X main.Version=${VERSION} -X main.BuildTime=${BUILD_TIME}" \
      -o /simpleauth \
      .

# ---------------------------------------------------------------------------
# Stage 2: Minimal runtime image
# ---------------------------------------------------------------------------
FROM alpine:3.19

# OCI image labels
LABEL org.opencontainers.image.title="SimpleAuth" \
      org.opencontainers.image.description="Lightweight authentication server with LDAP, Kerberos/SPNEGO, and JWT support" \
      org.opencontainers.image.vendor="SimpleAuth" \
      org.opencontainers.image.source="https://github.com/bodaay/SimpleAuth" \
      org.opencontainers.image.licenses="MIT"

# Runtime dependencies:
#   ca-certificates  — TLS verification for outbound LDAP/HTTPS calls
#   krb5-libs        — Kerberos client libraries for SPNEGO authentication
#   tzdata           — timezone data for correct log timestamps
RUN apk add --no-cache \
      ca-certificates \
      krb5-libs \
      tzdata

# Create a non-root user for the service
RUN addgroup -S simpleauth && \
    adduser -S -G simpleauth -h /home/simpleauth -s /sbin/nologin simpleauth

# Persistent data directory (BoltDB, TLS certs, keytabs)
RUN mkdir -p /data && chown simpleauth:simpleauth /data
VOLUME /data

# Copy the compiled binary from builder
COPY --from=builder /simpleauth /usr/local/bin/simpleauth

# Default environment — override at runtime as needed
ENV AUTH_DATA_DIR=/data \
    AUTH_PORT=8080 \
    AUTH_HTTP_PORT="" \
    AUTH_HOSTNAME=""

# Expose the HTTPS port (the app handles its own TLS)
EXPOSE 8080

# Health check: use /health endpoint (works with both HTTP and HTTPS modes)
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD wget --no-check-certificate --spider -q https://localhost:8080/health 2>/dev/null || \
      wget --spider -q http://localhost:8080/health || exit 1

# Run as non-root
USER simpleauth

ENTRYPOINT ["simpleauth"]

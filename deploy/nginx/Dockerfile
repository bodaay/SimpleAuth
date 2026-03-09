# =============================================================================
# SimpleAuth — Nginx Reverse Proxy
# =============================================================================
# Provides TLS termination and rate limiting in front of SimpleAuth.
#
# Build:  docker build -t simpleauth-nginx deploy/nginx/
# =============================================================================

FROM nginx:1.25-alpine

# Remove default config
RUN rm /etc/nginx/conf.d/default.conf

# Copy production config
COPY nginx.conf /etc/nginx/nginx.conf

# Create directories for SSL certs and ACME challenges
RUN mkdir -p /etc/nginx/ssl /var/www/certbot

EXPOSE 80 443

HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
  CMD wget --no-check-certificate --spider -q https://localhost:443/health || exit 1

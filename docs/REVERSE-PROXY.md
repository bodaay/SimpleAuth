# Reverse Proxy Deployment Guide

This guide covers deploying SimpleAuth behind nginx or other reverse proxies.

---

## Architecture

```
Client → nginx (TLS termination, :443) → SimpleAuth (HTTP, :8080)
```

nginx handles TLS with your real certificate. SimpleAuth runs in HTTP-only mode inside the private network. No self-signed certificates, no double encryption.

---

## SimpleAuth Configuration

Set these two options when running behind a reverse proxy:

```bash
# Disable TLS — serve plain HTTP
AUTH_TLS_DISABLED=true

# Only trust forwarded headers from your proxy's network
AUTH_TRUSTED_PROXIES="172.16.0.0/12,10.0.0.0/8,192.168.0.0/16"
```

Or in `simpleauth.yaml`:

```yaml
tls_disabled: true
trusted_proxies:
  - "172.16.0.0/12"
  - "10.0.0.0/8"
  - "192.168.0.0/16"
```

### Why `trusted_proxies` is important

Without `trusted_proxies`, SimpleAuth trusts `X-Forwarded-For` and `X-Real-IP` headers from **any** client. An attacker can spoof these headers to:

- Bypass IP-based rate limiting
- Pollute audit logs with fake IPs
- Evade IP-based blocking

Set `trusted_proxies` to your reverse proxy's network range. SimpleAuth will only read forwarded headers when the direct connection comes from a trusted IP. For all other connections, it uses the TCP source address.

---

## Docker Compose Deployment

### Quick start

```bash
# 1. Place your TLS certificate and key
mkdir -p deploy/nginx/certs
cp /path/to/fullchain.pem deploy/nginx/certs/
cp /path/to/privkey.pem deploy/nginx/certs/

# 2. Set your admin key and hostname
export AUTH_ADMIN_KEY="$(openssl rand -hex 16)"
export AUTH_HOSTNAME="auth.corp.local"

# 3. Start the full stack
docker compose --profile full up -d
```

This starts:
- **SimpleAuth** on port 8080 (HTTP, internal only)
- **nginx** on ports 80 (redirect) and 443 (HTTPS)

### docker-compose.yml overview

The included `docker-compose.yml` is pre-configured for reverse proxy mode:
- `AUTH_TLS_DISABLED=true` — no self-signed cert generation
- `AUTH_TRUSTED_PROXIES` — trusts Docker internal networks
- `AUTH_HTTP_PORT=""` — disables SimpleAuth's own HTTP→HTTPS redirect (nginx handles it)

---

## Nginx Configuration

The included [deploy/nginx/nginx.conf](../deploy/nginx/nginx.conf) provides a production-ready configuration with:

### TLS
- TLS 1.2 and 1.3 only (no legacy protocols)
- Modern cipher suite with forward secrecy
- Session caching and ticket rotation
- HSTS header (2 years, includeSubDomains, preload)
- ACME challenge passthrough for Let's Encrypt

### Real IP Forwarding
```nginx
proxy_set_header X-Real-IP         $remote_addr;
proxy_set_header X-Forwarded-For   $proxy_add_x_forwarded_for;
proxy_set_header X-Forwarded-Proto $scheme;
```

These headers are critical for:
- **Audit logs** — SimpleAuth logs the real client IP from these headers
- **Rate limiting** — IP-based rate limiting uses the real client IP
- **Login events** — the `ip` field in login audit entries shows the actual user IP

### Kerberos / SPNEGO Support
```nginx
# Large buffers for Negotiate tokens (can be 8-64KB+)
proxy_buffer_size          128k;
proxy_buffers              4 256k;
proxy_busy_buffers_size    256k;
large_client_header_buffers 4 64k;
client_header_buffer_size 64k;

# Pass Authorization and WWW-Authenticate headers through
proxy_pass_header Authorization;
proxy_pass_header WWW-Authenticate;
```

### Rate Limiting (Defense in Depth)
```nginx
# General: 10 req/s per IP
limit_req_zone $binary_remote_addr zone=auth_limit:10m rate=10r/s;

# Login endpoints: 3 req/s per IP
limit_req_zone $binary_remote_addr zone=login_limit:10m rate=3r/s;
```

nginx rate limiting works alongside SimpleAuth's built-in rate limiter for defense in depth.

### Security Headers
- `X-Frame-Options: SAMEORIGIN`
- `X-Content-Type-Options: nosniff`
- `Content-Security-Policy`
- `Referrer-Policy: strict-origin-when-cross-origin`

---

## Let's Encrypt with Certbot

### Initial certificate

```bash
# Stop nginx first (or use webroot mode)
docker compose --profile full down

# Get certificate
certbot certonly --standalone \
  -d auth.corp.local \
  --cert-path deploy/nginx/certs/fullchain.pem \
  --key-path deploy/nginx/certs/privkey.pem

# Start everything
docker compose --profile full up -d
```

### Auto-renewal with webroot

The nginx config includes an ACME challenge location:

```nginx
location /.well-known/acme-challenge/ {
    root /var/www/certbot;
}
```

Set up renewal:

```bash
# Add to crontab
0 3 * * * certbot renew --webroot -w /var/www/certbot --post-hook "docker compose restart nginx"
```

---

## Other Reverse Proxies

### Traefik

```yaml
# docker-compose.yml (Traefik labels)
services:
  simpleauth:
    environment:
      AUTH_TLS_DISABLED: "true"
      AUTH_TRUSTED_PROXIES: "172.16.0.0/12"
    labels:
      - "traefik.enable=true"
      - "traefik.http.routers.simpleauth.rule=Host(`auth.corp.local`)"
      - "traefik.http.routers.simpleauth.tls=true"
      - "traefik.http.routers.simpleauth.tls.certresolver=letsencrypt"
      - "traefik.http.services.simpleauth.loadbalancer.server.port=8080"
```

### Caddy

```
auth.corp.local {
    reverse_proxy simpleauth:8080 {
        header_up X-Real-IP {remote_host}
        header_up X-Forwarded-For {remote_host}
        header_up X-Forwarded-Proto {scheme}
    }
}
```

### HAProxy

```
frontend https
    bind *:443 ssl crt /etc/haproxy/certs/auth.pem
    default_backend simpleauth

backend simpleauth
    option forwardfor
    http-request set-header X-Real-IP %[src]
    http-request set-header X-Forwarded-Proto https
    server auth1 simpleauth:8080 check
```

---

## Standalone (No Reverse Proxy)

If you're **not** using a reverse proxy, SimpleAuth handles everything:

```bash
# Default mode — auto-generates self-signed certificate
AUTH_HOSTNAME=auth.corp.local ./simpleauth

# With your own certificate
AUTH_HOSTNAME=auth.corp.local \
AUTH_TLS_CERT=/etc/letsencrypt/live/auth.corp.local/fullchain.pem \
AUTH_TLS_KEY=/etc/letsencrypt/live/auth.corp.local/privkey.pem \
./simpleauth
```

In standalone mode:
- SimpleAuth serves HTTPS directly
- HTTP→HTTPS redirect is enabled on port 80 by default
- A self-signed certificate is auto-generated if none is provided

---

## Troubleshooting

### Audit logs show proxy IP instead of client IP

**Cause:** `trusted_proxies` is not configured, and the proxy is not in the trusted list.

**Fix:** Set `AUTH_TRUSTED_PROXIES` to your proxy's IP or network range:
```bash
AUTH_TRUSTED_PROXIES="172.16.0.0/12"
```

### Audit logs show wrong client IP (spoofed)

**Cause:** `trusted_proxies` is not set, so SimpleAuth trusts `X-Forwarded-For` from anyone.

**Fix:** Set `AUTH_TRUSTED_PROXIES` to restrict which IPs can set forwarded headers.

### Rate limiting not working behind proxy

**Cause:** All requests appear to come from the proxy's IP.

**Fix:** Ensure your proxy sets `X-Real-IP` or `X-Forwarded-For`, and SimpleAuth has `AUTH_TRUSTED_PROXIES` configured.

### "Connection refused" from nginx to SimpleAuth

**Cause:** SimpleAuth might still be running HTTPS while nginx expects HTTP.

**Fix:** Set `AUTH_TLS_DISABLED=true` on SimpleAuth when nginx proxies to `http://simpleauth:8080`.

### Kerberos 502 errors through nginx

**Cause:** SPNEGO Negotiate tokens can be very large (8-64KB+) and exceed default nginx buffer sizes.

**Fix:** Use the buffer settings from the included nginx config:
```nginx
proxy_buffer_size          128k;
proxy_buffers              4 256k;
large_client_header_buffers 4 64k;
```

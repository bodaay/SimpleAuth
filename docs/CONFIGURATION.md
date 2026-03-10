# SimpleAuth Configuration

SimpleAuth uses a layered configuration system: **defaults < config file < environment variables**. Environment variables always win.

---

## Quick Start

Generate a default config file:

```bash
simpleauth init-config
# creates simpleauth.yaml in the current directory

simpleauth init-config /etc/simpleauth/config.yaml
# or specify a custom path
```

---

## Config File Locations

SimpleAuth looks for a config file in this order:

1. Path specified by `AUTH_CONFIG_FILE` environment variable
2. `./simpleauth.yaml`
3. `./simpleauth.yml`
4. `/etc/simpleauth/config.yaml`
5. `/etc/simpleauth/config.yml`

---

## All Configuration Options

| Config Key | Env Variable | Default | Description |
|---|---|---|---|
| `hostname` | `AUTH_HOSTNAME` | OS hostname | FQDN clients use to access SimpleAuth. Used in TLS certificate SANs and Kerberos SPN. |
| `port` | `AUTH_PORT` | `9090` | HTTPS listening port. |
| `http_port` | `AUTH_HTTP_PORT` | `80` | HTTP port for automatic redirect to HTTPS. Set to `""` to disable. |
| `data_dir` | `AUTH_DATA_DIR` | `./data` | Directory for the BoltDB database, TLS certificates, and keytabs. |
| `admin_key` | `AUTH_ADMIN_KEY` | (auto-generated) | Master admin API key. If not set, a random key is generated on each startup and printed to logs. Set this to make it permanent. |
| `client_id` | `AUTH_CLIENT_ID` | (none) | OIDC client ID for this instance. Used in authorization code flow, token endpoint, and introspection. |
| `client_secret` | `AUTH_CLIENT_SECRET` | (none) | OIDC client secret for this instance. |
| `redirect_uris` | `AUTH_REDIRECT_URIS` | (none) | Comma-separated list of allowed OIDC redirect URIs. |
| `deployment_name` | `AUTH_DEPLOYMENT_NAME` | `sauth` | Deployment name (max 6 chars, letters only a-z/A-Z), used in AD service account naming (`svc-sauth-{deployment_name}`). Useful when running multiple SimpleAuth instances against the same AD. |
| `jwt_issuer` | `AUTH_JWT_ISSUER` | `simpleauth` | JWT issuer claim and OIDC realm name. The OIDC issuer URL becomes `https://{hostname}/realms/{jwt_issuer}`. |
| `access_ttl` | `AUTH_JWT_ACCESS_TTL` | `8h` | Access token lifetime. Go duration format (e.g., `30m`, `8h`, `24h`). |
| `refresh_ttl` | `AUTH_JWT_REFRESH_TTL` | `720h` | Refresh token lifetime (default 30 days). |
| `impersonate_ttl` | `AUTH_IMPERSONATE_TTL` | `1h` | Token lifetime for impersonation tokens. |
| `tls_cert` | `AUTH_TLS_CERT` | (auto-generated) | Path to TLS certificate file. If not set, SimpleAuth generates a self-signed cert in `data_dir`. |
| `tls_key` | `AUTH_TLS_KEY` | (auto-generated) | Path to TLS private key file. |
| `krb5_keytab` | `AUTH_KRB5_KEYTAB` | (none) | Path to Kerberos keytab file for SPNEGO authentication. Usually auto-configured via the admin UI. |
| `krb5_realm` | `AUTH_KRB5_REALM` | (none) | Kerberos realm (e.g., `CORP.LOCAL`). |
| `audit_retention` | `AUTH_AUDIT_RETENTION` | `2160h` | How long to keep audit log entries (default 90 days). Pruned daily. |
| `rate_limit_max` | `AUTH_RATE_LIMIT_MAX` | `10` | Maximum login attempts per IP within the rate limit window. |
| `rate_limit_window` | `AUTH_RATE_LIMIT_WINDOW` | `1m` | Rate limit sliding window duration. |
| `cors_origins` | `AUTH_CORS_ORIGINS` | (none) | Allowed CORS origins. Comma-separated list or `*` for all. Example: `https://app1.example.com,https://app2.example.com` |
| `default_roles` | `AUTH_DEFAULT_ROLES` | (none) | Default roles assigned to new users on first login. Comma-separated in env var, YAML list in config file. Example: `user,viewer` |

---

## Example Config File (YAML)

```yaml
# SimpleAuth Configuration
# Priority: this file < environment variables (env vars override file values)

# The FQDN clients use to access SimpleAuth
hostname: "auth.corp.local"

# Server ports
port: "9090"
http_port: "80"

# Data directory for database, keytabs, and certificates
data_dir: "/var/lib/simpleauth"

# Master admin API key (generate one: openssl rand -hex 16)
admin_key: "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6"

# OIDC client settings for this instance
client_id: "my-web-app"
client_secret: "my-client-secret"
redirect_uris: "https://myapp.example.com/callback,https://myapp.example.com/silent-renew"

# Deployment name for multi-instance deployments (max 6 chars, letters only)
deployment_name: "prod"

# JWT settings
jwt_issuer: "simpleauth"
access_ttl: "8h"
refresh_ttl: "720h"
impersonate_ttl: "1h"

# TLS (omit for auto-generated self-signed cert)
# tls_cert: "/etc/simpleauth/tls.crt"
# tls_key: "/etc/simpleauth/tls.key"

# Kerberos (usually auto-configured via admin API)
# krb5_keytab: "/etc/simpleauth/krb5.keytab"
# krb5_realm: "CORP.LOCAL"

# Audit log
audit_retention: "2160h"    # 90 days

# Rate limiting
rate_limit_max: 10
rate_limit_window: "1m"

# CORS
cors_origins: "https://app.corp.local,https://admin.corp.local"
```

---

## Docker Configuration

In Docker, use environment variables:

```bash
docker run -d \
  --name simpleauth \
  -p 8080:8080 \
  -v simpleauth-data:/data \
  -e AUTH_ADMIN_KEY="your-secret-admin-key" \
  -e AUTH_HOSTNAME="auth.corp.local" \
  -e AUTH_JWT_ISSUER="simpleauth" \
  -e AUTH_CLIENT_ID="my-web-app" \
  -e AUTH_CLIENT_SECRET="my-client-secret" \
  -e AUTH_REDIRECT_URIS="https://myapp.example.com/callback" \
  -e AUTH_CORS_ORIGINS="https://app.corp.local" \
  simpleauth
```

### Docker defaults (different from binary defaults)

The Docker image overrides some defaults for container environments:

| Setting | Docker Default | Binary Default |
|---|---|---|
| `AUTH_PORT` | `8080` | `9090` |
| `AUTH_DATA_DIR` | `/data` | `./data` |
| `AUTH_HTTP_PORT` | `""` (disabled) | `80` |

### Docker Compose example

```yaml
version: '3.8'

services:
  simpleauth:
    image: simpleauth
    ports:
      - "8080:8080"
    volumes:
      - simpleauth-data:/data
    environment:
      AUTH_ADMIN_KEY: "your-secret-admin-key"
      AUTH_HOSTNAME: "auth.corp.local"
      AUTH_JWT_ISSUER: "simpleauth"
      AUTH_JWT_ACCESS_TTL: "4h"
      AUTH_CLIENT_ID: "my-web-app"
      AUTH_CLIENT_SECRET: "my-client-secret"
      AUTH_REDIRECT_URIS: "https://myapp.example.com/callback"
      AUTH_CORS_ORIGINS: "*"
    restart: unless-stopped

volumes:
  simpleauth-data:
```

### Mounting a config file in Docker

```bash
docker run -d \
  -v /path/to/simpleauth.yaml:/etc/simpleauth/config.yaml:ro \
  -v simpleauth-data:/data \
  -p 8080:8080 \
  simpleauth
```

---

## Option Details

### `hostname`

The hostname is used for:
- TLS certificate Subject Alternative Names (SANs)
- Kerberos SPN (`HTTP/hostname@REALM`)
- OIDC issuer URL construction
- Log output (access URLs)

If not set, SimpleAuth uses the OS hostname. When changing the hostname, SimpleAuth will automatically regenerate the self-signed TLS certificate.

### `admin_key`

This is the master key for bootstrapping admin access. Treat it like a root password.

If you don't set it, SimpleAuth generates a random key on each startup and prints it to the logs. This is fine for development but not for production -- set it explicitly so it persists across restarts.

After bootstrap, you can assign the `SimpleAuthAdmin` role to users. Users with this role get full admin access without needing the master admin key.

Generate a good key:

```bash
openssl rand -hex 16
```

### `client_id` / `client_secret` / `redirect_uris`

These configure the OIDC client for this SimpleAuth instance. One instance serves one application.

- `client_id` is the identifier your app uses in OIDC flows (authorization code, token requests, introspection)
- `client_secret` is the shared secret used to authenticate your app to SimpleAuth
- `redirect_uris` is a comma-separated list of allowed redirect URIs for the authorization code flow

### `jwt_issuer`

This value serves double duty:
1. It becomes the `iss` claim in all JWTs (as part of the OIDC issuer URL)
2. It becomes the OIDC realm name in Keycloak-compatible URLs

The full OIDC issuer URL is: `https://{hostname}:{port}/realms/{jwt_issuer}`

### `access_ttl` / `refresh_ttl`

These control how long tokens last. Uses Go duration format:
- `30m` = 30 minutes
- `8h` = 8 hours
- `720h` = 30 days
- `2160h` = 90 days

Shorter access TTLs are more secure (less time for a stolen token to be used) but require more frequent refreshes.

### `cors_origins`

Set this when your frontend app runs on a different origin than SimpleAuth:
- Single origin: `https://app.example.com`
- Multiple origins: `https://app1.example.com,https://app2.example.com`
- Allow all: `*`

When set, SimpleAuth responds to preflight `OPTIONS` requests and adds `Access-Control-Allow-Origin`, `Access-Control-Allow-Methods`, and `Access-Control-Allow-Headers` headers.

### `deployment_name`

Only matters when you're running multiple SimpleAuth instances against the same Active Directory. It's used to namespace Kerberos SPNs and service accounts (e.g., `svc-sauth`), so they don't collide. Max 6 characters, letters only (a-z/A-Z).

### `rate_limit_max` / `rate_limit_window`

Controls brute-force protection on the login endpoint. The default of 10 attempts per minute per IP address is appropriate for most environments. Adjust if you have shared NAT IPs.

---

## Auto-Generated Resources

On first startup, SimpleAuth auto-generates several things if they don't already exist:

1. **Data directory** -- Created at `data_dir` with mode `0700`
2. **BoltDB database** -- `{data_dir}/auth.db`
3. **TLS certificate** -- `{data_dir}/tls.crt` and `{data_dir}/tls.key` (self-signed, 10-year validity, includes all local IPs in SANs)
4. **RSA signing keys** -- Stored in the database, used for JWT signing (RS256)
5. **Admin key** -- Printed to logs if not configured

---

## CLI Commands

```bash
# Print version
simpleauth version

# Generate default config file
simpleauth init-config [path]

# Start the server (default behavior)
simpleauth
```

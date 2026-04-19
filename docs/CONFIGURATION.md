# SimpleAuth Configuration

SimpleAuth uses a layered configuration system: **defaults < config file < environment variables**. Environment variables always win.

> **Ports:** Binary defaults to port `9090`. Docker defaults to port `8080`. Set `AUTH_PORT` to change.

---

## Required for Production

These MUST be set before deploying:

| Variable | Why |
|----------|-----|
| `AUTH_HOSTNAME` | Your public domain. Used in TLS cert, JWT issuer, OIDC discovery, redirect URLs. |
| `AUTH_ADMIN_KEY` | Secret for admin API and admin UI. If not set, a random one is generated each startup — making automation impossible. |
| `AUTH_REDIRECT_URIS` | Allowed callback URLs. **If empty, ALL login redirects are rejected.** |
| `AUTH_TRUSTED_PROXIES` | **Required if behind nginx/traefik/load balancer.** Without this, rate limiting sees all requests from the proxy IP and locks everyone out. Set to your proxy's CIDR (e.g. `172.16.0.0/12`). |

---

## Where to Set Parameters

SimpleAuth has two tiers of configuration:

### Tier 1: Startup Config (env vars / config file ONLY)

These settings affect SimpleAuth's ability to START and serve the admin UI. They CANNOT be changed from the admin UI — they must be set via environment variables or the config file BEFORE SimpleAuth starts.

| Parameter | Why it's startup-only |
|-----------|----------------------|
| `AUTH_HOSTNAME` | Determines TLS certificate, JWT issuer URL |
| `AUTH_PORT` | Binds the network listener at startup |
| `AUTH_BASE_PATH` | Registers all HTTP routes at startup |
| `AUTH_ADMIN_KEY` | Protects the admin UI itself |
| `AUTH_TLS_CERT`, `AUTH_TLS_KEY` | TLS listener config |
| `AUTH_TLS_DISABLED` | HTTP vs HTTPS mode |
| `AUTH_DATA_DIR` | Database and key file locations |
| `AUTH_POSTGRES_URL` | Database connection |
| `AUTH_JWT_ISSUER` | JWT signing identity |

**Do NOT hardcode these in your app code.** They belong in your Docker Compose, Kubernetes manifest, or `.env` file.

### Tier 2: Runtime Settings (admin UI / admin API)

These settings can be changed at any time from the admin UI (Settings page) or via `PUT /api/admin/settings`. They take effect immediately without restart.

| Parameter | Admin UI location |
|-----------|-------------------|
| Redirect URIs | Settings → Redirect URIs |
| CORS Origins | Settings → CORS |
| Password Policy | Settings → Password Policy |
| Account Lockout | Settings → Account Lockout |
| Rate Limiting | Settings → Rate Limiting |
| Default Roles | Settings → Default Roles |
| Audit Retention | Settings → Audit Log |
| Auto-SSO | Settings → Single Sign-On |
| SSO Delay | Settings → Single Sign-On |
| Enable shared SSO session cookie | Settings → Single Sign-On |
| Session idle timeout (hours) | Settings → Single Sign-On |
| Session absolute max (hours) | Settings → Single Sign-On |
| Deployment Name | Settings → General |

### Priority Order

```
Admin UI / API (highest) → Environment Variable → Config File → Code Default (lowest)
```

On **first run**, env vars seed the runtime settings into the database. After that, the database (admin UI) owns these values. Changing the env var after first run has NO effect — use the admin UI or API instead.

**Exception:** Tier 1 (startup) settings always come from env vars / config file. The admin UI cannot change them.

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
| `data_dir` | `AUTH_DATA_DIR` | `./data` | Directory for the database, TLS certificates, and keytabs. |
| `postgres_url` | `AUTH_POSTGRES_URL` | (none) | PostgreSQL connection string (e.g. `postgres://user:pass@host:5432/dbname?sslmode=disable`). When set, SimpleAuth uses Postgres instead of BoltDB. The target database is auto-created if it does not exist. Optional -- omit to use the embedded BoltDB backend. |
| `admin_key` | `AUTH_ADMIN_KEY` | (auto-generated) | Master admin API key. If not set, a random key is generated on each startup and printed to logs. Set this to make it permanent. |
| `redirect_uri` | `AUTH_REDIRECT_URI` | (none) | Allowed OIDC redirect URI (single value). |
| `redirect_uris` | `AUTH_REDIRECT_URIS` | (none) | Allowed OIDC redirect URIs (comma-separated list). Use this to allow multiple apps to share one SimpleAuth instance. Both `AUTH_REDIRECT_URI` and `AUTH_REDIRECT_URIS` can be set -- they are merged and deduplicated. Wildcard `*` suffix supported (e.g. `https://app.corp.local/*`). If neither is set, all redirects are **rejected** (only the hosted login page works). |
| `deployment_name` | `AUTH_DEPLOYMENT_NAME` | `sauth` | Deployment name (max 6 chars, letters only a-z/A-Z), used in AD service account naming (`svc-sauth-{deployment_name}`). Useful when running multiple SimpleAuth instances against the same AD. |
| `jwt_issuer` | `AUTH_JWT_ISSUER` | `simpleauth` | JWT issuer claim and OIDC realm name. The OIDC issuer URL becomes `https://{hostname}{base_path}/realms/{jwt_issuer}`. |
| `access_ttl` | `AUTH_JWT_ACCESS_TTL` | `15m` | Access token lifetime. Go duration format (e.g., `15m`, `1h`, `8h`). |
| `refresh_ttl` | `AUTH_JWT_REFRESH_TTL` | `720h` | Refresh token lifetime (default 30 days). |
| `impersonate_ttl` | `AUTH_IMPERSONATE_TTL` | `1h` | Token lifetime for impersonation tokens. |
| `tls_cert` | `AUTH_TLS_CERT` | (auto-generated) | Path to TLS certificate file. If not set, SimpleAuth generates a self-signed cert in `data_dir`. |
| `tls_key` | `AUTH_TLS_KEY` | (auto-generated) | Path to TLS private key file. |
| `tls_disabled` | `AUTH_TLS_DISABLED` | `false` | Disable TLS and serve plain HTTP. Use when behind a reverse proxy (nginx, Traefik, etc.) that handles TLS termination. |
| `trusted_proxies` | `AUTH_TRUSTED_PROXIES` | (none) | Comma-separated list of trusted proxy IPs/CIDRs. `X-Forwarded-For` and `X-Real-IP` headers are only trusted from these addresses. If empty, forwarded headers are **ignored** and rate limiting uses the direct connection IP. **REQUIRED** when behind a reverse proxy. Example: `172.16.0.0/12,10.0.0.0/8` |
| `base_path` | `AUTH_BASE_PATH` | `/sauth` | URL path prefix. All routes are served under this prefix (e.g. `/sauth/login`, `/sauth/api/...`, `/sauth/realms/...`). Set to `""` to serve from the root path. |
| `krb5_keytab` | `AUTH_KRB5_KEYTAB` | (none) | Path to Kerberos keytab file for SPNEGO authentication. Usually auto-configured via the admin UI. |
| `krb5_realm` | `AUTH_KRB5_REALM` | (none) | Kerberos realm (e.g., `CORP.LOCAL`). |
| `audit_retention` | `AUTH_AUDIT_RETENTION` | `2160h` | How long to keep audit log entries (default 90 days). Pruned daily. |
| `rate_limit_max` | `AUTH_RATE_LIMIT_MAX` | `10` | Maximum login attempts per IP within the rate limit window. |
| `rate_limit_window` | `AUTH_RATE_LIMIT_WINDOW` | `1m` | Rate limit sliding window duration. |
| `cors_origins` | `AUTH_CORS_ORIGINS` | (none) | Allowed CORS origins. Comma-separated list or `*` for all. Example: `https://app1.example.com,https://app2.example.com` |
| `default_roles` | `AUTH_DEFAULT_ROLES` | (none) | Default roles assigned to new users on first login. Comma-separated in env var, YAML list in config file. Example: `user,viewer` |
| `password_min_length` | `AUTH_PASSWORD_MIN_LENGTH` | `8` | Minimum password length. |
| `password_require_uppercase` | `AUTH_PASSWORD_REQUIRE_UPPERCASE` | `false` | Require at least one uppercase letter. |
| `password_require_lowercase` | `AUTH_PASSWORD_REQUIRE_LOWERCASE` | `false` | Require at least one lowercase letter. |
| `password_require_digit` | `AUTH_PASSWORD_REQUIRE_DIGIT` | `false` | Require at least one digit. |
| `password_require_special` | `AUTH_PASSWORD_REQUIRE_SPECIAL` | `false` | Require at least one special character. |
| `password_history_count` | `AUTH_PASSWORD_HISTORY_COUNT` | `0` | Number of previous passwords to remember and prevent reuse. `0` disables history check. |
| `account_lockout_threshold` | `AUTH_ACCOUNT_LOCKOUT_THRESHOLD` | `0` | Number of failed login attempts before the account is locked. `0` disables account lockout. |
| `account_lockout_duration` | `AUTH_ACCOUNT_LOCKOUT_DURATION` | `30m` | How long an account stays locked after hitting the lockout threshold. Go duration format. |
| `auto_sso` | `AUTH_AUTO_SSO` | `false` | When enabled, the login page automatically attempts Kerberos SSO without user interaction. Shows a "Attempting Single Sign-On..." spinner and redirects on success. Falls back to the manual login form if SSO fails. |
| `auto_sso_delay` | `AUTH_AUTO_SSO_DELAY` | `3` | Seconds to show the countdown animation before auto-redirecting to SSO. The user can cancel during the countdown. |
| `enable_session_sso` | `AUTH_ENABLE_SESSION_SSO` | `false` | Enables a shared SSO session cookie. After a successful login, SimpleAuth sets an HttpOnly cookie on its own host. On subsequent redirects from any app, the login page is skipped and fresh tokens are issued immediately. Works across different subdomains — apps never see the cookie; only SimpleAuth does. See [Session SSO](#shared-sso-session-cookie) below. |
| `session_sso_idle_ttl` | `AUTH_SESSION_SSO_IDLE_TTL` | `8h` | Session dies after this duration of inactivity. Bumped every time a user's browser hits SimpleAuth (each redirect from an app counts). Go duration format. |
| `session_sso_max_ttl` | `AUTH_SESSION_SSO_MAX_TTL` | `720h` | Absolute maximum lifetime regardless of activity. After this, the user must re-authenticate. Default is 30 days. Go duration format. |

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

# OIDC settings
redirect_uri: "https://myapp.example.com/callback"
# Multiple redirect URIs for multi-app deployments
redirect_uris:
  - "https://app2.example.com/callback"
  - "https://app3.example.com/*"

# Deployment name for multi-instance deployments (max 6 chars, letters only)
deployment_name: "prod"

# JWT settings
jwt_issuer: "simpleauth"
access_ttl: "15m"
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

# Password policy
password_min_length: 8
password_require_uppercase: false
password_require_lowercase: false
password_require_digit: false
password_require_special: false
password_history_count: 0

# Account lockout
account_lockout_threshold: 0
account_lockout_duration: "30m"

# Kerberos SSO
auto_sso: false            # auto-attempt SSO on login page (no click required)
auto_sso_delay: 3          # seconds to show countdown before SSO redirect
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
  -e AUTH_REDIRECT_URI="https://myapp.example.com/callback" \
  -e AUTH_REDIRECT_URIS="https://app2.example.com/callback,https://app3.example.com/*" \
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
      AUTH_JWT_ACCESS_TTL: "15m"
      AUTH_REDIRECT_URI: "https://myapp.example.com/callback"
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

Generate a good key:

```bash
openssl rand -hex 16
```

### `redirect_uri` / `redirect_uris`

- `redirect_uri` sets a single allowed redirect URI for the authorization code flow.
- `redirect_uris` sets multiple allowed redirect URIs as a comma-separated list (env var) or YAML list (config file). This lets multiple applications on different domains share one SimpleAuth instance.
- Both can be set simultaneously -- they are merged into one deduplicated allow-list.
- Wildcard `*` suffix is supported (e.g. `https://app.corp.local/*` matches any path under that origin).
- If neither is set, all redirect URIs are **rejected**. The hosted login page still works (it redirects to the built-in account page), but OIDC authorization-code flows that supply a `redirect_uri` parameter will fail.

**Example (env vars):**

```bash
AUTH_REDIRECT_URI=https://app1.corp.local/callback
AUTH_REDIRECT_URIS=https://app2.corp.local/callback,https://app3.corp.local/*
```

### `jwt_issuer`

This value serves double duty:
1. It becomes the `iss` claim in all JWTs (as part of the OIDC issuer URL)
2. It becomes the OIDC realm name in URLs

The full OIDC issuer URL is: `https://{hostname}:{port}{base_path}/realms/{jwt_issuer}`

### `access_ttl` / `refresh_ttl`

These control how long tokens last. Uses Go duration format:
- `15m` = 15 minutes (default access TTL)
- `1h` = 1 hour
- `720h` = 30 days (default refresh TTL)
- `2160h` = 90 days

Shorter access TTLs are more secure (less time for a stolen token to be used) but require more frequent refreshes. The 15-minute default is a deliberate security choice -- increase it if your clients cannot handle frequent token refreshes.

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

## Runtime Settings vs. Environment Variables

Environment variables and config file values **seed the database on first run only**. After that, the Admin UI (or `PUT /api/admin/settings`) owns these values and they are stored in the database under `runtime_settings`. Changing an env var after first run has no effect on settings that are already stored in the DB.

Settings managed this way include: `deployment_name`, `redirect_uris`, `cors_origins`, password policy, account lockout, and `default_roles`.

To reset a runtime setting to its env-var value, delete the `runtime_settings` key from the database (or delete the database and let SimpleAuth re-seed).

---

## Database Backend

SimpleAuth supports two storage backends:

### BoltDB (default)

An embedded, single-file key-value database. No external server needed. Data is stored in `{data_dir}/auth.db`.

### PostgreSQL (optional)

Set `AUTH_POSTGRES_URL` to a PostgreSQL connection string to use Postgres instead. SimpleAuth auto-creates the target database if it does not exist (it connects to the `postgres` maintenance database and issues `CREATE DATABASE`). All tables are prefixed with `sa_` and are auto-migrated on startup.

### How the backend is selected (`OpenSmart`)

1. **`db.json`** in the data directory -- if it exists and specifies `"backend": "postgres"`, that wins. This file is written by the Admin UI when you switch backends.
2. **`AUTH_POSTGRES_URL`** env var / config -- if `db.json` does not exist but the env var is set, Postgres is used and a `db.json` is written so the UI knows the active backend.
3. **Fallback** -- if neither is set, BoltDB is used.

If Postgres is configured but the connection fails at startup, SimpleAuth **falls back to BoltDB** with a warning in the logs.

### `db.json`

A small JSON file in the data directory that records the active backend choice:

```json
{
  "backend": "postgres",
  "postgres_url": "postgres://user:pass@host:5432/dbname?sslmode=disable"
}
```

This file is managed by the Admin UI migration/switch endpoints -- you do not need to create it manually.

### Migration

The Admin UI provides bidirectional migration between BoltDB and PostgreSQL:

- `POST /api/admin/database/migrate` with `direction: "to_postgres"` or `"to_boltdb"`
- The target is truncated before copy (idempotent)
- Row counts are verified after migration
- `POST /api/admin/database/switch` saves the backend choice to `db.json` and triggers a graceful restart

---

## Auto-Generated Resources

On first startup, SimpleAuth auto-generates several things if they don't already exist:

1. **Data directory** -- Created at `data_dir` with mode `0700`
2. **BoltDB database** -- `{data_dir}/auth.db` (unless Postgres is configured)
3. **TLS certificate** -- `{data_dir}/tls.crt` and `{data_dir}/tls.key` (self-signed, 10-year validity, includes all local IPs in SANs)
4. **RSA signing keys** -- Stored in the database, used for JWT signing (RS256)
5. **Admin key** -- Printed to logs if not configured

---

## Reverse Proxy Deployment

When running SimpleAuth behind a reverse proxy (nginx, Traefik, HAProxy, etc.), configure it for HTTP-only mode:

```yaml
# simpleauth.yaml
tls_disabled: true
trusted_proxies:
  - "172.16.0.0/12"
  - "10.0.0.0/8"
  - "192.168.0.0/16"
```

Or via environment variables:

```bash
AUTH_TLS_DISABLED=true
AUTH_TRUSTED_PROXIES="172.16.0.0/12,10.0.0.0/8,192.168.0.0/16"
```

### Why trusted proxies matter

When behind a reverse proxy, the client's real IP comes from `X-Forwarded-For` or `X-Real-IP` headers set by the proxy. If `trusted_proxies` is empty, SimpleAuth ignores these headers entirely and uses the direct TCP connection IP for rate limiting and audit logs. This means rate limiting will see your proxy's IP, not the client's IP -- effectively breaking per-client rate limiting.

Set `trusted_proxies` to your proxy's network range so SimpleAuth trusts forwarded headers only from known proxies. For Docker networks, `172.16.0.0/12` covers the default bridge range.

### Nginx example

See [deploy/nginx/nginx.conf](../deploy/nginx/nginx.conf) for a production-ready nginx config. Key points:

- nginx terminates TLS (with your real certificate)
- Proxies to SimpleAuth over plain HTTP inside the Docker network
- Forwards `X-Real-IP`, `X-Forwarded-For`, and `X-Forwarded-Proto` headers
- Large header buffers for Kerberos/SPNEGO tokens
- Rate limiting at the nginx level (defense in depth)

### Docker Compose with nginx

```bash
# Start SimpleAuth with nginx reverse proxy
docker compose --profile full up -d
```

Place your TLS certificates in `deploy/nginx/certs/`:
- `fullchain.pem` — certificate chain
- `privkey.pem` — private key

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

---

## Shared SSO Session Cookie

> **Status:** Optional. Disabled by default. Enable via `AUTH_ENABLE_SESSION_SSO=true` or the admin UI.

When a single SimpleAuth instance hosts multiple apps (often linked together, possibly iframed), re-entering credentials every time the user bounces between apps is painful — especially when access tokens are deliberately short-lived (15 min). The session SSO cookie solves this without introducing multi-realm complexity.

### How it works

1. User logs in to **App A** (password, Kerberos, OIDC — any flow). SimpleAuth sets a browser cookie `__sa_sso` on its own host (e.g. `auth.example.com`), scoped to that host only (no `Domain=` attribute).
2. User opens **App B**. App B's access token is expired. App B redirects to `https://auth.example.com/login?redirect_uri=https://app-b.example.com/callback`.
3. SimpleAuth sees the cookie, validates the session, and redirects back to App B immediately with fresh tokens in the URL fragment. The login page is never shown.
4. Each redirect to SimpleAuth bumps the session's `last_used_at`, so active users stay signed in indefinitely (up to `session_sso_max_ttl`).

### Why it works across different subdomains

The cookie lives on `auth.example.com` only. Apps on `app-a.corp.local` and `app-b.corp.local` never see it — they don't need to. The browser redirects to `auth.example.com`, and only SimpleAuth reads the cookie. The result goes back to the app via URL fragment (tokens). Because SimpleAuth is the only authority, every app participates in the same single sign-on with no cookie-domain tricks.

### Why this does not weaken security

| Concern | Mitigation |
|---------|------------|
| Cookie theft via XSS | `HttpOnly` — inaccessible from JS. |
| Cookie theft in transit | `Secure` — only sent over TLS. (Auto-disabled if `AUTH_TLS_DISABLED=true`, but then the reverse proxy is expected to terminate TLS.) |
| CSRF via `/login?redirect_uri=` | `redirect_uri` is validated against the allowlist. Attacker-controlled URIs are rejected. |
| Cross-site cookie use | `SameSite=Strict` (TLS) / `SameSite=Lax` (HTTP fallback). |
| Compromised account | Admin can destroy all SSO sessions via `DELETE /api/admin/users/{guid}/sessions`. |
| Disabled/merged user | Resolver re-checks every hit — disabled accounts cannot use an old cookie. |
| User-level revocation | Resolver checks `IsUserAccessRevoked` on every hit. |
| Unbounded session growth | Background cleanup task deletes expired sessions hourly. |
| Entropy | 32 bytes (256 bits) from `crypto/rand`. |

### Single logout

When the user hits SimpleAuth's `/logout` endpoint, the cookie is cleared on the browser **and** the session row is deleted from the DB. Subsequent auto-login redirects will fail, forcing a fresh login. The OIDC end-session endpoint (`/realms/{realm}/protocol/openid-connect/logout`) with an `id_token_hint` additionally destroys **all** sessions for that user across every browser (kills mobile + desktop sessions in one call).

### Admin revocation

`DELETE /api/admin/users/{guid}/sessions` now destroys:
- All refresh tokens for the user
- A blacklist entry for the user's access tokens (until they expire)
- **All shared SSO session cookies for that user on every browser**

Combined, this means an admin can fully sign a user out of every app in under a second.

### Two TTLs explained

- **`session_sso_idle_ttl` (default 8h)**: activity timer. Reset every time the user's browser hits SimpleAuth. A user who's actively bouncing between apps will stay signed in indefinitely.
- **`session_sso_max_ttl` (default 720h / 30 days)**: hard cap. Regardless of activity, the session expires. This protects long-stolen cookies from being valid forever.

### When NOT to enable this

- Single-app deployments with only one redirect URI — the login page is shown exactly once per access-token window; the cookie adds complexity without benefit.
- Kiosks / shared devices where each user must re-authenticate. If you do enable it on kiosks, set `session_sso_idle_ttl` to something aggressive like `15m`.
- Deployments where `/logout` is not called reliably (e.g. apps that only clear local tokens). The cookie survives client-side logout unless SimpleAuth's logout endpoint is hit.

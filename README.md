<p align="center">
  <h1 align="center">SimpleAuth</h1>
  <p align="center">
    <strong>The simplest way to add authentication to any app.</strong><br>
    Single binary &bull; 10MB &bull; Zero dependencies &bull; Full Kerberos SSO &bull; Standard OIDC provider
  </p>
  <p align="center">
    <a href="docs/QUICKSTART.md">Quick Start</a> &middot;
    <a href="docs/API.md">API Reference</a> &middot;
    <a href="docs/ACTIVE-DIRECTORY.md">AD Guide</a> &middot;
    <a href="docs/SDK-GUIDE.md">SDKs</a>
  </p>
</p>

---

SimpleAuth is an identity server that ships as a single Go binary. It connects to Active Directory, handles Kerberos/SPNEGO for transparent Windows SSO, serves as a standard OIDC provider, and issues RS256 JWTs. No Java. No containers required. No config files after first run -- everything is managed from the built-in admin UI.

Each instance serves one application. Users are auto-created on first login from any provider. No import. No sync. No migration.

## Why SimpleAuth?

| | Keycloak | ADFS | SimpleAuth |
|---|---------|------|------------|
| **Setup** | Hours (Java, Postgres, Redis) | Hours + Windows Server | **3 commands** |
| **Size** | ~500MB+ | N/A | **~10MB** |
| **Kerberos SSO** | Complex manual config | Built-in but rigid | **2-click auto-config** |
| **OIDC** | Full provider | Claims-based | **Full provider** |
| **REST API** | Complex | None | **Simple JSON + JWTs** |
| **Admin UI** | Steep learning curve | Windows-only | **Everything in one page** |
| **Deployment** | Cluster + database | Domain controller | **Single binary, optional DB** |

## Quick Start

### Docker

```bash
docker run -d -p 8080:8080 \
  -e AUTH_HOSTNAME=auth.example.com \
  -e AUTH_ADMIN_KEY=my-secret-admin-key \
  -e AUTH_REDIRECT_URIS="https://myapp.example.com/callback,https://myapp.example.com/*" \
  -e AUTH_CORS_ORIGINS="https://myapp.example.com" \
  -v simpleauth-data:/data \
  simpleauth
```

### Binary

```bash
./simpleauth init-config     # generates simpleauth.yaml
vim simpleauth.yaml          # set hostname, redirect URIs, admin key
./simpleauth                 # running
```

Admin UI is at `https://<hostname>/sauth/admin`. Enter your admin key to log in.

If you omit `AUTH_ADMIN_KEY`, one is auto-generated on first run and printed to stdout -- check your logs.

> **Required for any real deployment:** `AUTH_HOSTNAME`, `AUTH_ADMIN_KEY`, and `AUTH_REDIRECT_URIS`. Without redirect URIs, all login redirects are rejected.

---

## Integration Guide

This section explains how to add SimpleAuth to your app, step by step. No prior knowledge of OAuth2 or OIDC is needed.

### What You Need to Know First

- **What is SimpleAuth?** -- It is an authentication server. Your app talks to it over HTTP. SimpleAuth stores users, handles passwords, and issues tokens that prove a user is logged in. Your app never touches passwords directly.

- **What is a JWT?** -- A JWT (JSON Web Token) is a signed string your app receives after a user logs in. It contains the user's name, email, roles, and an expiration time (15 minutes by default). Your app sends it in the `Authorization: Bearer <token>` header on every API request to prove the user is authenticated.

- **What is a redirect URI?** -- When a user logs in through SimpleAuth's hosted login page, SimpleAuth needs to send them back to YOUR app with the tokens. The redirect URI is the URL in your app where SimpleAuth sends the user after login. You MUST tell SimpleAuth which URLs are allowed (via `AUTH_REDIRECT_URIS`), or it rejects the redirect for security.

- **What is CORS?** -- If your frontend JavaScript (running in a browser) calls SimpleAuth directly (not through your backend), the browser blocks the request unless SimpleAuth explicitly allows your frontend's domain. Set `AUTH_CORS_ORIGINS` to your frontend's URL to allow this.

- **What is the base path?** -- SimpleAuth serves everything under `/sauth` by default. Every URL starts with `https://your-host/sauth/...`. Do not forget this prefix -- it is the most common integration mistake.

- **What is the admin key?** -- A secret string that grants access to the admin API and admin UI. Set it via `AUTH_ADMIN_KEY`. If you do not set it, SimpleAuth auto-generates one on first run and prints it to stdout (check your container logs).

### Step-by-Step: Integrate with Any App

All examples below use `https://auth.example.com` as the SimpleAuth host (assuming a reverse proxy handles TLS on port 443). Replace it with your actual hostname.

---

#### Step 1: Deploy SimpleAuth

```bash
docker run -d -p 8080:8080 \
  -e AUTH_HOSTNAME=auth.example.com \
  -e AUTH_ADMIN_KEY=my-secret-admin-key \
  -e AUTH_REDIRECT_URIS="https://myapp.example.com/callback,https://myapp.example.com/*" \
  -e AUTH_CORS_ORIGINS="https://myapp.example.com" \
  -v simpleauth-data:/data \
  simpleauth
```

| Variable | What it does |
|----------|-------------|
| `AUTH_HOSTNAME` | The public domain name where SimpleAuth is reachable (used for TLS cert and token issuer). |
| `AUTH_ADMIN_KEY` | Secret key to access the admin UI and admin API -- keep it safe. |
| `AUTH_REDIRECT_URIS` | Comma-separated list of URLs where SimpleAuth is allowed to redirect users after login (supports `*` wildcards). |
| `AUTH_CORS_ORIGINS` | Comma-separated list of frontend domains allowed to call SimpleAuth from the browser. |
| `-v simpleauth-data:/data` | Persistent volume for the database, RSA keys, and TLS certs -- do not lose this. |

---

#### Step 2: Create a User

**Option A: Admin UI**

Open `https://auth.example.com/sauth/admin` in your browser. Enter your admin key. Click "Users" and create a user.

**Option B: Bootstrap API (curl)**

The bootstrap endpoint is idempotent -- safe to call on every app startup.

```bash
curl -X POST https://auth.example.com/sauth/api/admin/bootstrap \
  -H "Authorization: Bearer my-secret-admin-key" \
  -H "Content-Type: application/json" \
  -d '{
    "permissions": ["read", "write"],
    "role_permissions": {
      "admin": ["read", "write"],
      "viewer": ["read"]
    },
    "users": [
      {
        "username": "alice",
        "password": "secret123",
        "display_name": "Alice Smith",
        "email": "alice@example.com",
        "roles": ["admin"]
      }
    ]
  }'
```

Response:

```json
{
  "users": [
    { "username": "alice", "guid": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx", "created": true }
  ],
  "permissions_count": 2,
  "role_permissions_count": 2
}
```

---

#### Step 3: Log In and Get Tokens

There are three ways to log in. Pick the one that fits your app.

**Flow A: Direct API (your backend calls SimpleAuth)**

Best for: mobile apps, SPAs that talk to your backend, server-to-server.

```bash
curl -X POST https://auth.example.com/sauth/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"alice","password":"secret123"}'
```

Response:

```json
{
  "access_token": "eyJhbGciOiJSUzI1NiIs...",
  "refresh_token": "eyJhbGciOiJSUzI1NiIs...",
  "expires_in": 900,
  "token_type": "Bearer"
}
```

- `access_token` -- send this in the `Authorization: Bearer <token>` header on every request. Expires in 900 seconds (15 minutes).
- `refresh_token` -- use this to get a new access token when the old one expires (see Step 5).
- `expires_in` -- seconds until the access token expires.

**Flow B: Hosted Login Page (redirect users to SimpleAuth)**

Best for: web apps that do not want to build their own login form.

1. Your app redirects the user's browser to:
   ```
   https://auth.example.com/sauth/login?redirect_uri=https://myapp.example.com/callback
   ```
2. The user sees SimpleAuth's login page and enters their username/password (or is auto-logged in via Kerberos SSO).
3. After successful login, SimpleAuth redirects the user's browser to:
   ```
   https://myapp.example.com/callback#access_token=eyJ...&refresh_token=eyJ...&expires_in=900&token_type=Bearer
   ```
4. Your app extracts the tokens from the URL fragment (the part after `#`). In JavaScript:
   ```javascript
   const params = new URLSearchParams(window.location.hash.substring(1));
   const accessToken = params.get('access_token');
   const refreshToken = params.get('refresh_token');
   ```

**Flow C: OIDC (standard OAuth2 authorization code flow)**

Best for: apps using an OIDC client library (any language), or when you need an `id_token`.

1. **Discovery** -- your OIDC library fetches this automatically:
   ```
   GET https://auth.example.com/sauth/.well-known/openid-configuration
   ```

2. **Redirect the user** to the authorization endpoint:
   ```
   https://auth.example.com/sauth/realms/simpleauth/protocol/openid-connect/auth?client_id=simpleauth&redirect_uri=https://myapp.example.com/callback&response_type=code&state=RANDOM_STRING
   ```
   - `client_id` is always `simpleauth`. No client secret needed.
   - `state` is a random string you generate to prevent CSRF. Your app must verify it matches when the user comes back.

3. **User logs in** and SimpleAuth redirects to:
   ```
   https://myapp.example.com/callback?code=AUTH_CODE_HERE&state=RANDOM_STRING
   ```

4. **Exchange the code for tokens** (your backend calls SimpleAuth):
   ```bash
   curl -X POST https://auth.example.com/sauth/realms/simpleauth/protocol/openid-connect/token \
     -d "grant_type=authorization_code" \
     -d "code=AUTH_CODE_HERE" \
     -d "redirect_uri=https://myapp.example.com/callback" \
     -d "client_id=simpleauth"
   ```

5. **Response** contains `access_token`, `refresh_token`, and `id_token`.

---

#### Step 4: Verify Tokens

Your app needs to verify that the access token is valid and not expired.

**Option A: Local verification (recommended)**

Fetch the public keys once from the JWKS endpoint and verify the RS256 signature locally. Every JWT library supports this.

```
JWKS URL: https://auth.example.com/sauth/.well-known/jwks.json
```

This is the fastest option -- no network call on every request. Cache the JWKS keys and refresh them periodically (e.g., every hour).

**Option B: UserInfo endpoint**

Call SimpleAuth on every request to validate the token and get user info:

```bash
curl https://auth.example.com/sauth/api/auth/userinfo \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIs..."
```

Response:

```json
{
  "guid": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
  "preferred_username": "alice",
  "samaccountname": "alice",
  "display_name": "Alice Smith",
  "email": "alice@example.com",
  "department": "Engineering",
  "company": "Example Corp",
  "job_title": "Developer",
  "roles": ["admin"],
  "permissions": ["read", "write"],
  "groups": ["Domain Users"],
  "auth_source": "local"
}
```

---

#### Step 5: Refresh Tokens

Access tokens expire in 15 minutes. Use the refresh token to get a new access token without asking the user to log in again.

```bash
curl -X POST https://auth.example.com/sauth/api/auth/refresh \
  -H "Content-Type: application/json" \
  -d '{"refresh_token":"eyJhbGciOiJSUzI1NiIs..."}'
```

Response:

```json
{
  "access_token": "eyJ_NEW_ACCESS_TOKEN...",
  "refresh_token": "eyJ_NEW_REFRESH_TOKEN...",
  "expires_in": 900,
  "token_type": "Bearer"
}
```

**IMPORTANT:** SimpleAuth uses refresh token rotation. Each time you refresh, you get a NEW refresh token. The old refresh token is revoked. Always store and use the latest refresh token from the response. If you accidentally use an old refresh token, SimpleAuth revokes the entire token family for security.

---

#### Step 6: Logout

Redirect the user to SimpleAuth's logout endpoint:

```
https://auth.example.com/sauth/logout?redirect_uri=https://myapp.example.com/
```

This clears the user's SSO cookies and redirects them back to the login page (or to your app if you provide a redirect URI).

On your app's side, delete the stored access token and refresh token.

---

### Common Mistakes

| Mistake | Fix |
|---------|-----|
| Forgetting `/sauth` in URLs | Every SimpleAuth URL starts with `/sauth` (e.g., `/sauth/api/auth/login`, not `/api/auth/login`). |
| Not setting `AUTH_REDIRECT_URIS` | Without this, all redirects are rejected. Set it to your app's callback URL(s). |
| Not refreshing tokens | Access tokens expire in 15 minutes. Your app must call the refresh endpoint before they expire. |
| Reusing old refresh tokens | After refreshing, always use the NEW refresh token from the response. The old one is revoked (token rotation). |
| Not setting `AUTH_TRUSTED_PROXIES` | If SimpleAuth is behind nginx/Traefik/Caddy, rate limiting sees the proxy's IP instead of the client's. Set `AUTH_TRUSTED_PROXIES` to your proxy's CIDR (e.g., `172.16.0.0/12`). |
| Not setting `AUTH_CORS_ORIGINS` | If your browser-based frontend calls SimpleAuth directly, set this to your frontend's origin (e.g., `https://myapp.example.com`). Without it, browsers block the requests. |
| Using `http` instead of `https` in redirect URIs | Redirect URIs must match exactly, including the scheme. If your app uses `https`, the redirect URI must use `https`. |
| Not bootstrapping on startup | If your app defines roles/permissions, call `POST /sauth/api/admin/bootstrap` on EVERY startup. It's idempotent. See [Deployment Guide](docs/DEPLOYMENT-GUIDE.md). |
| Hardcoding admin key in code | Use environment variables (`AUTH_ADMIN_KEY`). Never commit secrets to source control. |
| **Kerberos SSO silently fails behind nginx** | nginx's default buffers (4KB) are too small for Negotiate headers. Click does nothing, no logs anywhere. Add **all four**: `proxy_buffer_size 128k`, `proxy_buffers 4 256k`, `large_client_header_buffers 4 64k`, `client_header_buffer_size 64k`. The last two are both needed — some nginx builds drop oversized headers if only one is set. See [Deployment Guide](docs/DEPLOYMENT-GUIDE.md#nginx-example). |

---

### JWT Token Structure

When you decode an access token (using any JWT library or [jwt.io](https://jwt.io)), the payload looks like this:

```json
{
  "sub": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
  "guid": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
  "preferred_username": "alice",
  "samaccountname": "alice",
  "name": "Alice Smith",
  "email": "alice@example.com",
  "department": "Engineering",
  "company": "Example Corp",
  "job_title": "Developer",
  "roles": ["admin"],
  "permissions": ["read", "write"],
  "groups": ["Domain Users"],
  "iss": "https://auth.example.com/sauth/realms/simpleauth",
  "exp": 1234567890,
  "iat": 1234567000
}
```

| Claim | Description |
|-------|-------------|
| `sub` | User's unique GUID (same as `guid`). Never changes, even if the username changes. |
| `preferred_username` | The user's login name (e.g., `alice`). Best-effort — may be UPN-shaped (`user@domain`) in some AD deployments. Do NOT use for authz lookups in authn-only apps. |
| `samaccountname` | **Authoritative AD sAMAccountName.** Captured from LDAP on every login, stable across email/UPN/display-name changes. The correct key for apps that maintain their own authz tables. Absent for local (non-AD) users. Self-heals on next login for users who existed before this claim. See [docs/API.md](docs/API.md#pattern-authn-only-apps-with-their-own-authz-table). |
| `name` | Display name. |
| `email` | Email address. In many AD deployments admins reuse this for role accounts — do NOT use as a stable authz key. |
| `roles` | Array of role names assigned to the user. |
| `permissions` | Array of permission strings resolved from the user's roles. |
| `groups` | LDAP/AD group memberships (empty for local-only users). |
| `department`, `company`, `job_title` | Profile fields synced from LDAP/AD or set manually. |
| `iss` | Issuer URL. Always `https://<hostname>/sauth/realms/simpleauth`. |
| `exp` | Expiration time (Unix timestamp). |
| `iat` | Issued-at time (Unix timestamp). |

---

## Features

### Authentication
- **Kerberos/SPNEGO** -- transparent Windows SSO with auto-configured keytab
- **Auto-SSO** -- optional automatic SSO attempt with countdown animation and cancel button (`AUTH_AUTO_SSO=true`)
- **Shared SSO session cookie** -- optional (`AUTH_ENABLE_SESSION_SSO=true`). Once logged in via any flow (password/Kerberos/OIDC), the browser carries a scoped HttpOnly cookie on the SimpleAuth host. Subsequent redirects from any participating app skip the login page entirely. Two TTLs: idle (8h default, bumped on every SimpleAuth visit) and absolute max (30 days default). Single-logout and admin-revocation supported. See [docs/CONFIGURATION.md](docs/CONFIGURATION.md#shared-sso-session-cookie).
- **LDAP bind** -- form-based login for non-domain users
- **Local passwords** -- bcrypt-hashed, configurable policy (length, complexity, history)
- **Account lockout** -- automatic lockout after repeated failures
- **Hosted login page** -- redirect-based flow at `/sauth/login`, apps don't need their own login form
- **Standard OIDC provider** -- discovery, authorization code flow, token endpoint, userinfo
- **Impersonation** -- admins generate tokens as any user, fully audited

### Authorization
- **RS256 JWTs** -- auto-generated RSA-2048 keys, 15-minute access tokens, 30-day refresh tokens
- **JWKS endpoint** -- `/.well-known/jwks.json` for offline token verification
- **Roles and permissions** -- global to the instance, assigned to users, with role-permission mapping
- **Default roles** -- auto-assigned to new users on first login
- **Refresh token rotation** -- family-based replay detection with automatic revocation

### Admin UI
Full management dashboard at `/sauth/admin` with dark mode:
- Users (CRUD, disable, merge, unlock, force password change)
- Roles and permissions
- LDAP providers with auto-discovery and AD setup script
- Identity mappings
- Audit log with configurable retention
- Runtime settings (redirect URIs, CORS, password policy, rate limiting)
- Database management (stats, migration, backend switching)
- Server restart

### Database
- **BoltDB** (default) -- embedded, zero config, zero dependencies
- **PostgreSQL** (optional) -- set `AUTH_POSTGRES_URL` to enable
- **Migrate between backends** from the Admin UI
- **Automatic fallback** -- if Postgres is unreachable, falls back to BoltDB

### Security

| Area | Implementation |
|------|---------------|
| JWT signing | RS256, auto-generated RSA-2048, JWKS endpoint |
| Token revocation | Access token blacklist + refresh token replay detection |
| Passwords | Bcrypt, configurable policy, password history |
| Account lockout | Configurable threshold and duration |
| CSRF | Token-based on all login forms |
| Rate limiting | Per-IP, configurable window/threshold, trusted proxy support |
| Redirect validation | Strict allowlist; empty list = reject all |
| Trusted proxies | Default: trust none; explicit CIDR configuration required |

### Developer Experience
- **Standard OIDC provider** -- works with any OIDC client library in any language
- **Direct REST API** -- simple JSON endpoints for lightweight integrations
- **Client SDKs** -- official libraries for JS/TS, Go, Python, .NET
- **Embeddable** -- `pkg/server` package for embedding in any Go application
- **Linux SSO script** -- auto-generated bash script configures krb5.conf + all major browsers
- **Backup/restore** -- live BoltDB snapshots via API

## OIDC Endpoints

SimpleAuth is a standard OpenID Connect provider. Use any OIDC client library.

**Discovery:** `GET /.well-known/openid-configuration`

| Endpoint | Method | Path |
|----------|--------|------|
| Authorization | `GET` | `/realms/{issuer}/protocol/openid-connect/auth` |
| Token | `POST` | `/realms/{issuer}/protocol/openid-connect/token` |
| UserInfo | `GET/POST` | `/realms/{issuer}/protocol/openid-connect/userinfo` |
| JWKS | `GET` | `/realms/{issuer}/protocol/openid-connect/certs` |
| Introspection | `POST` | `/realms/{issuer}/protocol/openid-connect/token/introspect` |
| End Session | `GET/POST` | `/realms/{issuer}/protocol/openid-connect/logout` |

**Supported flows:** `authorization_code`, `client_credentials`, `password`, `refresh_token`

```bash
# Example: Authorization Code Flow
curl "https://auth.example.com/sauth/.well-known/openid-configuration"

# Token exchange
curl -X POST "https://auth.example.com/sauth/realms/simpleauth/protocol/openid-connect/token" \
  -d "grant_type=authorization_code&code=AUTH_CODE&redirect_uri=https://myapp.example.com/callback"
```

## Direct API

For simple integrations that don't need full OIDC.

```bash
# Login
curl -X POST https://auth.example.com/sauth/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username": "jsmith", "password": "secret"}'

# Response: { "access_token": "eyJ...", "refresh_token": "...", "user": {...} }

# Refresh
curl -X POST https://auth.example.com/sauth/api/auth/refresh \
  -H "Content-Type: application/json" \
  -d '{"refresh_token": "..."}'

# UserInfo
curl https://auth.example.com/sauth/api/auth/userinfo \
  -H "Authorization: Bearer eyJ..."
```

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/api/auth/login` | Login, get JWT tokens |
| `POST` | `/api/auth/refresh` | Rotate refresh token |
| `GET` | `/api/auth/userinfo` | Current user info from JWT |
| `GET` | `/api/auth/negotiate` | Kerberos/SPNEGO SSO |
| `POST` | `/api/auth/impersonate` | Generate token as another user (admin) |
| `POST` | `/api/auth/reset-password` | Change password (authenticated) |
| `GET` | `/login` | Hosted login page |
| `GET` | `/logout` | Clear SSO cookies, redirect to login |
| `GET` | `/account` | Self-service profile + password change |
| `GET` | `/.well-known/jwks.json` | JWKS public keys |
| `GET` | `/health` | Health check |

## Admin API

All admin endpoints require `Authorization: Bearer <admin-key>`.

| Category | Endpoints |
|----------|-----------|
| **Bootstrap** | `POST /api/admin/bootstrap` -- idempotent: define roles, permissions, ensure users |
| **Users** | CRUD `/api/admin/users`, merge/unmerge, disable, unlock, sessions |
| **Roles & Permissions** | `/api/admin/roles`, `/api/admin/permissions`, `/api/admin/role-permissions` |
| **LDAP** | CRUD `/api/admin/ldap`, auto-discover, import/export, test connection |
| **AD Setup** | `GET /api/admin/setup-script` -- PowerShell script with hostname pre-injected |
| **Kerberos** | `/api/admin/ldap/:id/setup-kerberos` -- setup, cleanup, status |
| **Linux SSO** | `GET /api/admin/linux-setup-script` -- bash script for krb5 + browser config |
| **Settings** | `GET/PUT /api/admin/settings` -- runtime configuration |
| **Database** | Info, test, migrate, switch backends |
| **Operations** | Backup, restore, audit log, restart |

See [docs/API.md](docs/API.md) for the complete reference with request/response examples.

## Active Directory Setup

**2 clicks to full Kerberos SSO.**

1. **Admin UI** -> LDAP Providers -> AD Setup Script. Enter a service account name. Download the PowerShell script.
2. **Run the script** on any domain-joined machine (`.\Setup-SimpleAuth.ps1`). It creates the service account, registers SPNs, and exports a config file.
3. **Import the config** back in the Admin UI. SimpleAuth generates the keytab in-memory, enables SSO immediately.

No `ktpass`. No keytab files. No manual LDAP configuration. The script is fully interactive, idempotent, and handles cleanup.

### Linux SSO

The admin UI generates a bash script (`GET /api/admin/linux-setup-script`) that configures:
- `krb5.conf` for your domain
- Browser policies for Firefox, Chrome, Edge, Brave, Vivaldi, and Opera
- Optional SSSD domain join

## Client SDKs

| Language | Package | Install |
|----------|---------|---------|
| **JavaScript/TypeScript** | `@simpleauth/js` | `npm install @simpleauth/js` |
| **Go** | `github.com/bodaay/simpleauth-go` | `go get github.com/bodaay/simpleauth-go` |
| **Python** | `simpleauth` | `pip install simpleauth` |
| **.NET Core** | `SimpleAuth` | Reference the project |

All SDKs include:
- Login, refresh, and userinfo via direct API
- Offline JWT verification with cached JWKS keys
- Role and permission helpers (`HasRole`, `HasPermission`, `HasAnyRole`)
- Framework middleware (Express, net/http, FastAPI/Flask/Django, ASP.NET Core)

See [examples/](examples/) for integration code.

## Embed in Go

```go
package main

import (
    "log"
    "net/http"
    "simpleauth/pkg/server"
    "simpleauth/ui"
)

func main() {
    cfg := server.Defaults()
    cfg.Hostname = "myapp.example.com"
    cfg.AdminKey = "my-secret-key"
    cfg.DataDir = "./auth-data"
    cfg.BasePath = "/auth"
    cfg.TLSDisabled = true

    sa, err := server.New(cfg, ui.FS())
    if err != nil {
        log.Fatal(err)
    }
    defer sa.Close()

    mux := http.NewServeMux()
    mux.Handle("/auth/", http.StripPrefix("/auth", sa.Handler()))
    mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
        w.Write([]byte("My app with built-in auth"))
    })

    log.Println("Running on :8080")
    http.ListenAndServe(":8080", mux)
}
```

`server.New(cfg, uiFS)` gives you programmatic control. Pass `nil` as config to load from env vars. Pass `nil` as UI to run API-only.

### Bootstrap Pattern

Use `POST /api/admin/bootstrap` on every startup to ensure your app's roles, permissions, and root user exist. It's idempotent -- safe to call repeatedly.

```go
// After server.New(), call bootstrap to ensure auth state
bootstrapAuth(cfg.AdminKey, "http://localhost:8080/auth", os.Getenv("ROOT_PASSWORD"))
```

See the [full bootstrap example](docs/ARCHITECTURE.md) in the architecture docs.

## Configuration

Generate a config file with `./simpleauth init-config`. Environment variables always override config file values.

### Essential Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `AUTH_HOSTNAME` | OS hostname | FQDN for TLS cert and Kerberos SPN |
| `AUTH_ADMIN_KEY` | auto-generated | Admin API key |
| `AUTH_BASE_PATH` | `/sauth` | URL path prefix |
| `AUTH_REDIRECT_URI` | | Allowed redirect URI (single) |
| `AUTH_REDIRECT_URIS` | | Allowed redirect URIs (comma-separated) |
| `AUTH_POSTGRES_URL` | | PostgreSQL URL (enables Postgres backend) |
| `AUTH_TLS_DISABLED` | `false` | Disable TLS (for reverse proxy mode) |
| `AUTH_TRUSTED_PROXIES` | | Trusted proxy CIDRs (default: trust none) |
| `AUTH_JWT_ACCESS_TTL` | `15m` | Access token lifetime |
| `AUTH_JWT_REFRESH_TTL` | `720h` | Refresh token lifetime (30 days) |
| `AUTH_CORS_ORIGINS` | | CORS origins (comma-separated or `*`) |
| `AUTH_AUTO_SSO` | `false` | Auto-attempt Kerberos SSO on login page |
| `AUTH_AUTO_SSO_DELAY` | `3` | Seconds before auto-SSO redirect (with cancel) |
| `AUTH_ENABLE_SESSION_SSO` | `false` | Shared SSO session cookie — skip login page on subsequent app redirects |
| `AUTH_SESSION_SSO_IDLE_TTL` | `8h` | Session idle timeout (bumped on every SimpleAuth hit) |
| `AUTH_SESSION_SSO_MAX_TTL` | `720h` | Session absolute max lifetime (30 days) |
| `AUTH_DATA_DIR` | `./data` | Data directory for DB, certs, keytabs |
| `AUTH_DEPLOYMENT_NAME` | `sauth` | Deployment name (for service account naming) |

See [docs/CONFIGURATION.md](docs/CONFIGURATION.md) for all options including password policy, rate limiting, account lockout, and audit retention.

> **Note:** If neither `AUTH_REDIRECT_URI` nor `AUTH_REDIRECT_URIS` is set, all redirects are **rejected**.

### Reverse Proxy

```bash
AUTH_TLS_DISABLED=true
AUTH_TRUSTED_PROXIES="172.16.0.0/12,10.0.0.0/8"
```

See [docs/REVERSE-PROXY.md](docs/REVERSE-PROXY.md) for nginx, Traefik, Caddy, and HAProxy examples.

## Architecture

```
simpleauth
├── main.go                        # Entry point
├── pkg/server/                    # Embeddable library
├── internal/
│   ├── config/                    # YAML + env config, auto TLS
│   ├── store/
│   │   ├── interface.go           # Storage interface
│   │   ├── bolt.go                # BoltDB implementation
│   │   ├── postgres.go            # PostgreSQL implementation
│   │   └── migrate.go             # Backend migration
│   ├── auth/
│   │   ├── jwt.go                 # RSA keys, JWT, JWKS, OIDC tokens
│   │   ├── ldap.go                # LDAP search, bind, attribute sync
│   │   └── local.go               # Bcrypt password hashing
│   └── handler/
│       ├── auth.go                # Login, refresh, SSO, impersonation
│       ├── oidc.go                # Standard OIDC provider endpoints
│       ├── hosted_login.go        # Hosted login page
│       ├── admin.go               # User CRUD, roles, backup/restore
│       ├── admin_ldap.go          # LDAP management, AD setup
│       ├── admin_kerberos.go      # Keytab generation, SPN management
│       ├── admin_settings.go      # Runtime settings
│       └── admin_linux_sso.go     # Linux SSO setup script
├── sdk/                           # Official SDKs (JS, Go, Python, .NET)
├── examples/                      # Integration examples
├── docs/                          # Full documentation
├── deploy/nginx/                  # Production nginx config
└── ui/                            # Embedded Preact admin UI
```

## Documentation

| Document | Description |
|----------|-------------|
| [Quick Start](docs/QUICKSTART.md) | Running in 5 minutes |
| [API Reference](docs/API.md) | Every endpoint with examples |
| [Configuration](docs/CONFIGURATION.md) | All config options |
| [Architecture](docs/ARCHITECTURE.md) | How it works under the hood |
| [Active Directory](docs/ACTIVE-DIRECTORY.md) | AD setup, Kerberos, troubleshooting |
| [Reverse Proxy](docs/REVERSE-PROXY.md) | nginx, Traefik, Caddy, HAProxy |
| [SDK Guide](docs/SDK-GUIDE.md) | Client SDK usage |

## License

MIT

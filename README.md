<p align="center">
  <h1 align="center">SimpleAuth</h1>
  <p align="center">
    <strong>The simplest way to add Active Directory authentication to any app.</strong><br>
    Single binary. Zero dependencies. Full Kerberos SSO. REST API + RS256 JWTs.<br>
    BoltDB or PostgreSQL. Admin UI for everything. Embeddable as a Go library.
  </p>
</p>

---

**SimpleAuth** is a single-instance identity server that replaces Keycloak, ADFS, and custom LDAP code with a single Go binary. It connects to your Active Directory, handles Kerberos/SPNEGO for transparent Windows SSO, provides a clean REST API, and issues RS256 JWTs -- all with zero external dependencies and an embedded admin UI.

Each SimpleAuth instance serves one application. Roles and permissions are global to the instance. Every user gets a stable GUID. AD is just another identity provider. Users are auto-created on first login. No import. No sync. No migration.

## Why SimpleAuth?

| | Keycloak | ADFS | SimpleAuth |
|---|---------|------|------------|
| **Setup time** | Hours/days | Hours + Windows Server | **Minutes** |
| **Dependencies** | Java, PostgreSQL, Redis | Windows Server, IIS | **None** |
| **Binary size** | ~500MB+ container | N/A | **~15MB** |
| **Kerberos SSO** | Complex config | Built-in but rigid | **Auto-configured** |
| **AD integration** | Manual LDAP config | Native but complex | **Auto-discovery + PowerShell script** |
| **Learning curve** | Steep (realms, flows, mappers...) | Moderate | **Flat** |
| **REST API** | Custom per-setup | Claims-based | **Simple JSON API + RS256 JWTs** |

## Quick Start

### Option 1: Docker (recommended)

```bash
docker run -d -p 8080:8080 -p 80:80 \
  -e AUTH_HOSTNAME=auth.corp.local \
  -e AUTH_REDIRECT_URI=https://myapp.corp.local/callback \
  -v simpleauth-data:/data \
  simpleauth
```

**Multiple redirect URIs:** Use `AUTH_REDIRECT_URIS` (plural) to allow multiple redirect URIs, e.g. `AUTH_REDIRECT_URIS=https://app2.corp.local/callback,https://app3.corp.local/*`. Both `AUTH_REDIRECT_URI` and `AUTH_REDIRECT_URIS` can be set -- they are merged into one deduplicated list. Wildcard `*` suffix is supported. If neither is set, all redirects are **rejected**.

### Option 2: Binary

```bash
./simpleauth init-config          # generates simpleauth.yaml
vim simpleauth.yaml               # set hostname, config (admin_key auto-generates if empty)
./simpleauth                      # that's it
```

On first run, SimpleAuth will:
1. Generate a self-signed TLS certificate (with your hostname in SANs)
2. Generate RSA-2048 keys for JWT signing
3. Auto-generate an admin key if none configured (printed to stdout)
4. Start HTTPS on port 9090 and HTTP redirect on port 80

The default base path is `/sauth`. The admin UI is at `https://<hostname>/sauth/admin` (port 9090 for binary, 8080 for Docker). The hosted login page is at `/sauth/login`.

### Admin Access

Admin access is controlled exclusively by the **ADMIN_KEY** -- a secret set via config or environment variable. Include it as `Authorization: Bearer <admin-key>` in API requests or enter it in the admin UI.

## The AD Setup That Changes Everything

**This is the killer feature.** Traditionally, connecting an app to Active Directory for Kerberos SSO requires:
1. Create a service account in AD
2. Pick the right OU
3. Set the right flags (password never expires, cannot change password)
4. Register an SPN with `setspn`
5. Export a keytab with `ktpass` (get the flags wrong and start over)
6. Configure LDAP bind DN, base DN, filters
7. Copy keytab to server, set permissions, configure paths
8. Debug why it doesn't work for 3 hours

**SimpleAuth does this in 2 clicks:**

### Step 1: Generate the PowerShell Script

In the admin UI, go to **LDAP Providers** -> **AD Setup Script**. Enter a service account name and password. Download the script.

### Step 2: Run it on Any Domain-Joined Machine

```powershell
# Run as admin on a DC or any machine with RSAT
.\Setup-SimpleAuth.ps1
```

The script is **fully interactive** and **idempotent**:

```
  ========================================
       SimpleAuth  AD  Manager
  ========================================

  Domain:    corp.local
  Base DN:   DC=corp,DC=local
  DC:        dc01.corp.local

  [1/4] Select where to create the service account

    0) (Default Users container)
    1) corp.local/Service Accounts
    2) corp.local/IT/Applications
    ...

  Enter number [0]: 1
  Selected: corp.local/Service Accounts

  [2/4] Setting up service account...
  Account created in: OU=Service Accounts,DC=corp,DC=local

  [3/4] Kerberos / SPNEGO setup (optional)
  Enter the FQDN clients use to reach SimpleAuth
  (e.g. simpleauth.corp.local) or press Enter to skip.

  SimpleAuth hostname: auth.corp.local
  Registering SPN: HTTP/auth.corp.local on svc-sauth-sauth
  SPN registered successfully

  [4/4] Exporting config...

  ========================================
           Setup Complete!
  ========================================

  Config file: C:\Users\Admin\simpleauth-config.json

  Next steps:
    1. Copy simpleauth-config.json to your workstation
    2. Open SimpleAuth admin UI -> LDAP Providers
    3. Click Import Config and upload the file
```

### Step 3: Import the Config

Back in SimpleAuth's admin UI, click **Import Config** and upload `simpleauth-config.json`. SimpleAuth will:
- Auto-discover the domain (DCs, base DN, user filters)
- Create the LDAP provider
- **Generate the Kerberos keytab in-memory** (no `ktpass`, no file copying)
- Register the SPN on the service account via LDAP
- Enable SSO immediately

**That's it.** Domain-joined users now get transparent Kerberos SSO. Non-domain users see a login form with LDAP bind authentication. Both paths resolve to the same GUID.

### Re-running the Script

If the service account already exists, the script detects it and offers:

1. **Re-run setup** -- update password, manage SPNs, re-export config
2. **Remove everything** -- remove SPNs, delete or disable the account, clean up
3. **Exit**

No orphaned accounts. No mystery SPNs. Full lifecycle management.

### Why This Approach is Brilliant

- **No `ktpass` needed** -- SimpleAuth generates the keytab programmatically using the service account password and proper AD salt derivation. The keytab is generated server-side with AES-256, AES-128, and RC4-HMAC encryption types.
- **No file transfer** -- The only thing moving between AD and SimpleAuth is a small JSON config file. No keytab files being emailed around or sitting on network shares.
- **Idempotent** -- Run the script 10 times, get the same result. Existing accounts are updated, not duplicated.
- **Multi-instance aware** -- Use `deployment_name` config to run multiple SimpleAuth instances with distinct service accounts (`svc-prod`, `svc-dev`).
- **Self-healing KVNO** -- SimpleAuth patches keytab KVNO at runtime to match the ticket's KVNO. Password changes in AD don't break Kerberos -- just re-import the config.
- **GSS-API aware** -- Handles both raw AP-REQ tokens and GSS-API wrapped SPNEGO tokens from browsers. NTLM fallback is detected and gracefully handled with a login form.

## Features

### Database

- **BoltDB** (default) -- zero config, embedded, no external dependencies
- **PostgreSQL** (optional) -- set `AUTH_POSTGRES_URL` to enable; auto-creates the database if it doesn't exist
- **Migrate between backends** from the Admin UI -- move data from BoltDB to Postgres or vice versa
- **Automatic fallback** -- if Postgres is unreachable on startup, falls back to BoltDB

### Admin UI

Full management dashboard at `/sauth/admin` with dark mode:

- **Dashboard** -- system overview and stats
- **Users** -- CRUD, disable, merge/unmerge, force password change, unlock
- **Roles & Permissions** -- define and assign roles, permissions, and role-permission mappings
- **LDAP Settings** -- provider management, auto-discovery, import/export, AD setup script
- **Identity Mappings** -- view and manage `(provider, external_id) -> GUID` links
- **Impersonation** -- generate tokens as any user, fully audited
- **Audit Log** -- searchable event log with configurable retention
- **Settings** -- runtime configuration: redirect URIs, CORS, password policy, account lockout, rate limiting, default roles, audit retention
- **Database** -- backend stats, test connection, migrate data, switch backends

### Settings from UI

Most configuration is manageable from the Admin UI at runtime. Environment variables seed the database on first run, then the database owns the values. Changes take effect immediately without restart.

### Authentication

- **Kerberos/SPNEGO** -- transparent Windows SSO, auto-configured keytab
- **LDAP bind** -- form-based login with fallback user filter detection (sAMAccountName, userPrincipalName, uid)
- **Local passwords** -- bcrypt-hashed, for non-AD users
- **Password policy** -- configurable minimum length and complexity requirements (uppercase, lowercase, digit, special)
- **Password history** -- prevent reuse of recent passwords
- **Account lockout** -- automatic lockout after repeated failed login attempts, with configurable threshold and duration
- **Force password change** -- admin can require a user to change their password on next login
- **Hosted login page** -- redirect-based flow, apps don't need their own login form
- **Legacy OIDC compatibility** -- Keycloak-compatible endpoints available for migration (deprecated, direct API recommended)
- **Impersonation** -- admins generate tokens as any user, fully audited

### Identity

- **GUID-based users** -- stable identity across all systems, usernames are just attributes
- **Zero-import onboarding** -- users auto-created on first login from any provider
- **Identity mappings** -- `(provider, external_id) -> GUID` across LDAP, Kerberos
- **User merge/unmerge** -- consolidate duplicate accounts, all mappings follow
- **Rich profiles** -- name, email, department, company, job title, groups synced from AD on every login

### Authorization

- **Global roles and permissions** -- define roles and permissions at the instance level, assigned to users
- **Default roles** -- auto-assigned to new users on first login
- **Role-permission mapping** -- associate permissions with roles for structured access control
- **RS256 JWTs** -- auto-generated RSA-2048 keys, JWKS endpoint, all claims in the token
- **Refresh token rotation** -- family-based replay detection with automatic revocation
- **Token revocation blacklist** -- access tokens revoked immediately on demand

### Operations

- **Single binary** -- zero external dependencies, ~15MB, runs anywhere
- **Embedded admin UI** -- Preact SPA with dark mode, no build step
- **HTTPS or reverse proxy** -- auto-generates self-signed certs, or HTTP-only mode behind nginx/Traefik
- **User self-service** -- `/account` page for profile view and password change
- **LDAP/AD integration** -- connect to Active Directory or LDAP with auto-discovery
- **Backup/restore** -- live BoltDB snapshots via API
- **Audit logging** -- every action logged with configurable retention
- **Rate limiting** -- per-IP, configurable window and threshold, with trusted proxy support
- **Graceful restart from UI** -- `POST /api/admin/restart` for zero-downtime restarts
- **Linux SSO setup script** -- auto-generated bash script configures krb5.conf + browser policies (Firefox, Chrome, Edge, Brave, Vivaldi, Opera) + optional SSSD domain join
- **Embeddable** -- `pkg/server` package for embedding SimpleAuth in any Go application

### Legacy OIDC / Keycloak Compatibility (Deprecated)

> For new integrations, use the direct `/api/auth/*` endpoints. The OIDC layer exists only for migrating existing Keycloak apps and will be removed in v1.0.

Keycloak-compatible endpoints are available at `/realms/{realm}/protocol/openid-connect/*` for apps migrating from Keycloak. `client_id` and `client_secret` are accepted but not validated.

## Security

| Area | Implementation |
|------|---------------|
| **JWT signing** | RS256 with auto-generated RSA-2048 keys, JWKS endpoint for public key distribution |
| **Token revocation** | Access token blacklist with immediate effect; refresh token family-based replay detection |
| **Password storage** | Bcrypt hashing, configurable policy (length, complexity), password history |
| **Account protection** | Lockout after N failed attempts, configurable threshold and duration |
| **CSRF** | Token-based CSRF protection on all login forms |
| **Admin authentication** | Timing-safe comparison of admin key |
| **Rate limiting** | Per-IP with configurable window/threshold, trusted proxy CIDR support |
| **Redirect validation** | Scheme validation + allowlist; empty allowlist = reject all |

## Client SDKs

Official SDKs with JWKS-cached token validation, middleware, and role/permission helpers:

| Language | Package | Install |
|----------|---------|---------|
| **JavaScript/TypeScript** | `@simpleauth/js` | `npm install @simpleauth/js` |
| **Go** | `github.com/bodaay/simpleauth-go` | `go get github.com/bodaay/simpleauth-go` |
| **Python** | `simpleauth` | `pip install simpleauth` |
| **.NET Core** | `SimpleAuth` | Reference the project |

Every SDK supports:
- Login (`POST /api/auth/login`), refresh (`POST /api/auth/refresh`) via direct JSON API
- **Offline token verification** -- JWKS keys fetched from `GET /.well-known/jwks.json`, cached, RS256 signature verified locally
- UserInfo (`GET /api/auth/userinfo`)
- Admin operations via `AdminKey`
- Role and permission helpers (`HasRole`, `HasPermission`, `HasAnyRole`)
- Framework middleware (Express, net/http, FastAPI/Flask/Django, ASP.NET Core)

See [examples/](examples/) for copy-paste ready integration code.

## Embed in Your Go App

SimpleAuth can be embedded directly into any Go application as a library. It runs as a full auth server inside your process -- same REST API, same admin UI, same JWT issuance, same database backend support (BoltDB or PostgreSQL) -- no separate binary needed.

```go
package main

import (
    "log"
    "net/http"

    "simpleauth/pkg/server"
    "simpleauth/ui"
)

func main() {
    // Option 1: Programmatic config -- full control, no env vars read
    cfg := server.Defaults()
    cfg.Hostname = "myapp.example.com"
    cfg.AdminKey = "my-secret-key"
    cfg.DataDir = "./auth-data"
    cfg.BasePath = "/auth"
    cfg.TLSDisabled = true // your app handles TLS

    sa, err := server.New(cfg, ui.FS())
    if err != nil {
        log.Fatal(err)
    }
    defer sa.Close()

    // Option 2: Load from env vars / config file (same as standalone binary)
    // sa, err := server.New(nil, ui.FS())

    mux := http.NewServeMux()
    mux.Handle("/auth/", http.StripPrefix("/auth", sa.Handler()))
    mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
        w.Write([]byte("My app"))
    })

    log.Println("App running on :8080, auth at /auth/")
    http.ListenAndServe(":8080", mux)
}
```

**How it works:**
- `server.Defaults()` returns a config with sensible defaults -- modify only what you need
- `server.New(cfg, uiFS)` -- pass a config for full programmatic control (no env vars read)
- `server.New(nil, uiFS)` -- pass nil to load from `AUTH_*` env vars / config file (same as standalone)
- `sa.Handler()` returns a standard `http.Handler` you mount on your router
- `ui.FS()` provides the embedded admin UI; pass `nil` to run without a UI (API only)
- `server.Config` is the same struct used by the standalone binary -- every field is available
- Your app communicates with SimpleAuth via its REST API at whatever path you mount it on

### Bootstrap Pattern (Recommended)

When embedding SimpleAuth, your app should **bootstrap** the auth state on every startup using `POST /api/admin/bootstrap`. This single idempotent call defines the roles and permissions your app needs and ensures a root admin user exists with a password controlled by your config. This way:

- The config/env is always the source of truth for the root password
- If someone gets locked out, a restart resets the root password
- Your app's required roles and permissions are always present

```go
func bootstrapAuth(adminKey, baseURL, rootPassword string) error {
    body, _ := json.Marshal(map[string]interface{}{
        "permissions": []string{"posts:read", "posts:write", "users:manage", "admin:access"},
        "role_permissions": map[string][]string{
            "viewer": {"posts:read"},
            "editor": {"posts:read", "posts:write"},
            "admin":  {"posts:read", "posts:write", "users:manage", "admin:access"},
        },
        "users": []map[string]interface{}{
            {
                "username":       "root",
                "password":       rootPassword,
                "display_name":   "Root Admin",
                "roles":          []string{"admin"},
                "force_password": true,
            },
        },
    })

    req, _ := http.NewRequest("POST", baseURL+"/api/admin/bootstrap", bytes.NewReader(body))
    req.Header.Set("Authorization", "Bearer "+adminKey)
    req.Header.Set("Content-Type", "application/json")

    resp, err := http.DefaultClient.Do(req)
    if err != nil {
        return err
    }
    defer resp.Body.Close()
    if resp.StatusCode != 200 {
        b, _ := io.ReadAll(resp.Body)
        return fmt.Errorf("bootstrap failed (%d): %s", resp.StatusCode, b)
    }
    return nil
}
```

Call `bootstrapAuth()` after `server.New()` on every startup. Set the root password via environment variable (e.g. `ROOT_PASSWORD`) so it never lives in code:

```go
sa, _ := server.New(cfg, ui.FS())
bootstrapAuth(cfg.AdminKey, "http://localhost:8080/auth", os.Getenv("ROOT_PASSWORD"))
```

This pattern works identically when SimpleAuth runs as a standalone server -- just call the same endpoint from your app's startup script.

## Build

```bash
# Build for current platform
go build -ldflags "-X main.Version=$(cat VERSION)" -o simpleauth .

# Cross-compile for Linux
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -ldflags="-s -w -X main.Version=$(cat VERSION)" -trimpath -o simpleauth .

# Build for Windows
GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build -ldflags="-s -w -X main.Version=$(cat VERSION)" -trimpath -o simpleauth.exe .

# Build for all platforms
./build.sh
```

## Docker

```bash
docker build -t simpleauth .
docker run -d -p 8080:8080 -p 80:80 \
  -e AUTH_ADMIN_KEY=changeme \
  -e AUTH_HOSTNAME=auth.corp.local \
  -e AUTH_REDIRECT_URI=https://myapp.corp.local/callback \
  -v simpleauth-data:/data \
  simpleauth
```

See [docker-compose.yml](docker-compose.yml) for a production setup with nginx SSL termination.

## Configuration

SimpleAuth uses a YAML config file with environment variable overrides:

```bash
./simpleauth init-config              # creates simpleauth.yaml
./simpleauth init-config /etc/simpleauth/config.yaml  # custom path
```

**Config file search order:**
1. `AUTH_CONFIG_FILE` environment variable
2. `simpleauth.yaml` or `simpleauth.yml` in current directory
3. `/etc/simpleauth/config.yaml` or `/etc/simpleauth/config.yml`

**Priority:** defaults < config file < environment variables (env always wins on first run; then DB owns settings manageable from the Admin UI)

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `AUTH_HOSTNAME` | OS hostname | FQDN for TLS cert and Kerberos SPN |
| `AUTH_PORT` | `9090` | HTTPS listen port |
| `AUTH_HTTP_PORT` | `80` | HTTP redirect port (empty = disabled) |
| `AUTH_DATA_DIR` | `./data` | Data directory for DB, certs, keytabs |
| `AUTH_ADMIN_KEY` | auto-generated | Bootstrap admin API key |
| `AUTH_BASE_PATH` | `/sauth` | URL path prefix for sub-path mounting |
| `AUTH_POSTGRES_URL` | | PostgreSQL connection URL (optional; enables Postgres backend) |
| `AUTH_REDIRECT_URI` | | Allowed OIDC redirect URI (single value; backward compatible) |
| `AUTH_REDIRECT_URIS` | | Allowed OIDC redirect URIs (comma-separated list for multiple apps) |
| `AUTH_DEPLOYMENT_NAME` | `sauth` | Deployment name (max 6 chars, letters only; for service account naming) |
| `AUTH_JWT_ISSUER` | `simpleauth` | JWT `iss` claim |
| `AUTH_JWT_ACCESS_TTL` | `15m` | Access token lifetime |
| `AUTH_JWT_REFRESH_TTL` | `720h` | Refresh token lifetime (30 days) |
| `AUTH_IMPERSONATE_TTL` | `1h` | Impersonation token lifetime |
| `AUTH_TLS_CERT` | auto-generated | TLS certificate path |
| `AUTH_TLS_KEY` | auto-generated | TLS private key path |
| `AUTH_TLS_DISABLED` | `false` | Disable TLS for reverse proxy mode (plain HTTP) |
| `AUTH_TRUSTED_PROXIES` | | Trusted proxy CIDRs for X-Forwarded-For (comma-separated; required if behind a reverse proxy) |
| `AUTH_KRB5_KEYTAB` | | Kerberos keytab path (usually auto-configured) |
| `AUTH_KRB5_REALM` | | Kerberos realm (usually auto-configured) |
| `AUTH_AUDIT_RETENTION` | `2160h` | Audit log retention (90 days) |
| `AUTH_RATE_LIMIT_MAX` | `10` | Max login attempts per window |
| `AUTH_RATE_LIMIT_WINDOW` | `1m` | Rate limit window |
| `AUTH_CORS_ORIGINS` | | CORS origins (comma-separated or `*`) |
| `AUTH_DEFAULT_ROLES` | | Default roles for new users on first login (comma-separated) |
| `AUTH_PASSWORD_MIN_LENGTH` | `8` | Minimum password length |
| `AUTH_PASSWORD_REQUIRE_UPPERCASE` | `false` | Require at least one uppercase letter |
| `AUTH_PASSWORD_REQUIRE_LOWERCASE` | `false` | Require at least one lowercase letter |
| `AUTH_PASSWORD_REQUIRE_DIGIT` | `false` | Require at least one digit |
| `AUTH_PASSWORD_REQUIRE_SPECIAL` | `false` | Require at least one special character |
| `AUTH_PASSWORD_HISTORY_COUNT` | `0` | Number of previous passwords to remember (0 = disabled) |
| `AUTH_ACCOUNT_LOCKOUT_THRESHOLD` | `0` | Failed login attempts before lockout (0 = disabled) |
| `AUTH_ACCOUNT_LOCKOUT_DURATION` | `30m` | Duration of account lockout |

> **Note:** If neither `AUTH_REDIRECT_URI` nor `AUTH_REDIRECT_URIS` is set, all redirect URIs are **rejected**.

### Reverse Proxy (nginx / Traefik / Caddy)

When running behind a reverse proxy, disable TLS and configure trusted proxies:

```bash
AUTH_TLS_DISABLED=true
AUTH_TRUSTED_PROXIES="172.16.0.0/12,10.0.0.0/8"
```

To mount SimpleAuth at a custom sub-path:

```bash
AUTH_BASE_PATH=/auth
```

See [docs/REVERSE-PROXY.md](docs/REVERSE-PROXY.md) for full nginx/Traefik/Caddy/HAProxy examples and Docker Compose setup.

### TLS Certificates

In standalone mode (no reverse proxy), SimpleAuth **always runs over HTTPS**. If no certificate is configured:

- A self-signed ECDSA (P-256) certificate is generated in `{data_dir}/tls.crt`
- Includes hostname, OS hostname, `localhost`, and all local IPs as SANs
- Valid for 10 years, reused across restarts
- **Automatically regenerated** if the configured hostname changes

For production, provide your own certificate or put SimpleAuth behind nginx (see [deploy/nginx/](deploy/nginx/)).

## API Overview

### Authentication

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/api/auth/login` | Login with username/password, get JWT tokens |
| `POST` | `/api/auth/refresh` | Rotate refresh token, get new access token |
| `GET` | `/api/auth/userinfo` | Get current user info from JWT |
| `GET` | `/api/auth/negotiate` | Kerberos/SPNEGO SSO |
| `POST` | `/api/auth/impersonate` | Generate token as another user (admin) |
| `POST` | `/api/auth/reset-password` | Change password (authenticated) |
| `GET` | `/login` | Hosted login page (redirect flow) |
| `GET` | `/account` | User self-service page (profile + password change) |
| `GET` | `/test-negotiate` | Kerberos SSO test page |
| `GET` | `/.well-known/jwks.json` | JWKS public keys |
| `GET` | `/health` | Health check |

### OIDC / Keycloak-Compatible (Deprecated — use direct API above)

Legacy endpoints at `/realms/{realm}/protocol/openid-connect/*` are available for apps migrating from Keycloak. See [Keycloak Migration Guide](docs/KEYCLOAK-MIGRATION.md).

### Admin

All admin endpoints require `Authorization: Bearer <admin-key>`.

| Category | Endpoints |
|----------|-----------|
| **Bootstrap** | `POST /api/admin/bootstrap` -- idempotent startup: define permissions, roles, ensure users exist |
| **Users** | CRUD `/api/admin/users`, merge/unmerge, password, disable, sessions |
| **Roles** | `GET/PUT /api/admin/users/{guid}/roles`, `GET/PUT /api/admin/users/{guid}/permissions` |
| **Default Roles** | `GET/PUT /api/admin/defaults/roles` |
| **Role-Permissions** | `GET/PUT /api/admin/role-permissions` |
| **All Roles/Perms** | `GET /api/admin/roles`, `GET /api/admin/permissions`, `PUT /api/admin/permissions` |
| **LDAP** | CRUD `/api/admin/ldap`, auto-discover, import/export, test connection |
| **AD Sync** | `POST /api/admin/ldap/:id/sync-user`, `POST /api/admin/ldap/:id/sync-all` |
| **AD Setup Script** | `GET /api/admin/setup-script` (interactive PowerShell with hostname pre-injected) |
| **Kerberos** | Setup, cleanup, status via `/api/admin/ldap/:id/setup-kerberos` |
| **Mappings** | Identity mappings CRUD, resolve |
| **Password Policy** | `GET /api/admin/password-policy` |
| **Account Unlock** | `PUT /api/admin/users/{guid}/unlock` |
| **Settings** | `GET/PUT /api/admin/settings` -- runtime configuration |
| **Restart** | `POST /api/admin/restart` -- graceful server restart |
| **Database** | `GET /api/admin/database/info`, `POST /api/admin/database/test`, `POST /api/admin/database/migrate`, `GET /api/admin/database/migrate/status`, `POST /api/admin/database/switch` |
| **Linux SSO** | `GET /api/admin/linux-setup-script` -- auto-generated bash script for Linux SSO setup |
| **Operations** | Backup, restore, audit log, server info |

See [docs/API.md](docs/API.md) for the complete API reference with request/response examples.

## How Login Works

```
User types "jsmith" + password into your app
        |
        v
  POST /api/auth/login
  { "username": "jsmith" }
        |
        +-- Check local users first
        |     +-- Found locally -> authenticate with bcrypt password
        |
        +-- If no local match, search LDAP for "jsmith"
        |     +-- Found in AD -> create GUID + mapping (if first login)
        |     +-- Authenticate: LDAP bind with password
        |
        +-- Sync profile: name, email, dept, company, title, groups
        |
        +-- Load roles/permissions
        |     +-- No roles? Assign default roles
        |
        +-- Issue JWT
            {
              "sub": "a1b2c3d4-...",
              "name": "John Smith",
              "email": "jsmith@corp.local",
              "roles": ["editor"],
              "groups": ["Domain Users", "IT"],
              ...
            }
```

Users are auto-created on first login. No import, no sync, no migration.

**Authentication order:** Local users are always checked first. If no local match is found, LDAP is tried next.

## Architecture

```
simpleauth
├── main.go                        # Entry point, HTTPS + HTTP redirect
├── pkg/server/                    # Embeddable library (server.New + Handler)
├── simpleauth.yaml                # Config (generated with init-config)
├── Dockerfile                     # Multi-stage production build
├── docker-compose.yml             # Full stack with nginx
├── internal/
│   ├── config/config.go           # YAML + env config, auto TLS cert generation
│   ├── store/
│   │   ├── interface.go           # Storage interface (BoltDB / PostgreSQL)
│   │   ├── bolt.go                # BoltDB storage implementation
│   │   ├── postgres.go            # PostgreSQL storage implementation
│   │   ├── migrate.go             # Data migration between backends
│   │   └── dbconfig.go            # Database configuration and switching
│   ├── auth/
│   │   ├── jwt.go                 # RSA keys, JWT signing/validation, JWKS, OIDC tokens
│   │   ├── ldap.go                # LDAP search, bind, groups, attribute sync
│   │   ├── local.go               # bcrypt password hashing
│   └── handler/
│       ├── handler.go             # Route registration, CORS, helpers
│       ├── auth.go                # Login, refresh, negotiate, SPNEGO, impersonate
│       ├── oidc.go                # OIDC/Keycloak compatibility layer
│       ├── hosted_login.go        # Hosted login page (redirect flow)
│       ├── account.go             # User self-service page (profile, password change)
│       ├── admin.go               # User CRUD, roles, backup/restore, audit
│       ├── admin_ldap.go          # LDAP management, auto-discover, import/export
│       ├── admin_kerberos.go      # Kerberos setup, keytab generation, SPN mgmt
│       ├── admin_settings.go      # Runtime settings management
│       ├── admin_migration.go     # Database migration and switching
│       ├── admin_restart.go       # Graceful restart endpoint
│       ├── admin_linux_sso.go     # Linux SSO setup script generation
│       ├── secrets.go             # Secret management
│       └── middleware.go          # Admin auth, rate limiting
├── sdk/                           # Client SDKs
│   ├── js/                        # JavaScript/TypeScript
│   ├── go/                        # Go
│   ├── python/                    # Python
│   └── dotnet/                    # .NET Core
├── examples/                      # Copy-paste integration examples
│   ├── js/                        # Express, Next.js, service-to-service
│   ├── go/                        # HTTP server, service auth
│   ├── python/                    # FastAPI, Flask, Django
│   └── dotnet/                    # ASP.NET Core Web API
├── docs/                          # Comprehensive documentation
│   ├── QUICKSTART.md
│   ├── API.md
│   ├── CONFIGURATION.md
│   ├── ARCHITECTURE.md
│   ├── ACTIVE-DIRECTORY.md
│   ├── KEYCLOAK-MIGRATION.md
│   └── SDK-GUIDE.md
├── deploy/
│   └── nginx/                     # Production nginx config with SSL
└── ui/                            # Embedded Preact admin UI
    ├── embed.go                   # ui.FS() for embedding in Go apps
    └── dist/
        ├── index.html
        ├── app.js                 # SPA: Dashboard, Users, Roles, LDAP, Mappings, Settings, Database, Audit
        └── vendor/                # Preact, htm (offline, no CDN)
```

## LDAP User Attributes

SimpleAuth syncs these attributes from AD/LDAP on every login:

| SimpleAuth Field | Default LDAP Attribute | Configurable |
|-----------------|----------------------|--------------|
| Display Name | `displayName` | `display_name_attr` |
| Email | `mail` | `email_attr` |
| Department | `department` | `department_attr` |
| Company | `company` | `company_attr` |
| Job Title | `title` | `job_title_attr` |
| Groups | `memberOf` | `groups_attr` |

All attributes are editable per-provider in the admin UI. Changes in AD are automatically synced on next login.

## Documentation

| Document | Description |
|----------|-------------|
| [Quick Start](docs/QUICKSTART.md) | Running in 5 minutes |
| [API Reference](docs/API.md) | Every endpoint with examples |
| [Configuration](docs/CONFIGURATION.md) | All config options explained |
| [Architecture](docs/ARCHITECTURE.md) | How it works under the hood |
| [Active Directory Guide](docs/ACTIVE-DIRECTORY.md) | AD setup, Kerberos, troubleshooting |
| [Keycloak Migration](docs/KEYCLOAK-MIGRATION.md) | Switching from Keycloak |
| [Reverse Proxy](docs/REVERSE-PROXY.md) | nginx, Traefik, Caddy, HAProxy deployment |
| [SDK Guide](docs/SDK-GUIDE.md) | Client SDK usage for all platforms |

## License

MIT

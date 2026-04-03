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
  -e AUTH_REDIRECT_URIS=https://myapp.example.com/callback \
  -v simpleauth-data:/data \
  simpleauth
```

### Binary

```bash
./simpleauth init-config     # generates simpleauth.yaml
vim simpleauth.yaml          # set hostname + redirect URIs
./simpleauth                 # running
```

Admin UI is at `https://<hostname>/sauth/admin`. Admin key is auto-generated on first run and printed to stdout.

## Features

### Authentication
- **Kerberos/SPNEGO** -- transparent Windows SSO with auto-configured keytab
- **Auto-SSO** -- optional automatic SSO attempt with countdown animation and cancel button (`AUTH_AUTO_SSO=true`)
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

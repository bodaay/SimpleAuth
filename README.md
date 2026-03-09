# SimpleAuth

Central identity hub for your organization. Single Go binary, embedded admin UI, BoltDB storage. Replaces Keycloak without the complexity.

Every user is a GUID. Every app maps its own identifiers to that GUID. LDAP/AD is just another identity provider.

## Features

- **GUID-based users** -- usernames, emails, and display names are just attributes. The GUID never changes.
- **Multi-app support** -- each app gets its own API key, user mappings, roles, and permissions
- **Multi-LDAP/AD** -- connect multiple directories with priority-based failover
- **Auto-discovery** -- point at a domain, SimpleAuth figures out DCs, base DN, and filters
- **Provider mappings** -- apps define how to find users in each LDAP (`sAMAccountName`, `mail`, `telephoneNumber`, etc.)
- **Zero-import onboarding** -- users are auto-discovered and created on first login
- **Identity mappings** -- `(provider, external_id) -> GUID` across LDAP, apps, Kerberos, or any future provider
- **User merge/unmerge** -- consolidate duplicate accounts, all mappings follow
- **Kerberos/SPNEGO** -- transparent Windows SSO via keytab
- **Hosted login page** -- redirect-based flow for apps that don't want to build their own login form
- **Impersonation** -- admins generate tokens as any user, fully audited
- **RS256 JWTs** -- auto-generated RSA-2048 keys, JWKS endpoint for token validation
- **Refresh token rotation** -- family-based replay detection with automatic revocation
- **Role & permission management** -- app-scoped, with configurable defaults for new users
- **Audit logging** -- every login, impersonation, role change, and key rotation is logged with configurable retention
- **Embedded admin UI** -- Preact SPA with dark mode, no build step required
- **Single binary** -- zero external dependencies, runs anywhere
- **Backup/Restore** -- live BoltDB snapshots via API

## Quick Start

```bash
# Set the master admin key and run
export AUTH_ADMIN_KEY="your-secret-admin-key"
./simpleauth
```

Open http://localhost:9090 and sign in with your admin key.

## Build

```bash
# Build for current platform
go build -o simpleauth .

# Build for all platforms (linux, darwin, windows -- amd64 + arm64)
./build.sh
```

Artifacts land in `dist/` with SHA-256 checksums.

## Docker

```dockerfile
FROM golang:1.24-alpine AS build
WORKDIR /src
COPY . .
RUN CGO_ENABLED=0 go build -ldflags="-s -w" -trimpath -o /simpleauth .

FROM alpine:3.19
RUN apk add --no-cache ca-certificates
COPY --from=build /simpleauth /usr/local/bin/simpleauth
EXPOSE 9090
VOLUME /data
ENV AUTH_DATA_DIR=/data
ENTRYPOINT ["simpleauth"]
```

```bash
docker build -t simpleauth .
docker run -d -p 9090:9090 \
  -e AUTH_ADMIN_KEY=changeme \
  -v simpleauth-data:/data \
  simpleauth
```

## Configuration

All configuration is via environment variables:

| Variable | Default | Description |
|----------|---------|-------------|
| `AUTH_ADMIN_KEY` | **(required)** | Master admin API key |
| `AUTH_PORT` | `9090` | HTTP listen port |
| `AUTH_DATA_DIR` | `./data` | Directory for BoltDB and RSA keys |
| `AUTH_JWT_ISSUER` | `simpleauth` | JWT `iss` claim |
| `AUTH_JWT_ACCESS_TTL` | `8h` | Access token lifetime |
| `AUTH_JWT_REFRESH_TTL` | `720h` | Refresh token lifetime (30 days) |
| `AUTH_IMPERSONATE_TTL` | `1h` | Impersonation token lifetime |
| `AUTH_KRB5_KEYTAB` | | Path to Kerberos keytab file |
| `AUTH_KRB5_REALM` | | Kerberos realm (e.g. `CORP.LOCAL`) |
| `AUTH_TLS_CERT` | | TLS certificate file path |
| `AUTH_TLS_KEY` | | TLS private key file path |
| `AUTH_AUDIT_RETENTION` | `2160h` | Audit log retention (90 days) |

## API Reference

### Authentication

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/api/auth/login` | Authenticate user, get tokens |
| `POST` | `/api/auth/refresh` | Rotate refresh token, get new access token |
| `GET` | `/api/auth/userinfo` | Get current user info from JWT |
| `GET` | `/api/auth/negotiate` | Kerberos/SPNEGO login |
| `POST` | `/api/auth/impersonate` | Generate token as another user (admin only) |
| `GET` | `/login` | Hosted login page (redirect-based flow) |
| `GET` | `/.well-known/jwks.json` | JWKS public keys |
| `GET` | `/health` | Health check |

### Login

```bash
curl -X POST http://localhost:9090/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username": "khalefa", "password": "secret", "app_id": "my-app"}'
```

```json
{
  "access_token": "eyJ...",
  "refresh_token": "eyJ...",
  "expires_in": 28800,
  "token_type": "Bearer"
}
```

`app_id` is optional. When provided, SimpleAuth resolves the app-specific username to a GUID using provider mappings -- no user import needed.

### Hosted Login (Redirect Flow)

For apps that don't want to build a login form:

```
https://auth.corp.local/login?app_id=my-app&redirect_uri=https://myapp.com/callback
```

On success, redirects back with tokens in the URL fragment:
```
https://myapp.com/callback#access_token=eyJ...&refresh_token=eyJ...&expires_in=28800&token_type=Bearer
```

### JWT Claims

```json
{
  "sub": "a1b2c3d4-5678-90ab-cdef-1234567890ab",
  "name": "Khalefa Ahmad",
  "email": "kalahmad@corp.local",
  "app_id": "my-app",
  "roles": ["admin", "editor"],
  "permissions": ["read", "write", "delete"],
  "groups": ["Domain Users", "IT Department"],
  "iss": "simpleauth",
  "exp": 1741528800
}
```

### Admin API

All admin endpoints require `Authorization: Bearer <admin-key>`.

#### Apps

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/admin/apps` | List apps |
| `POST` | `/api/admin/apps` | Register app |
| `GET` | `/api/admin/apps/:id` | Get app |
| `PUT` | `/api/admin/apps/:id` | Update app |
| `DELETE` | `/api/admin/apps/:id` | Delete app |
| `POST` | `/api/admin/apps/:id/rotate-key` | Rotate API key |

#### Users

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/admin/users` | List users |
| `POST` | `/api/admin/users` | Create user |
| `GET` | `/api/admin/users/:guid` | Get user |
| `PUT` | `/api/admin/users/:guid` | Update user |
| `DELETE` | `/api/admin/users/:guid` | Delete user |
| `POST` | `/api/admin/users/merge` | Merge duplicate users |
| `POST` | `/api/admin/users/:guid/unmerge` | Undo merge |

#### Identity Mappings

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/admin/mappings` | List all mappings |
| `GET` | `/api/admin/users/:guid/mappings` | Get user's mappings |
| `PUT` | `/api/admin/users/:guid/mappings` | Set mapping |
| `DELETE` | `/api/admin/users/:guid/mappings/:provider/:id` | Delete mapping |
| `GET` | `/api/admin/mappings/resolve` | Resolve mapping to GUID |

#### Roles & Permissions

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/admin/apps/:app/users/:guid/roles` | Get user roles |
| `PUT` | `/api/admin/apps/:app/users/:guid/roles` | Set user roles |
| `GET` | `/api/admin/apps/:app/users/:guid/permissions` | Get user permissions |
| `PUT` | `/api/admin/apps/:app/users/:guid/permissions` | Set user permissions |
| `GET` | `/api/admin/apps/:app/defaults/roles` | Get default roles |
| `PUT` | `/api/admin/apps/:app/defaults/roles` | Set default roles |

#### LDAP Providers

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/admin/ldap` | List providers |
| `POST` | `/api/admin/ldap` | Add provider |
| `PUT` | `/api/admin/ldap/:id` | Update provider |
| `DELETE` | `/api/admin/ldap/:id` | Delete provider |
| `POST` | `/api/admin/ldap/:id/test` | Test connection |
| `POST` | `/api/admin/ldap/auto-discover` | Auto-configure from domain |
| `GET` | `/api/admin/ldap/export` | Export configs |
| `POST` | `/api/admin/ldap/import` | Import configs |

#### Operations

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/admin/backup` | Download BoltDB snapshot |
| `POST` | `/api/admin/restore` | Upload and restore backup |
| `GET` | `/api/admin/audit` | Query audit log |

## Architecture

```
simpleauth
├── main.go                    # Entry point, embeds UI
├── internal/
│   ├── config/config.go       # Environment variable loading
│   ├── store/store.go         # BoltDB storage layer
│   ├── auth/
│   │   ├── jwt.go             # RSA key management, JWT signing/validation, JWKS
│   │   ├── ldap.go            # LDAP search, bind, group extraction
│   │   └── local.go           # bcrypt password hashing
│   └── handler/
│       ├── handler.go         # Route registration, helpers
│       ├── auth.go            # Login, refresh, impersonate, Kerberos
│       ├── hosted_login.go    # Hosted login page (redirect flow)
│       ├── admin.go           # App/user/mapping/role CRUD, backup/restore
│       ├── admin_ldap.go      # LDAP provider management
│       └── middleware.go      # Admin auth, rate limiting
└── ui/dist/                   # Embedded Preact admin UI
    ├── index.html
    ├── app.js
    └── style.css
```

## How Auth Resolution Works

When a user logs in with `app_id`:

1. Check existing mapping `(app:<app_id>, username) -> GUID`
2. If no mapping, search LDAP using the app's `provider_mappings` config
3. If LDAP finds a match, create/reuse GUID and auto-create mappings
4. Authenticate via LDAP bind or local password
5. Load app-scoped roles/permissions, issue JWT

This means a new app can be added and users start logging in immediately -- no import, no sync, no migration.

## License

MIT

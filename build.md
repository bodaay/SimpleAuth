# Auth Server — Build Spec

Lightweight Go authentication service for AD/LDAP integration and JWT issuance.
Replaces Keycloak for internal Go apps that need Active Directory SSO.

---

## Overview

Single Go binary. Runs as a Docker container. No external dependencies except an optional AD/LDAP server.

- Authenticates users against AD/LDAP or local password
- Supports Windows SSO (Kerberos/SPNEGO) for transparent domain login
- Issues signed JWTs with roles, permissions, and AD groups
- Exposes JWKS endpoint so any app can validate tokens
- Admin API for managing LDAP config, users, roles, and permissions
- SQLite storage (single file, no database service needed)

---

## Tech Stack

- Go (stdlib `net/http` for HTTP)
- SQLite via `modernc.org/sqlite` (pure Go, no CGO)
- `github.com/go-ldap/ldap/v3` — LDAP authentication
- `github.com/golang-jwt/jwt/v5` — JWT signing/verification
- `github.com/jcmturner/gokrb5/v8` — Kerberos/SPNEGO
- `golang.org/x/crypto/bcrypt` — local password hashing

---

## JWT Claims

```json
{
  "sub": "jsmith",
  "name": "John Smith",
  "email": "jsmith@corp.local",
  "roles": ["admin", "user"],
  "permissions": ["can_view_profile_pictures", "can_export"],
  "groups": ["Domain Users", "IT Department"],
  "iss": "auth-server",
  "iat": 1741500000,
  "exp": 1741528800
}
```

| Field | Source |
|-------|--------|
| `sub` | Username (from login or LDAP) |
| `name` | LDAP `displayName` attr or local user display name |
| `email` | LDAP `mail` attr or local user email |
| `roles` | Managed via admin API, stored in SQLite |
| `permissions` | Managed via admin API, stored in SQLite |
| `groups` | Pulled from AD `memberOf` attribute during LDAP auth |

Signed with RS256. RSA-2048 key pair auto-generated on first start, saved to data directory.

---

## API Endpoints

### Authentication

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/api/auth/login` | Username/password login (LDAP or local) |
| `POST` | `/api/auth/refresh` | Refresh access token |
| `GET` | `/api/auth/userinfo` | Get user info from current token |
| `GET` | `/api/auth/negotiate` | Kerberos/SPNEGO login (Windows SSO) |
| `GET` | `/.well-known/jwks.json` | Public keys for token validation |
| `GET` | `/health` | Health check |

#### `POST /api/auth/login`

Request:
```json
{
  "username": "jsmith",
  "password": "secret"
}
```

Response:
```json
{
  "access_token": "eyJ...",
  "refresh_token": "eyJ...",
  "expires_in": 28800,
  "token_type": "Bearer"
}
```

Auth flow:
1. If LDAP configured → try LDAP bind with credentials
2. If LDAP bind succeeds → pull display name, email, groups from AD
3. If LDAP bind fails or not configured → try local user password (bcrypt)
4. On success → ensure user exists in SQLite, load roles/permissions, issue JWT
5. On failure → 401

#### `GET /api/auth/negotiate`

Kerberos/SPNEGO flow (transparent Windows SSO):
1. Browser sends `Authorization: Negotiate <base64 token>`
2. Server validates Kerberos ticket using keytab
3. Extracts username from ticket
4. Looks up user in LDAP for groups/display name
5. Issues JWT same as login

If no Negotiate header → responds with `401` + `WWW-Authenticate: Negotiate`

Requires:
- `AUTH_KRB5_KEYTAB` env var pointing to a keytab file
- `AUTH_KRB5_REALM` env var (e.g., `CORP.LOCAL`)
- Service registered as SPN in AD

### Admin API

All admin endpoints require `Authorization: Bearer <admin-api-key>` header.
The admin API key is set via `AUTH_ADMIN_KEY` env var.

#### LDAP Configuration

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/admin/ldap` | Get current LDAP config |
| `PUT` | `/api/admin/ldap` | Update LDAP config |
| `DELETE` | `/api/admin/ldap` | Remove LDAP config (disable LDAP) |
| `POST` | `/api/admin/ldap/test` | Test LDAP connection |

`PUT /api/admin/ldap` body:
```json
{
  "url": "ldap://dc1.corp.local:389",
  "base_dn": "DC=corp,DC=local",
  "bind_dn": "CN=svc-auth,OU=Service Accounts,DC=corp,DC=local",
  "bind_password": "service-password",
  "user_filter": "(sAMAccountName={{username}})",
  "use_tls": false,
  "skip_tls_verify": false,
  "display_name_attr": "displayName",
  "email_attr": "mail",
  "groups_attr": "memberOf"
}
```

`POST /api/admin/ldap/test` — tries to bind with configured credentials, returns success/error.

#### User Management

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/admin/users` | List all users |
| `GET` | `/api/admin/users/:username` | Get single user |
| `POST` | `/api/admin/users` | Create local user |
| `PUT` | `/api/admin/users/:username` | Update user (display name, email) |
| `DELETE` | `/api/admin/users/:username` | Delete user |
| `PUT` | `/api/admin/users/:username/password` | Set local password |
| `PUT` | `/api/admin/users/:username/disabled` | Enable/disable user |

`POST /api/admin/users` body:
```json
{
  "username": "admin",
  "password": "changeme",
  "display_name": "Admin User",
  "email": "admin@company.com"
}
```

#### Roles & Permissions

| Method | Path | Description |
|--------|------|-------------|
| `PUT` | `/api/admin/users/:username/roles` | Set user roles |
| `PUT` | `/api/admin/users/:username/permissions` | Set user permissions |
| `GET` | `/api/admin/defaults/roles` | Get default roles for new users |
| `PUT` | `/api/admin/defaults/roles` | Set default roles for new users |

`PUT /api/admin/users/:username/roles` body:
```json
["admin", "user"]
```

`PUT /api/admin/users/:username/permissions` body:
```json
["can_view_profile_pictures", "can_export"]
```

Default roles are automatically assigned to users created via LDAP login (first auth).

---

## Storage

SQLite database at `{DATA_DIR}/auth.db`.

### Tables

```sql
-- Key-value config (LDAP settings, default roles)
config (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL DEFAULT ''
)

-- Users (LDAP users auto-created on first login, local users created via admin API)
users (
    username      TEXT PRIMARY KEY,
    password_hash TEXT NOT NULL DEFAULT '',  -- empty for LDAP-only users
    display_name  TEXT NOT NULL DEFAULT '',
    email         TEXT NOT NULL DEFAULT '',
    disabled      BOOLEAN NOT NULL DEFAULT FALSE,
    created_at    DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
)

-- User roles (arbitrary strings)
user_roles (
    username TEXT NOT NULL REFERENCES users(username) ON DELETE CASCADE,
    role     TEXT NOT NULL,
    PRIMARY KEY (username, role)
)

-- User permissions (arbitrary strings)
user_permissions (
    username   TEXT NOT NULL REFERENCES users(username) ON DELETE CASCADE,
    permission TEXT NOT NULL,
    PRIMARY KEY (username, permission)
)
```

### RSA Keys

RSA-2048 key pair stored at:
- `{DATA_DIR}/private.pem`
- `{DATA_DIR}/public.pem`

Auto-generated on first start if not present.

---

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `AUTH_PORT` | `9090` | Listen port |
| `AUTH_DATA_DIR` | `./data` | Directory for SQLite DB and RSA keys |
| `AUTH_ADMIN_KEY` | (required) | API key for admin endpoints |
| `AUTH_JWT_ISSUER` | `auth-server` | JWT `iss` claim |
| `AUTH_JWT_ACCESS_TTL` | `8h` | Access token lifetime |
| `AUTH_JWT_REFRESH_TTL` | `720h` | Refresh token lifetime (30 days) |
| `AUTH_KRB5_KEYTAB` | (optional) | Path to Kerberos keytab file |
| `AUTH_KRB5_REALM` | (optional) | Kerberos realm (e.g., `CORP.LOCAL`) |

---

## Project Structure

```
auth-server/
  main.go
  go.mod
  Dockerfile
  .env.example
  build.md
  internal/
    config/config.go       # Bootstrap config from env vars
    store/store.go         # SQLite store (all tables, CRUD)
    auth/
      jwt.go               # RSA key management, JWT sign/verify, JWKS
      ldap.go              # LDAP bind + attribute fetch
      local.go             # bcrypt password verification
      spnego.go            # Kerberos/SPNEGO (optional)
    handler/
      auth.go              # Login, refresh, userinfo, negotiate
      admin.go             # LDAP config, user/role/permission CRUD
      middleware.go        # Admin API key validation
```

---

## Docker

```dockerfile
FROM golang:1.24-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN go build -o /auth-server .

FROM alpine:3.21
RUN apk add --no-cache ca-certificates
COPY --from=build /auth-server /auth-server
EXPOSE 9090
VOLUME /data
ENV AUTH_DATA_DIR=/data
ENTRYPOINT ["/auth-server"]
```

---

## Integration with Consuming Apps

Apps validate JWTs by fetching the public key from `/.well-known/jwks.json`.

### Go middleware (3 lines of setup):
```go
// Fetch JWKS once at startup
jwks := auth.FetchJWKS("http://auth-server:9090/.well-known/jwks.json")

// Middleware: validate JWT on every request
e.Use(auth.JWTMiddleware(jwks))

// In handlers: check roles/permissions from JWT claims
if !auth.HasRole(c, "admin") {
    return c.JSON(403, "forbidden")
}
```

### Frontend integration:
```js
// Login
const res = await fetch("/auth/login", {
  method: "POST",
  body: JSON.stringify({ username, password })
});
const { access_token, refresh_token } = await res.json();
localStorage.setItem("token", access_token);

// API calls
fetch("/api/v1/conversations", {
  headers: { Authorization: `Bearer ${access_token}` }
});
```

No OIDC redirect, no keycloak-js library, no external dependencies.

---

## Bootstrap Flow

1. Start auth server with `AUTH_ADMIN_KEY=your-secret`
2. Server auto-generates RSA key pair, creates empty SQLite DB
3. From your app's admin page, call `PUT /api/admin/ldap` to configure AD
4. Call `POST /api/admin/ldap/test` to verify connectivity
5. Create an admin user: `POST /api/admin/users` + `PUT /api/admin/users/admin/roles` → `["admin"]`
6. Users can now login via `/api/auth/login`
7. LDAP users are auto-created in SQLite on first login with default roles

---

## Token Lifecycle

1. User authenticates → receives `access_token` (8h) + `refresh_token` (30d)
2. Frontend sends `access_token` on every API request
3. When access token expires, frontend calls `POST /api/auth/refresh` with refresh token
4. Server validates refresh token, issues new access token
5. If refresh token is expired → user must login again

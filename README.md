# SimpleAuth

Central identity hub for your organization. Single Go binary, embedded admin UI, BoltDB storage. Replaces Keycloak without the complexity.

Every user is a GUID. Every app maps its own identifiers to that GUID. LDAP/AD is just another identity provider.

## Features

- **GUID-based users** -- usernames, emails, and display names are just attributes. The GUID never changes.
- **Rich user profiles** -- name, email, department, company, job title synced from LDAP on each login
- **Multi-app support** -- each app gets its own API key, user mappings, roles, and permissions
- **Multi-LDAP/AD** -- connect multiple directories with priority-based failover
- **Auto-discovery** -- point at a domain, SimpleAuth figures out DCs, base DN, and filters
- **Provider mappings** -- apps define how to find users in each LDAP (`sAMAccountName`, `mail`, `telephoneNumber`, etc.)
- **Zero-import onboarding** -- users are auto-discovered and created on first login
- **Identity mappings** -- `(provider, external_id) -> GUID` across LDAP, apps, Kerberos, or any future provider
- **User merge/unmerge** -- consolidate duplicate accounts, all mappings follow
- **Kerberos/SPNEGO** -- transparent Windows SSO via keytab, with LDAP form fallback for non-domain machines
- **Hosted login page** -- redirect-based flow for apps that don't want to build their own login form
- **Impersonation** -- admins generate tokens as any user, fully audited
- **RS256 JWTs** -- auto-generated RSA-2048 keys, JWKS endpoint for token validation
- **Refresh token rotation** -- family-based replay detection with automatic revocation
- **Role & permission management** -- app-scoped, with configurable defaults for new users
- **Audit logging** -- every login, impersonation, role change, and key rotation is logged with configurable retention
- **Embedded admin UI** -- Preact SPA with dark mode, no build step required
- **Single binary** -- zero external dependencies, runs anywhere
- **Always HTTPS** -- auto-generates self-signed certificates, regenerates when hostname changes
- **YAML config file** -- with environment variable overrides
- **One-time tokens** -- scoped, single-use `XXX-XXXX` tokens (e.g. app self-registration without the admin key)
- **Backup/Restore** -- live BoltDB snapshots via API
- **AD setup script** -- auto-generated PowerShell script for service account provisioning and cleanup

## Quick Start

```bash
# Generate a default config file
./simpleauth init-config

# Edit the config
vim simpleauth.yaml   # set hostname and admin_key at minimum

# Run
./simpleauth
```

SimpleAuth always runs over HTTPS. If no TLS certificate is configured, a self-signed certificate is auto-generated. On first run it will:

1. Create the `data/` directory
2. Generate a self-signed TLS certificate (with your hostname in SANs)
3. Generate RSA-2048 keys for JWT signing
4. Start HTTPS on port 9090 and HTTP redirect on port 80

Open `https://<hostname>:9090` and sign in with your admin key.

## Build

```bash
# Build for current platform
go build -o simpleauth .

# Cross-compile for Linux (static binary, no CGO)
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -ldflags="-s -w" -trimpath -o simpleauth .

# Build for Windows
GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build -ldflags="-s -w" -trimpath -o simpleauth.exe .

# Build for all platforms
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
EXPOSE 9090 80
VOLUME /data
ENV AUTH_DATA_DIR=/data
ENTRYPOINT ["simpleauth"]
```

```bash
docker build -t simpleauth .
docker run -d -p 9090:9090 -p 80:80 \
  -e AUTH_ADMIN_KEY=changeme \
  -e AUTH_HOSTNAME=auth.corp.local \
  -v simpleauth-data:/data \
  simpleauth
```

## Configuration

SimpleAuth uses a YAML config file with environment variable overrides. Generate a default config:

```bash
./simpleauth init-config              # creates simpleauth.yaml
./simpleauth init-config /etc/simpleauth/config.yaml  # custom path
```

**Config file search order:**
1. `AUTH_CONFIG_FILE` environment variable
2. `simpleauth.yaml` or `simpleauth.yml` in current directory
3. `/etc/simpleauth/config.yaml` or `/etc/simpleauth/config.yml`

**Priority:** defaults < config file < environment variables (env always wins)

### Config Reference

```yaml
# The FQDN clients use to access SimpleAuth
# Used for TLS certificate SANs — should match the Kerberos SPN hostname
hostname: "auth.corp.local"

# HTTPS listen port
port: "9090"

# HTTP port for automatic redirect to HTTPS (empty string disables)
http_port: "80"

# Data directory for database, keytabs, and certificates
data_dir: "./data"

# Master admin API key (required)
admin_key: "your-secret-key"

# JWT settings
jwt_issuer: "simpleauth"
access_ttl: "8h"
refresh_ttl: "720h"         # 30 days
impersonate_ttl: "1h"

# TLS certificate paths (auto-generated self-signed if empty)
tls_cert: ""
tls_key: ""

# Kerberos (usually auto-configured via admin UI)
krb5_keytab: ""
krb5_realm: ""

# Audit log retention
audit_retention: "2160h"     # 90 days

# Rate limiting (per IP)
rate_limit_max: 10
rate_limit_window: "1m"

# CORS origins (comma-separated, or "*")
cors_origins: ""
```

### Environment Variables

Every config option has a corresponding environment variable:

| Variable | Config Key | Default | Description |
|----------|-----------|---------|-------------|
| `AUTH_HOSTNAME` | `hostname` | OS hostname | FQDN for TLS cert and access URLs |
| `AUTH_PORT` | `port` | `9090` | HTTPS listen port |
| `AUTH_HTTP_PORT` | `http_port` | `80` | HTTP redirect port (empty = disabled) |
| `AUTH_DATA_DIR` | `data_dir` | `./data` | Data directory |
| `AUTH_ADMIN_KEY` | `admin_key` | **(required)** | Master admin API key |
| `AUTH_JWT_ISSUER` | `jwt_issuer` | `simpleauth` | JWT `iss` claim |
| `AUTH_JWT_ACCESS_TTL` | `access_ttl` | `8h` | Access token lifetime |
| `AUTH_JWT_REFRESH_TTL` | `refresh_ttl` | `720h` | Refresh token lifetime |
| `AUTH_IMPERSONATE_TTL` | `impersonate_ttl` | `1h` | Impersonation token lifetime |
| `AUTH_TLS_CERT` | `tls_cert` | auto-generated | TLS certificate path |
| `AUTH_TLS_KEY` | `tls_key` | auto-generated | TLS private key path |
| `AUTH_KRB5_KEYTAB` | `krb5_keytab` | | Kerberos keytab path |
| `AUTH_KRB5_REALM` | `krb5_realm` | | Kerberos realm |
| `AUTH_AUDIT_RETENTION` | `audit_retention` | `2160h` | Audit log retention |
| `AUTH_RATE_LIMIT_MAX` | `rate_limit_max` | `10` | Max login attempts per window |
| `AUTH_RATE_LIMIT_WINDOW` | `rate_limit_window` | `1m` | Rate limit window |
| `AUTH_CORS_ORIGINS` | `cors_origins` | | CORS origins |

### TLS Certificates

SimpleAuth **always runs over HTTPS**. If no certificate is configured:

- A self-signed ECDSA (P-256) certificate is generated in `{data_dir}/tls.crt`
- The cert includes the configured hostname, OS hostname, `localhost`, and all local IPs as SANs
- Valid for 10 years
- Reused across restarts
- **Automatically regenerated** if the configured hostname changes

For production, provide your own certificate via `tls_cert`/`tls_key` (from your internal CA or Let's Encrypt).

## Active Directory Setup

SimpleAuth includes a PowerShell script generator to automate AD provisioning. From the admin UI:

1. Go to **LDAP Providers**
2. Click **AD Setup Script**
3. Enter the service account name and password
4. Download and run the script on a Domain Controller (or any machine with RSAT)

The script will:
- Create the service account in a selected OU
- Register the `HTTP/<hostname>` SPN for Kerberos
- Export a `simpleauth-config.json` file

Back in the admin UI, click **Import Config** and upload the JSON file. SimpleAuth will configure the LDAP provider and auto-generate the Kerberos keytab.

### Re-running the Script

If the service account already exists, the script presents an interactive menu:
1. **Re-run setup** — update password, manage SPNs, re-export config
2. **Remove everything** — remove SPNs, delete or disable the account, clean up config
3. **Exit**

### Kerberos/SPNEGO

Once configured, Kerberos SSO works automatically for domain-joined machines:

1. User accesses SimpleAuth via the FQDN matching the SPN (e.g. `https://auth.corp.local:9090`)
2. Browser sends a Kerberos ticket via SPNEGO
3. SimpleAuth validates the ticket with the keytab
4. User is authenticated and gets JWT tokens

**If Kerberos fails** (non-domain machine, Linux without `kinit`, NTLM fallback), a login form is shown automatically. Users can sign in with their AD credentials via LDAP bind.

**Test page:** `https://<hostname>:9090/auth/test-negotiate` — tests Kerberos SSO and shows the authenticated user's full profile (name, email, department, company, job title, groups, which LDAP provider matched).

**Requirements for Kerberos:**
- The SPN `HTTP/<fqdn>` must be registered on the service account (`setspn -L <account>` to verify)
- The browser URL hostname must match the SPN exactly (port doesn't matter)
- Chrome/Edge may need the site in `AuthServerAllowlist` policy or intranet zone
- The self-signed cert or a trusted cert must be used (HTTPS required)

## API Reference

### Authentication

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/api/auth/login` | Authenticate user, get tokens |
| `POST` | `/api/auth/refresh` | Rotate refresh token, get new access token |
| `GET` | `/api/auth/userinfo` | Get current user info from JWT |
| `POST` | `/api/auth/reset-password` | Change password (authenticated) |
| `GET` | `/api/auth/negotiate` | Kerberos/SPNEGO login |
| `POST` | `/api/auth/impersonate` | Generate token as another user (admin only) |
| `GET` | `/login` | Hosted login page (redirect-based flow) |
| `GET` | `/auth/test-negotiate` | Kerberos/SPNEGO test page with LDAP fallback |
| `GET` | `/.well-known/jwks.json` | JWKS public keys |
| `GET` | `/health` | Health check |
| `POST` | `/api/register` | Self-register app with one-time token |

### Login

```bash
curl -X POST https://auth.corp.local:9090/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username": "jsmith", "password": "secret", "app_id": "my-app"}'
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
https://auth.corp.local:9090/login?app_id=my-app&redirect_uri=https://myapp.com/callback
```

On success, redirects back with tokens in the URL fragment:
```
https://myapp.com/callback#access_token=eyJ...&refresh_token=eyJ...&expires_in=28800&token_type=Bearer
```

### JWT Claims

```json
{
  "sub": "a1b2c3d4-5678-90ab-cdef-1234567890ab",
  "name": "John Smith",
  "email": "jsmith@corp.local",
  "department": "Engineering",
  "company": "Acme Corp",
  "job_title": "Software Engineer",
  "app_id": "my-app",
  "roles": ["admin", "editor"],
  "permissions": ["read", "write", "delete"],
  "groups": ["Domain Users", "IT Department"],
  "iss": "simpleauth",
  "exp": 1741528800
}
```

### App Self-Registration

Admins create scoped one-time tokens (in `XXX-XXXX` format) via the admin UI or API:

```bash
# Admin creates a token
curl -X POST https://auth.corp.local:9090/api/admin/tokens \
  -H "Authorization: Bearer $ADMIN_KEY" \
  -H "Content-Type: application/json" \
  -d '{"scope": "app-registration", "label": "For chat-app team", "ttl": "24h"}'
# Returns: {"token": "AB3-K9MX", "scope": "app-registration", ...}

# App team uses the token to self-register
curl -X POST https://auth.corp.local:9090/api/register \
  -H "Content-Type: application/json" \
  -d '{"token": "AB3-K9MX", "name": "Chat App"}'
# Returns: {"app_id": "app-xxxx", "name": "Chat App", "api_key": "sk-..."}
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
| `PUT` | `/api/admin/users/:guid` | Update user (name, email, department, company, job title) |
| `DELETE` | `/api/admin/users/:guid` | Delete user |
| `POST` | `/api/admin/users/merge` | Merge duplicate users |
| `POST` | `/api/admin/users/:guid/unmerge` | Undo merge |
| `PUT` | `/api/admin/users/:guid/password` | Set user password (admin) |
| `PUT` | `/api/admin/users/:guid/disabled` | Enable/disable user |
| `GET` | `/api/admin/users/:guid/sessions` | List active sessions |
| `DELETE` | `/api/admin/users/:guid/sessions` | Revoke all sessions |

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
| `GET` | `/api/admin/apps/:app/users` | List users with roles in app |
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
| `POST` | `/api/admin/ldap/import` | Import configs (with auto Kerberos setup) |

#### Kerberos

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/admin/kerberos/status` | Get Kerberos configuration status |
| `POST` | `/api/admin/ldap/:id/setup-kerberos` | Generate keytab and register SPN |
| `POST` | `/api/admin/ldap/:id/cleanup-kerberos` | Remove keytab and optionally unregister SPN |

#### One-Time Tokens

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/admin/tokens` | List tokens (optional `?scope=` filter) |
| `POST` | `/api/admin/tokens` | Create token (scope, label, ttl) |
| `DELETE` | `/api/admin/tokens/:token` | Delete token |

#### Operations

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/admin/backup` | Download BoltDB snapshot |
| `POST` | `/api/admin/restore` | Upload and restore backup |
| `GET` | `/api/admin/audit` | Query audit log (with filters) |

## Architecture

```
simpleauth
├── main.go                        # Entry point, embeds UI, HTTPS + HTTP redirect
├── simpleauth.yaml                # Config file (generated with init-config)
├── internal/
│   ├── config/config.go           # YAML + env config, auto TLS cert generation
│   ├── store/store.go             # BoltDB storage layer (12 buckets)
│   ├── auth/
│   │   ├── jwt.go                 # RSA key management, JWT signing/validation, JWKS
│   │   ├── ldap.go                # LDAP search, bind, group extraction, user attributes
│   │   └── local.go               # bcrypt password hashing
│   └── handler/
│       ├── handler.go             # Route registration, CORS, helpers
│       ├── auth.go                # Login, refresh, negotiate, impersonate, test page
│       ├── hosted_login.go        # Hosted login page (redirect flow)
│       ├── admin.go               # App/user CRUD, backup/restore, audit
│       ├── admin_ldap.go          # LDAP provider management, import/export, auto-discover
│       ├── admin_kerberos.go      # Kerberos setup, keytab generation, SPN management
│       └── middleware.go          # Admin auth, rate limiting
└── ui/dist/                       # Embedded Preact admin UI
    ├── index.html
    ├── app.js                     # SPA with 7 pages: Dashboard, Users, Apps, LDAP, Mappings, Impersonate, Audit
    ├── style.css
    └── vendor/                    # Preact, htm (offline, no CDN)
```

## How Auth Resolution Works

When a user logs in with `app_id`:

1. Check existing mapping `(app:<app_id>, username) -> GUID`
2. If no mapping, search LDAP using the app's `provider_mappings` config
3. If LDAP finds a match, create/reuse GUID and auto-create mappings
4. Authenticate via LDAP bind or local password
5. Sync user profile from LDAP (name, email, department, company, job title)
6. Load app-scoped roles/permissions, issue JWT with all claims

This means a new app can be added and users start logging in immediately -- no import, no sync, no migration.

## LDAP User Attributes

SimpleAuth syncs the following attributes from LDAP on each login:

| SimpleAuth Field | Default LDAP Attribute | Configurable |
|-----------------|----------------------|--------------|
| Display Name | `displayName` | `display_name_attr` |
| Email | `mail` | `email_attr` |
| Department | `department` | `department_attr` |
| Company | `company` | `company_attr` |
| Job Title | `title` | `job_title_attr` |
| Groups | `memberOf` | `groups_attr` |

These are stored on the user record and included in JWT claims. Changes in AD are automatically synced on next login.

## License

MIT

# SimpleAuth — Build Spec

Central identity hub for your organization. Single Go binary. Replaces Keycloak.
Every user is a GUID. Every app maps its own identifiers to that GUID. LDAP/AD is just another identity provider.

---

## Overview

Single Go binary with embedded admin UI. Runs as a Docker container. No external dependencies except an optional AD/LDAP server.

- **Users are GUIDs** — username, email, display name are just attributes
- **Apps are registered** — each app gets an API key and can map its own usernames to user GUIDs
- **LDAP/AD is a provider** — maps LDAP usernames to GUIDs, authenticates via bind
- **Identity mappings** — any provider (LDAP, app, future SAML/OAuth) maps external IDs to user GUIDs
- Issues signed JWTs with GUID as `sub`, plus roles, permissions, and AD groups
- Exposes JWKS endpoint so any app can validate tokens
- **Impersonation** — admins can generate tokens as any user (audited)
- **Embedded admin UI** — manage everything from the browser, no separate frontend
- BoltDB storage (single file, no database service needed)
- Recommended: run behind nginx for TLS termination

---

## Tech Stack

- Go (stdlib `net/http` for HTTP)
- Go `embed` package for bundling the admin UI
- BoltDB via `go.etcd.io/bbolt` (pure Go, embedded key-value store)
- `github.com/go-ldap/ldap/v3` — LDAP authentication
- `github.com/golang-jwt/jwt/v5` — JWT signing/verification
- `github.com/jcmturner/gokrb5/v8` — Kerberos/SPNEGO
- `golang.org/x/crypto/bcrypt` — local password hashing
- Frontend: Preact + Tailwind CSS (compiled to static files, embedded in binary)

---

## Core Concepts

### Users (GUIDs)

Every user in SimpleAuth is identified by a UUID. That's it. The GUID never changes regardless of username changes, email changes, or provider changes.

### Apps

Apps are registered consumers of SimpleAuth. Each app:
- Has a unique `app_id` and `name`
- Gets its own API key for calling SimpleAuth APIs
- Can register its own user mappings (app-specific usernames → GUIDs)

### Identity Providers

LDAP/AD is just one type of provider. A provider:
- Maps an external identifier to a user GUID
- May or may not support authentication (LDAP does, app mappings don't)

### Identity Mappings

The link between external identifiers and user GUIDs:
- `(provider, external_id) → user_guid`
- LDAP provider: `(ldap, "kalahmad") → abc-123`
- App provider: `(app:chat-app, "khalefa") → abc-123`
- Another app: `(app:hr-portal, "+971501234567") → abc-123`

All collapse to the same GUID.

---

## JWT Claims

```json
{
  "sub": "a1b2c3d4-5678-90ab-cdef-1234567890ab",
  "name": "Khalefa Ahmad",
  "email": "kalahmad@corp.local",
  "app_id": "chat-app",
  "roles": ["admin", "moderator"],
  "permissions": ["can_delete_messages", "can_ban_users"],
  "groups": ["Domain Users", "IT Department"],
  "iss": "simpleauth",
  "iat": 1741500000,
  "exp": 1741528800
}
```

Impersonated tokens include extra claims:
```json
{
  "sub": "a1b2c3d4-...",
  "impersonated": true,
  "impersonated_by": "d4c3b2a1-...",
  "...": "..."
}
```

| Field | Source |
|-------|--------|
| `sub` | User GUID (UUID) |
| `name` | LDAP `displayName` attr or local user display name |
| `email` | LDAP `mail` attr or local user email |
| `app_id` | The app the user authenticated for (from login request) |
| `roles` | App-scoped roles for this user in this app |
| `permissions` | App-scoped permissions for this user in this app |
| `groups` | Pulled from AD `memberOf` attribute during LDAP auth |
| `impersonated` | `true` if token was issued via impersonation |
| `impersonated_by` | GUID of the admin who impersonated |

Signed with RS256. RSA-2048 key pair auto-generated on first start, saved to data directory.

---

## API Endpoints

### Authentication

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/api/auth/login` | Login (resolves app mapping → authenticates via provider) |
| `POST` | `/api/auth/refresh` | Refresh access token |
| `GET` | `/api/auth/userinfo` | Get user info from current token |
| `GET` | `/api/auth/negotiate` | Kerberos/SPNEGO login (Windows SSO) |
| `POST` | `/api/auth/impersonate` | Impersonate a user (admin only) |
| `GET` | `/login` | Hosted login page (redirect-based flow for apps) |
| `GET` | `/.well-known/jwks.json` | Public keys for token validation |
| `GET` | `/health` | Health check |

#### `POST /api/auth/login`

Request:
```json
{
  "username": "khalefa",
  "password": "secret",
  "app_id": "chat-app"
}
```

`app_id` is optional. If provided, SimpleAuth resolves the app-specific username to a GUID first.

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
1. If `app_id` provided:
   a. Check if user already has an identity mapping `(app:<app_id>, username) → GUID` — if yes, use that GUID
   b. If no existing mapping, check app's `provider_mappings` — search each configured LDAP provider using the mapped field (e.g., search `(telephoneNumber=+971501234567)` in `ldap:corp`)
   c. If LDAP search finds a match → check if that LDAP user already has a GUID in SimpleAuth → if yes, reuse it; if no, create new GUID
   d. Auto-create identity mappings: `(ldap:<provider>, ldap_username)` and `(app:<app_id>, username)` → GUID
2. If no `app_id` → treat username as LDAP username directly (default field: `sAMAccountName`)
3. If LDAP configured → try LDAP bind with resolved LDAP username + password
4. If LDAP bind succeeds → pull display name, email, groups from AD
5. If LDAP bind fails or not configured → try local user password (bcrypt)
6. On success → load app-scoped roles/permissions, issue JWT with GUID as `sub`
7. On failure → 401

#### `POST /api/auth/impersonate`

Request (requires admin API key or user with `can_impersonate` permission):
```json
{
  "target_guid": "a1b2c3d4-5678-90ab-cdef-1234567890ab"
}
```

Response: same as login, but JWT includes `impersonated: true` and `impersonated_by` claims. Shorter TTL (1h default).

#### `GET /login` (Hosted Login Page)

Redirect-based login flow for apps that don't want to build their own login form.

**Redirect to SimpleAuth:**
```
https://auth.corp.local/login?app_id=chat-app&redirect_uri=https://chat.corp.local/callback
```

Flow:
1. App redirects user to SimpleAuth's `/login` page with `app_id` and `redirect_uri`
2. SimpleAuth shows the login form
3. User enters credentials
4. SimpleAuth authenticates (same flow as `/api/auth/login`)
5. On success → redirects back to the app:
   ```
   https://chat.corp.local/callback#access_token=eyJ...&refresh_token=eyJ...&expires_in=28800&token_type=Bearer
   ```
6. On failure → shows error on the login page, user can retry

Security:
- `redirect_uri` must match one of the app's registered allowed redirect URIs
- If `redirect_uri` doesn't match → reject with error
- Tokens passed in URL fragment (`#`) not query params (`?`) so they don't hit server logs

This means apps have **two choices** for login:
1. **API-based** — build your own login form, call `POST /api/auth/login` from your backend
2. **Redirect-based** — redirect to SimpleAuth's hosted login page, get tokens back via redirect

#### `GET /api/auth/negotiate`

Kerberos/SPNEGO flow (transparent Windows SSO):
1. Browser sends `Authorization: Negotiate <base64 token>`
2. Server validates Kerberos ticket using keytab
3. Extracts username from ticket
4. Resolves to user GUID (auto-creates if new)
5. Looks up user in LDAP for groups/display name
6. Issues JWT with GUID as `sub`

If no Negotiate header → responds with `401` + `WWW-Authenticate: Negotiate`

Requires:
- `AUTH_KRB5_KEYTAB` env var pointing to a keytab file
- `AUTH_KRB5_REALM` env var (e.g., `CORP.LOCAL`)
- Service registered as SPN in AD

### Admin API

All admin endpoints require `Authorization: Bearer <api-key>` header.
The master admin key is set via `AUTH_ADMIN_KEY` env var. Registered apps use their own API keys.

#### App Management

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/admin/apps` | List all registered apps |
| `GET` | `/api/admin/apps/:app_id` | Get single app |
| `POST` | `/api/admin/apps` | Register a new app |
| `PUT` | `/api/admin/apps/:app_id` | Update app (name, permissions) |
| `DELETE` | `/api/admin/apps/:app_id` | Remove app |
| `POST` | `/api/admin/apps/:app_id/rotate-key` | Rotate app API key |

`POST /api/admin/apps` body:
```json
{
  "name": "chat-app",
  "description": "Internal chat application",
  "redirect_uris": ["https://chat.corp.local/callback", "http://localhost:3000/callback"],
  "provider_mappings": {
    "ldap:corp": { "field": "sAMAccountName" },
    "ldap:partner": { "field": "mail" }
  }
}
```

`provider_mappings` tells SimpleAuth how to find users in each LDAP provider based on the app's username. When a user logs in with `app_id=chat-app`, SimpleAuth searches LDAP using the specified field to match the provided username. This means **no bulk user import is needed** — users are auto-discovered and created on first login.

If `provider_mappings` is not set, the app must manage its own identity mappings manually via the mappings API.

Response:
```json
{
  "app_id": "app-a1b2c3",
  "name": "chat-app",
  "api_key": "sk-xxxxxxxxxxxx"
}
```

#### LDAP Providers

Multiple LDAP/AD directories can be configured. Each gets a unique provider ID (e.g., `corp`, `partner`). Identity mappings reference them as `ldap:corp`, `ldap:partner`, etc.

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/admin/ldap` | List all LDAP providers |
| `GET` | `/api/admin/ldap/:provider_id` | Get single LDAP provider config |
| `POST` | `/api/admin/ldap` | Add a new LDAP provider |
| `PUT` | `/api/admin/ldap/:provider_id` | Update LDAP provider config |
| `DELETE` | `/api/admin/ldap/:provider_id` | Remove LDAP provider |
| `POST` | `/api/admin/ldap/:provider_id/test` | Test LDAP provider connection |
| `GET` | `/api/admin/ldap/export` | Export all LDAP provider configs as JSON |
| `POST` | `/api/admin/ldap/import` | Import LDAP provider configs from JSON |
| `POST` | `/api/admin/ldap/auto-discover` | Auto-configure LDAP from domain + service account |
| `POST` | `/api/admin/ldap/setup-kerberos` | One-time Kerberos/SPNEGO setup using privileged creds |

`POST /api/admin/ldap` body:
```json
{
  "provider_id": "corp",
  "name": "Corporate AD",
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

`GET /api/admin/ldap/export` response:
```json
{
  "ldap_providers": [
    {
      "provider_id": "corp",
      "name": "Corporate AD",
      "url": "ldap://dc1.corp.local:389",
      "base_dn": "DC=corp,DC=local",
      "bind_dn": "CN=svc-auth,OU=Service Accounts,DC=corp,DC=local",
      "bind_password": "service-password",
      "user_filter": "(sAMAccountName={{username}})",
      "use_tls": false,
      "skip_tls_verify": false,
      "display_name_attr": "displayName",
      "email_attr": "mail",
      "groups_attr": "memberOf",
      "priority": 0
    }
  ]
}
```

`POST /api/admin/ldap/import` — accepts the same JSON format. Upserts providers (creates new, updates existing by `provider_id`).

Note: Export/import covers LDAP connection config only. Kerberos keytab is a file managed at the instance level (`AUTH_KRB5_KEYTAB` env var) — Kerberos/SPNEGO won't work on a new instance until the keytab file is also deployed there separately.

#### `POST /api/admin/ldap/auto-discover`

Auto-configure an LDAP provider from just a domain name and service account credentials. No need to manually figure out DCs, base DN, or ports.

Request:
```json
{
  "domain": "corp.local",
  "bind_dn": "CN=svc-auth,OU=Service Accounts,DC=corp,DC=local",
  "bind_password": "service-password",
  "provider_id": "corp"
}
```

`provider_id` is optional — defaults to the domain name with dots replaced by dashes (e.g., `corp-local`).

Auto-discovery flow:
1. DNS SRV lookup for `_ldap._tcp.corp.local` → get DC hostnames + ports
2. Connect to the first reachable DC
3. Query RootDSE → extract `defaultNamingContext` (base DN), supported controls, forest info
4. Set sensible defaults: `user_filter=(sAMAccountName={{username}})`, `display_name_attr=displayName`, `email_attr=mail`, `groups_attr=memberOf`
5. Test bind with provided credentials to verify connectivity
6. Return the fully populated LDAP provider config (not yet saved)

Response:
```json
{
  "provider_id": "corp",
  "name": "corp.local (auto-discovered)",
  "url": "ldap://dc1.corp.local:389",
  "base_dn": "DC=corp,DC=local",
  "bind_dn": "CN=svc-auth,OU=Service Accounts,DC=corp,DC=local",
  "bind_password": "service-password",
  "user_filter": "(sAMAccountName={{username}})",
  "use_tls": false,
  "display_name_attr": "displayName",
  "email_attr": "mail",
  "groups_attr": "memberOf",
  "discovered_dcs": ["dc1.corp.local:389", "dc2.corp.local:389"],
  "saved": false
}
```

The response includes `"saved": false` — the caller can review and then `POST /api/admin/ldap` to save it, or pass `"save": true` in the request to auto-save.

#### `POST /api/admin/ldap/setup-kerberos`

One-time Kerberos/SPNEGO setup. Uses privileged AD credentials to create the service principal and generate a keytab — then **wipes the privileged credentials from memory**.

Request:
```json
{
  "domain": "corp.local",
  "domain_admin_dn": "CN=Administrator,CN=Users,DC=corp,DC=local",
  "domain_admin_password": "admin-password",
  "service_hostname": "auth.corp.local"
}
```

Setup flow:
1. Connect to AD using the privileged domain admin credentials
2. Create (or find existing) service account for SimpleAuth
3. Register SPN `HTTP/auth.corp.local` on the service account
4. Generate keytab for the SPN
5. Save keytab to `{DATA_DIR}/krb5.keytab`
6. Set `AUTH_KRB5_KEYTAB` and `AUTH_KRB5_REALM` internally (runtime config)
7. **Wipe domain admin credentials from memory** — they are never stored
8. Test: attempt a Kerberos handshake to verify the keytab works

Response:
```json
{
  "status": "ok",
  "realm": "CORP.LOCAL",
  "spn": "HTTP/auth.corp.local",
  "keytab_path": "/data/krb5.keytab",
  "message": "Kerberos configured. Domain admin credentials have been wiped."
}
```

**Security notes:**
- Domain admin credentials exist only for the duration of this API call
- They are never written to disk, never logged, never stored in the database
- After setup, only the keytab file is retained — it contains only the service account key, not admin credentials
- This endpoint should only be called once during initial setup
- If the keytab needs to be regenerated, call this endpoint again

Auth flow with multiple LDAP providers:
1. Login request comes in → resolve to user GUID
2. Find all `ldap:*` mappings for that GUID
3. Try authenticating against each mapped LDAP provider until one succeeds
4. If no GUID yet (new user with no `app_id`) → try each LDAP provider in order until one succeeds, then auto-create user + mapping

#### User Management

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/admin/users` | List all users |
| `GET` | `/api/admin/users/:guid` | Get single user |
| `POST` | `/api/admin/users` | Create local user (auto-generates GUID) |
| `PUT` | `/api/admin/users/:guid` | Update user (display name, email) |
| `DELETE` | `/api/admin/users/:guid` | Delete user |
| `PUT` | `/api/admin/users/:guid/password` | Set local password |
| `PUT` | `/api/admin/users/:guid/disabled` | Enable/disable user |

`POST /api/admin/users` body:
```json
{
  "username": "admin",
  "password": "changeme",
  "display_name": "Admin User",
  "email": "admin@company.com"
}
```

Response includes the generated GUID.

#### Identity Mappings

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/admin/users/:guid/mappings` | List all mappings for a user |
| `PUT` | `/api/admin/users/:guid/mappings` | Add/update a mapping |
| `DELETE` | `/api/admin/users/:guid/mappings/:provider/:external_id` | Remove a mapping |
| `GET` | `/api/admin/mappings/resolve` | Resolve an external ID to a GUID |

`PUT /api/admin/users/:guid/mappings` body:
```json
{
  "provider": "app:chat-app",
  "external_id": "khalefa"
}
```

`GET /api/admin/mappings/resolve?provider=app:chat-app&external_id=khalefa` → returns GUID.

#### Roles & Permissions (App-Scoped)

Roles and permissions are scoped per app. A user can be `admin` in chat-app but `viewer` in hr-portal.

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/admin/apps/:app_id/users` | List users with roles in this app |
| `GET` | `/api/admin/apps/:app_id/users/:guid/roles` | Get user's roles in this app |
| `PUT` | `/api/admin/apps/:app_id/users/:guid/roles` | Set user's roles in this app |
| `GET` | `/api/admin/apps/:app_id/users/:guid/permissions` | Get user's permissions in this app |
| `PUT` | `/api/admin/apps/:app_id/users/:guid/permissions` | Set user's permissions in this app |
| `GET` | `/api/admin/apps/:app_id/defaults/roles` | Get default roles for new users in this app |
| `PUT` | `/api/admin/apps/:app_id/defaults/roles` | Set default roles for new users in this app |

`PUT /api/admin/apps/chat-app/users/:guid/roles` body:
```json
["admin", "moderator"]
```

`PUT /api/admin/apps/chat-app/users/:guid/permissions` body:
```json
["can_delete_messages", "can_ban_users"]
```

Default roles are per-app and automatically assigned to users on first login to that app.

**Authorization scoping:** App API keys can only manage roles/permissions within their own app. Master admin key (`AUTH_ADMIN_KEY`) can manage any app.

#### User Merge

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/api/admin/users/merge` | Merge two users into a new one |
| `POST` | `/api/admin/users/:guid/unmerge` | Undo a merge (restore original user) |

`POST /api/admin/users/merge` body:
```json
{
  "source_guids": ["guid-A", "guid-B"],
  "display_name": "Khalefa Ahmad",
  "email": "kalahmad@corp.local"
}
```

Response:
```json
{
  "merged_guid": "guid-C",
  "sources": ["guid-A", "guid-B"]
}
```

Merge flow:
1. Create new user `guid-C` with provided display name/email
2. Move all identity mappings from `guid-A` and `guid-B` → `guid-C`
3. Merge roles and permissions (union of both) → `guid-C`
4. Mark `guid-A` and `guid-B` as `merged_into = guid-C`
5. All future JWTs use `guid-C` as `sub`
6. Any API call or login that resolves to `guid-A` or `guid-B` transparently follows `merged_into` → returns `guid-C`'s data

Un-merge flow (`POST /api/admin/users/:guid/unmerge`):
1. Restore original user record (clears `merged_into`)
2. Move back identity mappings that originally belonged to this user
3. The user becomes active again with its original GUID

Apps that stored the old GUIDs never need to update — SimpleAuth resolves merged GUIDs transparently on every lookup.

#### Backup & Restore

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/admin/backup` | Download a consistent snapshot of the entire DB |
| `POST` | `/api/admin/restore` | Upload a DB snapshot to replace current data |

`GET /api/admin/backup` — streams the BoltDB file as a binary download. Uses BoltDB's built-in consistent read snapshot, so it works while the server is running with zero downtime. Returns `Content-Disposition: attachment; filename="auth-backup-2026-03-09.db"`.

`POST /api/admin/restore` — accepts a BoltDB file upload. Validates the file, swaps the current DB, and reloads. This is a destructive operation — the current data is replaced entirely.

For simple backup, you can also just copy `{DATA_DIR}/auth.db` while the server is stopped.

---

## Storage

BoltDB database at `{DATA_DIR}/auth.db`. Single file, memory-mapped, pure Go.

Optimized for orgs up to 10K users. All lookups are key-based — no SQL, no query engine, just fast reads from a B+ tree.

### Buckets

```
config                          # Key-value config
  key → value (string)
  e.g. "app:chat-app:default_roles" → '["user"]'

ldap_providers                  # LDAP provider configs
  {provider_id} → JSON {
    provider_id, name, url, base_dn, bind_dn, bind_password,
    user_filter, use_tls, skip_tls_verify,
    display_name_attr, email_attr, groups_attr,
    priority, created_at
  }

apps                            # Registered apps
  {app_id} → JSON {
    app_id, name, description, api_key,
    redirect_uris, provider_mappings, created_at
  }

users                           # Users by GUID
  {guid} → JSON {
    guid, password_hash, display_name, email,
    disabled, merged_into, created_at
  }

identity_mappings               # External ID → user GUID
  {provider}:{external_id} → {guid}
  e.g. "ldap:corp:kalahmad" → "a1b2c3d4-..."
       "app:chat-app:khalefa" → "a1b2c3d4-..."
       "app:hr-portal:+971501234567" → "a1b2c3d4-..."

user_roles                      # App-scoped roles
  {guid}:{app_id} → JSON ["admin", "moderator"]

user_permissions                # App-scoped permissions
  {guid}:{app_id} → JSON ["can_delete_messages", "can_ban_users"]

refresh_tokens                  # Refresh token tracking (rotation + family revocation)
  {token_id} → JSON {
    token_id, family_id, user_guid, app_id,
    used, expires_at, created_at
  }

audit_log                       # Append-only security event log
  {timestamp}:{event_id} → JSON {
    id, timestamp, event, actor, ip, data
  }
```

### Reverse Indexes

For lookups that go the "wrong direction" (e.g., find all mappings for a GUID):

```
idx_mappings_by_guid            # GUID → list of mappings
  {guid} → JSON [{"provider":"ldap:corp","external_id":"kalahmad"}, ...]

idx_apps_by_api_key             # API key → app_id (for auth middleware)
  {api_key} → {app_id}
```

These are maintained on write — when a mapping is created, both `identity_mappings` and `idx_mappings_by_guid` are updated in the same BoltDB transaction (atomic).

### RSA Keys

RSA-2048 key pair stored at:
- `{DATA_DIR}/private.pem`
- `{DATA_DIR}/public.pem`

Auto-generated on first start if not present.

---

## Admin UI (Embedded)

Single-page app embedded in the Go binary via `go:embed`. Served at `/` (root).

### Pages

- **Dashboard** — overview: user count, app count, recent logins
- **Users** — list/search users, view GUID, edit profile, manage roles/permissions, view all identity mappings
- **Apps** — register/manage apps, rotate API keys, view app-specific user mappings
- **LDAP Providers** — add/configure multiple AD/LDAP directories, test connectivity, set priority
- **Identity Mappings** — browse/search all mappings across providers
- **Impersonation** — select a user, generate impersonated token
- **Login Page** — clean login form that apps can redirect to (supports `app_id` + `redirect_uri` query params)

### Tech

- Preact + Tailwind CSS
- Built to static files at build time
- Embedded into Go binary via `//go:embed ui/dist/*`
- Served by the same HTTP server on the same port
- API calls go to `/api/*`, UI serves from `/`

---

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `AUTH_PORT` | `9090` | Listen port |
| `AUTH_DATA_DIR` | `./data` | Directory for BoltDB file and RSA keys |
| `AUTH_ADMIN_KEY` | (required) | Master API key for admin endpoints |
| `AUTH_JWT_ISSUER` | `simpleauth` | JWT `iss` claim |
| `AUTH_JWT_ACCESS_TTL` | `8h` | Access token lifetime |
| `AUTH_JWT_REFRESH_TTL` | `720h` | Refresh token lifetime (30 days) |
| `AUTH_IMPERSONATE_TTL` | `1h` | Impersonated token lifetime |
| `AUTH_KRB5_KEYTAB` | (optional) | Path to Kerberos keytab file |
| `AUTH_KRB5_REALM` | (optional) | Kerberos realm (e.g., `CORP.LOCAL`) |
| `AUTH_TLS_CERT` | (optional) | Path to TLS certificate (if not using nginx) |
| `AUTH_TLS_KEY` | (optional) | Path to TLS private key (if not using nginx) |
| `AUTH_AUDIT_RETENTION` | `90d` | How long to keep audit log entries |

---

## Project Structure

```
simpleauth/
  main.go
  go.mod
  Dockerfile
  .env.example
  build.md
  ui/                          # Frontend source
    src/
      index.html
      app.jsx
      pages/
        Dashboard.jsx
        Users.jsx
        Apps.jsx
        LdapProviders.jsx
        Mappings.jsx
        Impersonate.jsx
        Login.jsx
      components/
        Layout.jsx
        Table.jsx
        Modal.jsx
    tailwind.config.js
    package.json
    dist/                      # Built static files (embedded)
  internal/
    config/config.go           # Bootstrap config from env vars
    store/store.go             # BoltDB store (all buckets, CRUD)
    auth/
      jwt.go                   # RSA key management, JWT sign/verify, JWKS
      ldap.go                  # LDAP bind + attribute fetch
      local.go                 # bcrypt password verification
      spnego.go                # Kerberos/SPNEGO (optional)
    handler/
      auth.go                  # Login, refresh, userinfo, negotiate, impersonate
      admin.go                 # App/user/mapping/role/permission CRUD
      admin_ldap.go            # LDAP provider CRUD endpoints
      middleware.go            # API key validation, admin auth
      ui.go                    # Serve embedded UI files
```

---

## Docker

```dockerfile
FROM node:22-alpine AS ui-build
WORKDIR /ui
COPY ui/package.json ui/package-lock.json ./
RUN npm ci
COPY ui/ .
RUN npm run build

FROM golang:1.24-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
COPY --from=ui-build /ui/dist ./ui/dist
RUN go build -o /simpleauth .

FROM alpine:3.21
RUN apk add --no-cache ca-certificates
COPY --from=build /simpleauth /simpleauth
EXPOSE 9090
VOLUME /data
ENV AUTH_DATA_DIR=/data
ENTRYPOINT ["/simpleauth"]
```

---

## Deployment Recommendation

Run behind nginx for TLS termination:

```nginx
server {
    listen 443 ssl;
    server_name auth.corp.local;

    ssl_certificate     /etc/ssl/certs/auth.pem;
    ssl_certificate_key /etc/ssl/private/auth.key;

    location / {
        proxy_pass http://127.0.0.1:9090;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

SimpleAuth can also serve TLS directly via `AUTH_TLS_CERT` and `AUTH_TLS_KEY` for simpler setups.

---

## Integration with Consuming Apps

Apps validate JWTs by fetching the public key from `/.well-known/jwks.json`.
Users are always identified by GUID (`sub` claim).

### Go middleware:
```go
// Fetch JWKS once at startup
jwks := auth.FetchJWKS("http://simpleauth:9090/.well-known/jwks.json")

// Middleware: validate JWT on every request
e.Use(auth.JWTMiddleware(jwks))

// In handlers: user GUID from JWT
userGUID := auth.GetUserGUID(c)  // "a1b2c3d4-5678-..."

// Check roles/permissions
if !auth.HasRole(c, "admin") {
    return c.JSON(403, "forbidden")
}
```

### Frontend integration:
```js
// Login (with app-specific username)
const res = await fetch("/api/auth/login", {
  method: "POST",
  headers: { "Content-Type": "application/json" },
  body: JSON.stringify({ username: "khalefa", password: "secret", app_id: "chat-app" })
});
const { access_token, refresh_token } = await res.json();
localStorage.setItem("token", access_token);

// API calls — user is identified by GUID in the token
fetch("/api/v1/conversations", {
  headers: { Authorization: `Bearer ${access_token}` }
});
```

No OIDC redirect, no keycloak-js library, no external dependencies.

---

## Bootstrap Flow

1. Start SimpleAuth with `AUTH_ADMIN_KEY=your-secret`
2. Server auto-generates RSA key pair, creates empty BoltDB
3. Open the admin UI at `http://localhost:9090`
4. Configure LDAP connection, test connectivity
5. Register your apps (each gets an API key)
6. Create initial admin user → assign `admin` role
7. For each app, set up identity mappings (app username → user GUID)
8. Users can now login via `/api/auth/login` with their app-specific usernames
9. LDAP users are auto-created in BoltDB (with new GUID) on first login with default roles

---

## Token Lifecycle

1. User authenticates → receives `access_token` (8h) + `refresh_token` (30d)
2. Frontend sends `access_token` on every API request
3. When access token expires, frontend calls `POST /api/auth/refresh` with refresh token
4. Server issues new access token **and a new refresh token** (rotation)
5. Old refresh token is invalidated — each refresh token is one-time use
6. If a previously-used refresh token is resubmitted → **revoke the entire token family** (likely stolen)
7. If refresh token is expired → user must login again

Refresh tokens are stored in BoltDB keyed by token ID, grouped into families (all tokens from the same login session). This enables detecting replay attacks.

---

## Rate Limiting

Simple per-IP throttling on login endpoints. In-memory, no external dependencies.

- `POST /api/auth/login` — max 10 attempts per IP per minute
- `GET /api/auth/negotiate` — max 20 attempts per IP per minute
- After limit exceeded → `429 Too Many Requests` with `Retry-After` header

Implementation: in-memory sliding window counter per IP. Automatically cleans up stale entries. Resets on server restart (intentional — keeps it simple).

Not a replacement for nginx rate limiting or fail2ban, but provides basic protection out of the box.

---

## Audit Log

All security-relevant events are logged to a dedicated BoltDB bucket. Append-only, keyed by timestamp.

### Logged Events

| Event | Logged Data |
|-------|-------------|
| `login_success` | user GUID, app_id, provider used, IP |
| `login_failed` | username attempted, app_id, reason, IP |
| `token_refresh` | user GUID, app_id |
| `impersonation` | admin GUID, target GUID, app_id, IP |
| `user_created` | new GUID, created_by |
| `user_merged` | source GUIDs, merged GUID, merged_by |
| `user_unmerged` | restored GUID, unmerged_by |
| `role_changed` | user GUID, app_id, old roles, new roles, changed_by |
| `permission_changed` | user GUID, app_id, old perms, new perms, changed_by |
| `app_registered` | app_id, registered_by |
| `app_key_rotated` | app_id, rotated_by |
| `ldap_provider_added` | provider_id, added_by |
| `kerberos_setup` | realm, SPN, setup_by |

### Storage

Each entry:
```json
{
  "id": "evt-uuid",
  "timestamp": "2026-03-09T14:30:00Z",
  "event": "login_success",
  "actor": "a1b2c3d4-...",
  "ip": "10.0.1.50",
  "data": { "app_id": "chat-app", "provider": "ldap:corp" }
}
```

### Admin API

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/admin/audit` | Query audit log (paginated, filterable) |

Query params: `?event=login_failed&from=2026-03-01&to=2026-03-09&user=guid&limit=100&offset=0`

### Retention

Configurable via `AUTH_AUDIT_RETENTION` env var (default `90d`). A background goroutine prunes old entries daily.

---

## Example: The Phone Number App

Scenario: App "hr-portal" uses phone numbers as usernames. User's phone is `+971501234567`, AD username is `kalahmad`.

Setup:
1. Register app `hr-portal` in SimpleAuth
2. User logs in via LDAP first time → SimpleAuth creates GUID `abc-123`, maps `(ldap, kalahmad) → abc-123`
3. Admin adds mapping: `(app:hr-portal, +971501234567) → abc-123`

Login flow:
1. User opens hr-portal, types `+971501234567` + password
2. hr-portal calls `POST /api/auth/login` with `{ "username": "+971501234567", "password": "...", "app_id": "hr-portal" }`
3. SimpleAuth resolves: `+971501234567` in `app:hr-portal` → GUID `abc-123`
4. Finds LDAP mapping for `abc-123` → `kalahmad`
5. Authenticates `kalahmad` against LDAP
6. Returns JWT with `"sub": "abc-123"`
7. hr-portal uses the GUID for everything internally

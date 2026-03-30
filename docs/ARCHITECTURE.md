# SimpleAuth Architecture

How SimpleAuth works under the hood. Read this if you want to extend SimpleAuth, debug issues, or just satisfy your curiosity.

---

## System Overview

```
                          +------------------+
                          |   Client App     |
                          | (Browser / API)  |
                          +--------+---------+
                                   |
                          HTTPS (TLS)
                                   |
                    +--------------+---------------+
                    |        SimpleAuth Server      |
                    |                               |
                    |  +-------------------------+  |
                    |  |     HTTP Handler         |  |
                    |  |  (routes, middleware)    |  |
                    |  +---+----+----+----+------+  |
                    |      |    |    |    |          |
                    |      v    v    v    v          |
                    |  +----+ +----+ +----+ +-----+ |
                    |  |Auth| |OIDC| |Admin| |Audit| |
                    |  +--+-+ +--+-+ +--+-+ +--+--+ |
                    |     |      |      |      |     |
                    |     v      v      v      v     |
                    |  +---------+---------+----+--+ |
                    |  |      JWT Manager           | |
                    |  |  (RSA sign/verify)          | |
                    |  +----------------------------+ |
                    |             |                    |
                    |             v                    |
                    |  +----------------------------+  |
                    |  |    Store Interface           |  |
                    |  |  (59 methods, interface.go)  |  |
                    |  +------+-------------+--------+  |
                    |         |             |            |
                    |         v             v            |
                    |  +----------+  +-------------+    |
                    |  | BoltDB   |  | PostgreSQL  |    |
                    |  | (auth.db)|  | (sa_* tables)|    |
                    |  +----------+  +-------------+    |
                    |         |             |            |
                    +---------|-------------|------------+
                              |             |
                    +---------+------+------+------+
                    |                |              |
               +----+----+   +------+------+  +----+---+
               |  Active  |   |   Kerberos  |  |Postgres|
               |Directory |   |    KDC      |  |Server  |
               | (LDAP)   |   |  (SPNEGO)   |  |(opt.)  |
               +----------+   +-------------+  +--------+
```

---

## Request Flow

Every request follows this path:

1. **TLS termination** -- SimpleAuth handles its own TLS. Always HTTPS.
2. **CORS** -- If `cors_origins` is configured, CORS headers are added. `OPTIONS` requests are handled automatically.
3. **Routing** -- Go 1.22+ `ServeMux` with method-based routing (`POST /api/auth/login`, etc.)
4. **Authentication middleware** -- Admin endpoints require a valid admin API key (`Authorization: Bearer <admin_key>`).
5. **Handler** -- Business logic executes.
6. **JSON response** -- All responses are JSON with appropriate status codes.

---

## Authentication Flows

SimpleAuth supports three authentication methods, tried in order:

### 1. LDAP Authentication

```
Client                    SimpleAuth                 Active Directory
  |                          |                              |
  |  POST /api/auth/login    |                              |
  |  {username, password}    |                              |
  |------------------------->|                              |
  |                          |  LDAP Bind (service acct)    |
  |                          |----------------------------->|
  |                          |  Search for user by filter   |
  |                          |  (sAMAccountName={username}) |
  |                          |----------------------------->|
  |                          |  <-- User DN, attributes     |
  |                          |<-----------------------------|
  |                          |  LDAP Bind (user DN + pwd)   |
  |                          |----------------------------->|
  |                          |  <-- Success/Failure         |
  |                          |<-----------------------------|
  |                          |                              |
  |                          |  Create/update User in DB    |
  |                          |  Set identity mapping        |
  |                          |  Issue JWT tokens            |
  |                          |                              |
  |  <-- {access_token,      |                              |
  |       refresh_token}     |                              |
  |<-------------------------|                              |
```

**LDAP configuration:** SimpleAuth supports a single LDAP provider configuration. If a user has an existing identity mapping, LDAP authentication is attempted using the stored mapping.

### 2. Kerberos/SPNEGO Authentication

```
Browser                   SimpleAuth                 KDC
  |                          |                          |
  |  GET /api/auth/negotiate |                          |
  |------------------------->|                          |
  |  <-- 401 + WWW-Auth:     |                          |
  |       Negotiate          |                          |
  |<-------------------------|                          |
  |                          |                          |
  |  (Browser gets ticket    |                          |
  |   from KDC for SPN)      |                          |
  |                          |  (ticket already exists) |
  |  GET /api/auth/negotiate |                          |
  |  Authorization: Negotiate|                          |
  |   <base64 AP-REQ>       |                          |
  |------------------------->|                          |
  |                          |  Validate ticket using   |
  |                          |  keytab (no KDC call)    |
  |                          |                          |
  |                          |  Extract principal name  |
  |                          |  Find/create user in DB  |
  |                          |  Issue JWT tokens        |
  |                          |                          |
  |  <-- {access_token, ...} |                          |
  |<-------------------------|                          |
```

SPNEGO is completely transparent to users on domain-joined machines. The browser handles everything. SimpleAuth validates tickets locally using the keytab file -- no network call to the KDC is needed per authentication.

### 3. Local Password Authentication

For users created directly in SimpleAuth (not from LDAP). Passwords are hashed with bcrypt.

```
Client                    SimpleAuth
  |                          |
  |  POST /api/auth/login    |
  |  {username, password}    |
  |------------------------->|
  |                          |  Resolve "local:{username}" mapping
  |                          |  Load user from DB
  |                          |  bcrypt.Compare(hash, password)
  |                          |  Issue JWT tokens
  |  <-- {access_token, ...} |
  |<-------------------------|
```

### Authentication Resolution Order

When a login request comes in:

1. Try local password authentication (`local:{username}` mapping) -- local users always take priority
2. Try LDAP authentication if configured

---

## Token Lifecycle

### Access Tokens

- **Type:** RS256-signed JWTs
- **Default TTL:** 15 minutes
- **Verification:** Offline using JWKS public keys (no server roundtrip)
- **Contents:** User GUID, name, email, roles, permissions, groups, department, company, job title

Access tokens include Keycloak-compatible claims:

```json
{
  "sub": "user-guid",
  "iss": "https://auth.example.com/realms/simpleauth",
  "aud": ["my-app"],
  "exp": 1700000000,
  "iat": 1699971200,
  "typ": "Bearer",
  "azp": "my-app",
  "scope": "openid profile email",
  "name": "John Smith",
  "email": "jsmith@corp.local",
  "preferred_username": "jsmith@corp.local",
  "roles": ["admin"],
  "permissions": ["read:reports"],
  "groups": ["CN=Engineering,..."],
  "department": "Engineering",
  "company": "Acme Corp",
  "job_title": "Senior Engineer",
  "realm_access": {"roles": ["admin"]}
}
```

### Refresh Tokens

- **Type:** RS256-signed JWTs (contain token ID and family ID)
- **Default TTL:** 30 days
- **Rotation:** Every refresh produces a new refresh token (the old one is marked as used)
- **Reuse detection:** If a used refresh token is presented again, the entire token family is revoked

### Token Families

Every login creates a new "family." All refresh tokens from that session share the same `family_id`. This enables:

- **Revocation:** Revoking a family kills the entire session
- **Reuse detection:** If token A is refreshed to produce token B, and then someone tries to use token A again, SimpleAuth knows it's been compromised (replayed). It revokes the entire family, logging out the attacker and the legitimate user. The legitimate user logs in again; the attacker is locked out.

```
Login -> RT-1 (family: F1)
              |
         Refresh
              |
         RT-2 (family: F1, RT-1 marked used)
              |
         Refresh
              |
         RT-3 (family: F1, RT-2 marked used)

If RT-1 is reused:
  -> ALERT: reuse detected
  -> Revoke ALL of family F1 (RT-1, RT-2, RT-3 all deleted)
```

### ID Tokens (OIDC)

- **Type:** RS256-signed JWTs
- **TTL:** Same as access tokens
- **Contents:** `sub`, `name`, `email`, `preferred_username`, `nonce`, `at_hash`
- **Purpose:** Prove the user's identity to the client application

---

## OIDC Compatibility Layer

> **Deprecated:** The OIDC/Keycloak-compatible layer is deprecated and will be removed in v1.0. Use the direct `/api/auth/*` endpoints instead. `client_id`, `client_secret`, and `realm` are accepted for backward compatibility but not validated. SimpleAuth is single-app, single-instance -- these fields add no security value.

SimpleAuth implements a Keycloak-compatible OIDC layer. This means any SDK or library that works with Keycloak works with SimpleAuth.

### URL Mapping

| Standard OIDC | SimpleAuth URL |
|---|---|
| Discovery | `/.well-known/openid-configuration` |
| Discovery (Keycloak) | `/realms/{realm}/.well-known/openid-configuration` |
| Authorization | `/realms/{realm}/protocol/openid-connect/auth` |
| Token | `/realms/{realm}/protocol/openid-connect/token` |
| UserInfo | `/realms/{realm}/protocol/openid-connect/userinfo` |
| JWKS | `/realms/{realm}/protocol/openid-connect/certs` |
| JWKS (also) | `/.well-known/jwks.json` |
| Introspection | `/realms/{realm}/protocol/openid-connect/token/introspect` |
| Logout | `/realms/{realm}/protocol/openid-connect/logout` |

The `{realm}` value is your `jwt_issuer` config (default: `simpleauth`).

### Supported Grant Types

1. **Authorization Code** -- Full browser-based flow with hosted login page
2. **Resource Owner Password** -- Direct username/password (for trusted clients)
3. **Client Credentials** -- Machine-to-machine (no user context)
4. **Refresh Token** -- Token rotation with reuse detection

### Authorization Code Flow Details

```
Browser             Your App              SimpleAuth
  |                    |                      |
  |  Click "Login"     |                      |
  |  ----------------->|                      |
  |                    |  Redirect to:        |
  |                    |  /realms/.../auth     |
  |                    |  ?client_id=...      |
  |                    |  &redirect_uri=...   |
  |                    |  &response_type=code |
  |  <-----------------------------------------
  |                    |                      |
  |  (User sees hosted login page)            |
  |  (Enters username + password)             |
  |                    |                      |
  |  POST credentials  |                      |
  |  ---------------------------------------->|
  |                    |                      |  Validate creds
  |                    |                      |  Generate auth code
  |  <-- 302 redirect to redirect_uri?code=X  |
  |  ---------------------------------------->|
  |  ----------------->|                      |
  |                    |  POST /token         |
  |                    |  grant_type=          |
  |                    |  authorization_code   |
  |                    |  code=X               |
  |                    |  ------------------>  |
  |                    |  <-- tokens           |
  |                    |  <------------------  |
  |  <-- Set session   |                      |
  |  <-----------------|                      |
```

---

## Data Model

SimpleAuth supports two storage backends with identical semantics. The `Store` interface (`internal/store/interface.go`) defines 59 methods; both `BoltStore` and `PostgresStore` implement all of them.

### BoltDB Buckets

[BoltDB](https://github.com/etcd-io/bbolt) is a single-file, embedded key-value database (`{data_dir}/auth.db`). No external database server needed.

| Bucket | Key | Value | Purpose |
|---|---|---|---|
| `config` | arbitrary string | arbitrary bytes | Generic config store (default roles, role-permissions, runtime settings, etc.) |
| `users` | GUID (UUID) | JSON `User` | User records |
| `ldap_providers` | Provider ID | JSON `LDAPProvider` | LDAP/AD configuration (single provider) |
| `identity_mappings` | `provider:external_id` | GUID string | Maps external IDs to users |
| `idx_mappings_by_guid` | GUID | JSON `[]IdentityMapping` | Reverse index: user -> all mappings |
| `user_roles` | `guid` | JSON `[]string` | Roles for users (global per instance) |
| `user_permissions` | `guid` | JSON `[]string` | Permissions for users (global per instance) |
| `refresh_tokens` | Token ID (UUID) | JSON `RefreshToken` | Active refresh tokens |
| `audit_log` | `timestamp:uuid` | JSON `AuditEntry` | Audit log (time-ordered) |
| `oidc_auth_codes` | Code (hex string) | JSON `OIDCAuthCode` | Short-lived auth codes (10 min) |
| `revoked_tokens` | JTI string | expiry time | Blacklisted access tokens (checked on every auth request) |
| `revoked_users` | User GUID | expiry time | Users whose access tokens are force-revoked (checked on every auth request) |

### PostgreSQL Tables

When using the Postgres backend, all tables are prefixed with `sa_` and auto-created on first connection.

| Table | Primary Key | Columns | Purpose |
|---|---|---|---|
| `sa_users` | `guid TEXT` | `data JSONB` | User records |
| `sa_identity_mappings` | `(provider, external_id)` | `user_guid TEXT` | Identity mappings (indexed on `user_guid`) |
| `sa_user_roles` | `guid TEXT` | `roles JSONB` | Roles per user |
| `sa_user_permissions` | `guid TEXT` | `permissions JSONB` | Permissions per user |
| `sa_config` | `key TEXT` | `value BYTEA` | Config key-value (runtime settings, default roles, etc.) |
| `sa_refresh_tokens` | `token_id TEXT` | `data JSONB` | Active refresh tokens |
| `sa_audit_log` | `id TEXT` | `timestamp TIMESTAMPTZ`, `data JSONB` | Audit log (indexed on `timestamp DESC`) |
| `sa_oidc_auth_codes` | `code TEXT` | `data JSONB`, `expires_at TIMESTAMPTZ` | Short-lived auth codes |
| `sa_revoked_tokens` | `jti TEXT` | `expires_at TIMESTAMPTZ` | Blacklisted access tokens |
| `sa_revoked_users` | `user_guid TEXT` | `expires_at TIMESTAMPTZ` | Force-revoked users |

### Data Types

**User:**
```json
{
  "guid": "uuid",
  "password_hash": "bcrypt-hash (omitted in API responses)",
  "display_name": "John Smith",
  "email": "jsmith@corp.local",
  "department": "Engineering",
  "company": "Acme Corp",
  "job_title": "Senior Engineer",
  "disabled": false,
  "merged_into": "" ,
  "created_at": "2024-01-15T10:30:00Z"
}
```

**Identity Mapping Pattern:**

The identity mapping system is the heart of SimpleAuth's authentication support. Mappings use a `provider:external_id` format:

- `local:jsmith` -- Local user "jsmith"
- `ldap:S-1-5-21-...` -- AD user by objectGUID
- `kerberos:jsmith@CORP.LOCAL` -- Kerberos principal

When a user authenticates, SimpleAuth resolves their identity mapping to find (or create) their user record. This means the same person can authenticate via LDAP, Kerberos, or a local password and end up as the same user.

---

## Store Interface and Database Selection

### Store Interface

`internal/store/interface.go` defines the `Store` interface with 59 methods covering users, LDAP config, identity mappings, roles/permissions, config key-value, refresh tokens, audit log, backup/restore, OIDC auth codes, runtime settings, database info, and token revocation. Both `BoltStore` (`internal/store/bolt.go`) and `PostgresStore` (`internal/store/postgres.go`) implement the full interface.

### Database Selection (`OpenSmart`)

`store.OpenSmart(dataDir, postgresURL)` determines which backend to open:

1. Read `db.json` from the data directory. If it exists and specifies `"backend": "postgres"` with a connection URL, open Postgres (decrypting the URL with `encrypt.key` if needed).
2. Otherwise, if `postgresURL` was passed (from `AUTH_POSTGRES_URL` env var or config file), try Postgres. On success, write `db.json` so the Admin UI knows the active backend.
3. If neither is set, or if Postgres fails at any step, fall back to BoltDB with a warning in the logs.

### Migration Engine

SimpleAuth provides bidirectional data migration between BoltDB and PostgreSQL (`internal/store/migrate.go`):

- **BoltDB to Postgres (`MigrateToPostgres`):** truncates all `sa_*` target tables, iterates every key in each BoltDB bucket, inserts into the corresponding Postgres table using `ON CONFLICT` upserts, then verifies row counts match.
- **Postgres to BoltDB (`MigrateFromPostgres`):** queries each `sa_*` table, writes key-value pairs into BoltDB buckets, then verifies row counts.
- **Auto-create database:** `TestPostgresConnection` connects to the `postgres` maintenance database and issues `CREATE DATABASE` if the target database does not exist.
- Progress is streamed via a status channel (state: `running` -> `verifying` -> `completed` or `failed`).

---

## Runtime Settings

Some configuration values are "runtime settings" -- they are seeded from environment variables / config file on first run, then owned by the database. After the initial seed, changes must be made through the Admin UI or `PUT /api/admin/settings`.

Runtime settings include: deployment name, redirect URIs, CORS origins, password policy, account lockout, and default roles. They are stored as a JSON blob under the `runtime_settings` key in the config bucket/table.

The handler caches runtime settings in memory (`runtimeSettingsCache`) and reloads from DB on `PUT /api/admin/settings`.

---

## Token Revocation

SimpleAuth maintains two blacklists checked on every authenticated request:

- **`revoked_tokens`** (BoltDB bucket) / **`sa_revoked_tokens`** (Postgres table) -- individual access tokens blacklisted by JTI. Used when an admin revokes a specific session.
- **`revoked_users`** (BoltDB bucket) / **`sa_revoked_users`** (Postgres table) -- user GUIDs whose access tokens should be rejected regardless of JTI. Used when a user is disabled or all their sessions are revoked.

Both have an `expires_at` timestamp. Expired entries are cleaned up by `CleanExpiredRevocations()` (called by the audit log pruner).

---

## Encryption at Rest

SimpleAuth generates a 256-bit AES key at `{data_dir}/encrypt.key` on first startup (32 random bytes, hex-encoded to 64 characters, file permissions `0600`).

Encryption uses AES-256-GCM (`internal/auth/encrypt.go`). Encrypted values are prefixed with `enc::` followed by base64-encoded `nonce || ciphertext`. The key is independent of the admin key -- changing `AUTH_ADMIN_KEY` does not break encrypted secrets.

Currently used to encrypt: the PostgreSQL connection string stored in `db.json`, and LDAP service account passwords.

---

## Graceful Restart

`main.go` runs the server in a `for` loop. When the Admin UI triggers a restart (e.g., after switching database backends), it sends on a `restartCh` channel. A goroutine receives from that channel and calls `http.Server.Shutdown()` with a 10-second timeout. `ListenAndServe` returns `http.ErrServerClosed`, which causes `runServer()` to return `false` (not exit). The loop sleeps 500ms and calls `runServer()` again, re-loading config and re-opening the store.

If the server exits for any other reason (fatal error, normal shutdown), the loop breaks and the process exits.

---

## Security Model

### Authentication

- All traffic is HTTPS (TLS). No plaintext HTTP (port 80 only redirects to HTTPS).
- Auto-generated self-signed certificates include all local IPs and hostnames in SANs.
- Rate limiting on login endpoints (configurable, default 10/min per IP).
- Passwords hashed with bcrypt (local users).
- LDAP bind verification (server-side, credentials never stored except the service account).

### Authorization

Admin access is controlled exclusively by the admin API key:

- **Admin Key** -- All admin endpoints require `Authorization: Bearer <admin_key>`. The key is set via the `AUTH_ADMIN_KEY` environment variable or `admin_key` config field. There is no role-based admin access; only the admin key grants administrative privileges.

### Password Security

SimpleAuth includes several configurable password security features:

- **Password policy** -- Configurable minimum length and complexity requirements. Complexity checks include: uppercase letter, lowercase letter, digit, and special character. Each requirement can be enabled independently.
- **Password history** -- Prevents users from reusing recent passwords. The number of remembered passwords is configurable via `AUTH_PASSWORD_HISTORY_COUNT`. When a user changes their password, it is checked against their last N password hashes.
- **Account lockout** -- Accounts are locked after a configurable number of consecutive failed login attempts (`AUTH_ACCOUNT_LOCKOUT_THRESHOLD`). Locked accounts are automatically unlocked after a configurable duration (`AUTH_ACCOUNT_LOCKOUT_DURATION`). Admins can also manually unlock accounts.
- **Force password change** -- An admin can set a flag on a user requiring them to change their password on next login. When this flag is set, the login response includes `force_password_change: true`, signaling the client to prompt the user for a new password before proceeding.

### Token Security

- RSA-256 signatures (asymmetric -- apps verify tokens without knowing the signing key)
- Refresh token rotation with family-based reuse detection
- Token family revocation on reuse (kills compromised sessions)
- Impersonation tokens have shorter TTL
- Disabled users cannot authenticate or refresh tokens

### Audit

- Every authentication event is logged with IP address
- Failed login attempts are logged with the reason
- Admin actions (change roles, etc.) are logged
- Security events (token reuse, sessions revoked) are logged
- Configurable retention (default 90 days)
- Daily automatic pruning

### Data at Rest

- BoltDB file has `0600` permissions
- Data directory has `0700` permissions
- TLS private keys have `0600` permissions
- Encryption key (`encrypt.key`) has `0600` permissions
- Sensitive secrets (Postgres URL, LDAP bind password) encrypted with AES-256-GCM using `encrypt.key`
- Docker container runs as non-root user (`simpleauth`)

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
                    |  |    BoltDB Store             |  |
                    |  | (users, tokens, roles, etc.)|  |
                    |  +----------------------------+  |
                    |             |                    |
                    +------------|--------------------+
                                 |
                    +------------+------------+
                    |                         |
               +----+----+            +------+------+
               |  Active  |            |   Kerberos  |
               |Directory |            |    KDC      |
               | (LDAP)   |            |  (SPNEGO)   |
               +----------+            +-------------+
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
- **Default TTL:** 8 hours
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

## Data Model (BoltDB)

SimpleAuth uses [BoltDB](https://github.com/etcd-io/bbolt) -- a single-file, embedded key-value database. No external database server needed.

### Buckets

| Bucket | Key | Value | Purpose |
|---|---|---|---|
| `config` | arbitrary string | arbitrary bytes | Generic config store (default roles, role-permissions, etc.) |
| `users` | GUID (UUID) | JSON `User` | User records |
| `ldap_providers` | Provider ID | JSON `LDAPProvider` | LDAP/AD configuration (single provider) |
| `identity_mappings` | `provider:external_id` | GUID string | Maps external IDs to users |
| `idx_mappings_by_guid` | GUID | JSON `[]IdentityMapping` | Reverse index: user -> all mappings |
| `user_roles` | `guid` | JSON `[]string` | Roles for users (global per instance) |
| `user_permissions` | `guid` | JSON `[]string` | Permissions for users (global per instance) |
| `refresh_tokens` | Token ID (UUID) | JSON `RefreshToken` | Active refresh tokens |
| `audit_log` | `timestamp:uuid` | JSON `AuditEntry` | Audit log (time-ordered) |
| `oidc_auth_codes` | Code (hex string) | JSON `OIDCAuthCode` | Short-lived auth codes (10 min) |

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
- Docker container runs as non-root user (`simpleauth`)

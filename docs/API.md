# SimpleAuth API Reference

Complete reference for every endpoint. All endpoints return JSON. All request bodies are JSON unless noted otherwise.

**Base URL:** `https://your-simpleauth-server:port` (if `AUTH_BASE_PATH` is set, e.g., `/auth`, prefix all paths: `https://your-simpleauth-server:port/auth/api/...`)

**Authentication types:**
- **Admin Key** -- `Authorization: Bearer YOUR_ADMIN_KEY` (the master admin key from config)
- **Bearer Token** -- `Authorization: Bearer ACCESS_TOKEN` (a JWT access token from login)
- **None** -- No authentication required

**Admin access:** All admin endpoints require the master `ADMIN_KEY`. There is no admin role — admin access is controlled exclusively by the admin key.

---

## Health & Server Info

### `GET /health`

**Auth:** None

Health check endpoint.

```bash
curl -k https://localhost:8080/health
```

```json
{"status": "ok"}
```

### `GET /api/admin/server-info`

**Auth:** Admin Key

Returns server configuration details.

```bash
curl -k -H "Authorization: Bearer ADMIN_KEY" \
  https://localhost:8080/api/admin/server-info
```

```json
{
  "hostname": "auth.corp.local",
  "deployment_name": "sauth",
  "jwt_issuer": "simpleauth",
  "version": "dev",
  "redirect_uri": "https://myapp.example.com/callback"
}
```

---

## Authentication

### `POST /api/auth/login`

**Auth:** None

Authenticate a user with username/password. Tries local password first, falls back to LDAP (if configured). Local users always take priority — SimpleAuth owns those credentials.

**Request:**

```json
{
  "username": "jsmith",
  "password": "secret"
}
```

**Response (200):**

```json
{
  "access_token": "eyJ...",
  "refresh_token": "eyJ...",
  "user": {
    "guid": "550e8400-e29b-41d4-a716-446655440000",
    "display_name": "John Smith",
    "email": "jsmith@corp.local",
    "department": "Engineering",
    "company": "Acme Corp",
    "job_title": "Senior Engineer",
    "roles": ["admin", "user"],
    "permissions": ["read:reports", "write:config"],
    "groups": ["Engineering", "IT"]
  }
}
```

When the user has a forced password change pending, the response includes an additional field:

```json
{
  "access_token": "eyJ...",
  "refresh_token": "eyJ...",
  "force_password_change": true,
  "user": { ... }
}
```

Clients should check for `force_password_change: true` and redirect the user to a password change flow before allowing normal access.

**Error responses:**
- `400` -- `{"error": "username and password required"}`
- `401` -- `{"error": "invalid credentials"}`
- `403` -- `{"error": "account disabled"}`
- `429` -- `{"error": "too many login attempts"}` (with `Retry-After` header)

---

### `POST /api/auth/refresh`

**Auth:** None

Exchange a refresh token for a new access token. Implements refresh token rotation with family-based reuse detection.

**Request:**

```json
{
  "refresh_token": "eyJ..."
}
```

**Response (200):**

```json
{
  "access_token": "eyJ...(new)",
  "refresh_token": "eyJ...(new, rotated)"
}
```

**Error responses:**
- `401` -- `{"error": "invalid refresh token"}` (expired or malformed)
- `401` -- `{"error": "token reuse detected, all sessions revoked"}` (replay attack detected)

> **Security note:** If a refresh token is reused (replayed), SimpleAuth revokes the entire token family, invalidating all sessions for that login. This protects against token theft.

---

### `GET /api/auth/userinfo`

**Auth:** Bearer Token

Returns user information from a valid access token.

```bash
curl -k -H "Authorization: Bearer ACCESS_TOKEN" \
  https://localhost:8080/api/auth/userinfo
```

**Response (200):**

```json
{
  "guid": "550e8400-...",
  "preferred_username": "jsmith",
  "display_name": "John Smith",
  "email": "jsmith@corp.local",
  "department": "Engineering",
  "company": "Acme Corp",
  "job_title": "Software Engineer",
  "roles": ["admin"],
  "permissions": ["read:reports"],
  "groups": ["Engineering"],
  "auth_source": "ldap"
}
```

| Field | Description |
|---|---|
| `preferred_username` | Local username, falls back to email or display name |
| `auth_source` | `"local"` for password-based users, `"ldap"` for AD/LDAP users |

---

### `POST /api/auth/impersonate`

**Auth:** Admin Key (master admin key only)

Generate an access token for any user. Useful for testing and support scenarios.

**Request:**

```json
{
  "target_guid": "550e8400-..."
}
```

**Response (200):**

```json
{
  "access_token": "eyJ...",
  "expires_in": 3600,
  "token_type": "Bearer",
  "impersonated": true
}
```

The token has a shorter TTL (`impersonate_ttl`, default 1 hour).

---

### `GET /api/auth/negotiate`

**Auth:** None (Kerberos SPNEGO)

Kerberos/SPNEGO authentication endpoint. The client sends an `Authorization: Negotiate <base64-token>` header. On success, returns JWT tokens.

**Response (200):**

```json
{
  "access_token": "eyJ...",
  "refresh_token": "eyJ...",
  "user": { ... }
}
```

**Error responses:**
- `401` -- `WWW-Authenticate: Negotiate` header (prompts browser to send Kerberos ticket)

---

### `POST /api/auth/reset-password`

**Auth:** Bearer Token

Change the authenticated user's password. Requires a valid access token. If the user already has a password set, the current password must be provided -- unless `force_password_change` is set on the user, in which case `current_password` is not required.

Enforces the configured password policy (minimum length, complexity requirements). Rejects passwords that appear in the user's password history (based on `history_count` setting). On success, clears the `force_password_change` flag.

**Request:**

```json
{
  "current_password": "oldpass",
  "new_password": "newpass"
}
```

**Response (200):**

```json
{"status": "password updated"}
```

**Error responses:**
- `401` -- `{"error": "authorization required"}` or `{"error": "invalid token"}`
- `400` -- `{"error": "new_password required"}` or `{"error": "new_password must be at least 6 characters"}`
- `400` -- `{"error": "password does not meet policy requirements: ..."}` (policy violation details)
- `400` -- `{"error": "password was recently used"}` (password history check)
- `403` -- `{"error": "current password is incorrect"}`

---

### `GET /` (Root)

**Auth:** None

Redirects to `/login`.

---

### `GET /login` / `POST /login`

**Auth:** None

Hosted login page. Renders a branded login form and handles form submission. If Kerberos is configured, shows an "Sign in with SSO" button.

On successful login without a `redirect_uri`, the user is redirected to `/account` with tokens in the URL fragment.

---

### `GET /login/sso`

**Auth:** None (Kerberos SPNEGO)

SSO login endpoint for the hosted login flow. Attempts Kerberos/SPNEGO authentication. On success, redirects to `redirect_uri` (or `/account`) with tokens in the URL fragment. On failure, redirects back to `/login` with an error message instead of hanging.

**Query parameters:**
- `redirect_uri` -- Where to redirect after successful SSO login

---

### `GET /account`

**Auth:** None (page loads, then authenticates via JavaScript)

User self-service page. Shows the authenticated user's profile information and allows password changes.

- **Profile view** -- display name, email, username, department, company, job title, roles
- **Password change** -- current password + new password (uses `POST /api/auth/reset-password` internally)
- **LDAP users** -- password change form is hidden; shows a note that their password is managed by the directory

The page reads the access token from the URL fragment (after login redirect) or from `sessionStorage`.

---

### `GET /test-negotiate` / `POST /test-negotiate`

**Auth:** None

Diagnostic page for testing Kerberos/SPNEGO authentication. Shows the raw negotiation flow and results. Useful for troubleshooting SSO configuration.

---

## OIDC / Keycloak-Compatible Endpoints

> **Deprecated:** The OIDC/Keycloak-compatible endpoints are deprecated and will be removed in v1.0. Use the direct `/api/auth/*` endpoints instead. `client_id` and `client_secret` are accepted but not validated. **All official SDKs (Go, JavaScript, Python, .NET) now use the direct API endpoints by default** (`POST /api/auth/login`, `POST /api/auth/refresh`, `GET /.well-known/jwks.json`, `GET /api/auth/userinfo`) and no longer use these OIDC realm URLs.

All OIDC endpoints follow the Keycloak URL pattern: `/realms/{realm}/protocol/openid-connect/...`

The realm defaults to your `jwt_issuer` config value (default: `simpleauth`).

OIDC client settings (`AUTH_CLIENT_ID`, `AUTH_CLIENT_SECRET`) are accepted for backward compatibility but are not validated. SimpleAuth is single-app, single-instance -- these fields add no security value.

### `GET /.well-known/openid-configuration`

**Auth:** None

OIDC Discovery document. Also available at `/realms/{realm}/.well-known/openid-configuration`.

```bash
curl -k https://localhost:8080/.well-known/openid-configuration
```

**Response (200):**

```json
{
  "issuer": "https://localhost:8080/realms/simpleauth",
  "authorization_endpoint": "https://localhost:8080/realms/simpleauth/protocol/openid-connect/auth",
  "token_endpoint": "https://localhost:8080/realms/simpleauth/protocol/openid-connect/token",
  "userinfo_endpoint": "https://localhost:8080/realms/simpleauth/protocol/openid-connect/userinfo",
  "jwks_uri": "https://localhost:8080/realms/simpleauth/protocol/openid-connect/certs",
  "introspection_endpoint": "https://localhost:8080/realms/simpleauth/protocol/openid-connect/token/introspect",
  "end_session_endpoint": "https://localhost:8080/realms/simpleauth/protocol/openid-connect/logout",
  "response_types_supported": ["code"],
  "grant_types_supported": ["authorization_code", "client_credentials", "password", "refresh_token"],
  "subject_types_supported": ["public"],
  "id_token_signing_alg_values_supported": ["RS256"],
  "scopes_supported": ["openid", "profile", "email", "roles"],
  "token_endpoint_auth_methods_supported": ["client_secret_basic", "client_secret_post"],
  "claims_supported": [
    "sub", "iss", "aud", "exp", "iat", "name", "email",
    "preferred_username", "realm_access",
    "department", "company", "job_title", "groups"
  ]
}
```

---

### `GET /.well-known/jwks.json`

**Auth:** None

JSON Web Key Set. Contains the RSA public keys used to sign JWTs. Also available at `/realms/{realm}/protocol/openid-connect/certs`.

```bash
curl -k https://localhost:8080/.well-known/jwks.json
```

**Response (200):**

```json
{
  "keys": [
    {
      "kty": "RSA",
      "use": "sig",
      "kid": "key-id-here",
      "alg": "RS256",
      "n": "...",
      "e": "AQAB"
    }
  ]
}
```

---

### `GET /realms/{realm}/protocol/openid-connect/auth`

**Auth:** None

OAuth2 Authorization endpoint. Renders the hosted login page for the authorization code flow.

**Query parameters:**
- `client_id` (required) -- Must match the configured `AUTH_CLIENT_ID`
- `redirect_uri` -- Where to redirect after login (must match one of the allowed redirect URIs configured via `AUTH_REDIRECT_URI` and/or `AUTH_REDIRECT_URIS`; supports wildcard `*` suffix matching)
- `response_type` -- Must be `code`
- `state` -- CSRF protection value (passed through)
- `nonce` -- Replay protection for ID tokens
- `scope` -- Space-separated scopes (e.g., `openid profile email`)

```
https://auth.example.com/realms/simpleauth/protocol/openid-connect/auth?client_id=my-app&redirect_uri=https://myapp.com/callback&response_type=code&state=xyz
```

On successful login, redirects to `redirect_uri?code=AUTH_CODE&state=xyz`.

---

### `POST /realms/{realm}/protocol/openid-connect/token`

**Auth:** Client credentials (Basic auth or form post)

OAuth2 Token endpoint. Supports four grant types.

**Client authentication methods:**
- HTTP Basic: `Authorization: Basic base64(client_id:client_secret)`
- Form body: `client_id=...&client_secret=...`

The `client_id` and `client_secret` must match the instance-level `AUTH_CLIENT_ID` and `AUTH_CLIENT_SECRET`.

#### Authorization Code Grant

```bash
curl -k -X POST \
  https://localhost:8080/realms/simpleauth/protocol/openid-connect/token \
  -u "my-app:my-secret" \
  -d "grant_type=authorization_code&code=AUTH_CODE&redirect_uri=https://myapp.com/callback"
```

#### Resource Owner Password Grant

```bash
curl -k -X POST \
  https://localhost:8080/realms/simpleauth/protocol/openid-connect/token \
  -u "my-app:my-secret" \
  -d "grant_type=password&username=jsmith&password=secret&scope=openid profile email"
```

#### Client Credentials Grant

```bash
curl -k -X POST \
  https://localhost:8080/realms/simpleauth/protocol/openid-connect/token \
  -u "my-app:my-secret" \
  -d "grant_type=client_credentials"
```

#### Refresh Token Grant

```bash
curl -k -X POST \
  https://localhost:8080/realms/simpleauth/protocol/openid-connect/token \
  -u "my-app:my-secret" \
  -d "grant_type=refresh_token&refresh_token=eyJ..."
```

**Response (200) -- all grant types:**

```json
{
  "access_token": "eyJ...",
  "refresh_token": "eyJ...",
  "id_token": "eyJ...",
  "token_type": "Bearer",
  "expires_in": 28800,
  "scope": "openid profile email"
}
```

**Error responses (OAuth2 format):**

```json
{
  "error": "invalid_grant",
  "error_description": "invalid credentials"
}
```

Error codes: `invalid_request`, `invalid_client`, `invalid_grant`, `unsupported_grant_type`, `server_error`

---

### `GET/POST /realms/{realm}/protocol/openid-connect/userinfo`

**Auth:** Bearer Token

OIDC UserInfo endpoint.

```bash
curl -k -H "Authorization: Bearer ACCESS_TOKEN" \
  https://localhost:8080/realms/simpleauth/protocol/openid-connect/userinfo
```

**Response (200):**

```json
{
  "sub": "550e8400-...",
  "name": "John Smith",
  "email": "jsmith@corp.local",
  "preferred_username": "jsmith@corp.local",
  "department": "Engineering",
  "company": "Acme Corp",
  "job_title": "Senior Engineer",
  "roles": ["admin"],
  "groups": ["Engineering"],
  "realm_access": {"roles": ["admin"]}
}
```

---

### `POST /realms/{realm}/protocol/openid-connect/token/introspect`

**Auth:** Client credentials

RFC 7662 Token Introspection. Validates a token and returns its claims.

```bash
curl -k -X POST \
  https://localhost:8080/realms/simpleauth/protocol/openid-connect/token/introspect \
  -u "my-app:my-secret" \
  -d "token=eyJ..."
```

**Response (200) -- active token:**

```json
{
  "active": true,
  "sub": "550e8400-...",
  "iss": "https://localhost:8080/realms/simpleauth",
  "exp": 1700000000,
  "iat": 1699971200,
  "token_type": "Bearer",
  "client_id": "my-app",
  "scope": "openid profile email",
  "preferred_username": "jsmith@corp.local",
  "name": "John Smith",
  "email": "jsmith@corp.local"
}
```

**Response (200) -- inactive/invalid token:**

```json
{"active": false}
```

---

### `GET/POST /realms/{realm}/protocol/openid-connect/logout`

**Auth:** None

OIDC End Session endpoint. Revokes all sessions for the user.

**Parameters (query or form):**
- `id_token_hint` -- The user's ID token (used to identify the user and revoke sessions)
- `post_logout_redirect_uri` -- Where to redirect after logout

```bash
curl -k -X POST \
  https://localhost:8080/realms/simpleauth/protocol/openid-connect/logout \
  -d "id_token_hint=eyJ...&post_logout_redirect_uri=https://myapp.com"
```

---

## Admin: Users

### `GET /api/admin/users`

**Auth:** Admin Key

List all users. Password hashes are stripped from the response.

**Query Parameters:**

| Parameter | Value | Description |
|-----------|-------|-------------|
| `include` | `identities` | Include each user's identity mappings as an `identities` array. Without this parameter, the `identities` field is omitted (backward compatible). |

```bash
curl -k -H "Authorization: Bearer ADMIN_KEY" \
  https://localhost:8080/api/admin/users
```

**With identities:**

```bash
curl -k -H "Authorization: Bearer ADMIN_KEY" \
  "https://localhost:8080/api/admin/users?include=identities"
```

Each entry in the `identities` array contains:

| Field | Type | Description |
|-------|------|-------------|
| `provider` | string | Identity provider (e.g. `"local"`, `"ldap"`) |
| `external_id` | string | User identifier within that provider (e.g. `"kalahmad"`) |

**Example response with `?include=identities`:**

```json
[
  {
    "guid": "abc-123...",
    "display_name": "Khalefa Ahmad",
    "email": "kalahmad@corp.local",
    "identities": [
      {"provider": "local", "external_id": "kalahmad"},
      {"provider": "ldap", "external_id": "kalahmad"}
    ]
  }
]
```

---

### `POST /api/admin/users`

**Auth:** Admin Key

Create a local user.

**Request:**

```json
{
  "username": "jsmith",
  "password": "a-strong-password",
  "display_name": "John Smith",
  "email": "jsmith@example.com",
  "department": "Engineering",
  "company": "Acme Corp",
  "job_title": "Senior Engineer"
}
```

The `username` field creates a `local` identity mapping (e.g., `local:jsmith`). The `password` field is optional — if omitted, the user can only authenticate via LDAP. If a password is provided, it must satisfy the configured password policy (minimum length, complexity requirements).

**Response (201):**

```json
{
  "guid": "550e8400-...",
  "display_name": "John Smith",
  "email": "jsmith@example.com"
}
```

---

### `GET /api/admin/users/{guid}`

**Auth:** Admin Key

Get a single user by GUID.

**Query Parameters:**

| Parameter | Value | Description |
|-----------|-------|-------------|
| `include` | `identities` | Include the user's identity mappings as an `identities` array. Without this parameter, the `identities` field is omitted (backward compatible). |

```bash
curl -k -H "Authorization: Bearer ADMIN_KEY" \
  "https://localhost:8080/api/admin/users/{guid}?include=identities"
```

See [`GET /api/admin/users`](#get-apiadminusers) for the `identities` array format.

**User object fields include:**

| Field | Type | Description |
|---|---|---|
| `guid` | string | Unique user identifier |
| `display_name` | string | User's display name |
| `email` | string | User's email address |
| `department` | string | Department |
| `company` | string | Company |
| `job_title` | string | Job title |
| `disabled` | boolean | Whether the account is disabled |
| `force_password_change` | boolean | Whether the user must change password on next login |
| `failed_login_attempts` | integer | Number of consecutive failed login attempts |
| `locked_until` | datetime, nullable | Timestamp until which the account is locked (null if not locked) |

---

### `PUT /api/admin/users/{guid}`

**Auth:** Admin Key

Update user fields. Only provided fields are updated.

**Request:**

```json
{
  "display_name": "Jonathan Smith",
  "email": "jonathan.smith@example.com",
  "department": "Platform",
  "company": "Acme Corp",
  "job_title": "Staff Engineer"
}
```

---

### `DELETE /api/admin/users/{guid}`

**Auth:** Admin Key

Delete a user.

---

### `PUT /api/admin/users/{guid}/password`

**Auth:** Admin Key

Set a user's password (admin override, no current password required).

**Request:**

```json
{
  "password": "new-password-here",
  "force_change": true
}
```

| Field | Description |
|---|---|
| `password` | The new password to set |
| `force_change` | Optional boolean. If `true`, the user will be required to change their password on next login |

---

### `PUT /api/admin/users/{guid}/unlock`

**Auth:** Admin Key

Clears failed login attempts and lockout for a user. Use this to manually unlock an account that has been locked due to too many failed login attempts.

**Response (200):**

```json
{"status": "ok"}
```

---

### `PUT /api/admin/users/{guid}/disabled`

**Auth:** Admin Key

Enable or disable a user account. Disabled users cannot log in.

**Request:**

```json
{"disabled": true}
```

**Response (200):**

```json
{"guid": "550e8400-...", "disabled": true}
```

---

### `POST /api/admin/users/merge`

**Auth:** Admin Key

Merge multiple user records into one. This is useful when the same person has separate accounts from different identity sources. Identity mappings, roles, and permissions are all merged.

**Request:**

```json
{
  "source_guids": ["guid-1", "guid-2"],
  "display_name": "John Smith",
  "email": "jsmith@corp.local"
}
```

**Response (200):**

```json
{
  "merged_guid": "new-guid",
  "sources": ["guid-1", "guid-2"]
}
```

---

### `POST /api/admin/users/{guid}/unmerge`

**Auth:** Admin Key

Reverse a merge operation. The user record has its `merged_into` pointer cleared.

---

### `GET /api/admin/users/{guid}/sessions`

**Auth:** Admin Key

List active sessions (non-expired, non-used refresh tokens) for a user.

**Response (200):**

```json
[
  {
    "family_id": "fam-xxxx",
    "created_at": "2024-01-15T10:30:00Z",
    "expires_at": "2024-02-14T10:30:00Z"
  }
]
```

---

### `DELETE /api/admin/users/{guid}/sessions`

**Auth:** Admin Key

Revoke all sessions for a user. This revokes **both** refresh tokens and access tokens. Active access tokens are added to a blacklist and checked on every authenticated request, so revocation is immediate -- there is no waiting for token expiry. Forces the user to log in again everywhere.

---

## Roles & Permissions Model

SimpleAuth is the authority for roles and permissions -- they must be defined in the registries before they can be assigned to users. Use `PUT /api/admin/role-permissions` to define roles (and their associated permissions) and `PUT /api/admin/permissions` to define the master permissions list. On first startup, any roles or permissions already assigned to existing users are automatically registered into the respective registries.

---

## Admin: Roles & Permissions

Roles and permissions are global per SimpleAuth instance.

### `GET /api/admin/users/{guid}/roles`

**Auth:** Admin Key

Get a user's roles.

**Response (200):**

```json
["admin", "user"]
```

---

### `PUT /api/admin/users/{guid}/roles`

**Auth:** Admin Key

Set a user's roles. Replaces the entire role list.

> **Note:** All roles must be defined in the role registry first (via `PUT /api/admin/role-permissions`), otherwise a `400` error is returned.

**Request body:** Array of strings.

```json
["admin", "user", "manager"]
```

---

### `GET /api/admin/users/{guid}/permissions`

**Auth:** Admin Key

Get a user's permissions.

**Response (200):**

```json
["read:reports", "write:config"]
```

---

### `PUT /api/admin/users/{guid}/permissions`

**Auth:** Admin Key

Set a user's permissions.

> **Note:** All permissions must be defined in the permissions registry first (via `PUT /api/admin/permissions`), otherwise a `400` error is returned.

**Request body:** Array of strings.

```json
["read:reports", "write:config", "delete:users"]
```

---

### `GET /api/admin/defaults/roles`

**Auth:** Admin Key

Get default roles that are automatically assigned to new users when they first log in. Can also be set via the `AUTH_DEFAULT_ROLES` environment variable.

---

### `PUT /api/admin/defaults/roles`

**Auth:** Admin Key

Set default roles for new users.

> **Note:** Default roles must be defined in the role registry first (via `PUT /api/admin/role-permissions`).

**Request body:** Array of strings.

```json
["user", "viewer"]
```

---

### `GET /api/admin/role-permissions`

**Auth:** Admin Key

Get the role-to-permissions mapping. This defines which permissions are automatically granted by each role.

---

### `PUT /api/admin/role-permissions`

**Auth:** Admin Key

Set the role-to-permissions mapping.

> **Note:** All permissions referenced in the mapping must be defined in the permissions registry first (via `PUT /api/admin/permissions`).

**Request body:** Object mapping role names to permission arrays.

```json
{
  "admin": ["read:all", "write:all", "delete:all"],
  "editor": ["read:all", "write:all"],
  "viewer": ["read:all"]
}
```

---

### `GET /api/admin/roles`

**Auth:** Admin Key

Returns all defined roles from the role registry.

```bash
curl -k -H "Authorization: Bearer ADMIN_KEY" \
  https://localhost:8080/api/admin/roles
```

```json
["admin", "editor", "user", "viewer"]
```

---

### `GET /api/admin/permissions`

**Auth:** Admin Key

Returns all defined permissions from the permissions registry.

```bash
curl -k -H "Authorization: Bearer ADMIN_KEY" \
  https://localhost:8080/api/admin/permissions
```

```json
["delete:all", "read:all", "write:all"]
```

---

### `PUT /api/admin/permissions`

**Auth:** Admin Key

Sets the master permissions list. Replaces the entire permissions registry.

**Request body:** Array of strings.

```json
["read:all", "write:all", "delete:all", "read:reports", "write:config"]
```

**Response (200):**

```json
["read:all", "write:all", "delete:all", "read:reports", "write:config"]
```

---

## Admin: Password Policy

### `GET /api/admin/password-policy`

**Auth:** Admin Key

Returns the current password policy configuration.

```bash
curl -k -H "Authorization: Bearer ADMIN_KEY" \
  https://localhost:8080/api/admin/password-policy
```

**Response (200):**

```json
{
  "min_length": 8,
  "require_uppercase": false,
  "require_lowercase": false,
  "require_digit": false,
  "require_special": false,
  "history_count": 0
}
```

| Field | Description |
|---|---|
| `min_length` | Minimum password length |
| `require_uppercase` | Require at least one uppercase letter |
| `require_lowercase` | Require at least one lowercase letter |
| `require_digit` | Require at least one digit |
| `require_special` | Require at least one special character |
| `history_count` | Number of previous passwords to remember (0 = disabled) |

---

## Admin: Bootstrap

### `POST /api/admin/bootstrap`

**Auth:** Admin Key

Idempotent endpoint for app startup. Defines permissions, roles, and ensures users exist with correct credentials. Safe to call on every boot -- designed for the "config is the source of truth" pattern.

All fields are optional. Only include what you need.

**Request:**

```json
{
  "permissions": ["posts:read", "posts:write", "users:manage", "admin:access"],
  "role_permissions": {
    "viewer": ["posts:read"],
    "editor": ["posts:read", "posts:write"],
    "admin": ["posts:read", "posts:write", "users:manage", "admin:access"]
  },
  "users": [
    {
      "username": "root",
      "password": "from-env-var",
      "display_name": "Root Admin",
      "email": "root@example.com",
      "roles": ["admin"],
      "permissions": ["admin:access"],
      "force_password": true
    }
  ]
}
```

| Field | Type | Description |
|---|---|---|
| `permissions` | string[] | Master permissions list. Replaces the permissions registry (same as `PUT /api/admin/permissions`) |
| `role_permissions` | object | Role-to-permissions mapping. Keys are role names, values are permission arrays (same as `PUT /api/admin/role-permissions`) |
| `users` | array | Users to ensure exist. See user fields below |

**User fields:**

| Field | Type | Description |
|---|---|---|
| `username` | string | **Required.** Local username. Used to look up the user via `local` identity mapping |
| `password` | string | Password to set. On new users, always set. On existing users, only set if `force_password` is `true` |
| `display_name` | string | Display name. Set on create; updated on existing users if provided |
| `email` | string | Email address. Set on create; updated on existing users if provided |
| `roles` | string[] | Roles to assign. Must be defined in role registry first (via `permissions` + `role_permissions` in the same request, or previously) |
| `permissions` | string[] | Direct permissions to assign. Must be defined in permissions registry first |
| `force_password` | boolean | If `true`, always reset the password (even if user already exists). If `false` or omitted, password is only set on newly created users |

**User resolution:** Each user is looked up by `username` via the `local` identity mapping. If no mapping exists, a new user is created with a `local` identity mapping.

**Processing order:** Permissions are defined first, then role-permissions, then users. This means you can define roles and permissions in the same request that assigns them to users.

```bash
curl -k -X POST \
  https://localhost:8080/api/admin/bootstrap \
  -H "Authorization: Bearer ADMIN_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "permissions": ["posts:read", "posts:write", "admin:access"],
    "role_permissions": {
      "viewer": ["posts:read"],
      "admin": ["posts:read", "posts:write", "admin:access"]
    },
    "users": [
      {
        "username": "root",
        "password": "'"$ROOT_PASSWORD"'",
        "display_name": "Root Admin",
        "roles": ["admin"],
        "force_password": true
      }
    ]
  }'
```

**Response (200):**

```json
{
  "users": [
    {
      "username": "root",
      "guid": "550e8400-e29b-41d4-a716-446655440000",
      "created": false
    }
  ],
  "permissions_count": 3,
  "role_permissions_count": 2
}
```

| Field | Type | Description |
|---|---|---|
| `users` | array | One entry per user in the request. `created` is `true` if the user was newly created, `false` if it already existed |
| `permissions_count` | integer | Number of permissions defined (only present if `permissions` was provided) |
| `role_permissions_count` | integer | Number of roles defined (only present if `role_permissions` was provided) |

---

## Admin: LDAP Configuration

SimpleAuth supports a single LDAP/Active Directory configuration. All LDAP endpoints are under `/api/admin/ldap` (no provider IDs).

### `GET /api/admin/ldap`

**Auth:** Admin Key

Get the current LDAP configuration. Returns `null` if not configured. The bind password is masked in the response.

---

### `PUT /api/admin/ldap`

**Auth:** Admin Key

Save or update the LDAP configuration.

**Request:**

```json
{
  "url": "ldaps://dc01.corp.local:636",
  "base_dn": "DC=corp,DC=local",
  "bind_dn": "CN=svc-sauth-prod,OU=Service Accounts,DC=corp,DC=local",
  "bind_password": "ServiceAccountPassword",
  "username_attr": "sAMAccountName",
  "use_tls": true,
  "skip_tls_verify": false,
  "display_name_attr": "displayName",
  "email_attr": "mail",
  "department_attr": "department",
  "company_attr": "company",
  "job_title_attr": "title",
  "groups_attr": "memberOf"
}
```

| Field | Description |
|---|---|
| `username_attr` | LDAP attribute for username lookup. Common values: `sAMAccountName` (AD), `userPrincipalName` (AD), `uid` (OpenLDAP), `mail` |
| `custom_filter` | Optional. Advanced LDAP filter with `{{username}}` placeholder. Overrides `username_attr` when set. Example: `(&(objectClass=person)(sAMAccountName={{username}}))` |
| `domain` | Optional. AD domain name (e.g., `corp.local`). Used by auto-discover and setup scripts |

If the bind password is sent as `••••••••`, the existing password is preserved (allows updating other fields without re-entering the password).

---

### `DELETE /api/admin/ldap`

**Auth:** Admin Key

Remove the LDAP configuration.

---

### `POST /api/admin/ldap/test`

**Auth:** Admin Key

Test connectivity and bind credentials for the saved LDAP configuration.

**Response (200):**

```json
{"status": "ok"}
```

Or on error:

```json
{"status": "error", "error": "connection refused"}
```

---

### `POST /api/admin/ldap/test-user`

**Auth:** Admin Key

Search for a user in LDAP and preview the mapped attributes. Useful for verifying attribute mapping before importing users.

**Request:**

```json
{"username": "alice"}
```

**Response (200):**

```json
{
  "status": "ok",
  "username": "alice",
  "display_name": "Alice Johnson",
  "email": "alice@corp.local",
  "department": "Engineering",
  "company": "Acme Corp",
  "job_title": "Software Engineer",
  "groups": ["Engineering", "IT"],
  "dn": "CN=Alice Johnson,OU=Users,DC=corp,DC=local"
}
```

---

### `POST /api/admin/ldap/auto-discover`

**Auth:** Admin Key

Auto-discover LDAP configuration by connecting to a server, querying RootDSE for the base DN, and detecting whether it's Active Directory or OpenLDAP (to choose the correct `username_attr`). Saves the configuration on success.

**Request:**

```json
{
  "server": "dc01.corp.local",
  "username": "svc-simpleauth",
  "password": "ServicePassword"
}
```

The server can be a hostname, `hostname:port`, or full URL (`ldap://` or `ldaps://`). Default port is 389 for ldap, 636 for ldaps.

**Response (200):** Returns the discovered and saved LDAP configuration (with masked password).

---

### `POST /api/admin/ldap/import`

**Auth:** Admin Key

Import LDAP configuration from the PowerShell setup script JSON output.

**Request:**

```json
{
  "server": "dc01.corp.local",
  "username": "svc-simpleauth",
  "password": "ServicePassword",
  "domain": "corp.local",
  "base_dn": "DC=corp,DC=local",
  "service_hostname": "auth.corp.local",
  "spn": "HTTP/auth.corp.local"
}
```

If `service_hostname` is provided, Kerberos setup is automatically triggered after the LDAP config is saved.

---

### `POST /api/admin/ldap/search-users`

**Auth:** Admin Key

Search the LDAP directory for users matching a query string. Searches across username, display name, and email attributes. Returns whether each user is already imported into SimpleAuth.

**Request:**

```json
{
  "query": "john",
  "limit": 50
}
```

**Response (200):**

```json
[
  {
    "username": "jsmith",
    "display_name": "John Smith",
    "email": "jsmith@corp.local",
    "department": "Engineering",
    "company": "Acme Corp",
    "job_title": "Senior Engineer",
    "groups": ["Engineering"],
    "dn": "CN=John Smith,OU=Users,DC=corp,DC=local",
    "imported": false,
    "user_guid": ""
  },
  {
    "username": "jdoe",
    "display_name": "John Doe",
    "email": "jdoe@corp.local",
    "department": "Marketing",
    "company": "Acme Corp",
    "job_title": "Manager",
    "groups": ["Marketing"],
    "dn": "CN=John Doe,OU=Users,DC=corp,DC=local",
    "imported": true,
    "user_guid": "660e8400-..."
  }
]
```

---

### `POST /api/admin/ldap/import-users`

**Auth:** Admin Key

Import one or more LDAP users into SimpleAuth. For each username, looks up the user in LDAP, creates a SimpleAuth user record, creates an `ldap` identity mapping, and assigns default roles.

**Request:**

```json
{
  "usernames": ["alice", "bob", "charlie"]
}
```

**Response (200):**

```json
[
  {"username": "alice", "status": "imported", "user_guid": "550e8400-..."},
  {"username": "bob", "status": "exists", "user_guid": "660e8400-..."},
  {"username": "charlie", "status": "error", "error": "user not found: sAMAccountName=charlie"}
]
```

Status values: `imported` (newly created), `exists` (already imported), `error` (lookup or creation failed).

---

### `POST /api/admin/ldap/sync-user`

**Auth:** Admin Key

Sync a single user's profile from LDAP. Looks up the user by their configured username attribute in the LDAP directory, then updates their SimpleAuth profile (display name, email, department, company, job title).

**Request:**

```json
{"username": "jsmith"}
```

```bash
curl -k -X POST \
  https://localhost:8080/api/admin/ldap/sync-user \
  -H "Authorization: Bearer ADMIN_KEY" \
  -H "Content-Type: application/json" \
  -d '{"username": "jsmith"}'
```

**Response (200):**

```json
{
  "status": "synced",
  "user": { ... }
}
```

---

### `POST /api/admin/ldap/sync-all`

**Auth:** Admin Key

Sync all users that have `ldap` identity mappings. Iterates all non-merged users with an LDAP mapping and updates their profiles from the directory.

```bash
curl -k -X POST \
  https://localhost:8080/api/admin/ldap/sync-all \
  -H "Authorization: Bearer ADMIN_KEY"
```

**Response (200):**

```json
{
  "status": "completed",
  "synced": 42,
  "failed": 3,
  "errors": ["charlie: user not found"]
}
```

The `errors` array is only present when there are failures.

---

### `POST /api/admin/ldap/setup-kerberos`

**Auth:** Admin Key

Set up Kerberos/SPNEGO authentication using the LDAP provider's AD credentials. Creates the SPN and generates a keytab.

**Request:**

```json
{
  "admin_username": "admin@CORP.LOCAL",
  "admin_password": "AdminPassword"
}
```

---

### `POST /api/admin/ldap/cleanup-kerberos`

**Auth:** Admin Key

Remove Kerberos configuration (delete SPN, clean up keytab).

---

### `GET /api/admin/kerberos/status`

**Auth:** Admin Key

Check the status of Kerberos configuration (keytab exists, SPN configured, etc.).

---

### `GET /api/admin/setup-script`

**Auth:** Admin Key

Download an interactive PowerShell script for AD setup. The script has the SimpleAuth hostname pre-injected and offers:
- Create a new service account or use an existing one
- OU selection for new accounts
- SPN registration for Kerberos
- Config JSON export for one-click import into the admin UI

Returns a `.ps1` file with UTF-8 BOM encoding.

---

## Admin: Identity Mappings

Identity mappings link external identities (LDAP usernames, local usernames) to SimpleAuth user GUIDs. This is how SimpleAuth tracks that "jsmith" in AD is the same person across logins.

**Provider names:**
- `local` -- Local username/password authentication
- `ldap` -- LDAP/Active Directory authentication

### `GET /api/admin/mappings`

**Auth:** Admin Key

List all identity mappings.

**Response (200):**

```json
[
  {
    "provider": "ldap",
    "external_id": "jsmith",
    "user_guid": "550e8400-..."
  },
  {
    "provider": "local",
    "external_id": "admin",
    "user_guid": "660e8400-..."
  }
]
```

---

### `GET /api/admin/users/{guid}/mappings`

**Auth:** Admin Key

Get all identity mappings for a specific user.

---

### `PUT /api/admin/users/{guid}/mappings`

**Auth:** Admin Key

Create or update an identity mapping.

**Request:**

```json
{
  "provider": "ldap",
  "external_id": "jsmith"
}
```

---

### `DELETE /api/admin/users/{guid}/mappings/{provider}/{external_id}`

**Auth:** Admin Key

Delete an identity mapping.

---

### `GET /api/admin/mappings/resolve`

**Auth:** Admin Key

Resolve an external identity to a SimpleAuth user GUID.

**Query parameters:**
- `provider` -- The identity provider (e.g., `ldap`, `local`)
- `external_id` -- The external identifier

```bash
curl -k -H "Authorization: Bearer ADMIN_KEY" \
  "https://localhost:8080/api/admin/mappings/resolve?provider=local&external_id=jsmith"
```

**Response (200):**

```json
{"guid": "550e8400-..."}
```

---

## Admin: Backup & Restore

### `GET /api/admin/backup`

**Auth:** Admin Key

Download a complete database backup as a binary file.

```bash
curl -k -H "Authorization: Bearer ADMIN_KEY" \
  https://localhost:8080/api/admin/backup -o backup.db
```

---

### `POST /api/admin/restore`

**Auth:** Admin Key

Restore from a backup file. Multipart form upload. **This replaces the entire database.**

```bash
curl -k -X POST -H "Authorization: Bearer ADMIN_KEY" \
  -F "file=@backup.db" \
  https://localhost:8080/api/admin/restore
```

**Response (200):**

```json
{"status": "restored"}
```

---

## Admin: Audit Log

### `GET /api/admin/audit`

**Auth:** Admin Key

Query the audit log. All authentication events, admin actions, and security events are logged.

**Query parameters:**
- `event` -- Filter by event type (e.g., `login_success`, `login_failed`)
- `user` -- Filter by user GUID (actor)
- `from` -- Start date (`YYYY-MM-DD`)
- `to` -- End date (`YYYY-MM-DD`)
- `limit` -- Max results (default 100)
- `offset` -- Pagination offset

```bash
curl -k -H "Authorization: Bearer ADMIN_KEY" \
  "https://localhost:8080/api/admin/audit?event=login_failed&from=2024-01-01&limit=50"
```

**Response (200):**

```json
[
  {
    "id": "entry-uuid",
    "timestamp": "2024-01-15T10:31:00Z",
    "event": "login_failed",
    "actor": "",
    "ip": "192.168.1.100",
    "data": {
      "username": "jsmith",
      "reason": "invalid credentials"
    }
  }
]
```

**Event types:**
| Event | Description |
|-------|-------------|
| `login_success` | Successful authentication |
| `login_failed` | Failed authentication attempt |
| `token_refreshed` | Refresh token used |
| `token_reuse` | Refresh token replay detected (security event) |
| `user_created` | New user created |
| `user_merged` | Users merged |
| `user_unmerged` | User unmerged |
| `role_changed` | User roles updated |
| `permission_changed` | User permissions updated |
| `default_roles_changed` | Default roles updated |
| `role_permissions_changed` | Role-to-permissions mapping updated |
| `sessions_revoked` | All sessions revoked for a user |
| `negotiate_success` | Kerberos/SPNEGO authentication succeeded |
| `negotiate_failed` | Kerberos/SPNEGO authentication failed |
| `oidc_authorize` | OIDC authorization code issued |
| `oidc_token` | OIDC token issued |
| `oidc_logout` | OIDC logout |
| `ldap_config_saved` | LDAP configuration saved |
| `ldap_config_removed` | LDAP configuration deleted |
| `ldap_config_imported` | LDAP config imported from setup script |
| `ldap_sync_user` | Single user synced from LDAP |
| `ldap_sync_all` | All LDAP users synced |
| `ldap_user_imported` | User imported from LDAP directory |
| `password_set` | User password was set (by admin or self-service) |
| `account_locked` | Account locked due to too many failed login attempts |
| `account_unlocked` | Account unlocked (by admin) |
| `impersonation` | Admin impersonated a user |

---

## Admin: Settings

### `GET /api/admin/settings`

**Auth:** Admin Key

Returns the current runtime settings.

```bash
curl -k -H "Authorization: Bearer ADMIN_KEY" \
  https://localhost:8080/api/admin/settings
```

**Response (200):**

```json
{
  "redirect_uris": ["https://myapp.example.com/callback"],
  "cors_origins": ["https://myapp.example.com"],
  "password_policy": {
    "min_length": 8,
    "require_uppercase": true,
    "require_lowercase": true,
    "require_digit": true,
    "require_special": false,
    "history_count": 5
  },
  "lockout": {
    "max_attempts": 5,
    "duration_minutes": 15
  },
  "rate_limiting": {
    "enabled": true,
    "requests_per_second": 10
  },
  "default_roles": ["user"],
  "audit_retention_days": 90,
  "deployment_name": "sauth",
  "auto_sso": false
}
```

---

### `PUT /api/admin/settings`

**Auth:** Admin Key

Update runtime settings. Only provided fields are updated.

**Request:**

```json
{
  "redirect_uris": ["https://myapp.example.com/callback", "https://other.example.com/callback"],
  "cors_origins": ["https://myapp.example.com"],
  "password_policy": {
    "min_length": 12,
    "require_uppercase": true,
    "require_lowercase": true,
    "require_digit": true,
    "require_special": true,
    "history_count": 10
  },
  "lockout": {
    "max_attempts": 3,
    "duration_minutes": 30
  },
  "rate_limiting": {
    "enabled": true,
    "requests_per_second": 5
  },
  "default_roles": ["user", "viewer"],
  "audit_retention_days": 180,
  "deployment_name": "prod-auth",
  "auto_sso": true
}
```

**Response (200):** Returns the full updated `RuntimeSettings` JSON (same shape as `GET`).

---

## Admin: Server

### `POST /api/admin/restart`

**Auth:** Admin Key

Triggers a graceful server restart. Active connections are allowed to complete before the server restarts.

```bash
curl -k -X POST -H "Authorization: Bearer ADMIN_KEY" \
  https://localhost:8080/api/admin/restart
```

**Response (200):**

```json
{"status": "restarting"}
```

---

## Admin: Database

### `GET /api/admin/database/info`

**Auth:** Admin Key

Returns information about the current database backend.

```bash
curl -k -H "Authorization: Bearer ADMIN_KEY" \
  https://localhost:8080/api/admin/database/info
```

**Response (200):**

```json
{
  "backend": "boltdb",
  "health": "ok",
  "size": 1048576,
  "rows": 350,
  "tables": {
    "users": 120,
    "sessions": 80,
    "audit": 150
  },
  "connection_stats": {}
}
```

---

### `POST /api/admin/database/test`

**Auth:** Admin Key

Test connectivity to a Postgres database. If the specified database does not exist, it is automatically created.

**Request:**

```json
{
  "postgres_url": "postgres://user:pass@localhost:5432/simpleauth?sslmode=disable"
}
```

**Response (200):**

```json
{"status": "ok"}
```

---

### `POST /api/admin/database/migrate`

**Auth:** Admin Key

Start a database migration between backends.

**Request (migrate to Postgres):**

```json
{
  "postgres_url": "postgres://user:pass@localhost:5432/simpleauth?sslmode=disable",
  "direction": "to_postgres"
}
```

**Request (migrate to BoltDB):**

```json
{
  "direction": "to_boltdb"
}
```

**Response (200):**

```json
{"status": "migration_started"}
```

---

### `GET /api/admin/database/migrate/status`

**Auth:** Admin Key

Returns the current migration progress.

```bash
curl -k -H "Authorization: Bearer ADMIN_KEY" \
  https://localhost:8080/api/admin/database/migrate/status
```

**Response (200):**

```json
{
  "state": "migrating",
  "progress": {
    "users": {"total": 120, "migrated": 80},
    "sessions": {"total": 80, "migrated": 80},
    "audit": {"total": 150, "migrated": 45}
  },
  "items": {
    "total": 350,
    "migrated": 205
  }
}
```

| Field | Description |
|---|---|
| `state` | `idle`, `migrating`, `completed`, or `failed` |
| `progress` | Per-table migration counts |
| `items` | Aggregate item counts across all tables |

---

### `POST /api/admin/database/switch`

**Auth:** Admin Key

Switch the active database backend. Saves the backend choice to `db.json` and automatically triggers a server restart.

**Request (switch to Postgres):**

```json
{
  "backend": "postgres",
  "postgres_url": "postgres://user:pass@localhost:5432/simpleauth?sslmode=disable"
}
```

**Request (switch to BoltDB):**

```json
{
  "backend": "boltdb"
}
```

**Response (200):**

```json
{"status": "switched", "backend": "postgres"}
```

The server will restart automatically after responding.

---

## Admin: Linux SSO

### `GET /api/admin/linux-setup-script`

**Auth:** Admin Key

Download a bash script for setting up Linux Kerberos SSO. The script has the SimpleAuth hostname pre-injected and handles Kerberos client configuration, keytab setup, and SPN registration on Linux hosts.

Returns a `.sh` file.

```bash
curl -k -H "Authorization: Bearer ADMIN_KEY" \
  https://localhost:8080/api/admin/linux-setup-script -o linux-sso-setup.sh
```

---

## Security Notes

- **Timing-safe admin key comparison** -- The admin key is compared using a constant-time comparison function to prevent timing side-channel attacks.
- **CSRF protection on login forms** -- Login form submissions include CSRF tokens to prevent cross-site request forgery.
- **Rate limiting behind reverse proxies** -- If SimpleAuth is deployed behind a reverse proxy (nginx, Caddy, etc.), configure `AUTH_TRUSTED_PROXIES` so that rate limiting uses the real client IP from `X-Forwarded-For` headers instead of the proxy's IP.
- **Redirect URI validation** -- If the configured redirect URI list is empty, all redirect requests are rejected. This is a secure default -- you must explicitly allow at least one redirect URI for OAuth/OIDC flows to work.

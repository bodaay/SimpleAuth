# SimpleAuth API Reference

> **Base URL:** All endpoints are served under the base path (default: `/sauth`).
> Example: `https://auth.example.com/sauth/api/auth/login`
>
> **Admin endpoints** require `Authorization: Bearer <admin-key>` header.
> **User endpoints** require `Authorization: Bearer <access-token>` header.

Complete reference for every endpoint. All endpoints return JSON. All request bodies are JSON unless noted otherwise.

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
curl -k https://auth.example.com/sauth/health
```

**Response (200):**

```json
{"status": "ok"}
```

**Error response (503):**

```json
{"status": "unavailable"}
```

### `GET /api/admin/server-info`

**Auth:** Admin Key

Returns server configuration details.

```bash
curl -k -H "Authorization: Bearer ADMIN_KEY" \
  https://auth.example.com/sauth/api/admin/server-info
```

**Response (200):**

```json
{
  "hostname": "auth.corp.local",
  "deployment_name": "sauth",
  "jwt_issuer": "simpleauth",
  "version": "dev",
  "redirect_uri": "https://myapp.example.com/callback"
}
```

**Error response (401):**

```json
{"error": "unauthorized"}
```

---

## Authentication

### `POST /api/auth/login`

**Auth:** None

Authenticate a user with username/password. Tries local password first, falls back to LDAP (if configured). Local users always take priority — SimpleAuth owns those credentials.

**Request:**

```bash
curl -k -X POST https://auth.example.com/sauth/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "username": "jsmith",
    "password": "secret"
  }'
```

**Response (200):**

```json
{
  "access_token": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiI1NTBlODQwMC1lMjliLTQxZDQtYTcxNi00NDY2NTU0NDAwMDAiLCJpc3MiOiJzaW1wbGVhdXRoIiwiZXhwIjoxNzAwMDAwMDAwfQ...",
  "refresh_token": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJmYW1pbHlfaWQiOiJmYW0teHh4eCIsInNlcSI6MX0...",
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

**Error response (400):**

```json
{"error": "username and password required"}
```

**Error response (401):**

```json
{"error": "invalid credentials"}
```

**Error response (403):**

```json
{"error": "account disabled"}
```

**Error response (429):**

Returns a `Retry-After` header indicating how many seconds to wait.

```json
{"error": "too many login attempts"}
```

---

### `POST /api/auth/refresh`

**Auth:** None

Exchange a refresh token for a new access token. Implements refresh token rotation with family-based reuse detection.

> **Important:** Each call returns a NEW `refresh_token`. You MUST store and use this new refresh token for subsequent refresh calls. The old refresh token is invalidated immediately. If you replay an old refresh token, SimpleAuth treats it as a token theft attempt and revokes the entire token family (all sessions for that login).

```bash
curl -k -X POST https://auth.example.com/sauth/api/auth/refresh \
  -H "Content-Type: application/json" \
  -d '{
    "refresh_token": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJmYW1pbHlfaWQiOiJmYW0teHh4eCIsInNlcSI6MX0..."
  }'
```

**Response (200):**

```json
{
  "access_token": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiI1NTBlODQwMCIsImlzcyI6InNpbXBsZWF1dGgiLCJleHAiOjE3MDAwMjg4MDB9...",
  "refresh_token": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJmYW1pbHlfaWQiOiJmYW0teHh4eCIsInNlcSI6Mn0..."
}
```

**Error response (401 -- expired or malformed):**

```json
{"error": "invalid refresh token"}
```

**Error response (401 -- replay attack detected):**

```json
{"error": "token reuse detected, all sessions revoked"}
```

> **Security note:** If a refresh token is reused (replayed), SimpleAuth revokes the entire token family, invalidating all sessions for that login. This protects against token theft.

---

### `GET /api/auth/userinfo`

**Auth:** Bearer Token

Returns user information from a valid access token.

```bash
curl -k -H "Authorization: Bearer ACCESS_TOKEN" \
  https://auth.example.com/sauth/api/auth/userinfo
```

**Response (200):**

```json
{
  "guid": "550e8400-e29b-41d4-a716-446655440000",
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

**Error response (401):**

```json
{"error": "invalid token"}
```

---

### `POST /api/auth/impersonate`

**Auth:** Admin Key (master admin key only)

Generate an access token for any user. Useful for testing and support scenarios.

```bash
curl -k -X POST https://auth.example.com/sauth/api/auth/impersonate \
  -H "Authorization: Bearer ADMIN_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "target_guid": "550e8400-e29b-41d4-a716-446655440000"
  }'
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

**Error response (401):**

```json
{"error": "unauthorized"}
```

---

### `GET /api/auth/negotiate`

**Auth:** None (Kerberos SPNEGO)

Kerberos/SPNEGO authentication endpoint. The client sends an `Authorization: Negotiate <base64-token>` header. On success, returns JWT tokens.

```bash
curl -k --negotiate -u : \
  https://auth.example.com/sauth/api/auth/negotiate
```

**Response (200):**

```json
{
  "access_token": "eyJ...",
  "refresh_token": "eyJ...",
  "user": { ... }
}
```

**Error response (401):**

Returns `WWW-Authenticate: Negotiate` header (prompts browser to send Kerberos ticket).

---

### `POST /api/auth/reset-password`

**Auth:** Bearer Token

Change the authenticated user's password. Requires a valid access token. If the user already has a password set, the current password must be provided -- unless `force_password_change` is set on the user, in which case `current_password` is not required.

Enforces the configured password policy (minimum length, complexity requirements). Rejects passwords that appear in the user's password history (based on `history_count` setting). On success, clears the `force_password_change` flag.

```bash
curl -k -X POST https://auth.example.com/sauth/api/auth/reset-password \
  -H "Authorization: Bearer ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "current_password": "oldpass",
    "new_password": "N3wP@ssw0rd!"
  }'
```

**Response (200):**

```json
{"status": "password updated"}
```

**Error response (401):**

```json
{"error": "authorization required"}
```

**Error response (400 -- policy violation):**

```json
{"error": "password does not meet policy requirements: must contain at least one uppercase letter"}
```

**Error response (400 -- history check):**

```json
{"error": "password was recently used"}
```

**Error response (403):**

```json
{"error": "current password is incorrect"}
```

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

### `GET /logout`

**Auth:** None

Logout endpoint. Clears SSO cookies and redirects to the login page with `manual=1` to prevent auto-SSO from immediately logging the user back in.

**Query parameters:**
- `redirect_uri` -- Passed through to the login page redirect

**Behavior:**

```
GET https://auth.example.com/sauth/logout?redirect_uri=https://myapp.example.com/callback
  -> clears SSO cookies
  -> 302 redirect to /login?manual=1&redirect_uri=https://myapp.example.com/callback
```

This is the **recommended logout path** for apps using auto-SSO (`AUTH_AUTO_SSO=true`). If your app redirects to `/login` after logout, auto-SSO may immediately re-authenticate the user without showing the login form. Redirecting to `/logout` instead ensures the SSO session is cleared first.

> **Not a breaking change.** `/login` continues to work as before. `/logout` is an additive endpoint.

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

## OIDC Endpoints

SimpleAuth implements standard OIDC endpoints. All official SDKs (Go, JavaScript, Python, .NET) use the direct API endpoints by default (`POST /api/auth/login`, `POST /api/auth/refresh`, `GET /.well-known/jwks.json`, `GET /api/auth/userinfo`), but the OIDC endpoints are fully supported for use with any standard OIDC library.

All OIDC endpoints follow the URL pattern: `/realms/{realm}/protocol/openid-connect/...`

The realm defaults to your `jwt_issuer` config value (default: `simpleauth`). The `client_id` is always `simpleauth` -- no `client_secret` is needed (the field is accepted but not validated).

### `GET /.well-known/openid-configuration`

**Auth:** None

OIDC Discovery document. Also available at `/realms/{realm}/.well-known/openid-configuration`.

```bash
curl -k https://auth.example.com/sauth/.well-known/openid-configuration
```

**Response (200):**

```json
{
  "issuer": "https://auth.example.com/sauth/realms/simpleauth",
  "authorization_endpoint": "https://auth.example.com/sauth/realms/simpleauth/protocol/openid-connect/auth",
  "token_endpoint": "https://auth.example.com/sauth/realms/simpleauth/protocol/openid-connect/token",
  "userinfo_endpoint": "https://auth.example.com/sauth/realms/simpleauth/protocol/openid-connect/userinfo",
  "jwks_uri": "https://auth.example.com/sauth/realms/simpleauth/protocol/openid-connect/certs",
  "introspection_endpoint": "https://auth.example.com/sauth/realms/simpleauth/protocol/openid-connect/token/introspect",
  "end_session_endpoint": "https://auth.example.com/sauth/realms/simpleauth/protocol/openid-connect/logout",
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
curl -k https://auth.example.com/sauth/.well-known/jwks.json
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
      "n": "0vx7agoebGcQSuu...",
      "e": "AQAB"
    }
  ]
}
```

**Error response (500):**

```json
{"error": "failed to load signing key"}
```

---

### `GET /realms/{realm}/protocol/openid-connect/auth`

**Auth:** None

OAuth2 Authorization endpoint. Renders the hosted login page for the authorization code flow.

**Query parameters:**
- `client_id` (required) -- Must be `simpleauth`
- `redirect_uri` -- Where to redirect after login (must match one of the allowed redirect URIs configured via `AUTH_REDIRECT_URI` and/or `AUTH_REDIRECT_URIS`; supports wildcard `*` suffix matching)
- `response_type` -- Must be `code`
- `state` -- CSRF protection value (passed through)
- `nonce` -- Replay protection for ID tokens
- `scope` -- Space-separated scopes (e.g., `openid profile email`)

**Complete URL with all query parameters:**

```
https://auth.example.com/sauth/realms/simpleauth/protocol/openid-connect/auth?client_id=simpleauth&redirect_uri=https%3A%2F%2Fmyapp.example.com%2Fcallback&response_type=code&state=random-csrf-state-value&nonce=random-nonce-value&scope=openid%20profile%20email
```

On successful login, redirects to:

```
https://myapp.example.com/callback?code=AUTH_CODE_HERE&state=random-csrf-state-value
```

**Error response (400 -- invalid client_id):**

```json
{"error": "invalid_request", "error_description": "invalid client_id"}
```

---

### `POST /realms/{realm}/protocol/openid-connect/token`

**Auth:** Client credentials (Basic auth or form post)

OAuth2 Token endpoint. Supports four grant types.

**Client authentication methods:**
- HTTP Basic: `Authorization: Basic base64(simpleauth:any-value)`
- Form body: `client_id=simpleauth`

The `client_id` is always `simpleauth`. No `client_secret` is needed (the field is accepted but not validated).

#### Authorization Code Grant

```bash
curl -k -X POST \
  https://auth.example.com/sauth/realms/simpleauth/protocol/openid-connect/token \
  -d "grant_type=authorization_code" \
  -d "code=AUTH_CODE_FROM_REDIRECT" \
  -d "redirect_uri=https://myapp.example.com/callback" \
  -d "client_id=simpleauth"
```

**Response (200):**

```json
{
  "access_token": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiI1NTBlODQwMCIsImlzcyI6InNpbXBsZWF1dGgiLCJleHAiOjE3MDAwMjg4MDB9...",
  "refresh_token": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJmYW1pbHlfaWQiOiJmYW0teHh4eCIsInNlcSI6MX0...",
  "id_token": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiI1NTBlODQwMCIsIm5hbWUiOiJKb2huIFNtaXRoIn0...",
  "token_type": "Bearer",
  "expires_in": 28800,
  "scope": "openid profile email"
}
```

**Error response (400):**

```json
{
  "error": "invalid_grant",
  "error_description": "authorization code expired or already used"
}
```

#### Resource Owner Password Grant

```bash
curl -k -X POST \
  https://auth.example.com/sauth/realms/simpleauth/protocol/openid-connect/token \
  -d "grant_type=password" \
  -d "username=jsmith" \
  -d "password=secret" \
  -d "scope=openid profile email" \
  -d "client_id=simpleauth"
```

**Response (200):**

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

**Error response (401):**

```json
{
  "error": "invalid_grant",
  "error_description": "invalid credentials"
}
```

#### Client Credentials Grant

```bash
curl -k -X POST \
  https://auth.example.com/sauth/realms/simpleauth/protocol/openid-connect/token \
  -d "grant_type=client_credentials" \
  -d "client_id=simpleauth"
```

**Response (200):**

```json
{
  "access_token": "eyJ...",
  "token_type": "Bearer",
  "expires_in": 28800
}
```

#### Refresh Token Grant

```bash
curl -k -X POST \
  https://auth.example.com/sauth/realms/simpleauth/protocol/openid-connect/token \
  -d "grant_type=refresh_token" \
  -d "refresh_token=eyJ..." \
  -d "client_id=simpleauth"
```

**Response (200):**

```json
{
  "access_token": "eyJ...(new)",
  "refresh_token": "eyJ...(new, rotated)",
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
  https://auth.example.com/sauth/realms/simpleauth/protocol/openid-connect/userinfo
```

**Response (200):**

```json
{
  "sub": "550e8400-e29b-41d4-a716-446655440000",
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

**Error response (401):**

```json
{"error": "invalid token"}
```

---

### `POST /realms/{realm}/protocol/openid-connect/token/introspect`

**Auth:** Client credentials

RFC 7662 Token Introspection. Validates a token and returns its claims.

```bash
curl -k -X POST \
  https://auth.example.com/sauth/realms/simpleauth/protocol/openid-connect/token/introspect \
  -d "token=eyJ..." \
  -d "client_id=simpleauth"
```

**Response (200) -- active token:**

```json
{
  "active": true,
  "sub": "550e8400-e29b-41d4-a716-446655440000",
  "iss": "https://auth.example.com/sauth/realms/simpleauth",
  "exp": 1700000000,
  "iat": 1699971200,
  "token_type": "Bearer",
  "client_id": "simpleauth",
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
  https://auth.example.com/sauth/realms/simpleauth/protocol/openid-connect/logout \
  -d "id_token_hint=eyJ...&post_logout_redirect_uri=https://myapp.example.com"
```

**Error response (400):**

```json
{"error": "invalid_request", "error_description": "id_token_hint is required"}
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
  https://auth.example.com/sauth/api/admin/users
```

**With identities:**

```bash
curl -k -H "Authorization: Bearer ADMIN_KEY" \
  "https://auth.example.com/sauth/api/admin/users?include=identities"
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

**Error response (401):**

```json
{"error": "unauthorized"}
```

---

### `POST /api/admin/users`

**Auth:** Admin Key

Create a local user.

```bash
curl -k -X POST https://auth.example.com/sauth/api/admin/users \
  -H "Authorization: Bearer ADMIN_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "username": "jsmith",
    "password": "a-strong-password",
    "display_name": "John Smith",
    "email": "jsmith@example.com",
    "department": "Engineering",
    "company": "Acme Corp",
    "job_title": "Senior Engineer"
  }'
```

The `username` field creates a `local` identity mapping (e.g., `local:jsmith`). The `password` field is optional — if omitted, the user can only authenticate via LDAP. If a password is provided, it must satisfy the configured password policy (minimum length, complexity requirements).

**Response (201):**

```json
{
  "guid": "550e8400-e29b-41d4-a716-446655440000",
  "display_name": "John Smith",
  "email": "jsmith@example.com"
}
```

**Error response (400):**

```json
{"error": "username already exists"}
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
  "https://auth.example.com/sauth/api/admin/users/550e8400-e29b-41d4-a716-446655440000?include=identities"
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

**Error response (404):**

```json
{"error": "user not found"}
```

---

### `PUT /api/admin/users/{guid}`

**Auth:** Admin Key

Update user fields. Only provided fields are updated.

```bash
curl -k -X PUT https://auth.example.com/sauth/api/admin/users/550e8400-e29b-41d4-a716-446655440000 \
  -H "Authorization: Bearer ADMIN_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "display_name": "Jonathan Smith",
    "email": "jonathan.smith@example.com",
    "department": "Platform",
    "company": "Acme Corp",
    "job_title": "Staff Engineer"
  }'
```

**Error response (404):**

```json
{"error": "user not found"}
```

---

### `DELETE /api/admin/users/{guid}`

**Auth:** Admin Key

Delete a user.

```bash
curl -k -X DELETE \
  -H "Authorization: Bearer ADMIN_KEY" \
  https://auth.example.com/sauth/api/admin/users/550e8400-e29b-41d4-a716-446655440000
```

**Error response (404):**

```json
{"error": "user not found"}
```

---

### `PUT /api/admin/users/{guid}/password`

**Auth:** Admin Key

Set a user's password (admin override, no current password required).

```bash
curl -k -X PUT https://auth.example.com/sauth/api/admin/users/550e8400-e29b-41d4-a716-446655440000/password \
  -H "Authorization: Bearer ADMIN_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "password": "new-password-here",
    "force_change": true
  }'
```

| Field | Description |
|---|---|
| `password` | The new password to set |
| `force_change` | Optional boolean. If `true`, the user will be required to change their password on next login |

**Error response (400):**

```json
{"error": "password does not meet policy requirements: must be at least 8 characters"}
```

---

### `PUT /api/admin/users/{guid}/unlock`

**Auth:** Admin Key

Clears failed login attempts and lockout for a user. Use this to manually unlock an account that has been locked due to too many failed login attempts.

```bash
curl -k -X PUT \
  -H "Authorization: Bearer ADMIN_KEY" \
  https://auth.example.com/sauth/api/admin/users/550e8400-e29b-41d4-a716-446655440000/unlock
```

**Response (200):**

```json
{"status": "ok"}
```

---

### `PUT /api/admin/users/{guid}/disabled`

**Auth:** Admin Key

Enable or disable a user account. Disabled users cannot log in.

```bash
curl -k -X PUT https://auth.example.com/sauth/api/admin/users/550e8400-e29b-41d4-a716-446655440000/disabled \
  -H "Authorization: Bearer ADMIN_KEY" \
  -H "Content-Type: application/json" \
  -d '{"disabled": true}'
```

**Response (200):**

```json
{"guid": "550e8400-e29b-41d4-a716-446655440000", "disabled": true}
```

---

### `POST /api/admin/users/merge`

**Auth:** Admin Key

Merge multiple user records into one. This is useful when the same person has separate accounts from different identity sources. Identity mappings, roles, and permissions are all merged.

```bash
curl -k -X POST https://auth.example.com/sauth/api/admin/users/merge \
  -H "Authorization: Bearer ADMIN_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "source_guids": ["guid-1", "guid-2"],
    "display_name": "John Smith",
    "email": "jsmith@corp.local"
  }'
```

**Response (200):**

```json
{
  "merged_guid": "new-guid",
  "sources": ["guid-1", "guid-2"]
}
```

**Error response (400):**

```json
{"error": "at least 2 source GUIDs required"}
```

---

### `POST /api/admin/users/{guid}/unmerge`

**Auth:** Admin Key

Reverse a merge operation. The user record has its `merged_into` pointer cleared.

```bash
curl -k -X POST \
  -H "Authorization: Bearer ADMIN_KEY" \
  https://auth.example.com/sauth/api/admin/users/550e8400-e29b-41d4-a716-446655440000/unmerge
```

---

### `GET /api/admin/users/{guid}/sessions`

**Auth:** Admin Key

List active sessions (non-expired, non-used refresh tokens) for a user.

```bash
curl -k -H "Authorization: Bearer ADMIN_KEY" \
  https://auth.example.com/sauth/api/admin/users/550e8400-e29b-41d4-a716-446655440000/sessions
```

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

```bash
curl -k -X DELETE \
  -H "Authorization: Bearer ADMIN_KEY" \
  https://auth.example.com/sauth/api/admin/users/550e8400-e29b-41d4-a716-446655440000/sessions
```

**Response (200):**

```json
{"status": "ok"}
```

---

## Roles & Permissions Model

SimpleAuth is the authority for roles and permissions -- they must be defined in the registries before they can be assigned to users. Use `PUT /api/admin/role-permissions` to define roles (and their associated permissions) and `PUT /api/admin/permissions` to define the master permissions list. On first startup, any roles or permissions already assigned to existing users are automatically registered into the respective registries.

---

## Admin: Roles & Permissions

Roles and permissions are global per SimpleAuth instance.

### `GET /api/admin/users/{guid}/roles`

**Auth:** Admin Key

Get a user's roles.

```bash
curl -k -H "Authorization: Bearer ADMIN_KEY" \
  https://auth.example.com/sauth/api/admin/users/550e8400-e29b-41d4-a716-446655440000/roles
```

**Response (200):**

```json
["admin", "user"]
```

---

### `PUT /api/admin/users/{guid}/roles`

**Auth:** Admin Key

Set a user's roles. Replaces the entire role list.

> **Note:** All roles must be defined in the role registry first (via `PUT /api/admin/role-permissions`), otherwise a `400` error is returned.

```bash
curl -k -X PUT https://auth.example.com/sauth/api/admin/users/550e8400-e29b-41d4-a716-446655440000/roles \
  -H "Authorization: Bearer ADMIN_KEY" \
  -H "Content-Type: application/json" \
  -d '["admin", "user", "manager"]'
```

**Error response (400):**

```json
{"error": "unknown roles: [manager]"}
```

---

### `GET /api/admin/users/{guid}/permissions`

**Auth:** Admin Key

Get a user's permissions.

```bash
curl -k -H "Authorization: Bearer ADMIN_KEY" \
  https://auth.example.com/sauth/api/admin/users/550e8400-e29b-41d4-a716-446655440000/permissions
```

**Response (200):**

```json
["read:reports", "write:config"]
```

---

### `PUT /api/admin/users/{guid}/permissions`

**Auth:** Admin Key

Set a user's permissions.

> **Note:** All permissions must be defined in the permissions registry first (via `PUT /api/admin/permissions`), otherwise a `400` error is returned.

```bash
curl -k -X PUT https://auth.example.com/sauth/api/admin/users/550e8400-e29b-41d4-a716-446655440000/permissions \
  -H "Authorization: Bearer ADMIN_KEY" \
  -H "Content-Type: application/json" \
  -d '["read:reports", "write:config", "delete:users"]'
```

**Error response (400):**

```json
{"error": "unknown permissions: [delete:users]"}
```

---

### `GET /api/admin/defaults/roles`

**Auth:** Admin Key

Get default roles that are automatically assigned to new users when they first log in. Can also be set via the `AUTH_DEFAULT_ROLES` environment variable.

```bash
curl -k -H "Authorization: Bearer ADMIN_KEY" \
  https://auth.example.com/sauth/api/admin/defaults/roles
```

---

### `PUT /api/admin/defaults/roles`

**Auth:** Admin Key

Set default roles for new users.

> **Note:** Default roles must be defined in the role registry first (via `PUT /api/admin/role-permissions`).

```bash
curl -k -X PUT https://auth.example.com/sauth/api/admin/defaults/roles \
  -H "Authorization: Bearer ADMIN_KEY" \
  -H "Content-Type: application/json" \
  -d '["user", "viewer"]'
```

---

### `GET /api/admin/role-permissions`

**Auth:** Admin Key

Get the role-to-permissions mapping. This defines which permissions are automatically granted by each role.

```bash
curl -k -H "Authorization: Bearer ADMIN_KEY" \
  https://auth.example.com/sauth/api/admin/role-permissions
```

---

### `PUT /api/admin/role-permissions`

**Auth:** Admin Key

Set the role-to-permissions mapping.

> **Note:** All permissions referenced in the mapping must be defined in the permissions registry first (via `PUT /api/admin/permissions`).

```bash
curl -k -X PUT https://auth.example.com/sauth/api/admin/role-permissions \
  -H "Authorization: Bearer ADMIN_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "admin": ["read:all", "write:all", "delete:all"],
    "editor": ["read:all", "write:all"],
    "viewer": ["read:all"]
  }'
```

---

### `GET /api/admin/roles`

**Auth:** Admin Key

Returns all defined roles from the role registry.

```bash
curl -k -H "Authorization: Bearer ADMIN_KEY" \
  https://auth.example.com/sauth/api/admin/roles
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
  https://auth.example.com/sauth/api/admin/permissions
```

```json
["delete:all", "read:all", "write:all"]
```

---

### `PUT /api/admin/permissions`

**Auth:** Admin Key

Sets the master permissions list. Replaces the entire permissions registry.

```bash
curl -k -X PUT https://auth.example.com/sauth/api/admin/permissions \
  -H "Authorization: Bearer ADMIN_KEY" \
  -H "Content-Type: application/json" \
  -d '["read:all", "write:all", "delete:all", "read:reports", "write:config"]'
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
  https://auth.example.com/sauth/api/admin/password-policy
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
  https://auth.example.com/sauth/api/admin/bootstrap \
  -H "Authorization: Bearer ADMIN_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "permissions": ["posts:read", "posts:write", "users:manage", "admin:access"],
    "role_permissions": {
      "viewer": ["posts:read"],
      "editor": ["posts:read", "posts:write"],
      "admin": ["posts:read", "posts:write", "users:manage", "admin:access"]
    },
    "users": [
      {
        "username": "root",
        "password": "R00t@dmin!2024",
        "display_name": "Root Admin",
        "email": "root@example.com",
        "roles": ["admin"],
        "permissions": ["admin:access"],
        "force_password": true
      },
      {
        "username": "editor1",
        "password": "Ed1t0r!Pass",
        "display_name": "Content Editor",
        "email": "editor@example.com",
        "roles": ["editor"]
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
    },
    {
      "username": "editor1",
      "guid": "660e8400-e29b-41d4-a716-446655440001",
      "created": true
    }
  ],
  "permissions_count": 4,
  "role_permissions_count": 3
}
```

| Field | Type | Description |
|---|---|---|
| `users` | array | One entry per user in the request. `created` is `true` if the user was newly created, `false` if it already existed |
| `permissions_count` | integer | Number of permissions defined (only present if `permissions` was provided) |
| `role_permissions_count` | integer | Number of roles defined (only present if `role_permissions` was provided) |

**Error response (400):**

```json
{"error": "unknown roles: [nonexistent-role]"}
```

---

## Admin: LDAP Configuration

SimpleAuth supports a single LDAP/Active Directory configuration. All LDAP endpoints are under `/api/admin/ldap` (no provider IDs).

### `GET /api/admin/ldap`

**Auth:** Admin Key

Get the current LDAP configuration. Returns `null` if not configured. The bind password is masked in the response.

```bash
curl -k -H "Authorization: Bearer ADMIN_KEY" \
  https://auth.example.com/sauth/api/admin/ldap
```

---

### `PUT /api/admin/ldap`

**Auth:** Admin Key

Save or update the LDAP configuration.

```bash
curl -k -X PUT https://auth.example.com/sauth/api/admin/ldap \
  -H "Authorization: Bearer ADMIN_KEY" \
  -H "Content-Type: application/json" \
  -d '{
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
  }'
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

```bash
curl -k -X DELETE \
  -H "Authorization: Bearer ADMIN_KEY" \
  https://auth.example.com/sauth/api/admin/ldap
```

---

### `POST /api/admin/ldap/test`

**Auth:** Admin Key

Test connectivity and bind credentials for the saved LDAP configuration.

```bash
curl -k -X POST \
  -H "Authorization: Bearer ADMIN_KEY" \
  https://auth.example.com/sauth/api/admin/ldap/test
```

**Response (200):**

```json
{"status": "ok"}
```

**Error response (200 with error status):**

```json
{"status": "error", "error": "connection refused"}
```

---

### `POST /api/admin/ldap/test-user`

**Auth:** Admin Key

Search for a user in LDAP and preview the mapped attributes. Useful for verifying attribute mapping before importing users.

```bash
curl -k -X POST https://auth.example.com/sauth/api/admin/ldap/test-user \
  -H "Authorization: Bearer ADMIN_KEY" \
  -H "Content-Type: application/json" \
  -d '{"username": "alice"}'
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

**Error response (404):**

```json
{"status": "error", "error": "user not found"}
```

---

### `POST /api/admin/ldap/auto-discover`

**Auth:** Admin Key

Auto-discover LDAP configuration by connecting to a server, querying RootDSE for the base DN, and detecting whether it's Active Directory or OpenLDAP (to choose the correct `username_attr`). Saves the configuration on success.

```bash
curl -k -X POST https://auth.example.com/sauth/api/admin/ldap/auto-discover \
  -H "Authorization: Bearer ADMIN_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "server": "dc01.corp.local",
    "username": "svc-simpleauth",
    "password": "ServicePassword"
  }'
```

The server can be a hostname, `hostname:port`, or full URL (`ldap://` or `ldaps://`). Default port is 389 for ldap, 636 for ldaps.

**Response (200):** Returns the discovered and saved LDAP configuration (with masked password).

---

### `POST /api/admin/ldap/import`

**Auth:** Admin Key

Import LDAP configuration from the PowerShell setup script JSON output.

```bash
curl -k -X POST https://auth.example.com/sauth/api/admin/ldap/import \
  -H "Authorization: Bearer ADMIN_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "server": "dc01.corp.local",
    "username": "svc-simpleauth",
    "password": "ServicePassword",
    "domain": "corp.local",
    "base_dn": "DC=corp,DC=local",
    "service_hostname": "auth.corp.local",
    "spn": "HTTP/auth.corp.local"
  }'
```

If `service_hostname` is provided, Kerberos setup is automatically triggered after the LDAP config is saved.

---

### `POST /api/admin/ldap/search-users`

**Auth:** Admin Key

Search the LDAP directory for users matching a query string. Searches across username, display name, and email attributes. Returns whether each user is already imported into SimpleAuth.

```bash
curl -k -X POST https://auth.example.com/sauth/api/admin/ldap/search-users \
  -H "Authorization: Bearer ADMIN_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "query": "john",
    "limit": 50
  }'
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

```bash
curl -k -X POST https://auth.example.com/sauth/api/admin/ldap/import-users \
  -H "Authorization: Bearer ADMIN_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "usernames": ["alice", "bob", "charlie"]
  }'
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

```bash
curl -k -X POST \
  https://auth.example.com/sauth/api/admin/ldap/sync-user \
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

**Error response (404):**

```json
{"status": "error", "error": "user not found in LDAP"}
```

---

### `POST /api/admin/ldap/sync-all`

**Auth:** Admin Key

Sync all users that have `ldap` identity mappings. Iterates all non-merged users with an LDAP mapping and updates their profiles from the directory.

```bash
curl -k -X POST \
  https://auth.example.com/sauth/api/admin/ldap/sync-all \
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

```bash
curl -k -X POST https://auth.example.com/sauth/api/admin/ldap/setup-kerberos \
  -H "Authorization: Bearer ADMIN_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "admin_username": "admin@CORP.LOCAL",
    "admin_password": "AdminPassword"
  }'
```

---

### `POST /api/admin/ldap/cleanup-kerberos`

**Auth:** Admin Key

Remove Kerberos configuration (delete SPN, clean up keytab).

```bash
curl -k -X POST \
  -H "Authorization: Bearer ADMIN_KEY" \
  https://auth.example.com/sauth/api/admin/ldap/cleanup-kerberos
```

---

### `GET /api/admin/kerberos/status`

**Auth:** Admin Key

Check the status of Kerberos configuration (keytab exists, SPN configured, etc.).

```bash
curl -k -H "Authorization: Bearer ADMIN_KEY" \
  https://auth.example.com/sauth/api/admin/kerberos/status
```

---

### `GET /api/admin/setup-script`

**Auth:** Admin Key

Download an interactive PowerShell script for AD setup. The script has the SimpleAuth hostname pre-injected and offers:
- Create a new service account or use an existing one
- OU selection for new accounts
- SPN registration for Kerberos
- Config JSON export for one-click import into the admin UI

Returns a `.ps1` file with UTF-8 BOM encoding.

```bash
curl -k -H "Authorization: Bearer ADMIN_KEY" \
  https://auth.example.com/sauth/api/admin/setup-script -o setup-ad.ps1
```

---

## Admin: Identity Mappings

Identity mappings link external identities (LDAP usernames, local usernames) to SimpleAuth user GUIDs. This is how SimpleAuth tracks that "jsmith" in AD is the same person across logins.

**Provider names:**
- `local` -- Local username/password authentication
- `ldap` -- LDAP/Active Directory authentication

### `GET /api/admin/mappings`

**Auth:** Admin Key

List all identity mappings.

```bash
curl -k -H "Authorization: Bearer ADMIN_KEY" \
  https://auth.example.com/sauth/api/admin/mappings
```

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

```bash
curl -k -H "Authorization: Bearer ADMIN_KEY" \
  https://auth.example.com/sauth/api/admin/users/550e8400-e29b-41d4-a716-446655440000/mappings
```

---

### `PUT /api/admin/users/{guid}/mappings`

**Auth:** Admin Key

Create or update an identity mapping.

```bash
curl -k -X PUT https://auth.example.com/sauth/api/admin/users/550e8400-e29b-41d4-a716-446655440000/mappings \
  -H "Authorization: Bearer ADMIN_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "provider": "ldap",
    "external_id": "jsmith"
  }'
```

---

### `DELETE /api/admin/users/{guid}/mappings/{provider}/{external_id}`

**Auth:** Admin Key

Delete an identity mapping.

```bash
curl -k -X DELETE \
  -H "Authorization: Bearer ADMIN_KEY" \
  https://auth.example.com/sauth/api/admin/users/550e8400-e29b-41d4-a716-446655440000/mappings/ldap/jsmith
```

---

### `GET /api/admin/mappings/resolve`

**Auth:** Admin Key

Resolve an external identity to a SimpleAuth user GUID.

**Query parameters:**
- `provider` -- The identity provider (e.g., `ldap`, `local`)
- `external_id` -- The external identifier

```bash
curl -k -H "Authorization: Bearer ADMIN_KEY" \
  "https://auth.example.com/sauth/api/admin/mappings/resolve?provider=local&external_id=jsmith"
```

**Response (200):**

```json
{"guid": "550e8400-..."}
```

**Error response (404):**

```json
{"error": "mapping not found"}
```

---

## Admin: Backup & Restore

### `GET /api/admin/backup`

**Auth:** Admin Key

Download a complete database backup as a binary file.

```bash
curl -k -H "Authorization: Bearer ADMIN_KEY" \
  https://auth.example.com/sauth/api/admin/backup -o backup.db
```

---

### `POST /api/admin/restore`

**Auth:** Admin Key

Restore from a backup file. Multipart form upload. **This replaces the entire database.**

```bash
curl -k -X POST -H "Authorization: Bearer ADMIN_KEY" \
  -F "file=@backup.db" \
  https://auth.example.com/sauth/api/admin/restore
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
  "https://auth.example.com/sauth/api/admin/audit?event=login_failed&from=2024-01-01&limit=50"
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
  https://auth.example.com/sauth/api/admin/settings
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
  "auto_sso": false,
  "auto_sso_delay": 3
}
```

**Error response (401):**

```json
{"error": "unauthorized"}
```

---

### `PUT /api/admin/settings`

**Auth:** Admin Key

Update runtime settings. Only provided fields are updated.

```bash
curl -k -X PUT https://auth.example.com/sauth/api/admin/settings \
  -H "Authorization: Bearer ADMIN_KEY" \
  -H "Content-Type: application/json" \
  -d '{
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
    "auto_sso": true,
    "auto_sso_delay": 5
  }'
```

**Response (200):** Returns the full updated `RuntimeSettings` JSON (same shape as `GET`).

**Error response (401):**

```json
{"error": "unauthorized"}
```

---

## Admin: Server

### `POST /api/admin/restart`

**Auth:** Admin Key

Triggers a graceful server restart. Active connections are allowed to complete before the server restarts.

```bash
curl -k -X POST -H "Authorization: Bearer ADMIN_KEY" \
  https://auth.example.com/sauth/api/admin/restart
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
  https://auth.example.com/sauth/api/admin/database/info
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

```bash
curl -k -X POST https://auth.example.com/sauth/api/admin/database/test \
  -H "Authorization: Bearer ADMIN_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "postgres_url": "postgres://user:pass@localhost:5432/simpleauth?sslmode=disable"
  }'
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

```bash
curl -k -X POST https://auth.example.com/sauth/api/admin/database/migrate \
  -H "Authorization: Bearer ADMIN_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "postgres_url": "postgres://user:pass@localhost:5432/simpleauth?sslmode=disable",
    "direction": "to_postgres"
  }'
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
  https://auth.example.com/sauth/api/admin/database/migrate/status
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

```bash
curl -k -X POST https://auth.example.com/sauth/api/admin/database/switch \
  -H "Authorization: Bearer ADMIN_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "backend": "postgres",
    "postgres_url": "postgres://user:pass@localhost:5432/simpleauth?sslmode=disable"
  }'
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
  https://auth.example.com/sauth/api/admin/linux-setup-script -o linux-sso-setup.sh
```

---

## Security Notes

- **Timing-safe admin key comparison** -- The admin key is compared using a constant-time comparison function to prevent timing side-channel attacks.
- **CSRF protection on login forms** -- Login form submissions include CSRF tokens to prevent cross-site request forgery.
- **Rate limiting behind reverse proxies** -- If SimpleAuth is deployed behind a reverse proxy (nginx, Caddy, etc.), configure `AUTH_TRUSTED_PROXIES` so that rate limiting uses the real client IP from `X-Forwarded-For` headers instead of the proxy's IP.
- **Redirect URI validation** -- If the configured redirect URI list is empty, all redirect requests are rejected. This is a secure default -- you must explicitly allow at least one redirect URI for OAuth/OIDC flows to work.

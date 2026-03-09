# SimpleAuth API Reference

Complete reference for every endpoint. All endpoints return JSON. All request bodies are JSON unless noted otherwise.

**Base URL:** `https://your-simpleauth-server:port`

**Authentication types:**
- **Admin Key** -- `Authorization: Bearer YOUR_ADMIN_KEY` (the master admin key from config)
- **App API Key** -- `Authorization: Bearer YOUR_APP_API_KEY` (the `api_key` returned when creating an app)
- **Bearer Token** -- `Authorization: Bearer ACCESS_TOKEN` (a JWT access token from login)
- **None** -- No authentication required

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
  "project_name": "default",
  "jwt_issuer": "simpleauth",
  "version": "dev"
}
```

---

## Authentication

### `POST /api/auth/login`

**Auth:** None

Authenticate a user with username/password. Tries LDAP providers first, falls back to local password.

**Request:**

```json
{
  "username": "jsmith",
  "password": "secret",
  "app_id": "app-a1b2c3d4"
}
```

- `app_id` is optional. When provided, SimpleAuth resolves the user via app-specific identity mappings and provider mappings. When omitted, it searches all LDAP providers and local users.

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
    "groups": ["CN=Engineering,OU=Groups,DC=corp,DC=local"]
  }
}
```

**Error responses:**
- `400` -- `{"error": "username and password required"}`
- `400` -- `{"error": "invalid app_id"}`
- `401` -- `{"error": "invalid credentials"}`
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
  "display_name": "John Smith",
  "email": "jsmith@corp.local",
  "roles": ["admin"],
  "permissions": ["read:reports"],
  "groups": ["CN=Engineering,..."]
}
```

---

### `POST /api/auth/impersonate`

**Auth:** Admin Key

Generate an access token for any user. Useful for testing and support scenarios.

**Request:**

```json
{
  "guid": "550e8400-...",
  "app_id": "app-a1b2c3d4"
}
```

**Response (200):**

```json
{
  "access_token": "eyJ..."
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

**Auth:** None

Reset a local user's password. Requires the current password.

**Request:**

```json
{
  "username": "jsmith",
  "current_password": "oldpass",
  "new_password": "newpass"
}
```

**Response (200):**

```json
{"status": "password updated"}
```

---

### `GET /login` / `POST /login`

**Auth:** None

Hosted login page. Renders a branded login form and handles form submission. Primarily used for the OIDC authorization code flow.

---

## OIDC / Keycloak-Compatible Endpoints

All OIDC endpoints follow the Keycloak URL pattern: `/realms/{realm}/protocol/openid-connect/...`

The realm defaults to your `jwt_issuer` config value (default: `simpleauth`).

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
    "preferred_username", "realm_access", "resource_access",
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
- `client_id` (required) -- App ID
- `redirect_uri` -- Where to redirect after login
- `response_type` -- Must be `code`
- `state` -- CSRF protection value (passed through)
- `nonce` -- Replay protection for ID tokens
- `scope` -- Space-separated scopes (e.g., `openid profile email`)

```
https://auth.example.com/realms/simpleauth/protocol/openid-connect/auth?client_id=app-abc&redirect_uri=https://myapp.com/callback&response_type=code&state=xyz
```

On successful login, redirects to `redirect_uri?code=AUTH_CODE&state=xyz`.

---

### `POST /realms/{realm}/protocol/openid-connect/token`

**Auth:** Client credentials (Basic auth or form post)

OAuth2 Token endpoint. Supports four grant types.

**Client authentication methods:**
- HTTP Basic: `Authorization: Basic base64(client_id:client_secret)`
- Form body: `client_id=...&client_secret=...`

#### Authorization Code Grant

```bash
curl -k -X POST \
  https://localhost:8080/realms/simpleauth/protocol/openid-connect/token \
  -u "app-abc:sk-xxxx" \
  -d "grant_type=authorization_code&code=AUTH_CODE&redirect_uri=https://myapp.com/callback"
```

#### Resource Owner Password Grant

```bash
curl -k -X POST \
  https://localhost:8080/realms/simpleauth/protocol/openid-connect/token \
  -u "app-abc:sk-xxxx" \
  -d "grant_type=password&username=jsmith&password=secret&scope=openid profile email"
```

#### Client Credentials Grant

```bash
curl -k -X POST \
  https://localhost:8080/realms/simpleauth/protocol/openid-connect/token \
  -u "app-abc:sk-xxxx" \
  -d "grant_type=client_credentials"
```

#### Refresh Token Grant

```bash
curl -k -X POST \
  https://localhost:8080/realms/simpleauth/protocol/openid-connect/token \
  -u "app-abc:sk-xxxx" \
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
  "groups": ["CN=Engineering,..."],
  "realm_access": {"roles": ["admin"]},
  "resource_access": {"app-abc": {"roles": ["admin"]}}
}
```

---

### `POST /realms/{realm}/protocol/openid-connect/token/introspect`

**Auth:** Client credentials

RFC 7662 Token Introspection. Validates a token and returns its claims.

```bash
curl -k -X POST \
  https://localhost:8080/realms/simpleauth/protocol/openid-connect/token/introspect \
  -u "app-abc:sk-xxxx" \
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
  "client_id": "app-abc",
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

## Admin: Apps

### `GET /api/admin/apps`

**Auth:** Admin Key or App API Key

List all registered applications.

```bash
curl -k -H "Authorization: Bearer ADMIN_KEY" \
  https://localhost:8080/api/admin/apps
```

**Response (200):**

```json
[
  {
    "app_id": "app-a1b2c3d4",
    "name": "My Web App",
    "description": "Our main application",
    "api_key": "sk-xxxx",
    "redirect_uris": ["https://myapp.example.com/callback"],
    "provider_mappings": {},
    "created_at": "2024-01-15T10:30:00Z"
  }
]
```

---

### `POST /api/admin/apps`

**Auth:** Admin Key

Create a new application.

**Request:**

```json
{
  "name": "My App",
  "description": "Optional description",
  "redirect_uris": ["https://myapp.example.com/callback"],
  "provider_mappings": {
    "corp-ad": {"field": "sAMAccountName"}
  }
}
```

- `provider_mappings` (optional): Maps an LDAP provider ID to the LDAP attribute used as the username for that app. Default is to use the username as-is.

**Response (201):**

```json
{
  "app_id": "app-a1b2c3d4",
  "name": "My App",
  "api_key": "sk-xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
}
```

---

### `GET /api/admin/apps/{app_id}`

**Auth:** Admin Key or App API Key

Get a single application by ID.

---

### `PUT /api/admin/apps/{app_id}`

**Auth:** Admin Key

Update an application. Only the fields you provide are updated.

**Request:**

```json
{
  "name": "Updated Name",
  "description": "Updated description",
  "redirect_uris": ["https://new-url.example.com/callback"],
  "provider_mappings": {"corp-ad": {"field": "mail"}}
}
```

---

### `DELETE /api/admin/apps/{app_id}`

**Auth:** Admin Key

Delete an application.

```bash
curl -k -X DELETE -H "Authorization: Bearer ADMIN_KEY" \
  https://localhost:8080/api/admin/apps/app-a1b2c3d4
```

**Response (200):**

```json
{"status": "deleted"}
```

---

### `POST /api/admin/apps/{app_id}/rotate-key`

**Auth:** Admin Key

Rotate an app's API key. The old key is immediately invalidated.

```bash
curl -k -X POST -H "Authorization: Bearer ADMIN_KEY" \
  https://localhost:8080/api/admin/apps/app-a1b2c3d4/rotate-key
```

**Response (200):**

```json
{
  "app_id": "app-a1b2c3d4",
  "new_api_key": "sk-new-key-here"
}
```

---

## Admin: Users

### `GET /api/admin/users`

**Auth:** Admin Key

List all users. Password hashes are stripped from the response.

```bash
curl -k -H "Authorization: Bearer ADMIN_KEY" \
  https://localhost:8080/api/admin/users
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
{"password": "new-password-here"}
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

Merge multiple user records into one. This is useful when the same person has separate accounts from different LDAP providers. Identity mappings, roles, and permissions are all merged.

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
    "app_id": "app-a1b2c3d4",
    "created_at": "2024-01-15T10:30:00Z",
    "expires_at": "2024-02-14T10:30:00Z"
  }
]
```

---

### `DELETE /api/admin/users/{guid}/sessions`

**Auth:** Admin Key

Revoke all sessions for a user. Forces them to log in again everywhere.

---

## Admin: LDAP Providers

### `GET /api/admin/ldap`

**Auth:** Admin Key

List all configured LDAP providers.

---

### `POST /api/admin/ldap`

**Auth:** Admin Key

Create a new LDAP provider.

**Request:**

```json
{
  "provider_id": "corp-ad",
  "name": "Corporate Active Directory",
  "url": "ldaps://dc01.corp.local:636",
  "base_dn": "DC=corp,DC=local",
  "bind_dn": "CN=svc-simpleauth,OU=Service Accounts,DC=corp,DC=local",
  "bind_password": "ServiceAccountPassword",
  "user_filter": "(sAMAccountName={0})",
  "use_tls": true,
  "skip_tls_verify": false,
  "display_name_attr": "displayName",
  "email_attr": "mail",
  "department_attr": "department",
  "company_attr": "company",
  "job_title_attr": "title",
  "groups_attr": "memberOf",
  "priority": 10
}
```

---

### `GET /api/admin/ldap/{provider_id}`

**Auth:** Admin Key

Get a single LDAP provider by ID.

---

### `PUT /api/admin/ldap/{provider_id}`

**Auth:** Admin Key

Update an LDAP provider.

---

### `DELETE /api/admin/ldap/{provider_id}`

**Auth:** Admin Key

Delete an LDAP provider.

---

### `POST /api/admin/ldap/{provider_id}/test`

**Auth:** Admin Key

Test connectivity to an LDAP provider. Returns success or an error message.

---

### `POST /api/admin/ldap/auto-discover`

**Auth:** Admin Key

Auto-discover LDAP providers using DNS SRV records.

---

### `GET /api/admin/ldap/export`

**Auth:** Admin Key

Export all LDAP provider configurations as JSON.

---

### `POST /api/admin/ldap/import`

**Auth:** Admin Key

Import LDAP provider configurations from JSON.

---

### `POST /api/admin/ldap/{provider_id}/setup-kerberos`

**Auth:** Admin Key

Set up Kerberos/SPNEGO authentication for an LDAP provider. Creates the SPN and generates a keytab using the provider's AD credentials.

**Request:**

```json
{
  "admin_username": "admin@CORP.LOCAL",
  "admin_password": "AdminPassword"
}
```

---

### `POST /api/admin/ldap/{provider_id}/cleanup-kerberos`

**Auth:** Admin Key

Remove Kerberos configuration (delete SPN, clean up keytab).

---

### `GET /api/admin/kerberos/status`

**Auth:** Admin Key

Check the status of Kerberos configuration (keytab exists, SPN configured, etc.).

---

## Admin: Roles & Permissions

### `GET /api/admin/apps/{app_id}/users`

**Auth:** Admin Key or App API Key (scoped to own app)

List all users who have roles in a specific app, along with their roles and permissions.

**Response (200):**

```json
[
  {
    "guid": "550e8400-...",
    "display_name": "John Smith",
    "email": "jsmith@corp.local",
    "roles": ["admin", "user"],
    "permissions": ["read:reports"]
  }
]
```

---

### `GET /api/admin/apps/{app_id}/users/{guid}/roles`

**Auth:** Admin Key or App API Key (scoped)

Get a user's roles for a specific app.

**Response (200):**

```json
["admin", "user"]
```

---

### `PUT /api/admin/apps/{app_id}/users/{guid}/roles`

**Auth:** Admin Key or App API Key (scoped)

Set a user's roles for a specific app. Replaces the entire role list.

**Request body:** Array of strings.

```json
["admin", "user", "manager"]
```

---

### `GET /api/admin/apps/{app_id}/users/{guid}/permissions`

**Auth:** Admin Key or App API Key (scoped)

Get a user's permissions for a specific app.

**Response (200):**

```json
["read:reports", "write:config"]
```

---

### `PUT /api/admin/apps/{app_id}/users/{guid}/permissions`

**Auth:** Admin Key or App API Key (scoped)

Set a user's permissions for a specific app.

**Request body:** Array of strings.

```json
["read:reports", "write:config", "delete:users"]
```

---

### `GET /api/admin/apps/{app_id}/defaults/roles`

**Auth:** Admin Key or App API Key (scoped)

Get default roles that are automatically assigned to new users when they first log in to an app.

---

### `PUT /api/admin/apps/{app_id}/defaults/roles`

**Auth:** Admin Key or App API Key (scoped)

Set default roles for new users.

**Request body:** Array of strings.

```json
["user", "viewer"]
```

---

## Admin: Identity Mappings

Identity mappings link external identities (LDAP usernames, app-specific IDs) to SimpleAuth user GUIDs. This is how SimpleAuth tracks that "jsmith" in AD and "john.smith" in your app are the same person.

### `GET /api/admin/mappings`

**Auth:** Admin Key or App API Key

List all identity mappings.

**Response (200):**

```json
[
  {
    "provider": "ldap:corp-ad",
    "external_id": "jsmith",
    "user_guid": "550e8400-..."
  },
  {
    "provider": "app:my-app",
    "external_id": "john.smith",
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

**Auth:** Admin Key or App API Key (apps can only set their own provider)

Create or update an identity mapping.

**Request:**

```json
{
  "provider": "app:my-app",
  "external_id": "john.smith"
}
```

---

### `DELETE /api/admin/users/{guid}/mappings/{provider}/{external_id}`

**Auth:** Admin Key or App API Key

Delete an identity mapping.

---

### `GET /api/admin/mappings/resolve`

**Auth:** Admin Key or App API Key

Resolve an external identity to a SimpleAuth user GUID.

**Query parameters:**
- `provider` -- The identity provider (e.g., `ldap:corp-ad`, `app:my-app`, `local`)
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

## Admin: One-Time Tokens

One-time tokens are used for self-registration. You create a token, give it to a developer, and they use it to register their app without needing the admin key.

### `GET /api/admin/tokens`

**Auth:** Admin Key

List all one-time tokens. Optionally filter by scope.

**Query parameters:**
- `scope` (optional) -- Filter by scope (e.g., `app-registration`)

---

### `POST /api/admin/tokens`

**Auth:** Admin Key

Create a new one-time token.

**Request:**

```json
{
  "scope": "app-registration",
  "label": "For team-alpha's new service",
  "ttl": "48h"
}
```

- `ttl` defaults to `24h` if omitted.

**Response (201):**

```json
{
  "token": "ABC-1234",
  "scope": "app-registration",
  "label": "For team-alpha's new service",
  "used": false,
  "expires_at": "2024-01-17T10:30:00Z",
  "created_at": "2024-01-15T10:30:00Z"
}
```

---

### `DELETE /api/admin/tokens/{token}`

**Auth:** Admin Key

Delete a one-time token.

---

### `POST /api/register`

**Auth:** None (requires a valid one-time token)

Self-register an app using a one-time token. This is a public endpoint.

**Request:**

```json
{
  "token": "ABC-1234",
  "name": "Team Alpha Service",
  "description": "Internal microservice",
  "redirect_uris": ["https://alpha.internal/callback"],
  "provider_mappings": {}
}
```

**Response (201):**

```json
{
  "app_id": "app-e5f6g7h8",
  "name": "Team Alpha Service",
  "api_key": "sk-xxxx"
}
```

**Error responses:**
- `401` -- Token not found, expired, already used, or scope mismatch

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
- `event` -- Filter by event type (e.g., `login_success`, `login_failed`, `app_registered`, `role_changed`, `sessions_revoked`, `oidc_authorize`, `oidc_token`, `oidc_logout`)
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
      "app_id": "app-abc",
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
| `app_registered` | New app created |
| `app_self_registered` | App self-registered with one-time token |
| `app_key_rotated` | App API key rotated |
| `user_created` | New user created |
| `user_merged` | Users merged |
| `user_unmerged` | User unmerged |
| `role_changed` | User roles updated |
| `permission_changed` | User permissions updated |
| `sessions_revoked` | All sessions revoked for a user |
| `negotiate_success` | Kerberos/SPNEGO authentication succeeded |
| `negotiate_failed` | Kerberos/SPNEGO authentication failed |
| `oidc_authorize` | OIDC authorization code issued |
| `oidc_token` | OIDC token issued |
| `oidc_logout` | OIDC logout |
| `token_created` | One-time registration token created |

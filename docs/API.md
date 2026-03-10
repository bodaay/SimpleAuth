# SimpleAuth API Reference

Complete reference for every endpoint. All endpoints return JSON. All request bodies are JSON unless noted otherwise.

**Base URL:** `https://your-simpleauth-server:port`

**Authentication types:**
- **Admin Key** -- `Authorization: Bearer YOUR_ADMIN_KEY` (the master admin key from config, or a token from a user with the `SimpleAuthAdmin` role)
- **Bearer Token** -- `Authorization: Bearer ACCESS_TOKEN` (a JWT access token from login)
- **None** -- No authentication required

**Admin access:** Use the `ADMIN_KEY` for initial bootstrap. After that, any user with the `SimpleAuthAdmin` role gets full admin access.

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

**Auth:** Admin

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
    "groups": ["CN=Engineering,OU=Groups,DC=corp,DC=local"]
  }
}
```

**Error responses:**
- `400` -- `{"error": "username and password required"}`
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

**Auth:** Admin

Generate an access token for any user. Useful for testing and support scenarios.

**Request:**

```json
{
  "guid": "550e8400-..."
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

OIDC client settings (client ID, client secret, redirect URIs) are configured at the instance level using environment variables: `AUTH_CLIENT_ID`, `AUTH_CLIENT_SECRET`, `AUTH_REDIRECT_URIS`.

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
- `redirect_uri` -- Where to redirect after login (must be in `AUTH_REDIRECT_URIS`)
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
  "groups": ["CN=Engineering,..."],
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

**Auth:** Admin

List all users. Password hashes are stripped from the response.

```bash
curl -k -H "Authorization: Bearer ADMIN_KEY" \
  https://localhost:8080/api/admin/users
```

---

### `POST /api/admin/users`

**Auth:** Admin

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

**Auth:** Admin

Get a single user by GUID.

---

### `PUT /api/admin/users/{guid}`

**Auth:** Admin

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

**Auth:** Admin

Delete a user.

---

### `PUT /api/admin/users/{guid}/password`

**Auth:** Admin

Set a user's password (admin override, no current password required).

**Request:**

```json
{"password": "new-password-here"}
```

---

### `PUT /api/admin/users/{guid}/disabled`

**Auth:** Admin

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

**Auth:** Admin

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

**Auth:** Admin

Reverse a merge operation. The user record has its `merged_into` pointer cleared.

---

### `GET /api/admin/users/{guid}/sessions`

**Auth:** Admin

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

**Auth:** Admin

Revoke all sessions for a user. Forces them to log in again everywhere.

---

## Admin: Roles & Permissions

Roles and permissions are global per SimpleAuth instance.

### `GET /api/admin/users/{guid}/roles`

**Auth:** Admin

Get a user's roles.

**Response (200):**

```json
["admin", "user"]
```

---

### `PUT /api/admin/users/{guid}/roles`

**Auth:** Admin

Set a user's roles. Replaces the entire role list.

**Request body:** Array of strings.

```json
["admin", "user", "manager"]
```

---

### `GET /api/admin/users/{guid}/permissions`

**Auth:** Admin

Get a user's permissions.

**Response (200):**

```json
["read:reports", "write:config"]
```

---

### `PUT /api/admin/users/{guid}/permissions`

**Auth:** Admin

Set a user's permissions.

**Request body:** Array of strings.

```json
["read:reports", "write:config", "delete:users"]
```

---

### `GET /api/admin/defaults/roles`

**Auth:** Admin

Get default roles that are automatically assigned to new users when they first log in.

---

### `PUT /api/admin/defaults/roles`

**Auth:** Admin

Set default roles for new users.

**Request body:** Array of strings.

```json
["user", "viewer"]
```

---

### `GET /api/admin/role-permissions`

**Auth:** Admin

Get the role-to-permissions mapping. This defines which permissions are automatically granted by each role.

---

### `PUT /api/admin/role-permissions`

**Auth:** Admin

Set the role-to-permissions mapping.

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

**Auth:** Admin

List all unique roles across all users.

```bash
curl -k -H "Authorization: Bearer ADMIN_KEY" \
  https://localhost:8080/api/admin/roles
```

```json
["admin", "editor", "user", "viewer"]
```

---

### `GET /api/admin/permissions`

**Auth:** Admin

List all unique permissions across all users and the role-permissions mapping.

```bash
curl -k -H "Authorization: Bearer ADMIN_KEY" \
  https://localhost:8080/api/admin/permissions
```

```json
["delete:all", "read:all", "write:all"]
```

---

## Admin: LDAP Providers

### `GET /api/admin/ldap`

**Auth:** Admin

List all configured LDAP providers.

---

### `POST /api/admin/ldap`

**Auth:** Admin

Create a new LDAP provider.

**Request:**

```json
{
  "provider_id": "corp-ad",
  "name": "Corporate Active Directory",
  "url": "ldaps://dc01.corp.local:636",
  "base_dn": "DC=corp,DC=local",
  "bind_dn": "CN=svc-sauth-prod,OU=Service Accounts,DC=corp,DC=local",
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

**Auth:** Admin

Get a single LDAP provider by ID.

---

### `PUT /api/admin/ldap/{provider_id}`

**Auth:** Admin

Update an LDAP provider.

---

### `DELETE /api/admin/ldap/{provider_id}`

**Auth:** Admin

Delete an LDAP provider.

---

### `POST /api/admin/ldap/{provider_id}/test`

**Auth:** Admin

Test connectivity to an LDAP provider. Returns success or an error message.

---

### `POST /api/admin/ldap/auto-discover`

**Auth:** Admin

Auto-discover LDAP providers using DNS SRV records.

---

### `GET /api/admin/ldap/export`

**Auth:** Admin

Export all LDAP provider configurations as JSON.

---

### `POST /api/admin/ldap/import`

**Auth:** Admin

Import LDAP provider configurations from JSON.

---

### `POST /api/admin/ldap/{provider_id}/setup-kerberos`

**Auth:** Admin

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

**Auth:** Admin

Remove Kerberos configuration (delete SPN, clean up keytab).

---

### `GET /api/admin/kerberos/status`

**Auth:** Admin

Check the status of Kerberos configuration (keytab exists, SPN configured, etc.).

---

### `GET /api/admin/setup-script`

**Auth:** Admin

Download an interactive PowerShell script for AD setup. The script has the SimpleAuth hostname pre-injected and offers:
- Create a new service account or use an existing one
- OU selection for new accounts
- SPN registration for Kerberos
- Config JSON export for one-click import into the admin UI

Returns a `.ps1` file with UTF-8 BOM encoding.

---

### `POST /api/admin/ldap/{provider_id}/sync-user`

**Auth:** Admin

Sync a single user's profile from AD. Looks up the user by sAMAccountName in the LDAP provider, then updates their SimpleAuth profile (display name, email, department, company, job title).

```bash
curl -k -X POST \
  https://localhost:8080/api/admin/ldap/corp-ad/sync-user \
  -H "Authorization: Bearer ADMIN_KEY" \
  -H "Content-Type: application/json" \
  -d '{"username": "jsmith"}'
```

---

### `POST /api/admin/ldap/{provider_id}/sync-all`

**Auth:** Admin

Sync all users mapped to this LDAP provider. Iterates all non-merged users with an `ldap:{provider_id}` identity mapping and updates their profiles from AD.

```bash
curl -k -X POST \
  https://localhost:8080/api/admin/ldap/corp-ad/sync-all \
  -H "Authorization: Bearer ADMIN_KEY"
```

```json
{"synced": 42, "errors": 0}
```

---

## Admin: Identity Mappings

Identity mappings link external identities (LDAP usernames) to SimpleAuth user GUIDs. This is how SimpleAuth tracks that "jsmith" in AD is the same person across logins.

### `GET /api/admin/mappings`

**Auth:** Admin

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
    "provider": "local",
    "external_id": "admin",
    "user_guid": "660e8400-..."
  }
]
```

---

### `GET /api/admin/users/{guid}/mappings`

**Auth:** Admin

Get all identity mappings for a specific user.

---

### `PUT /api/admin/users/{guid}/mappings`

**Auth:** Admin

Create or update an identity mapping.

**Request:**

```json
{
  "provider": "ldap:corp-ad",
  "external_id": "jsmith"
}
```

---

### `DELETE /api/admin/users/{guid}/mappings/{provider}/{external_id}`

**Auth:** Admin

Delete an identity mapping.

---

### `GET /api/admin/mappings/resolve`

**Auth:** Admin

Resolve an external identity to a SimpleAuth user GUID.

**Query parameters:**
- `provider` -- The identity provider (e.g., `ldap:corp-ad`, `local`)
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

**Auth:** Admin

Download a complete database backup as a binary file.

```bash
curl -k -H "Authorization: Bearer ADMIN_KEY" \
  https://localhost:8080/api/admin/backup -o backup.db
```

---

### `POST /api/admin/restore`

**Auth:** Admin

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

**Auth:** Admin

Query the audit log. All authentication events, admin actions, and security events are logged.

**Query parameters:**
- `event` -- Filter by event type (e.g., `login_success`, `login_failed`, `role_changed`, `sessions_revoked`, `oidc_authorize`, `oidc_token`, `oidc_logout`)
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
| `sessions_revoked` | All sessions revoked for a user |
| `negotiate_success` | Kerberos/SPNEGO authentication succeeded |
| `negotiate_failed` | Kerberos/SPNEGO authentication failed |
| `oidc_authorize` | OIDC authorization code issued |
| `oidc_token` | OIDC token issued |
| `oidc_logout` | OIDC logout |

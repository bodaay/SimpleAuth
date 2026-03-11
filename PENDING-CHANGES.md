# Pending Changes to Propagate

Once all server-side changes are finalized, update the following:

## SDKs
- [ ] sdk/go/simpleauth.go
- [ ] sdk/js/index.ts
- [ ] sdk/python/simpleauth/client.py
- [ ] sdk/python/simpleauth/middleware.py
- [ ] sdk/dotnet/SimpleAuthClient.cs
- [ ] sdk/dotnet/SimpleAuthMiddleware.cs

## SDK READMEs
- [ ] sdk/go/README.md
- [ ] sdk/js/README.md
- [ ] sdk/python/README.md
- [ ] sdk/dotnet/README.md

## Docs
- [ ] docs/API.md
- [ ] docs/ARCHITECTURE.md
- [ ] docs/CONFIGURATION.md
- [ ] docs/QUICKSTART.md
- [ ] docs/SDK-GUIDE.md
- [ ] docs/REVERSE-PROXY.md
- [ ] docs/ACTIVE-DIRECTORY.md
- [ ] docs/KEYCLOAK-MIGRATION.md

## Examples
- [ ] examples/go/
- [ ] examples/js/
- [ ] examples/python/
- [ ] examples/dotnet/

## Root
- [ ] README.md

## Changes to propagate
- One-time tokens removed (no more /api/admin/tokens endpoints)
- SSO login endpoint added (GET /login/sso)
- SSO failure fallback (redirects to /login with error instead of hanging)
- Route renamed: /auth/test-negotiate -> /test-negotiate
- Google Fonts removed, system font stack used
- Wildcard redirect_uri support
- SimpleAuthAdmin role REMOVED — admin access is admin_key only
- Admin UI moved from / to /admin
- LDAP: multi-provider removed, single config only (no more provider_id in routes)
- LDAP API routes changed: all under /api/admin/ldap (no /{provider_id} segments)
- New endpoint: POST /api/admin/ldap/test-user (search user and preview mapped attributes)
- New endpoint: POST /api/admin/ldap/auto-discover (auto-detect config from server)
- Identity mapping prefix changed: "ldap:{providerID}" → "ldap"
- LDAP: `user_filter` replaced with `username_attr` (dropdown: sAMAccountName, userPrincipalName, uid, mail) + optional `custom_filter`
- `redirect_uris` (array) → `redirect_uri` (single string). Old array still accepted, only index 0 used
- `AUTH_REDIRECT_URI` env var added
- Root URL `/` now redirects to `/login`
- New endpoint: POST /api/admin/ldap/search-users (search LDAP directory for users)
- New endpoint: POST /api/admin/ldap/import-users (import LDAP users into SimpleAuth with identity mappings)
- Impersonation page: "Launch in App" button sends tokens to configured redirect_uri via fragment
- server-info API returns `redirect_uri` (singular) instead of `redirect_uris`
- Account page: view-only profile + password change (no self-service profile editing)
- Authentication order: local users always take priority over LDAP (not configurable)
- Password policy: configurable min length, complexity requirements (uppercase, lowercase, digit, special char)
- Password history: prevent reusing last N passwords (AUTH_PASSWORD_HISTORY_COUNT)
- Account lockout: lock account after N failed login attempts (AUTH_ACCOUNT_LOCKOUT_THRESHOLD, AUTH_ACCOUNT_LOCKOUT_DURATION)
- Force password change: admin can set flag on user, login response includes `force_password_change: true`
- Admin set password: new `force_change` field in PUT /api/admin/users/{guid}/password
- New endpoint: GET /api/admin/password-policy (returns current password policy config)
- New endpoint: PUT /api/admin/users/{guid}/unlock (clears failed login attempts and lockout)
- User struct: new fields `force_password_change`, `failed_login_attempts`, `locked_until`
- Password change (POST /api/auth/reset-password): enforces complexity, history, clears force_password_change flag
- Create user (POST /api/admin/users): enforces password policy on initial password

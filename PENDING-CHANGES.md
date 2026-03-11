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

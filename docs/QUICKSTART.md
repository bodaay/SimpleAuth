# SimpleAuth Quickstart

**Get a production-grade authentication server running in 5 minutes.**

SimpleAuth is a lightweight authentication server that connects to Active Directory (or works standalone with local users) and issues JWTs your apps can verify. It speaks OIDC, so any library that works with Keycloak or Auth0 works with SimpleAuth. One binary, one database file, zero external dependencies.

One SimpleAuth instance serves one application. Need multiple apps? Run multiple instances -- they're tiny.

> **Base path:** SimpleAuth serves all routes under `/sauth` by default. All URLs in this guide include this prefix.

---

## 1. Start SimpleAuth

### Docker (recommended)

```bash
docker run -d \
  --name simpleauth \
  -p 8080:8080 \
  -v simpleauth-data:/data \
  -e AUTH_REDIRECT_URI="https://myapp.example.com/callback" \
  simpleauth
```

That's it. SimpleAuth is running at `https://localhost:8080/sauth` with a self-signed TLS certificate. The admin UI is available at `https://localhost:8080/sauth/admin`.

Grab the auto-generated admin key from the logs:

```bash
docker logs simpleauth 2>&1 | grep "admin_key"
```

Save that key. You'll need it for admin operations.

### Binary

```bash
# Generate a config file (optional)
./simpleauth init-config

# Start the server
./simpleauth
```

SimpleAuth listens on HTTPS port 9090 by default and auto-generates a self-signed TLS cert. The admin UI is available at `https://hostname:9090/sauth/admin`.

---

## 2. Connect to Active Directory (optional)

Skip this if you just want local users.

```bash
# Replace with your AD details
curl -k -X POST https://localhost:8080/sauth/api/admin/ldap \
  -H "Authorization: Bearer YOUR_ADMIN_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Corporate AD",
    "url": "ldaps://dc01.corp.local:636",
    "base_dn": "DC=corp,DC=local",
    "bind_dn": "CN=svc-sauth-prod,OU=Service Accounts,DC=corp,DC=local",
    "bind_password": "YourServiceAccountPassword",
    "username_attr": "sAMAccountName",
    "use_tls": true,
    "display_name_attr": "displayName",
    "email_attr": "mail",
    "department_attr": "department",
    "company_attr": "company",
    "job_title_attr": "title",
    "groups_attr": "memberOf"
  }'
```

Test the connection:

```bash
curl -k -X POST https://localhost:8080/sauth/api/admin/ldap/test \
  -H "Authorization: Bearer YOUR_ADMIN_KEY"
```

> **Linux SSO:** After configuring LDAP, you can download a Linux SSO script from the admin UI (`/sauth/admin`) to configure Linux clients for single sign-on against your directory.

> **Auto SSO:** Set `AUTH_AUTO_SSO=true` (or `auto_sso: true` in config) to make the login page automatically attempt Kerberos SSO without requiring a button click. On failure, it falls back to the manual login form. This can also be toggled at runtime from the Admin UI Settings page.

> **Logout with auto-SSO:** When auto-SSO is enabled, apps should redirect users to `/logout?redirect_uri=X` instead of `/login?redirect_uri=X` when logging out. The `/logout` endpoint clears SSO cookies and redirects to `/login?manual=1&redirect_uri=X`, preventing auto-SSO from immediately logging the user back in.

---

## 3. Configure OIDC (optional)

OIDC settings are configured at the instance level using environment variables or the config file:

- `AUTH_REDIRECT_URI` -- Allowed redirect URI (single value)
- `AUTH_REDIRECT_URIS` -- Allowed redirect URIs (comma-separated list, for multiple apps sharing one instance)

Both can be set -- they are merged and deduplicated. Wildcard `*` suffix is supported. If neither is set, all redirect URIs are rejected.

These are set when you start SimpleAuth. See [Configuration](CONFIGURATION.md) for details.

---

## 4. Test login

### Option A: Direct API login

```bash
curl -k -X POST https://localhost:8080/sauth/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "username": "jsmith",
    "password": "their-ad-password"
  }'
```

### Option B: OIDC password grant (standard OAuth2)

```bash
curl -k -X POST \
  https://localhost:8080/sauth/realms/simpleauth/protocol/openid-connect/token \
  -d "grant_type=password&username=jsmith&password=their-ad-password&scope=openid"
```

Both return JWT tokens:

```json
{
  "access_token": "eyJhbGciOiJSUzI1NiIs...",
  "refresh_token": "eyJhbGciOiJSUzI1NiIs...",
  "id_token": "eyJhbGciOiJSUzI1NiIs...",
  "token_type": "Bearer",
  "expires_in": 900
}
```

---

## 5. Verify tokens in your app

### Using JWKS (any language)

Fetch the public keys from `/sauth/.well-known/jwks.json` and verify RS256 signatures locally. No network call needed per request.

### Using an SDK

**JavaScript/TypeScript:**

```bash
npm install @simpleauth/js
```

```typescript
import { createSimpleAuth } from '@simpleauth/js';

const auth = createSimpleAuth({
  url: 'https://auth.corp.local:8080',
});

// In your API handler:
const user = await auth.verify(req.headers.authorization.split(' ')[1]);
console.log(user.name, user.roles, user.hasRole('admin'));
```

**Go:**

```go
client := simpleauth.New(simpleauth.Options{
    URL: "https://auth.corp.local:8080",
})

// As middleware:
mux.Handle("/api/", client.Middleware(yourHandler))

// In a handler:
user := simpleauth.UserFromContext(r.Context())
```

**Python:**

```bash
pip install simpleauth
```

```python
from simpleauth import SimpleAuth

auth = SimpleAuth(
    url="https://auth.corp.local:8080",
    verify_ssl=False,  # for self-signed certs in dev
)

user = auth.verify(access_token)
print(user.name, user.roles, user.has_role("admin"))
```

**C# / .NET:**

```csharp
builder.Services.AddSimpleAuth(opts => {
    opts.Url = "https://auth.corp.local:8080";
});

app.UseSimpleAuth();

// In a controller:
var user = HttpContext.GetSimpleAuthUser();
```

---

## 6. Done

That's it. You have:

- An authentication server connected to your Active Directory
- OIDC configured at the instance level
- Users logging in and getting JWTs
- Your app verifying those JWTs locally using JWKS

### Admin UI features

The admin UI at `/sauth/admin` also provides:

- **Settings page** -- Runtime configuration without restarting the server
- **Database page** -- Migrate from the embedded BoltDB to PostgreSQL for production deployments

### What's next?

- **[API Reference](API.md)** -- Every endpoint, documented
- **[Configuration](CONFIGURATION.md)** -- All the knobs you can turn
- **[Active Directory Guide](ACTIVE-DIRECTORY.md)** -- Deep dive into AD integration
- **[Architecture](ARCHITECTURE.md)** -- How it all fits together
- **[Keycloak Migration](KEYCLOAK-MIGRATION.md)** -- Replacing Keycloak with SimpleAuth
- **[SDK Guide](SDK-GUIDE.md)** -- Integration patterns for all 4 platforms

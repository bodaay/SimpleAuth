# SimpleAuth Quickstart

**Get a production-grade authentication server running in 5 minutes.**

SimpleAuth is a lightweight authentication server that connects to Active Directory (or works standalone with local users) and issues JWTs your apps can verify. It speaks OIDC, so any library that works with Keycloak or Auth0 works with SimpleAuth. One binary, one database file, zero external dependencies.

---

## 1. Start SimpleAuth

### Docker (recommended)

```bash
docker run -d \
  --name simpleauth \
  -p 8080:8080 \
  -v simpleauth-data:/data \
  simpleauth
```

That's it. SimpleAuth is running at `https://localhost:8080` with a self-signed TLS certificate.

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

SimpleAuth listens on HTTPS port 9090 by default and auto-generates a self-signed TLS cert.

---

## 2. Connect to Active Directory (optional)

Skip this if you just want local users.

```bash
# Replace with your AD details
curl -k -X POST https://localhost:8080/api/admin/ldap \
  -H "Authorization: Bearer YOUR_ADMIN_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "provider_id": "corp-ad",
    "name": "Corporate AD",
    "url": "ldaps://dc01.corp.local:636",
    "base_dn": "DC=corp,DC=local",
    "bind_dn": "CN=svc-simpleauth,OU=Service Accounts,DC=corp,DC=local",
    "bind_password": "YourServiceAccountPassword",
    "user_filter": "(sAMAccountName={0})",
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
curl -k -X POST https://localhost:8080/api/admin/ldap/corp-ad/test \
  -H "Authorization: Bearer YOUR_ADMIN_KEY"
```

---

## 3. Create your first app

Every application that authenticates through SimpleAuth needs to be registered:

```bash
curl -k -X POST https://localhost:8080/api/admin/apps \
  -H "Authorization: Bearer YOUR_ADMIN_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "My Web App",
    "description": "Our main application",
    "redirect_uris": ["https://myapp.example.com/callback"]
  }'
```

Response:

```json
{
  "app_id": "app-a1b2c3d4",
  "name": "My Web App",
  "api_key": "sk-xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
}
```

Save `app_id` and `api_key`. These are your `client_id` and `client_secret`.

---

## 4. Test login

### Option A: Direct API login

```bash
curl -k -X POST https://localhost:8080/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "username": "jsmith",
    "password": "their-ad-password",
    "app_id": "app-a1b2c3d4"
  }'
```

### Option B: OIDC password grant (standard OAuth2)

```bash
curl -k -X POST \
  https://localhost:8080/realms/simpleauth/protocol/openid-connect/token \
  -u "app-a1b2c3d4:sk-xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx" \
  -d "grant_type=password&username=jsmith&password=their-ad-password&scope=openid"
```

Both return JWT tokens:

```json
{
  "access_token": "eyJhbGciOiJSUzI1NiIs...",
  "refresh_token": "eyJhbGciOiJSUzI1NiIs...",
  "id_token": "eyJhbGciOiJSUzI1NiIs...",
  "token_type": "Bearer",
  "expires_in": 28800
}
```

---

## 5. Verify tokens in your app

### Using JWKS (any language)

Fetch the public keys from `/.well-known/jwks.json` and verify RS256 signatures locally. No network call needed per request.

### Using an SDK

**JavaScript/TypeScript:**

```bash
npm install @simpleauth/js
```

```typescript
import { createSimpleAuth } from '@simpleauth/js';

const auth = createSimpleAuth({
  url: 'https://auth.corp.local:8080',
  appId: 'app-a1b2c3d4',
  appSecret: 'sk-xxxx',
});

// In your API handler:
const user = await auth.verify(req.headers.authorization.split(' ')[1]);
console.log(user.name, user.roles, user.hasRole('admin'));
```

**Go:**

```go
client := simpleauth.New(simpleauth.Options{
    URL:       "https://auth.corp.local:8080",
    AppID:     "app-a1b2c3d4",
    AppSecret: "sk-xxxx",
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
    app_id="app-a1b2c3d4",
    app_secret="sk-xxxx",
    verify_ssl=False,  # for self-signed certs in dev
)

user = auth.verify(access_token)
print(user.name, user.roles, user.has_role("admin"))
```

**C# / .NET:**

```csharp
builder.Services.AddSimpleAuth(opts => {
    opts.Url = "https://auth.corp.local:8080";
    opts.AppId = "app-a1b2c3d4";
    opts.AppSecret = "sk-xxxx";
});

app.UseSimpleAuth();

// In a controller:
var user = HttpContext.GetSimpleAuthUser();
```

---

## 6. Done

That's it. You have:

- An authentication server connected to your Active Directory
- An app registered with a client ID and secret
- Users logging in and getting JWTs
- Your app verifying those JWTs locally using JWKS

### What's next?

- **[API Reference](API.md)** -- Every endpoint, documented
- **[Configuration](CONFIGURATION.md)** -- All the knobs you can turn
- **[Active Directory Guide](ACTIVE-DIRECTORY.md)** -- Deep dive into AD integration
- **[Architecture](ARCHITECTURE.md)** -- How it all fits together
- **[Keycloak Migration](KEYCLOAK-MIGRATION.md)** -- Replacing Keycloak with SimpleAuth
- **[SDK Guide](SDK-GUIDE.md)** -- Integration patterns for all 4 platforms

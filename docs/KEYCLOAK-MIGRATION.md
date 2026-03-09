# Migrating from Keycloak to SimpleAuth

You're running Keycloak. It works, but it's a lot of infrastructure for what you actually need: authenticate users against AD and issue JWTs. This guide gets you migrated.

---

## Why Migrate

| | Keycloak | SimpleAuth |
|---|---|---|
| **Runtime** | JVM, PostgreSQL, 512MB+ RAM | Single Go binary, ~20MB RAM |
| **Database** | PostgreSQL/MySQL required | Embedded BoltDB (single file) |
| **Config** | Admin console with hundreds of options | YAML file with 17 options |
| **Deployment** | Multiple containers, DB migrations | One container, one volume |
| **LDAP setup** | Realm > User Federation > LDAP > attribute mapping wizards | One API call |
| **Upgrade path** | Theme migrations, DB migrations, breaking changes | Replace the binary |
| **OIDC compatibility** | Full spec | What you actually use (4 grant types, JWKS, userinfo, introspect, logout) |

**What SimpleAuth doesn't do (on purpose):**
- Social login (Google, GitHub, etc.) -- use a dedicated service like Auth0 for that
- SAML -- it's 2024+, use OIDC
- User self-service (password reset emails, registration flows) -- your app should own that UX
- Themes and branding -- the hosted login page is intentionally simple; use the authorization code flow with your own login page
- Fine-grained authorization policies (UMA) -- keep authorization logic in your app where it belongs
- Multi-realm -- use `jwt_issuer` to create separate issuers, or just run another instance (it's 20MB)

These aren't missing features. They're deliberate omissions that keep SimpleAuth simple and fast.

---

## Concept Mapping

| Keycloak | SimpleAuth | Notes |
|---|---|---|
| Realm | `jwt_issuer` config | SimpleAuth has one "realm" per instance. The OIDC URLs use it the same way: `/realms/{issuer}/...` |
| Client | App | Created via `POST /api/admin/apps` |
| Client ID | `app_id` | Auto-generated like `app-a1b2c3d4` |
| Client Secret | `api_key` | Auto-generated like `sk-uuid` |
| User Federation (LDAP) | LDAP Provider | Created via `POST /api/admin/ldap` |
| Realm Roles | Roles | Set per-user per-app via `PUT /api/admin/apps/{app_id}/users/{guid}/roles` |
| Client Roles | Also Roles | SimpleAuth doesn't distinguish; roles are always scoped to an app |
| Client Scopes | Not needed | Claims are always included in tokens |
| Protocol Mappers | Not needed | Standard claims are always mapped |
| Groups | AD Groups | Passed through from `memberOf` attribute |
| Service Account | Client Credentials | The app itself authenticates (no service account user needed) |
| Admin Console | Admin API + UI | Same operations, simpler interface |

---

## URL Mapping

SimpleAuth uses Keycloak-compatible URLs. In most cases, you just change the base URL.

| Keycloak URL | SimpleAuth URL |
|---|---|
| `https://keycloak.example.com/realms/myrealm/.well-known/openid-configuration` | `https://simpleauth.example.com/realms/simpleauth/.well-known/openid-configuration` |
| `https://keycloak.example.com/realms/myrealm/protocol/openid-connect/token` | `https://simpleauth.example.com/realms/simpleauth/protocol/openid-connect/token` |
| `https://keycloak.example.com/realms/myrealm/protocol/openid-connect/auth` | `https://simpleauth.example.com/realms/simpleauth/protocol/openid-connect/auth` |
| `https://keycloak.example.com/realms/myrealm/protocol/openid-connect/userinfo` | `https://simpleauth.example.com/realms/simpleauth/protocol/openid-connect/userinfo` |
| `https://keycloak.example.com/realms/myrealm/protocol/openid-connect/certs` | `https://simpleauth.example.com/realms/simpleauth/protocol/openid-connect/certs` |
| `https://keycloak.example.com/realms/myrealm/protocol/openid-connect/token/introspect` | `https://simpleauth.example.com/realms/simpleauth/protocol/openid-connect/token/introspect` |
| `https://keycloak.example.com/realms/myrealm/protocol/openid-connect/logout` | `https://simpleauth.example.com/realms/simpleauth/protocol/openid-connect/logout` |

If you set `jwt_issuer: "myrealm"` in SimpleAuth's config, the URLs become identical except for the hostname.

---

## Migration Steps

### Step 1: Deploy SimpleAuth alongside Keycloak

Run SimpleAuth on a new port/host. Don't tear down Keycloak yet.

```bash
docker run -d \
  --name simpleauth \
  -p 8080:8080 \
  -v simpleauth-data:/data \
  -e AUTH_ADMIN_KEY="your-admin-key" \
  -e AUTH_JWT_ISSUER="myrealm" \
  simpleauth
```

Setting `jwt_issuer` to your Keycloak realm name keeps URLs compatible.

### Step 2: Configure the same LDAP provider

Take your Keycloak LDAP User Federation settings and translate them:

```bash
curl -k -X POST https://simpleauth:8080/api/admin/ldap \
  -H "Authorization: Bearer your-admin-key" \
  -H "Content-Type: application/json" \
  -d '{
    "provider_id": "corp-ad",
    "name": "Corporate AD",
    "url": "ldaps://dc01.corp.local:636",
    "base_dn": "DC=corp,DC=local",
    "bind_dn": "CN=svc-keycloak,OU=Service Accounts,DC=corp,DC=local",
    "bind_password": "same-password-as-keycloak",
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

### Step 3: Register your apps

For each Keycloak client, create a SimpleAuth app:

```bash
curl -k -X POST https://simpleauth:8080/api/admin/apps \
  -H "Authorization: Bearer your-admin-key" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "My Frontend App",
    "redirect_uris": ["https://myapp.example.com/callback"]
  }'
```

Note the returned `app_id` and `api_key`. These replace your Keycloak client ID and secret.

### Step 4: Set up roles

If you used Keycloak roles, set default roles for new users:

```bash
# Set default roles
curl -k -X PUT \
  https://simpleauth:8080/api/admin/apps/app-abc/defaults/roles \
  -H "Authorization: Bearer your-admin-key" \
  -H "Content-Type: application/json" \
  -d '["user"]'
```

For existing users who need specific roles, set them after they first log in, or pre-create users and assign roles.

### Step 5: Update your application

This is the core change. You need to update your app's OIDC configuration.

---

## SDK Changes by Grant Type

### Authorization Code Flow

**Keycloak (before):**

```javascript
// keycloak-js or oidc-client
const keycloak = new Keycloak({
  url: 'https://keycloak.example.com',
  realm: 'myrealm',
  clientId: 'my-app',
});
```

**SimpleAuth (after):**

```javascript
import { createSimpleAuth } from '@simpleauth/js';

const auth = createSimpleAuth({
  url: 'https://simpleauth.example.com',
  appId: 'app-abc',
  appSecret: 'sk-xxxx',
  realm: 'myrealm',  // optional, defaults to 'simpleauth'
});

// Redirect to login
const authUrl = auth.getAuthorizationUrl({
  redirectUri: 'https://myapp.example.com/callback',
  state: 'random-state',
});

// Exchange code for tokens (in your callback handler)
const tokens = await auth.exchangeCode(code, 'https://myapp.example.com/callback');
```

Or just change the OIDC discovery URL in any standard OIDC library -- the endpoints are compatible.

### Resource Owner Password Grant

**Keycloak (before):**

```bash
curl -X POST https://keycloak.example.com/realms/myrealm/protocol/openid-connect/token \
  -d "client_id=my-app&client_secret=old-secret&grant_type=password&username=user&password=pass"
```

**SimpleAuth (after):**

```bash
curl -k -X POST https://simpleauth.example.com/realms/myrealm/protocol/openid-connect/token \
  -d "client_id=app-abc&client_secret=sk-xxxx&grant_type=password&username=user&password=pass"
```

Same endpoint path. Just change the hostname and credentials.

### Client Credentials Grant

**Keycloak (before):**

```bash
curl -X POST https://keycloak.example.com/realms/myrealm/protocol/openid-connect/token \
  -d "client_id=my-service&client_secret=old-secret&grant_type=client_credentials"
```

**SimpleAuth (after):**

```bash
curl -k -X POST https://simpleauth.example.com/realms/myrealm/protocol/openid-connect/token \
  -d "client_id=app-abc&client_secret=sk-xxxx&grant_type=client_credentials"
```

### Token Verification

**Keycloak (before):**

```javascript
// Using keycloak-connect or passport-keycloak
const keycloak = new Keycloak({
  'auth-server-url': 'https://keycloak.example.com',
  realm: 'myrealm',
  resource: 'my-app',
  'ssl-required': 'all',
  'confidential-port': 0,
});
app.use(keycloak.middleware());
```

**SimpleAuth (after):**

```javascript
import { createSimpleAuth } from '@simpleauth/js';

const auth = createSimpleAuth({
  url: 'https://simpleauth.example.com',
  appId: 'app-abc',
  appSecret: 'sk-xxxx',
});
app.use(auth.expressMiddleware());
```

Or with any generic OIDC/JWT library -- just point the JWKS URL to SimpleAuth.

### Role Checking

**Keycloak token claim structure:**

```json
{
  "realm_access": {"roles": ["admin"]},
  "resource_access": {"my-app": {"roles": ["admin"]}}
}
```

**SimpleAuth token claim structure (identical):**

```json
{
  "roles": ["admin"],
  "permissions": ["read:reports"],
  "realm_access": {"roles": ["admin"]},
  "resource_access": {"app-abc": {"roles": ["admin"]}}
}
```

SimpleAuth includes **both** the flat `roles` array and the Keycloak-compatible `realm_access`/`resource_access` structures. So existing Keycloak role-checking code works unchanged.

---

## Step 6: Switch DNS / Load Balancer

Once your app is working with SimpleAuth:

1. Point your DNS or reverse proxy from Keycloak to SimpleAuth
2. Monitor the audit log for any errors
3. After a few days of stable operation, decommission Keycloak

---

## Token Claim Comparison

### Keycloak Access Token

```json
{
  "exp": 1700000000,
  "iat": 1699971200,
  "jti": "uuid",
  "iss": "https://keycloak.example.com/realms/myrealm",
  "aud": "account",
  "sub": "keycloak-user-uuid",
  "typ": "Bearer",
  "azp": "my-app",
  "scope": "openid profile email",
  "name": "John Smith",
  "email": "jsmith@corp.local",
  "preferred_username": "jsmith",
  "realm_access": {"roles": ["admin"]},
  "resource_access": {"my-app": {"roles": ["admin"]}}
}
```

### SimpleAuth Access Token

```json
{
  "exp": 1700000000,
  "iat": 1699971200,
  "jti": "uuid",
  "iss": "https://simpleauth.example.com/realms/myrealm",
  "aud": ["app-abc"],
  "sub": "simpleauth-user-guid",
  "typ": "Bearer",
  "azp": "app-abc",
  "scope": "openid profile email",
  "name": "John Smith",
  "email": "jsmith@corp.local",
  "preferred_username": "jsmith@corp.local",
  "app_id": "app-abc",
  "roles": ["admin"],
  "permissions": ["read:reports"],
  "groups": ["CN=Engineering,..."],
  "department": "Engineering",
  "company": "Acme Corp",
  "job_title": "Senior Engineer",
  "realm_access": {"roles": ["admin"]},
  "resource_access": {"app-abc": {"roles": ["admin"]}}
}
```

**Key differences:**
- `sub` is a new GUID (SimpleAuth generates its own user IDs)
- `aud` is an array (matches OIDC spec)
- SimpleAuth adds `roles`, `permissions`, `groups`, `department`, `company`, `job_title` as top-level claims (in addition to Keycloak-compatible nested structures)
- `preferred_username` defaults to email (Keycloak uses the Keycloak username)

### Impact on your code

- If you check `token.realm_access.roles` -- works unchanged
- If you check `token.resource_access["my-app"].roles` -- update the client name to the new `app_id`
- If you use `token.sub` as a user identifier -- you'll get new GUIDs (users will appear as new users in your app's database on first login)

**Handling the sub change:** If your app stores user data keyed by `sub`, you have two options:
1. **Identity mapping:** Use SimpleAuth's identity mapping API to map your old Keycloak UUIDs to new SimpleAuth GUIDs
2. **Migration script:** After users log in through SimpleAuth, update your app's user table to map old IDs to new ones

---

## Frequently Asked Questions

### Can I use my existing Keycloak OIDC libraries?

Yes. Any library that does OIDC discovery (fetches `/.well-known/openid-configuration`) will auto-configure itself to work with SimpleAuth. Just change the issuer URL.

### What about existing refresh tokens?

They won't work with SimpleAuth (different signing keys). Users will need to log in again. This is a one-time inconvenience.

### Can I run both during migration?

Absolutely. Run SimpleAuth alongside Keycloak on a different port. Migrate apps one at a time. There's no coupling between the two systems.

### What if I need social login?

SimpleAuth doesn't do social login. If you need it, keep Keycloak for those apps, or use a service like Auth0/Clerk for social login and SimpleAuth for AD authentication.

### What about user federation sync?

Keycloak has a "sync all users" feature. SimpleAuth doesn't. Users are created on first login. This is simpler and means you don't have stale users in your database. If you need to pre-populate users, use the admin API.

# Deployment Guide

Real-world deployment scenarios, common mistakes, and how to avoid them.

---

## The #1 Pattern: Bootstrap on Every Startup

If your app relies on SimpleAuth for roles and permissions, your app MUST call the bootstrap endpoint **on every startup** to ensure the roles, permissions, and default admin user exist.

**Why:** SimpleAuth is the authority for roles and permissions. Your app defines what roles/permissions it needs. If SimpleAuth doesn't have them (first deploy, database reset, new permission added), your app breaks. The bootstrap endpoint is **idempotent** — calling it 100 times is the same as calling it once.

### How It Works

Add this to your app's startup code (runs before serving requests):

```bash
# Call this on EVERY app startup — it's idempotent
curl -X POST https://auth.example.com/sauth/api/admin/bootstrap \
  -H "Authorization: Bearer $AUTH_ADMIN_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "permissions": [
      "documents:read",
      "documents:write",
      "documents:delete",
      "users:manage",
      "settings:manage"
    ],
    "role_permissions": {
      "ADMIN": ["documents:read", "documents:write", "documents:delete", "users:manage", "settings:manage"],
      "EDITOR": ["documents:read", "documents:write"],
      "VIEWER": ["documents:read"]
    },
    "users": [
      {
        "username": "admin",
        "password": "'$ROOT_PASSWORD'",
        "display_name": "System Administrator",
        "roles": ["ADMIN"],
        "force_password": true
      }
    ]
  }'
```

### What This Does

1. **Permissions** — ensures all permissions exist in SimpleAuth. If they already exist, nothing changes. If you add a new permission to the list, it gets registered.
2. **Role-permissions mapping** — ensures all roles exist with the correct permissions. If a role already exists, its permissions are updated to match.
3. **Users** — creates the user if they don't exist. If `force_password: true`, the password is reset to the configured value on EVERY startup (so the env var / config always dictates the root password).

### Code Examples

**Go:**
```go
func bootstrapAuth(simpleauthURL, adminKey, rootPassword string) error {
    body := map[string]interface{}{
        "permissions": []string{"documents:read", "documents:write", "users:manage"},
        "role_permissions": map[string][]string{
            "ADMIN":  {"documents:read", "documents:write", "users:manage"},
            "VIEWER": {"documents:read"},
        },
        "users": []map[string]interface{}{
            {
                "username":       "admin",
                "password":       rootPassword,
                "roles":          []string{"ADMIN"},
                "force_password": true,
            },
        },
    }
    data, _ := json.Marshal(body)
    req, _ := http.NewRequest("POST", simpleauthURL+"/api/admin/bootstrap", bytes.NewReader(data))
    req.Header.Set("Authorization", "Bearer "+adminKey)
    req.Header.Set("Content-Type", "application/json")
    resp, err := http.DefaultClient.Do(req)
    if err != nil {
        return err
    }
    defer resp.Body.Close()
    if resp.StatusCode != 200 {
        body, _ := io.ReadAll(resp.Body)
        return fmt.Errorf("bootstrap failed: %s", body)
    }
    return nil
}

// Call in main() before starting your server:
// bootstrapAuth(os.Getenv("SIMPLEAUTH_URL"), os.Getenv("AUTH_ADMIN_KEY"), os.Getenv("ROOT_PASSWORD"))
```

**JavaScript/TypeScript:**
```typescript
async function bootstrapAuth(simpleauthUrl: string, adminKey: string, rootPassword: string) {
  const resp = await fetch(`${simpleauthUrl}/api/admin/bootstrap`, {
    method: 'POST',
    headers: {
      'Authorization': `Bearer ${adminKey}`,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({
      permissions: ['documents:read', 'documents:write', 'users:manage'],
      role_permissions: {
        ADMIN: ['documents:read', 'documents:write', 'users:manage'],
        VIEWER: ['documents:read'],
      },
      users: [{
        username: 'admin',
        password: rootPassword,
        roles: ['ADMIN'],
        force_password: true,
      }],
    }),
  });
  if (!resp.ok) throw new Error(`Bootstrap failed: ${await resp.text()}`);
}

// Call before app.listen():
// await bootstrapAuth(process.env.SIMPLEAUTH_URL, process.env.AUTH_ADMIN_KEY, process.env.ROOT_PASSWORD);
```

**Python:**
```python
import requests

def bootstrap_auth(simpleauth_url: str, admin_key: str, root_password: str):
    resp = requests.post(
        f"{simpleauth_url}/api/admin/bootstrap",
        headers={"Authorization": f"Bearer {admin_key}", "Content-Type": "application/json"},
        json={
            "permissions": ["documents:read", "documents:write", "users:manage"],
            "role_permissions": {
                "ADMIN": ["documents:read", "documents:write", "users:manage"],
                "VIEWER": ["documents:read"],
            },
            "users": [{
                "username": "admin",
                "password": root_password,
                "roles": ["ADMIN"],
                "force_password": True,
            }],
        },
    )
    resp.raise_for_status()

# Call at app startup:
# bootstrap_auth(os.environ["SIMPLEAUTH_URL"], os.environ["AUTH_ADMIN_KEY"], os.environ["ROOT_PASSWORD"])
```

### Key Rules

- **Call it on EVERY startup** — don't skip it, don't put it behind a flag, don't check "if first run"
- **`force_password: true`** for the root user — this means the password in your env var ALWAYS wins. If someone changes it in the UI, the next restart resets it. This is intentional — the config is the source of truth.
- **`force_password: false`** (or omitted) for regular users — password is only set on first creation, not overwritten on subsequent startups
- **Add new permissions freely** — just add them to the array and restart. Existing permissions are untouched, new ones are registered.
- **The admin key comes from env var** — never hardcode it in your app code. Use `os.Getenv("AUTH_ADMIN_KEY")` / `process.env.AUTH_ADMIN_KEY`.

---

## How SimpleAuth Works With Your App

SimpleAuth handles **authentication** (who is this user?) and **authorization** (what can they do?). Your app talks to SimpleAuth via HTTP.

```
User → Your App → SimpleAuth → Active Directory / LDAP
                ↓
         Your App gets a JWT with user info, roles, permissions
```

**Important:** SimpleAuth stores users, roles, and permissions. But your app might ALSO have its own user table (for app-specific data like preferences, profiles). When a user first authenticates via SimpleAuth, your app needs to **create a local user record** linked to SimpleAuth's user GUID.

### The First-Login Pattern

When a user logs in via Kerberos/LDAP/SSO for the first time, SimpleAuth auto-creates them. But YOUR app doesn't know about them yet. Here's how to handle it:

```
1. User clicks "Sign in with SSO" on your app
2. SimpleAuth authenticates via Kerberos → issues JWT
3. Your app receives the JWT
4. Your app decodes the JWT → gets user GUID, name, email, roles
5. Your app checks its OWN database: "Do I have this user GUID?"
   - YES → proceed normally
   - NO → create a new local user record with the GUID, name, email
6. Continue with the authenticated user
```

**Example (Node.js):**
```javascript
app.get('/callback', async (req, res) => {
  const token = extractTokenFromFragment(req);
  const user = await simpleauth.verify(token);
  
  // Check if user exists in YOUR database
  let localUser = await db.users.findByGuid(user.sub);
  if (!localUser) {
    // First login — create local user record
    localUser = await db.users.create({
      guid: user.sub,
      username: user.preferred_username,
      email: user.email,
      name: user.name,
      // App-specific defaults
      role: 'viewer',
      theme: 'auto',
    });
  }
  
  req.session.user = localUser;
  res.redirect('/dashboard');
});
```

**Using the Bootstrap Endpoint:** If you want SimpleAuth to be the ONLY user store (no separate app database), use the bootstrap endpoint to pre-define roles and permissions, then read everything from the JWT claims:

```bash
curl -X POST https://auth.example.com/sauth/api/admin/bootstrap \
  -H "Authorization: Bearer YOUR_ADMIN_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "permissions": ["read", "write", "admin"],
    "role_permissions": {
      "viewer": ["read"],
      "editor": ["read", "write"],
      "admin": ["read", "write", "admin"]
    },
    "users": [{
      "username": "admin",
      "password": "initial-password",
      "roles": ["admin"],
      "force_password": true
    }]
  }'
```

---

## Behind a Reverse Proxy (nginx, Traefik, Caddy)

Most production deployments put SimpleAuth behind a reverse proxy. This requires specific configuration.

### Required Environment Variables

```bash
AUTH_TLS_DISABLED=true              # SimpleAuth serves plain HTTP; proxy handles TLS
AUTH_TRUSTED_PROXIES=172.16.0.0/12  # Trust proxy's IP range for X-Forwarded-For
AUTH_HOSTNAME=auth.example.com      # Your public hostname (used in JWT issuer, redirects)
```

### Why AUTH_TRUSTED_PROXIES Matters

Without this, SimpleAuth sees ALL requests coming from the proxy's IP address. This means:
- **Rate limiting breaks:** 10 requests/minute from the proxy IP = ALL users get locked out
- **Audit logs are wrong:** Every event shows the proxy IP, not the real user
- **Account lockout affects everyone:** One user's failed logins lock out all users behind the same proxy

**Common values:**
```bash
# Docker default bridge
AUTH_TRUSTED_PROXIES=172.16.0.0/12

# Kubernetes
AUTH_TRUSTED_PROXIES=10.0.0.0/8

# Multiple ranges
AUTH_TRUSTED_PROXIES=172.16.0.0/12,10.0.0.0/8,192.168.0.0/16
```

### CSRF and TLS

SimpleAuth's login form uses CSRF cookies. When TLS is disabled (proxy handles TLS), SimpleAuth automatically:
- Sets `Secure=false` on CSRF cookies (so they work over HTTP between proxy and SimpleAuth)
- Sets `SameSite=Lax` instead of `Strict`

**You don't need to do anything** — just set `AUTH_TLS_DISABLED=true`.

### nginx Example

```nginx
server {
    listen 443 ssl;
    server_name auth.example.com;

    ssl_certificate /path/to/cert.pem;
    ssl_certificate_key /path/to/key.pem;

    location /sauth/ {
        proxy_pass http://simpleauth:8080/sauth/;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

### Docker Compose Example

```yaml
services:
  simpleauth:
    image: simpleauth
    environment:
      AUTH_HOSTNAME: auth.example.com
      AUTH_ADMIN_KEY: "your-secret-admin-key"
      AUTH_TLS_DISABLED: "true"
      AUTH_TRUSTED_PROXIES: "172.16.0.0/12"
      AUTH_REDIRECT_URIS: "https://myapp.example.com/callback"
      AUTH_CORS_ORIGINS: "https://myapp.example.com"
    volumes:
      - simpleauth-data:/data

  nginx:
    image: nginx:alpine
    ports:
      - "443:443"
    volumes:
      - ./nginx.conf:/etc/nginx/conf.d/default.conf
      - ./certs:/etc/nginx/certs
    depends_on:
      - simpleauth

volumes:
  simpleauth-data:
```

### Docker Compose with PostgreSQL (healthcheck required)

> **CRITICAL:** If you use Postgres, SimpleAuth MUST wait for Postgres to be healthy before starting. Otherwise SimpleAuth's retry+fallback logic may either refuse to start or (in very old deployments) silently fall back to a stale BoltDB — losing recent LDAP/user/settings changes.
>
> Since v1.0.2 SimpleAuth refuses to fall back silently when `db.json` says Postgres, but the deployment still stalls. The fix is a standard `depends_on: condition: service_healthy` + Postgres `healthcheck`.

```yaml
services:
  postgres:
    image: postgres:16
    restart: always
    environment:
      POSTGRES_DB: simpleauth
      POSTGRES_USER: simpleauth
      POSTGRES_PASSWORD: change-me
    volumes:
      - pg-data:/var/lib/postgresql/data
    # Healthcheck is REQUIRED — SimpleAuth depends on it
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U simpleauth -d simpleauth"]
      interval: 5s
      timeout: 5s
      retries: 10
      start_period: 10s

  simpleauth:
    image: simpleauth
    restart: always
    depends_on:
      postgres:
        condition: service_healthy    # <-- the critical part
    environment:
      AUTH_HOSTNAME: auth.example.com
      AUTH_ADMIN_KEY: "your-secret-admin-key"
      AUTH_POSTGRES_URL: "postgres://simpleauth:change-me@postgres:5432/simpleauth?sslmode=disable"
      AUTH_TLS_DISABLED: "true"
      AUTH_TRUSTED_PROXIES: "172.16.0.0/12"
      AUTH_REDIRECT_URIS: "https://myapp.example.com/callback"
      AUTH_CORS_ORIGINS: "https://myapp.example.com"
    volumes:
      - simpleauth-data:/data

  nginx:
    image: nginx:alpine
    restart: always
    ports:
      - "443:443"
    volumes:
      - ./nginx.conf:/etc/nginx/conf.d/default.conf
      - ./certs:/etc/nginx/certs
    depends_on:
      - simpleauth

volumes:
  pg-data:
  simpleauth-data:
```

**Why all three pieces matter:**

| Piece | Without it |
|-------|-----------|
| `healthcheck` on Postgres | Docker has no way to know when Postgres is ready. `depends_on` only ensures process start, not readiness. |
| `condition: service_healthy` on SimpleAuth's `depends_on` | SimpleAuth starts before Postgres accepts connections. It retries 5× with exponential backoff, but on slow hosts that's still not enough. |
| `restart: always` on both | If either crashes (OOM, kernel panic, node reboot), neither will come back. |

**Symptom checklist — did you skip the healthcheck?**

- On first boot, SimpleAuth logs `failed to connect to postgres after 5 retries — refusing to start` → set the healthcheck and restart.
- LDAP config "disappeared" after a restart — previously this meant SimpleAuth fell back to BoltDB (a separate DB file) and served stale data. Since v1.0.2 it refuses to start, so you'll see the error in logs instead. Fix the healthcheck.
- Admin settings changed but didn't persist — same root cause.

---

## Security: Don't Use Wildcards

**Never do this in production:**
```bash
AUTH_REDIRECT_URIS=*                    # DANGER: allows redirect to ANY URL
AUTH_CORS_ORIGINS=*                     # DANGER: allows ANY website to call your API
AUTH_TRUSTED_PROXIES=0.0.0.0/0          # DANGER: trusts ANY IP as a proxy
```

**Why wildcards are dangerous:**

| Parameter | Wildcard Risk |
|---|---|
| `AUTH_REDIRECT_URIS=*` | Attacker sends user a link to `https://auth.example.com/sauth/login?redirect_uri=https://evil.com/steal` → user logs in → tokens sent to attacker |
| `AUTH_CORS_ORIGINS=*` | Any website can make authenticated requests to your SimpleAuth API |
| `AUTH_TRUSTED_PROXIES=0.0.0.0/0` | Anyone can spoof their IP via X-Forwarded-For, bypassing rate limiting |

**Do this instead:**
```bash
# List specific allowed redirect URLs
AUTH_REDIRECT_URIS="https://myapp.example.com/callback,https://myapp.example.com/auth/callback"

# List specific allowed CORS origins
AUTH_CORS_ORIGINS="https://myapp.example.com,https://admin.example.com"

# List specific proxy CIDR ranges
AUTH_TRUSTED_PROXIES="172.16.0.0/12"
```

**Wildcard suffix for redirect URIs** (safe — matches path only, not domain):
```bash
# This is OK — matches any path under myapp.example.com
AUTH_REDIRECT_URIS="https://myapp.example.com/*"

# This is NOT OK — would match myapp.example.com.evil.com
# (SimpleAuth prevents this — wildcard requires a / before *)
```

---

## Kerberos SSO: What Your App Needs to Do

When a user authenticates via Kerberos SSO, SimpleAuth handles the entire authentication flow. Your app receives the same JWT as any other login method. **You don't need Kerberos libraries in your app.**

### Flow

```
1. User visits your app
2. Your app redirects to: https://auth.example.com/sauth/login?redirect_uri=https://myapp.example.com/callback
3. SimpleAuth's login page shows "Sign in with Single Sign-On"
4. User clicks SSO (or auto-SSO does it automatically)
5. Browser sends Kerberos ticket to SimpleAuth
6. SimpleAuth validates ticket, creates/updates user, issues JWT
7. SimpleAuth redirects to: https://myapp.example.com/callback#access_token=eyJ...
8. Your app extracts the token from the URL fragment
```

### What Your App Receives

The JWT from SSO login is IDENTICAL to a password login. Same claims, same format:
```json
{
  "sub": "user-guid",
  "preferred_username": "kalahmad",
  "name": "Khalefa Ahmad",
  "email": "kalahmad@corp.local",
  "roles": ["user"],
  "permissions": ["read"],
  "groups": ["Domain Users", "IT Department"]
}
```

### Linux Client Setup

Download the setup script from the admin UI (LDAP Settings → "Linux SSO Script"). It configures:
- `/etc/krb5.conf` — Kerberos realm and KDC
- Browser policies — Firefox, Chrome, Edge, Brave, Vivaldi, Opera
- Optional SSSD domain join — auto-ticket on Linux login

---

## Token Lifecycle

```
Login → access_token (15 min) + refresh_token (30 days)
        ↓
        Use access_token for API calls
        ↓
        Token expiring? → POST /api/auth/refresh with refresh_token
        ↓
        Get NEW access_token + NEW refresh_token
        ↓
        IMPORTANT: Use the NEW refresh_token. Old one is invalidated.
        ↓
        If old refresh_token is reused → ALL tokens for that user are revoked (security)
```

### Refresh Example

```bash
curl -X POST https://auth.example.com/sauth/api/auth/refresh \
  -H "Content-Type: application/json" \
  -d '{"refresh_token":"eyJ...old-refresh-token..."}'
```

Response:
```json
{
  "access_token": "eyJ...new...",
  "refresh_token": "eyJ...NEW-refresh-token...",
  "expires_in": 900,
  "token_type": "Bearer"
}
```

**Always store and use the new `refresh_token`.** The old one is now invalid.

---

## Production Checklist

Before going live, verify:

- [ ] `AUTH_HOSTNAME` set to your public domain
- [ ] `AUTH_ADMIN_KEY` set to a strong, persistent secret (not auto-generated)
- [ ] `AUTH_REDIRECT_URIS` set to your app's exact callback URLs (no wildcards)
- [ ] `AUTH_TRUSTED_PROXIES` set if behind reverse proxy
- [ ] `AUTH_CORS_ORIGINS` set if frontend calls SimpleAuth directly
- [ ] LDAP/AD configured and tested (green dot in admin UI)
- [ ] Kerberos setup completed (if using SSO)
- [ ] Test user can log in and get a valid token
- [ ] Token refresh works
- [ ] Logout redirects correctly (use `/logout` not `/login`)
- [ ] Health check responds: `GET /sauth/health`

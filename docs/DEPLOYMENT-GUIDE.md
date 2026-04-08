# Deployment Guide

Real-world deployment scenarios, common mistakes, and how to avoid them.

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

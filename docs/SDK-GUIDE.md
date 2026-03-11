# SimpleAuth SDK Guide

Official SDKs for JavaScript/TypeScript, Go, Python, and .NET. All four SDKs follow the same patterns: authenticate, verify tokens, check roles, and use middleware.

---

## Quick Comparison

| Feature | JavaScript/TS | Go | Python | .NET |
|---|---|---|---|---|
| **Install** | `npm i @simpleauth/js` | `go get simpleauth/sdk/go` | `pip install simpleauth` | `dotnet add package SimpleAuth` |
| **Zero deps** | Yes | Yes | `requests`, `cryptography` | System.Text.Json |
| **Token verify** | `auth.verify(token)` | `client.Verify(token)` | `auth.verify(token)` | `await client.VerifyAsync(token)` |
| **Middleware** | Express | net/http | FastAPI, Flask, Django | ASP.NET Core |
| **JWKS caching** | Yes (1h TTL) | Yes (1h TTL) | Yes (1h TTL) | Yes (1h TTL) |
| **Role check** | `user.hasRole("admin")` | `user.HasRole("admin")` | `user.has_role("admin")` | `user.HasRole("admin")` |
| **Self-signed TLS** | Node: custom agent | `InsecureSkipVerify` | `verify_ssl=False` | `ValidateSsl = false` |

---

## JavaScript / TypeScript

### Installation

```bash
npm install @simpleauth/js
# or
yarn add @simpleauth/js
```

Works in Node.js 18+ and modern browsers. Zero external dependencies.

### Initialize

```typescript
import { createSimpleAuth } from '@simpleauth/js';

const auth = createSimpleAuth({
  url: 'https://auth.corp.local:8080',
  realm: 'simpleauth',        // optional, default 'simpleauth'
});
```

### Login (Resource Owner Password)

```typescript
const tokens = await auth.login('jsmith', 'password');
// tokens.access_token, tokens.refresh_token, tokens.id_token, tokens.force_password_change
```

### Refresh Tokens

```typescript
const newTokens = await auth.refresh(tokens.refresh_token);
```

### Verify Token (Server-Side)

```typescript
const user = await auth.verify(accessToken);

console.log(user.sub);          // GUID
console.log(user.name);         // "John Smith"
console.log(user.email);        // "jsmith@corp.local"
console.log(user.roles);        // ["admin", "user"]
console.log(user.permissions);  // ["read:reports"]
console.log(user.groups);       // ["CN=Engineering,..."]
console.log(user.department);   // "Engineering"
console.log(user.company);      // "Acme Corp"
console.log(user.job_title);    // "Senior Engineer"

// Role & permission checks
user.hasRole('admin');           // true
user.hasPermission('read:reports');  // true
user.hasAnyRole('admin', 'manager'); // true
```

### Express Middleware

```typescript
import express from 'express';

const app = express();

// Protect all routes under /api
app.use('/api', auth.expressMiddleware());

app.get('/api/profile', (req, res) => {
  // req.user is a SimpleAuthUser
  res.json({
    name: req.user.name,
    roles: req.user.roles,
    isAdmin: req.user.hasRole('admin'),
  });
});

// Optional authentication (don't reject unauthenticated requests)
app.use('/public', auth.expressMiddleware({ required: false }));

app.get('/public/info', (req, res) => {
  if (req.user) {
    res.json({ greeting: `Hello, ${req.user.name}` });
  } else {
    res.json({ greeting: 'Hello, guest' });
  }
});
```

### Authorization Code Flow

```typescript
// Step 1: Redirect user to login
const authUrl = auth.getAuthorizationUrl({
  redirectUri: 'https://myapp.com/callback',
  state: 'random-csrf-token',
  scope: 'openid profile email',
});
// Redirect the browser to authUrl

// Step 2: Handle callback
app.get('/callback', async (req, res) => {
  const { code, state } = req.query;
  // Verify state matches what you sent
  const tokens = await auth.exchangeCode(code, 'https://myapp.com/callback');
  // Store tokens in session
});
```

### Admin Operations

```typescript
// Initialize with admin key for admin operations
const adminAuth = createSimpleAuth({
  url: 'https://auth.corp.local:8080',
  adminKey: 'YOUR_ADMIN_KEY',
});

// Get user details
const user = await adminAuth.getUser('user-guid');

// Manage roles (global per instance)
const roles = await adminAuth.getUserRoles('user-guid');
await adminAuth.setUserRoles('user-guid', ['admin', 'user']);

// Manage permissions (global per instance)
const perms = await adminAuth.getUserPermissions('user-guid');
await adminAuth.setUserPermissions('user-guid', ['read:all', 'write:config']);
```

### Logout

```typescript
await auth.logout(idToken);
```

---

## Go

### Installation

```bash
go get simpleauth/sdk/go
```

Zero external dependencies. Uses only the Go standard library.

### Initialize

```go
import simpleauth "simpleauth/sdk/go"

client := simpleauth.New(simpleauth.Options{
    URL:                "https://auth.corp.local:8080",
    Realm:              "simpleauth",    // optional
    InsecureSkipVerify: true,            // for self-signed certs
})
```

### Login

```go
ctx := context.Background()
tokens, err := client.Login(ctx, "jsmith", "password")
if err != nil {
    log.Fatal(err)
}
fmt.Println(tokens.AccessToken)
```

### Refresh Tokens

```go
newTokens, err := client.Refresh(ctx, tokens.RefreshToken)
```

### Client Credentials (Machine-to-Machine)

```go
tokens, err := client.ClientCredentials(ctx)
```

### Verify Token

```go
user, err := client.Verify(accessToken)
if err != nil {
    // Token invalid, expired, or signature mismatch
    http.Error(w, "unauthorized", 401)
    return
}

fmt.Println(user.Sub)         // GUID
fmt.Println(user.Name)        // "John Smith"
fmt.Println(user.Roles)       // ["admin"]
user.HasRole("admin")         // true
user.HasPermission("read:x")  // true
user.HasAnyRole("admin", "mod") // true
```

### HTTP Middleware

```go
mux := http.NewServeMux()

// Protect all routes
mux.Handle("/api/", client.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
    user := simpleauth.UserFromContext(r.Context())
    fmt.Fprintf(w, "Hello, %s", user.Name)
})))

// Require a specific role
mux.Handle("/admin/", client.RequireRole("admin", adminHandler))

// Require a specific permission
mux.Handle("/reports/", client.RequirePermission("read:reports", reportsHandler))
```

### Extract User in Handlers

```go
func myHandler(w http.ResponseWriter, r *http.Request) {
    user := simpleauth.UserFromContext(r.Context())
    if user == nil {
        http.Error(w, "not authenticated", 401)
        return
    }

    if !user.HasRole("admin") {
        http.Error(w, "forbidden", 403)
        return
    }

    // Proceed with admin logic
}
```

### Authorization Code Flow

```go
// Exchange code from callback
tokens, err := client.ExchangeCode(ctx, code, "https://myapp.com/callback")
```

### Admin Operations

```go
// Initialize with admin key
adminClient := simpleauth.New(simpleauth.Options{
    URL:      "https://auth.corp.local:8080",
    AdminKey: "YOUR_ADMIN_KEY",
})

// Get/set roles (global per instance)
roles, err := adminClient.GetUserRoles(ctx, "user-guid")
err = adminClient.SetUserRoles(ctx, "user-guid", []string{"admin", "user"})

// Get/set permissions (global per instance)
perms, err := adminClient.GetUserPermissions(ctx, "user-guid")
err = adminClient.SetUserPermissions(ctx, "user-guid", []string{"read:all"})
```

---

## Python

### Installation

```bash
pip install simpleauth
```

Requires `requests` and `cryptography` (both are widely used, stable dependencies).

### Initialize

```python
from simpleauth import SimpleAuth

auth = SimpleAuth(
    url="https://auth.corp.local:8080",
    realm="simpleauth",     # optional
    verify_ssl=False,        # for self-signed certs
)
```

### Login

```python
tokens = auth.login("jsmith", "password")
print(tokens.access_token)
print(tokens.refresh_token)
```

### Refresh Tokens

```python
new_tokens = auth.refresh(tokens.refresh_token)
```

### Client Credentials

```python
tokens = auth.client_credentials()
```

### Verify Token

```python
user = auth.verify(access_token)

print(user.sub)          # GUID
print(user.name)         # "John Smith"
print(user.email)        # "jsmith@corp.local"
print(user.roles)        # ["admin"]
print(user.permissions)  # ["read:reports"]
print(user.department)   # "Engineering"

user.has_role("admin")           # True
user.has_permission("read:all")  # True
user.has_any_role("admin", "mod") # True
```

### FastAPI Integration

```python
from fastapi import Depends, FastAPI
from simpleauth import SimpleAuth, User
from simpleauth.middleware import SimpleAuthDep

auth = SimpleAuth(url="https://auth.corp.local:8080")
get_user = SimpleAuthDep(auth)

app = FastAPI()

@app.get("/profile")
async def profile(user: User = Depends(get_user)):
    return {"name": user.name, "roles": user.roles}

# With role requirement
require_admin = SimpleAuthDep(auth, required_role="admin")

@app.get("/admin")
async def admin_only(user: User = Depends(require_admin)):
    return {"admin": user.name}

# With permission requirement
require_read = SimpleAuthDep(auth, required_permission="read:reports")

@app.get("/reports")
async def reports(user: User = Depends(require_read)):
    return {"reports": "..."}
```

### Flask Integration

```python
from flask import Flask, g, jsonify
from simpleauth import SimpleAuth
from simpleauth.middleware import flask_middleware

auth = SimpleAuth(url="https://auth.corp.local:8080")
app = Flask(__name__)

@app.route("/profile")
@flask_middleware(auth)
def profile():
    user = g.user
    return jsonify({"name": user.name})

@app.route("/admin")
@flask_middleware(auth, required_role="admin")
def admin_only():
    return jsonify({"admin": g.user.name})
```

### Django Integration

```python
# settings.py
MIDDLEWARE = [
    # ... other middleware
    "simpleauth.middleware.SimpleAuthMiddleware",
]

SIMPLEAUTH_URL = "https://auth.corp.local:8080"
SIMPLEAUTH_REALM = "simpleauth"
SIMPLEAUTH_VERIFY_SSL = True

# views.py
from simpleauth.middleware import django_login_required

@django_login_required()
def profile(request):
    user = request.simpleauth_user
    return JsonResponse({"name": user.name})

@django_login_required(required_role="admin")
def admin_view(request):
    return JsonResponse({"admin": request.simpleauth_user.name})
```

### Admin Operations

```python
admin_auth = SimpleAuth(
    url="https://auth.corp.local:8080",
    admin_key="YOUR_ADMIN_KEY",
)

# Global roles and permissions
roles = admin_auth.get_user_roles("user-guid")
admin_auth.set_user_roles("user-guid", ["admin", "user"])

perms = admin_auth.get_user_permissions("user-guid")
admin_auth.set_user_permissions("user-guid", ["read:all"])
```

### Authorization Code Flow

```python
# Build the authorization URL
auth_url = auth.get_authorization_url(
    redirect_uri="https://myapp.com/callback",
    state="random-csrf-token",
)
# Redirect user to auth_url

# Exchange code for tokens (in your callback handler)
tokens = auth.exchange_code(code, "https://myapp.com/callback")
```

---

## .NET (C#)

### Installation

```bash
dotnet add package SimpleAuth
```

### Initialize

```csharp
using SimpleAuth;

var options = new SimpleAuthOptions
{
    Url = "https://auth.corp.local:8080",
    Realm = "simpleauth",
    ValidateSsl = false,     // for self-signed certs
};

using var client = new SimpleAuthClient(options);
```

### Login

```csharp
var tokens = await client.LoginAsync("jsmith", "password");
Console.WriteLine(tokens.AccessToken);
```

### Refresh Tokens

```csharp
var newTokens = await client.RefreshAsync(tokens.RefreshToken);
```

### Client Credentials

```csharp
var tokens = await client.ClientCredentialsAsync();
```

### Verify Token

```csharp
var user = await client.VerifyAsync(accessToken);

Console.WriteLine(user.Sub);          // GUID
Console.WriteLine(user.Name);         // "John Smith"
Console.WriteLine(user.Email);        // "jsmith@corp.local"
Console.WriteLine(user.Roles);        // ["admin"]
Console.WriteLine(user.Department);   // "Engineering"

user.HasRole("admin");                // true
user.HasPermission("read:reports");   // true
```

### ASP.NET Core Middleware

```csharp
// Program.cs
var builder = WebApplication.CreateBuilder(args);

builder.Services.AddSimpleAuth(opts =>
{
    opts.Url = "https://auth.corp.local:8080";
    opts.ValidateSsl = false;
});

var app = builder.Build();

app.UseSimpleAuth();  // Add after UseRouting, before MapControllers

app.MapGet("/profile", (HttpContext ctx) =>
{
    var user = ctx.GetSimpleAuthUser();
    if (user is null)
        return Results.Unauthorized();

    return Results.Ok(new { user.Name, user.Roles });
});

app.Run();
```

### Role-Based Authorization Attributes

```csharp
using SimpleAuth;

[ApiController]
[Route("api/[controller]")]
public class AdminController : ControllerBase
{
    [HttpGet]
    [SimpleAuthRole("admin")]
    public IActionResult GetAdminData()
    {
        var user = HttpContext.GetSimpleAuthUser()!;
        return Ok(new { message = $"Hello admin {user.Name}" });
    }

    [HttpPost("config")]
    [SimpleAuthPermission("write:config")]
    public IActionResult UpdateConfig()
    {
        return Ok(new { status = "updated" });
    }
}
```

### Admin Operations

```csharp
var adminClient = new SimpleAuthClient(new SimpleAuthOptions
{
    Url = "https://auth.corp.local:8080",
    AdminKey = "YOUR_ADMIN_KEY",
});

// Global roles and permissions
var roles = await adminClient.GetUserRolesAsync("user-guid");
await adminClient.SetUserRolesAsync("user-guid", new List<string> { "admin", "user" });

var perms = await adminClient.GetUserPermissionsAsync("user-guid");
await adminClient.SetUserPermissionsAsync("user-guid", new List<string> { "read:all" });
```

### Authorization Code Flow

```csharp
// Build URL
var authUrl = client.GetAuthorizationUrl(
    redirectUri: "https://myapp.com/callback",
    state: "random-csrf-token"
);

// Exchange code
var tokens = await client.ExchangeCodeAsync(code, "https://myapp.com/callback");
```

---

## Common Patterns

### Pattern 1: Backend API Protection

The most common pattern. Your API verifies JWTs on every request.

```
Browser/Client --> Your API (with Bearer token) --> SimpleAuth JWKS (cached)
                                                     (verify signature locally)
```

Token verification is **local** -- no network call to SimpleAuth per request. The JWKS (public keys) are cached for 1 hour and refreshed automatically.

### Pattern 2: Role-Based Access Control

Assign roles to users. Check them in your handlers.

> **Note:** Roles must be defined in SimpleAuth before they can be assigned to users. Define the available roles first via the admin UI or `PUT /api/admin/defaults/roles`, then assign them to individual users.

```
Admin: PUT /api/admin/users/guid/roles ["admin", "editor"]
Login: roles appear in the JWT
App:   user.hasRole("editor") ? allow : deny
```

### Pattern 3: Permission-Based Access Control

More granular than roles. Use for specific operations.

> **Note:** Permissions must be defined in SimpleAuth before they can be assigned to users. Define the available permissions first via the admin UI or `PUT /api/admin/permissions`, then assign them to individual users.

```
Admin: PUT /api/admin/users/guid/permissions ["read:posts", "write:posts", "delete:own-posts"]
Login: permissions appear in the JWT
App:   user.hasPermission("delete:own-posts") ? allow : deny
```

### Pattern 4: Self-Signed Certs in Development

Every SDK supports disabling TLS verification for development with self-signed certificates.

| SDK | Setting |
|---|---|
| JavaScript | Use a custom fetch agent with `NODE_TLS_REJECT_UNAUTHORIZED=0` |
| Go | `InsecureSkipVerify: true` |
| Python | `verify_ssl=False` |
| .NET | `ValidateSsl = false` |

Never disable TLS verification in production. Use a proper certificate (Let's Encrypt, internal CA, etc.).

### Pattern 5: Admin Operations via SDK

Use the admin key to manage roles and permissions. SimpleAuth acts as the authority for roles and permissions -- they must be defined in SimpleAuth before they can be assigned to users.

```typescript
const adminAuth = createSimpleAuth({
  url: 'https://auth.corp.local:8080',
  adminKey: 'YOUR_ADMIN_KEY',
});

// Step 1: Define available permissions (PUT /api/admin/permissions)
// This is done via the admin UI or API before assigning to users.

// Step 2: Assign roles and permissions to users
await adminAuth.setUserRoles('user-guid', ['editor']);
await adminAuth.setUserPermissions('user-guid', ['write:posts']);
```

### Pattern 6: Handling Force Password Change

All SDKs include a `force_password_change` field in the token response. When login returns `force_password_change: true`, the user must change their password before proceeding. Your app should check this field after every login and redirect the user to a password change screen when it is set.

**JavaScript/TypeScript:**

```typescript
const tokens = await auth.login('jsmith', 'password');
if (tokens.force_password_change) {
  // Redirect user to change password before allowing access
  window.location.href = '/change-password';
  return;
}
// Proceed normally
```

**Go:**

```go
tokens, err := client.Login(ctx, "jsmith", "password")
if err != nil {
    log.Fatal(err)
}
if tokens.ForcePasswordChange {
    // Redirect user to change password
}
```

**Python:**

```python
tokens = auth.login("jsmith", "password")
if tokens.force_password_change:
    # Redirect user to change password
    pass
```

**.NET:**

```csharp
var tokens = await client.LoginAsync("jsmith", "password");
if (tokens.ForcePasswordChange)
{
    // Redirect user to change password
}
```

Do not allow the user to access protected resources until they have changed their password. This is typically enforced by your application's frontend routing or middleware.

---

## Error Handling

All SDKs throw/return errors with consistent information:

| SDK | Error Type | Properties |
|---|---|---|
| JavaScript | `SimpleAuthError` | `message`, `status`, `code`, `description` |
| Go | `error` (standard) | Error message with status code |
| Python | `SimpleAuthError`, `AuthenticationError`, `TokenVerificationError` | `message`, `status_code`, `detail` |
| .NET | `SimpleAuthException` | `Message` |

Common error scenarios:
- **Invalid credentials** -- Login fails, returns 401
- **Expired token** -- Verify fails, catch and refresh
- **Token reuse** -- Refresh fails with "token reuse detected", user must log in again
- **Network error** -- JWKS fetch fails, thrown as an error
- **Missing role** -- Middleware returns 403

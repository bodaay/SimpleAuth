# SimpleAuth Python SDK

Python SDK for [SimpleAuth](https://github.com/bodaay/simpleauth) -- an OIDC-compatible authentication server.

## Installation

```bash
pip install simpleauth

# With framework extras:
pip install simpleauth[fastapi]
pip install simpleauth[flask]
pip install simpleauth[django]
```

## Quick Start

```python
from simpleauth import SimpleAuth

auth = SimpleAuth(
    url="https://auth.example.com",
    client_id="my-client",       # optional, for OIDC flows
    client_secret="my-secret",   # optional
    realm="simpleauth",          # default
)
```

## Authentication

### Password Login (Resource Owner)

```python
tokens = auth.login(username="alice", password="secret")
print(tokens.access_token)
print(tokens.refresh_token)
```

### Handling Force Password Change

The login response may indicate that the user must change their password before proceeding:

```python
tokens = auth.login(username="alice", password="secret")
if tokens.force_password_change:
    # Redirect user to password change page
```

### Refresh Token

```python
new_tokens = auth.refresh(refresh_token=tokens.refresh_token)
```

### Client Credentials (Machine-to-Machine)

```python
tokens = auth.client_credentials()
print(tokens.access_token)
```

### Authorization Code Flow

```python
# Step 1: Redirect user to the authorization URL
url = auth.get_authorization_url(
    redirect_uri="https://myapp.com/callback",
    state="random-state-value",
)

# Step 2: Exchange the code from the callback
tokens = auth.exchange_code(code="auth-code-from-callback", redirect_uri="https://myapp.com/callback")
```

## Token Verification

Verify a JWT access token locally using the server's JWKS (cached for 1 hour, re-fetched on key ID miss):

```python
user = auth.verify(tokens.access_token)

print(user.sub)           # user GUID
print(user.name)          # display name
print(user.email)
print(user.roles)         # ["admin", "editor"]
print(user.permissions)   # ["read:posts", "write:posts"]
print(user.groups)        # LDAP groups
print(user.department)
print(user.company)
print(user.job_title)

# Role/permission checks
if user.has_role("admin"):
    print("User is admin")

if user.has_permission("write:posts"):
    print("User can write posts")

if user.has_any_role("admin", "editor"):
    print("User is admin or editor")
```

## User Info

Fetch user info from the server (requires a valid access token):

```python
info = auth.userinfo(access_token=tokens.access_token)
```

## Admin Operations

Manage user roles and permissions (requires `client_secret`). The secret is sent as a Bearer token (not Basic auth) to the SimpleAuth admin API:

```python
# Roles
roles = auth.get_user_roles(guid="user-guid")
auth.set_user_roles(guid="user-guid", roles=["admin", "editor"])

# Permissions
perms = auth.get_user_permissions(guid="user-guid")
auth.set_user_permissions(guid="user-guid", permissions=["read:posts", "write:posts"])
```

## Framework Middleware

### FastAPI

```python
from fastapi import Depends, FastAPI
from simpleauth import SimpleAuth, User
from simpleauth.middleware import SimpleAuthDep

auth = SimpleAuth(url="https://auth.example.com")

# Create a dependency
get_user = SimpleAuthDep(auth)

# Or with a role requirement
require_admin = SimpleAuthDep(auth, required_role="admin")

app = FastAPI()

@app.get("/me")
async def me(user: User = Depends(get_user)):
    return {"sub": user.sub, "name": user.name, "roles": user.roles}

@app.get("/admin")
async def admin(user: User = Depends(require_admin)):
    return {"admin": user.name}
```

### Flask

```python
from flask import Flask, g, jsonify
from simpleauth import SimpleAuth
from simpleauth.middleware import flask_middleware

auth = SimpleAuth(url="https://auth.example.com")
app = Flask(__name__)

@app.route("/me")
@flask_middleware(auth)
def me():
    user = g.user
    return jsonify({"sub": user.sub, "name": user.name})

@app.route("/admin")
@flask_middleware(auth, required_role="admin")
def admin():
    return jsonify({"admin": g.user.name})
```

### Django

Add the middleware to `settings.py`:

```python
# settings.py
MIDDLEWARE = [
    ...
    "simpleauth.middleware.SimpleAuthMiddleware",
]

SIMPLEAUTH_URL = "https://auth.example.com"
SIMPLEAUTH_CLIENT_ID = ""           # optional, for OIDC flows
SIMPLEAUTH_CLIENT_SECRET = ""       # optional
SIMPLEAUTH_REALM = "simpleauth"     # optional
SIMPLEAUTH_VERIFY_SSL = True        # optional
```

Use in views:

```python
from simpleauth.middleware import django_login_required

@django_login_required()
def my_view(request):
    user = request.simpleauth_user
    return JsonResponse({"sub": user.sub, "name": user.name})

@django_login_required(required_role="admin")
def admin_view(request):
    return JsonResponse({"admin": request.simpleauth_user.name})
```

## Self-Signed Certificates

For development with self-signed TLS certificates:

```python
auth = SimpleAuth(
    url="https://localhost:8443",
    verify_ssl=False,
)
```

## Error Handling

```python
from simpleauth import SimpleAuth, AuthenticationError, TokenVerificationError, SimpleAuthError

auth = SimpleAuth(url="https://auth.example.com")

try:
    tokens = auth.login("alice", "wrong-password")
except AuthenticationError as e:
    print(f"Login failed: {e} (status={e.status_code})")

try:
    user = auth.verify("invalid-token")
except TokenVerificationError as e:
    print(f"Token invalid: {e}")
```

## Dependencies

- `requests` -- HTTP client
- `cryptography` -- RSA/JWKS signature verification

No JWT library is used. Tokens are parsed manually (base64url-decode header + payload) and RS256 signatures are verified directly using `cryptography`.

## License

MIT

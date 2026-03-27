# @simpleauth/js

Zero-dependency JavaScript/TypeScript SDK for [SimpleAuth](https://github.com/your-org/simpleauth). Uses direct API endpoints (not OIDC realm URLs). Works in Node.js (18+) and browsers.

## Installation

```bash
npm install @simpleauth/js
```

## Quick Start

```ts
import { SimpleAuth } from '@simpleauth/js';

const auth = new SimpleAuth({
  url: 'https://auth.corp.local:9090',
});
```

## Authentication

### Password Login

Sends `POST /api/auth/login` with a JSON body.

```ts
const tokens = await auth.login('username', 'password');
console.log(tokens.access_token);
console.log(tokens.refresh_token);
```

### Handling Force Password Change

The login response may indicate that the user must change their password before proceeding:

```ts
const tokens = await auth.login('username', 'password');
if (tokens.force_password_change) {
  // Redirect user to password change page
}
```

### Refresh Token

Sends `POST /api/auth/refresh` with a JSON body.

```ts
const newTokens = await auth.refresh(tokens.refresh_token);
```

### Logout

```ts
await auth.logout(tokens.id_token);
```

## Token Verification (Server-Side)

Verify a JWT access token using the server's JWKS (fetched from `GET /.well-known/jwks.json`). The SDK caches JWKS keys for 1 hour and automatically re-fetches on key ID miss.

```ts
const user = await auth.verify(tokens.access_token);

console.log(user.sub);           // GUID
console.log(user.name);          // Display name
console.log(user.email);
console.log(user.roles);         // ['admin', 'editor']
console.log(user.permissions);   // ['read', 'write']
console.log(user.groups);        // ['engineering']
console.log(user.department);
console.log(user.company);
console.log(user.job_title);

// Helper methods
user.hasRole('admin');            // true
user.hasPermission('write');      // true
user.hasAnyRole('admin', 'mod'); // true
```

## User Info

Fetch user claims from `GET /api/auth/userinfo`:

```ts
const info = await auth.userInfo(tokens.access_token);
```

## Express Middleware

Protect your Express routes with automatic JWT verification:

```ts
import express from 'express';
import { SimpleAuth } from '@simpleauth/js';

const app = express();
const auth = new SimpleAuth({
  url: 'https://auth.corp.local:9090',
});

// Require authentication (returns 401 if no valid token)
app.get('/api/protected', auth.expressMiddleware(), (req, res) => {
  const user = req.user; // SimpleAuthUser
  res.json({ message: `Hello ${user.name}` });
});

// Optional authentication (continues without user if no token)
app.get('/api/public', auth.expressMiddleware({ required: false }), (req, res) => {
  if (req.user) {
    res.json({ message: `Hello ${req.user.name}` });
  } else {
    res.json({ message: 'Hello anonymous' });
  }
});
```

### Role-Based Access Control

```ts
function requireRole(...roles) {
  return (req, res, next) => {
    if (!req.user || !req.user.hasAnyRole(...roles)) {
      return res.status(403).json({ error: 'Forbidden' });
    }
    next();
  };
}

app.get('/api/admin',
  auth.expressMiddleware(),
  requireRole('admin'),
  (req, res) => {
    res.json({ admin: true });
  }
);
```

## Admin Operations

Admin operations require the admin key. The key is sent as a Bearer token (not Basic auth) to the SimpleAuth admin API.

### Get User

```ts
const user = await auth.getUser('user-guid-here');
```

### Roles

```ts
// Get roles for a user
const roles = await auth.getUserRoles('user-guid');

// Set roles
await auth.setUserRoles('user-guid', ['admin', 'editor']);
```

### Permissions

```ts
// Get permissions for a user
const perms = await auth.getUserPermissions('user-guid');

// Set permissions
await auth.setUserPermissions('user-guid', ['read', 'write', 'delete']);
```

> **Note:** Roles and permissions must be defined in SimpleAuth before they can be assigned to users. Use the admin API to define roles (`PUT /api/admin/role-permissions`) and permissions (`PUT /api/admin/permissions`) first, or define them in the Admin UI under Roles & Permissions.

## Error Handling

All methods throw `SimpleAuthError` on failure:

```ts
import { SimpleAuthError } from '@simpleauth/js';

try {
  await auth.login('bad-user', 'bad-pass');
} catch (err) {
  if (err instanceof SimpleAuthError) {
    console.error(err.message);      // Human-readable message
    console.error(err.status);       // HTTP status code
    console.error(err.code);         // OAuth2 error code (e.g. 'invalid_grant')
    console.error(err.description);  // OAuth2 error description
  }
}
```

## Configuration

| Option         | Type     | Required | Default         | Description                              |
|----------------|----------|----------|-----------------|------------------------------------------|
| `url`          | `string` | Yes      | --              | SimpleAuth server URL                    |
| `adminKey`     | `string` | No       | --              | Admin key for admin API operations (sent as Bearer token) |
| `clientId`     | `string` | No       | `''`            | **(Deprecated)** OIDC client ID. Accepted but ignored. Will be removed in v1.0. |
| `clientSecret` | `string` | No       | --              | **(Deprecated)** OIDC client secret. Accepted but ignored. Will be removed in v1.0. |
| `realm`        | `string` | No       | `'simpleauth'`  | **(Deprecated)** OIDC realm name. Accepted but ignored. Will be removed in v1.0. |

## Browser Usage

The SDK works in browsers without any bundler configuration. It uses the native `fetch` API and `SubtleCrypto` for RS256 token verification.

```html
<script type="module">
import { SimpleAuth } from './index.js';

const auth = new SimpleAuth({
  url: 'https://auth.corp.local:9090',
});

const tokens = await auth.login('username', 'password');
</script>
```

> **Note:** Do not include `adminKey` in browser code. For browser-based applications, use the hosted login page redirect flow at `/login` instead of embedding credentials.

## Platform Support

- **Node.js** 18+ (uses native `fetch` and `crypto.subtle` or `crypto` module)
- **Browsers** -- all modern browsers with `fetch` and `SubtleCrypto` support
- **Deno** -- compatible via npm specifier
- **Bun** -- compatible

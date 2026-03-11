# simpleauth-go

Go SDK for [SimpleAuth](https://github.com/bodaay/SimpleAuth) — a lightweight OIDC-compatible authentication server.

Zero external dependencies. Uses only the Go standard library.

## Install

```bash
go get github.com/bodaay/simpleauth-go
```

Requires **Go 1.21+**.

## Quick start

```go
package main

import (
    "context"
    "fmt"
    "log"

    sa "github.com/bodaay/simpleauth-go"
)

func main() {
    client := sa.New(sa.Options{
        URL: "https://auth.example.com",
    })

    // Password login
    tok, err := client.Login(context.Background(), "alice", "password123")
    if err != nil {
        log.Fatal(err)
    }
    fmt.Println("Access token:", tok.AccessToken)

    // Verify the token locally (RS256 + JWKS)
    user, err := client.Verify(tok.AccessToken)
    if err != nil {
        log.Fatal(err)
    }
    fmt.Println("Hello,", user.PreferredUsername)
}
```

## Authentication flows

### Resource Owner Password

```go
tok, err := client.Login(ctx, "username", "password")
```

### Client Credentials

```go
tok, err := client.ClientCredentials(ctx)
```

### Authorization Code Exchange

```go
tok, err := client.ExchangeCode(ctx, code, "https://myapp.example.com/callback")
```

### Refresh Token

```go
tok, err := client.Refresh(ctx, tok.RefreshToken)
```

## Handling Force Password Change

The login response may indicate that the user must change their password before proceeding:

```go
// Handle force password change
tok, err := client.Login(ctx, "alice", "password123")
if tok.ForcePasswordChange {
    // Redirect user to change their password before proceeding
}
```

## Token verification

`Verify` decodes and cryptographically verifies a JWT using the RS256 algorithm. Public keys are fetched from the JWKS endpoint and cached for one hour. A cache miss on the `kid` header triggers an automatic re-fetch.

```go
user, err := client.Verify(accessToken)
if err != nil {
    // invalid or expired token
}

fmt.Println(user.Sub, user.Email, user.Roles)
```

## User helpers

```go
if user.HasRole("admin") { ... }
if user.HasPermission("documents:write") { ... }
if user.HasAnyRole("admin", "editor") { ... }
```

## UserInfo endpoint

```go
info, err := client.UserInfo(ctx, accessToken)
```

## HTTP middleware

The SDK provides middleware for `net/http` that validates the `Authorization: Bearer <token>` header on every request.

### Basic authentication middleware

```go
mux := http.NewServeMux()
mux.HandleFunc("/api/data", func(w http.ResponseWriter, r *http.Request) {
    user := sa.UserFromContext(r.Context())
    fmt.Fprintf(w, "Hello %s", user.PreferredUsername)
})

// Wrap with auth middleware
http.ListenAndServe(":8080", client.Middleware(mux))
```

### Role / permission gates

```go
adminOnly := client.RequireRole("admin", adminHandler)
canWrite  := client.RequirePermission("documents:write", writeHandler)

mux.Handle("/admin", adminOnly)
mux.Handle("/write", canWrite)
```

Unauthenticated requests receive **401 Unauthorized**. Requests that lack the required role or permission receive **403 Forbidden**.

## Admin operations

Manage user roles and permissions via the SimpleAuth admin API. Admin operations require `ClientSecret` -- it is sent as a Bearer token (not Basic auth) to authenticate with the admin API.

```go
roles, err := client.GetUserRoles(ctx, userGUID)
err = client.SetUserRoles(ctx, userGUID, []string{"admin", "editor"})

perms, err := client.GetUserPermissions(ctx, userGUID)
err = client.SetUserPermissions(ctx, userGUID, []string{"read", "write"})
```

> **Note:** Roles and permissions must be defined in SimpleAuth before they can be assigned to users. Use the admin API to define roles (`PUT /api/admin/role-permissions`) and permissions (`PUT /api/admin/permissions`) first, or define them in the Admin UI under Roles & Permissions.

## Self-signed certificates

For development environments with self-signed TLS certificates:

```go
client := sa.New(sa.Options{
    URL:                "https://localhost:8443",
    InsecureSkipVerify: true,
})
```

## Configuration reference

| Field | Description | Default |
|---|---|---|
| `URL` | SimpleAuth server base URL | *(required)* |
| `ClientID` | OIDC client ID (for auth code / client credentials flows) | `""` |
| `ClientSecret` | OIDC client secret | `""` |
| `Realm` | OIDC realm name | `"simpleauth"` |
| `InsecureSkipVerify` | Skip TLS certificate verification | `false` |

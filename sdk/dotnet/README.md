# SimpleAuth .NET SDK

.NET 8 SDK for [SimpleAuth](https://github.com/bodaay/SimpleAuth). JWT verification with JWKS caching, admin operations, and ASP.NET Core middleware.

> **Important:**
> - Access tokens expire in **15 minutes** — implement token refresh
> - URL must include the base path `/sauth` (e.g. `https://auth.example.com/sauth`)
> - `AdminKey` is required for admin operations (roles, permissions, bootstrap)

## Installation

Add a project reference or package reference:

```xml
<PackageReference Include="SimpleAuth" Version="1.0.0" />
```

## Quick Start

### Standalone Client

```csharp
using SimpleAuth;

var client = new SimpleAuthClient(new SimpleAuthOptions
{
    Url = "https://auth.corp.local/sauth",
});

// Password login
var tokens = await client.LoginAsync("alice", "password123");
Console.WriteLine(tokens.AccessToken);

// Verify a token (JWKS is cached automatically)
var user = await client.VerifyAsync(tokens.AccessToken);
Console.WriteLine($"Hello, {user.Name}");
Console.WriteLine($"Is admin? {user.HasRole("admin")}");
```

### ASP.NET Core Integration

**Program.cs:**

```csharp
var builder = WebApplication.CreateBuilder(args);

builder.Services.AddControllers();
builder.Services.AddSimpleAuth(options =>
{
    options.Url = "https://auth.corp.local/sauth";
});

var app = builder.Build();

app.UseSimpleAuth();
app.MapControllers();
app.Run();
```

**Controller:**

```csharp
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using SimpleAuth;

[ApiController]
[Route("api/[controller]")]
public class ProfileController : ControllerBase
{
    [HttpGet]
    public IActionResult Get()
    {
        var user = HttpContext.GetSimpleAuthUser();
        if (user is null)
            return Unauthorized();

        return Ok(new { user.Name, user.Email, user.Roles });
    }

    [HttpGet("admin")]
    [SimpleAuthRole("admin")]
    public IActionResult Admin()
    {
        return Ok("You are an admin.");
    }

    [HttpGet("reports")]
    [SimpleAuthPermission("reports:read")]
    public IActionResult Reports()
    {
        return Ok("Here are your reports.");
    }
}
```

> **Note:** The default access token TTL is **15 minutes**. Applications should implement proper token refresh using the `RefreshAsync` method before the access token expires, rather than relying on long-lived tokens.

## Authentication Flows

### Password Login

Sends `POST /api/auth/login` with a JSON body.

```csharp
var tokens = await client.LoginAsync("alice", "password123");
```

### Handling Force Password Change

The login response may indicate that the user must change their password before proceeding:

```csharp
var tokens = await client.LoginAsync("alice", "password123");
if (tokens.ForcePasswordChange)
{
    // Redirect user to change their password
}
```

### Refresh Token

Sends `POST /api/auth/refresh` with a JSON body.

```csharp
var newTokens = await client.RefreshAsync(tokens.RefreshToken);
```

## Token Verification

Tokens are verified locally using RS256. JWKS keys are fetched from `GET /.well-known/jwks.json` and cached for 1 hour. If a token contains a `kid` that is not in the cache, the SDK automatically re-fetches the JWKS endpoint.

```csharp
var user = await client.VerifyAsync(accessToken);
// Checks: RS256 signature, exp claim, iss claim
```

## User Info

```csharp
var info = await client.UserInfoAsync(tokens.AccessToken);
```

## Admin Operations

Admin operations require the admin key. The key is sent as a Bearer token (not Basic auth) to the SimpleAuth admin API.

```csharp
// Roles
var roles = await client.GetUserRolesAsync(userGuid);
await client.SetUserRolesAsync(userGuid, new List<string> { "admin", "editor" });

// Permissions
var perms = await client.GetUserPermissionsAsync(userGuid);
await client.SetUserPermissionsAsync(userGuid, new List<string> { "reports:read", "reports:write" });
```

> **Note:** Roles and permissions must be defined in SimpleAuth before they can be assigned to users. Use the admin API to define roles (`PUT /api/admin/role-permissions`) and permissions (`PUT /api/admin/permissions`) first, or define them in the Admin UI under Roles & Permissions.

## Authorization Attributes

Use `[SimpleAuthRole]` and `[SimpleAuthPermission]` on controllers or actions:

```csharp
[SimpleAuthRole("admin")]
[SimpleAuthPermission("users:manage")]
public class AdminController : ControllerBase { ... }
```

Multiple attributes are evaluated independently -- each one must pass.

## SSL Validation

To disable SSL certificate validation (development only):

```csharp
var client = new SimpleAuthClient(new SimpleAuthOptions
{
    Url = "https://localhost/sauth",
    ValidateSsl = false,
});
```

## Configuration

| Option         | Type     | Required | Default         | Description                              |
|----------------|----------|----------|-----------------|------------------------------------------|
| `Url`          | `string` | Yes      | --              | SimpleAuth server URL (include `/sauth` base path, e.g. `https://auth.example.com/sauth`) |
| `AdminKey`     | `string` | No       | `""`            | Admin key for admin API operations (sent as Bearer token) |
| `ValidateSsl`  | `bool`   | No       | `true`          | Whether to validate SSL certificates     |

## Error Handling

All errors throw `SimpleAuthException`:

```csharp
try
{
    var user = await client.VerifyAsync(token);
}
catch (SimpleAuthException ex)
{
    Console.WriteLine($"Auth failed: {ex.Message}");
}
```

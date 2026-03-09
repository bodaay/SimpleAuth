# SimpleAuth .NET SDK

.NET 8 SDK for the SimpleAuth authentication server. Provides JWT verification with JWKS caching, OAuth2/OIDC flows, admin operations, and ASP.NET Core middleware.

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
    Url = "https://auth.corp.local:9090",
    AppId = "my-app",
    AppSecret = "sk-...",
    Realm = "simpleauth",
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
    options.Url = "https://auth.corp.local:9090";
    options.AppId = "my-app";
    options.AppSecret = "sk-...";
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

## Authentication Flows

### Password Grant

```csharp
var tokens = await client.LoginAsync("alice", "password123");
```

### Client Credentials

```csharp
var tokens = await client.ClientCredentialsAsync();
```

### Authorization Code (OIDC)

```csharp
// Step 1: Redirect user to auth URL
var authUrl = client.GetAuthorizationUrl(
    redirectUri: "https://myapp.com/callback",
    state: "random-state",
    scope: "openid profile email"
);

// Step 2: Exchange code for tokens in callback
var tokens = await client.ExchangeCodeAsync(code, "https://myapp.com/callback");
```

### Refresh Token

```csharp
var newTokens = await client.RefreshAsync(tokens.RefreshToken);
```

## Token Verification

Tokens are verified locally using RS256. JWKS keys are fetched from the SimpleAuth server and cached for 1 hour. If a token contains a `kid` that is not in the cache, the SDK automatically re-fetches the JWKS endpoint.

```csharp
var user = await client.VerifyAsync(accessToken);
// Checks: RS256 signature, exp claim, iss claim
```

## User Info

```csharp
var info = await client.UserInfoAsync(tokens.AccessToken);
```

## Admin Operations

```csharp
// Roles
var roles = await client.GetUserRolesAsync(userGuid);
await client.SetUserRolesAsync(userGuid, new List<string> { "admin", "editor" });

// Permissions
var perms = await client.GetUserPermissionsAsync(userGuid);
await client.SetUserPermissionsAsync(userGuid, new List<string> { "reports:read", "reports:write" });
```

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
    Url = "https://localhost:9090",
    AppId = "my-app",
    AppSecret = "sk-...",
    ValidateSsl = false,
});
```

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

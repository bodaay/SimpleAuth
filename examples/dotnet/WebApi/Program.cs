// WebApi/Program.cs -- ASP.NET Core Minimal API with SimpleAuth middleware.
//
// Demonstrates:
//   - Registering SimpleAuth via AddSimpleAuth / UseSimpleAuth
//   - Public, protected, and role/permission-restricted endpoints
//   - [SimpleAuthRole] and [SimpleAuthPermission] attribute filters
//   - Accessing the SimpleAuthUser from HttpContext
//   - Swagger/OpenAPI integration with Bearer auth
//
// Prerequisites:
//   dotnet add reference to the SimpleAuth SDK project
//   (see WebApi.csproj for project reference and package setup)
//
// Usage:
//   cd examples/dotnet/WebApi
//   dotnet run
//   # Then open https://localhost:5001/swagger for interactive API docs

using Microsoft.AspNetCore.Mvc;
using Microsoft.OpenApi.Models;
using SimpleAuth;

var builder = WebApplication.CreateBuilder(args);

// ---------------------------------------------------------------------------
// Register SimpleAuth
// ---------------------------------------------------------------------------

builder.Services.AddSimpleAuth(options =>
{
    // In production, load these from appsettings.json or environment variables:
    //   options.Url = builder.Configuration["SimpleAuth:Url"]!;
    //   options.AppId = builder.Configuration["SimpleAuth:AppId"]!;
    //   options.AppSecret = builder.Configuration["SimpleAuth:AppSecret"]!;

    options.Url = "https://auth.example.com";
    options.AppId = "my-webapi-app";
    options.AppSecret = "app-secret-key-here";
    options.Realm = "simpleauth";
    options.ValidateSsl = true;
});

// ---------------------------------------------------------------------------
// Swagger / OpenAPI with Bearer auth
// ---------------------------------------------------------------------------

builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen(c =>
{
    c.SwaggerDoc("v1", new OpenApiInfo
    {
        Title = "SimpleAuth WebApi Example",
        Version = "v1",
        Description = "ASP.NET Core Minimal API protected by SimpleAuth.",
    });

    // Add Bearer token input to Swagger UI
    c.AddSecurityDefinition("Bearer", new OpenApiSecurityScheme
    {
        Name = "Authorization",
        Type = SecuritySchemeType.Http,
        Scheme = "bearer",
        BearerFormat = "JWT",
        In = ParameterLocation.Header,
        Description = "Paste your SimpleAuth access token here.",
    });

    c.AddSecurityRequirement(new OpenApiSecurityRequirement
    {
        {
            new OpenApiSecurityScheme
            {
                Reference = new OpenApiReference
                {
                    Type = ReferenceType.SecurityScheme,
                    Id = "Bearer",
                }
            },
            Array.Empty<string>()
        }
    });
});

// Add controllers support (needed for [SimpleAuthRole] attribute filters)
builder.Services.AddControllers();

var app = builder.Build();

// ---------------------------------------------------------------------------
// Middleware pipeline
// ---------------------------------------------------------------------------

app.UseSwagger();
app.UseSwaggerUI(c =>
{
    c.SwaggerEndpoint("/swagger/v1/swagger.json", "SimpleAuth WebApi v1");
    c.RoutePrefix = "swagger";
});

// SimpleAuth middleware -- verifies Bearer tokens on every request
// and stores the SimpleAuthUser in HttpContext.Items["SimpleAuthUser"]
app.UseSimpleAuth();

app.MapControllers();

// ---------------------------------------------------------------------------
// Helper: extract user or return 401
// ---------------------------------------------------------------------------

static SimpleAuthUser? GetUser(HttpContext ctx) => ctx.GetSimpleAuthUser();

static IResult RequireUser(HttpContext ctx, out SimpleAuthUser user)
{
    user = ctx.GetSimpleAuthUser()!;
    if (user is null)
        return Results.Json(new { error = "Authentication required" }, statusCode: 401);
    return null!;
}

// ---------------------------------------------------------------------------
// Public endpoints
// ---------------------------------------------------------------------------

app.MapGet("/", () => new { status = "ok", service = "SimpleAuth WebApi Example" })
    .WithTags("Public")
    .WithSummary("Health check");

app.MapGet("/public/info", () => new
{
    app_id = "my-webapi-app",
    auth_server = "https://auth.example.com",
    docs = "/swagger",
})
    .WithTags("Public")
    .WithSummary("Application info");

// ---------------------------------------------------------------------------
// Protected endpoints -- any authenticated user
// ---------------------------------------------------------------------------

app.MapGet("/me", (HttpContext ctx) =>
{
    var user = GetUser(ctx);
    if (user is null)
        return Results.Json(new { error = "Authentication required" }, statusCode: 401);

    return Results.Ok(new
    {
        sub = user.Sub,
        name = user.Name,
        email = user.Email,
        username = user.PreferredUsername,
        roles = user.Roles,
        permissions = user.Permissions,
        groups = user.Groups,
        department = user.Department,
        company = user.Company,
        job_title = user.JobTitle,
    });
})
    .WithTags("Protected")
    .WithSummary("Get current user profile");

app.MapGet("/dashboard", (HttpContext ctx) =>
{
    var user = GetUser(ctx);
    if (user is null)
        return Results.Json(new { error = "Authentication required" }, statusCode: 401);

    return Results.Ok(new
    {
        message = $"Welcome back, {user.Name ?? user.PreferredUsername}!",
        your_roles = user.Roles,
    });
})
    .WithTags("Protected")
    .WithSummary("Personalized dashboard");

// ---------------------------------------------------------------------------
// Inline role/permission checks in Minimal API endpoints
// ---------------------------------------------------------------------------

app.MapGet("/reports/monthly", (HttpContext ctx) =>
{
    var user = GetUser(ctx);
    if (user is null)
        return Results.Json(new { error = "Authentication required" }, statusCode: 401);

    if (!user.HasPermission("reports:read"))
        return Results.Json(new { error = "Required permission: reports:read" }, statusCode: 403);

    return Results.Ok(new
    {
        report = "Monthly Sales Report",
        generated_for = user.Name,
        data = new[] { 100, 200, 150, 300 },
    });
})
    .WithTags("Reports")
    .WithSummary("Monthly report (requires reports:read)");

app.MapGet("/team", (HttpContext ctx) =>
{
    var user = GetUser(ctx);
    if (user is null)
        return Results.Json(new { error = "Authentication required" }, statusCode: 401);

    var response = new Dictionary<string, object>
    {
        ["team"] = "Engineering",
        ["member"] = user.Name ?? "",
    };

    if (user.HasRole("manager"))
        response["salaries"] = new { avg = 95000, total = 950000 };

    return Results.Ok(response);
})
    .WithTags("Protected")
    .WithSummary("Team info (managers see salary data)");

// ---------------------------------------------------------------------------
// Controller-based endpoints with [SimpleAuthRole] / [SimpleAuthPermission]
// ---------------------------------------------------------------------------

app.Run();

// ---------------------------------------------------------------------------
// Controller example using attribute-based authorization
// ---------------------------------------------------------------------------

[ApiController]
[Route("admin")]
public class AdminController : ControllerBase
{
    /// <summary>
    /// List all users. Requires 'admin' role.
    /// The [SimpleAuthRole] attribute returns 403 automatically if missing.
    /// </summary>
    [HttpGet("users")]
    [SimpleAuthRole("admin")]
    public IActionResult ListUsers()
    {
        var user = HttpContext.GetSimpleAuthUser()!;
        return Ok(new
        {
            message = $"Admin {user.Name} accessed user list.",
            users = new[] { "alice", "bob", "charlie" },
        });
    }

    /// <summary>
    /// Delete a user. Requires 'admin' role.
    /// </summary>
    [HttpDelete("users/{userId}")]
    [SimpleAuthRole("admin")]
    public IActionResult DeleteUser(string userId)
    {
        var user = HttpContext.GetSimpleAuthUser()!;
        return Ok(new { deleted = userId, by = user.Sub });
    }

    /// <summary>
    /// View audit logs. Requires 'audit:read' permission.
    /// </summary>
    [HttpGet("audit")]
    [SimpleAuthPermission("audit:read")]
    public IActionResult AuditLogs()
    {
        var user = HttpContext.GetSimpleAuthUser()!;
        return Ok(new
        {
            logs = new[]
            {
                new { timestamp = "2025-01-15T10:30:00Z", action = "user.login", actor = "alice" },
                new { timestamp = "2025-01-15T11:00:00Z", action = "settings.update", actor = "bob" },
            },
            requested_by = user.Sub,
        });
    }

    /// <summary>
    /// Endpoint with multiple attribute filters -- user must have BOTH
    /// the 'admin' role AND the 'settings:write' permission.
    /// </summary>
    [HttpPut("settings")]
    [SimpleAuthRole("admin")]
    [SimpleAuthPermission("settings:write")]
    public IActionResult UpdateSettings()
    {
        var user = HttpContext.GetSimpleAuthUser()!;
        return Ok(new
        {
            updated = true,
            modified_by = user.Sub,
        });
    }
}

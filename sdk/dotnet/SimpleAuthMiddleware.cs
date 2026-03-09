using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;

namespace SimpleAuth;

/// <summary>
/// ASP.NET Core middleware that validates SimpleAuth JWT tokens from the
/// Authorization header and populates HttpContext.Items with a SimpleAuthUser.
/// </summary>
public class SimpleAuthMiddleware
{
    private readonly RequestDelegate _next;
    private readonly SimpleAuthClient _client;
    private readonly ILogger<SimpleAuthMiddleware> _logger;

    public SimpleAuthMiddleware(
        RequestDelegate next,
        SimpleAuthClient client,
        ILogger<SimpleAuthMiddleware> logger)
    {
        _next = next;
        _client = client;
        _logger = logger;
    }

    public async Task InvokeAsync(HttpContext context)
    {
        var authHeader = context.Request.Headers.Authorization.FirstOrDefault();

        if (authHeader is not null && authHeader.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase))
        {
            var token = authHeader["Bearer ".Length..].Trim();
            try
            {
                var user = await _client.VerifyAsync(token);
                context.Items["SimpleAuthUser"] = user;
            }
            catch (SimpleAuthException ex)
            {
                _logger.LogWarning("SimpleAuth token verification failed: {Message}", ex.Message);
            }
        }

        await _next(context);
    }
}

/// <summary>
/// Authorization filter that requires the user to have a specific role.
/// </summary>
[AttributeUsage(AttributeTargets.Class | AttributeTargets.Method, AllowMultiple = true)]
public class SimpleAuthRoleAttribute : Attribute, Microsoft.AspNetCore.Mvc.Filters.IAsyncAuthorizationFilter
{
    private readonly string _role;

    public SimpleAuthRoleAttribute(string role)
    {
        _role = role;
    }

    public Task OnAuthorizationAsync(Microsoft.AspNetCore.Mvc.Filters.AuthorizationFilterContext context)
    {
        var user = context.HttpContext.GetSimpleAuthUser();
        if (user is null || !user.HasRole(_role))
        {
            context.Result = new Microsoft.AspNetCore.Mvc.ForbidResult();
        }
        return Task.CompletedTask;
    }
}

/// <summary>
/// Authorization filter that requires the user to have a specific permission.
/// </summary>
[AttributeUsage(AttributeTargets.Class | AttributeTargets.Method, AllowMultiple = true)]
public class SimpleAuthPermissionAttribute : Attribute, Microsoft.AspNetCore.Mvc.Filters.IAsyncAuthorizationFilter
{
    private readonly string _permission;

    public SimpleAuthPermissionAttribute(string permission)
    {
        _permission = permission;
    }

    public Task OnAuthorizationAsync(Microsoft.AspNetCore.Mvc.Filters.AuthorizationFilterContext context)
    {
        var user = context.HttpContext.GetSimpleAuthUser();
        if (user is null || !user.HasPermission(_permission))
        {
            context.Result = new Microsoft.AspNetCore.Mvc.ForbidResult();
        }
        return Task.CompletedTask;
    }
}

/// <summary>
/// Extension methods for integrating SimpleAuth into ASP.NET Core.
/// </summary>
public static class SimpleAuthExtensions
{
    private const string SimpleAuthUserKey = "SimpleAuthUser";

    /// <summary>
    /// Registers SimpleAuthClient as a singleton and configures options.
    /// </summary>
    public static IServiceCollection AddSimpleAuth(
        this IServiceCollection services,
        Action<SimpleAuthOptions> configure)
    {
        var options = new SimpleAuthOptions();
        configure(options);

        var client = new SimpleAuthClient(options);
        services.AddSingleton(options);
        services.AddSingleton(client);

        return services;
    }

    /// <summary>
    /// Adds the SimpleAuth middleware to the request pipeline.
    /// Must be called after UseRouting and before UseEndpoints / MapControllers.
    /// </summary>
    public static IApplicationBuilder UseSimpleAuth(this IApplicationBuilder app)
    {
        return app.UseMiddleware<SimpleAuthMiddleware>();
    }

    /// <summary>
    /// Gets the authenticated SimpleAuthUser from the current request, or null
    /// if the request is unauthenticated.
    /// </summary>
    public static SimpleAuthUser? GetSimpleAuthUser(this HttpContext context)
    {
        return context.Items.TryGetValue(SimpleAuthUserKey, out var value)
            ? value as SimpleAuthUser
            : null;
    }
}

// ServiceAuth/Program.cs -- Service-to-service authentication with SimpleAuth.
//
// Demonstrates:
//   - Client credentials flow (machine-to-machine)
//   - IHttpClientFactory with auto-injected Bearer token via DelegatingHandler
//   - Background service that maintains a fresh token
//   - Making authenticated calls to downstream APIs
//
// Prerequisites:
//   dotnet add reference to the SimpleAuth SDK project
//   (see ServiceAuth.csproj for project reference setup)
//
// Usage:
//   cd examples/dotnet/ServiceAuth
//   dotnet run

using System.Net.Http.Headers;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using SimpleAuth;

// ---------------------------------------------------------------------------
// Build the host with DI
// ---------------------------------------------------------------------------

var builder = Host.CreateApplicationBuilder(args);

// Register SimpleAuth client as a singleton
var authOptions = new SimpleAuthOptions
{
    Url = "https://auth.example.com",
    ClientId = "inventory-service",
    ClientSecret = "service-secret-key-here",
    Realm = "simpleauth",
    ValidateSsl = true,
};
var authClient = new SimpleAuthClient(authOptions);
builder.Services.AddSingleton(authClient);

// Register the token provider (holds and refreshes the service token)
builder.Services.AddSingleton<ServiceTokenProvider>();

// Register the DelegatingHandler that injects Bearer tokens
builder.Services.AddTransient<AuthenticatedHttpHandler>();

// Register a named HttpClient for the downstream orders API.
// Every request through this client automatically includes a valid Bearer token.
builder.Services.AddHttpClient("OrdersApi", client =>
{
    client.BaseAddress = new Uri("https://api.internal.example.com/");
    client.Timeout = TimeSpan.FromSeconds(30);
})
.AddHttpMessageHandler<AuthenticatedHttpHandler>();

// Register the background worker that periodically calls the orders API
builder.Services.AddHostedService<OrderPollingService>();

var host = builder.Build();
await host.RunAsync();


// ===========================================================================
// ServiceTokenProvider -- obtains and caches a client-credentials token
// ===========================================================================

/// <summary>
/// Thread-safe token provider that uses the client_credentials grant
/// and refreshes the token before it expires.
/// </summary>
public class ServiceTokenProvider
{
    private readonly SimpleAuthClient _client;
    private readonly ILogger<ServiceTokenProvider> _logger;
    private readonly SemaphoreSlim _lock = new(1, 1);

    private string? _accessToken;
    private DateTime _expiresAt = DateTime.MinValue;

    // Refresh 60 seconds before the token actually expires
    private static readonly TimeSpan RefreshMargin = TimeSpan.FromSeconds(60);

    public ServiceTokenProvider(SimpleAuthClient client, ILogger<ServiceTokenProvider> logger)
    {
        _client = client;
        _logger = logger;
    }

    /// <summary>
    /// Returns a valid access token, obtaining or refreshing one if needed.
    /// </summary>
    public async Task<string> GetTokenAsync(CancellationToken ct = default)
    {
        // Fast path: token is still valid
        if (_accessToken is not null && DateTime.UtcNow < _expiresAt)
            return _accessToken;

        await _lock.WaitAsync(ct);
        try
        {
            // Double-check after acquiring the lock
            if (_accessToken is not null && DateTime.UtcNow < _expiresAt)
                return _accessToken;

            _logger.LogInformation("Obtaining new service token via client_credentials...");

            var tokens = await _client.ClientCredentialsAsync();
            _accessToken = tokens.AccessToken!;
            _expiresAt = DateTime.UtcNow.AddSeconds(tokens.ExpiresIn) - RefreshMargin;

            _logger.LogInformation(
                "Service token obtained. Expires in {ExpiresIn}s (will refresh at {RefreshAt:HH:mm:ss})",
                tokens.ExpiresIn,
                _expiresAt);

            return _accessToken;
        }
        catch (SimpleAuthException ex)
        {
            _logger.LogError(ex, "Failed to obtain service token");
            throw;
        }
        finally
        {
            _lock.Release();
        }
    }
}


// ===========================================================================
// AuthenticatedHttpHandler -- DelegatingHandler for IHttpClientFactory
// ===========================================================================

/// <summary>
/// A DelegatingHandler that injects a Bearer token from
/// <see cref="ServiceTokenProvider"/> into every outgoing HTTP request.
///
/// Register with IHttpClientFactory:
///   builder.Services.AddHttpClient("MyApi").AddHttpMessageHandler&lt;AuthenticatedHttpHandler&gt;();
/// </summary>
public class AuthenticatedHttpHandler : DelegatingHandler
{
    private readonly ServiceTokenProvider _tokenProvider;

    public AuthenticatedHttpHandler(ServiceTokenProvider tokenProvider)
    {
        _tokenProvider = tokenProvider;
    }

    protected override async Task<HttpResponseMessage> SendAsync(
        HttpRequestMessage request,
        CancellationToken cancellationToken)
    {
        var token = await _tokenProvider.GetTokenAsync(cancellationToken);
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
        return await base.SendAsync(request, cancellationToken);
    }
}


// ===========================================================================
// OrderPollingService -- BackgroundService example
// ===========================================================================

/// <summary>
/// A hosted background service that periodically calls a downstream API
/// using the authenticated HttpClient. Demonstrates a real-world pattern
/// for service-to-service communication.
/// </summary>
public class OrderPollingService : BackgroundService
{
    private readonly IHttpClientFactory _httpFactory;
    private readonly ILogger<OrderPollingService> _logger;

    private static readonly TimeSpan PollInterval = TimeSpan.FromMinutes(1);

    public OrderPollingService(
        IHttpClientFactory httpFactory,
        ILogger<OrderPollingService> logger)
    {
        _httpFactory = httpFactory;
        _logger = logger;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        _logger.LogInformation("OrderPollingService started. Polling every {Interval}.", PollInterval);

        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                await PollOrdersAsync(stoppingToken);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error polling orders");
            }

            await Task.Delay(PollInterval, stoppingToken);
        }

        _logger.LogInformation("OrderPollingService stopped.");
    }

    private async Task PollOrdersAsync(CancellationToken ct)
    {
        // The "OrdersApi" named client is configured with the
        // AuthenticatedHttpHandler, so Bearer token is injected automatically.
        using var client = _httpFactory.CreateClient("OrdersApi");

        _logger.LogInformation("Fetching pending orders...");

        var response = await client.GetAsync("orders?status=pending", ct);

        if (response.IsSuccessStatusCode)
        {
            var body = await response.Content.ReadAsStringAsync(ct);
            _logger.LogInformation("Received orders: {Body}", body);

            // Process orders here...
        }
        else
        {
            _logger.LogWarning(
                "Orders API returned {StatusCode}: {Body}",
                response.StatusCode,
                await response.Content.ReadAsStringAsync(ct));
        }
    }
}

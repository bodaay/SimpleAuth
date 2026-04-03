using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace SimpleAuth;

public class SimpleAuthClient : IDisposable
{
    private readonly SimpleAuthOptions _options;
    private readonly HttpClient _http;
    private readonly SemaphoreSlim _jwksLock = new(1, 1);
    private Dictionary<string, RSAParameters>? _jwksCache;
    private DateTime _jwksCacheExpiry = DateTime.MinValue;

    private string BaseUrl => _options.Url.TrimEnd('/');
    private string LoginUrl => $"{BaseUrl}/api/auth/login";
    private string RefreshUrl => $"{BaseUrl}/api/auth/refresh";
    private string CertsUrl => $"{BaseUrl}/.well-known/jwks.json";
    private string UserInfoUrl => $"{BaseUrl}/api/auth/userinfo";
    private string AdminUrl => $"{BaseUrl}/api/admin";

    /// <summary>Admin key for Bearer auth on admin endpoints.</summary>
    private string EffectiveAdminKey => _options.AdminKey;

    public SimpleAuthClient(SimpleAuthOptions options)
    {
        _options = options ?? throw new ArgumentNullException(nameof(options));

        if (string.IsNullOrWhiteSpace(options.Url))
            throw new ArgumentException("Url is required.", nameof(options));

        var handler = new HttpClientHandler();
        if (!options.ValidateSsl)
        {
            handler.ServerCertificateCustomValidationCallback =
                HttpClientHandler.DangerousAcceptAnyServerCertificateValidator;
        }

        _http = new HttpClient(handler);
    }

    // ── Authentication ──────────────────────────────────────────────────

    public async Task<TokenResponse> LoginAsync(string username, string password)
    {
        var body = new { username, password };
        var content = new StringContent(
            JsonSerializer.Serialize(body),
            Encoding.UTF8,
            "application/json");

        using var response = await _http.PostAsync(LoginUrl, content);
        var json = await response.Content.ReadAsStringAsync();

        if (!response.IsSuccessStatusCode)
            throw new SimpleAuthException($"Login request failed ({response.StatusCode}): {json}");

        return JsonSerializer.Deserialize<TokenResponse>(json)
            ?? throw new SimpleAuthException("Empty login response.");
    }

    public async Task<TokenResponse> RefreshAsync(string refreshToken)
    {
        var body = new { refresh_token = refreshToken };
        var content = new StringContent(
            JsonSerializer.Serialize(body),
            Encoding.UTF8,
            "application/json");

        using var response = await _http.PostAsync(RefreshUrl, content);
        var json = await response.Content.ReadAsStringAsync();

        if (!response.IsSuccessStatusCode)
            throw new SimpleAuthException($"Refresh request failed ({response.StatusCode}): {json}");

        return JsonSerializer.Deserialize<TokenResponse>(json)
            ?? throw new SimpleAuthException("Empty refresh response.");
    }

    // ── Token verification ──────────────────────────────────────────────

    public async Task<SimpleAuthUser> VerifyAsync(string token)
    {
        var parts = token.Split('.');
        if (parts.Length != 3)
            throw new SimpleAuthException("Invalid JWT: expected 3 parts.");

        var headerJson = Base64UrlDecode(parts[0]);
        var header = JsonSerializer.Deserialize<JwtHeader>(headerJson)
            ?? throw new SimpleAuthException("Failed to parse JWT header.");

        if (!string.Equals(header.Alg, "RS256", StringComparison.OrdinalIgnoreCase))
            throw new SimpleAuthException($"Unsupported algorithm: {header.Alg}");

        var kid = header.Kid ?? throw new SimpleAuthException("JWT header missing kid.");

        // Verify signature
        var rsaParams = await GetRsaKeyAsync(kid);
        VerifySignature(parts[0], parts[1], parts[2], rsaParams);

        // Decode payload
        var payloadJson = Base64UrlDecode(parts[1]);
        using var doc = JsonDocument.Parse(payloadJson);
        var root = doc.RootElement;

        // Check expiry
        if (root.TryGetProperty("exp", out var expEl))
        {
            var expUnix = expEl.GetInt64();
            var expTime = DateTimeOffset.FromUnixTimeSeconds(expUnix);
            if (expTime < DateTimeOffset.UtcNow)
                throw new SimpleAuthException("Token has expired.");
        }

        // Check issuer
        if (root.TryGetProperty("iss", out var issEl))
        {
            var issuer = issEl.GetString();
            var expectedIssuer = BaseUrl;
            if (!string.Equals(issuer, expectedIssuer, StringComparison.OrdinalIgnoreCase))
                throw new SimpleAuthException($"Invalid issuer: {issuer}, expected: {expectedIssuer}");
        }

        // Map claims to SimpleAuthUser
        var user = new SimpleAuthUser
        {
            Sub = root.TryGetProperty("sub", out var sub) ? sub.GetString() ?? "" : "",
            Name = root.TryGetProperty("name", out var name) ? name.GetString() : null,
            Email = root.TryGetProperty("email", out var email) ? email.GetString() : null,
            PreferredUsername = root.TryGetProperty("preferred_username", out var pref)
                ? pref.GetString() : null,
            Department = root.TryGetProperty("department", out var dept) ? dept.GetString() : null,
            Company = root.TryGetProperty("company", out var comp) ? comp.GetString() : null,
            JobTitle = root.TryGetProperty("job_title", out var jt) ? jt.GetString() : null,
            Roles = GetStringList(root, "roles"),
            Permissions = GetStringList(root, "permissions"),
            Groups = GetStringList(root, "groups"),
        };

        return user;
    }

    private static List<string> GetStringList(JsonElement root, string property)
    {
        if (!root.TryGetProperty(property, out var el) || el.ValueKind != JsonValueKind.Array)
            return [];
        return el.EnumerateArray()
            .Where(v => v.ValueKind == JsonValueKind.String)
            .Select(v => v.GetString()!)
            .ToList();
    }

    private static void VerifySignature(string headerB64, string payloadB64, string signatureB64, RSAParameters rsaParams)
    {
        var data = Encoding.ASCII.GetBytes($"{headerB64}.{payloadB64}");
        var signature = Base64UrlDecodeBytes(signatureB64);

        using var rsa = RSA.Create();
        rsa.ImportParameters(rsaParams);

        var valid = rsa.VerifyData(data, signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        if (!valid)
            throw new SimpleAuthException("Invalid JWT signature.");
    }

    // ── JWKS ────────────────────────────────────────────────────────────

    private async Task<RSAParameters> GetRsaKeyAsync(string kid)
    {
        // Fast path: cache is valid and key exists
        if (_jwksCache is not null && _jwksCacheExpiry > DateTime.UtcNow && _jwksCache.TryGetValue(kid, out var cached))
            return cached;

        await _jwksLock.WaitAsync();
        try
        {
            // Double-check after acquiring lock
            if (_jwksCache is not null && _jwksCacheExpiry > DateTime.UtcNow && _jwksCache.TryGetValue(kid, out cached))
                return cached;

            // Fetch fresh JWKS (also handles kid-miss refresh)
            await FetchJwksAsync();

            if (_jwksCache!.TryGetValue(kid, out cached))
                return cached;

            throw new SimpleAuthException($"Key with kid '{kid}' not found in JWKS.");
        }
        finally
        {
            _jwksLock.Release();
        }
    }

    private async Task FetchJwksAsync()
    {
        using var response = await _http.GetAsync(CertsUrl);
        var json = await response.Content.ReadAsStringAsync();

        if (!response.IsSuccessStatusCode)
            throw new SimpleAuthException($"Failed to fetch JWKS ({response.StatusCode}): {json}");

        using var doc = JsonDocument.Parse(json);
        var keys = doc.RootElement.GetProperty("keys");

        var newCache = new Dictionary<string, RSAParameters>();
        foreach (var key in keys.EnumerateArray())
        {
            var kty = key.GetProperty("kty").GetString();
            if (!string.Equals(kty, "RSA", StringComparison.OrdinalIgnoreCase))
                continue;

            var keyKid = key.GetProperty("kid").GetString();
            if (keyKid is null) continue;

            var n = Base64UrlDecodeBytes(key.GetProperty("n").GetString()!);
            var e = Base64UrlDecodeBytes(key.GetProperty("e").GetString()!);

            newCache[keyKid] = new RSAParameters { Modulus = n, Exponent = e };
        }

        _jwksCache = newCache;
        _jwksCacheExpiry = DateTime.UtcNow.AddHours(1);
    }

    // ── User info ───────────────────────────────────────────────────────

    public async Task<UserInfo> UserInfoAsync(string accessToken)
    {
        using var request = new HttpRequestMessage(HttpMethod.Get, UserInfoUrl);
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);

        using var response = await _http.SendAsync(request);
        var json = await response.Content.ReadAsStringAsync();

        if (!response.IsSuccessStatusCode)
            throw new SimpleAuthException($"UserInfo request failed ({response.StatusCode}): {json}");

        return JsonSerializer.Deserialize<UserInfo>(json)
            ?? throw new SimpleAuthException("Empty userinfo response.");
    }

    // ── Admin operations ────────────────────────────────────────────────

    public async Task<List<string>> GetUserRolesAsync(string guid)
    {
        var url = $"{AdminUrl}/users/{guid}/roles";
        return await AdminGetListAsync(url);
    }

    public async Task SetUserRolesAsync(string guid, List<string> roles)
    {
        var url = $"{AdminUrl}/users/{guid}/roles";
        await AdminPutListAsync(url, roles);
    }

    public async Task<List<string>> GetUserPermissionsAsync(string guid)
    {
        var url = $"{AdminUrl}/users/{guid}/permissions";
        return await AdminGetListAsync(url);
    }

    public async Task SetUserPermissionsAsync(string guid, List<string> permissions)
    {
        var url = $"{AdminUrl}/users/{guid}/permissions";
        await AdminPutListAsync(url, permissions);
    }

    private async Task<List<string>> AdminGetListAsync(string url)
    {
        using var request = new HttpRequestMessage(HttpMethod.Get, url);
        request.Headers.Add("Authorization", $"Bearer {EffectiveAdminKey}");

        using var response = await _http.SendAsync(request);
        var json = await response.Content.ReadAsStringAsync();

        if (!response.IsSuccessStatusCode)
            throw new SimpleAuthException($"Admin request failed ({response.StatusCode}): {json}");

        return JsonSerializer.Deserialize<List<string>>(json) ?? [];
    }

    private async Task AdminPutListAsync(string url, List<string> items)
    {
        using var request = new HttpRequestMessage(HttpMethod.Put, url)
        {
            Content = new StringContent(
                JsonSerializer.Serialize(items),
                Encoding.UTF8,
                "application/json"),
        };
        request.Headers.Add("Authorization", $"Bearer {EffectiveAdminKey}");

        using var response = await _http.SendAsync(request);
        if (!response.IsSuccessStatusCode)
        {
            var json = await response.Content.ReadAsStringAsync();
            throw new SimpleAuthException($"Admin request failed ({response.StatusCode}): {json}");
        }
    }

    // ── Base64url helpers ───────────────────────────────────────────────

    private static byte[] Base64UrlDecode(string input)
    {
        return Base64UrlDecodeBytes(input);
    }

    private static byte[] Base64UrlDecodeBytes(string input)
    {
        var s = input.Replace('-', '+').Replace('_', '/');
        switch (s.Length % 4)
        {
            case 2: s += "=="; break;
            case 3: s += "="; break;
        }
        return Convert.FromBase64String(s);
    }

    public void Dispose()
    {
        _http.Dispose();
        _jwksLock.Dispose();
        GC.SuppressFinalize(this);
    }

    private sealed class JwtHeader
    {
        [JsonPropertyName("alg")]
        public string? Alg { get; set; }

        [JsonPropertyName("kid")]
        public string? Kid { get; set; }
    }
}

public class SimpleAuthException : Exception
{
    public SimpleAuthException(string message) : base(message) { }
    public SimpleAuthException(string message, Exception inner) : base(message, inner) { }
}

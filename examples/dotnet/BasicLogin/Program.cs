// BasicLogin/Program.cs -- Simple console app demonstrating SimpleAuth login and token verification.
//
// Demonstrates:
//   - Authenticating with username and password
//   - Verifying an access token and printing claims
//   - Refreshing an access token
//   - Fetching user info from the OIDC userinfo endpoint
//   - Handling errors gracefully
//
// Prerequisites:
//   dotnet add reference to the SimpleAuth SDK project
//   (see BasicLogin.csproj for project reference setup)
//
// Usage:
//   cd examples/dotnet/BasicLogin
//   dotnet run

using SimpleAuth;

// ---------------------------------------------------------------------------
// Configuration -- replace with your SimpleAuth server details
// ---------------------------------------------------------------------------

var options = new SimpleAuthOptions
{
    Url = "https://auth.example.com/sauth",
    ValidateSsl = true, // set false for self-signed certs in development
};

using var client = new SimpleAuthClient(options);

// ---------------------------------------------------------------------------
// Step 1: Login with username and password
// ---------------------------------------------------------------------------

Console.Write("Username: ");
var username = Console.ReadLine() ?? "";

Console.Write("Password: ");
var password = Console.ReadLine() ?? "";

TokenResponse tokens;
try
{
    tokens = await client.LoginAsync(username, password);
}
catch (SimpleAuthException ex)
{
    Console.WriteLine($"\nLogin failed: {ex.Message}");
    return;
}

Console.WriteLine("\nLogin successful!");
Console.WriteLine($"  Access token:  {tokens.AccessToken?[..Math.Min(40, tokens.AccessToken.Length)]}...");
Console.WriteLine($"  Token type:    {tokens.TokenType}");
Console.WriteLine($"  Expires in:    {tokens.ExpiresIn} seconds");
Console.WriteLine($"  Refresh token: {(tokens.RefreshToken is not null ? tokens.RefreshToken[..Math.Min(40, tokens.RefreshToken.Length)] + "..." : "N/A")}");

if (tokens.ForcePasswordChange)
{
    Console.WriteLine("\n  ** You must change your password before continuing. **");
}

// ---------------------------------------------------------------------------
// Step 2: Verify the access token and inspect claims
// ---------------------------------------------------------------------------

SimpleAuthUser user;
try
{
    user = await client.VerifyAsync(tokens.AccessToken!);
}
catch (SimpleAuthException ex)
{
    Console.WriteLine($"\nToken verification failed: {ex.Message}");
    return;
}

Console.WriteLine("\nVerified user claims:");
Console.WriteLine($"  Subject (sub):  {user.Sub}");
Console.WriteLine($"  Name:           {user.Name}");
Console.WriteLine($"  Email:          {user.Email}");
Console.WriteLine($"  Username:       {user.PreferredUsername}");
Console.WriteLine($"  Roles:          [{string.Join(", ", user.Roles)}]");
Console.WriteLine($"  Permissions:    [{string.Join(", ", user.Permissions)}]");
Console.WriteLine($"  Groups:         [{string.Join(", ", user.Groups)}]");
Console.WriteLine($"  Department:     {user.Department}");
Console.WriteLine($"  Company:        {user.Company}");
Console.WriteLine($"  Job title:      {user.JobTitle}");

// Check specific roles and permissions
if (user.HasRole("admin"))
    Console.WriteLine("\n  ** This user is an admin **");

if (user.HasPermission("documents:write"))
    Console.WriteLine("  ** This user can write documents **");

if (user.HasAnyRole("admin", "manager"))
    Console.WriteLine("  ** This user is an admin or manager **");

// ---------------------------------------------------------------------------
// Step 3: Fetch additional info from the OIDC userinfo endpoint
// ---------------------------------------------------------------------------

try
{
    var info = await client.UserInfoAsync(tokens.AccessToken!);
    Console.WriteLine("\nUserinfo endpoint response:");
    Console.WriteLine($"  Sub:            {info.Sub}");
    Console.WriteLine($"  Name:           {info.Name}");
    Console.WriteLine($"  Email:          {info.Email}");
    Console.WriteLine($"  Email verified: {info.EmailVerified}");
    Console.WriteLine($"  Department:     {info.Department}");
    Console.WriteLine($"  Company:        {info.Company}");
}
catch (SimpleAuthException ex)
{
    Console.WriteLine($"\nUserinfo fetch failed: {ex.Message}");
}

// ---------------------------------------------------------------------------
// Step 4: Refresh the token
// ---------------------------------------------------------------------------

if (tokens.RefreshToken is not null)
{
    Console.WriteLine("\nRefreshing access token...");
    try
    {
        var newTokens = await client.RefreshAsync(tokens.RefreshToken);
        Console.WriteLine("  New access token obtained!");
        Console.WriteLine($"  Expires in: {newTokens.ExpiresIn} seconds");

        if (newTokens.RefreshToken is not null)
            Console.WriteLine("  New refresh token issued (rotate it in your storage).");
    }
    catch (SimpleAuthException ex)
    {
        Console.WriteLine($"  Refresh failed: {ex.Message}");
    }
}
else
{
    Console.WriteLine("\nNo refresh token available.");
}

Console.WriteLine("\nDone.");

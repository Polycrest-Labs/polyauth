using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Text.Encodings.Web;
using System.Text.Json;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Data.SqlClient;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using PolyAuth.OAuth;
using Xunit;
using Xunit.Abstractions;

namespace PolyAuth.IntegrationTests;

/// <summary>
/// A test bearer scheme standing in for a consuming app's own authentication (e.g. its JwtBearer):
/// any request carrying an Authorization: Bearer header authenticates as user 42.
/// </summary>
public sealed class TestBearerHandler : AuthenticationHandler<AuthenticationSchemeOptions>
{
    public const string SchemeName = "TestBearer";

    public TestBearerHandler(IOptionsMonitor<AuthenticationSchemeOptions> options, ILoggerFactory logger, UrlEncoder encoder)
        : base(options, logger, encoder)
    {
    }

    protected override Task<AuthenticateResult> HandleAuthenticateAsync()
    {
        var header = Request.Headers.Authorization.ToString();
        if (!header.StartsWith("Bearer ", StringComparison.Ordinal))
        {
            return Task.FromResult(AuthenticateResult.NoResult());
        }

        var identity = new ClaimsIdentity(
        [
            new Claim("uid", "42"),
            new Claim("email", "bridge@polyauth.test"),
            new Claim("name", "Bridge Test User")
        ], Scheme.Name);

        return Task.FromResult(AuthenticateResult.Success(
            new AuthenticationTicket(new ClaimsPrincipal(identity), Scheme.Name)));
    }
}

/// <summary>
/// Proves the bring-your-own-identity session bridge end to end on the SqlServer store: with Firebase
/// disabled and SessionBridge.AuthenticationSchemes = [TestBearer], POST /api/oauth/session converts a
/// test-scheme principal into the OAuthSession cookie and the full authorize → consent → code → token
/// loop completes. The host is built directly (WebApplication + TestServer) with the same wiring shape
/// as the sample app, because WebApplicationFactory's ConfigureAppConfiguration values are not visible
/// to Program-time reads under minimal hosting. Runs only when POLYAUTH_TEST_SQLSERVER is set.
/// </summary>
[Trait("category", "sqlserver")]
public sealed class SessionBridgeTests
{
    private readonly ITestOutputHelper _output;
    private static readonly string? SqlConnectionString = Environment.GetEnvironmentVariable("POLYAUTH_TEST_SQLSERVER");

    public SessionBridgeTests(ITestOutputHelper output) => _output = output;

    private static string B64Url(byte[] b) => Convert.ToBase64String(b).TrimEnd('=').Replace('+', '-').Replace('/', '_');

    private static async Task<WebApplication> BuildAppAsync(string connectionString)
    {
        var builder = WebApplication.CreateBuilder(new WebApplicationOptions { EnvironmentName = "Development" });
        builder.WebHost.UseTestServer();

        // The exact bring-your-own-identity shape a consumer like the Land Sale app uses:
        // OAuth + MCP on, Firebase off, SQL store, session bridge gated by the app's own scheme.
        builder.Services.AddPolyAuth(builder.Configuration, o =>
        {
            o.Firebase.Enabled = false;
            o.OAuth.Enabled = true;
            o.Mcp.Enabled = true;
            o.OAuth.Issuer = null;
            o.OAuth.Store.Provider = StoreProviders.SqlServer;
            o.OAuth.Store.ConnectionString = connectionString;
            o.OAuth.SessionBridge.Enabled = true;
            o.OAuth.SessionBridge.AuthenticationSchemes = [TestBearerHandler.SchemeName];

            if (!o.OAuth.StaticClients.Any(c => c.ClientId == "claude-desktop"))
            {
                o.OAuth.StaticClients.Add(new OAuthStaticClientOptions
                {
                    ClientId = "claude-desktop",
                    ClientName = "Claude Desktop",
                    AllowLoopbackRedirectUris = true,
                    AllowedLoopbackRedirectPaths = ["/callback", "/oauth/callback"],
                    Scopes = ["openid", "profile", "email", "offline_access", "mcp.read", "mcp.write"]
                });
            }
        });

        builder.Services.AddAuthentication()
            .AddScheme<AuthenticationSchemeOptions, TestBearerHandler>(TestBearerHandler.SchemeName, _ => { });

        var app = builder.Build();
        app.UsePolyAuth();
        app.MapPolyAuthEndpoints();
        await app.StartAsync();
        return app;
    }

    [Fact]
    public async Task Session_bridge_with_custom_scheme_and_sql_store_completes_the_oauth_flow()
    {
        if (string.IsNullOrWhiteSpace(SqlConnectionString))
        {
            _output.WriteLine("POLYAUTH_TEST_SQLSERVER not set — skipping the session-bridge test.");
            return;
        }

        // A unique scratch database per run, dropped in the finally.
        var csBuilder = new SqlConnectionStringBuilder(SqlConnectionString)
        {
            InitialCatalog = "PolyAuthBridgeTest_" + Guid.NewGuid().ToString("N")[..8]
        };
        var connectionString = csBuilder.ConnectionString;

        var dbOptions = new DbContextOptionsBuilder<PolyAuthSqlDbContext>()
            .UseSqlServer(connectionString)
            .UseOpenIddict()
            .Options;

        try
        {
            // Create the scratch schema inside the try so the finally always drops the database,
            // even if EnsureCreated partially succeeds before throwing.
            await using (var context = new PolyAuthSqlDbContext(dbOptions))
            {
                await context.Database.EnsureCreatedAsync();
            }

            await using var app = await BuildAppAsync(connectionString);
            using var client = app.GetTestClient();

            // 0) Without the test bearer header the bridge must challenge (401), not mint a session.
            var anonymous = await client.PostAsJsonAsync("/api/oauth/session", new { returnUrl = "/" });
            Assert.Equal(HttpStatusCode.Unauthorized, anonymous.StatusCode);

            // 1) Establish the OAuthSession cookie from the test-scheme principal (the "app JWT" stand-in).
            var sessionReq = new HttpRequestMessage(HttpMethod.Post, "/api/oauth/session")
            {
                Content = JsonContent.Create(new { returnUrl = "/" })
            };
            sessionReq.Headers.Authorization = new AuthenticationHeaderValue("Bearer", "test-app-token");
            var sessionResp = await client.SendAsync(sessionReq);
            Assert.Equal(HttpStatusCode.OK, sessionResp.StatusCode);

            var setCookie = sessionResp.Headers.GetValues("Set-Cookie")
                .First(c => c.StartsWith("__Host-polyauth-oauth", StringComparison.Ordinal));
            var cookie = setCookie.Split(';')[0];
            _output.WriteLine("Session bridge issued the OAuthSession cookie from the TestBearer principal.");

            // 2) PKCE authorize for the loopback client (seeded into the SQL store at startup).
            var verifier = B64Url(RandomNumberGenerator.GetBytes(32));
            var challenge = B64Url(SHA256.HashData(Encoding.ASCII.GetBytes(verifier)));
            const string redirectUri = "http://127.0.0.1:8765/callback";
            var query = $"response_type=code&client_id=claude-desktop&redirect_uri={Uri.EscapeDataString(redirectUri)}" +
                        $"&scope={Uri.EscapeDataString("openid offline_access mcp.read mcp.write")}" +
                        $"&code_challenge={challenge}&code_challenge_method=S256&state=s1";

            var consentReq = new HttpRequestMessage(HttpMethod.Get, $"/connect/authorize?{query}");
            consentReq.Headers.Add("Cookie", cookie);
            var consentResp = await client.SendAsync(consentReq);
            Assert.Equal(HttpStatusCode.OK, consentResp.StatusCode);
            Assert.Contains("Authorize", await consentResp.Content.ReadAsStringAsync());

            // 3) Approve consent → 302 to the loopback redirect with a code.
            var approveReq = new HttpRequestMessage(HttpMethod.Post, "/connect/authorize")
            {
                Content = new FormUrlEncodedContent(new Dictionary<string, string>
                {
                    ["response_type"] = "code",
                    ["client_id"] = "claude-desktop",
                    ["redirect_uri"] = redirectUri,
                    ["scope"] = "openid offline_access mcp.read mcp.write",
                    ["code_challenge"] = challenge,
                    ["code_challenge_method"] = "S256",
                    ["state"] = "s1",
                    ["consent_action"] = "approve"
                })
            };
            approveReq.Headers.Add("Cookie", cookie);
            var approveResp = await client.SendAsync(approveReq);
            Assert.Equal(HttpStatusCode.Redirect, approveResp.StatusCode);
            var location = approveResp.Headers.Location!.ToString();
            Assert.StartsWith(redirectUri, location);
            var code = new Uri(location).Query.TrimStart('?').Split('&')
                .FirstOrDefault(p => p.StartsWith("code=", StringComparison.Ordinal))?["code=".Length..];
            code = code is null ? null : Uri.UnescapeDataString(code);
            Assert.False(string.IsNullOrEmpty(code));

            // 4) Exchange the code (PKCE) for tokens — the whole loop ran on the SqlServer store.
            var tokenResp = await client.PostAsync("/connect/token", new FormUrlEncodedContent(new Dictionary<string, string>
            {
                ["grant_type"] = "authorization_code",
                ["client_id"] = "claude-desktop",
                ["code"] = code!,
                ["redirect_uri"] = redirectUri,
                ["code_verifier"] = verifier
            }));

            var tokenBody = await tokenResp.Content.ReadAsStringAsync();
            Assert.True(tokenResp.StatusCode == HttpStatusCode.OK, $"token exchange failed: {(int)tokenResp.StatusCode}: {tokenBody}");
            using var doc = JsonDocument.Parse(tokenBody);
            Assert.False(string.IsNullOrEmpty(doc.RootElement.GetProperty("access_token").GetString()));
            _output.WriteLine("Authorization-code + PKCE flow completed with the SQL-backed store and the bridged identity.");
        }
        finally
        {
            await using var context = new PolyAuthSqlDbContext(dbOptions);
            await context.Database.EnsureDeletedAsync();
        }
    }
}

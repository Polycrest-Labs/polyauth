using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using OpenIddict.Abstractions;
using PolyAuth.Firebase;

namespace PolyAuth.IntegrationTests;

/// <summary>A Firebase ID-token verifier that returns a fixed result without contacting Google.</summary>
public sealed class StubFirebaseTokenVerifier : IFirebaseTokenVerifier
{
    public string Uid { get; set; } = "test-user-uid";
    public string? Email { get; set; } = "e2e@polyauth.test";
    public string? Name { get; set; } = "PolyAuth E2E";

    public Task<VerifiedFirebaseToken> VerifyIdTokenAsync(string idToken, CancellationToken ct = default)
        => Task.FromResult(new VerifiedFirebaseToken(Uid, Email, Name));
}

public sealed class PolyAuthWebFactory : WebApplicationFactory<Program>
{
    public const string ClientCredentialsClientId = "test-mcp-cc";
    public const string ClientCredentialsSecret = "test-secret-please-change";

    public StubFirebaseTokenVerifier Verifier { get; } = new();

    private readonly string _databaseName = "polyauth-test-" + Guid.NewGuid().ToString("N");

    private static string MongoConnectionString =>
        Environment.GetEnvironmentVariable("POLYAUTH_TEST_MONGO") ?? "mongodb://localhost:27017";

    protected override void ConfigureWebHost(IWebHostBuilder builder)
    {
        builder.UseEnvironment("Development");

        builder.ConfigureAppConfiguration((_, config) =>
        {
            config.AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["PolyAuth:Firebase:Enabled"] = "true",
                ["PolyAuth:Firebase:ProjectId"] = "test-project",
                ["PolyAuth:Firebase:ServiceAccountJson"] = "",
                ["PolyAuth:OAuth:Enabled"] = "true",
                ["PolyAuth:OAuth:Issuer"] = "",
                ["PolyAuth:OAuth:Store:ConnectionString"] = MongoConnectionString,
                ["PolyAuth:OAuth:Store:DatabaseName"] = _databaseName,
                ["PolyAuth:Mcp:Enabled"] = "true",
                ["CosmosDb:ConnectionString"] = "" // force in-memory item store
            });
        });

        builder.ConfigureTestServices(services =>
        {
            services.RemoveAll<IFirebaseTokenVerifier>();
            services.AddSingleton<IFirebaseTokenVerifier>(Verifier);
        });
    }

    /// <summary>Seeds a confidential client-credentials client so tests can mint mcp.* tokens.</summary>
    public async Task EnsureClientCredentialsClientAsync()
    {
        using var scope = Services.CreateScope();
        var manager = scope.ServiceProvider.GetRequiredService<IOpenIddictApplicationManager>();
        if (await manager.FindByClientIdAsync(ClientCredentialsClientId) is not null)
        {
            return;
        }

        await manager.CreateAsync(new OpenIddictApplicationDescriptor
        {
            ClientId = ClientCredentialsClientId,
            ClientSecret = ClientCredentialsSecret,
            DisplayName = "Test client-credentials client",
            ClientType = OpenIddictConstants.ClientTypes.Confidential,
            Permissions =
            {
                OpenIddictConstants.Permissions.Endpoints.Token,
                OpenIddictConstants.Permissions.GrantTypes.ClientCredentials,
                OpenIddictConstants.Permissions.Prefixes.Scope + AuthScopes.McpRead,
                OpenIddictConstants.Permissions.Prefixes.Scope + AuthScopes.McpWrite,
                OpenIddictConstants.Permissions.Prefixes.Scope + AuthScopes.ApiRead,
                OpenIddictConstants.Permissions.Prefixes.Scope + AuthScopes.ApiWrite
            }
        });
    }
}

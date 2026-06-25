using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using OpenIddict.Abstractions;

namespace PolyAuth.OAuth;

public interface IOpenIddictSeeder
{
    Task SeedAsync(CancellationToken ct = default);
}

/// <summary>Runs the seeder once at startup.</summary>
public sealed class OpenIddictSeederHostedService : IHostedService
{
    private readonly IServiceProvider _serviceProvider;

    public OpenIddictSeederHostedService(IServiceProvider serviceProvider) => _serviceProvider = serviceProvider;

    public async Task StartAsync(CancellationToken cancellationToken)
    {
        using var scope = _serviceProvider.CreateScope();
        var seeder = scope.ServiceProvider.GetRequiredService<IOpenIddictSeeder>();
        await seeder.SeedAsync(cancellationToken);
    }

    public Task StopAsync(CancellationToken cancellationToken) => Task.CompletedTask;
}

/// <summary>
/// Idempotently ensures the built-in scopes, the first-party UI client (permitted to use the
/// Firebase token-exchange grant), and any statically configured clients exist in the OpenIddict store.
/// </summary>
public sealed class OpenIddictSeeder : IOpenIddictSeeder
{
    private readonly IOpenIddictApplicationManager _applicationManager;
    private readonly IOpenIddictScopeManager _scopeManager;
    private readonly OAuthServerOptions _options;
    private readonly McpAuthOptions _mcpOptions;
    private readonly ILogger<OpenIddictSeeder> _logger;

    public OpenIddictSeeder(
        IOpenIddictApplicationManager applicationManager,
        IOpenIddictScopeManager scopeManager,
        IOptions<PolyAuthOptions> options,
        ILogger<OpenIddictSeeder> logger)
    {
        _applicationManager = applicationManager;
        _scopeManager = scopeManager;
        _options = options.Value.OAuth;
        _mcpOptions = options.Value.Mcp;
        _logger = logger;
    }

    public async Task SeedAsync(CancellationToken ct = default)
    {
        var apiResources = OAuthResourceIndicators.GetApiResources(_options);
        var mcpResources = OAuthResourceIndicators.GetMcpResources(_options, _mcpOptions);

        await EnsureScopeAsync(AuthScopes.ApiRead, "Read the REST API", apiResources, ct);
        await EnsureScopeAsync(AuthScopes.ApiWrite, "Create and update via the REST API", apiResources, ct);
        await EnsureScopeAsync(AuthScopes.McpRead, "Read data through MCP", mcpResources, ct);
        await EnsureScopeAsync(AuthScopes.McpWrite, "Create and update data through MCP", mcpResources, ct);

        foreach (var scope in _options.Scopes.Additional)
        {
            await EnsureScopeAsync(scope, scope, apiResources, ct);
        }

        await EnsureUiClientAsync(ct);

        foreach (var client in _options.StaticClients)
        {
            await EnsureStaticClientAsync(client, ct);
        }
    }

    private async Task EnsureScopeAsync(string name, string displayName, IEnumerable<string> resources, CancellationToken ct)
    {
        var descriptor = new OpenIddictScopeDescriptor { Name = name, DisplayName = displayName };
        foreach (var resource in resources.Distinct(StringComparer.Ordinal))
        {
            descriptor.Resources.Add(resource);
        }

        var existing = await _scopeManager.FindByNameAsync(name, ct);
        if (existing == null)
        {
            try
            {
                await _scopeManager.CreateAsync(descriptor, ct);
                _logger.LogInformation("Created OpenIddict scope {Scope}", name);
            }
            catch (OpenIddictExceptions.ConcurrencyException)
            {
                existing = await _scopeManager.FindByNameAsync(name, ct);
                if (existing != null)
                {
                    await UpdateScopeIfNeededAsync(existing, descriptor, ct);
                }
            }

            return;
        }

        await UpdateScopeIfNeededAsync(existing, descriptor, ct);
    }

    private async Task UpdateScopeIfNeededAsync(object existing, OpenIddictScopeDescriptor descriptor, CancellationToken ct)
    {
        var currentDisplayName = await _scopeManager.GetDisplayNameAsync(existing, ct);
        var currentResources = await _scopeManager.GetResourcesAsync(existing, ct);
        var descriptorResources = descriptor.Resources.ToHashSet(StringComparer.Ordinal);

        var needsUpdate = currentDisplayName != descriptor.DisplayName
            || currentResources.Length != descriptorResources.Count
            || !currentResources.All(descriptorResources.Contains);

        if (needsUpdate)
        {
            try
            {
                await _scopeManager.UpdateAsync(existing, descriptor, ct);
            }
            catch (OpenIddictExceptions.ConcurrencyException ex)
            {
                _logger.LogWarning(ex, "Concurrency while updating scope {Scope}; another instance won.", descriptor.Name);
            }
        }
    }

    private async Task EnsureUiClientAsync(CancellationToken ct)
    {
        var descriptor = new OpenIddictApplicationDescriptor
        {
            ClientId = _options.UiClientId,
            DisplayName = "PolyAuth first-party UI client",
            ClientType = OpenIddictConstants.ClientTypes.Public,
            ConsentType = OpenIddictConstants.ConsentTypes.Implicit,
            Permissions =
            {
                OpenIddictConstants.Permissions.Endpoints.Token,
                OpenIddictConstants.Permissions.Endpoints.Revocation,
                OpenIddictConstants.Permissions.GrantTypes.RefreshToken,
                OpenIddictConstants.Permissions.Prefixes.GrantType + PolyAuthConstants.FirebaseTokenExchangeGrantType,
                OpenIddictConstants.Permissions.Scopes.Email,
                OpenIddictConstants.Permissions.Scopes.Profile,
                OpenIddictConstants.Permissions.Prefixes.Scope + OpenIddictConstants.Scopes.OpenId,
                OpenIddictConstants.Permissions.Prefixes.Scope + OpenIddictConstants.Scopes.OfflineAccess,
                OpenIddictConstants.Permissions.Prefixes.Scope + AuthScopes.ApiRead,
                OpenIddictConstants.Permissions.Prefixes.Scope + AuthScopes.ApiWrite
            }
        };

        await UpsertApplicationAsync(_options.UiClientId, descriptor, ct);
    }

    private async Task EnsureStaticClientAsync(OAuthStaticClientOptions client, CancellationToken ct)
    {
        ValidateStaticClient(client);
        var descriptor = OAuthStaticClientRules.CreateApplicationDescriptor(client);
        await UpsertApplicationAsync(client.ClientId, descriptor, ct);
    }

    private async Task UpsertApplicationAsync(string clientId, OpenIddictApplicationDescriptor descriptor, CancellationToken ct)
    {
        var existing = await _applicationManager.FindByClientIdAsync(clientId, ct);
        if (existing == null)
        {
            try
            {
                await _applicationManager.CreateAsync(descriptor, ct);
                _logger.LogInformation("Created OpenIddict client {ClientId}", clientId);
            }
            catch (OpenIddictExceptions.ConcurrencyException)
            {
                existing = await _applicationManager.FindByClientIdAsync(clientId, ct);
                if (existing != null)
                {
                    await UpdateApplicationIfNeededAsync(existing, descriptor, ct);
                }
            }

            return;
        }

        await UpdateApplicationIfNeededAsync(existing, descriptor, ct);
    }

    private async Task UpdateApplicationIfNeededAsync(object existing, OpenIddictApplicationDescriptor descriptor, CancellationToken ct)
    {
        var currentDisplayName = await _applicationManager.GetDisplayNameAsync(existing, ct);
        var currentClientType = await _applicationManager.GetClientTypeAsync(existing, ct);
        var currentConsentType = await _applicationManager.GetConsentTypeAsync(existing, ct);
        var currentPermissions = await _applicationManager.GetPermissionsAsync(existing, ct);
        var currentRedirectUris = await _applicationManager.GetRedirectUrisAsync(existing, ct);
        var currentPostLogoutRedirectUris = await _applicationManager.GetPostLogoutRedirectUrisAsync(existing, ct);

        var descriptorPermissions = descriptor.Permissions.ToHashSet(StringComparer.Ordinal);
        var descriptorRedirectUris = descriptor.RedirectUris.Select(u => u.OriginalString).ToHashSet(StringComparer.OrdinalIgnoreCase);
        var descriptorPostLogoutRedirectUris = descriptor.PostLogoutRedirectUris.Select(u => u.OriginalString).ToHashSet(StringComparer.OrdinalIgnoreCase);

        var needsUpdate = currentDisplayName != descriptor.DisplayName
            || currentClientType != descriptor.ClientType
            || currentConsentType != descriptor.ConsentType
            || currentPermissions.Length != descriptorPermissions.Count
            || !currentPermissions.All(descriptorPermissions.Contains)
            || currentRedirectUris.Length != descriptorRedirectUris.Count
            || !currentRedirectUris.All(descriptorRedirectUris.Contains)
            || currentPostLogoutRedirectUris.Length != descriptorPostLogoutRedirectUris.Count
            || !currentPostLogoutRedirectUris.All(descriptorPostLogoutRedirectUris.Contains);

        if (needsUpdate)
        {
            try
            {
                await _applicationManager.UpdateAsync(existing, descriptor, ct);
                _logger.LogInformation("Updated OpenIddict client {ClientId}", descriptor.ClientId);
            }
            catch (OpenIddictExceptions.ConcurrencyException ex)
            {
                _logger.LogWarning(ex, "Concurrency while updating client {ClientId}; another instance won.", descriptor.ClientId);
            }
        }
    }

    private static bool IsValidRedirectUri(string value)
        => Uri.TryCreate(value, UriKind.Absolute, out var uri) && (uri.Scheme == Uri.UriSchemeHttps || uri.IsLoopback);

    public static void ValidateStaticClient(OAuthStaticClientOptions client)
    {
        if (string.IsNullOrWhiteSpace(client.ClientId))
        {
            throw new InvalidOperationException("PolyAuth:OAuth:StaticClients entries must set ClientId.");
        }

        if (client.RedirectUris.Count == 0 && !client.AllowLoopbackRedirectUris)
        {
            throw new InvalidOperationException($"OAuth static client '{client.ClientId}' must set at least one RedirectUris entry.");
        }

        var invalidRedirectUri = client.RedirectUris.FirstOrDefault(uri => !IsValidRedirectUri(uri));
        if (invalidRedirectUri != null)
        {
            throw new InvalidOperationException($"OAuth static client '{client.ClientId}' has invalid redirect URI '{invalidRedirectUri}'.");
        }

        var invalidPostLogoutRedirectUri = client.PostLogoutRedirectUris.FirstOrDefault(uri => !IsValidRedirectUri(uri));
        if (invalidPostLogoutRedirectUri != null)
        {
            throw new InvalidOperationException($"OAuth static client '{client.ClientId}' has invalid post-logout redirect URI '{invalidPostLogoutRedirectUri}'.");
        }

        if (client.AllowLoopbackRedirectUris)
        {
            if (client.AllowedLoopbackRedirectPaths.Count == 0)
            {
                throw new InvalidOperationException($"OAuth static client '{client.ClientId}' must set AllowedLoopbackRedirectPaths when AllowLoopbackRedirectUris is true.");
            }

            var invalidPath = client.AllowedLoopbackRedirectPaths.FirstOrDefault(path =>
                string.IsNullOrWhiteSpace(path)
                || !path.StartsWith('/')
                || path.Contains('?', StringComparison.Ordinal)
                || path.Contains('#', StringComparison.Ordinal)
                || path.Contains("://", StringComparison.Ordinal));
            if (invalidPath != null)
            {
                throw new InvalidOperationException($"OAuth static client '{client.ClientId}' has invalid loopback redirect path '{invalidPath}'.");
            }
        }

        var scopes = OAuthStaticClientRules.GetScopes(client);
        if (scopes.Length == 0)
        {
            throw new InvalidOperationException($"OAuth static client '{client.ClientId}' must set Scopes.");
        }

        var invalidScope = scopes.FirstOrDefault(scope => !OAuthClientMetadataRules.AllowedScopes.Contains(scope));
        if (invalidScope != null)
        {
            throw new InvalidOperationException($"OAuth static client '{client.ClientId}' requests unsupported scope '{invalidScope}'.");
        }
    }
}

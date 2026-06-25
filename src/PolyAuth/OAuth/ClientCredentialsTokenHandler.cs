using Microsoft.Extensions.Logging;
using OpenIddict.Abstractions;
using OpenIddict.Server;

namespace PolyAuth.OAuth;

/// <summary>
/// Machine-to-machine token issuance. OpenIddict has already authenticated the client; this handler
/// validates the requested scopes against the grantable set, builds the principal (subject = client id),
/// and lets an optional <see cref="IPolyAuthPrincipalEnricher"/> add app claims.
/// </summary>
public sealed class ClientCredentialsTokenHandler :
    IOpenIddictServerHandler<OpenIddictServerEvents.HandleTokenRequestContext>
{
    private static readonly HashSet<string> AllowedScopes = new(AuthScopes.Grantable, StringComparer.Ordinal);
    private static readonly string[] DefaultScopes = [AuthScopes.ApiRead, AuthScopes.ApiWrite];

    private readonly IOpenIddictApplicationManager _applicationManager;
    private readonly IPolyAuthPrincipalEnricher _enricher;
    private readonly ILogger<ClientCredentialsTokenHandler> _logger;

    public ClientCredentialsTokenHandler(
        IOpenIddictApplicationManager applicationManager,
        IPolyAuthPrincipalEnricher enricher,
        ILogger<ClientCredentialsTokenHandler> logger)
    {
        _applicationManager = applicationManager;
        _enricher = enricher;
        _logger = logger;
    }

    public async ValueTask HandleAsync(OpenIddictServerEvents.HandleTokenRequestContext context)
    {
        if (!context.Request.IsClientCredentialsGrantType())
        {
            return;
        }

        var clientId = context.Request.ClientId!;
        var application = await _applicationManager.FindByClientIdAsync(clientId, context.CancellationToken);
        if (application == null)
        {
            context.Reject(OpenIddictConstants.Errors.InvalidClient, "The client application could not be found.", uri: null);
            return;
        }

        var scopes = context.Request.GetScopes().ToArray();
        if (scopes.Length == 0)
        {
            scopes = DefaultScopes;
        }

        if (scopes.Any(scope => !AllowedScopes.Contains(scope)))
        {
            context.Reject(
                OpenIddictConstants.Errors.InvalidScope,
                $"Only the following scopes are supported by the client credentials grant: {string.Join(", ", AuthScopes.Grantable)}.",
                uri: null);
            return;
        }

        var displayName = await _applicationManager.GetDisplayNameAsync(application, context.CancellationToken);

        // For client_credentials, OpenIddict requires the subject to equal the client_id.
        var principal = OpenIddictPrincipalFactory.ForClient(clientId, scopes, displayName);

        await _enricher.EnrichAsync(
            new PrincipalEnrichmentContext(principal, PrincipalEnrichmentGrant.ClientCredentials, clientId),
            context.CancellationToken);
        OpenIddictPrincipalFactory.ApplyDestinations(principal);

        _logger.LogInformation("Issued client credentials token for client {ClientId}", clientId);
        context.SignIn(principal);
    }
}

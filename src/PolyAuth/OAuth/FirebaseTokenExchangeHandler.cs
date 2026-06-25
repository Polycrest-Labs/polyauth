using FirebaseAdmin.Auth;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using OpenIddict.Abstractions;
using OpenIddict.Server;
using PolyAuth.Firebase;

namespace PolyAuth.OAuth;

/// <summary>
/// Handles the custom <c>urn:polyauth:firebase</c> grant: validates the supplied Firebase ID token
/// and issues OAuth access/refresh tokens with the Firebase uid as subject and the requested
/// (allowed) scopes. Restricted to the configured first-party UI client.
/// </summary>
public sealed class FirebaseTokenExchangeHandler :
    IOpenIddictServerHandler<OpenIddictServerEvents.HandleTokenRequestContext>
{
    private static readonly HashSet<string> UiAllowedScopes = new(StringComparer.Ordinal)
    {
        OpenIddictConstants.Scopes.OpenId,
        OpenIddictConstants.Scopes.Profile,
        OpenIddictConstants.Scopes.Email,
        OpenIddictConstants.Scopes.OfflineAccess,
        AuthScopes.ApiRead,
        AuthScopes.ApiWrite
    };

    private static readonly string[] DefaultUiScopes =
    [
        OpenIddictConstants.Scopes.OpenId,
        OpenIddictConstants.Scopes.Profile,
        OpenIddictConstants.Scopes.Email,
        AuthScopes.ApiRead,
        AuthScopes.ApiWrite,
        OpenIddictConstants.Scopes.OfflineAccess
    ];

    private readonly IFirebaseTokenVerifier _verifier;
    private readonly IPolyAuthPrincipalEnricher _enricher;
    private readonly OAuthServerOptions _options;
    private readonly ILogger<FirebaseTokenExchangeHandler> _logger;

    public FirebaseTokenExchangeHandler(
        IFirebaseTokenVerifier verifier,
        IPolyAuthPrincipalEnricher enricher,
        IOptions<PolyAuthOptions> options,
        ILogger<FirebaseTokenExchangeHandler> logger)
    {
        _verifier = verifier;
        _enricher = enricher;
        _options = options.Value.OAuth;
        _logger = logger;
    }

    public async ValueTask HandleAsync(OpenIddictServerEvents.HandleTokenRequestContext context)
    {
        if (!string.Equals(context.Request.GrantType, PolyAuthConstants.FirebaseTokenExchangeGrantType, StringComparison.Ordinal))
        {
            return;
        }

        var clientId = context.Request.ClientId;
        if (!string.Equals(clientId, _options.UiClientId, StringComparison.Ordinal))
        {
            context.Reject(
                OpenIddictConstants.Errors.InvalidClient,
                "The Firebase token exchange grant is restricted to the first-party UI client.",
                uri: null);
            return;
        }

        var firebaseIdToken = (string?)context.Request.GetParameter(PolyAuthConstants.FirebaseIdTokenParameter);
        if (string.IsNullOrWhiteSpace(firebaseIdToken))
        {
            context.Reject(
                OpenIddictConstants.Errors.InvalidRequest,
                $"The {PolyAuthConstants.FirebaseIdTokenParameter} parameter is required.",
                uri: null);
            return;
        }

        var scopes = context.Request.GetScopes().ToArray();
        if (scopes.Length == 0)
        {
            scopes = DefaultUiScopes;
        }

        if (scopes.Any(scope => !UiAllowedScopes.Contains(scope)))
        {
            context.Reject(
                OpenIddictConstants.Errors.InvalidScope,
                "One or more requested scopes are not supported by the UI client.",
                uri: null);
            return;
        }

        try
        {
            var token = await _verifier.VerifyIdTokenAsync(firebaseIdToken, context.CancellationToken);
            var principal = OpenIddictPrincipalFactory.FromFirebaseToken(token, scopes);

            await _enricher.EnrichAsync(
                new PrincipalEnrichmentContext(principal, PrincipalEnrichmentGrant.FirebaseTokenExchange, clientId),
                context.CancellationToken);
            OpenIddictPrincipalFactory.ApplyDestinations(principal);

            _logger.LogInformation(
                "Exchanged Firebase ID token for OpenIddict tokens for UI client {ClientId} and subject {Subject}",
                clientId, token.Uid);

            context.SignIn(principal);
        }
        catch (FirebaseAuthException ex)
        {
            _logger.LogWarning(ex, "Firebase token exchange failed because Firebase rejected the ID token.");
            context.Reject(OpenIddictConstants.Errors.InvalidGrant, "The Firebase ID token is invalid.", uri: null);
        }
    }
}

using System.Security.Claims;
using System.Text.Json;
using System.Text.Json.Nodes;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using OpenIddict.Abstractions;
using OpenIddict.Server;

namespace PolyAuth.OAuth;

/// <summary>Materializes a CIMD (DCR-by-URL) client when an authorization request uses an HTTPS client_id.</summary>
public sealed class OAuthClientMetadataAuthorizationHandler :
    IOpenIddictServerHandler<OpenIddictServerEvents.ValidateAuthorizationRequestContext>
{
    private readonly IOAuthClientMetadataService _metadataService;
    private readonly ILogger<OAuthClientMetadataAuthorizationHandler> _logger;

    public OAuthClientMetadataAuthorizationHandler(
        IOAuthClientMetadataService metadataService,
        ILogger<OAuthClientMetadataAuthorizationHandler> logger)
    {
        _metadataService = metadataService;
        _logger = logger;
    }

    public async ValueTask HandleAsync(OpenIddictServerEvents.ValidateAuthorizationRequestContext context)
    {
        if (!OAuthClientMetadataRules.LooksLikeClientMetadataDocumentId(context.ClientId))
        {
            return;
        }

        try
        {
            await _metadataService.EnsureOpenIddictClientAsync(context.Request, context.CancellationToken);
        }
        catch (OAuthClientMetadataException ex)
        {
            _logger.LogWarning(ex, "Rejected CIMD authorization request for client {ClientId}", context.ClientId);
            context.Reject(OpenIddictConstants.Errors.InvalidClient, ex.Message, uri: null);
        }
    }
}

/// <summary>Advertises CIMD / private_key_jwt support in the AS discovery document.</summary>
public sealed class OAuthClientMetadataConfigurationHandler :
    IOpenIddictServerHandler<OpenIddictServerEvents.HandleConfigurationRequestContext>
{
    public ValueTask HandleAsync(OpenIddictServerEvents.HandleConfigurationRequestContext context)
    {
        context.Metadata["client_id_metadata_document_supported"] = true;
        context.Metadata["registration_endpoint"] = new Uri(context.Issuer!, "/connect/register").AbsoluteUri;
        context.Metadata["token_endpoint_auth_methods_supported"] = new JsonArray(
            OpenIddictConstants.ClientAuthenticationMethods.None,
            OpenIddictConstants.ClientAuthenticationMethods.PrivateKeyJwt);
        context.Metadata["revocation_endpoint_auth_methods_supported"] = new JsonArray(
            OpenIddictConstants.ClientAuthenticationMethods.None,
            OpenIddictConstants.ClientAuthenticationMethods.PrivateKeyJwt);
        return default;
    }
}

/// <summary>Materializes loopback redirect URIs (Claude Desktop) for configured loopback clients.</summary>
public sealed class OAuthLoopbackRedirectAuthorizationHandler :
    IOpenIddictServerHandler<OpenIddictServerEvents.ValidateAuthorizationRequestContext>
{
    private readonly IOpenIddictApplicationManager _applicationManager;
    private readonly OAuthServerOptions _options;
    private readonly ILogger<OAuthLoopbackRedirectAuthorizationHandler> _logger;

    public OAuthLoopbackRedirectAuthorizationHandler(
        IOpenIddictApplicationManager applicationManager,
        IOptions<PolyAuthOptions> options,
        ILogger<OAuthLoopbackRedirectAuthorizationHandler> logger)
    {
        _applicationManager = applicationManager;
        _options = options.Value.OAuth;
        _logger = logger;
    }

    public async ValueTask HandleAsync(OpenIddictServerEvents.ValidateAuthorizationRequestContext context)
    {
        if (string.IsNullOrWhiteSpace(context.ClientId) || string.IsNullOrWhiteSpace(context.RedirectUri))
        {
            return;
        }

        var client = _options.StaticClients.FirstOrDefault(c =>
            string.Equals(c.ClientId, context.ClientId, StringComparison.Ordinal));
        if (client == null || !OAuthStaticClientRules.IsConfiguredLoopbackClient(client))
        {
            return;
        }

        if (!OAuthStaticClientRules.IsAllowedLoopbackRedirectUri(client, context.RedirectUri))
        {
            context.Reject(
                OpenIddictConstants.Errors.InvalidRequest,
                "The loopback redirect_uri is not allowed for this client.",
                uri: null);
            return;
        }

        var application = await _applicationManager.FindByClientIdAsync(context.ClientId, context.CancellationToken);
        if (application == null)
        {
            return;
        }

        var redirectUris = client.RedirectUris.Append(context.RedirectUri).Distinct(StringComparer.Ordinal);
        var descriptor = OAuthStaticClientRules.CreateApplicationDescriptor(client, redirectUris);

        await _applicationManager.UpdateAsync(application, descriptor, context.CancellationToken);
        _logger.LogDebug(
            "Materialized loopback redirect URI {RedirectUri} for OAuth client {ClientId}",
            context.RedirectUri, context.ClientId);
    }
}

/// <summary>Reads the alg/kid/typ from a JWT header for diagnostics, without verifying it.</summary>
public sealed record OAuthJwtHeaderDiagnostics(string? Algorithm, string? KeyId, string? Type);

public static class OAuthJwtDiagnostics
{
    public static OAuthJwtHeaderDiagnostics ReadHeader(string? token)
    {
        if (string.IsNullOrWhiteSpace(token))
        {
            return new OAuthJwtHeaderDiagnostics(null, null, null);
        }

        var separator = token.IndexOf('.', StringComparison.Ordinal);
        if (separator <= 0)
        {
            return new OAuthJwtHeaderDiagnostics(null, null, null);
        }

        try
        {
            var headerBytes = Base64UrlEncoder.DecodeBytes(token[..separator]);
            using var document = JsonDocument.Parse(headerBytes);
            var root = document.RootElement;
            return new OAuthJwtHeaderDiagnostics(GetString(root, "alg"), GetString(root, "kid"), GetString(root, "typ"));
        }
        catch (Exception)
        {
            return new OAuthJwtHeaderDiagnostics(null, null, null);
        }
    }

    private static string? GetString(JsonElement element, string propertyName)
        => element.TryGetProperty(propertyName, out var property) && property.ValueKind == JsonValueKind.String
            ? property.GetString()
            : null;
}

/// <summary>(Optional) Accepts generic-JWT client assertions (private_key_jwt) at the token endpoint.</summary>
public sealed class OAuthClientAssertionTokenTypeHandler :
    IOpenIddictServerHandler<OpenIddictServerEvents.ValidateTokenContext>
{
    private readonly ILogger<OAuthClientAssertionTokenTypeHandler> _logger;

    public OAuthClientAssertionTokenTypeHandler(ILogger<OAuthClientAssertionTokenTypeHandler> logger)
        => _logger = logger;

    public ValueTask HandleAsync(OpenIddictServerEvents.ValidateTokenContext context)
    {
        if (!IsClientAssertionValidation(context))
        {
            return default;
        }

        context.ValidTokenTypes.Add(OpenIddictConstants.JsonWebTokenTypes.GenericJsonWebToken);
        context.ValidTokenTypes.Add(OpenIddictConstants.TokenTypeIdentifiers.IdentityToken);
        context.TokenValidationParameters.ValidTypes = AddValidType(
            context.TokenValidationParameters.ValidTypes,
            OpenIddictConstants.JsonWebTokenTypes.GenericJsonWebToken);

        var header = OAuthJwtDiagnostics.ReadHeader(context.Token);
        _logger.LogInformation(
            "OAuth client assertion accepted generic JWT token type for client {ClientId}. Header alg={Algorithm}, kid={KeyId}, typ={Type}",
            context.Request?.ClientId, header.Algorithm ?? "(missing)", header.KeyId ?? "(missing)", header.Type ?? "(missing)");
        return default;
    }

    private static bool IsClientAssertionValidation(OpenIddictServerEvents.ValidateTokenContext context)
        => !string.IsNullOrWhiteSpace(context.Token)
           && string.Equals(context.Token, context.Request?.ClientAssertion, StringComparison.Ordinal)
           && string.Equals(context.Request?.ClientAssertionType, OpenIddictConstants.ClientAssertionTypes.JwtBearer, StringComparison.Ordinal);

    private static IEnumerable<string> AddValidType(IEnumerable<string>? values, string value)
        => (values ?? []).Append(value).Distinct(StringComparer.Ordinal).ToArray();
}

/// <summary>(Optional) Normalizes client-assertion audiences for CIMD clients across issuer/token-endpoint variants.</summary>
public sealed class OAuthClientAssertionAudienceCompatibilityHandler :
    IOpenIddictServerHandler<OpenIddictServerEvents.ProcessAuthenticationContext>
{
    private const string TokenEndpointPath = "/connect/token";
    private readonly ILogger<OAuthClientAssertionAudienceCompatibilityHandler> _logger;

    public OAuthClientAssertionAudienceCompatibilityHandler(ILogger<OAuthClientAssertionAudienceCompatibilityHandler> logger)
        => _logger = logger;

    public ValueTask HandleAsync(OpenIddictServerEvents.ProcessAuthenticationContext context)
    {
        if (!IsClientAssertionValidation(context)
            || !IsHttpsClientMetadataIdentifier(context.Request?.ClientId)
            || context.ClientAssertionPrincipal?.Identity is not ClaimsIdentity identity)
        {
            return default;
        }

        var audiences = identity.FindAll(OpenIddictConstants.Claims.Audience)
            .Select(claim => claim.Value)
            .Where(value => !string.IsNullOrWhiteSpace(value))
            .Distinct(StringComparer.Ordinal)
            .ToArray();
        if (audiences.Length == 0)
        {
            return default;
        }

        var expectedAudience = GetExpectedIssuerAudience(context);
        if (string.IsNullOrWhiteSpace(expectedAudience))
        {
            return default;
        }

        if (audiences.Any(audience => AudienceEquals(audience, expectedAudience)))
        {
            NormalizeAudienceClaims(identity, expectedAudience);
            return default;
        }

        var legacyTokenEndpointAudiences = GetLegacyTokenEndpointAudiences(context, expectedAudience);
        if (audiences.Any(audience => legacyTokenEndpointAudiences.Contains(NormalizeAudience(audience))))
        {
            NormalizeAudienceClaims(identity, expectedAudience);
            _logger.LogInformation(
                "Normalized client assertion audience for CIMD client {ClientId}", context.Request?.ClientId);
        }

        return default;
    }

    private static bool IsClientAssertionValidation(OpenIddictServerEvents.ProcessAuthenticationContext context)
        => context.ClientAssertionPrincipal is not null
           && IsTokenEndpointRequest(context)
           && !string.IsNullOrWhiteSpace(context.ClientAssertion)
           && string.Equals(context.ClientAssertion, context.Request?.ClientAssertion, StringComparison.Ordinal)
           && string.Equals(context.ClientAssertionType, OpenIddictConstants.ClientAssertionTypes.JwtBearer, StringComparison.Ordinal);

    private static bool IsTokenEndpointRequest(OpenIddictServerEvents.ProcessAuthenticationContext context)
        => context.EndpointType == OpenIddictServerEndpointType.Token
           || string.Equals(context.RequestUri?.AbsolutePath, TokenEndpointPath, StringComparison.Ordinal);

    private static bool IsHttpsClientMetadataIdentifier(string? clientId)
        => Uri.TryCreate(clientId, UriKind.Absolute, out var uri)
           && string.Equals(uri.Scheme, Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase);

    private static string? GetExpectedIssuerAudience(OpenIddictServerEvents.ProcessAuthenticationContext context)
        => context.Options.Issuer is not null
            ? context.Options.Issuer.AbsoluteUri
            : context.BaseUri?.AbsoluteUri;

    private static HashSet<string> GetLegacyTokenEndpointAudiences(
        OpenIddictServerEvents.ProcessAuthenticationContext context, string expectedAudience)
    {
        var audiences = new HashSet<string>(StringComparer.Ordinal);
        if (context.RequestUri is not null)
        {
            audiences.Add(NormalizeAudience(context.RequestUri.GetLeftPart(UriPartial.Path)));
        }

        if (Uri.TryCreate(expectedAudience, UriKind.Absolute, out var issuer))
        {
            audiences.Add(NormalizeAudience(new Uri(issuer, TokenEndpointPath).AbsoluteUri));
        }

        return audiences;
    }

    private static void NormalizeAudienceClaims(ClaimsIdentity identity, string expectedAudience)
    {
        foreach (var claim in identity.FindAll(OpenIddictConstants.Claims.Audience).ToArray())
        {
            identity.RemoveClaim(claim);
        }

        identity.AddClaim(new Claim(OpenIddictConstants.Claims.Audience, expectedAudience));
    }

    private static string NormalizeAudience(string audience) => audience.TrimEnd('/');

    private static bool AudienceEquals(string left, string right)
        => string.Equals(NormalizeAudience(left), NormalizeAudience(right), StringComparison.Ordinal);
}

/// <summary>(Optional) Logs token-endpoint errors with client / grant / assertion-header context.</summary>
public sealed class OAuthTokenEndpointDiagnosticsHandler :
    IOpenIddictServerHandler<OpenIddictServerEvents.ApplyTokenResponseContext>
{
    private readonly ILogger<OAuthTokenEndpointDiagnosticsHandler> _logger;

    public OAuthTokenEndpointDiagnosticsHandler(ILogger<OAuthTokenEndpointDiagnosticsHandler> logger)
        => _logger = logger;

    public ValueTask HandleAsync(OpenIddictServerEvents.ApplyTokenResponseContext context)
    {
        if (string.IsNullOrWhiteSpace(context.Response?.Error))
        {
            return default;
        }

        var assertionHeader = OAuthJwtDiagnostics.ReadHeader(context.Request?.ClientAssertion);
        _logger.LogWarning(
            "OAuth token endpoint returned error {Error} for client {ClientId}, grant {GrantType}. Has client assertion: {HasClientAssertion}. Assertion header alg={Algorithm}, kid={KeyId}, typ={Type}. Description: {ErrorDescription}",
            context.Response.Error,
            context.Request?.ClientId,
            context.Request?.GrantType,
            !string.IsNullOrWhiteSpace(context.Request?.ClientAssertion),
            assertionHeader.Algorithm ?? "(missing)",
            assertionHeader.KeyId ?? "(missing)",
            assertionHeader.Type ?? "(missing)",
            context.Response.ErrorDescription);
        return default;
    }
}

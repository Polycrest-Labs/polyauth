using Microsoft.IdentityModel.Tokens;
using OpenIddict.Abstractions;

namespace PolyAuth.OAuth;

/// <summary>
/// Validation + descriptor building for client-id metadata documents (DCR-by-URL). External MCP
/// clients (ChatGPT) are restricted to MCP scopes and the authorization_code / refresh_token grants.
/// </summary>
public static class OAuthClientMetadataRules
{
    public static readonly HashSet<string> AllowedScopes = new(StringComparer.Ordinal)
    {
        OpenIddictConstants.Scopes.OpenId,
        OpenIddictConstants.Scopes.Profile,
        OpenIddictConstants.Scopes.Email,
        OpenIddictConstants.Scopes.OfflineAccess,
        AuthScopes.McpRead,
        AuthScopes.McpWrite
    };

    public static bool LooksLikeClientMetadataDocumentId(string? clientId)
        => clientId?.StartsWith("https://", StringComparison.OrdinalIgnoreCase) == true
           || clientId?.StartsWith("http://", StringComparison.OrdinalIgnoreCase) == true;

    public static string? ValidateClientMetadataDocumentId(string? clientId)
    {
        if (string.IsNullOrWhiteSpace(clientId)
            || !Uri.TryCreate(clientId, UriKind.Absolute, out var uri)
            || uri.Scheme != Uri.UriSchemeHttps)
        {
            return "CIMD client_id values must be absolute HTTPS URLs.";
        }

        if (uri.UserInfo.Length != 0 || uri.Fragment.Length != 0)
        {
            return "CIMD client_id URLs must not include user info or fragments.";
        }

        if (string.IsNullOrWhiteSpace(uri.AbsolutePath) || uri.AbsolutePath == "/")
        {
            return "CIMD client_id URLs must include a path component.";
        }

        if (!OAuthRedirectUriRules.IsPublicHost(uri.Host))
        {
            return "CIMD client_id URLs must use public HTTPS hosts.";
        }

        return null;
    }

    public static string? Validate(
        OAuthClientMetadataDocument? document,
        string clientId,
        string? redirectUri,
        IReadOnlySet<string> requestedScopes)
    {
        var clientIdError = ValidateClientMetadataDocumentId(clientId);
        if (clientIdError != null)
        {
            return clientIdError;
        }

        if (document == null)
        {
            return "The CIMD metadata document could not be parsed.";
        }

        if (!string.Equals(document.ClientId, clientId, StringComparison.Ordinal))
        {
            return "The CIMD metadata document client_id must exactly match the requested client_id.";
        }

        if (string.IsNullOrWhiteSpace(redirectUri))
        {
            return "CIMD authorization requests must include a redirect_uri.";
        }

        if (!document.RedirectUris.Contains(redirectUri, StringComparer.Ordinal))
        {
            return "The authorization redirect_uri is not listed in the CIMD metadata document.";
        }

        if (document.RedirectUris.Count == 0 || document.RedirectUris.Any(uri => !OAuthRedirectUriRules.IsValidPublicHttpsUri(uri)))
        {
            return "All CIMD redirect_uris entries must be absolute HTTPS URLs.";
        }

        if (!IsSupportedTokenEndpointAuthMethod(document.TokenEndpointAuthMethod))
        {
            return "Only public PKCE clients using token_endpoint_auth_method 'none' and CIMD clients using private_key_jwt are supported.";
        }

        if (UsesPrivateKeyJwt(document))
        {
            if (string.IsNullOrWhiteSpace(document.JwksUri))
            {
                return "CIMD clients using private_key_jwt must include jwks_uri.";
            }

            if (!OAuthRedirectUriRules.IsValidPublicHttpsUri(document.JwksUri))
            {
                return "CIMD jwks_uri values must be absolute public HTTPS URLs without user info or fragments.";
            }
        }

        // A CIMD can describe grant types the client uses with other authorization servers. Only require the
        // interactive grant needed by this server; CreateApplicationDescriptor deliberately grants no permissions
        // beyond authorization_code and refresh_token. Claude, for example, also advertises JWT bearer here.
        if (document.GrantTypes.Count == 0
            || !document.GrantTypes.Contains(OpenIddictConstants.GrantTypes.AuthorizationCode, StringComparer.Ordinal))
        {
            return "The authorization_code grant type is required.";
        }

        if (document.ResponseTypes.Count == 0
            || !document.ResponseTypes.Contains(OpenIddictConstants.ResponseTypes.Code, StringComparer.Ordinal)
            || document.ResponseTypes.Any(responseType => responseType != OpenIddictConstants.ResponseTypes.Code))
        {
            return "Only the code response type is supported.";
        }

        var documentScopes = ParseScopes(document.Scope);
        if (documentScopes.Any(scope => !AllowedScopes.Contains(scope))
            || requestedScopes.Any(scope => !AllowedScopes.Contains(scope)))
        {
            return "One or more requested scopes are not supported.";
        }

        if (documentScopes.Count != 0 && requestedScopes.Any(scope => !documentScopes.Contains(scope)))
        {
            return "Requested scopes must be listed in the CIMD metadata document scope value.";
        }

        return null;
    }

    public static HashSet<string> ParseScopes(string? scope)
        => string.IsNullOrWhiteSpace(scope)
            ? []
            : scope.Split(' ', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
                .ToHashSet(StringComparer.Ordinal);

    public static OpenIddictApplicationDescriptor CreateApplicationDescriptor(
        OAuthClientMetadataDocument document,
        IReadOnlySet<string> requestedScopes,
        JsonWebKeySet? jsonWebKeySet = null,
        IEnumerable<string>? requestedResources = null)
    {
        var scopes = ParseScopes(document.Scope);
        if (scopes.Count == 0)
        {
            scopes = requestedScopes.ToHashSet(StringComparer.Ordinal);
        }

        if (!UsesPrivateKeyJwt(document))
        {
            return OAuthPublicClientDescriptorFactory.Create(
                document.ClientId!,
                document.ClientName,
                scopes,
                document.RedirectUris,
                resources: requestedResources);
        }

        var descriptor = new OpenIddictApplicationDescriptor
        {
            ClientId = document.ClientId,
            DisplayName = string.IsNullOrWhiteSpace(document.ClientName) ? document.ClientId : document.ClientName,
            ClientType = OpenIddictConstants.ClientTypes.Confidential,
            ConsentType = OpenIddictConstants.ConsentTypes.Explicit,
            JsonWebKeySet = jsonWebKeySet ?? throw new ArgumentNullException(nameof(jsonWebKeySet)),
            Requirements = { OpenIddictConstants.Requirements.Features.ProofKeyForCodeExchange },
            Permissions =
            {
                OpenIddictConstants.Permissions.Endpoints.Authorization,
                OpenIddictConstants.Permissions.Endpoints.Token,
                OpenIddictConstants.Permissions.Endpoints.Revocation,
                OpenIddictConstants.Permissions.GrantTypes.AuthorizationCode,
                OpenIddictConstants.Permissions.GrantTypes.RefreshToken,
                OpenIddictConstants.Permissions.ResponseTypes.Code
            }
        };

        foreach (var scope in scopes)
        {
            descriptor.Permissions.Add(OAuthScopePermissions.GetScopePermission(scope));
        }

        descriptor.AddResourcePermissions(requestedResources?.Distinct(StringComparer.Ordinal).ToArray() ?? []);

        foreach (var redirectUri in document.RedirectUris)
        {
            descriptor.RedirectUris.Add(new Uri(redirectUri));
        }

        return descriptor;
    }

    public static bool UsesPrivateKeyJwt(OAuthClientMetadataDocument document)
        => string.Equals(
            document.TokenEndpointAuthMethod,
            OpenIddictConstants.ClientAuthenticationMethods.PrivateKeyJwt,
            StringComparison.Ordinal);

    private static bool IsSupportedTokenEndpointAuthMethod(string? method)
        => string.IsNullOrWhiteSpace(method)
           || string.Equals(method, OpenIddictConstants.ClientAuthenticationMethods.None, StringComparison.Ordinal)
           || string.Equals(method, OpenIddictConstants.ClientAuthenticationMethods.PrivateKeyJwt, StringComparison.Ordinal);
}

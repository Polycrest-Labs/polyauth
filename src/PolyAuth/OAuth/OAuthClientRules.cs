using System.Net;
using Microsoft.IdentityModel.Tokens;
using OpenIddict.Abstractions;

namespace PolyAuth.OAuth;

/// <summary>Maps a scope name to the corresponding OpenIddict permission string.</summary>
public static class OAuthScopePermissions
{
    public static string GetScopePermission(string scope) => scope switch
    {
        OpenIddictConstants.Scopes.Email => OpenIddictConstants.Permissions.Scopes.Email,
        OpenIddictConstants.Scopes.Profile => OpenIddictConstants.Permissions.Scopes.Profile,
        _ => OpenIddictConstants.Permissions.Prefixes.Scope + scope
    };
}

/// <summary>Public-host / public-HTTPS validation for redirect URIs and CIMD client ids.</summary>
public static class OAuthRedirectUriRules
{
    public static bool IsValidPublicHttpsUri(string value)
    {
        return Uri.TryCreate(value, UriKind.Absolute, out var uri)
               && uri.Scheme == Uri.UriSchemeHttps
               && uri.UserInfo.Length == 0
               && uri.Fragment.Length == 0
               && IsPublicHost(uri.Host);
    }

    public static bool IsPublicHost(string host) => !IsLocalHost(host) && !IsPrivateIpAddress(host);

    private static bool IsLocalHost(string host)
        => string.Equals(host, "localhost", StringComparison.OrdinalIgnoreCase)
           || string.Equals(host, "localhost.", StringComparison.OrdinalIgnoreCase);

    private static bool IsPrivateIpAddress(string host)
    {
        if (!IPAddress.TryParse(host, out var address))
        {
            return false;
        }

        if (IPAddress.IsLoopback(address))
        {
            return true;
        }

        var bytes = address.GetAddressBytes();
        return address.AddressFamily switch
        {
            System.Net.Sockets.AddressFamily.InterNetwork => bytes[0] == 10
                || bytes[0] == 0
                || bytes[0] == 127
                || (bytes[0] == 172 && bytes[1] >= 16 && bytes[1] <= 31)
                || (bytes[0] == 192 && bytes[1] == 168)
                || (bytes[0] == 169 && bytes[1] == 254)
                || (bytes[0] == 100 && bytes[1] >= 64 && bytes[1] <= 127)
                || bytes[0] >= 224,
            System.Net.Sockets.AddressFamily.InterNetworkV6 => address.IsIPv6LinkLocal
                || address.IsIPv6SiteLocal
                || address.IsIPv6Multicast
                || address.Equals(IPAddress.IPv6Loopback)
                || (bytes[0] & 0xFE) == 0xFC,
            _ => false
        };
    }
}

/// <summary>Builds public PKCE client descriptors (used for static, loopback, and CIMD public clients).</summary>
public static class OAuthPublicClientDescriptorFactory
{
    public static OpenIddictApplicationDescriptor Create(
        string clientId,
        string? displayName,
        IEnumerable<string> scopes,
        IEnumerable<string> redirectUris,
        IEnumerable<string>? postLogoutRedirectUris = null,
        IEnumerable<string>? resources = null)
    {
        var descriptor = new OpenIddictApplicationDescriptor
        {
            ClientId = clientId,
            DisplayName = string.IsNullOrWhiteSpace(displayName) ? clientId : displayName,
            ClientType = OpenIddictConstants.ClientTypes.Public,
            ConsentType = OpenIddictConstants.ConsentTypes.Explicit,
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

        descriptor.AddResourcePermissions(resources?.Distinct(StringComparer.Ordinal).ToArray() ?? []);

        foreach (var redirectUri in redirectUris)
        {
            descriptor.RedirectUris.Add(new Uri(redirectUri));
        }

        foreach (var redirectUri in postLogoutRedirectUris ?? [])
        {
            descriptor.PostLogoutRedirectUris.Add(new Uri(redirectUri));
        }

        return descriptor;
    }
}

/// <summary>Rules and descriptor building for statically configured clients (incl. loopback clients).</summary>
public static class OAuthStaticClientRules
{
    public static string[] GetScopes(OAuthStaticClientOptions client)
        => client.Scopes
            .SelectMany(scope => scope.Split(' ', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
            .Distinct(StringComparer.Ordinal)
            .ToArray();

    public static bool IsConfiguredLoopbackClient(OAuthStaticClientOptions client) => client.AllowLoopbackRedirectUris;

    public static bool IsAllowedLoopbackRedirectUri(OAuthStaticClientOptions client, string? redirectUri)
    {
        if (!client.AllowLoopbackRedirectUris
            || string.IsNullOrWhiteSpace(redirectUri)
            || !Uri.TryCreate(redirectUri, UriKind.Absolute, out var uri))
        {
            return false;
        }

        return uri.Scheme == Uri.UriSchemeHttp
               && uri.UserInfo.Length == 0
               && uri.Query.Length == 0
               && uri.Fragment.Length == 0
               && !uri.IsDefaultPort
               && (string.Equals(uri.Host, "127.0.0.1", StringComparison.Ordinal)
                   || string.Equals(uri.Host, "localhost", StringComparison.OrdinalIgnoreCase))
               && client.AllowedLoopbackRedirectPaths.Contains(uri.AbsolutePath, StringComparer.Ordinal);
    }

    public static OpenIddictApplicationDescriptor CreateApplicationDescriptor(
        OAuthStaticClientOptions client,
        IEnumerable<string>? redirectUris = null)
        => OAuthPublicClientDescriptorFactory.Create(
            client.ClientId,
            client.ClientName,
            GetScopes(client),
            redirectUris ?? client.RedirectUris,
            client.PostLogoutRedirectUris);
}

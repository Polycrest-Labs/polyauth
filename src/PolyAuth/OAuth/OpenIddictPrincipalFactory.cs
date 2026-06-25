using System.Security.Claims;
using OpenIddict.Abstractions;
using PolyAuth.Firebase;

namespace PolyAuth.OAuth;

/// <summary>
/// Builds the OpenIddict <see cref="ClaimsPrincipal"/> for issued tokens: sets the subject (uid),
/// the granted scopes, the matching resource indicators, and per-claim token destinations.
/// </summary>
public static class OpenIddictPrincipalFactory
{
    public static ClaimsPrincipal FromFirebaseToken(VerifiedFirebaseToken token, IEnumerable<string> scopes)
    {
        var claims = new List<Claim>
        {
            new(OpenIddictConstants.Claims.Subject, token.Uid),
            new("uid", token.Uid),
            new(ClaimTypes.NameIdentifier, token.Uid)
        };

        AddOptionalClaim(claims, OpenIddictConstants.Claims.Email, token.Email);
        AddOptionalClaim(claims, ClaimTypes.Email, token.Email);
        AddOptionalClaim(claims, OpenIddictConstants.Claims.Name, token.Name);
        AddOptionalClaim(claims, ClaimTypes.Name, token.Name);

        return CreatePrincipal(claims, scopes);
    }

    public static ClaimsPrincipal FromOAuthSession(
        ClaimsPrincipal source,
        IEnumerable<string> scopes,
        IEnumerable<string>? requestedResources = null)
    {
        var uid = source.FindFirstValue("uid")
                  ?? source.FindFirstValue(OpenIddictConstants.Claims.Subject)
                  ?? source.FindFirstValue(ClaimTypes.NameIdentifier)
                  ?? throw new InvalidOperationException("The OAuth session is missing the required user identifier claim.");

        var claims = new List<Claim>
        {
            new(OpenIddictConstants.Claims.Subject, uid),
            new("uid", uid),
            new(ClaimTypes.NameIdentifier, uid)
        };

        AddOptionalClaim(claims, OpenIddictConstants.Claims.Email, GetFirstClaimValue(source, ClaimTypes.Email, "email"));
        AddOptionalClaim(claims, ClaimTypes.Email, GetFirstClaimValue(source, ClaimTypes.Email, "email"));
        AddOptionalClaim(claims, OpenIddictConstants.Claims.Name, GetFirstClaimValue(source, ClaimTypes.Name, "name"));
        AddOptionalClaim(claims, ClaimTypes.Name, GetFirstClaimValue(source, ClaimTypes.Name, "name"));

        return CreatePrincipal(claims, scopes, requestedResources);
    }

    /// <summary>Creates a principal with a single subject claim (used by the client-credentials grant).</summary>
    public static ClaimsPrincipal ForClient(string subject, IEnumerable<string> scopes, string? displayName = null)
    {
        var claims = new List<Claim> { new(OpenIddictConstants.Claims.Subject, subject) };
        AddOptionalClaim(claims, OpenIddictConstants.Claims.Name, displayName);
        return CreatePrincipal(claims, scopes);
    }

    public static string[] GetResourcesForScopes(IEnumerable<string> scopes)
    {
        var values = scopes.ToHashSet(StringComparer.Ordinal);
        var resources = new List<string>();

        if (values.Contains(AuthScopes.ApiRead) || values.Contains(AuthScopes.ApiWrite))
        {
            resources.Add(PolyAuthConstants.ApiResource);
        }

        if (values.Contains(AuthScopes.McpRead) || values.Contains(AuthScopes.McpWrite))
        {
            resources.Add(PolyAuthConstants.McpResource);
        }

        return resources.ToArray();
    }

    private static ClaimsPrincipal CreatePrincipal(
        IEnumerable<Claim> claims,
        IEnumerable<string> scopes,
        IEnumerable<string>? requestedResources = null)
    {
        var identity = new ClaimsIdentity(
            OpenIddictConstants.Schemes.Bearer,
            OpenIddictConstants.Claims.Name,
            OpenIddictConstants.Claims.Role);

        identity.AddClaims(claims);

        var principal = new ClaimsPrincipal(identity);
        var scopeArray = scopes.Distinct(StringComparer.Ordinal).ToArray();
        principal.SetScopes(scopeArray);
        principal.SetResources(GetResourcesForScopes(scopeArray)
            .Concat(requestedResources ?? [])
            .Distinct(StringComparer.Ordinal)
            .ToArray());

        ApplyDestinations(principal);
        return principal;
    }

    /// <summary>(Re)applies the standard claim destinations — call after an enricher adds claims.</summary>
    public static void ApplyDestinations(ClaimsPrincipal principal)
    {
        foreach (var claim in principal.Claims)
        {
            claim.SetDestinations(GetDestinations(claim));
        }
    }

    private static void AddOptionalClaim(List<Claim> claims, string type, string? value)
    {
        if (!string.IsNullOrWhiteSpace(value)
            && claims.All(claim => claim.Type != type || claim.Value != value))
        {
            claims.Add(new Claim(type, value));
        }
    }

    private static string? GetFirstClaimValue(ClaimsPrincipal principal, params string[] types)
        => types.Select(principal.FindFirstValue).FirstOrDefault(value => !string.IsNullOrWhiteSpace(value));

    private static IEnumerable<string> GetDestinations(Claim claim)
    {
        return claim.Type switch
        {
            OpenIddictConstants.Claims.Subject or "uid" or ClaimTypes.NameIdentifier
                => [OpenIddictConstants.Destinations.AccessToken, OpenIddictConstants.Destinations.IdentityToken],
            OpenIddictConstants.Claims.Email or ClaimTypes.Email
                => [OpenIddictConstants.Destinations.AccessToken, OpenIddictConstants.Destinations.IdentityToken],
            OpenIddictConstants.Claims.Name or ClaimTypes.Name
                => [OpenIddictConstants.Destinations.AccessToken, OpenIddictConstants.Destinations.IdentityToken],
            _ => [OpenIddictConstants.Destinations.AccessToken]
        };
    }
}

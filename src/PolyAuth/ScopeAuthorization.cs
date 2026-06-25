using System.Security.Claims;
using OpenIddict.Abstractions;

namespace PolyAuth;

/// <summary>
/// Scope checks that understand both the OpenIddict private scope claims and the
/// space-delimited <c>scope</c> claim. <c>write</c> scopes are treated as a superset of
/// the matching <c>read</c> scope by the policies that combine them.
/// </summary>
public static class ScopeAuthorization
{
    public static bool HasScope(ClaimsPrincipal user, string scope)
    {
        return user.FindAll(OpenIddictConstants.Claims.Private.Scope).Any(claim => claim.Value == scope)
               || user.FindAll("scope")
                   .SelectMany(claim => claim.Value.Split(' ', StringSplitOptions.RemoveEmptyEntries))
                   .Contains(scope, StringComparer.Ordinal);
    }

    public static bool HasAnyScope(ClaimsPrincipal user, params string[] scopes)
    {
        return scopes.Any(scope => HasScope(user, scope));
    }
}

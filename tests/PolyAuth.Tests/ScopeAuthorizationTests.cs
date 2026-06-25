using System.Security.Claims;
using OpenIddict.Abstractions;
using Xunit;

namespace PolyAuth.Tests;

public sealed class ScopeAuthorizationTests
{
    private static ClaimsPrincipal WithPrivateScopes(params string[] scopes)
    {
        var identity = new ClaimsIdentity("test");
        foreach (var scope in scopes)
        {
            identity.AddClaim(new Claim(OpenIddictConstants.Claims.Private.Scope, scope));
        }

        return new ClaimsPrincipal(identity);
    }

    private static ClaimsPrincipal WithSpaceDelimitedScope(string scope)
        => new(new ClaimsIdentity([new Claim("scope", scope)], "test"));

    [Fact]
    public void HasScope_finds_openiddict_private_scope_claim()
    {
        var user = WithPrivateScopes(AuthScopes.ApiRead, AuthScopes.McpRead);
        Assert.True(ScopeAuthorization.HasScope(user, AuthScopes.ApiRead));
        Assert.False(ScopeAuthorization.HasScope(user, AuthScopes.ApiWrite));
    }

    [Fact]
    public void HasScope_finds_space_delimited_scope_claim()
    {
        var user = WithSpaceDelimitedScope("api.read mcp.read mcp.write");
        Assert.True(ScopeAuthorization.HasScope(user, AuthScopes.McpWrite));
        Assert.False(ScopeAuthorization.HasScope(user, AuthScopes.ApiWrite));
    }

    [Fact]
    public void HasAnyScope_is_true_when_any_match()
    {
        var user = WithPrivateScopes(AuthScopes.ApiWrite);
        // The ApiRead policy accepts api.read OR api.write (write is a superset of read).
        Assert.True(ScopeAuthorization.HasAnyScope(user, AuthScopes.ApiRead, AuthScopes.ApiWrite));
    }

    [Fact]
    public void HasAnyScope_is_false_when_none_match()
    {
        var user = WithPrivateScopes(AuthScopes.McpRead);
        Assert.False(ScopeAuthorization.HasAnyScope(user, AuthScopes.ApiRead, AuthScopes.ApiWrite));
    }
}

using OpenIddict.Abstractions;
using PolyAuth.Firebase;
using PolyAuth.OAuth;
using Xunit;

namespace PolyAuth.Tests;

public sealed class OpenIddictPrincipalFactoryTests
{
    [Fact]
    public void FromFirebaseToken_sets_subject_scopes_and_resources()
    {
        var token = new VerifiedFirebaseToken("uid-123", "user@example.com", "Test User");
        var principal = OpenIddictPrincipalFactory.FromFirebaseToken(
            token, [AuthScopes.ApiRead, AuthScopes.ApiWrite]);

        Assert.Equal("uid-123", principal.GetClaim(OpenIddictConstants.Claims.Subject));
        Assert.Equal("uid-123", principal.GetClaim("uid"));
        Assert.Contains(AuthScopes.ApiRead, principal.GetScopes());
        Assert.Contains(PolyAuthConstants.ApiResource, principal.GetResources());
        Assert.DoesNotContain(PolyAuthConstants.McpResource, principal.GetResources());
    }

    [Fact]
    public void Mcp_scopes_map_to_mcp_resource()
    {
        var token = new VerifiedFirebaseToken("uid-9", null, null);
        var principal = OpenIddictPrincipalFactory.FromFirebaseToken(token, [AuthScopes.McpRead]);

        Assert.Contains(PolyAuthConstants.McpResource, principal.GetResources());
        Assert.DoesNotContain(PolyAuthConstants.ApiResource, principal.GetResources());
    }

    [Fact]
    public void Subject_claim_is_destined_for_access_and_identity_tokens()
    {
        var token = new VerifiedFirebaseToken("uid-7", "a@b.com", null);
        var principal = OpenIddictPrincipalFactory.FromFirebaseToken(token, [AuthScopes.ApiRead]);

        var subject = principal.Claims.First(c => c.Type == OpenIddictConstants.Claims.Subject);
        var destinations = subject.GetDestinations();
        Assert.Contains(OpenIddictConstants.Destinations.AccessToken, destinations);
        Assert.Contains(OpenIddictConstants.Destinations.IdentityToken, destinations);
    }

    [Fact]
    public void ForClient_uses_clientId_as_subject()
    {
        var principal = OpenIddictPrincipalFactory.ForClient("my-client", [AuthScopes.ApiRead], "My Client");
        Assert.Equal("my-client", principal.GetClaim(OpenIddictConstants.Claims.Subject));
    }
}

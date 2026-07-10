using OpenIddict.Abstractions;
using PolyAuth.OAuth;
using Xunit;

namespace PolyAuth.Tests;

public sealed class OAuthClientMetadataRulesTests
{
    private const string ClientId = "https://claude.ai/oauth/mcp-oauth-client-metadata";
    private const string RedirectUri = "https://claude.ai/api/mcp/auth_callback";

    [Fact]
    public void Validate_AllowsAdditionalAdvertisedGrantTypes()
    {
        var document = ClaudeMetadata();

        var error = OAuthClientMetadataRules.Validate(
            document,
            ClientId,
            RedirectUri,
            new HashSet<string>([AuthScopes.McpRead, AuthScopes.McpWrite], StringComparer.Ordinal));

        Assert.Null(error);
    }

    [Fact]
    public void CreateApplicationDescriptor_DoesNotGrantAdditionalAdvertisedGrantTypes()
    {
        var document = ClaudeMetadata();

        var descriptor = OAuthClientMetadataRules.CreateApplicationDescriptor(
            document,
            new HashSet<string>([AuthScopes.McpRead, AuthScopes.McpWrite], StringComparer.Ordinal));

        Assert.Contains(OpenIddictConstants.Permissions.GrantTypes.AuthorizationCode, descriptor.Permissions);
        Assert.Contains(OpenIddictConstants.Permissions.GrantTypes.RefreshToken, descriptor.Permissions);
        Assert.DoesNotContain(
            OpenIddictConstants.Permissions.Prefixes.GrantType + "urn:ietf:params:oauth:grant-type:jwt-bearer",
            descriptor.Permissions);
    }

    [Fact]
    public void Validate_RejectsMetadataWithoutAuthorizationCode()
    {
        var document = ClaudeMetadata();
        document.GrantTypes.Clear();
        document.GrantTypes.Add(OpenIddictConstants.GrantTypes.RefreshToken);

        var error = OAuthClientMetadataRules.Validate(
            document,
            ClientId,
            RedirectUri,
            new HashSet<string>([AuthScopes.McpRead], StringComparer.Ordinal));

        Assert.Equal("The authorization_code grant type is required.", error);
    }

    private static OAuthClientMetadataDocument ClaudeMetadata() => new()
    {
        ClientId = ClientId,
        ClientName = "Claude",
        RedirectUris = [RedirectUri],
        GrantTypes =
        [
            OpenIddictConstants.GrantTypes.AuthorizationCode,
            OpenIddictConstants.GrantTypes.RefreshToken,
            "urn:ietf:params:oauth:grant-type:jwt-bearer"
        ],
        ResponseTypes = [OpenIddictConstants.ResponseTypes.Code],
        TokenEndpointAuthMethod = OpenIddictConstants.ClientAuthenticationMethods.None
    };
}

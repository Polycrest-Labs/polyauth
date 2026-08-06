using System.Net;
using System.Text.Json;
using Xunit;

namespace PolyAuth.IntegrationTests;

public sealed class DiscoveryTests : IClassFixture<PolyAuthWebFactory>
{
    private readonly PolyAuthWebFactory _factory;

    public DiscoveryTests(PolyAuthWebFactory factory) => _factory = factory;

    [Fact]
    public async Task Authorization_server_metadata_is_served()
    {
        var client = _factory.CreateClient();
        var response = await client.GetAsync("/.well-known/oauth-authorization-server");
        response.EnsureSuccessStatusCode();

        using var doc = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        Assert.True(doc.RootElement.TryGetProperty("token_endpoint", out _));
        Assert.True(doc.RootElement.TryGetProperty("client_id_metadata_document_supported", out var cimd));
        Assert.True(cimd.GetBoolean());
    }

    [Fact]
    public async Task Mcp_discovery_alias_is_rewritten()
    {
        var client = _factory.CreateClient();
        var response = await client.GetAsync("/.well-known/oauth-authorization-server/mcp");
        response.EnsureSuccessStatusCode();
        using var doc = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        Assert.True(doc.RootElement.TryGetProperty("token_endpoint", out _));
    }

    [Fact]
    public async Task Protected_resource_metadata_for_mcp_is_served()
    {
        var client = _factory.CreateClient();
        var response = await client.GetAsync("/.well-known/oauth-protected-resource/mcp");
        response.EnsureSuccessStatusCode();

        using var doc = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        var scopes = doc.RootElement.GetProperty("scopes_supported").EnumerateArray().Select(e => e.GetString()).ToArray();
        Assert.Contains(AuthScopes.McpRead, scopes);
    }

    [Fact]
    public async Task Mcp_without_token_is_unauthorized_and_advertises_resource_metadata()
    {
        var client = _factory.CreateClient();
        using var content = new StringContent(
            "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/list\",\"params\":{}}",
            System.Text.Encoding.UTF8,
            "application/json");
        var response = await client.PostAsync("/mcp", content);
        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        Assert.True(response.Headers.Contains("WWW-Authenticate"));
        Assert.Contains("resource_metadata", string.Join(" ", response.Headers.GetValues("WWW-Authenticate")));
    }

    [Fact]
    public async Task Mcp_get_does_not_fall_through_to_spa()
    {
        var response = await _factory.CreateClient().GetAsync("/mcp");
        Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
    }
}

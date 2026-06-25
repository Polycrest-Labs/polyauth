using System.Net.Http.Headers;
using System.Text.Json;
using Xunit;

namespace PolyAuth.IntegrationTests;

public sealed class McpEndpointTests : IClassFixture<PolyAuthWebFactory>
{
    private readonly PolyAuthWebFactory _factory;

    public McpEndpointTests(PolyAuthWebFactory factory) => _factory = factory;

    private async Task<string> GetMcpTokenAsync(HttpClient client, string scope)
    {
        await _factory.EnsureClientCredentialsClientAsync();

        var response = await client.PostAsync("/connect/token", new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["grant_type"] = "client_credentials",
            ["client_id"] = PolyAuthWebFactory.ClientCredentialsClientId,
            ["client_secret"] = PolyAuthWebFactory.ClientCredentialsSecret,
            ["scope"] = scope
        }));

        var body = await response.Content.ReadAsStringAsync();
        Assert.True(response.IsSuccessStatusCode, $"client_credentials token failed: {(int)response.StatusCode}: {body}");
        using var doc = JsonDocument.Parse(body);
        return doc.RootElement.GetProperty("access_token").GetString()!;
    }

    [Fact]
    public async Task Mcp_initialize_and_tools_list_with_valid_token()
    {
        var httpClient = _factory.CreateClient();
        var token = await GetMcpTokenAsync(httpClient, "mcp.read mcp.write");
        httpClient.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);

        var mcp = new McpStreamableHttpClient(httpClient, new Uri(httpClient.BaseAddress!, "mcp"));

        var initResult = await mcp.InitializeAsync();
        Assert.True(initResult.TryGetProperty("result", out var result), "initialize should return a result");
        Assert.True(result.TryGetProperty("serverInfo", out _) || result.TryGetProperty("protocolVersion", out _));

        var tools = await mcp.ListToolNamesAsync();
        Assert.Contains("ping", tools);
        Assert.Contains("list_items", tools);
    }

    [Fact]
    public async Task List_items_advertises_output_schema_and_returns_structured_items()
    {
        var httpClient = _factory.CreateClient();
        var token = await GetMcpTokenAsync(httpClient, "mcp.read mcp.write");
        httpClient.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);

        var mcp = new McpStreamableHttpClient(httpClient, new Uri(httpClient.BaseAddress!, "mcp"));
        await mcp.InitializeAsync();

        // tools/list: list_items must advertise an outputSchema (UseStructuredContent = true).
        var toolsResult = await mcp.ListToolsAsync();
        var listItems = toolsResult.GetProperty("result").GetProperty("tools").EnumerateArray()
            .First(t => t.GetProperty("name").GetString() == "list_items");
        Assert.True(listItems.TryGetProperty("outputSchema", out _), "list_items should advertise an outputSchema");

        // tools/call: the result must carry structuredContent shaped as { items: [...] } for the widget.
        var call = await mcp.CallToolAsync("list_items");
        var result = call.GetProperty("result");
        Assert.True(result.TryGetProperty("structuredContent", out var structured), "tools/call should return structuredContent");
        Assert.Equal(JsonValueKind.Array, structured.GetProperty("items").ValueKind);
    }

    [Fact]
    public async Task Mcp_without_mcp_scope_is_forbidden()
    {
        // A token with only api.read does not satisfy the mcp.read policy on /mcp.
        var httpClient = _factory.CreateClient();
        var token = await GetMcpTokenAsync(httpClient, "api.read");
        httpClient.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);

        var response = await httpClient.PostAsync("/mcp",
            new StringContent("{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"initialize\",\"params\":{}}",
                System.Text.Encoding.UTF8, "application/json"));

        Assert.Equal(System.Net.HttpStatusCode.Forbidden, response.StatusCode);
    }
}

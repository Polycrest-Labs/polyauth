using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;
using Xunit;

namespace PolyAuth.IntegrationTests;

public sealed class OAuthFlowTests : IClassFixture<PolyAuthWebFactory>
{
    private readonly PolyAuthWebFactory _factory;

    public OAuthFlowTests(PolyAuthWebFactory factory) => _factory = factory;

    private async Task<string> ExchangeFirebaseTokenAsync(HttpClient client, string scope)
    {
        var response = await client.PostAsync("/connect/token", new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["grant_type"] = PolyAuthConstants.FirebaseTokenExchangeGrantType,
            ["client_id"] = "polyauth-ui",
            ["firebase_id_token"] = "stub-id-token",
            ["scope"] = scope
        }));

        var body = await response.Content.ReadAsStringAsync();
        Assert.True(response.StatusCode == HttpStatusCode.OK, $"Token endpoint returned {(int)response.StatusCode}: {body}");

        using var doc = JsonDocument.Parse(body);
        return doc.RootElement.GetProperty("access_token").GetString()!;
    }

    [Fact]
    public async Task Token_exchange_issues_a_usable_access_token()
    {
        var client = _factory.CreateClient();
        var token = await ExchangeFirebaseTokenAsync(client, "openid api.read api.write");

        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);
        var items = await client.GetAsync("/api/items");
        Assert.Equal(HttpStatusCode.OK, items.StatusCode);
    }

    [Fact]
    public async Task Token_exchange_requires_a_firebase_token()
    {
        var client = _factory.CreateClient();
        var response = await client.PostAsync("/connect/token", new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["grant_type"] = PolyAuthConstants.FirebaseTokenExchangeGrantType,
            ["client_id"] = "polyauth-ui",
            ["firebase_id_token"] = "",
            ["scope"] = "openid api.read"
        }));
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
    }

    [Fact]
    public async Task Token_exchange_rejects_non_first_party_client()
    {
        var client = _factory.CreateClient();
        var response = await client.PostAsync("/connect/token", new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["grant_type"] = PolyAuthConstants.FirebaseTokenExchangeGrantType,
            ["client_id"] = "some-other-client",
            ["firebase_id_token"] = "stub-id-token",
            ["scope"] = "openid api.read"
        }));
        // The Firebase grant is restricted to the first-party UI client, and an unknown client also
        // fails OpenIddict client validation — either way it must not succeed.
        Assert.True(
            response.StatusCode is HttpStatusCode.BadRequest or HttpStatusCode.Unauthorized,
            $"Expected 400/401 but got {(int)response.StatusCode}");
    }

    [Fact]
    public async Task Api_read_token_cannot_write()
    {
        var client = _factory.CreateClient();
        var token = await ExchangeFirebaseTokenAsync(client, "openid api.read");
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);

        var read = await client.GetAsync("/api/items");
        Assert.Equal(HttpStatusCode.OK, read.StatusCode);

        var write = await client.PostAsJsonAsync("/api/items", new { title = "should fail" });
        Assert.Equal(HttpStatusCode.Forbidden, write.StatusCode);
    }

    [Fact]
    public async Task Api_write_token_can_create_and_read_items()
    {
        var client = _factory.CreateClient();
        var token = await ExchangeFirebaseTokenAsync(client, "openid api.read api.write");
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);

        var write = await client.PostAsJsonAsync("/api/items", new { title = "hello" });
        Assert.Equal(HttpStatusCode.OK, write.StatusCode);

        var read = await client.GetFromJsonAsync<JsonElement>("/api/items");
        Assert.Equal(JsonValueKind.Array, read.ValueKind);
        Assert.True(read.GetArrayLength() >= 1);
    }

    [Fact]
    public async Task Unauthenticated_api_call_is_rejected()
    {
        var client = _factory.CreateClient();
        var response = await client.GetAsync("/api/items");
        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }
}

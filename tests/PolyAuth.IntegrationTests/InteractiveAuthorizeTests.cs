using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.Mvc.Testing;
using Xunit;

namespace PolyAuth.IntegrationTests;

/// <summary>
/// Exercises the library-owned interactive endpoints (CR-1): the Firebase→session bridge, the
/// /connect/authorize consent + sign-in, and the authorization_code + PKCE token exchange — proving
/// that MapPolyAuthEndpoints' minimal-API Results.SignIn triggers OpenIddict's passthrough.
/// The in-memory server is HTTP, so the Secure __Host- session cookie is captured and re-attached manually.
/// </summary>
public sealed class InteractiveAuthorizeTests : IClassFixture<PolyAuthWebFactory>
{
    private readonly PolyAuthWebFactory _factory;

    public InteractiveAuthorizeTests(PolyAuthWebFactory factory) => _factory = factory;

    private HttpClient NoRedirectClient()
        => _factory.CreateClient(new WebApplicationFactoryClientOptions { AllowAutoRedirect = false });

    private static string B64Url(byte[] b) => Convert.ToBase64String(b).TrimEnd('=').Replace('+', '-').Replace('/', '_');

    [Fact]
    public async Task Unauthenticated_authorize_redirects_to_sign_in_with_return_url()
    {
        var client = NoRedirectClient();
        var response = await client.GetAsync(
            "/connect/authorize?response_type=code&client_id=claude-desktop&redirect_uri=http%3A%2F%2F127.0.0.1%3A8765%2Fcallback&scope=openid&code_challenge=abc&code_challenge_method=S256&state=s");

        Assert.Equal(HttpStatusCode.Redirect, response.StatusCode);
        var location = response.Headers.Location!.ToString();
        Assert.StartsWith("/sign-in", location);
        Assert.Contains("returnUrl=", location);
    }

    [Fact]
    public async Task Session_endpoint_requires_firebase_auth()
    {
        var client = NoRedirectClient();
        var response = await client.PostAsJsonAsync("/api/oauth/session", new { returnUrl = "/" });
        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [Fact]
    public async Task Full_authorization_code_pkce_flow_via_library_endpoints()
    {
        var client = NoRedirectClient();

        // 1) Establish the OAuthSession cookie from a (stubbed) Firebase login.
        var sessionReq = new HttpRequestMessage(HttpMethod.Post, "/api/oauth/session")
        {
            Content = JsonContent.Create(new { returnUrl = "/" })
        };
        sessionReq.Headers.Authorization = new AuthenticationHeaderValue("Bearer", "stub-firebase-id-token");
        var sessionResp = await client.SendAsync(sessionReq);
        Assert.Equal(HttpStatusCode.OK, sessionResp.StatusCode);

        var setCookie = sessionResp.Headers.GetValues("Set-Cookie").First(c => c.StartsWith("__Host-polyauth-oauth", StringComparison.Ordinal));
        var cookie = setCookie.Split(';')[0]; // name=value

        // 2) PKCE authorize for the third-party loopback client → consent page.
        var verifier = B64Url(RandomNumberGenerator.GetBytes(32));
        var challenge = B64Url(SHA256.HashData(Encoding.ASCII.GetBytes(verifier)));
        const string redirectUri = "http://127.0.0.1:8765/callback";
        var query = $"response_type=code&client_id=claude-desktop&redirect_uri={Uri.EscapeDataString(redirectUri)}" +
                    $"&scope={Uri.EscapeDataString("openid offline_access mcp.read mcp.write")}" +
                    $"&code_challenge={challenge}&code_challenge_method=S256&state=s1";

        var consentReq = new HttpRequestMessage(HttpMethod.Get, $"/connect/authorize?{query}");
        consentReq.Headers.Add("Cookie", cookie);
        var consentResp = await client.SendAsync(consentReq);
        Assert.Equal(HttpStatusCode.OK, consentResp.StatusCode);
        Assert.Contains("Authorize", await consentResp.Content.ReadAsStringAsync());

        // 3) Approve consent → 302 to the loopback redirect with a code.
        var approveFields = new Dictionary<string, string>
        {
            ["response_type"] = "code",
            ["client_id"] = "claude-desktop",
            ["redirect_uri"] = redirectUri,
            ["scope"] = "openid offline_access mcp.read mcp.write",
            ["code_challenge"] = challenge,
            ["code_challenge_method"] = "S256",
            ["state"] = "s1",
            ["consent_action"] = "approve"
        };
        var approveReq = new HttpRequestMessage(HttpMethod.Post, "/connect/authorize")
        {
            Content = new FormUrlEncodedContent(approveFields)
        };
        approveReq.Headers.Add("Cookie", cookie);
        var approveResp = await client.SendAsync(approveReq);
        Assert.Equal(HttpStatusCode.Redirect, approveResp.StatusCode);
        var location = approveResp.Headers.Location!.ToString();
        Assert.StartsWith(redirectUri, location);
        var code = new Uri(location).Query.TrimStart('?').Split('&')
            .FirstOrDefault(p => p.StartsWith("code=", StringComparison.Ordinal))?["code=".Length..];
        code = code is null ? null : Uri.UnescapeDataString(code);
        Assert.False(string.IsNullOrEmpty(code));

        // 4) Exchange the code (PKCE) for tokens.
        var tokenResp = await client.PostAsync("/connect/token", new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["grant_type"] = "authorization_code",
            ["client_id"] = "claude-desktop",
            ["code"] = code!,
            ["redirect_uri"] = redirectUri,
            ["code_verifier"] = verifier
        }));

        var tokenBody = await tokenResp.Content.ReadAsStringAsync();
        Assert.True(tokenResp.StatusCode == HttpStatusCode.OK, $"token exchange failed: {(int)tokenResp.StatusCode}: {tokenBody}");
        using var doc = JsonDocument.Parse(tokenBody);
        Assert.False(string.IsNullOrEmpty(doc.RootElement.GetProperty("access_token").GetString()));
    }

    [Fact]
    public async Task Logout_returns_sign_out_redirect()
    {
        var client = NoRedirectClient();
        var response = await client.GetAsync("/connect/logout");
        // OpenIddict end-session passthrough produces a redirect (to "/").
        Assert.True(response.StatusCode is HttpStatusCode.Redirect or HttpStatusCode.OK or HttpStatusCode.Found);
    }
}

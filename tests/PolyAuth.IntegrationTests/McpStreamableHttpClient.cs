using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;

namespace PolyAuth.IntegrationTests;

/// <summary>
/// A minimal scripted MCP client over the Streamable HTTP transport: initialize, notifications/initialized,
/// then tools/list. Parses either a JSON or a text/event-stream response. Used to verify the /mcp endpoint
/// without taking a dependency on the MCP client SDK.
/// </summary>
public sealed class McpStreamableHttpClient
{
    private readonly HttpClient _http;
    private readonly Uri _endpoint;
    private string? _sessionId;

    public McpStreamableHttpClient(HttpClient http, Uri endpoint)
    {
        _http = http;
        _endpoint = endpoint;
    }

    public async Task<JsonElement> InitializeAsync(CancellationToken ct = default)
    {
        var result = await SendAsync(new
        {
            jsonrpc = "2.0",
            id = 1,
            method = "initialize",
            @params = new
            {
                protocolVersion = "2025-06-18",
                capabilities = new { },
                clientInfo = new { name = "polyauth-itests", version = "1.0.0" }
            }
        }, captureSession: true, ct);

        await SendNotificationAsync(new { jsonrpc = "2.0", method = "notifications/initialized" }, ct);
        return result;
    }

    public async Task<IReadOnlyList<string>> ListToolNamesAsync(CancellationToken ct = default)
    {
        var result = await SendAsync(new { jsonrpc = "2.0", id = 2, method = "tools/list", @params = new { } }, captureSession: false, ct);
        var names = new List<string>();
        if (result.TryGetProperty("result", out var r) && r.TryGetProperty("tools", out var tools))
        {
            foreach (var tool in tools.EnumerateArray())
            {
                if (tool.TryGetProperty("name", out var name))
                {
                    names.Add(name.GetString()!);
                }
            }
        }

        return names;
    }

    private async Task<JsonElement> SendAsync(object payload, bool captureSession, CancellationToken ct)
    {
        using var request = BuildRequest(payload);
        using var response = await _http.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, ct);
        response.EnsureSuccessStatusCode();

        if (captureSession && response.Headers.TryGetValues("Mcp-Session-Id", out var sid))
        {
            _sessionId = sid.FirstOrDefault();
        }

        var body = await response.Content.ReadAsStringAsync(ct);
        var json = ExtractJson(body);
        return JsonDocument.Parse(json).RootElement.Clone();
    }

    private async Task SendNotificationAsync(object payload, CancellationToken ct)
    {
        using var request = BuildRequest(payload);
        using var response = await _http.SendAsync(request, ct);
        // Notifications return 202 Accepted (or 200); ignore the body.
    }

    private HttpRequestMessage BuildRequest(object payload)
    {
        var request = new HttpRequestMessage(HttpMethod.Post, _endpoint)
        {
            Content = new StringContent(JsonSerializer.Serialize(payload), Encoding.UTF8, "application/json")
        };
        request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
        request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("text/event-stream"));
        if (!string.IsNullOrEmpty(_sessionId))
        {
            request.Headers.TryAddWithoutValidation("Mcp-Session-Id", _sessionId);
        }

        return request;
    }

    /// <summary>Extracts the JSON-RPC object from a JSON body or the first SSE data frame.</summary>
    private static string ExtractJson(string body)
    {
        var trimmed = body.TrimStart();
        if (trimmed.StartsWith('{') || trimmed.StartsWith('['))
        {
            return body;
        }

        var sb = new StringBuilder();
        foreach (var line in body.Split('\n'))
        {
            if (line.StartsWith("data:", StringComparison.Ordinal))
            {
                sb.Append(line["data:".Length..].Trim());
            }
        }

        return sb.Length > 0 ? sb.ToString() : body;
    }
}

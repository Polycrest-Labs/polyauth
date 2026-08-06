using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;

namespace PolyAuth.IntegrationTests;

public enum McpProtocolMode
{
    Legacy2025,
    Current2026,
}

/// <summary>
/// A minimal scripted MCP client over the Streamable HTTP transport. It exercises both the legacy
/// initialize/session flow and the stateless 2026-07-28 per-request metadata flow without taking a
/// dependency on the MCP client SDK. Responses may be JSON or text/event-stream.
/// </summary>
public sealed class McpStreamableHttpClient
{
    private const string LegacyProtocolVersion = "2025-06-18";
    private const string CurrentProtocolVersion = "2026-07-28";
    private const string ProtocolVersionMetaKey = "io.modelcontextprotocol/protocolVersion";
    private const string ClientInfoMetaKey = "io.modelcontextprotocol/clientInfo";
    private const string ClientCapabilitiesMetaKey = "io.modelcontextprotocol/clientCapabilities";

    private readonly HttpClient _http;
    private readonly Uri _endpoint;
    private readonly McpProtocolMode _protocolMode;
    private string? _sessionId;

    public McpStreamableHttpClient(
        HttpClient http,
        Uri endpoint,
        McpProtocolMode protocolMode = McpProtocolMode.Legacy2025)
    {
        _http = http;
        _endpoint = endpoint;
        _protocolMode = protocolMode;
    }

    public Task<JsonElement> ConnectAsync(CancellationToken ct = default)
        => _protocolMode == McpProtocolMode.Current2026 ? DiscoverAsync(ct) : InitializeAsync(ct);

    public async Task<JsonElement> InitializeAsync(CancellationToken ct = default)
    {
        if (_protocolMode != McpProtocolMode.Legacy2025)
        {
            throw new InvalidOperationException("The 2026-07-28 protocol uses server/discover instead of initialize.");
        }

        var result = await SendAsync(new
        {
            jsonrpc = "2.0",
            id = 1,
            method = "initialize",
            @params = new
            {
                protocolVersion = LegacyProtocolVersion,
                capabilities = new { },
                clientInfo = new { name = "polyauth-itests", version = "1.0.0" }
            }
        }, captureSession: true, method: null, targetName: null, ct);

        await SendNotificationAsync(new { jsonrpc = "2.0", method = "notifications/initialized" }, ct);
        return result;
    }

    public Task<JsonElement> DiscoverAsync(CancellationToken ct = default)
    {
        if (_protocolMode != McpProtocolMode.Current2026)
        {
            throw new InvalidOperationException("server/discover belongs to the stateless 2026-07-28 protocol flow.");
        }

        return SendRpcAsync("server/discover", new { }, id: 1, targetName: null, ct);
    }

    public async Task<IReadOnlyList<string>> ListToolNamesAsync(CancellationToken ct = default)
    {
        var result = await SendRpcAsync("tools/list", new { }, id: 2, targetName: null, ct);
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

    /// <summary>Returns the raw <c>tools/list</c> result (so tests can inspect each tool's outputSchema).</summary>
    public Task<JsonElement> ListToolsAsync(CancellationToken ct = default)
        => SendRpcAsync("tools/list", new { }, id: 3, targetName: null, ct);

    /// <summary>Calls a tool and returns the raw result (so tests can inspect structuredContent).</summary>
    public Task<JsonElement> CallToolAsync(string name, object? arguments = null, CancellationToken ct = default)
        => SendRpcAsync("tools/call", new { name, arguments = arguments ?? new { } }, id: 4, targetName: name, ct);

    private Task<JsonElement> SendRpcAsync(
        string method,
        object parameters,
        int id,
        string? targetName,
        CancellationToken ct)
    {
        if (_protocolMode == McpProtocolMode.Legacy2025)
        {
            return SendAsync(
                new { jsonrpc = "2.0", id, method, @params = parameters },
                captureSession: false,
                method: null,
                targetName: null,
                ct);
        }

        var requestParams = JsonSerializer.SerializeToNode(parameters)?.AsObject() ?? new JsonObject();
        requestParams["_meta"] = new JsonObject
        {
            [ProtocolVersionMetaKey] = CurrentProtocolVersion,
            [ClientInfoMetaKey] = JsonSerializer.SerializeToNode(new { name = "polyauth-itests", version = "1.0.0" }),
            [ClientCapabilitiesMetaKey] = new JsonObject(),
        };

        var payload = new JsonObject
        {
            ["jsonrpc"] = "2.0",
            ["id"] = id,
            ["method"] = method,
            ["params"] = requestParams,
        };

        return SendAsync(payload, captureSession: false, method, targetName, ct);
    }

    private async Task<JsonElement> SendAsync(
        object payload,
        bool captureSession,
        string? method,
        string? targetName,
        CancellationToken ct)
    {
        using var request = BuildRequest(payload, method, targetName);
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
        using var request = BuildRequest(payload, method: null, targetName: null);
        using var response = await _http.SendAsync(request, ct);
        // Notifications return 202 Accepted (or 200); ignore the body.
    }

    private HttpRequestMessage BuildRequest(object payload, string? method, string? targetName)
    {
        var request = new HttpRequestMessage(HttpMethod.Post, _endpoint)
        {
            Content = new StringContent(JsonSerializer.Serialize(payload), Encoding.UTF8, "application/json")
        };
        request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
        request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("text/event-stream"));

        if (_protocolMode == McpProtocolMode.Current2026)
        {
            request.Headers.TryAddWithoutValidation("MCP-Protocol-Version", CurrentProtocolVersion);
            request.Headers.TryAddWithoutValidation("Mcp-Method", method);
            if (targetName is not null)
            {
                request.Headers.TryAddWithoutValidation("Mcp-Name", targetName);
            }
        }

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

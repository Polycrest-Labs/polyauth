namespace PolyAuth.OAuth;

/// <summary>
/// Builds OAuth resource indicators for the API and MCP surfaces from the configured
/// public base URLs. The internal indicators (<see cref="PolyAuthConstants.ApiResource"/>
/// and <see cref="PolyAuthConstants.McpResource"/>) are always present; the public
/// HTTPS indicators are added when an issuer / MCP base URL is configured.
/// </summary>
public static class OAuthResourceIndicators
{
    public static string[] GetApiResources(OAuthServerOptions oauth)
        => BuildResources(PolyAuthConstants.ApiResource, oauth.Issuer, "/api");

    public static string[] GetMcpResources(OAuthServerOptions oauth, McpAuthOptions mcp)
    {
        var publicBaseUrl = string.IsNullOrWhiteSpace(mcp.McpBaseUrl) ? oauth.Issuer : mcp.McpBaseUrl;
        return BuildResources(PolyAuthConstants.McpResource, publicBaseUrl, "/mcp");
    }

    public static string[] GetPublicResourceIndicators(OAuthServerOptions oauth, McpAuthOptions mcp)
    {
        var resources = new List<string>();
        AddPublicResource(resources, oauth.Issuer, "/api", "PolyAuth:OAuth:Issuer");

        var mcpBaseUrl = string.IsNullOrWhiteSpace(mcp.McpBaseUrl) ? oauth.Issuer : mcp.McpBaseUrl;
        AddPublicResource(resources, mcpBaseUrl, "/mcp",
            string.IsNullOrWhiteSpace(mcp.McpBaseUrl) ? "PolyAuth:OAuth:Issuer" : "PolyAuth:Mcp:McpBaseUrl");

        return resources.Distinct(StringComparer.Ordinal).ToArray();
    }

    private static string[] BuildResources(string internalResource, string? publicBaseUrl, string path)
    {
        var resources = new List<string> { internalResource };
        if (!string.IsNullOrWhiteSpace(publicBaseUrl))
        {
            resources.Add($"{publicBaseUrl.TrimEnd('/')}{path}");
        }

        return resources.Distinct(StringComparer.Ordinal).ToArray();
    }

    private static void AddPublicResource(List<string> resources, string? publicBaseUrl, string path, string configurationKey)
    {
        if (string.IsNullOrWhiteSpace(publicBaseUrl))
        {
            return;
        }

        var resource = $"{publicBaseUrl.TrimEnd('/')}{path}";
        if (!Uri.TryCreate(resource, UriKind.Absolute, out var uri)
            || (uri.Scheme != Uri.UriSchemeHttps && uri.Scheme != Uri.UriSchemeHttp))
        {
            throw new InvalidOperationException(
                $"{configurationKey} must be an absolute HTTP(S) base URL to register OAuth resource indicators. "
                + $"The computed resource indicator '{resource}' is invalid.");
        }

        resources.Add(resource);
    }
}

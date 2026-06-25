using System.Text.Json;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using PolyAuth.OAuth;

namespace PolyAuth;

/// <summary>The consumer middleware entry point: <c>UsePolyAuth</c>.</summary>
public static class PolyAuthApplicationBuilderExtensions
{
    /// <summary>
    /// Wires, in the correct order: OAuth discovery aliases, the protected-resource metadata endpoints,
    /// the MCP resource-metadata challenge, then <c>UseAuthentication</c> + <c>UseAuthorization</c>.
    /// No-op for disabled providers.
    /// </summary>
    public static IApplicationBuilder UsePolyAuth(this IApplicationBuilder app)
    {
        var options = app.ApplicationServices.GetRequiredService<IOptions<PolyAuthOptions>>().Value;

        if (options.OAuth.Enabled)
        {
            UseOAuthDiscoveryAliases(app);
            UseProtectedResourceMetadata(app, options);
        }

        if (options.Mcp.Enabled)
        {
            UseMcpResourceMetadataChallenge(app);
        }

        if (options.Firebase.Enabled || options.OAuth.Enabled)
        {
            app.UseAuthentication();
            app.UseAuthorization();
        }

        return app;
    }

    private static void UseOAuthDiscoveryAliases(IApplicationBuilder app)
    {
        app.Use(async (context, next) =>
        {
            if (context.Request.Path.Equals("/.well-known/oauth-authorization-server/mcp", StringComparison.OrdinalIgnoreCase))
            {
                context.Request.Path = "/.well-known/oauth-authorization-server";
            }
            else if (context.Request.Path.Equals("/.well-known/openid-configuration/mcp", StringComparison.OrdinalIgnoreCase))
            {
                context.Request.Path = "/.well-known/openid-configuration";
            }

            await next();
        });
    }

    private static void UseMcpResourceMetadataChallenge(IApplicationBuilder app)
    {
        app.Use(async (context, next) =>
        {
            await next();

            if (!context.Response.HasStarted
                && context.Response.StatusCode == StatusCodes.Status401Unauthorized
                && context.Request.Path.StartsWithSegments("/mcp", StringComparison.OrdinalIgnoreCase))
            {
                var resourceMetadata = $"{context.Request.Scheme}://{context.Request.Host}/.well-known/oauth-protected-resource/mcp";
                context.Response.Headers.WWWAuthenticate = $"Bearer resource_metadata=\"{resourceMetadata}\"";
            }
        });
    }

    /// <summary>Serves RFC 9728 protected-resource metadata for /api and /mcp without requiring the app to add a controller.</summary>
    private static void UseProtectedResourceMetadata(IApplicationBuilder app, PolyAuthOptions options)
    {
        app.Use(async (context, next) =>
        {
            var path = context.Request.Path;
            if (path.Equals("/.well-known/oauth-protected-resource", StringComparison.OrdinalIgnoreCase)
                || path.Equals("/.well-known/oauth-protected-resource/mcp", StringComparison.OrdinalIgnoreCase))
            {
                await WriteMetadataAsync(context, GetMcpResource(context, options),
                    [AuthScopes.McpRead, AuthScopes.McpWrite], options);
                return;
            }

            if (path.Equals("/.well-known/oauth-protected-resource/api", StringComparison.OrdinalIgnoreCase))
            {
                await WriteMetadataAsync(context, $"{context.Request.Scheme}://{context.Request.Host}/api",
                    [AuthScopes.ApiRead, AuthScopes.ApiWrite], options);
                return;
            }

            await next();
        });
    }

    private static async Task WriteMetadataAsync(HttpContext context, string resource, string[] scopes, PolyAuthOptions options)
    {
        var issuer = !string.IsNullOrWhiteSpace(options.OAuth.Issuer)
            ? options.OAuth.Issuer!.TrimEnd('/')
            : $"{context.Request.Scheme}://{context.Request.Host}".TrimEnd('/');

        var payload = new Dictionary<string, object>
        {
            ["resource"] = resource,
            ["authorization_servers"] = new[] { issuer },
            ["scopes_supported"] = scopes,
            ["bearer_methods_supported"] = new[] { "header" }
        };

        context.Response.ContentType = "application/json";
        await context.Response.WriteAsync(JsonSerializer.Serialize(payload, JsonSerializerOptions.Web));
    }

    private static string GetMcpResource(HttpContext context, PolyAuthOptions options)
    {
        var baseUrl = string.IsNullOrWhiteSpace(options.Mcp.McpBaseUrl) ? options.OAuth.Issuer : options.Mcp.McpBaseUrl;
        return !string.IsNullOrWhiteSpace(baseUrl)
            ? $"{baseUrl.TrimEnd('/')}/mcp"
            : $"{context.Request.Scheme}://{context.Request.Host}/mcp";
    }
}

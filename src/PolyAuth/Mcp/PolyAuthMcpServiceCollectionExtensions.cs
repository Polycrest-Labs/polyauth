using System.Diagnostics;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using ModelContextProtocol.Server;

namespace PolyAuth.Mcp;

/// <summary>The consumer MCP entry point: <c>AddPolyAuthMcp</c>.</summary>
public static class PolyAuthMcpServiceCollectionExtensions
{
    /// <summary>
    /// Wires <c>AddMcpServer().WithHttpTransport()</c> plus a tool-error request filter (maps exceptions to
    /// user-facing tool errors and logs them with correlation/trace ids), then applies the app's
    /// <paramref name="configureServer"/> delegate so the app can register its own tools and resources.
    /// </summary>
    public static IServiceCollection AddPolyAuthMcp(
        this IServiceCollection services,
        Action<IMcpServerBuilder> configureServer)
    {
        ArgumentNullException.ThrowIfNull(configureServer);

        services.AddHttpContextAccessor();

        var builder = services
            .AddMcpServer(options => options.ServerInstructions = McpServerInstructions.Default)
            .WithHttpTransport()
            .WithRequestFilters(filters =>
            {
                filters.AddCallToolFilter(next => async (request, cancellationToken) =>
                {
                    var logger = request.Services?
                        .GetService<ILoggerFactory>()?
                        .CreateLogger("PolyAuth.Mcp.ToolErrors");
                    var toolName = request.Params?.Name ?? "unknown";

                    try
                    {
                        return await next(request, cancellationToken);
                    }
                    catch (Exception ex) when (McpToolHelpers.TryBuildUserFacingToolError(ex, out var result, out var error))
                    {
                        var activity = Activity.Current;
                        logger?.LogWarning(
                            ex,
                            "MCP tool {ToolName} returned user-facing error {ErrorCode}. ExceptionType={ExceptionType}, TraceId={TraceId}",
                            toolName, error.ErrorCode, ex.GetType().FullName, activity?.TraceId.ToString());
                        activity?.SetStatus(ActivityStatusCode.Error, $"MCP tool returned user-facing error: {error.ErrorCode}.");
                        return result;
                    }
                    catch (Exception ex)
                    {
                        var activity = Activity.Current;
                        logger?.LogError(
                            ex,
                            "Unexpected MCP tool failure in {ToolName}. ExceptionType={ExceptionType}, TraceId={TraceId}",
                            toolName, ex.GetType().FullName, activity?.TraceId.ToString());
                        activity?.SetStatus(ActivityStatusCode.Error, "Unexpected MCP tool failure.");
                        return McpToolHelpers.BuildUnexpectedToolError();
                    }
                });
            });

        configureServer(builder);
        return services;
    }
}

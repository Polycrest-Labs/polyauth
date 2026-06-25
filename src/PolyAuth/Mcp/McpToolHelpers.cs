using System.Text.Json;
using System.Text.Json.Serialization;
using ModelContextProtocol.Protocol;

namespace PolyAuth.Mcp;

/// <summary>The structured payload returned to MCP clients for a user-facing tool error.</summary>
public sealed record McpToolErrorResponse(
    [property: JsonPropertyName("errorCode")] string ErrorCode,
    [property: JsonPropertyName("message")] string Message,
    [property: JsonPropertyName("details")] IReadOnlyList<string> Details);

/// <summary>Metadata describing a mapped tool error (for logging/telemetry).</summary>
public sealed record McpToolErrorMetadata(string ErrorCode, string Message, IReadOnlyList<string> Details);

/// <summary>
/// Maps exceptions thrown by MCP tools to clean, user-facing <see cref="CallToolResult"/> errors so the
/// model gets an actionable message instead of a stack trace. Dependency-free: FluentValidation's
/// <c>ValidationException</c> is detected by type name (its message already carries the failures).
/// </summary>
public static class McpToolHelpers
{
    public static bool TryBuildUserFacingToolError(Exception exception, out CallToolResult result)
        => TryBuildUserFacingToolError(exception, out result, out _);

    public static bool TryBuildUserFacingToolError(
        Exception exception,
        out CallToolResult result,
        out McpToolErrorMetadata error)
    {
        (string ErrorCode, string Message, IReadOnlyList<string> Details)? mapped = exception switch
        {
            JsonException jsonException => (
                "invalid_argument",
                $"Tool arguments could not be parsed: {jsonException.Message} Check the tool's inputSchema for the expected shape.",
                (IReadOnlyList<string>)[]),
            ArgumentException argumentException => ("invalid_argument", argumentException.Message, []),
            InvalidOperationException invalidOperationException => ("operation_failed", invalidOperationException.Message, []),
            UnauthorizedAccessException unauthorizedAccessException => ("forbidden", unauthorizedAccessException.Message, []),
            _ when IsValidationException(exception) => ("validation_failed",
                string.IsNullOrWhiteSpace(exception.Message) ? "Validation failed." : exception.Message, []),
            _ => null
        };

        if (mapped == null)
        {
            result = null!;
            error = null!;
            return false;
        }

        error = new McpToolErrorMetadata(mapped.Value.ErrorCode, mapped.Value.Message, mapped.Value.Details);
        result = BuildToolError(error.ErrorCode, error.Message, error.Details);
        return true;
    }

    public static CallToolResult BuildUnexpectedToolError()
        => BuildToolError("unexpected_error", "The MCP tool failed unexpectedly. Check server logs for details.", []);

    public static CallToolResult BuildToolError(string errorCode, string message, IReadOnlyList<string> details)
    {
        var payload = new McpToolErrorResponse(errorCode, message, details);
        return new CallToolResult
        {
            IsError = true,
            Content = [new TextContentBlock { Text = message }],
            StructuredContent = JsonSerializer.SerializeToElement(payload, JsonSerializerOptions.Web)
        };
    }

    private static bool IsValidationException(Exception exception)
        => exception.GetType().Name == "ValidationException";
}

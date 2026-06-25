namespace PolyAuth.Mcp;

/// <summary>Default LLM-facing server instructions. Apps may override via <c>AddPolyAuthMcp</c> options.</summary>
public static class McpServerInstructions
{
    public const string Default =
        """
        This MCP server exposes the application's tools over an OAuth 2.1-protected endpoint.
        General rules:
        - Resolve referenced resources before acting on them; never guess identifiers.
        - For destructive actions, confirm the target with the user before calling the tool.
        - Tool errors are returned as structured results with an errorCode and a human-readable message;
          read the message and correct the arguments rather than retrying blindly.
        """;
}

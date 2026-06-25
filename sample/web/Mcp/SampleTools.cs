using System.ComponentModel;
using System.Security.Claims;
using Microsoft.AspNetCore.Http;
using ModelContextProtocol.Server;
using PolyAuth;
using Sample.Web.Items;

namespace Sample.Web.Mcp;

/// <summary>Sample MCP tools demonstrating read (mcp.read) and write (mcp.write) scope enforcement.</summary>
[McpServerToolType]
public sealed class SampleTools
{
    private readonly IHttpContextAccessor _httpContextAccessor;
    private readonly IItemStore _store;

    public SampleTools(IHttpContextAccessor httpContextAccessor, IItemStore store)
    {
        _httpContextAccessor = httpContextAccessor;
        _store = store;
    }

    private ClaimsPrincipal User =>
        _httpContextAccessor.HttpContext?.User
        ?? throw new InvalidOperationException("No authenticated MCP request context.");

    private string UserId =>
        User.FindFirstValue("sub")
        ?? User.FindFirstValue("uid")
        ?? User.FindFirstValue(ClaimTypes.NameIdentifier)
        ?? throw new UnauthorizedAccessException("The MCP token is missing a subject claim.");

    [McpServerTool(Name = "ping"), Description("Health check that echoes back the provided message.")]
    public string Ping([Description("A message to echo.")] string message = "pong") => message;

    // UseStructuredContent = true makes the SDK emit an output schema (clears ChatGPT's
    // "Output schema recommended") AND populate structuredContent for the widget — provided the
    // return is a concrete typed record (here ItemListResult), not object/CallToolResult/bare array.
    [McpServerTool(Name = "list_items", UseStructuredContent = true), Description("List the authenticated user's items. Requires mcp.read.")]
    public async Task<ItemListResult> ListItems(CancellationToken ct)
        => new(await _store.ListAsync(UserId, ct));

    [McpServerTool(Name = "add_item", UseStructuredContent = true), Description("Create an item for the authenticated user. Requires mcp.write.")]
    public async Task<ItemListResult> AddItem([Description("The item title.")] string title, CancellationToken ct)
    {
        if (!ScopeAuthorization.HasScope(User, AuthScopes.McpWrite))
        {
            throw new UnauthorizedAccessException("This tool requires the mcp.write scope.");
        }

        if (string.IsNullOrWhiteSpace(title))
        {
            throw new ArgumentException("title is required.");
        }

        await _store.CreateAsync(UserId, title.Trim(), ct);
        // Return the refreshed list so the bound items widget reflects the new item.
        return new ItemListResult(await _store.ListAsync(UserId, ct));
    }
}

/// <summary>Typed tool result so the SDK can generate an output schema and structuredContent.
/// Serializes camelCase as { items: [...] } — the shape the mcp-ui widget reads (output.items).</summary>
public sealed record ItemListResult(IReadOnlyList<Item> Items);

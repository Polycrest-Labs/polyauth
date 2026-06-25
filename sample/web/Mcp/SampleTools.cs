using System.ComponentModel;
using System.Security.Claims;
using System.Text.Json;
using Microsoft.AspNetCore.Http;
using ModelContextProtocol.Protocol;
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

    [McpServerTool(Name = "list_items"), Description("List the authenticated user's items. Requires mcp.read.")]
    public async Task<CallToolResult> ListItems(CancellationToken ct)
        // Emit structuredContent ({ items: [...] }) — ChatGPT/MCP-App widgets receive this as
        // window.openai.toolOutput; a bare return only produces a text block (structuredContent=null)
        // and the widget renders empty.
        => ItemsResult(await _store.ListAsync(UserId, ct));

    [McpServerTool(Name = "add_item"), Description("Create an item for the authenticated user. Requires mcp.write.")]
    public async Task<CallToolResult> AddItem([Description("The item title.")] string title, CancellationToken ct)
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
        return ItemsResult(await _store.ListAsync(UserId, ct));
    }

    private static CallToolResult ItemsResult(IReadOnlyList<Item> items)
    {
        var payload = new { items };
        return new CallToolResult
        {
            Content = [new TextContentBlock { Text = JsonSerializer.Serialize(payload, JsonSerializerOptions.Web) }],
            StructuredContent = JsonSerializer.SerializeToElement(payload, JsonSerializerOptions.Web)
        };
    }
}

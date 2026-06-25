using System.Text.Json.Nodes;
using Microsoft.Extensions.Options;
using ModelContextProtocol.Protocol;
using ModelContextProtocol.Server;
using PolyAuth;
using PolyAuth.Mcp;

namespace Sample.Web.Mcp;

/// <summary>
/// A sample ChatGPT-App widget resource. The HTML bootstraps the Angular widget app served by the
/// separate MCP-UI host (PolyAuth:Mcp:WidgetHostBaseUrl), using the reusable
/// <see cref="McpWidgetHtmlBuilder"/>. The mime type is <c>text/html+skybridge</c> (the ChatGPT Apps
/// SDK value); the <c>list_items</c> tool advertises this template via <c>openai/outputTemplate</c>
/// (wired in Program.cs) so ChatGPT renders this widget instead of plain JSON.
/// </summary>
[McpServerResourceType]
public sealed class SampleWidgetResources
{
    public const string ItemsWidgetTemplateUri = "ui://widget/polyauth-sample-items.html";
    private const string WidgetMimeType = "text/html+skybridge";

    private readonly string _widgetHostBaseUrl;

    public SampleWidgetResources(IOptions<PolyAuthOptions> options)
        => _widgetHostBaseUrl = options.Value.Mcp.WidgetHostBaseUrl ?? string.Empty;

    [McpServerResource(
        UriTemplate = ItemsWidgetTemplateUri,
        Name = "polyauth-sample-items-widget",
        Title = "PolyAuth sample items widget",
        MimeType = WidgetMimeType)]
    public ReadResourceResult ItemsWidget()
        => new()
        {
            Contents =
            [
                new TextResourceContents
                {
                    Uri = ItemsWidgetTemplateUri,
                    MimeType = WidgetMimeType,
                    Text = McpWidgetHtmlBuilder.BuildWidgetHtml(_widgetHostBaseUrl, "/items", "PolyAuth Sample"),
                    Meta = BuildMeta()
                }
            ]
        };

    private JsonObject BuildMeta()
    {
        var domain = _widgetHostBaseUrl.TrimEnd('/');
        var meta = McpWidgetHtmlBuilder.BuildResourceMeta(_widgetHostBaseUrl);
        // ChatGPT Apps SDK CSP: allow loading/connecting to the widget host.
        meta["openai/widgetDescription"] = "Shows the signed-in user's items.";
        meta["openai/widgetPrefersBorder"] = true;
        meta["openai/widgetCSP"] = new JsonObject
        {
            ["connect_domains"] = new JsonArray(domain),
            ["resource_domains"] = new JsonArray(domain)
        };
        return meta;
    }
}

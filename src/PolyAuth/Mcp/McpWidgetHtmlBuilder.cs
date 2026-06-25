using System.Text.Encodings.Web;
using System.Text.Json;
using System.Text.Json.Nodes;

namespace PolyAuth.Mcp;

/// <summary>
/// Builds the bootstrap HTML and ChatGPT/MCP-App metadata for an embedded widget served from a separate
/// static host (the MCP-UI host). Reusable across apps; pass the widget host base URL and the SPA route
/// to start on. Generalized from the docstosheets ChatGPT-UI widget pattern.
/// </summary>
public static class McpWidgetHtmlBuilder
{
    public const string WidgetMimeType = "text/html;profile=mcp-app";

    public static string BuildWidgetHtml(string widgetHostBaseUrl, string startupRoute, string title = "PolyAuth MCP UI")
    {
        var normalizedBaseUrl = (widgetHostBaseUrl ?? string.Empty).TrimEnd('/');
        var escapedStartupRoute = HtmlEncoder.Default.Encode(startupRoute);
        var escapedTitle = HtmlEncoder.Default.Encode(title);
        var serializedBaseUrl = JsonSerializer.Serialize(normalizedBaseUrl);

        return $$"""
            <!doctype html>
            <html lang="en">
            <head>
              <meta charset="utf-8">
              <meta name="viewport" content="width=device-width, initial-scale=1">
              <title>{{escapedTitle}}</title>
            </head>
            <body>
              <app-root data-startup-route="{{escapedStartupRoute}}"></app-root>
              <div id="polyauth-widget-load-error" role="alert" hidden>
                Unable to load the widget.
              </div>
              <script>
                (() => {
                  const hostBaseUrl = {{serializedBaseUrl}};
                  const baseUrl = new URL(hostBaseUrl.endsWith('/') ? hostBaseUrl : `${hostBaseUrl}/`);
                  const indexUrl = new URL('index.html', baseUrl);
                  indexUrl.searchParams.set('mcpWidgetVersion', String(Date.now()));

                  const shouldRewriteUrl = (value) => value
                    && !value.startsWith('#')
                    && !value.startsWith('//')
                    && !/^[a-z][a-z0-9+.-]*:/i.test(value);

                  const rewriteUrl = (value) => shouldRewriteUrl(value)
                    ? new URL(value, baseUrl).toString()
                    : value;

                  const copyAssetElement = (sourceElement) => {
                    const element = document.createElement(sourceElement.tagName.toLowerCase());
                    for (const attribute of sourceElement.attributes) {
                      const value = attribute.name === 'href' || attribute.name === 'src'
                        ? rewriteUrl(attribute.value)
                        : attribute.value;
                      element.setAttribute(attribute.name, value);
                    }
                    if (sourceElement.tagName.toLowerCase() === 'style') {
                      element.textContent = sourceElement.textContent;
                    }
                    return element;
                  };

                  const load = async () => {
                    const response = await fetch(indexUrl.toString(), { cache: 'no-store' });
                    if (!response.ok) {
                      throw new Error(`Failed to load MCP UI index: ${response.status}`);
                    }
                    const html = await response.text();
                    const parsed = new DOMParser().parseFromString(html, 'text/html');
                    const headSelectors = ['style', 'link[rel="stylesheet"][href]', 'link[rel="modulepreload"][href]'];
                    for (const sourceElement of parsed.head.querySelectorAll(headSelectors.join(','))) {
                      document.head.appendChild(copyAssetElement(sourceElement));
                    }
                    for (const sourceScript of parsed.body.querySelectorAll('script[src]')) {
                      document.body.appendChild(copyAssetElement(sourceScript));
                    }
                  };

                  load().catch((error) => {
                    console.error(error);
                    document.getElementById('polyauth-widget-load-error')?.removeAttribute('hidden');
                  });
                })();
              </script>
            </body>
            </html>
            """;
    }

    /// <summary>Resource _meta advertising the widget host domain + CSP for ChatGPT/MCP-Apps.</summary>
    public static JsonObject BuildResourceMeta(string widgetHostBaseUrl)
    {
        var normalizedBaseUrl = (widgetHostBaseUrl ?? string.Empty).TrimEnd('/');
        return new JsonObject
        {
            ["ui"] = new JsonObject
            {
                ["prefersBorder"] = true,
                ["domain"] = normalizedBaseUrl,
                ["csp"] = new JsonObject
                {
                    ["resourceDomains"] = new JsonArray(normalizedBaseUrl),
                    ["connectDomains"] = new JsonArray(normalizedBaseUrl)
                }
            },
            ["openai/widgetDomain"] = normalizedBaseUrl
        };
    }

    /// <summary>Tool _meta binding a tool's output to a widget output template.</summary>
    public static JsonObject BuildToolMeta(string resourceUri)
        => new()
        {
            ["openai/outputTemplate"] = resourceUri,
            ["ui"] = new JsonObject { ["resourceUri"] = resourceUri }
        };
}

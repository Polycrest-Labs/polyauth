using System.Text.Json.Serialization;
using Azure.Monitor.OpenTelemetry.AspNetCore;
using Microsoft.Azure.Cosmos;
using PolyAuth;
using PolyAuth.Mcp;
using Sample.Web.Items;
using Sample.Web.Mcp;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddControllers().AddJsonOptions(o =>
{
    o.JsonSerializerOptions.PropertyNamingPolicy = System.Text.Json.JsonNamingPolicy.CamelCase;
    o.JsonSerializerOptions.Converters.Add(new JsonStringEnumConverter());
});

builder.Services.AddHealthChecks();
builder.Services.AddCors(options => options.AddDefaultPolicy(policy =>
    policy.AllowAnyOrigin().AllowAnyHeader().AllowAnyMethod()));

// Optional Application Insights (guarded — UseAzureMonitor throws without a connection string).
var aiConnectionString = builder.Configuration["APPLICATIONINSIGHTS_CONNECTION_STRING"];
if (!string.IsNullOrWhiteSpace(aiConnectionString))
{
    builder.Services.AddOpenTelemetry().UseAzureMonitor(o => o.ConnectionString = aiConnectionString);
}

// Item store: Cosmos when configured, in-memory otherwise (dev/tests).
var cosmosConnectionString = builder.Configuration["CosmosDb:ConnectionString"];
var cosmosDatabaseId = builder.Configuration["CosmosDb:DatabaseId"] ?? "polyauth-sample";
if (!string.IsNullOrWhiteSpace(cosmosConnectionString))
{
    var cosmosClient = new CosmosClient(cosmosConnectionString, new CosmosClientOptions
    {
        UseSystemTextJsonSerializerWithOptions = new System.Text.Json.JsonSerializerOptions(System.Text.Json.JsonSerializerDefaults.Web)
    });
    builder.Services.AddSingleton(cosmosClient);
    builder.Services.AddSingleton<IItemStore>(_ => new CosmosItemStore(cosmosClient, cosmosDatabaseId));
}
else
{
    builder.Services.AddSingleton<IItemStore, InMemoryItemStore>();
}

// Runtime SPA config payload (non-secret).
builder.Services.Configure<ClientConfig>(builder.Configuration.GetSection("UiClient"));

// PolyAuth — Firebase login + OAuth Authorization Server + MCP authorization.
builder.Services.AddPolyAuth(builder.Configuration, o =>
{
    o.Firebase.Enabled = builder.Configuration.GetValue("PolyAuth:Firebase:Enabled", true);
    o.OAuth.Enabled = builder.Configuration.GetValue("PolyAuth:OAuth:Enabled", true);
    o.Mcp.Enabled = builder.Configuration.GetValue("PolyAuth:Mcp:Enabled", true);
});

builder.Services.AddPolyAuthMcp(mcp => mcp
    .WithTools<SampleTools>()
    .WithResources<SampleWidgetResources>()
    // Advertise the items widget as the ChatGPT/MCP-App output template for the list_items tool, so
    // ChatGPT renders the custom UI (the Angular widget on the MCP-UI host) instead of plain JSON.
    .WithRequestFilters(filters => filters.AddListToolsFilter(next => async (request, ct) =>
    {
        var result = await next(request, ct);
        foreach (var tool in result.Tools)
        {
            if (tool.Name is "list_items")
            {
                var meta = PolyAuth.Mcp.McpWidgetHtmlBuilder.BuildToolMeta(SampleWidgetResources.ItemsWidgetTemplateUri);
                meta["openai/toolInvocation/invoking"] = "Loading items…";
                meta["openai/toolInvocation/invoked"] = "Loaded items.";
                tool.Meta = meta;
            }
        }

        return result;
    })));

var app = builder.Build();

if (!string.IsNullOrWhiteSpace(cosmosConnectionString))
{
    using var scope = app.Services.CreateScope();
    await CosmosItemStore.EnsureContainerAsync(
        scope.ServiceProvider.GetRequiredService<CosmosClient>(), cosmosDatabaseId);
}

// App Service (Linux) terminates TLS at the platform; honor X-Forwarded-Proto so the app sees
// https and OpenIddict's transport-security requirement is satisfied in Production.
var forwardedHeaders = new Microsoft.AspNetCore.Builder.ForwardedHeadersOptions
{
    ForwardedHeaders = Microsoft.AspNetCore.HttpOverrides.ForwardedHeaders.XForwardedFor
        | Microsoft.AspNetCore.HttpOverrides.ForwardedHeaders.XForwardedProto
};
forwardedHeaders.KnownIPNetworks.Clear();
forwardedHeaders.KnownProxies.Clear();
app.UseForwardedHeaders(forwardedHeaders);

app.UseCors();

app.UseDefaultFiles();
app.UseStaticFiles(new Microsoft.AspNetCore.Builder.StaticFileOptions
{
    OnPrepareResponse = ctx =>
    {
        var path = ctx.Context.Request.Path.Value ?? string.Empty;
        ctx.Context.Response.Headers.CacheControl =
            path.EndsWith("index.html", StringComparison.OrdinalIgnoreCase)
                ? "no-cache"
                : "public, max-age=31536000, immutable";
    }
});

app.UsePolyAuth();

app.MapControllers();
app.MapHealthChecks("/health");

// Runtime config for the SPA.
app.MapGet("/config.json", (Microsoft.Extensions.Options.IOptions<ClientConfig> cfg) => Results.Json(cfg.Value));

// MCP endpoint, protected by the mcp.read policy.
app.MapMcp("/mcp").RequireAuthorization(AuthPolicies.McpRead);

app.MapFallbackToFile("index.html");

app.Run();

/// <summary>The non-secret runtime configuration served at /config.json for the SPA.</summary>
public sealed class ClientConfig
{
    [JsonPropertyName("firebase")]
    public FirebaseClientConfig Firebase { get; set; } = new();

    [JsonPropertyName("oauth")]
    public OAuthClientConfig OAuth { get; set; } = new();

    [JsonPropertyName("applicationInsightsConnectionString")]
    public string ApplicationInsightsConnectionString { get; set; } = string.Empty;
}

public sealed class FirebaseClientConfig
{
    public string ApiKey { get; set; } = string.Empty;
    public string AuthDomain { get; set; } = string.Empty;
    public string ProjectId { get; set; } = string.Empty;
    public string AppId { get; set; } = string.Empty;
}

public sealed class OAuthClientConfig
{
    public string ClientId { get; set; } = "polyauth-ui";
    public string TokenEndpoint { get; set; } = "/connect/token";
    public string RevocationEndpoint { get; set; } = "/connect/revocation";
    public string Scope { get; set; } = "openid profile email api.read api.write offline_access";
}

/// <summary>Exposed so the integration test project can use WebApplicationFactory&lt;Program&gt;.</summary>
public partial class Program;

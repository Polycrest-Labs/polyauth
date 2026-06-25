var builder = WebApplication.CreateBuilder(args);

builder.Logging.ClearProviders();
builder.Logging.AddConsole();
builder.Services.AddHealthChecks();

var app = builder.Build();

// Widgets are embedded cross-origin (inside ChatGPT / Claude), so allow cross-origin GETs and
// serve index.html uncached.
app.Use(async (context, next) =>
{
    var headers = context.Response.Headers;
    headers.AccessControlAllowOrigin = "*";
    headers.AccessControlAllowMethods = "GET,HEAD,OPTIONS";
    headers.AccessControlAllowHeaders = "*";
    headers["Cross-Origin-Resource-Policy"] = "cross-origin";

    var isIndex = context.Request.Path.Equals("/", StringComparison.OrdinalIgnoreCase)
        || context.Request.Path.Equals("/index.html", StringComparison.OrdinalIgnoreCase);
    if (isIndex)
    {
        context.Response.OnStarting(() =>
        {
            headers.CacheControl = "no-store";
            headers.Pragma = "no-cache";
            headers.Expires = "0";
            return Task.CompletedTask;
        });
    }

    if (HttpMethods.IsOptions(context.Request.Method))
    {
        context.Response.StatusCode = StatusCodes.Status204NoContent;
        return;
    }

    await next();
});

app.UseDefaultFiles();
app.UseStaticFiles();
app.MapHealthChecks("/health");
app.MapFallbackToFile("index.html");

app.Run();

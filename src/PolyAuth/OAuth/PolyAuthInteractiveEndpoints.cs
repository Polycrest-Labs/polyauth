using System.Net;
using System.Security.Claims;
using System.Text;
using Microsoft.AspNetCore;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using OpenIddict.Abstractions;
using OpenIddict.Server.AspNetCore;
using PolyAuth.OAuth;

namespace PolyAuth;

/// <summary>Request body for the OAuth session-login endpoint.</summary>
public sealed record OAuthSessionRequest(string? ReturnUrl);

/// <summary>Response from the OAuth session-login endpoint.</summary>
public sealed record OAuthSessionResponse(string ReturnUrl);

/// <summary>Context handed to a custom consent renderer.</summary>
public sealed record PolyAuthConsentRequest(HttpContext HttpContext, string? ClientId, string DisplayName, IReadOnlyList<string> Scopes);

/// <summary>
/// Optional hook to render the third-party consent screen with the app's own UI. Register an implementation
/// in DI to override the built-in default consent page. The first-party UI client is always auto-consented.
/// </summary>
public interface IPolyAuthConsentRenderer
{
    ValueTask<IResult> RenderAsync(PolyAuthConsentRequest request);
}

/// <summary>
/// Maps the library-owned interactive OAuth endpoints — <c>/connect/authorize</c>, <c>/connect/logout</c>, and
/// (when Firebase is enabled) the Firebase→session-cookie bridge <c>POST /api/oauth/session</c>. A consuming app
/// calls <c>app.MapPolyAuthEndpoints()</c> instead of hand-writing these controllers. No-ops when OAuth is disabled.
/// </summary>
public static class PolyAuthEndpointRouteBuilderExtensions
{
    public static IEndpointRouteBuilder MapPolyAuthEndpoints(this IEndpointRouteBuilder endpoints)
    {
        var options = endpoints.ServiceProvider.GetRequiredService<IOptions<PolyAuthOptions>>().Value;
        if (!options.OAuth.Enabled)
        {
            return endpoints;
        }

        endpoints.MapMethods("/connect/authorize", ["GET", "POST"], AuthorizeAsync).AllowAnonymous();
        // Cast to Delegate so the route-handler (IResult-returning) overload is selected rather than the
        // RequestDelegate overload, which would discard the IResult (ASP0016).
        endpoints.MapMethods("/connect/logout", ["GET", "POST"], (Delegate)LogoutAsync).AllowAnonymous();

        if (SessionBridgeGating.IsEnabled(options))
        {
            // Gate the bridge by the configured schemes (the consuming app's own bearer scheme when
            // SessionBridge.AuthenticationSchemes is set; Firebase otherwise — the 0.1.x behavior).
            var policy = new Microsoft.AspNetCore.Authorization.AuthorizationPolicyBuilder(
                    SessionBridgeGating.ResolveSchemes(options))
                .RequireAuthenticatedUser()
                .Build();
            endpoints.MapPost("/api/oauth/session", CreateSessionAsync).RequireAuthorization(policy);
        }

        return endpoints;
    }

    private static async Task<IResult> AuthorizeAsync(
        HttpContext http,
        IOptions<PolyAuthOptions> options,
        IOpenIddictApplicationManager applicationManager,
        IPolyAuthPrincipalEnricher enricher)
    {
        var oauth = options.Value.OAuth;
        var request = http.GetOpenIddictServerRequest()
            ?? throw new InvalidOperationException("The OpenID Connect request cannot be retrieved.");

        var result = await http.AuthenticateAsync(AuthSchemes.OAuthSession);
        if (!result.Succeeded || result.Principal is null)
        {
            var returnUrl = http.Request.PathBase + http.Request.Path + http.Request.QueryString;
            return Results.Redirect($"{oauth.SignInPath}?returnUrl={Uri.EscapeDataString(returnUrl)}");
        }

        var isThirdParty = !string.Equals(request.ClientId, oauth.UiClientId, StringComparison.Ordinal);
        var consentAction = ConsentAction(http.Request);
        if (isThirdParty && consentAction != "approve")
        {
            if (consentAction == "deny")
            {
                return Forbid(OpenIddictConstants.Errors.AccessDenied, "The authorization request was denied.");
            }

            if (HttpMethods.IsPost(http.Request.Method))
            {
                return Results.BadRequest(new { error = "invalid_request", error_description = "The consent form must include an approve or deny action." });
            }

            return await RenderConsentAsync(http, applicationManager, request);
        }

        var principal = OpenIddictPrincipalFactory.FromOAuthSession(result.Principal, request.GetScopes(), request.GetResources());
        await enricher.EnrichAsync(
            new PrincipalEnrichmentContext(principal, PrincipalEnrichmentGrant.AuthorizationCode, request.ClientId),
            http.RequestAborted);
        OpenIddictPrincipalFactory.ApplyDestinations(principal);

        return Results.SignIn(principal, properties: null, OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
    }

    private static async Task<IResult> LogoutAsync(HttpContext http)
    {
        await http.SignOutAsync(AuthSchemes.OAuthSession);
        return Results.SignOut(
            new AuthenticationProperties { RedirectUri = "/" },
            [OpenIddictServerAspNetCoreDefaults.AuthenticationScheme]);
    }

    private static async Task<IResult> CreateSessionAsync(HttpContext http, OAuthSessionRequest body)
    {
        var user = http.User;
        var userId = user.FindFirstValue("uid")
                     ?? user.FindFirstValue("sub")
                     ?? user.FindFirstValue(ClaimTypes.NameIdentifier)!;

        var claims = new List<Claim>
        {
            new("uid", userId),
            new("sub", userId),
            new(ClaimTypes.NameIdentifier, userId)
        };
        AddOptional(claims, user, "email", ClaimTypes.Email);
        AddOptional(claims, user, "name", ClaimTypes.Name);

        var identity = new ClaimsIdentity(claims, AuthSchemes.OAuthSession, "name", ClaimTypes.Role);
        await http.SignInAsync(
            AuthSchemes.OAuthSession,
            new ClaimsPrincipal(identity),
            new AuthenticationProperties { IsPersistent = false, ExpiresUtc = DateTimeOffset.UtcNow.AddMinutes(30) });

        return Results.Ok(new OAuthSessionResponse(NormalizeReturnUrl(body.ReturnUrl)));
    }

    private static IResult Forbid(string error, string description)
        => Results.Forbid(
            new AuthenticationProperties(new Dictionary<string, string?>
            {
                [OpenIddictServerAspNetCoreConstants.Properties.Error] = error,
                [OpenIddictServerAspNetCoreConstants.Properties.ErrorDescription] = description
            }),
            [OpenIddictServerAspNetCoreDefaults.AuthenticationScheme]);

    // "approve" / "deny", or null on a GET or a POST without the form action.
    private static string? ConsentAction(HttpRequest request)
        => HttpMethods.IsPost(request.Method) && request.HasFormContentType
            ? request.Form["consent_action"].ToString()
            : null;

    private static async Task<IResult> RenderConsentAsync(
        HttpContext http, IOpenIddictApplicationManager applicationManager, OpenIddictRequest request)
    {
        var displayName = request.ClientId ?? "OAuth client";
        if (!string.IsNullOrWhiteSpace(request.ClientId))
        {
            var application = await applicationManager.FindByClientIdAsync(request.ClientId, http.RequestAborted);
            if (application is not null)
            {
                displayName = await applicationManager.GetDisplayNameAsync(application, http.RequestAborted) ?? request.ClientId;
            }
        }

        var scopes = request.GetScopes().ToArray();
        var renderer = http.RequestServices.GetService<IPolyAuthConsentRenderer>();
        if (renderer is not null)
        {
            return await renderer.RenderAsync(new PolyAuthConsentRequest(http, request.ClientId, displayName, scopes));
        }

        return Results.Content(BuildDefaultConsentHtml(http.Request, displayName, scopes), "text/html", Encoding.UTF8);
    }

    private static string BuildDefaultConsentHtml(HttpRequest request, string displayName, IReadOnlyList<string> scopes)
    {
        var html = new StringBuilder();
        html.AppendLine("<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">");
        html.AppendLine("<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\"><title>Authorize</title>");
        html.AppendLine("<style>body{font-family:system-ui,sans-serif;max-width:560px;margin:12vh auto;padding:32px}button{padding:10px 16px;margin-right:12px;border-radius:6px;border:0;font-weight:650;cursor:pointer}.approve{background:#12694f;color:#fff}</style></head><body>");
        html.Append("<h1>Authorize ").Append(WebUtility.HtmlEncode(displayName)).AppendLine("</h1>");
        html.AppendLine("<p>This client is requesting access with these scopes:</p><ul>");
        foreach (var scope in scopes)
        {
            html.Append("<li><code>").Append(WebUtility.HtmlEncode(scope)).AppendLine("</code></li>");
        }

        html.AppendLine("</ul><form method=\"post\" action=\"/connect/authorize\">");
        foreach (var parameter in request.Query)
        {
            foreach (var value in parameter.Value)
            {
                html.Append("<input type=\"hidden\" name=\"").Append(WebUtility.HtmlEncode(parameter.Key))
                    .Append("\" value=\"").Append(WebUtility.HtmlEncode(value ?? string.Empty)).AppendLine("\">");
            }
        }

        html.AppendLine("<button class=\"approve\" type=\"submit\" name=\"consent_action\" value=\"approve\">Authorize</button>");
        html.AppendLine("<button type=\"submit\" name=\"consent_action\" value=\"deny\">Deny</button>");
        html.AppendLine("</form></body></html>");
        return html.ToString();
    }

    private static void AddOptional(List<Claim> claims, ClaimsPrincipal source, string sourceType, string destinationType)
    {
        var value = source.FindFirstValue(sourceType) ?? source.FindFirstValue(destinationType);
        if (!string.IsNullOrWhiteSpace(value))
        {
            claims.Add(new Claim(destinationType, value));
        }
    }

    private static string NormalizeReturnUrl(string? returnUrl)
        => !string.IsNullOrWhiteSpace(returnUrl)
           && Uri.TryCreate(returnUrl, UriKind.Relative, out _)
           && returnUrl.StartsWith('/')
           && !returnUrl.StartsWith("//", StringComparison.Ordinal)
            ? returnUrl
            : "/";
}

using System.Net;
using System.Text;
using Microsoft.AspNetCore;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using OpenIddict.Abstractions;
using OpenIddict.Server.AspNetCore;
using PolyAuth;
using PolyAuth.OAuth;

namespace Sample.Web.OAuth;

/// <summary>
/// Handles the OpenIddict authorization-code endpoint (passthrough). When the user has an OAuthSession
/// cookie, it issues the code; otherwise it redirects to the SPA sign-in page. Third-party clients
/// (ChatGPT/Claude) see a minimal consent page; the first-party UI client is auto-consented.
/// </summary>
[ApiController]
[AllowAnonymous]
public sealed class AuthorizationController : ControllerBase
{
    private readonly IOpenIddictApplicationManager _applicationManager;
    private readonly string _uiClientId;

    public AuthorizationController(
        IOpenIddictApplicationManager applicationManager,
        Microsoft.Extensions.Options.IOptions<PolyAuthOptions> options)
    {
        _applicationManager = applicationManager;
        _uiClientId = options.Value.OAuth.UiClientId;
    }

    [HttpGet("/connect/authorize")]
    [HttpPost("/connect/authorize")]
    public async Task<IActionResult> Authorize(CancellationToken ct)
    {
        var request = HttpContext.GetOpenIddictServerRequest()
                      ?? throw new InvalidOperationException("The OpenID Connect request cannot be retrieved.");

        var result = await HttpContext.AuthenticateAsync(AuthSchemes.OAuthSession);
        if (!result.Succeeded || result.Principal == null)
        {
            var returnUrl = Request.PathBase + Request.Path + Request.QueryString;
            return Redirect($"/sign-in?returnUrl={Uri.EscapeDataString(returnUrl)}");
        }

        if (RequiresConsent(request) && !IsConsentApproved())
        {
            if (IsConsentDenied())
            {
                return Forbid(
                    new AuthenticationProperties(new Dictionary<string, string?>
                    {
                        [OpenIddictServerAspNetCoreConstants.Properties.Error] = OpenIddictConstants.Errors.AccessDenied,
                        [OpenIddictServerAspNetCoreConstants.Properties.ErrorDescription] = "The authorization request was denied."
                    }),
                    OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
            }

            if (HttpMethods.IsPost(Request.Method))
            {
                return BadRequest(new ProblemDetails { Title = "Invalid consent response", Status = StatusCodes.Status400BadRequest });
            }

            return await RenderConsentAsync(request, ct);
        }

        var principal = OpenIddictPrincipalFactory.FromOAuthSession(
            result.Principal, request.GetScopes(), request.GetResources());

        return SignIn(principal, OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
    }

    [HttpGet("/connect/logout")]
    [HttpPost("/connect/logout")]
    public async Task<IActionResult> Logout()
    {
        await HttpContext.SignOutAsync(AuthSchemes.OAuthSession);
        return SignOut(new AuthenticationProperties { RedirectUri = "/" }, OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
    }

    private bool RequiresConsent(OpenIddictRequest request)
        => !string.Equals(request.ClientId, _uiClientId, StringComparison.Ordinal);

    private bool IsConsentApproved()
        => HttpMethods.IsPost(Request.Method) && Request.HasFormContentType
           && string.Equals(Request.Form["consent_action"], "approve", StringComparison.Ordinal);

    private bool IsConsentDenied()
        => HttpMethods.IsPost(Request.Method) && Request.HasFormContentType
           && string.Equals(Request.Form["consent_action"], "deny", StringComparison.Ordinal);

    private async Task<ContentResult> RenderConsentAsync(OpenIddictRequest request, CancellationToken ct)
    {
        var displayName = request.ClientId ?? "OAuth client";
        if (!string.IsNullOrWhiteSpace(request.ClientId))
        {
            var application = await _applicationManager.FindByClientIdAsync(request.ClientId, ct);
            if (application != null)
            {
                displayName = await _applicationManager.GetDisplayNameAsync(application, ct) ?? request.ClientId;
            }
        }

        var html = new StringBuilder();
        html.AppendLine("<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">");
        html.AppendLine("<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\"><title>Authorize</title>");
        html.AppendLine("<style>body{font-family:system-ui,sans-serif;max-width:560px;margin:12vh auto;padding:32px}button{padding:10px 16px;margin-right:12px;border-radius:6px;border:0;font-weight:650;cursor:pointer}.approve{background:#12694f;color:#fff}</style></head><body>");
        html.Append("<h1>Authorize ").Append(WebUtility.HtmlEncode(displayName)).AppendLine("</h1>");
        html.AppendLine("<p>This client is requesting access with these scopes:</p><ul>");
        foreach (var scope in request.GetScopes())
        {
            html.Append("<li><code>").Append(WebUtility.HtmlEncode(scope)).AppendLine("</code></li>");
        }

        html.AppendLine("</ul><form method=\"post\" action=\"/connect/authorize\">");
        foreach (var parameter in Request.Query)
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

        return Content(html.ToString(), "text/html", Encoding.UTF8);
    }
}

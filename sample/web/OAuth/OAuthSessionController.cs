using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using PolyAuth;

namespace Sample.Web.OAuth;

public sealed record OAuthSessionRequest(string? ReturnUrl);
public sealed record OAuthSessionResponse(string ReturnUrl);

/// <summary>
/// Establishes the interactive OAuthSession cookie from a verified Firebase login, so the
/// authorization-code flow (for MCP clients) can issue codes for the signed-in user.
/// </summary>
[ApiController]
public sealed class OAuthSessionController : ControllerBase
{
    [Authorize(AuthenticationSchemes = AuthSchemes.Firebase, Policy = AuthPolicies.FirebaseUser)]
    [HttpPost("/api/oauth/session")]
    [ProducesResponseType(typeof(OAuthSessionResponse), StatusCodes.Status200OK)]
    public async Task<IActionResult> CreateSession([FromBody] OAuthSessionRequest request)
    {
        var userId = User.FindFirstValue("uid")
                     ?? User.FindFirstValue("sub")
                     ?? User.FindFirstValue(ClaimTypes.NameIdentifier)!;

        var claims = new List<Claim>
        {
            new("uid", userId),
            new("sub", userId),
            new(ClaimTypes.NameIdentifier, userId)
        };

        AddOptional(claims, User, "email", ClaimTypes.Email);
        AddOptional(claims, User, "name", ClaimTypes.Name);

        var identity = new ClaimsIdentity(claims, AuthSchemes.OAuthSession, "name", ClaimTypes.Role);
        await HttpContext.SignInAsync(
            AuthSchemes.OAuthSession,
            new ClaimsPrincipal(identity),
            new AuthenticationProperties { IsPersistent = false, ExpiresUtc = DateTimeOffset.UtcNow.AddMinutes(30) });

        return Ok(new OAuthSessionResponse(NormalizeReturnUrl(request.ReturnUrl)));
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

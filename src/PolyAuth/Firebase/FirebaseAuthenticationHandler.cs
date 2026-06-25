using System.Security.Claims;
using System.Text.Encodings.Web;
using FirebaseAdmin.Auth;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace PolyAuth.Firebase;

/// <summary>Scheme name and display name for the Firebase bearer scheme.</summary>
public static class FirebaseAuthenticationDefaults
{
    public const string AuthenticationScheme = AuthSchemes.Firebase;
    public const string DisplayName = "Firebase";
}

/// <summary>
/// Reads <c>Authorization: Bearer &lt;firebase-id-token&gt;</c>, verifies it via
/// <see cref="IFirebaseTokenVerifier"/>, and builds a ClaimsPrincipal whose user id is the
/// Firebase uid (exposed as <c>sub</c>, <c>uid</c>, and NameIdentifier).
/// </summary>
public sealed class FirebaseAuthenticationHandler : AuthenticationHandler<AuthenticationSchemeOptions>
{
    private readonly IFirebaseTokenVerifier _verifier;

    public FirebaseAuthenticationHandler(
        IOptionsMonitor<AuthenticationSchemeOptions> options,
        ILoggerFactory logger,
        UrlEncoder encoder,
        IFirebaseTokenVerifier verifier)
        : base(options, logger, encoder)
    {
        _verifier = verifier;
    }

    protected override async Task<AuthenticateResult> HandleAuthenticateAsync()
    {
        var authorization = Request.Headers.Authorization.ToString();
        if (string.IsNullOrWhiteSpace(authorization))
        {
            return AuthenticateResult.NoResult();
        }

        const string bearerPrefix = "Bearer ";
        if (!authorization.StartsWith(bearerPrefix, StringComparison.OrdinalIgnoreCase))
        {
            return AuthenticateResult.NoResult();
        }

        var idToken = authorization[bearerPrefix.Length..].Trim();
        if (string.IsNullOrWhiteSpace(idToken))
        {
            return AuthenticateResult.Fail("Bearer token is empty.");
        }

        try
        {
            var verified = await _verifier.VerifyIdTokenAsync(idToken, Context.RequestAborted);

            var claims = new List<Claim>
            {
                new("uid", verified.Uid),
                new("sub", verified.Uid),
                new(ClaimTypes.NameIdentifier, verified.Uid)
            };

            if (!string.IsNullOrWhiteSpace(verified.Email))
            {
                claims.Add(new Claim("email", verified.Email));
                claims.Add(new Claim(ClaimTypes.Email, verified.Email));
            }

            if (!string.IsNullOrWhiteSpace(verified.Name))
            {
                claims.Add(new Claim("name", verified.Name));
                claims.Add(new Claim(ClaimTypes.Name, verified.Name));
            }

            var identity = new ClaimsIdentity(claims, Scheme.Name, "name", ClaimTypes.Role);
            var ticket = new AuthenticationTicket(new ClaimsPrincipal(identity), Scheme.Name);
            return AuthenticateResult.Success(ticket);
        }
        catch (FirebaseAuthException ex)
        {
            Logger.LogWarning(ex, "Firebase token validation failed");
            return AuthenticateResult.Fail("Invalid Firebase ID token.");
        }
        catch (Exception ex)
        {
            Logger.LogError(ex, "Firebase authentication failed");
            return AuthenticateResult.Fail("Firebase authentication failed.");
        }
    }
}

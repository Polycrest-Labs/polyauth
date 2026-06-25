using FirebaseAdmin;
using FirebaseAdmin.Auth;
using Google.Apis.Auth.OAuth2;
using Microsoft.Extensions.Options;

namespace PolyAuth.Firebase;

/// <summary>A verified Firebase ID token reduced to the claims PolyAuth needs.</summary>
public sealed record VerifiedFirebaseToken(string Uid, string? Email, string? Name);

/// <summary>
/// Verifies Firebase ID tokens. Injected so tests can substitute a deterministic verifier
/// without contacting Google.
/// </summary>
public interface IFirebaseTokenVerifier
{
    Task<VerifiedFirebaseToken> VerifyIdTokenAsync(string idToken, CancellationToken ct = default);
}

/// <summary>
/// The production verifier, backed by the Firebase Admin SDK. Owns lazy, thread-safe creation
/// of the named <see cref="FirebaseApp"/> from <see cref="FirebaseOptions.ServiceAccountJson"/>.
/// </summary>
public sealed class FirebaseTokenVerifier : IFirebaseTokenVerifier
{
    private readonly FirebaseOptions _options;
    private readonly Lazy<FirebaseAuth> _auth;

    public FirebaseTokenVerifier(IOptions<PolyAuthOptions> options)
    {
        _options = options.Value.Firebase;
        _auth = new Lazy<FirebaseAuth>(() => FirebaseAuth.GetAuth(FirebaseAppFactory.GetOrCreate(_options)));
    }

    public async Task<VerifiedFirebaseToken> VerifyIdTokenAsync(string idToken, CancellationToken ct = default)
    {
        var decoded = await _auth.Value.VerifyIdTokenAsync(idToken, ct);

        string? email = null;
        string? name = null;
        if (decoded.Claims.TryGetValue("email", out var e) && e is string es)
        {
            email = es;
        }

        if (decoded.Claims.TryGetValue("name", out var n) && n is string ns)
        {
            name = ns;
        }

        return new VerifiedFirebaseToken(decoded.Uid, email, name);
    }
}

/// <summary>Creates (once) and resolves the named FirebaseApp from PolyAuth's Firebase options.</summary>
public static class FirebaseAppFactory
{
    private static readonly object Gate = new();

    public static FirebaseApp GetOrCreate(FirebaseOptions options)
    {
        var name = string.IsNullOrWhiteSpace(options.AppName) ? "polyauth" : options.AppName;

        var existing = TryGet(name);
        if (existing is not null)
        {
            return existing;
        }

        lock (Gate)
        {
            existing = TryGet(name);
            if (existing is not null)
            {
                return existing;
            }

            return FirebaseApp.Create(new AppOptions
            {
                Credential = ResolveCredential(options),
                ProjectId = options.ProjectId
            }, name);
        }
    }

    private static FirebaseApp? TryGet(string name)
    {
        try
        {
            // FirebaseApp.GetInstance throws InvalidOperationException when the app does not exist.
            return FirebaseApp.GetInstance(name);
        }
        catch (InvalidOperationException)
        {
            return null;
        }
    }

    private static GoogleCredential ResolveCredential(FirebaseOptions options)
    {
        if (string.IsNullOrWhiteSpace(options.ServiceAccountJson))
        {
            // Fall back to application default credentials (e.g. workload identity).
            return GoogleCredential.GetApplicationDefault();
        }

        var json = NormalizeServiceAccountJson(options.ServiceAccountJson);
        try
        {
            return CredentialFactory.FromJson(json, JsonCredentialParameters.ServiceAccountCredentialType);
        }
        catch (Exception ex)
        {
            throw new InvalidOperationException(
                "PolyAuth:Firebase:ServiceAccountJson is set but could not be parsed as a Google service account JSON value.",
                ex);
        }
    }

    /// <summary>Accepts either raw service-account JSON or base64-encoded JSON.</summary>
    public static string NormalizeServiceAccountJson(string value)
    {
        var trimmed = value.Trim();
        if (trimmed.StartsWith('{'))
        {
            return trimmed;
        }

        try
        {
            var bytes = Convert.FromBase64String(trimmed);
            var decoded = System.Text.Encoding.UTF8.GetString(bytes);
            if (decoded.TrimStart().StartsWith('{'))
            {
                return decoded;
            }
        }
        catch (FormatException)
        {
            // Not base64 — fall through and return as-is so Google surfaces a clear error.
        }

        return trimmed;
    }
}

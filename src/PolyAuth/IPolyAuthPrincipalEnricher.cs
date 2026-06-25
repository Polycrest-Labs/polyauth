using System.Security.Claims;

namespace PolyAuth;

/// <summary>Describes which grant produced the principal being enriched.</summary>
public enum PrincipalEnrichmentGrant
{
    FirebaseTokenExchange,
    ClientCredentials,
    AuthorizationCode
}

/// <summary>Context handed to <see cref="IPolyAuthPrincipalEnricher"/> before tokens are issued.</summary>
public sealed class PrincipalEnrichmentContext
{
    public PrincipalEnrichmentContext(ClaimsPrincipal principal, PrincipalEnrichmentGrant grant, string? clientId)
    {
        Principal = principal;
        Grant = grant;
        ClientId = clientId;
    }

    /// <summary>The principal that will back the issued tokens. Add claims here.</summary>
    public ClaimsPrincipal Principal { get; }

    public PrincipalEnrichmentGrant Grant { get; }

    public string? ClientId { get; }
}

/// <summary>
/// Optional hook so a consuming app can add its own claims (for example an account id) to issued
/// tokens. Add claims to <see cref="PrincipalEnrichmentContext.Principal"/>; PolyAuth re-applies
/// token destinations afterwards. The default registration is a no-op.
/// </summary>
public interface IPolyAuthPrincipalEnricher
{
    ValueTask EnrichAsync(PrincipalEnrichmentContext context, CancellationToken ct = default);
}

internal sealed class NoOpPrincipalEnricher : IPolyAuthPrincipalEnricher
{
    public ValueTask EnrichAsync(PrincipalEnrichmentContext context, CancellationToken ct = default)
        => ValueTask.CompletedTask;
}

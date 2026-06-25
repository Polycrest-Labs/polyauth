using System.Text.Json.Serialization;

namespace PolyAuth.OAuth;

/// <summary>A client-id metadata document (CIMD / DCR-by-URL) fetched from an HTTPS client_id.</summary>
public sealed class OAuthClientMetadataDocument
{
    [JsonPropertyName("client_id")]
    public string? ClientId { get; init; }

    [JsonPropertyName("client_name")]
    public string? ClientName { get; init; }

    [JsonPropertyName("redirect_uris")]
    public List<string> RedirectUris { get; init; } = [];

    [JsonPropertyName("grant_types")]
    public List<string> GrantTypes { get; init; } = [];

    [JsonPropertyName("response_types")]
    public List<string> ResponseTypes { get; init; } = [];

    [JsonPropertyName("token_endpoint_auth_method")]
    public string? TokenEndpointAuthMethod { get; init; }

    [JsonPropertyName("token_endpoint_auth_signing_alg")]
    public string? TokenEndpointAuthSigningAlg { get; init; }

    [JsonPropertyName("jwks_uri")]
    public string? JwksUri { get; init; }

    [JsonPropertyName("client_uri")]
    public string? ClientUri { get; init; }

    [JsonPropertyName("logo_uri")]
    public string? LogoUri { get; init; }

    [JsonPropertyName("scope")]
    public string? Scope { get; init; }
}

/// <summary>Raised when a CIMD metadata document is missing, malformed, or fails validation.</summary>
public sealed class OAuthClientMetadataException : Exception
{
    public OAuthClientMetadataException(string message) : base(message)
    {
    }
}

using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.Tokens;
using OpenIddict.Abstractions;

namespace PolyAuth.OAuth;

/// <summary>Fetches, validates, caches, and materializes CIMD (DCR-by-URL) clients into the OpenIddict store.</summary>
public interface IOAuthClientMetadataService
{
    Task<OAuthClientMetadataDocument> GetValidatedMetadataAsync(OpenIddictRequest request, CancellationToken ct);
    Task EnsureOpenIddictClientAsync(OpenIddictRequest request, CancellationToken ct);
}

public sealed class OAuthClientMetadataService : IOAuthClientMetadataService
{
    public const string HttpClientName = "PolyAuth.OAuthClientMetadata";
    private const int MaxMetadataBytes = 64 * 1024;
    private const int MaxJwksBytes = 64 * 1024;
    private static readonly TimeSpan DefaultCacheDuration = TimeSpan.FromMinutes(5);
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web);

    private readonly IHttpClientFactory _httpClientFactory;
    private readonly IMemoryCache _cache;
    private readonly IOpenIddictApplicationManager _applicationManager;
    private readonly ILogger<OAuthClientMetadataService> _logger;

    public OAuthClientMetadataService(
        IHttpClientFactory httpClientFactory,
        IMemoryCache cache,
        IOpenIddictApplicationManager applicationManager,
        ILogger<OAuthClientMetadataService> logger)
    {
        _httpClientFactory = httpClientFactory;
        _cache = cache;
        _applicationManager = applicationManager;
        _logger = logger;
    }

    public async Task<OAuthClientMetadataDocument> GetValidatedMetadataAsync(OpenIddictRequest request, CancellationToken ct)
    {
        var clientId = request.ClientId;
        if (string.IsNullOrWhiteSpace(clientId))
        {
            throw new OAuthClientMetadataException("The authorization request is missing client_id.");
        }

        var requestedScopes = request.GetScopes().ToHashSet(StringComparer.Ordinal);
        var document = await GetMetadataAsync(clientId, ct);
        var validationError = OAuthClientMetadataRules.Validate(document, clientId, request.RedirectUri, requestedScopes);
        if (validationError != null)
        {
            throw new OAuthClientMetadataException(validationError);
        }

        return document;
    }

    public async Task EnsureOpenIddictClientAsync(OpenIddictRequest request, CancellationToken ct)
    {
        var document = await GetValidatedMetadataAsync(request, ct);
        var requestedScopes = request.GetScopes().ToHashSet(StringComparer.Ordinal);
        var jsonWebKeySet = OAuthClientMetadataRules.UsesPrivateKeyJwt(document)
            ? await GetJsonWebKeySetAsync(document.JwksUri!, ct)
            : null;
        var descriptor = OAuthClientMetadataRules.CreateApplicationDescriptor(
            document, requestedScopes, jsonWebKeySet, request.GetResources());

        var existing = await _applicationManager.FindByClientIdAsync(document.ClientId!, ct);
        if (existing == null)
        {
            await _applicationManager.CreateAsync(descriptor, ct);
            _logger.LogInformation("Created CIMD OpenIddict client {ClientId}", document.ClientId);
            return;
        }

        await _applicationManager.UpdateAsync(existing, descriptor, ct);
        _logger.LogInformation("Updated CIMD OpenIddict client {ClientId}", document.ClientId);
    }

    private async Task<OAuthClientMetadataDocument> GetMetadataAsync(string clientId, CancellationToken ct)
    {
        var clientIdError = OAuthClientMetadataRules.ValidateClientMetadataDocumentId(clientId);
        if (clientIdError != null)
        {
            throw new OAuthClientMetadataException(clientIdError);
        }

        var cacheKey = $"{nameof(OAuthClientMetadataService)}:{clientId}";
        if (_cache.TryGetValue(cacheKey, out OAuthClientMetadataDocument? cached) && cached != null)
        {
            return cached;
        }

        using var request = new HttpRequestMessage(HttpMethod.Get, clientId);
        request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));

        using var response = await _httpClientFactory
            .CreateClient(HttpClientName)
            .SendAsync(request, HttpCompletionOption.ResponseHeadersRead, ct);

        if (!response.IsSuccessStatusCode)
        {
            throw new OAuthClientMetadataException("The CIMD metadata document could not be fetched.");
        }

        if (!IsJson(response.Content.Headers.ContentType?.MediaType))
        {
            throw new OAuthClientMetadataException("The CIMD metadata document response must be JSON.");
        }

        if (response.Content.Headers.ContentLength > MaxMetadataBytes)
        {
            throw new OAuthClientMetadataException("The CIMD metadata document is too large.");
        }

        var bytes = await response.Content.ReadAsByteArrayAsync(ct);
        if (bytes.Length > MaxMetadataBytes)
        {
            throw new OAuthClientMetadataException("The CIMD metadata document is too large.");
        }

        OAuthClientMetadataDocument? document;
        try
        {
            document = JsonSerializer.Deserialize<OAuthClientMetadataDocument>(bytes, JsonOptions);
        }
        catch (JsonException ex)
        {
            throw new OAuthClientMetadataException($"The CIMD metadata document contains invalid JSON: {ex.Message}");
        }

        var validationError = OAuthClientMetadataRules.Validate(
            document, clientId, redirectUri: null, requestedScopes: new HashSet<string>(StringComparer.Ordinal));
        if (validationError != null && !validationError.Contains("redirect_uri", StringComparison.Ordinal))
        {
            throw new OAuthClientMetadataException(validationError);
        }

        if (document == null)
        {
            throw new OAuthClientMetadataException("The CIMD metadata document could not be parsed.");
        }

        var cacheDuration = GetCacheDuration(response.Headers.CacheControl, response.Content.Headers.Expires);
        if (cacheDuration > TimeSpan.Zero)
        {
            _cache.Set(cacheKey, document, cacheDuration);
        }

        return document;
    }

    private async Task<JsonWebKeySet> GetJsonWebKeySetAsync(string jwksUri, CancellationToken ct)
    {
        var cacheKey = $"{nameof(OAuthClientMetadataService)}:jwks:{jwksUri}";
        if (_cache.TryGetValue(cacheKey, out JsonWebKeySet? cached) && cached != null)
        {
            return cached;
        }

        using var request = new HttpRequestMessage(HttpMethod.Get, jwksUri);
        request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));

        using var response = await _httpClientFactory
            .CreateClient(HttpClientName)
            .SendAsync(request, HttpCompletionOption.ResponseHeadersRead, ct);

        if (!response.IsSuccessStatusCode)
        {
            throw new OAuthClientMetadataException("The CIMD jwks_uri document could not be fetched.");
        }

        if (!IsJson(response.Content.Headers.ContentType?.MediaType))
        {
            throw new OAuthClientMetadataException("The CIMD jwks_uri response must be JSON.");
        }

        if (response.Content.Headers.ContentLength > MaxJwksBytes)
        {
            throw new OAuthClientMetadataException("The CIMD jwks_uri document is too large.");
        }

        var json = await response.Content.ReadAsStringAsync(ct);
        if (Encoding.UTF8.GetByteCount(json) > MaxJwksBytes)
        {
            throw new OAuthClientMetadataException("The CIMD jwks_uri document is too large.");
        }

        JsonWebKeySet jsonWebKeySet;
        try
        {
            jsonWebKeySet = new JsonWebKeySet(json);
        }
        catch (ArgumentException ex)
        {
            throw new OAuthClientMetadataException($"The CIMD jwks_uri document contains invalid JSON Web Keys: {ex.Message}");
        }

        if (jsonWebKeySet.Keys.Count == 0)
        {
            throw new OAuthClientMetadataException("The CIMD jwks_uri document must contain at least one key.");
        }

        var cacheDuration = GetCacheDuration(response.Headers.CacheControl, response.Content.Headers.Expires);
        if (cacheDuration > TimeSpan.Zero)
        {
            _cache.Set(cacheKey, jsonWebKeySet, cacheDuration);
        }

        return jsonWebKeySet;
    }

    private static bool IsJson(string? mediaType)
        => string.Equals(mediaType, "application/json", StringComparison.OrdinalIgnoreCase)
           || mediaType?.EndsWith("+json", StringComparison.OrdinalIgnoreCase) == true;

    private static TimeSpan GetCacheDuration(CacheControlHeaderValue? cacheControl, DateTimeOffset? expires)
    {
        if (cacheControl?.NoStore == true)
        {
            return TimeSpan.Zero;
        }

        if (cacheControl?.MaxAge is { } maxAge && maxAge > TimeSpan.Zero)
        {
            return maxAge;
        }

        if (expires is { } expiresAt)
        {
            var duration = expiresAt - DateTimeOffset.UtcNow;
            if (duration > TimeSpan.Zero)
            {
                return duration;
            }
        }

        return DefaultCacheDuration;
    }
}

namespace PolyAuth;

/// <summary>
/// Root configuration for PolyAuth. Bound from the configuration section named
/// <c>PolyAuth</c> and then refined by the optional configure delegate passed to
/// <c>AddPolyAuth</c>.
/// </summary>
public sealed class PolyAuthOptions
{
    /// <summary>Human login via Firebase email/password (ID-token bearer auth on the API).</summary>
    public FirebaseOptions Firebase { get; } = new();

    /// <summary>The OpenIddict OAuth 2.1 Authorization Server.</summary>
    public OAuthServerOptions OAuth { get; } = new();

    /// <summary>MCP authorization (resource metadata + the <c>/mcp</c> protected resource).</summary>
    public McpAuthOptions Mcp { get; } = new();
}

/// <summary>Firebase human-login options.</summary>
public sealed class FirebaseOptions
{
    /// <summary>Enables the Firebase bearer authentication scheme.</summary>
    public bool Enabled { get; set; }

    /// <summary>The Firebase project id. Required when <see cref="Enabled"/> is true.</summary>
    public string? ProjectId { get; set; }

    /// <summary>
    /// The Firebase Admin service-account credential, as raw JSON or base64-encoded JSON.
    /// Required for token-exchange and test-user provisioning.
    /// </summary>
    public string? ServiceAccountJson { get; set; }

    /// <summary>Optional distinct name for the underlying FirebaseApp instance.</summary>
    public string AppName { get; set; } = "polyauth";
}

/// <summary>OpenIddict Authorization Server options.</summary>
public sealed class OAuthServerOptions
{
    /// <summary>Enables the OAuth Authorization Server (OpenIddict Core + Server + Validation).</summary>
    public bool Enabled { get; set; }

    /// <summary>Public HTTPS base URL of the API. Required outside Development.</summary>
    public string? Issuer { get; set; }

    public CertificateOptions SigningCertificate { get; set; } = new();
    public CertificateOptions EncryptionCertificate { get; set; } = new();

    public int AccessTokenLifetimeMinutes { get; set; } = 60;
    public int RefreshTokenLifetimeDays { get; set; } = 14;

    /// <summary>The persistence backing the OpenIddict store (Mongo by default, or SQL Server).</summary>
    public StoreOptions Store { get; set; } = new();

    /// <summary>Grantable scopes beyond the built-in <c>api.*</c>/<c>mcp.*</c> set.</summary>
    public ScopeOptions Scopes { get; set; } = new();

    /// <summary>The first-party UI client id permitted to use the Firebase token-exchange grant.</summary>
    public string UiClientId { get; set; } = "polyauth-ui";

    /// <summary>
    /// SPA route the library's <c>/connect/authorize</c> endpoint redirects unauthenticated users to.
    /// The sign-in page must establish the OAuth session (POST <c>/api/oauth/session</c>) and then navigate
    /// back to the supplied <c>returnUrl</c>. Default <c>/sign-in</c>.
    /// </summary>
    public string SignInPath { get; set; } = "/sign-in";

    /// <summary>Statically configured clients (e.g. loopback clients for Claude Desktop).</summary>
    public IList<OAuthStaticClientOptions> StaticClients { get; } = new List<OAuthStaticClientOptions>();

    /// <summary>Baseline: ChatGPT DCR-by-URL (client-id metadata document) support.</summary>
    public bool EnableUrlClientMetadata { get; set; } = true;

    /// <summary>Baseline: Claude Desktop loopback (127.0.0.1 / localhost) redirect URIs.</summary>
    public bool EnableLoopbackRedirects { get; set; } = true;

    /// <summary>Optional extension: private_key_jwt client authentication.</summary>
    public bool EnableClientAssertion { get; set; }

    /// <summary>Optional extension: token-endpoint diagnostics logging.</summary>
    public bool EnableDiagnostics { get; set; }

    /// <summary>
    /// Bring-your-own-identity session bridge: gates <c>POST /api/oauth/session</c> (which converts an
    /// authenticated bearer principal into the interactive <c>OAuthSession</c> cookie) by any configured
    /// authentication scheme instead of only Firebase. Defaults preserve today's behavior: the endpoint
    /// maps when Firebase is enabled and authenticates with the Firebase scheme.
    /// </summary>
    public SessionBridgeOptions SessionBridge { get; set; } = new();
}

/// <summary>Options for the bring-your-own-identity session bridge.</summary>
public sealed class SessionBridgeOptions
{
    /// <summary>
    /// Whether <c>POST /api/oauth/session</c> is mapped. When null (the default) the endpoint follows
    /// <c>Firebase.Enabled</c>, exactly as before this option existed.
    /// </summary>
    public bool? Enabled { get; set; }

    /// <summary>
    /// The authentication schemes that may establish an OAuth session (e.g. the consuming app's own
    /// JwtBearer scheme). When null/empty the Firebase scheme is used.
    /// </summary>
    public string[]? AuthenticationSchemes { get; set; }
}

/// <summary>Resolves the effective session-bridge gating from the configured options.</summary>
internal static class SessionBridgeGating
{
    /// <summary>Whether <c>POST /api/oauth/session</c> should be mapped.</summary>
    public static bool IsEnabled(PolyAuthOptions options)
        => options.OAuth.SessionBridge.Enabled ?? options.Firebase.Enabled;

    /// <summary>The authentication schemes gating the endpoint (Firebase when none are configured).</summary>
    public static string[] ResolveSchemes(PolyAuthOptions options)
        => options.OAuth.SessionBridge.AuthenticationSchemes is { Length: > 0 } configured
            ? configured
            : [AuthSchemes.Firebase];
}

/// <summary>MCP authorization options.</summary>
public sealed class McpAuthOptions
{
    /// <summary>Enables MCP resource-metadata discovery and the <c>/mcp</c> challenge.</summary>
    public bool Enabled { get; set; }

    /// <summary>Public base URL used as the resource indicator for <c>/mcp</c>. Defaults to Issuer.</summary>
    public string? McpBaseUrl { get; set; }

    /// <summary>Public base URL of the MCP-UI (widget) host, used when building widget HTML.</summary>
    public string? WidgetHostBaseUrl { get; set; }
}

/// <summary>A signing or encryption certificate source (base64 or path + optional password).</summary>
public sealed class CertificateOptions
{
    public string? Base64 { get; set; }
    public string? Path { get; set; }
    public string? Password { get; set; }

    public bool IsConfigured => !string.IsNullOrWhiteSpace(Base64) || !string.IsNullOrWhiteSpace(Path);
}

/// <summary>The connection used by the OpenIddict store.</summary>
public sealed class StoreOptions
{
    /// <summary>Store provider: <c>"Mongo"</c> (the default, Cosmos-for-Mongo compatible) or <c>"SqlServer"</c>.</summary>
    public string Provider { get; set; } = StoreProviders.Mongo;

    public string? ConnectionString { get; set; }

    /// <summary>Mongo only — ignored by the SqlServer provider (the database is part of the connection string).</summary>
    public string? DatabaseName { get; set; }
}

/// <summary>The supported <see cref="StoreOptions.Provider"/> values.</summary>
public static class StoreProviders
{
    public const string Mongo = "Mongo";
    public const string SqlServer = "SqlServer";
}

/// <summary>Additional grantable scopes beyond the built-in api.*/mcp.* set.</summary>
public sealed class ScopeOptions
{
    public IList<string> Additional { get; } = new List<string>();
}

/// <summary>A statically configured OAuth client (for example a Claude Desktop loopback client).</summary>
public sealed class OAuthStaticClientOptions
{
    public string ClientId { get; set; } = string.Empty;
    public string ClientName { get; set; } = string.Empty;
    public IList<string> RedirectUris { get; set; } = new List<string>();
    public IList<string> PostLogoutRedirectUris { get; set; } = new List<string>();
    public bool AllowLoopbackRedirectUris { get; set; }
    public IList<string> AllowedLoopbackRedirectPaths { get; set; } = new List<string>();
    public IList<string> Scopes { get; set; } = new List<string>();
}

using OpenIddict.Validation.AspNetCore;

namespace PolyAuth;

/// <summary>The OAuth scopes PolyAuth issues and enforces.</summary>
public static class AuthScopes
{
    public const string ApiRead = "api.read";
    public const string ApiWrite = "api.write";
    public const string McpRead = "mcp.read";
    public const string McpWrite = "mcp.write";

    /// <summary>Every built-in scope the server registers and the client-credentials grant may issue.</summary>
    public static readonly string[] Grantable = [ApiRead, ApiWrite, McpRead, McpWrite];
}

/// <summary>Authorization policy names registered by PolyAuth. Use with <c>[Authorize(Policy = ...)]</c>.</summary>
public static class AuthPolicies
{
    public const string ApiRead = "api.read";
    public const string ApiWrite = "api.write";
    public const string McpRead = "mcp.read";
    public const string McpWrite = "mcp.write";

    /// <summary>Requires a Firebase-authenticated user (the bootstrap scheme), no scope check.</summary>
    public const string FirebaseUser = "polyauth.firebase";
}

/// <summary>Authentication scheme names registered by PolyAuth.</summary>
public static class AuthSchemes
{
    public const string Firebase = "Firebase";
    public const string OAuthSession = "OAuthSession";

    /// <summary>The OpenIddict validation scheme that protects the API and MCP endpoints.</summary>
    public const string OAuthValidation = OpenIddictValidationAspNetCoreDefaults.AuthenticationScheme;
}

/// <summary>Resource indicators and the custom grant for the Firebase token exchange.</summary>
public static class PolyAuthConstants
{
    /// <summary>The custom OAuth grant_type that exchanges a Firebase ID token for OAuth tokens.</summary>
    public const string FirebaseTokenExchangeGrantType = "urn:polyauth:firebase";

    /// <summary>The token-request parameter carrying the Firebase ID token.</summary>
    public const string FirebaseIdTokenParameter = "firebase_id_token";

    /// <summary>The internal API resource indicator.</summary>
    public const string ApiResource = "polyauth-api";

    /// <summary>The internal MCP resource indicator.</summary>
    public const string McpResource = "polyauth-mcp";
}

namespace PolyAuth;

/// <summary>Fail-fast validation of <see cref="PolyAuthOptions"/> with clear, actionable messages.</summary>
internal static class PolyAuthConfigValidation
{
    public static void Validate(PolyAuthOptions options, bool isDevelopment)
    {
        if (options.Firebase.Enabled && string.IsNullOrWhiteSpace(options.Firebase.ServiceAccountJson) && !isDevelopment)
        {
            throw new InvalidOperationException(
                "PolyAuth:Firebase:ServiceAccountJson is required when Firebase is enabled (outside Development, where application default credentials may be used).");
        }

        if (!options.OAuth.Enabled)
        {
            return;
        }

        var oauth = options.OAuth;

        if (string.IsNullOrWhiteSpace(oauth.Store.ConnectionString))
        {
            throw new InvalidOperationException("PolyAuth:OAuth:Store:ConnectionString is required when OAuth is enabled.");
        }

        if (string.IsNullOrWhiteSpace(oauth.Store.DatabaseName))
        {
            throw new InvalidOperationException("PolyAuth:OAuth:Store:DatabaseName is required when OAuth is enabled.");
        }

        if (!isDevelopment)
        {
            if (string.IsNullOrWhiteSpace(oauth.Issuer))
            {
                throw new InvalidOperationException("PolyAuth:OAuth:Issuer is required outside Development.");
            }

            if (!oauth.SigningCertificate.IsConfigured)
            {
                throw new InvalidOperationException(
                    "PolyAuth:OAuth:SigningCertificate (Base64 or Path) is required outside Development.");
            }

            if (!oauth.EncryptionCertificate.IsConfigured)
            {
                throw new InvalidOperationException(
                    "PolyAuth:OAuth:EncryptionCertificate (Base64 or Path) is required outside Development.");
            }

            // Resource indicators must resolve to absolute HTTPS URLs.
            var resources = PolyAuth.OAuth.OAuthResourceIndicators.GetPublicResourceIndicators(oauth, options.Mcp);
            if (resources.Length == 0)
            {
                throw new InvalidOperationException(
                    "PolyAuth resource indicators could not be built. Configure PolyAuth:OAuth:Issuer or PolyAuth:Mcp:McpBaseUrl with the public HTTPS base URL.");
            }
        }

        if (options.Firebase.Enabled && string.IsNullOrWhiteSpace(options.Firebase.ServiceAccountJson) && !isDevelopment)
        {
            throw new InvalidOperationException(
                "PolyAuth:Firebase:ServiceAccountJson is required for the Firebase token-exchange grant.");
        }
    }
}

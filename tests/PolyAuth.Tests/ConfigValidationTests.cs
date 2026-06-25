using Xunit;

namespace PolyAuth.Tests;

public sealed class ConfigValidationTests
{
    private static PolyAuthOptions OAuthOptions(Action<PolyAuthOptions> configure)
    {
        var options = new PolyAuthOptions();
        options.OAuth.Enabled = true;
        options.OAuth.Store.ConnectionString = "mongodb://localhost:27017";
        options.OAuth.Store.DatabaseName = "db";
        options.OAuth.Issuer = "https://example.com";
        options.OAuth.SigningCertificate.Base64 = "x";
        options.OAuth.EncryptionCertificate.Base64 = "x";
        configure(options);
        return options;
    }

    [Fact]
    public void Missing_store_connection_string_throws()
    {
        var options = OAuthOptions(o => o.OAuth.Store.ConnectionString = null);
        var ex = Assert.Throws<InvalidOperationException>(() => PolyAuthConfigValidation.Validate(options, isDevelopment: false));
        Assert.Contains("Store:ConnectionString", ex.Message);
    }

    [Fact]
    public void Missing_issuer_outside_development_throws()
    {
        var options = OAuthOptions(o => o.OAuth.Issuer = null);
        var ex = Assert.Throws<InvalidOperationException>(() => PolyAuthConfigValidation.Validate(options, isDevelopment: false));
        Assert.Contains("Issuer", ex.Message);
    }

    [Fact]
    public void Missing_signing_cert_outside_development_throws()
    {
        var options = OAuthOptions(o => o.OAuth.SigningCertificate.Base64 = null);
        var ex = Assert.Throws<InvalidOperationException>(() => PolyAuthConfigValidation.Validate(options, isDevelopment: false));
        Assert.Contains("SigningCertificate", ex.Message);
    }

    [Fact]
    public void Development_allows_missing_issuer_and_certs()
    {
        var options = new PolyAuthOptions();
        options.OAuth.Enabled = true;
        options.OAuth.Store.ConnectionString = "mongodb://localhost:27017";
        options.OAuth.Store.DatabaseName = "db";

        // Should not throw in Development.
        PolyAuthConfigValidation.Validate(options, isDevelopment: true);
    }

    [Fact]
    public void Disabled_oauth_skips_oauth_validation()
    {
        var options = new PolyAuthOptions();
        PolyAuthConfigValidation.Validate(options, isDevelopment: false);
    }
}

using PolyAuth.OAuth;
using Xunit;

namespace PolyAuth.Tests;

public sealed class CertificateLoaderTests
{
    [Fact]
    public void Load_from_base64_without_password_succeeds()
    {
        var options = new CertificateOptions { Base64 = TestCertificates.CreateBase64Pfx() };
        using var cert = CertificateLoader.Load(options, "Test:Cert");
        Assert.NotNull(cert);
        Assert.True(cert.HasPrivateKey);
    }

    [Fact]
    public void Load_from_base64_with_password_succeeds()
    {
        var options = new CertificateOptions { Base64 = TestCertificates.CreateBase64Pfx("p@ss"), Password = "p@ss" };
        using var cert = CertificateLoader.Load(options, "Test:Cert");
        Assert.True(cert.HasPrivateKey);
    }

    [Fact]
    public void Load_with_invalid_base64_throws_clear_error()
    {
        var options = new CertificateOptions { Base64 = "not-valid-base64!!!" };
        var ex = Assert.Throws<InvalidOperationException>(() => CertificateLoader.Load(options, "Test:Cert"));
        Assert.Contains("Test:Cert", ex.Message);
    }

    [Fact]
    public void Load_with_no_source_throws()
    {
        var ex = Assert.Throws<InvalidOperationException>(() => CertificateLoader.Load(new CertificateOptions(), "Test:Cert"));
        Assert.Contains("Base64 or Path", ex.Message);
    }
}

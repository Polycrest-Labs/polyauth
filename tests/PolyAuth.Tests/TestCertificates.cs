using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace PolyAuth.Tests;

internal static class TestCertificates
{
    /// <summary>Creates a self-signed RSA certificate and returns it as a base64 PKCS#12 blob.</summary>
    public static string CreateBase64Pfx(string? password = null)
    {
        using var rsa = RSA.Create(2048);
        var request = new CertificateRequest("CN=PolyAuth Test", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using var cert = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(1));
        var bytes = cert.Export(X509ContentType.Pkcs12, password);
        return Convert.ToBase64String(bytes);
    }
}

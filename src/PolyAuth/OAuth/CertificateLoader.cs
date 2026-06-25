using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace PolyAuth.OAuth;

/// <summary>Loads PKCS#12 signing/encryption certificates from base64 or a file path (with optional password).</summary>
public static class CertificateLoader
{
    public static X509Certificate2 Load(CertificateOptions options, string configurationSection)
    {
        if (!string.IsNullOrWhiteSpace(options.Base64))
        {
            return LoadFromBase64(options, configurationSection);
        }

        if (string.IsNullOrWhiteSpace(options.Path))
        {
            throw new InvalidOperationException($"{configurationSection} requires Base64 or Path.");
        }

        var fullPath = System.IO.Path.GetFullPath(options.Path);
        if (!File.Exists(fullPath))
        {
            throw new InvalidOperationException($"{configurationSection}:Path points to '{fullPath}', but the file does not exist.");
        }

        return string.IsNullOrWhiteSpace(options.Password)
            ? X509CertificateLoader.LoadPkcs12FromFile(fullPath, null)
            : X509CertificateLoader.LoadPkcs12FromFile(fullPath, options.Password);
    }

    private static X509Certificate2 LoadFromBase64(CertificateOptions options, string configurationSection)
    {
        try
        {
            var bytes = Convert.FromBase64String(options.Base64!);
            return string.IsNullOrWhiteSpace(options.Password)
                ? X509CertificateLoader.LoadPkcs12(bytes, null)
                : X509CertificateLoader.LoadPkcs12(bytes, options.Password);
        }
        catch (FormatException ex)
        {
            throw new InvalidOperationException($"{configurationSection}:Base64 is not valid base64-encoded certificate data.", ex);
        }
        catch (CryptographicException ex)
        {
            throw new InvalidOperationException($"{configurationSection}:Base64 could not be loaded as a PKCS#12 certificate.", ex);
        }
    }
}

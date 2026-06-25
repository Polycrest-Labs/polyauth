# Generates self-signed signing + encryption certificates for the PolyAuth OAuth server and prints the
# azd env-set lines (base64 app settings). Windows-friendly: uses .NET directly, no OpenSSL required.
#
#   pwsh ./scripts/generate-certs.ps1            # print azd env set lines
#   pwsh ./scripts/generate-certs.ps1 -OutDir ./certs   # also write the .pfx files

param([string]$OutDir)

function New-PfxBase64([string]$cn, [string]$outPath) {
    $rsa = [System.Security.Cryptography.RSA]::Create(2048)
    try {
        $req = [System.Security.Cryptography.X509Certificates.CertificateRequest]::new(
            "CN=$cn", $rsa,
            [System.Security.Cryptography.HashAlgorithmName]::SHA256,
            [System.Security.Cryptography.RSASignaturePadding]::Pkcs1)
        $cert = $req.CreateSelfSigned([DateTimeOffset]::UtcNow.AddDays(-1), [DateTimeOffset]::UtcNow.AddYears(10))
        $bytes = $cert.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Pkcs12)
        if ($outPath) { [System.IO.File]::WriteAllBytes($outPath, $bytes) }
        return [Convert]::ToBase64String($bytes)
    } finally { $rsa.Dispose() }
}

if ($OutDir) { New-Item -ItemType Directory -Force -Path $OutDir | Out-Null }
$signPath = if ($OutDir) { Join-Path $OutDir 'signing.pfx' } else { $null }
$encPath  = if ($OutDir) { Join-Path $OutDir 'encryption.pfx' } else { $null }

$sign = New-PfxBase64 'PolyAuth-signing' $signPath
$enc  = New-PfxBase64 'PolyAuth-encryption' $encPath

# These names match sample/infra/main.parameters.json (${POLYAUTH_SIGNING_CERT_B64} / ${POLYAUTH_ENCRYPTION_CERT_B64}),
# which Bicep maps to the PolyAuth__OAuth__*Certificate__Base64 app settings.
Write-Output "# Run from the sample/ directory (where azure.yaml lives), then 'azd up':"
Write-Output "azd env set POLYAUTH_SIGNING_CERT_B64 $sign"
Write-Output "azd env set POLYAUTH_ENCRYPTION_CERT_B64 $enc"

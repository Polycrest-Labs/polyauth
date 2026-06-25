#!/usr/bin/env bash
# Generates self-signed signing + encryption certificates for the PolyAuth OAuth server and prints the
# azd env-set lines (base64 app settings). Uses OpenSSL with legacy PKCS#12 algorithms for maximum
# X509CertificateLoader compatibility.
#
#   ./scripts/generate-certs.sh            # writes ./certs/*.pfx and prints azd env set lines
#   ./scripts/generate-certs.sh /tmp/c     # use a different output dir
set -euo pipefail
OUT="${1:-./certs}"
mkdir -p "$OUT"

for kind in signing encryption; do
  # MSYS_NO_PATHCONV stops Git Bash from mangling the -subj "/CN=..." into a Windows path.
  MSYS_NO_PATHCONV=1 openssl req -x509 -newkey rsa:2048 -nodes -days 3650 \
    -keyout "$OUT/$kind.key" -out "$OUT/$kind.crt" -subj "/CN=PolyAuth-$kind" >/dev/null 2>&1
  openssl pkcs12 -export -out "$OUT/$kind.pfx" -inkey "$OUT/$kind.key" -in "$OUT/$kind.crt" -passout pass: \
    -legacy -keypbe PBE-SHA1-3DES -certpbe PBE-SHA1-3DES -macalg sha1 >/dev/null 2>&1
done

SIGN_B64=$(base64 -w0 "$OUT/signing.pfx")
ENC_B64=$(base64 -w0 "$OUT/encryption.pfx")

# These names match sample/infra/main.parameters.json (${POLYAUTH_SIGNING_CERT_B64} / ${POLYAUTH_ENCRYPTION_CERT_B64}),
# which Bicep maps to the PolyAuth__OAuth__*Certificate__Base64 app settings.
echo "# Run from the sample/ directory (where azure.yaml lives), then 'azd up':"
echo "azd env set POLYAUTH_SIGNING_CERT_B64 $SIGN_B64"
echo "azd env set POLYAUTH_ENCRYPTION_CERT_B64 $ENC_B64"

#!/usr/bin/env sh
# Local-development TLS only. The private key is intentionally Git-ignored.
set -eu
umask 077
output_dir="${1:-secrets/tls}"
if [ -e "$output_dir/dev-cert.pem" ] || [ -e "$output_dir/dev-key.pem" ]; then
  echo "Refusing to overwrite existing development certificate material" >&2
  exit 1
fi
mkdir -p "$output_dir"
openssl req -x509 -newkey rsa:4096 -sha256 -nodes -days 30 \
  -keyout "$output_dir/dev-key.pem" \
  -out "$output_dir/dev-cert.pem" \
  -subj "/CN=localhost" \
  -addext "subjectAltName=DNS:localhost,IP:127.0.0.1"
chmod 600 "$output_dir/dev-key.pem"
chmod 644 "$output_dir/dev-cert.pem"
echo "Created local-only certificate in $output_dir (trust warning is expected)."

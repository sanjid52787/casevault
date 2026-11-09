#!/usr/bin/env sh
# Generate a development Tink AES-GCM keyset; never commit the resulting file.
set -eu
mkdir -p secrets
echo "Use the CaseVault keyset generator in deployment tooling; set TINK_KEYSET_PATH to the generated secret path."
echo "This placeholder intentionally does not emit key material from shell into repository files."

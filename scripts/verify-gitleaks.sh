#!/usr/bin/env sh
set -eu
command -v gitleaks >/dev/null 2>&1 || { echo "gitleaks is not installed" >&2; exit 2; }
tmp_dir="$(mktemp -d)"
trap 'rm -rf "$tmp_dir"' EXIT
# Split the marker so the repository itself never contains a matching secret pattern.
printf '%s%s\n' 'CASEVAULT_TEST_FAKE_SECRET_' '0123456789ABCDEF' > "$tmp_dir/fake-secret.txt"
if gitleaks detect --no-git --source "$tmp_dir" --config .gitleaks.toml --redact >/dev/null 2>&1; then
  echo "gitleaks did not flag the deliberately fake temporary marker" >&2
  exit 1
fi
echo "gitleaks temporary-marker self-test passed"

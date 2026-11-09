#!/usr/bin/env sh
# Read-only local smoke checks supporting the manual-testing guide. No exploit payload
# is sent to a third party and no credential is embedded in this script.
set -eu
target="${CASEVAULT_TARGET:-https://localhost}"
case "$target" in https://localhost*|https://127.0.0.1*) ;; *) echo "Local target only" >&2; exit 64;; esac

echo "[headers]"
curl --fail --silent --show-error --insecure -D - -o /dev/null "$target/login" | \
  grep -Ei '^(content-security-policy|x-content-type-options|x-frame-options|referrer-policy|permissions-policy|strict-transport-security):'
echo "[health]"
curl --fail --silent --show-error --insecure "$target/actuator/health"
echo "[actuator exposure]"
test "$(curl --silent --insecure -o /dev/null -w '%{http_code}' "$target/actuator/env")" = "401" || \
  test "$(curl --silent --insecure -o /dev/null -w '%{http_code}' "$target/actuator/env")" = "404"
echo "Manual smoke checks completed. Follow docs/assurance/manual-testing.md for authenticated checks."

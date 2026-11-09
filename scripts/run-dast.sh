#!/usr/bin/env sh
# Runs ZAP only against the explicitly authorised local CaseVault stack.
# Credentials are supplied at execution time and are never written to Git or reports.
set -eu

target="${ZAP_TARGET:-https://localhost}"
date_stamp="$(date +%F)"
output_dir="${ZAP_OUTPUT_DIR:-docs/assurance/results/${date_stamp}/zap}"
zap_image="${ZAP_IMAGE:-ghcr.io/zaproxy/zaproxy:stable}"

case "$target" in
  https://localhost*|https://127.0.0.1*) ;;
  *) echo "Refusing DAST target outside the authorised local stack: $target" >&2; exit 64 ;;
esac

command -v docker >/dev/null || { echo "Docker is required for the official ZAP image." >&2; exit 69; }
mkdir -p "$output_dir"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT INT TERM

# Baseline scan is intentionally unauthenticated: it checks public surface/configuration.
# It does not suppress alerts: the HTML/JSON/XML reports remain the review evidence.
docker run --rm --network host -v "$(pwd)/$output_dir:/zap/wrk:rw" "$zap_image" \
  zap-baseline.py -t "$target" -m 3 -r baseline.html -J baseline.json -x baseline.xml

# Optional authenticated spider/active scan. The synthetic credentials must be passed in
# environment variables; they are used only for a local login and removed with $work.
if [ "${ZAP_AUTHENTICATED:-false}" = "true" ]; then
  : "${ZAP_SYNTHETIC_USERNAME:?Set a synthetic local username}"
  : "${ZAP_SYNTHETIC_PASSWORD:?Set a synthetic local password}"
  jar="$work/cookies.txt"
  login_page="$work/login.html"
  curl --fail --silent --show-error --insecure --cookie-jar "$jar" "$target/login" -o "$login_page"
  csrf="$(sed -n 's/.*name="_csrf"[^>]*value="\([^"]*\)".*/\1/p' "$login_page" | head -n 1)"
  [ -n "$csrf" ] || { echo "Could not obtain a CSRF token from local login page." >&2; exit 65; }
  curl --fail --silent --show-error --insecure --location --cookie "$jar" --cookie-jar "$jar" \
    --data-urlencode "username=$ZAP_SYNTHETIC_USERNAME" \
    --data-urlencode "password=$ZAP_SYNTHETIC_PASSWORD" \
    --data-urlencode "_csrf=$csrf" "$target/login" -o /dev/null
  session="$(awk '$6 == "SESSION" { print $7 }' "$jar" | tail -n 1)"
  [ -n "$session" ] || { echo "Local authentication did not issue a session cookie." >&2; exit 65; }
  # The cookie is injected into ZAP's transient process configuration only. It is not logged.
  docker run --rm --network host -v "$(pwd)/$output_dir:/zap/wrk:rw" "$zap_image" \
    zap-full-scan.py -t "$target" -m 3 -r authenticated.html -J authenticated.json -x authenticated.xml \
    -z "-config replacer.full_list(0).description=casevault-session -config replacer.full_list(0).enabled=true -config replacer.full_list(0).matchtype=REQ_HEADER -config replacer.full_list(0).matchstr=Cookie -config replacer.full_list(0).regex=false -config replacer.full_list(0).replacement=SESSION=${session}"
fi

echo "ZAP reports written to $output_dir"

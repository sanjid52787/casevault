#!/usr/bin/env sh
# Reads Docker secret files only into this process environment. Never echo these values.
set -eu

read_secret() {
  secret_file="$1"
  if [ ! -r "$secret_file" ]; then
    echo "Required Docker secret is unavailable" >&2
    exit 78
  fi
  tr -d '\r\n' < "$secret_file"
}

export CASEVAULT_DB_PASSWORD="$(read_secret "${CASEVAULT_DB_PASSWORD_FILE:-/run/secrets/casevault_db_password}")"
export AUDIT_HMAC_KEY="$(read_secret "${AUDIT_HMAC_KEY_FILE:-/run/secrets/casevault_audit_hmac_key}")"
export SPRING_FLYWAY_PASSWORD="$(read_secret "${FLYWAY_PASSWORD_FILE:-/run/secrets/casevault_migrator_password}")"
export TINK_KEYSET_PATH="${TINK_KEYSET_PATH:-/run/secrets/casevault_tink_keyset}"
export CASEVAULT_SECRETS_DATABASE_PASSWORD="$CASEVAULT_DB_PASSWORD"
export CASEVAULT_SECRETS_TINK_KEYSET_PATH="$TINK_KEYSET_PATH"
export CASEVAULT_SECRETS_AUDIT_HMAC_KEY="$AUDIT_HMAC_KEY"
export CASEVAULT_SECRETS_SESSION_SECRET="$(read_secret "${SESSION_SECRET_FILE:-/run/secrets/casevault_session_secret}")"

exec java ${JAVA_TOOL_OPTIONS:-} org.springframework.boot.loader.launch.JarLauncher

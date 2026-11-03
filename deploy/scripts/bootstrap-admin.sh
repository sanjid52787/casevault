#!/usr/bin/env sh
# CaseVault Docker Admin Bootstrap Script (POSIX Shell)
# Bootstraps the initial AUDITOR_ADMIN account into a running Docker stack in production mode.
# Refuses to run if any user already exists in the database.
set -eu

ADMIN_EMAIL="${ADMIN_EMAIL:-admin@example.test}"
ORG_NAME="${ORG_NAME:-Northbridge Internal}"
SECRET_PATH="${SECRET_PATH:-secrets/admin_initial_password.txt}"

echo "=== CaseVault Docker AUDITOR_ADMIN Bootstrap ==="

# 1. Connectivity check
docker compose exec -T db pg_isready -U casevault_admin -d casevault >/dev/null 2>&1 || {
  echo "Database service is not reachable. Ensure the Docker stack is running." >&2
  exit 1
}

# 2. Strict guard: Refuse to run if any user exists
USER_COUNT="$(docker compose exec -T db psql -U casevault_admin -d casevault -t -A -c "SELECT COUNT(*) FROM users;")"
if [ "$USER_COUNT" -gt 0 ]; then
  echo "SECURITY REFUSAL: Database already contains $USER_COUNT user(s)." >&2
  echo "The bootstrap script is strictly a one-time provisioning mechanism and will NOT run on an initialized database." >&2
  exit 1
fi

# 3. Secret Ingestion / Generation
mkdir -p "$(dirname "$SECRET_PATH")"
if [ ! -f "$SECRET_PATH" ]; then
  echo "Generating initial administrator password..."
  openssl rand -base64 24 > "$SECRET_PATH"
  chmod 600 "$SECRET_PATH"
else
  chmod 600 "$SECRET_PATH"
fi

# 4. Generate Argon2id hash using application's actual PasswordEncoder bean configuration
HASH_FILE="$(mktemp target/admin-hash.XXXXXX)"
sh ./mvnw -q "-Dexec.mainClass=uk.ac.ravensbourne.casevault.crypto.Argon2Hasher" "-Dexec.args=$SECRET_PATH $HASH_FILE" exec:java
ARGON_HASH="$(cat "$HASH_FILE")"
rm -f "$HASH_FILE"

case "$ARGON_HASH" in
  \$argon2id*) ;;
  *) echo "Invalid hash format received" >&2; exit 1 ;;
esac

# 5. Insert Organisation and AUDITOR_ADMIN
ORG_ID="$(cat /proc/sys/kernel/random/uuid 2>/dev/null || openssl rand -hex 16)"
USER_ID="$(cat /proc/sys/kernel/random/uuid 2>/dev/null || openssl rand -hex 16)"
CLEAN_EMAIL="$(echo "$ADMIN_EMAIL" | tr '[:upper:]' '[:lower:]')"

docker compose exec -T db psql -U casevault_admin -d casevault -v ON_ERROR_STOP=1 <<EOF
BEGIN;
INSERT INTO organisations (id, name, created_at, updated_at)
VALUES ('$ORG_ID', '$ORG_NAME', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
ON CONFLICT (name) DO NOTHING;

INSERT INTO users (
    id,
    organisation_id,
    email,
    password_hash,
    role,
    enabled,
    failed_attempts,
    force_password_reset,
    locked_until,
    last_login_at,
    created_at,
    updated_at,
    password_changed_at
) VALUES (
    '$USER_ID',
    (SELECT id FROM organisations WHERE name = '$ORG_NAME'),
    '$CLEAN_EMAIL',
    '$ARGON_HASH',
    'AUDITOR_ADMIN',
    TRUE,
    0,
    TRUE,
    NULL,
    NULL,
    CURRENT_TIMESTAMP,
    CURRENT_TIMESTAMP,
    CURRENT_TIMESTAMP
);
COMMIT;
EOF

echo "CaseVault AUDITOR_ADMIN Bootstrapped Successfully!"
echo "Role: AUDITOR_ADMIN, Email: $CLEAN_EMAIL, Forced Reset: TRUE"


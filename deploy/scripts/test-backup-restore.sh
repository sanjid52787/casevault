#!/usr/bin/env sh
# Integration drill: requires a running hardened compose stack containing synthetic data only.
# It restores into an isolated temporary PostgreSQL container and never alters the source database.
set -eu
project="${1:-casevault}"
root_dir="$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)"
backup_dir="${2:-$root_dir/backups/restore-drill-$(date +%Y%m%d%H%M%S)}"
cd "$root_dir"
mkdir -p "$backup_dir"
umask 077

docker compose -p "$project" ps db --status running | grep -q db || { echo "CaseVault db is not running" >&2; exit 1; }
docker compose -p "$project" exec -T db sh -c 'PGPASSWORD="$(cat /run/secrets/casevault_postgres_password)" pg_dump -U casevault_admin -Fc casevault' > "$backup_dir/casevault.dump"
docker compose -p "$project" exec -T app tar -C /var/lib/casevault/evidence -cf - . > "$backup_dir/evidence.tar"

restore_name="casevault-restore-$(date +%s)-$$"
restore_network="${restore_name}-net"
cleanup() { docker rm -f "$restore_name" >/dev/null 2>&1 || true; docker network rm "$restore_network" >/dev/null 2>&1 || true; }
trap cleanup EXIT
mkdir -p "$backup_dir/evidence"
tar -C "$backup_dir/evidence" -xf "$backup_dir/evidence.tar"
docker network create "$restore_network" >/dev/null
docker run -d --name "$restore_name" --network "$restore_network" --network-alias db \
  -v "$root_dir/secrets:/run/secrets:ro" \
  -v "$root_dir/deploy/scripts/restore-create-roles.sh:/opt/casevault/restore-create-roles.sh:ro" \
  -e POSTGRES_PASSWORD=restore-only -e POSTGRES_DB=casevault postgres:16.6-alpine >/dev/null
until docker exec "$restore_name" pg_isready -U postgres -d casevault >/dev/null 2>&1; do sleep 1; done
docker exec "$restore_name" sh /opt/casevault/restore-create-roles.sh
docker exec -i "$restore_name" sh -c 'PGPASSWORD=restore-only pg_restore -U postgres -d casevault --clean --if-exists' < "$backup_dir/casevault.dump"

docker exec "$restore_name" sh -c 'PGPASSWORD=restore-only psql -U postgres -d casevault -tAc "SELECT count(*) FROM audit_events"' > "$backup_dir/audit-event-count.txt"
test -s "$backup_dir/audit-event-count.txt"
app_image="$(docker compose -p "$project" images -q app)"
test -n "$app_image"
docker run --rm --network "$restore_network" \
  -v "$backup_dir/evidence:/var/lib/casevault/evidence" \
  -v "$root_dir/secrets/db_password.txt:/run/secrets/casevault_db_password:ro" \
  -v "$root_dir/secrets/migrator_password.txt:/run/secrets/casevault_migrator_password:ro" \
  -v "$root_dir/secrets/audit_hmac_key.txt:/run/secrets/casevault_audit_hmac_key:ro" \
  -v "$root_dir/secrets/session_secret.txt:/run/secrets/casevault_session_secret:ro" \
  -v "$root_dir/secrets/tink-keyset.json:/run/secrets/casevault_tink_keyset:ro" \
  -e SPRING_PROFILES_ACTIVE=prod,restore-verification \
  -e CASEVAULT_DB_URL=jdbc:postgresql://db:5432/casevault \
  -e CASEVAULT_DB_USERNAME=casevault_app \
  -e SPRING_FLYWAY_USER=casevault_migrator \
  -e CASEVAULT_EVIDENCE_DIRECTORY=/var/lib/casevault/evidence \
  "$app_image"
echo "Restore drill passed: fresh database restored, audit HMAC chain verified and one encrypted evidence item decrypted and hash-checked."

#!/usr/bin/env sh
set -eu
read_secret() { tr -d '\r\n' < "$1"; }
export PGPASSWORD="$(read_secret /run/secrets/casevault_postgres_password)"
psql -v ON_ERROR_STOP=1 \
  -v CASEVAULT_MIGRATOR_PASSWORD="$(read_secret /run/secrets/casevault_migrator_password)" \
  -v CASEVAULT_APP_PASSWORD="$(read_secret /run/secrets/casevault_db_password)" \
  -U "$POSTGRES_USER" -d "$POSTGRES_DB" -f /opt/casevault/init/01-roles.sql

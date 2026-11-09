#!/usr/bin/env sh
set -eu
read_secret() { tr -d '\r\n' < "$1"; }
export PGPASSWORD=restore-only
psql -v ON_ERROR_STOP=1 -U postgres -d casevault \
  -v CASEVAULT_MIGRATOR_PASSWORD="$(read_secret /run/secrets/migrator_password.txt)" \
  -v CASEVAULT_APP_PASSWORD="$(read_secret /run/secrets/db_password.txt)" <<'SQL'
CREATE ROLE casevault_migrator LOGIN PASSWORD :'CASEVAULT_MIGRATOR_PASSWORD';
CREATE ROLE casevault_app LOGIN PASSWORD :'CASEVAULT_APP_PASSWORD';
SQL

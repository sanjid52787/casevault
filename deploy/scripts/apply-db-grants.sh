#!/usr/bin/env sh
set -eu
export PGPASSWORD="$(tr -d '\r\n' < "$PGPASSWORD_FILE")"
exec psql -v ON_ERROR_STOP=1 -f /opt/casevault/02-apply-app-grants.sql

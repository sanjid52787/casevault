# Database roles

`casevault_migrator` is the Flyway-only account and receives schema create/DDL privileges. `casevault_app` is the runtime account: CRUD on application tables but only `INSERT`/`SELECT` on `audit_events`; it receives no DDL privilege. `01-roles.sql` is executed by `init-db.sh` only on a fresh PostgreSQL volume using Docker secret files. It sets default privileges for Flyway-created tables. After Flyway succeeds, `db-grants` runs `02-apply-app-grants.sql` and explicitly revokes UPDATE/DELETE on `audit_events` before nginx is exposed.

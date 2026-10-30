# Database roles

`casevault_migrator` is the Flyway-only account and receives DDL/maintenance privileges. `casevault_app` is the runtime account: CRUD on application tables but only `INSERT`/`SELECT` on `audit_events`; it receives no DDL privilege. The container/init environment supplies both placeholder passwords as secrets. Apply [01-roles.sql](init/01-roles.sql) only to a fresh PostgreSQL instance after replacing secret parameters through the deployment mechanism.

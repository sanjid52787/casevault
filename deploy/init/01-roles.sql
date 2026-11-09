-- Executed only by deploy/scripts/init-db.sh against a fresh PostgreSQL database.
-- psql variables are passed from Docker secret files and quoted as SQL literals.
CREATE ROLE casevault_migrator LOGIN PASSWORD :'CASEVAULT_MIGRATOR_PASSWORD';
CREATE ROLE casevault_app LOGIN PASSWORD :'CASEVAULT_APP_PASSWORD';

REVOKE CREATE ON SCHEMA public FROM PUBLIC;
GRANT CONNECT ON DATABASE casevault TO casevault_migrator, casevault_app;
GRANT USAGE, CREATE ON SCHEMA public TO casevault_migrator;
GRANT USAGE ON SCHEMA public TO casevault_app;

-- Flyway creates tables as casevault_migrator. Runtime CRUD is granted by default;
-- deploy/init/02-apply-app-grants.sql removes UPDATE/DELETE from audit_events before proxy exposure.
ALTER DEFAULT PRIVILEGES FOR ROLE casevault_migrator IN SCHEMA public
  GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO casevault_app;
ALTER DEFAULT PRIVILEGES FOR ROLE casevault_migrator IN SCHEMA public
  GRANT USAGE, SELECT ON SEQUENCES TO casevault_app;

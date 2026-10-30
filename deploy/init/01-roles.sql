-- Run only by the PostgreSQL container initialisation account, never by CaseVault.
CREATE ROLE casevault_migrator LOGIN PASSWORD :'CASEVAULT_MIGRATOR_PASSWORD';
CREATE ROLE casevault_app LOGIN PASSWORD :'CASEVAULT_APP_PASSWORD';
GRANT CONNECT ON DATABASE casevault TO casevault_migrator, casevault_app;
GRANT USAGE ON SCHEMA public TO casevault_migrator, casevault_app;
GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO casevault_migrator;
GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public TO casevault_migrator;
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO casevault_app;
REVOKE UPDATE, DELETE ON audit_events FROM casevault_app;
GRANT USAGE, SELECT ON SEQUENCE audit_events_id_seq TO casevault_app;

-- Run after Flyway, before nginx is exposed. This is intentionally deployment SQL, not application code.
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO casevault_app;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO casevault_app;
REVOKE UPDATE, DELETE ON audit_events FROM casevault_app;

# CaseVault deployment runbook

This runbook is for the fictional, synthetic-data CaseVault deployment only. It is not a production approval. Keep Docker secrets, backups and cryptographic keys out of Git, tickets and chat.

## Prerequisites

- Docker Engine with the Compose v2 plugin, OpenSSL, Git and Java 21 for local builds/key generation.
- A clean clone, enough local disk for PostgreSQL volumes and the generated build image.
- Port 443 free on the host. Docker Desktop must be running on Windows.

## First-time local setup

From the repository root, generate fresh local-only material once:

```sh
sh deploy/scripts/gen-secrets.sh
sh deploy/scripts/gen-dev-certs.sh
docker compose -f docker-compose.yml -f docker-compose.hardened.yml build --no-cache
docker compose -f docker-compose.yml -f docker-compose.hardened.yml up -d
```

On Windows, run the shell scripts from Git Bash/WSL, or generate the Tink keyset with `./scripts/gen-tink-keyset.ps1` and use OpenSSL/Git Bash for the remaining local secrets. The scripts create Git-ignored `secrets/` files with owner-only permissions. Do not replace those paths with checked-in `.env` values.

The `storage-init` container prepares PostgreSQL and evidence volumes. The app runs migrations through `casevault_migrator`; it then uses `casevault_app`. `db-grants` revokes UPDATE/DELETE on `audit_events` before nginx becomes reachable. Only nginx publishes `https://localhost:443`; database and application ports are internal.

## Start, stop and health

```sh
docker compose -f docker-compose.yml -f docker-compose.hardened.yml ps
curl --insecure https://localhost/actuator/health
docker compose -f docker-compose.yml -f docker-compose.hardened.yml logs --tail=200 app proxy db
docker compose -f docker-compose.yml -f docker-compose.hardened.yml down
```

`--insecure` is required only because the generated certificate is deliberately self-signed for local use. Use a CA-issued certificate and hostname-specific `server_name` outside development. Do not publish app port 8080 or PostgreSQL port 5432.

## Reproducible build, upgrade and rollback

Run `./mvnw -B verify` before building. Build and tag a release image from an immutable Git commit:

```sh
git rev-parse HEAD
docker build -t casevault:<git-commit> .
docker compose -f docker-compose.yml -f docker-compose.hardened.yml up -d --no-deps app
```

Flyway migrations are forward-only. Use expand/contract migrations: first add compatible schema/data paths, deploy code that supports both shapes, migrate/backfill, then remove obsolete structures later. Before upgrade, take a verified backup and retain the previous immutable image tag. Roll back application code only when the new migration remains compatible; never attempt a Flyway schema downgrade in place. Otherwise restore the verified backup to a new database, validate it, and redirect traffic under change control.

## Backup and restore

Back up PostgreSQL with `pg_dump -Fc`, encrypt the backup with organisation-approved backup tooling, and copy the encrypted evidence volume separately. Store the Tink keyset and audit HMAC key in a separate secrets system from database/evidence backups; losing either makes evidence verification/decryption impossible.

Run the synthetic restore drill against a running stack:

```sh
sh deploy/scripts/test-backup-restore.sh casevault
```

It restores into a temporary PostgreSQL container, starts the `restore-verification` profile against that copy, verifies the HMAC audit chain and decrypts/SHA-256-checks one synthetic encrypted evidence object. It never modifies the source database. **Result in this repository environment:** not executed because Docker, Trivy and Hadolint are unavailable; run it before deployment and retain its output as evidence.

## Key rotation

- Tink: create a new key in the keyset, mark it primary, deploy through the secret manager, then re-encrypt existing evidence in a controlled migration before retiring the old key.
- Audit HMAC: do not overwrite the key. Verify/export the existing chain, establish a documented new chain epoch with a new key, and retain the old key in a restricted archive for historical verification.
- Database/session secrets: rotate through Docker/secret-manager updates, restart app instances in a controlled window and revoke sessions where required.

## Incident response

- **Account compromise:** disable the account in `/admin`, revoke sessions, preserve audit evidence, reset the password and investigate source IP/correlation IDs.
- **Suspected evidence exposure:** stop proxy access if necessary, preserve database/evidence snapshots, rotate affected Tink material under incident procedures, verify the audit chain and notify the assessment owner. Do not edit audit records.
- **Audit-chain failure:** treat it as an integrity incident; restrict admin changes, preserve a DB copy and HMAC key separately, run verification against a clone and investigate the first broken record.

## Monitoring and alerts

Alert on sustained login-failure spikes, `ACCESS_DENIED` spikes, audit-chain verification failures, app 5xx rate, proxy 429 rate, storage/database health failures, container restarts, disk growth and backup/restore drill failure. Collect application logs with `docker compose logs`; never send secret files or decrypted evidence to a log platform.

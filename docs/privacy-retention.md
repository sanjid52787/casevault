# Privacy and retention

CaseVault is an academic system and must contain synthetic data only. The application stores the minimum case, account, remediation, report, evidence-metadata and audit fields needed for the assessed workflow. Evidence bytes are encrypted at rest and are not retained separately from their evidence record.

## Retention policy

When a case manager changes a case to `CLOSED`, the service sets `cases.retention_until` to the current application-clock time plus `casevault.retention.retention-days`. The default is 365 days. `casevault.retention.cron` defaults to `0 0 3 * * *` (03:00 in the scheduler's configured time zone). The scheduler is disabled by default and in the `test` profile; `application-prod.yml` enables it. Deployments may override all three settings with `CASEVAULT_RETENTION_DAYS`, `CASEVAULT_RETENTION_CRON` and `CASEVAULT_RETENTION_GRACE_DAYS`.

The scheduled `RetentionPurgeService` has two phases:

1. A case is soft-deleted only when its status is `CLOSED`, `retention_until` is before the current clock time, and `deleted_at` is null. A conditional database update sets `deleted_at`, so two application instances cannot claim the same case.
2. A soft-deleted closed case is eligible for hard deletion after `casevault.retention.grace-days` (30 days by default). The service obtains a pessimistic database lock on the eligible case, deletes reports, remediation actions, notes, evidence metadata and assignments, then deletes the case. The ciphertext files are deleted only in an after-commit callback. A missing ciphertext file is recorded as a sanitised warning and does not stop the rest of the purge.

The job never deletes or updates `audit_events` or the audit-chain head. It records one `RETENTION_PURGE` event for each successful soft or hard purge, with the case UUID as the target and a count-only detail value. It does not place case titles, notes, report content, filenames or evidence bytes in the audit record. The ordinary HMAC-SHA256 audit chain remains verifiable after retention work.

## Access after soft deletion

Soft-deleted cases are excluded inside database queries, rather than being post-filtered in Java. Case lists, search queries, organisation-scoped lookup and active-case lookup all require `deleted_at is null`. Detail, report and evidence operations obtain their case through the active object-access service, so a soft-deleted case cannot be viewed, reported on or downloaded by any role.

## Operational limits and assumptions

- Retention is an operational baseline, not a substitute for a legal hold process. Legal holds, statutory schedules and secure external backup expiry are out of scope for this synthetic-data assessment.
- Database transaction rollback means no ciphertext cleanup is attempted before the corresponding metadata and case deletion commit.
- If storage cleanup fails after commit, the case data is already gone and a ciphertext orphan can remain. The sanitised warning contains the case UUID only; operational staff must investigate storage cleanup separately.
- The two-instance guard uses a conditional update for soft delete and a pessimistic row lock for hard delete. Its production semantics rely on PostgreSQL; H2 is used only for local automated tests.

## Automated evidence

`RetentionPurgeServiceTest` uses `TestDataCleaner` before and after each test and covers:

| Test ID | Evidence |
|---|---|
| T-RET-001 | An expired closed case is soft-deleted and absent from the client case list. |
| T-RET-002 | After the grace period, dependent rows and the encrypted ciphertext are removed. |
| T-RET-003 | A non-closed case is never purged even when its retention date has passed. |
| T-RET-004 | `RETENTION_PURGE` events are chained and `verifyChain()` still succeeds. |
| T-RET-005 | A missing ciphertext file does not abort hard deletion. |

# Evidence index

| Claim ID | Claim | Test ID(s) | Tool output path | Status |
|---|---|---|---|---|
| SR-AUDIT | Persistent HMAC-SHA256 audit chain, tamper detection and concurrent appends | T-AUDIT-001..004 | `target/surefire-reports/uk.ac.ravensbourne.casevault.audit.PersistentAuditServiceTest.txt` | Verified |
| SR-AUTH | Login, lockout, generic failures, Argon2id and password policy | T-AUTH-001..010 | `target/surefire-reports/uk.ac.ravensbourne.casevault.security.AuthenticationSessionSecurityTest.txt` | Verified |
| SR-SESS | JDBC sessions, fixation protection, timeout, revocation and cookie flags | T-SESS-001..003 | `target/surefire-reports/uk.ac.ravensbourne.casevault.security.AuthenticationSessionSecurityTest.txt` | Verified |
| SR-AUTHZ | HTTP role/tenant/assignment matrix and IDOR controls | T-AUTHZ-001; T-AUTHZ-IDOR-001..007 | `target/surefire-reports/uk.ac.ravensbourne.casevault.web.AuthorisationHttpMatrixTest.txt` | Verified |
| SR-AUTHZ-ARCH | Controllers do not use repositories directly | T-AUTHZ-ARCH-001 | `target/surefire-reports/uk.ac.ravensbourne.casevault.security.ArchitectureRulesTest.txt` | Verified |
| SR-CRYPTO | Test-only in-memory Tink keysets and non-test missing-keyset rejection | T-CRYPTO-001, T-CRYPTO-002 | `target/surefire-reports/uk.ac.ravensbourne.casevault.crypto.TinkKeysetProviderTest.txt` | Verified |
| SR-FILE | Evidence validation, encrypted storage, integrity verification, tenant controls and safe downloads | T-FILE-001..012 | `target/surefire-reports/uk.ac.ravensbourne.casevault.service.EvidenceSecurityTest.txt`; `target/surefire-reports/uk.ac.ravensbourne.casevault.web.EvidenceHttpTest.txt` | Verified |
| SR-FILE-RATE | Per-user and per-IP upload/download transfer throttling returns 429 with Retry-After | T-FILE-013 | `target/surefire-reports/uk.ac.ravensbourne.casevault.web.EvidenceHttpTest.txt` | Verified |
| SR-XSS | Stored case titles/notes and reflected search text are Thymeleaf-escaped in HTTP responses | T-XSS-001 | `target/surefire-reports/uk.ac.ravensbourne.casevault.web.CaseSecurityHardeningTest.txt` | Verified |
| SR-VAL | Dedicated client case DTO ignores tenant, role, owner and status mass-assignment fields | T-CASE-003 | `target/surefire-reports/uk.ac.ravensbourne.casevault.web.CaseSecurityHardeningTest.txt` | Verified |
| SR-CONCURRENCY | Stale case version returns a generic, friendly conflict page without persistence internals | T-CASE-005 | `target/surefire-reports/uk.ac.ravensbourne.casevault.web.CaseSecurityHardeningTest.txt` | Verified |
| SR-INJ | Date range is applied as a typed, database-scoped predicate within client case search | T-CASE-004 | `target/surefire-reports/uk.ac.ravensbourne.casevault.web.CaseSecurityHardeningTest.txt` | Verified |
| SR-ADMIN | Auditor-only account administration, disable/revoke/reset protections and audit access | T-ADMIN-001..005 | `target/surefire-reports/uk.ac.ravensbourne.casevault.web.AdminSecurityTest.txt` | Verified |
| SR-ERR | Generic malformed-request response with correlation ID and no implementation details | T-ERR-001 | `target/surefire-reports/uk.ac.ravensbourne.casevault.web.AdminSecurityTest.txt` | Verified |
| SR-LOG | CR/LF sanitisation for log-safe user-controlled values | T-LOG-001..002 | `target/surefire-reports/uk.ac.ravensbourne.casevault.common.LogSanitizerTest.txt` | Verified |

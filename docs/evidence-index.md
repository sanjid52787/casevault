# Evidence index

`Done` means a named automated test class exists and has been run during local development. `Planned` means the corresponding control or end-to-end evidence is not established by a named current test. Test reports are written under `target/surefire-reports/` and are not committed.

| Claim ID | Claim | Commit | Issue | Test ID | Tool output path | Status |
|---|---|---|---|---|---|---|
| SR-AUTH | Argon2id passwords, generic login failures, lockout and abuse controls | Pending docs commit | TODO | T-AUTH-001..010 | `AuthenticationSessionSecurityTest.txt` | Done |
| SR-SESS | JDBC sessions, fixation protection, timeout, revocation and secure cookie flags | Pending docs commit | TODO | T-SESS-001..003 | `AuthenticationSessionSecurityTest.txt` | Done |
| SR-AUTHZ | Role/tenant/assignment checks and IDOR 404 responses | Pending docs commit | TODO | T-AUTHZ-001; T-AUTHZ-IDOR-001..007 | `AuthorisationHttpMatrixTest.txt` | Done |
| SR-AUTHZ-ARCH | Controllers do not access repositories directly | Pending docs commit | TODO | T-AUTHZ-ARCH-001 | `ArchitectureRulesTest.txt` | Done |
| SR-VAL | DTO validation, form binding, mass-assignment resistance and scoped queries | Pending docs commit | TODO | T-CASE-003..007; T-INJ-001..002 | `CaseSecurityHardeningTest.txt`; `CaseControllerValidationTest.txt` | Done |
| SR-XSS | Case/search/report output encoding | Pending docs commit | TODO | T-XSS-001; T-REPORT-002 | `CaseSecurityHardeningTest.txt`; `ReportSecurityTest.txt` | Done |
| SR-FILE | Evidence validation, encrypted storage, integrity and safe downloads | Pending docs commit | TODO | T-FILE-001..013 | `EvidenceSecurityTest.txt`; `EvidenceHttpTest.txt` | Done |
| SR-CRYPTO | Ephemeral test Tink keysets and keyset separation | Pending docs commit | TODO | T-CRYPTO-001..002 | `TinkKeysetProviderTest.txt` | Done |
| SR-AUDIT | HMAC-SHA256 chain, tamper detection and serialised concurrent appends | Pending docs commit | TODO | T-AUDIT-001..005 | `PersistentAuditServiceTest.txt`; `AuditServiceTest.txt` | Done |
| SR-ERR/LOG | Generic correlated errors and CR/LF-safe logging | Pending docs commit | TODO | T-ERR-001..002; T-LOG-001..002 | `AdminSecurityTest.txt`; `LogSanitizerTest.txt` | Done |
| SR-ADMIN | Auditor-only account administration without case-content access | Pending docs commit | TODO | T-ADMIN-001..005 | `AdminSecurityTest.txt` | Done |
| SR-REPORT | Versioned reports, SoD, redaction and content access controls | Pending docs commit | TODO | T-REPORT-001..008 | `ReportSecurityTest.txt`; `ReportServiceTest.txt` | Done |
| SR-RATE | Login, evidence, search and report-generation quotas | Pending docs commit | TODO | T-RATE-001..004; T-FILE-013 | `RateLimitSecurityTest.txt`; `EvidenceHttpTest.txt`; `AuthenticationSessionSecurityTest.txt` | Done |
| SR-HDR | Nonce CSP and defensive response headers | Pending docs commit | TODO | T-HDR-001..002; T-CORS-001 | `SecurityHeadersTest.txt` | Done |
| SR-RET | Scheduled retention purge | TODO | TODO | none | none | Planned |
| SR-SUPPLY/DEPLOY | SBOM/scanning and deployment hardening assurance | TODO | TODO | none | none | Planned |

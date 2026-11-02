# Test plan

Automated test identifiers, claims and Surefire report paths are indexed in [evidence-index.md](evidence-index.md). Tests use H2 in PostgreSQL compatibility mode and only synthetic/inert data. PostgreSQL/Testcontainers locking coverage and deployment/supply-chain tests remain planned.

Spring integration tests share the `jdbc:h2:mem:casevault` database; any test that creates organisations, users or cases must use `TestDataCleaner` before and after each test to remove fixtures in foreign-key order.
Rate-limit buckets are in-memory singleton state in the cached Spring test context; endpoint tests must use `TestDataCleaner` before and after each test so the case, evidence and login limiter buckets are reset.

## Test strategy and levels

| Level | Purpose | Typical tests |
|---|---|---|
| Unit | Exercise a narrow decision or pure component without the web stack. | `PasswordPolicyTest`, `AccessPolicyTest`, `CaseStatusMachineTest`, `LogSanitizerTest`, `TinkKeysetProviderTest`. |
| Repository | Validate Flyway/JPA mappings and scoped queries against H2 in PostgreSQL compatibility mode. | `FlywayMigrationTest`, `CaseRepositoryTest`. |
| Spring integration | Verify service, database, session, encryption and audit behaviour together. | `PersistentAuditServiceTest`, `EvidenceSecurityTest`, `RetentionPurgeServiceTest`. |
| MVC/security regression | Send MockMvc requests through Spring Security, CSRF, filters and controllers. | Authentication/session, authorisation matrix, evidence HTTP, report endpoint, header and rate-limit tests. |
| End-to-end workflow | Exercise the synthetic multi-role business flow across the application boundary. | `T-E2E-001` in `EndToEndWorkflowTest`. |

The test profile uses only H2 and inert synthetic files. PostgreSQL lock semantics, reverse-proxy TLS and deployment/container controls require a separately provisioned integration environment and are recorded as gaps rather than claimed as verified.

## Requirement traceability

ASVS references are chapter-level references to OWASP ASVS 5.0.0. WSTG references identify the relevant OWASP testing family; exact scenario identifiers must be selected when the manual checklist is executed.

| Test ID(s) | Requirement(s) | ASVS / WSTG reference | CWE |
|---|---|---|---|
| T-AUTH-001..010 | FR-01, SR-01 | ASVS V2; WSTG-ATHN | CWE-204, CWE-307, CWE-521 |
| T-SESS-001..003; T-AUTH-006..008 | FR-01, SR-02 | ASVS V3; WSTG-SESS | CWE-384, CWE-613, CWE-614 |
| T-AUTHZ-001..014; T-AUTHZ-MATRIX-001; T-AUTHZ-ARCH-003 | FR-02..07, SR-03 | ASVS V4; WSTG-ATHZ | CWE-639, CWE-862, CWE-863 |
| T-CASE-006..011; T-INJ-001..002 | FR-02..06, SR-04 | ASVS V5; WSTG-INPV | CWE-20, CWE-89 |
| T-XSS-001..002; T-HDR-002 | FR-02..07, SR-05 | ASVS V5; WSTG-CLNT | CWE-79 |
| T-CSRF-001..002 | SR-06 | ASVS V4; WSTG-SESS | CWE-352 |
| T-HDR-001..002; T-CORS-001 | SR-07 | ASVS V14; WSTG-CONF | CWE-693, CWE-1021 |
| none — explicit gap | SR-08 client-convenience-layer design assurance | ASVS V4/V14; WSTG-CLNT | CWE-602, CWE-798 |
| T-FILE-001..015; T-CRYPTO-001..002 | FR-05, SR-09 | ASVS V12/V6; WSTG-BUSL | CWE-22, CWE-311, CWE-434 |
| T-ERR-001..002; T-LOG-001..002 | SR-10 | ASVS V7; WSTG-ERRH | CWE-117, CWE-209, CWE-497 |
| T-AUDIT-001..005; T-ADMIN-004 | FR-08, SR-11 | ASVS V7/V6; WSTG-LOGI | CWE-345, CWE-778 |
| T-RATE-001..005 | SR-12 | ASVS V11; WSTG-ATHN | CWE-307, CWE-770 |
| T-CONFIG-001; T-CRYPTO-001; T-DEV-001 | SR-13 | ASVS V14; WSTG-CONF | CWE-522, CWE-798 |
| T-RET-001..005 | SR-14 | ASVS V8; WSTG-INFO | CWE-359, CWE-404 |
| none — explicit gap | SR-15 supply-chain assurance | ASVS V14; WSTG-CONF | CWE-937, CWE-1104 |
| none — explicit gap | SR-16 hardened deployment assurance | ASVS V9/V14; WSTG-CONF | CWE-250, CWE-319, CWE-732 |
| T-E2E-001 | FR-01..09 | Cross-cutting ASVS V2–V14; WSTG workflow regression | CWE-613, CWE-639, CWE-863 |

## Current named coverage

The following test source and its latest local Surefire report exist with zero failures/errors. This documentation update did not run tests.

| Requirement area | Test IDs | Test class | Coverage |
|---|---|---|---|
| Reports | T-REPORT-001..008 | `ReportSecurityTest` | Redaction, escaped injection payloads, exclusion of internal notes/identities, approval separation of duties, approved-only client access, cross-tenant not-found, auditor denial and lifecycle audit events. |
| Search/report quotas | T-RATE-001..004 | `RateLimitSecurityTest` | HTTP 429 and `Retry-After`, report quota, per-user separation and aggregated audit recording. |
| Shared-IP quota | T-RATE-005 | `IpRateLimitSecurityTest` | Two different users sharing a source IP consume the same search IP bucket. |
| Report HTTP access | T-REPORT-009..013 | `ReportEndpointSecurityTest` | Cross-tenant 404, DRAFT/SUBMITTED client denial, manager self-approval denial, auditor denial and report-generation CSRF rejection. |
| Redirect and CSRF | T-REDIR-001; T-CSRF-001..002 | `LoginRedirectAndCsrfTest` | Safe post-login targets, a missing CSRF token and a token replayed from another session. |
| Case validation | T-CASE-006..007 | `CaseControllerValidationTest` | Friendly invalid-title and unknown-enum form responses. |
| Safe errors | T-ERR-002 | `AdminSecurityTest` | Generic correlated 400, 404, 405 and 415 responses. |
| Admin storage health | T-ADMIN-006 | `AdminHealthStorageProbeTest` | Writable and unusable storage probe outcomes, auditor-only page access and response path non-disclosure. |
| Headers/source scan | T-HDR-001..002; T-CORS-001 | `SecurityHeadersTest` | Strict nonce CSP on login/case/admin routes, source scan for unsafe client-side constructs and rejected CORS preflight. |
| Retention | T-RET-001..005 | `RetentionPurgeServiceTest` | Closed-case soft deletion, post-grace hard deletion and ciphertext cleanup, non-closed preservation, audit-chain integrity and missing-file resilience. |
| End-to-end workflow | T-E2E-001 | `EndToEndWorkflowTest` | Client creation through manager assignment, analyst investigation/evidence/report, client report download, auditor audit view and administrator session revocation. |
| Secure-review regressions | T-SCR-002..004 | `SecureCodeReviewRegressionTest` | Dev logger does not contain plaintext-password template; direct non-admin account administration is denied; login throttling returns retry metadata and aggregates audit events. |

## Automated assurance tooling

`mvn verify` runs the JaCoCo gate, CycloneDX SBOM generation and SpotBugs with Find Security Bugs at High
priority. Semgrep, Gitleaks and OWASP Dependency-Check are invoked by `scripts/run-assurance.ps1` or
`scripts/run-assurance.sh`; Dependency-Check uses the optional Maven `dependency-check` profile and fails on
CVSS 9.0 or higher. These scanners complement—not replace—security regression tests, manual review and the
authorisation matrix. Results and triage are recorded in `assurance/sast-sca-analysis.md`.

## Gaps

| Requirement | Gap |
|---|---|
| Report HTTP delivery | No named MockMvc test currently verifies the report controller's rendered/download response end-to-end. |
| Report-generation IP quota | T-RATE-005 proves the search IP quota, but no named test independently proves the report-generation IP quota. |
| Storage health failure page | T-ADMIN-006 proves a failing storage probe and a safe normal health-page response, but does not inject a probe failure into the page render. |
| Production HSTS | No named prod-profile test verifies HSTS. |
| Complete CSRF endpoint coverage | T-CSRF-001/002 prove two important cases, but no named test enumerates every state-changing endpoint. |
| Supply-chain/deployment | No named automated tests exist yet. |
| Dependency-Check execution | The CVSS >= 9 gate is configured, but the initial local database update was not completed without `NVD_API_KEY`; it remains a release prerequisite rather than a passing test claim. |

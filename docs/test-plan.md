# Test plan

Automated test identifiers, claims and Surefire report paths are indexed in [evidence-index.md](evidence-index.md). Tests use H2 in PostgreSQL compatibility mode and only synthetic/inert data. PostgreSQL/Testcontainers locking coverage and deployment/supply-chain tests remain planned.

Spring integration tests share the `jdbc:h2:mem:casevault` database; any test that creates organisations, users or cases must use `TestDataCleaner` before and after each test to remove fixtures in foreign-key order.
Rate-limit buckets are in-memory singleton state in the cached Spring test context; endpoint tests must use `TestDataCleaner` before and after each test so the case, evidence and login limiter buckets are reset.

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

## Gaps

| Requirement | Gap |
|---|---|
| Report HTTP delivery | No named MockMvc test currently verifies the report controller's rendered/download response end-to-end. |
| Report-generation IP quota | T-RATE-005 proves the search IP quota, but no named test independently proves the report-generation IP quota. |
| Storage health failure page | T-ADMIN-006 proves a failing storage probe and a safe normal health-page response, but does not inject a probe failure into the page render. |
| Production HSTS | No named prod-profile test verifies HSTS. |
| Complete CSRF endpoint coverage | T-CSRF-001/002 prove two important cases, but no named test enumerates every state-changing endpoint. |
| Retention and supply-chain/deployment | No named automated tests exist yet. |

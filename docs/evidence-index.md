# Evidence index

`Done` means the named source test exists and its latest local Surefire report records zero failures and zero errors. The reports under `target/surefire-reports/` are local evidence and are not committed. `Planned` means there is no named automated test for the stated requirement; it is a gap, not a claim that the control is absent.

| Claim ID | Claim | Commit | Issue | Test ID | Tool output path | Status |
|---|---|---|---|---|---|---|
| SR-REPORT | Generated report redacts email addresses, IPv4 addresses and API-key-like values. | Pending docs commit | TODO | T-REPORT-001 | `target/surefire-reports/uk.ac.ravensbourne.casevault.report.ReportSecurityTest.txt` | Done |
| SR-REPORT | Report injection payloads are escaped. | Pending docs commit | TODO | T-REPORT-002 | `target/surefire-reports/uk.ac.ravensbourne.casevault.report.ReportSecurityTest.txt` | Done |
| SR-REPORT | Internal-only notes and internal identities are excluded from reports. | Pending docs commit | TODO | T-REPORT-003 | `target/surefire-reports/uk.ac.ravensbourne.casevault.report.ReportSecurityTest.txt` | Done |
| SR-REPORT | A manager cannot approve a report they generated. | Pending docs commit | TODO | T-REPORT-004 | `target/surefire-reports/uk.ac.ravensbourne.casevault.report.ReportSecurityTest.txt` | Done |
| SR-REPORT | Clients can retrieve only approved reports. | Pending docs commit | TODO | T-REPORT-005 | `target/surefire-reports/uk.ac.ravensbourne.casevault.report.ReportSecurityTest.txt` | Done |
| SR-REPORT | A client from another organisation receives not-found for a report. | Pending docs commit | TODO | T-REPORT-006 | `target/surefire-reports/uk.ac.ravensbourne.casevault.report.ReportSecurityTest.txt` | Done |
| SR-REPORT | AUDITOR_ADMIN cannot retrieve report content. | Pending docs commit | TODO | T-REPORT-007 | `target/surefire-reports/uk.ac.ravensbourne.casevault.report.ReportSecurityTest.txt` | Done |
| SR-REPORT/AUDIT | Report generation, submission, approval and download are audit events. | Pending docs commit | TODO | T-REPORT-008 | `target/surefire-reports/uk.ac.ravensbourne.casevault.report.ReportSecurityTest.txt` | Done |
| SR-RATE | The case search/list quota returns HTTP 429 with `Retry-After`. | Pending docs commit | TODO | T-RATE-001 | `target/surefire-reports/uk.ac.ravensbourne.casevault.web.RateLimitSecurityTest.txt` | Done |
| SR-RATE | The report-generation quota returns HTTP 429 with `Retry-After`. | Pending docs commit | TODO | T-RATE-002 | `target/surefire-reports/uk.ac.ravensbourne.casevault.web.RateLimitSecurityTest.txt` | Done |
| SR-RATE | Search/list quotas are independent for different users. | Pending docs commit | TODO | T-RATE-003 | `target/surefire-reports/uk.ac.ravensbourne.casevault.web.RateLimitSecurityTest.txt` | Done |
| SR-RATE/AUDIT | Repeated rate-limit denials produce one aggregated audit event per window. | Pending docs commit | TODO | T-RATE-004 | `target/surefire-reports/uk.ac.ravensbourne.casevault.web.RateLimitSecurityTest.txt` | Done |
| SR-AUTH | Post-login redirects accept only same-origin relative paths. | Pending docs commit | TODO | T-REDIR-001 | `target/surefire-reports/uk.ac.ravensbourne.casevault.security.LoginRedirectAndCsrfTest.txt` | Done |
| SR-CSRF | A state-changing request without a CSRF token is rejected. | Pending docs commit | TODO | T-CSRF-001 | `target/surefire-reports/uk.ac.ravensbourne.casevault.security.LoginRedirectAndCsrfTest.txt` | Done |
| SR-CSRF | A CSRF token from another session is rejected. | Pending docs commit | TODO | T-CSRF-002 | `target/surefire-reports/uk.ac.ravensbourne.casevault.security.LoginRedirectAndCsrfTest.txt` | Done |
| SR-VAL | An invalid case title returns a safe validation response. | Pending docs commit | TODO | T-CASE-006 | `target/surefire-reports/uk.ac.ravensbourne.casevault.web.CaseControllerValidationTest.txt` | Done |
| SR-VAL | An unknown case enum value returns a safe validation response. | Pending docs commit | TODO | T-CASE-007 | `target/surefire-reports/uk.ac.ravensbourne.casevault.web.CaseControllerValidationTest.txt` | Done |
| SR-ERR | 400, 404, 405 and 415 responses are generic and correlated. | Pending docs commit | TODO | T-ERR-002 | `target/surefire-reports/uk.ac.ravensbourne.casevault.web.AdminSecurityTest.txt` | Done |
| SR-ADMIN | Evidence-storage health probe reports writable storage, unusable storage and auditor-only access without path disclosure. | Pending docs commit | TODO | T-ADMIN-006 | `target/surefire-reports/uk.ac.ravensbourne.casevault.storage.AdminHealthStorageProbeTest.txt` | Done |
| SR-HDR | Key routes receive a nonce CSP with neither `unsafe-inline` nor `unsafe-eval`. | Pending docs commit | TODO | T-HDR-001 | `target/surefire-reports/uk.ac.ravensbourne.casevault.web.SecurityHeadersTest.txt` | Done |
| SR-HDR/XSS | Templates and static JavaScript contain no prohibited unsafe client-side sinks or inline script/style without a nonce. | Pending docs commit | TODO | T-HDR-002 | `target/surefire-reports/uk.ac.ravensbourne.casevault.web.SecurityHeadersTest.txt` | Done |
| SR-CORS | A cross-origin CORS preflight is refused. | Pending docs commit | TODO | T-CORS-001 | `target/surefire-reports/uk.ac.ravensbourne.casevault.web.SecurityHeadersTest.txt` | Done |
| SR-REPORT | Report controller rendering/download response headers are exercised end-to-end with MockMvc. | TODO | TODO | none | none | Planned — gap |
| SR-RATE | Per-IP search and report-generation quotas are independently exercised. | TODO | TODO | none | none | Planned — gap |
| SR-ADMIN | The health page itself is exercised while a probe failure is injected, confirming it renders `FAIL`. | TODO | TODO | none | none | Planned — gap |
| SR-HDR | HSTS is exercised under the `prod` profile. | TODO | TODO | none | none | Planned — gap |
| SR-CSRF | Every state-changing endpoint is covered by an endpoint-specific CSRF regression test. | TODO | TODO | none | none | Planned — gap |
| SR-RET | Scheduled retention purge is covered. | TODO | TODO | none | none | Planned — gap |
| SR-SUPPLY/DEPLOY | SBOM/scanning and deployment-hardening assurance are covered. | TODO | TODO | none | none | Planned — gap |

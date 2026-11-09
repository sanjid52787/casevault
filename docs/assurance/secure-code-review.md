# Secure code review — Phase 9

## Scope and method

Review date: 2026-11-01. Scope was every production controller, service, repository, configuration/security class and Thymeleaf/static asset under `src/main`, plus the matching test structure. The review used a manual checklist derived from OWASP ASVS 5.0 chapters V2–V14, the OWASP Top 10:2025 and CWE Top 25 families. OWASP Top 10:2025 category names in this document were verified against the [official OWASP list](https://top10.owasp.org/2025/): A01 Broken Access Control, A02 Security Misconfiguration, A03 Software Supply Chain Failures, A04 Cryptographic Failures, A05 Injection, A06 Insecure Design, A07 Authentication Failures, A08 Software or Data Integrity Failures, A09 Security Logging and Alerting Failures and A10 Mishandling of Exceptional Conditions.

This is a source review, not a penetration test. Findings distinguish confirmed defects from assurance gaps. A `Fixed` finding has a source change and regression test in the working tree; it still requires the normal build/review process before release.

## Checklist applied

| Area | Checks |
|---|---|
| Controllers and templates | Authentication/`@PreAuthorize`, CSRF on writes, DTO binding, no raw errors, output encoding, CSP-compatible assets and no privileged client storage. |
| Services | Deny-by-default role/object checks, tenant derivation from principal, assignment and separation-of-duties enforcement, transactions and audit records. |
| Repositories/data | Bound parameters, tenant/deleted predicates, UUID object lookup, foreign keys, retention ordering and no audit update/delete path. |
| Authentication/session | Argon2id, generic failures, lockout/rate limits, session fixation, revocation, cookie flags and redirect validation. |
| Evidence/crypto | File validation order, generated storage names, path containment, Tink AEAD associated data, digest verification and safe downloads. |
| Audit/logging/configuration | HMAC chain locking, metadata allow-list, correlation IDs, CR/LF sanitisation, production secrets and profile settings. |
| Dependencies/deployment | Pinned dependencies, Enforcer, Dependabot and documented remaining supply-chain/container assurance gaps. |

## Findings

| ID | File:line | Description | CWE | OWASP Top 10:2025 | Severity | Status | Fix commit / regression |
|---|---|---|---|---|---|---|---|
| F-SCR-001 | `src/main/java/uk/ac/ravensbourne/casevault/service/CaseWorkflowService.java:81` | Manager assignment previously changed only `owner_analyst_id`; it did not create `case_assignments`, while analyst access checks require that table. An analyst could therefore be shown as owner but be denied investigation/report access. | CWE-639 | A01 Broken Access Control | High | Fixed | Pending `security:` commit; `T-E2E-001` exercises assignment then analyst note/action/evidence/report operations. |
| F-SCR-002 | `src/main/java/uk/ac/ravensbourne/casevault/config/DevDataSeeder.java:4` | The dev seeder previously emitted generated plaintext passwords through the application logger. Application logs can be retained or exported, turning development credentials into an avoidable secret leak. | CWE-532 | A09 Security Logging and Alerting Failures | Medium | Fixed | Pending `security:` commit; `F-SCR-002` regression in `SecureCodeReviewRegressionTest`. Passwords are now written only to an attached interactive console once; logger output contains no password. |
| F-SCR-003 | `src/main/java/uk/ac/ravensbourne/casevault/service/AdminAccountService.java:21`; `src/main/java/uk/ac/ravensbourne/casevault/service/AdminAuditService.java:4` | Administrative service methods relied on controller method security. A direct internal invocation could disable accounts or read audit data without independently checking the actor role. | CWE-862 | A01 Broken Access Control | Medium | Fixed | Pending `security:` commit; `F-SCR-003` regression in `SecureCodeReviewRegressionTest`. Both services now require `AUDITOR_ADMIN`; health viewing is audited. |
| F-SCR-004 | `src/main/java/uk/ac/ravensbourne/casevault/security/LoginRateLimitFilter.java:4` | Login throttling previously redirected to the generic login-error page rather than returning HTTP 429 with `Retry-After`, and lacked an aggregated `RATE_LIMITED` audit event. | CWE-770 | A06 Insecure Design | Medium | Fixed | Pending `security:` commit; `F-SCR-004` regression in `SecureCodeReviewRegressionTest`. The limiter now returns a safe empty 429 response, calculates a retry delay and records one metadata-only audit event per IP/window. |
| F-SCR-005 | `src/main/java/uk/ac/ravensbourne/casevault/service/AdminAuditService.java:4` | Audit UI filtering currently supports action only. Date, actor and outcome filters specified for the administrator audit view are absent. Access is correctly restricted, but the assurance/operational requirement is incomplete. | CWE-778 | A09 Security Logging and Alerting Failures | Low | Open | Backlog issue 22; add bound date/actor/outcome filters and tests. |
| F-SCR-006 | `pom.xml` | Dependency pinning/Enforcer are present, but no reproducible SBOM, OWASP Dependency-Check, commit-SHA-pinned CI or hardened deployment evidence is currently automated. | CWE-1104 | A03 Software Supply Chain Failures | Medium | Open | Existing backlog issue 20; retain as a release gate. |

## Review outcome and residual risk

The review fixed all confirmed High and code-level Medium defects identified above. Supply-chain/deployment assurance remains a Medium release risk rather than a code defect and is deliberately not represented as completed control evidence. Remaining Low operational gaps include richer audit filtering. The evidence/file, report, CSP, CSRF, tenant-isolation, session and audit-chain controls should still be re-reviewed after any new endpoint, repository or deployment change.

# CaseVault requirements

## Functional requirements

| ID | Requirement | Acceptance criteria |
|---|---|---|
| FR-01 | Authenticate users and terminate sessions. | Valid enabled users can sign in; logout invalidates the server session; disabling a user revokes their active sessions. |
| FR-02 | Create and view incident cases. | A client user can create a case for their organisation and see only authorised cases. |
| FR-03 | Manage case classification and ownership. | A case manager can set allow-listed category, severity, status, and analyst owner. |
| FR-04 | Record investigation work. | An assigned analyst can add notes and remediation actions only to an authorised case. |
| FR-05 | Upload and retrieve evidence. | An authorised user can upload an accepted inert file and download it only through an authorised attachment endpoint. |
| FR-06 | Search and filter cases. | Results are filtered by the same server-side tenant/object policy as direct case access. |
| FR-07 | Generate sanitised reports. | An authorised report is produced from case data with untrusted text safely encoded/sanitised. |
| FR-08 | Record security events. | Security-relevant actions create protected, verifiable audit records. |
| FR-09 | Administer account access. | An auditor/admin can disable accounts and revoke sessions without receiving case body, note, or evidence-content access. |

## Security requirements

ASVS references are chapter-level references to OWASP ASVS 5.0; **verify exact requirement number against ASVS 5.0.0** during implementation.

| ID | Statement and rationale | ASVS chapter | CWE | Planned tests |
|---|---|---|---|---|
| SR-01 | Argon2id, 12+ characters, common-password rejection, generic failures and progressive lockout/delay resist credential stuffing and enumeration. | V2 Authentication | CWE-521, CWE-307, CWE-204 | T-AUTH-001..005 |
| SR-02 | JDBC server sessions use HttpOnly/Secure/SameSite=Strict, fixation rotation, 15-minute idle/8-hour absolute limits, and full logout/disable invalidation. | V3 Session Management | CWE-384, CWE-613, CWE-614 | T-SESS-001..005 |
| SR-03 | Deny by default; service-layer RBAC, organisation and object checks. UUIDs are not access control; cross-tenant objects return 404. | V4 Access Control | CWE-639, CWE-862, CWE-863 | T-AUTHZ-001..008 |
| SR-04 | Validate every DTO with allow-listed enums and limits; use parameterised JPA/bound queries only. | V5 Validation, Sanitization and Encoding | CWE-20, CWE-89 | T-INPUT-001..004 |
| SR-05 | Thymeleaf-escape untrusted text; prohibit unsafe `th:utext`/`innerHTML`; use OWASP sanitizer for future rich text. | V5 Validation, Sanitization and Encoding | CWE-79 | T-XSS-001..003 |
| SR-06 | Retain CSRF protection for every state-changing request. | V4 Access Control | CWE-352 | T-CSRF-001..002 |
| SR-07 | Set nonce strict CSP (no `unsafe-inline`), nosniff, frame denial, no-referrer, Permissions-Policy, HSTS and no-store authenticated pages. | V14 Configuration; V5 | CWE-693, CWE-1021 | T-HEADERS-001..006 |
| SR-08 | Browser code is untrusted convenience: server revalidates/re-authorises; no secrets or privileged IDs in browser storage/markup. | V4; V14 | CWE-602, CWE-798 | T-CLIENT-001..003 |
| SR-09 | Allow-list extension/magic bytes and size; generated out-of-web-root names, safe display names, SHA-256, Tink AES-GCM, authorised nosniff attachment downloads, ScanService seam. | V12 Files and Resources; V6 Cryptography | CWE-434, CWE-22, CWE-829 | T-FILE-001..010 |
| SR-10 | Safe global errors have correlation IDs and no stack trace, SQL, path or version disclosure; `server.error.include-*=never`. | V7 Error Handling and Logging | CWE-209, CWE-497 | T-ERR-001..003 |
| SR-11 | Separate append-only audit table with HMAC-SHA256 previous-hash chain, verifier, INSERT/SELECT-only app DB privilege, read-only admin views and CR/LF-safe fields. | V7; V6 | CWE-778, CWE-117, CWE-345 | T-AUDIT-001..006 |
| SR-12 | Bucket4j limits login, upload, search, report and admin actions with safe throttling responses. | V11 Business Logic | CWE-770, CWE-307 | T-RATE-001..005 |
| SR-13 | Environment/Docker-secret configuration and dev/test/prod profiles; prod fails fast without required secrets. | V14 Configuration | CWE-798, CWE-522 | T-CONFIG-001..004 |
| SR-14 | Minimise fields and use configurable closed-case retention: soft delete then scheduled hard delete. | V8 Data Protection | CWE-359, CWE-404 | T-RET-001..004 |
| SR-15 | Pin/version-review dependencies; Enforcer, CycloneDX, Dependency-Check, Dependabot and commit-SHA-pinned Actions. | V14 Configuration | CWE-1104, CWE-937 | T-SC-001..005 |
| SR-16 | Multi-stage non-root read-only container; dropped capabilities/no-new-privileges/resource limits/healthcheck; proxy TLS from uncommitted local certs. | V9 Communications; V14 | CWE-250, CWE-732, CWE-319 | T-DEPLOY-001..005 |

## Non-functional constraints

- Java 21 LTS, Spring Boot 3.x, Maven Wrapper, PostgreSQL and Flyway are mandatory.
- Use only synthetic data and inert evidence in local, authorised, isolated testing. No malware, real client data, or third-party testing.
- Do not design cryptographic algorithms: use Argon2id, Google Tink AES-GCM, JDK HmacSHA256 and platform TLS only.
- Every dependency is version-pinned with a recorded licence; every implemented control has reproducible test evidence.

## Role and permission matrix

Scope: **own org** is the caller's organisation; **assigned** is an analyst assigned to that case; **all** is all tenant cases; **none** is no content access.

| Action | CLIENT_USER | SECURITY_ANALYST | CASE_MANAGER | AUDITOR_ADMIN |
|---|---|---|---|---|
| Create incident | own org | none | all | none |
| View case body | own org | assigned | all | none |
| Set classification/status; assign analyst | none | none | all | none |
| Add/view notes and actions | none | assigned | all | none |
| Upload/download evidence | own org | assigned | all | **none — never evidence content** |
| Search cases | own org | assigned | all | security-event metadata only |
| Generate/approve report | own org / no approval | assigned / no approval | all / approve | none |
| View audit/account health; disable/revoke | none | none | none | all administrative metadata |

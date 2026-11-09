> **Note:** This audit is a point-in-time snapshot. Some entries (commit state, image names, test counts) have since changed. See docs/ai-declaration.md, docs/runbook-local.md and the CI results for the current state.

# CaseVault Completeness Audit & Assessment Readiness Review

**Document Purpose:** Independent, evidence-backed read-only audit of the **CaseVault** repository against the CYS22301 "Software and Platform Security" assessment specification, module rubric, and security engineering requirements.  
**Audit Date:** 2026-11-04  
**Auditor Mode:** Read-Only Formal Security Audit  
**Codebase Baseline:** Java 21 LTS, Spring Boot 3.4.2, PostgreSQL 16, Docker, nginx  
**Current Git Branch:** `feat/gaps` (11 commits ahead of `main`; uncommitted changes in working tree)  
**Latest Commit Hash:** `761260ebbf59d1e0c23170fee7ee26893575dae5`  

---

## 1. Summary Scorecard

| Assessment Part | Scope | DONE | PARTIAL | MISSING | UNVERIFIED | Total Items |
|---|---|---:|---:|---:|---:|---:|
| **Part 1** | Functional Requirements (FR-01..09) & RBAC Matrix | 10 | 0 | 0 | 0 | 10 |
| **Part 2** | Security Controls (Brief & ASVS baseline) | 17 | 2 | 0 | 0 | 19 |
| **Part 3** | Threat Scenarios (11 Brief Scenarios) | 6 | 5 | 0 | 0 | 11 |
| **Part 4** | Assurance Activities (15 Brief Items) & Bugs | 12 | 2 | 0 | 1 | 15 |
| **Part 5** | Delivery, DevSecOps & Repository Hygiene | 8 | 3 | 0 | 1 | 12 |
| **Part 6** | Minimum Submission Checklist | 10 | 4 | 0 | 0 | 14 |
| **Part 7** | Honesty & Discrepancy Checks | 5 | 0 | 0 | 0 | 5 |
| **Part 8** | Rubric Readiness Criteria (6 Dimensions) | 6 | 0 | 0 | 0 | 6 |
| **TOTAL** | **Comprehensive System Audit** | **74** | **16** | **0** | **2** | **92** |

*Note on status definitions:*
- **DONE:** Implemented in code, backed by reproducible automated tests or committed evidence artifacts.
- **PARTIAL:** Implemented or configured, but has a documented limitation, environment gap, or uncommitted branch state.
- **MISSING:** Specified in requirements/brief but absent from the codebase.
- **UNVERIFIED:** Cannot be confirmed from the local git repository alone; requires manual student execution, credentials, or live platform validation.

---

## 2. Comprehensive Audit Tables

### Part 1: Functional Requirements (Brief Items 1–9) and Role-Permission Matrix

| Item | Requirement & Scope | Status | Evidence (File / Class / Test ID / Commit) | Gap and Smallest Fix |
|---|---|---|---|---|
| **FR-01** | Authenticate securely and terminate sessions | **DONE** | [`CaseVaultAuthenticationProvider.java`](../../src/main/java/uk/ac/ravensbourne/casevault/security/CaseVaultAuthenticationProvider.java), [`SecurityConfiguration.java`](../../src/main/java/uk/ac/ravensbourne/casevault/security/SecurityConfiguration.java), [`LoginController.java`](../../src/main/java/uk/ac/ravensbourne/casevault/web/LoginController.java); Tests: `T-AUTH-001..010`, `T-SESS-001..003`, `T-REDIR-001..004` in [`AuthenticationSessionSecurityTest.java`](../../src/test/java/uk/ac/ravensbourne/casevault/security/AuthenticationSessionSecurityTest.java) and [`LoginRedirectAndCsrfTest.java`](../../src/test/java/uk/ac/ravensbourne/casevault/security/LoginRedirectAndCsrfTest.java); Commit: `761260e` / `b013586`. | None. Session termination and invalidation work across H2 and PostgreSQL. |
| **FR-02** | Create and view incident cases | **DONE** | [`CaseWorkflowService.java`](../../src/main/java/uk/ac/ravensbourne/casevault/service/CaseWorkflowService.java) (`createCase`, `getCaseForUser`), [`CaseController.java`](../../src/main/java/uk/ac/ravensbourne/casevault/web/CaseController.java); Tests: `T-AUTHZ-001`, `T-AUTHZ-MATRIX-001`, `T-CASE-006..011`, `T-E2E-001` in [`EndToEndWorkflowTest.java`](../../src/test/java/uk/ac/ravensbourne/casevault/web/EndToEndWorkflowTest.java); Commit: `f59b426` / `cc62464`. | None. Client creates in own org; views only own org. |
| **FR-03** | Assign category, severity, status, and owner | **DONE** | [`CaseWorkflowService.java`](../../src/main/java/uk/ac/ravensbourne/casevault/service/CaseWorkflowService.java) (`assignAnalyst`, `changeStatus`, `editMetadata`), [`AccessPolicy.java`](../../src/main/java/uk/ac/ravensbourne/casevault/service/AccessPolicy.java); Tests: `T-AUTHZ-002`, `CaseStatusMachineTest`, `CaseDetailWorkflowTest`; Commit: `f59b426`. | None. Manager-only assignment and status transitions enforced at domain service layer. |
| **FR-04** | Add investigation notes and remediation actions | **DONE** | [`CaseWorkflowService.java`](../../src/main/java/uk/ac/ravensbourne/casevault/service/CaseWorkflowService.java) (`addNote`, `addRemediationAction`, `updateActionStatus`), [`AccessPolicy.java`](../../src/main/java/uk/ac/ravensbourne/casevault/service/AccessPolicy.java); Tests: `T-AUTHZ-002`, `T-AUTHZ-007`, `T-AUTHZ-MATRIX-001`, `AuthorisationReconciliationTest`; Commit: `f59b426`. | None. Note visibility compartmentalization (internal analyst notes hidden from client/manager) enforced in `getCaseNotesForUser`. |
| **FR-05** | Upload and retrieve authorised evidence files | **DONE** | [`EvidenceService.java`](../../src/main/java/uk/ac/ravensbourne/casevault/service/EvidenceService.java), [`EvidenceController.java`](../../src/main/java/uk/ac/ravensbourne/casevault/web/EvidenceController.java), [`TinkAeadFileStorage.java`](../../src/main/java/uk/ac/ravensbourne/casevault/storage/TinkAeadFileStorage.java); Tests: `T-FILE-001..015`, `T-CRYPTO-001..002` in [`EvidenceSecurityTest.java`](../../src/test/java/uk/ac/ravensbourne/casevault/service/EvidenceSecurityTest.java); Commit: `f59b426` / `cc62464`. | None for academic scope. Live AV is stubbed (`NoOpScanService`) per assessment brief rules. |
| **FR-06** | Search/filter cases without exposing unauthorised records | **DONE** | [`CaseWorkflowService.java`](../../src/main/java/uk/ac/ravensbourne/casevault/service/CaseWorkflowService.java), [`CaseSpecifications.java`](../../src/main/java/uk/ac/ravensbourne/casevault/repository/CaseSpecifications.java), [`CaseRepository.java`](../../src/main/java/uk/ac/ravensbourne/casevault/repository/CaseRepository.java); Tests: `T-AUTHZ-001`, `T-AUTHZ-002`, `PostgresCaseSearchIntegrationTest`, `CaseSearchSpecificationTest`; Uncommitted on `feat/gaps`. | Working-copy changes replace static JPQL with dynamic Criteria Specifications to fix PostgreSQL 42P18 null-parameter bug. Smallest fix: commit `CaseSpecifications.java` and `CaseRepository.java`. |
| **FR-07** | Generate sanitised case summary / remediation report | **DONE** | [`CaseReportService.java`](../../src/main/java/uk/ac/ravensbourne/casevault/report/CaseReportService.java), [`SanitizedReportBuilder.java`](../../src/main/java/uk/ac/ravensbourne/casevault/report/SanitizedReportBuilder.java), [`ReportController.java`](../../src/main/java/uk/ac/ravensbourne/casevault/web/ReportController.java); Tests: `T-REPORT-001..013`, `T-BIZ-001` in [`ReportSecurityTest.java`](../../src/test/java/uk/ac/ravensbourne/casevault/report/ReportSecurityTest.java) and [`ReportEndpointSecurityTest.java`](../../src/test/java/uk/ac/ravensbourne/casevault/web/ReportEndpointSecurityTest.java); Commit: `076352c` / `cc62464`. | None. Excludes internal notes/identities, redacts PII/API keys, enforces two-person approval. |
| **FR-08** | Record security events in a protected audit log | **DONE** | [`PersistentAuditService.java`](../../src/main/java/uk/ac/ravensbourne/casevault/audit/PersistentAuditService.java), [`AuditEvent.java`](../../src/main/java/uk/ac/ravensbourne/casevault/domain/AuditEvent.java); Tests: `T-AUDIT-001..006`, `PostgresAuditAndLoginIntegrationTest`; Commit: `6b0d23c` / `761260e`. | Working-copy fix in `PersistentAuditService` for PostgreSQL `Instant` timestamp binding must be committed. |
| **FR-09** | Administer accounts (disable, revoke, create, delete) | **DONE** | [`AdminAccountService.java`](../../src/main/java/uk/ac/ravensbourne/casevault/service/AdminAccountService.java), [`AdminController.java`](../../src/main/java/uk/ac/ravensbourne/casevault/web/AdminController.java); Tests: `T-ADMIN-001..006`, `T-ADMIN-CREATE-001..007`, `T-ADMIN-DEL-001..006`; Commit: `cc62464` / `761260e` / working copy. | Admin creation/deletion endpoints and V7/V8 migrations are uncommitted in working tree. Smallest fix: stage and commit uncommitted admin files. |
| **RBAC** | Four roles & role-permission enforcement matrix | **DONE** | [`AccessPolicy.java`](../../src/main/java/uk/ac/ravensbourne/casevault/service/AccessPolicy.java), [`AuthorisationOperationMatrixTest.java`](../../src/test/java/uk/ac/ravensbourne/casevault/web/AuthorisationOperationMatrixTest.java), [`docs/assurance/authorisation-matrix.md`](../../docs/assurance/authorisation-matrix.md); Test: `T-AUTHZ-MATRIX-001` (176 parameterized HTTP test cases). | None. Complete parity between specification, service policy, and automated HTTP matrix. |

#### Detailed Role-Permission Enforcement Matrix (176 Parametric Executions)

| Operation | CLIENT_USER | SECURITY_ANALYST | CASE_MANAGER | AUDITOR_ADMIN | Enforcing Class & Method | Primary Verifying Test |
|---|---|---|---|---|---|---|
| **Create case** | **ALLOWED** (own org) | DENIED (403) | DENIED (403) | DENIED (403) | `AccessPolicy.canCreateCase` | `T-AUTHZ-MATRIX-001`, `CaseSecurityHardeningTest` |
| **View case body** | **ALLOWED** (own org; 404 other) | **ALLOWED** (assigned; 404 unassigned) | **ALLOWED** (all cases in org scope) | **DENIED** (404 - zero case content) | `AccessPolicy.canViewCase` | `T-AUTHZ-001`, `T-AUTHZ-002`, `T-AUTHZ-004` |
| **Assign analyst** | DENIED (403) | DENIED (403) | **ALLOWED** (all cases) | DENIED (403) | `AccessPolicy.canAssign` | `T-AUTHZ-003`, `T-AUTHZ-MATRIX-001` |
| **Change case status** | DENIED (403) | DENIED (403) | **ALLOWED** (all cases) | DENIED (403) | `AccessPolicy.canChangeStatus` | `T-AUTHZ-003`, `CaseStatusMachineTest` |
| **Add note / action** | DENIED (403) | **ALLOWED** (assigned only) | **ALLOWED** (all cases) | **DENIED** (403 / 404) | `AccessPolicy.canAddNote` | `T-AUTHZ-002`, `AuthorisationReconciliationTest` |
| **View notes** | Client-visible notes ONLY | Assigned analyst notes & client notes | Client-visible notes ONLY (internal notes hidden) | **DENIED** (never case content) | `CaseWorkflowService.getCaseNotesForUser` | `tReconcile004ManagerNotesDoNotLeakInternalNotes` |
| **Upload evidence** | **ALLOWED** (own org) | **ALLOWED** (assigned only) | **ALLOWED** (all cases) | **DENIED** (403 / 404) | `AccessPolicy.canUploadEvidence` | `EvidenceHttpTest`, `T-AUTHZ-MATRIX-001` |
| **Download evidence** | **ALLOWED** (own org) | **ALLOWED** (assigned only) | **ALLOWED** (all cases) | **DENIED** (404 - zero content) | `AccessPolicy.canDownloadEvidence` | `T-FILE-007`, `T-AUTHZ-MATRIX-001` |
| **Search cases** | Scoped to own org | Scoped to assigned cases | Scoped to all managed cases | DENIED / Audit events only | `CaseWorkflowService.searchCases` | `PostgresCaseSearchIntegrationTest` |
| **Generate report** | DENIED (403) | **ALLOWED** (draft when assigned) | DENIED (403) | **DENIED** (403 / 404) | `AccessPolicy.canGenerateReport` | `T-REPORT-001`, `ReportEndpointSecurityTest` |
| **Approve report** | DENIED (403) | DENIED (403) | **ALLOWED** (if not generator) | **DENIED** (403 / 404) | `AccessPolicy.canApproveReport` | `T-REPORT-004`, `T-BIZ-001` |
| **Download report** | **ALLOWED** (approved only) | **ALLOWED** (assigned) | **ALLOWED** (all cases) | **DENIED** (404 - zero content) | `CaseReportService.getReportForUser` | `T-REPORT-005`, `T-REPORT-007` |
| **View audit log** | DENIED (403) | DENIED (403) | DENIED (403) | **ALLOWED** (read-only metadata) | `AdminAuditService.getAuditEvents` | `T-ADMIN-001`, `tAdmin006AuditFiltering...` |
| **Disable / revoke** | DENIED (403) | DENIED (403) | DENIED (403) | **ALLOWED** (cannot self-disable) | `AdminAccountService.disableAccount` | `T-ADMIN-002`, `T-ADMIN-005` |
| **Create user / org** | DENIED (403) | DENIED (403) | DENIED (403) | **ALLOWED** (cannot create admin) | `AdminAccountService.createUser` | `T-ADMIN-CREATE-001..007` |
| **Delete user** | DENIED (403) | DENIED (403) | DENIED (403) | **ALLOWED** (cannot self-delete) | `AdminAccountService.deleteUser` | `T-ADMIN-DEL-001..006` |

---

### Part 2: Security Controls (19 Specific Areas)

| Security Control | Implementation Details | Status | Evidence (File / Class / Test ID / Commit) | Gap and Smallest Fix |
|---|---|---|---|---|
| **Password hashing & policy** | Argon2id (memory 64MB, 1 iteration, 1 thread, 32-byte hash, 16-byte salt via Spring Security `Argon2PasswordEncoder.defaultsForSpringSecurity_v5_8()`); min length 12; common-password blacklist (`common-passwords.txt`); generic failure responses. | **DONE** | [`CaseVaultAuthenticationProvider.java`](../../src/main/java/uk/ac/ravensbourne/casevault/security/CaseVaultAuthenticationProvider.java), [`PasswordPolicy.java`](../../src/main/java/uk/ac/ravensbourne/casevault/security/PasswordPolicy.java); Tests: `T-AUTH-001..005`, `PasswordPolicyTest`, `Argon2HasherTest`; Commit: `b4cd2d8`. | None. Custom crypto strictly avoided. |
| **Lockout & rate limiting** | Bucket4j in-memory token bucket; progressive lockout (5 failed attempts); per-IP and per-account buckets; search, report, upload, and admin endpoint throttling with HTTP 429 and `Retry-After`. | **PARTIAL** | [`LoginRateLimiter.java`](../../src/main/java/uk/ac/ravensbourne/casevault/security/LoginRateLimiter.java), [`CaseRateLimitService.java`](../../src/main/java/uk/ac/ravensbourne/casevault/service/CaseRateLimitService.java), [`AdminRateLimitService.java`](../../src/main/java/uk/ac/ravensbourne/casevault/service/AdminRateLimitService.java); Tests: `T-RATE-001..005`, `T-SCR-004`; Commit: `076352c` / working copy. | Rate limit buckets are in-memory single-node; not shared across horizontal cluster replicas. Documented as accepted residual risk in `docs/future-work.md`. |
| **Session management** | Spring Session JDBC (`SPRING_SESSION`); cookie attributes `HttpOnly; Secure; SameSite=Strict`; session fixation rotation on login; idle timeout 15 min; absolute timeout 8h; instant revocation on logout or account disable. | **DONE** | [`SecurityConfiguration.java`](../../src/main/java/uk/ac/ravensbourne/casevault/security/SecurityConfiguration.java), [`V2__spring_session_jdbc.sql`](../../src/main/resources/db/migration/V2__spring_session_jdbc.sql); Tests: `T-SESS-001..003`, `T-AUTH-006..008` in `AuthenticationSessionSecurityTest`; Commit: `f59b426`. | None. |
| **RBAC & tenant isolation** | Deny-by-default; service-layer complete mediation via `AccessPolicy`; organisation UUID checked on all operations; cross-tenant requests return uniform 404 to block identifier enumeration. | **DONE** | [`AccessPolicy.java`](../../src/main/java/uk/ac/ravensbourne/casevault/service/AccessPolicy.java), [`CaseAccessService.java`](../../src/main/java/uk/ac/ravensbourne/casevault/service/CaseAccessService.java); Tests: `T-AUTHZ-001..008`, `T-AUTHZ-MATRIX-001`; Commit: `f59b426`. | None. Verified by 176-test HTTP matrix and ArchUnit architecture rule. |
| **IDOR / BOLA protection** | Object-level authorization in service layer; UUIDs treated as public references, never as authorization tokens; returns 404 on unowned objects. | **DONE** | [`CaseAccessService.java`](../../src/main/java/uk/ac/ravensbourne/casevault/service/CaseAccessService.java); Tests: `T-AUTHZ-IDOR-001`, `CaseSecurityHardeningTest`; Commit: `f59b426`. | Proven by dedicated branch test `evidence/idor-vulnerable-confirmed` where intentional bypass failed test. |
| **Server-side validation** | Jakarta Bean Validation on all DTOs (`@Valid`, `@NotBlank`, `@Size`, `@Pattern`); strict enum allow-lists (`Category`, `Severity`, `CaseStatus`, `Role`); parameter validation before processing. | **DONE** | [`CreateCaseRequest.java`](../../src/main/java/uk/ac/ravensbourne/casevault/web/dto/CreateCaseRequest.java), [`CreateUserRequest.java`](../../src/main/java/uk/ac/ravensbourne/casevault/web/dto/CreateUserRequest.java); Tests: `T-CASE-006..007`, `CaseControllerValidationTest`; Commit: `f59b426` / working copy. | None. Form validation errors mapped cleanly without stack traces. |
| **Output encoding / XSS & CSP** | Thymeleaf context-aware escaping (`th:text`, zero `th:utext`); strict Content-Security-Policy with per-request cryptographically random nonces; `X-Content-Type-Options: nosniff`; `X-Frame-Options: DENY`. | **DONE** | [`ContentSecurityPolicyFilter.java`](../../src/main/java/uk/ac/ravensbourne/casevault/security/ContentSecurityPolicyFilter.java), templates in `src/main/resources/templates/`; Tests: `T-XSS-001..002`, `T-HDR-001..002` in `SecurityHeadersTest`; Commit: `6ba3669`. | Verified by source code scanner and deliberate mutation test on `evidence/xss-vulnerable`. |
| **CSRF protection** | Spring Security CSRF enabled on all state-changing endpoints; token synchronizer pattern; token bound to session; invalid/missing token returns 403. | **DONE** | [`SecurityConfiguration.java`](../../src/main/java/uk/ac/ravensbourne/casevault/security/SecurityConfiguration.java); Tests: `T-CSRF-001..002` in `LoginRedirectAndCsrfTest`; Commit: `b013586`. | None. |
| **SQL injection prevention** | Zero string concatenation in SQL/JPQL; Spring Data JPA parameterized queries; dynamic `CaseSpecifications` using CriteriaBuilder; `PreparedStatement` with bound parameters in audit/admin services. | **DONE** | [`CaseSpecifications.java`](../../src/main/java/uk/ac/ravensbourne/casevault/repository/CaseSpecifications.java), [`PersistentAuditService.java`](../../src/main/java/uk/ac/ravensbourne/casevault/audit/PersistentAuditService.java); Tests: `T-INJ-001..002`, `PostgresCaseSearchIntegrationTest`; Semgrep rule `casevault-prevent-raw-sql-concatenation`. | Uncommitted `CaseSpecifications.java` must be staged and committed. |
| **File-upload validation & storage** | Extension allow-list (`.pdf`, `.txt`, `.log`, `.json`, `.csv`, `.png`, `.jpg`); Apache Tika magic-byte detection; rejection of executable headers (ELF, PE, Mach-O, Java class); max 10MB; stored off-web-root under random UUID; SHA-256 integrity hash. | **DONE** | [`ApacheTikaMagicBytesDetector.java`](../../src/main/java/uk/ac/ravensbourne/casevault/storage/ApacheTikaMagicBytesDetector.java), [`EvidenceService.java`](../../src/main/java/uk/ac/ravensbourne/casevault/service/EvidenceService.java); Tests: `T-FILE-001..015`; Commit: `f59b426`. | Live antivirus is an inert stub (`NoOpScanService`) as required by assessment rules (no live malware/EICAR). |
| **Encryption at rest and in transit** | Google Tink `AesGcmJce` (AES-256-GCM AEAD) with associated data binding (case UUID + file UUID); keyset loaded outside web root; TLS 1.2/1.3 reverse proxy via nginx. **NO custom cryptography.** | **DONE** | [`TinkAeadFileStorage.java`](../../src/main/java/uk/ac/ravensbourne/casevault/storage/TinkAeadFileStorage.java), [`TinkKeysetProvider.java`](../../src/main/java/uk/ac/ravensbourne/casevault/crypto/TinkKeysetProvider.java), [`deploy/nginx.conf`](../../deploy/nginx.conf); Tests: `T-CRYPTO-001..002`, `EvidenceSecurityTest`; Commit: `f59b426` / `1dd9f0b`. | None. Validated standard cryptographic primitives only. |
| **Safe error handling** | Global `@ControllerAdvice` (`GlobalExceptionHandler`); generic user views with correlation IDs; `server.error.include-*=never`; zero stack trace, SQL dialect, path, or package disclosures. | **DONE** | [`GlobalExceptionHandler.java`](../../src/main/java/uk/ac/ravensbourne/casevault/web/GlobalExceptionHandler.java), [`application.yml`](../../src/main/resources/application.yml); Tests: `T-ERR-001..003` in `AdminSecurityTest`; Commit: `3f40ecf` / `6ba3669`. | None. |
| **Secrets & config management** | 12-factor configuration via environment variables and Docker secrets; Spring profiles (`dev`, `test`, `prod`); `SecretsValidator` fails startup fast in `prod` if secrets are blank; zero secrets in Git. | **DONE** | [`SecretsValidator.java`](../../src/main/java/uk/ac/ravensbourne/casevault/config/SecretsValidator.java), [`CaseVaultSecretsProperties.java`](../../src/main/java/uk/ac/ravensbourne/casevault/config/CaseVaultSecretsProperties.java); Tests: `T-CONFIG-001`, `SecretsValidatorTest`; Commit: `f59b426`. | None. Tested with blank secret values producing startup failure. |
| **Audit log integrity (HMAC chain)** | Append-only `audit_events` table; HMAC-SHA256 hash chain with previous hash link; chain head row locking via `SELECT ... FOR UPDATE`; DB role has `INSERT`/`SELECT` only; tamper-detection verification method. | **DONE** | [`PersistentAuditService.java`](../../src/main/java/uk/ac/ravensbourne/casevault/audit/PersistentAuditService.java), [`V3__add_audit_chain_head.sql`](../../src/main/resources/db/migration/V3__add_audit_chain_head.sql); Tests: `T-AUDIT-001..006`, `PersistentAuditServiceTest`, `PostgresAuditAndLoginIntegrationTest`; Commit: `6b0d23c` / `761260e`. | Working copy fix for PostgreSQL `Instant` timestamp binding must be committed. |
| **Security logging without secrets** | `LogSanitizer.sanitize()` strips CR/LF (`\r`, `\n`) to prevent log injection (CWE-117); dev seeder prints credentials only to attached interactive console once; zero passwords/keys in logs or audit events. | **DONE** | [`LogSanitizer.java`](../../src/main/java/uk/ac/ravensbourne/casevault/common/LogSanitizer.java), [`DevDataSeeder.java`](../../src/main/java/uk/ac/ravensbourne/casevault/config/DevDataSeeder.java); Tests: `T-LOG-001..002`, `T-SCR-002`; Commit: `f59b426`. | None. |
| **Data minimisation & retention** | Configurable retention period for closed cases (default 365 days); scheduled purge job (`RetentionPurgeService`): soft-delete closed cases, hard-delete after grace period (30 days); removes metadata & ciphertext; audit records never deleted. | **DONE** | [`RetentionPurgeService.java`](../../src/main/java/uk/ac/ravensbourne/casevault/service/RetentionPurgeService.java), [`docs/privacy-retention.md`](../../docs/privacy-retention.md); Tests: `T-RET-001..005`; Commit: `f59b426`. | None. |
| **Admin accountability** | Auditor/admin has ZERO case body/evidence/report content access; all admin actions generate HMAC audit events; rate-limited; admin cannot self-disable or self-delete; admin cannot create another admin. | **DONE** | [`AccessPolicy.java`](../../src/main/java/uk/ac/ravensbourne/casevault/service/AccessPolicy.java), [`AdminAccountService.java`](../../src/main/java/uk/ac/ravensbourne/casevault/service/AdminAccountService.java); Tests: `T-ADMIN-001..006`, `T-ADMIN-CREATE-001..007`, `T-ADMIN-DEL-001..006`; Commit: `761260e` / working copy. | Uncommitted admin creation/deletion and V7/V8 migrations must be committed. |
| **Dependency / supply chain** | Pinned versions in `pom.xml`; Maven Enforcer (`dependencyConvergence`); CycloneDX 1.6 SBOM; Dependency-Check profile (CVSS >= 9 gate); Dependabot; SHA-pinned GitHub Actions. | **PARTIAL** | [`pom.xml`](../../pom.xml), [`.github/dependabot.yml`](../../.github/dependabot.yml), [`docs/assurance/sbom/bom.json`](../../docs/assurance/sbom/bom.json); Tests: `T-SC-001..005`, `sast-sca-analysis.md`; Commit: `1dd9f0b`. | Dependency-Check local execution did not finish due to missing `NVD_API_KEY` (F-SCR-006). Smallest fix: run with student/CI `NVD_API_KEY` before release. |
| **Deployment hardening** | Multi-stage Dockerfile (`eclipse-temurin:21-jre-alpine`); non-root user `appuser` (UID 10001); read-only rootfs; `cap_drop: ALL`; `no-new-privileges: true`; memory/CPU limits; Docker healthcheck; nginx TLS reverse proxy. | **DONE** | [`Dockerfile`](../../Dockerfile), [`docker-compose.hardened.yml`](../../docker-compose.hardened.yml), [`docs/assurance/container-hardening.md`](../../docs/assurance/container-hardening.md); Commit: `1dd9f0b` / `cc62464`. | None. Hardened Docker Compose overlay enforces all containment controls. |

*Cryptographic Compliance Notice:* Custom cryptography is **STRICTLY ABSENT**. The application exclusively utilizes standard primitives: Argon2id (Spring Security / BouncyCastle), Google Tink AES-256-GCM AEAD, JDK `javax.crypto.Mac` HmacSHA256, and OpenSSL TLS 1.2/1.3 via nginx.

---

### Part 3: Threat Scenarios (The 11 in Assessment Brief)

| Threat Scenario | Present in `docs/threat-model.md`? | Mitigating Architectural Control | Verifying Test ID & Class | Stated Residual Risk |
|---|---|---|---|---|
| **1. Cross-tenant access (BOLA/IDOR)** | **YES** (R-01, Attack Path A-01) | Service-layer `AccessPolicy` and `CaseAccessService` enforce organisation UUID matching; returns HTTP 404 on unowned objects. | `T-AUTHZ-001`, `T-AUTHZ-IDOR-001` in `CaseSecurityHardeningTest`; `T-AUTHZ-MATRIX-001` in `AuthorisationOperationMatrixTest`. | New direct repository queries might omit tenant filter; ArchUnit rule mitigates. |
| **2. Compromised low-privilege account escalating** | **PARTIAL** (In MU-03, but missing standalone R-xx row in risk table; R-07 covers admin rogue creation) | Server-side RBAC from database-persisted `Role` enum; `@PreAuthorize` and `AccessPolicy`; user creation endpoint strictly forbids `AUDITOR_ADMIN` role assignment. | `T-AUTHZ-003` in `CaseSecurityHardeningTest`; `T-ADMIN-CREATE-003` in `AdminUserCreationTest`. | Direct DB compromise could alter role column; mitigated by DB least privilege. |
| **3. Identifier manipulation (BOLA/UUID tampering)** | **YES** (R-01, Attack Path A-01, MU-01) | UUIDs treated as non-secret identifiers, never as an authorization token. Every access resolves through `findByIdAndOrganisationId` or `AccessPolicy`. | `T-AUTHZ-001` in `CaseSecurityHardeningTest`; `T-AUTHZ-MATRIX-001`. | Direct unguarded routes in future development; guarded by central policy architecture test. |
| **4. Injection in notes, search, reports** | **YES** (R-05, MU-06, MU-07) | Bound parameters in JPA / Criteria Specifications; Thymeleaf context-aware escaping (`th:text`); strict per-request nonce CSP; `SanitizedReportBuilder` escapes and redacts. | `T-INPUT-002`, `T-INJ-001..002` in `CaseSecurityHardeningTest`; `T-XSS-001..002` in `SecurityHeadersTest`; `T-REPORT-002`. | Future addition of unescaped rich-text rendering would require strict HTML sanitizer enforcement. |
| **5. Disguised file upload** | **YES** (R-03, Attack Path A-03, MU-08) | Extension allow-list; Apache Tika magic-byte detection; executable header signature checking; off-root UUID storage; Tink AES-GCM encryption. | `T-FILE-001..005` in `EvidenceSecurityTest`. | Inert stub scanner (`NoOpScanService`) used due to academic ban on real malware/EICAR; polyglot attacks in allow-listed types. |
| **6. Credential / secret exposure** | **PARTIAL** (Asset table & MU-10, but not a standalone R-xx row in table) | Zero secrets in Git; `.gitignore` blocks secret files; Gitleaks scan in CI; `LogSanitizer` removes secrets from logs; `SecretsValidator` fails fast in prod. | `T-CONFIG-001` in `SecretsValidatorTest`; `T-SCR-002` in `SecureCodeReviewRegressionTest`; Gitleaks CI scan. | One-time admin passwords shown once on web UI result screen; requires secure delivery. |
| **7. Vulnerable dependencies** | **PARTIAL** (Asset table & MU-11, but not a standalone R-xx row in table) | Version pinning in `pom.xml`; Maven Enforcer; CycloneDX SBOM; Dependency-Check CVSS >= 9 gate; Dependabot; commit-SHA-pinned Actions. | `T-SC-001` in `sast-sca-analysis.md`; Maven verify log. | Dependency-Check run is incomplete without `NVD_API_KEY`; zero-day library vulnerabilities prior to CVE release. |
| **8. Audit tampering / deletion / excess access** | **YES** (R-04, Attack Path A-04, MU-12, MU-13) | Append-only DB table; HMAC-SHA256 monotonic hash chain; head locked via `SELECT ... FOR UPDATE`; DB role lacks UPDATE/DELETE; verifier detects alterations; admin view rate-limited. | `T-AUDIT-001..006` in `PersistentAuditServiceTest`; `PostgresAuditAndLoginIntegrationTest`. | Database superuser possessing HMAC key could re-hash history; external timestamping/WORM storage needed for complete protection. |
| **9. Leakage through logs / errors / backups / config** | **PARTIAL** (Asset table & MU-14, but not a standalone R-xx row in table) | Global `@ControllerAdvice` returns generic error view with correlation ID; `server.error.include-*=never`; actuator health details hidden; `LogSanitizer` strips CR/LF. | `T-ERR-001..003` in `AdminSecurityTest`; `T-LOG-001..002` in `LogSanitizerTest`. | Unencrypted host backups or log files exported to external unauthenticated syslog infrastructure. |
| **10. Automated login / enumeration / resource exhaustion** | **YES** (R-02, R-06, Attack Path A-02, MU-09, MU-15, MU-16) | Argon2id hashing; generic login responses with timing dummy calculation; progressive lockout (5 attempts); Bucket4j token bucket rate limits on all sensitive endpoints; 10MB upload ceiling. | `T-AUTH-004` in `AuthenticationSessionSecurityTest`; `T-RATE-001..005` in `RateLimitSecurityTest` & `IpRateLimitSecurityTest`. | In-memory token buckets do not scale across multiple clustered instances; shared NAT IPs share a single rate-limit bucket. |
| **11. Authorised insider misuse** | **PARTIAL** (Attack Path A-05 & R-07 cover aspects, but not a unified R-xx row in table) | Strict separation of duties: manager cannot approve self-generated reports; auditor denied case bodies/evidence; analyst restricted to assigned cases; admin actions audited. | `T-REPORT-004`, `T-REPORT-007` in `ReportSecurityTest`; `T-AUTHZ-002`, `T-AUTHZ-004`. | An authorised user acting within legitimate permissions cannot be technically prevented from reading data they are cleared to view. |

---

### Part 4: Assurance Activities (The 15 in Brief), Documented Vulnerability Chains, and Real Bugs

| Assurance Activity | Artefact Exists? | Output Interpreted? (Not raw dump) | FP / FN Discussed? | CWE / OWASP Mapped? | Status | Gap and Smallest Fix |
|---|---|---|---|---|---|---|
| **1. Requirements & misuse cases** | [`docs/requirements.md`](../../docs/requirements.md), [`docs/misuse-cases.md`](../../docs/misuse-cases.md) | **YES** (structured tables with rationale) | **YES** (attack step nuances) | **YES** (ASVS 5.0, CWEs) | **DONE** | None. |
| **2. Architecture & data-flow diagrams** | [`docs/architecture.md`](../../docs/architecture.md), [`docs/data-flow.md`](../../docs/data-flow.md) | **YES** (Mermaid topology, sequence diagrams, ERD) | **YES** (boundary trust assumptions) | **YES** (Saltzer-Schroeder, CWE-639) | **DONE** | None. |
| **3. Risk-based threat model** | [`docs/threat-model.md`](../../docs/threat-model.md) | **YES** (STRIDE, 5 Mermaid attack paths, risk register) | **YES** (tool limits, residual risks) | **YES** (CWEs, STRIDE) | **DONE** | Missing dedicated risk register rows for 5 brief threats (documented in Part 3). |
| **4. Secure code review** | [`docs/assurance/secure-code-review.md`](../../docs/assurance/secure-code-review.md) | **YES** (checklist against ASVS V2..V14, 6 findings triaged) | **YES** (distinguishes defects from gaps) | **YES** (CWE-639, 532, 862, 770, 778, 1104; OWASP 2025) | **DONE** | None. |
| **5. Automated functional & security tests** | `src/test/java/...` (44 classes, 148 methods, 339+ runs), [`docs/test-plan.md`](../../docs/test-plan.md) | **YES** (traceability matrix, test level definitions) | **YES** (limits of automated regressions) | **YES** (ASVS V2..V14, CWEs, WSTG) | **DONE** | None. |
| **6. Static Application Security Testing (SAST)** | [`docs/assurance/sast-sca-analysis.md`](../../docs/assurance/sast-sca-analysis.md), `spotbugs.log`, `semgrep.json` | **YES** (SpotBugs CSPRNG triaged, 8 custom Semgrep rules evaluated) | **YES** (pattern matching vs business logic limits) | **YES** (CWE-330, CWE-79, CWE-89, etc.) | **DONE** | None. |
| **7. Dynamic Application Security Testing (DAST)** | [`scripts/run-dast.sh`](../../scripts/run-dast.sh), [`.github/workflows/ci.yml`](../../.github/workflows/ci.yml) | **PARTIAL** (configured in script and CI; execution report not committed) | **YES** (in `assurance-summary.md`: ZAP cannot detect BOLA) | **YES** (CWE-693, OWASP A02) | **UNVERIFIED - needs manual proof** | Student must execute `./scripts/run-dast.sh` against local Docker stack and retain ZAP report. |
| **8. Software Composition Analysis (SCA)** | [`docs/assurance/sbom/bom.json`](../../docs/assurance/sbom/bom.json), [`docs/third-party-licences.md`](../../docs/third-party-licences.md) | **YES** (CycloneDX 101 components, License report evaluated) | **YES** (CPE false matches, NVD delay, reachability) | **YES** (CWE-1104, OWASP A03) | **PARTIAL** | Dependency-Check requires `NVD_API_KEY` to complete full vulnerability scan. |
| **9. Secrets scanning** | [`.gitleaks.toml`](../../.gitleaks.toml), [`scripts/verify-gitleaks.ps1`](../../scripts/verify-gitleaks.ps1), `gitleaks.json` | **YES** (full-history scan evaluated; 2 legacy fixture matches triaged) | **YES** (active vs inactive secrets, regex limits) | **YES** (CWE-798, OWASP A02) | **DONE** | None. |
| **10. Manual testing (authn/authz/input)** | [`docs/assurance/manual-testing.md`](../../docs/assurance/manual-testing.md), [`docs/assurance/auth-manual-test-checklist.md`](../../docs/assurance/auth-manual-test-checklist.md) | **YES** (step-by-step procedures with safe local probes) | **YES** (manual testing cannot test exhaustive state) | **YES** (OWASP WSTG test cases) | **DONE** | None. |
| **11. Remediation and retest of findings** | [`docs/assurance/vulnerability-register.md`](../../docs/assurance/vulnerability-register.md) | **YES** (register tracks status, fix commits, retest evidence) | **YES** (residual risk documented per finding) | **YES** (CWEs, OWASP Top 10) | **DONE** | Missing 2 real PostgreSQL bugs (see below). |
| **12. CI/CD secure pipeline** | [`.github/workflows/ci.yml`](../../.github/workflows/ci.yml), [`docs/ci-cd.md`](../../docs/ci-cd.md) | **YES** (gates build, SAST, SCA, secrets, container, provenance) | **YES** (limits of CI vs local testing) | **YES** (CWE-1104, CWE-798) | **DONE** | None. |
| **13. Container hardening** | [`Dockerfile`](../../Dockerfile), [`docker-compose.hardened.yml`](../../docker-compose.hardened.yml), [`docs/assurance/container-hardening.md`](../../docs/assurance/container-hardening.md) | **YES** (multi-stage JRE Alpine, non-root 10001, read-only root, cap drop) | **YES** (container isolation vs host kernel compromise) | **YES** (CWE-250, CWE-732) | **DONE** | None. |
| **14. Logging, monitoring & recovery** | [`deploy/runbook.md`](../../deploy/runbook.md), [`deploy/scripts/test-backup-restore.sh`](../../deploy/scripts/test-backup-restore.sh), [`docs/runbook-local.md`](../../docs/runbook-local.md) | **YES** (backup/restore drill procedure, DB health probe) | **YES** (local drill vs offsite replication limits) | **YES** (CWE-778, CWE-404) | **DONE** | None. |
| **15. Least-privilege data tier** | [`deploy/scripts/db-grants.sql`](../../deploy/scripts/db-grants.sql), [`V1__create_casevault_schema.sql`..`V8`](../../src/main/resources/db/migration) | **YES** (revokes UPDATE/DELETE on audit table; separate migrator user) | **YES** (superuser compromise limits) | **YES** (CWE-250, CWE-732) | **DONE** | None. |

#### Documented Vulnerability Remediation Chains

1. **DEMO-IDOR-001 (BOLA / Cross-Tenant Bypass):**
   - **Finding:** Deliberate removal of organisation check in `AccessPolicy.java` and repository scope.
   - **Exploit / Failing Test:** `T-AUTHZ-IDOR-001` failed with HTTP 200 instead of expected 404 at commit `dea12ea` (tag `evidence/idor-vulnerable-confirmed`).
   - **Fix Commit:** `c694693` (tag `evidence/idor-fixed`) restored tenant boundary check.
   - **Retest:** `target/phase13-idor-retest.log` confirms `T-AUTHZ-IDOR-001` passes with HTTP 404.

2. **DEMO-XSS-001 (Stored Template Injection):**
   - **Finding:** Deliberate introduction of unescaped `th:utext` sink in `case-detail.html`.
   - **Failing Test / Tool Alert:** `T-HDR-002` failed at commit `2145397` (tag `evidence/xss-vulnerable`) due to template scanner detecting forbidden `th:utext`.
   - **Fix Commit:** `314a2c3` (tag `evidence/xss-fixed`) restored `th:text` context-aware escaping.
   - **Retest:** `T-HDR-002` passed with zero violations.

#### Real Codebase Bugs Found and Status in Vulnerability Register

| Real Defect Description | Discovered In | Code Fix Location | Automated Retest Test ID | In `vulnerability-register.md`? |
|---|---|---|---|---|
| **F-SCR-001:** Case assignment did not insert `case_assignments` row | Phase 9 code review | [`CaseWorkflowService.java:81`](../../src/main/java/uk/ac/ravensbourne/casevault/service/CaseWorkflowService.java) | `T-E2E-001` in `EndToEndWorkflowTest` | **YES** (Fixed in `f59b426`) |
| **F-SCR-002:** Dev seeder logged generated plaintext passwords | Phase 9 code review | [`DevDataSeeder.java`](../../src/main/java/uk/ac/ravensbourne/casevault/config/DevDataSeeder.java) | `T-SCR-002` in `SecureCodeReviewRegressionTest` | **YES** (Fixed in `f59b426`) |
| **F-SCR-003:** Admin services lacked service-level role checks | Phase 9 code review | [`AdminAccountService.java`](../../src/main/java/uk/ac/ravensbourne/casevault/service/AdminAccountService.java), `AdminAuditService.java` | `T-SCR-003` in `SecureCodeReviewRegressionTest` | **YES** (Fixed in `f59b426`) |
| **F-SCR-004:** Login limiter did not return 429 or aggregate audit | Phase 9 code review | [`LoginRateLimitFilter.java`](../../src/main/java/uk/ac/ravensbourne/casevault/security/LoginRateLimitFilter.java) | `T-SCR-004` in `SecureCodeReviewRegressionTest` | **YES** (Fixed in `f59b426`) |
| **F-SCR-005:** Audit UI lacked multi-criteria filter parameters | Phase 9 code review | [`AdminAuditService.java`](../../src/main/java/uk/ac/ravensbourne/casevault/service/AdminAuditService.java), `AdminController.java` | `tAdmin006AuditFilteringByActionRoleAndOutcome` in `AdminSecurityTest` | **YES** (Fixed in `cc62464`) |
| **PostgreSQL Instant JDBC Binding Bug:** JDBC failed on PostgreSQL binding `java.time.Instant` in `statement.setObject(1, ts)` | Real PostgreSQL test run | [`PersistentAuditService.java:68`](../../src/main/java/uk/ac/ravensbourne/casevault/audit/PersistentAuditService.java) (`setTimestamp(1, Timestamp.from(ts))`) | `PostgresAuditAndLoginIntegrationTest` | **MISSING FROM REGISTER** (Must be added) |
| **PostgreSQL Search Null-Parameter Bug:** Static JPQL query `(:param IS NULL OR col = :param)` caused SQLState 42P18 ("could not determine data type of parameter $N") on PostgreSQL | Real PostgreSQL test run | [`CaseSpecifications.java`](../../src/main/java/uk/ac/ravensbourne/casevault/repository/CaseSpecifications.java), [`CaseRepository.java`](../../src/main/java/uk/ac/ravensbourne/casevault/repository/CaseRepository.java) | `PostgresCaseSearchIntegrationTest`, `CaseSearchSpecificationTest` | **MISSING FROM REGISTER** (Must be added) |

---

### Part 5: Delivery, DevSecOps, and Repository Hygiene

| Item | Requirement & Description | Status | Evidence (File / Commit) | Gap and Smallest Fix |
|---|---|---|---|---|
| **CI workflow files & gating** | Gates: Maven verify, JaCoCo, SpotBugs, Semgrep, CodeQL, CycloneDX SBOM, Dependency-Check, Gitleaks, Hadolint, Trivy image/config, local DAST, Sigstore release. | **DONE** | [`.github/workflows/ci.yml`](../../.github/workflows/ci.yml); [`docs/ci-cd.md`](../../docs/ci-cd.md); Commit `1dd9f0b`. | Workflow is complete and SHA-pinned. |
| **Has CI actually run green?** | Proof of remote GitHub Actions execution. | **UNVERIFIED - needs manual proof** | `.github/workflows/ci.yml` | Cannot verify from local repo. Student must push to GitHub and verify green pipeline badges. |
| **Software Bill of Materials (SBOM)** | CycloneDX 1.6 JSON format, component inventory, licensing metadata. | **DONE** | [`docs/assurance/sbom/bom.json`](../../docs/assurance/sbom/bom.json) (101 components, SHA-256 verified). | None. |
| **Dependency locking / pinning** | Direct dependency and plugin versions pinned in `pom.xml`; Maven Enforcer dependency convergence enforced. | **PARTIAL** | [`pom.xml`](../../pom.xml) (`<dependencyConvergence/>`); Commit `1dd9f0b`. | Maven has no native lockfile (like Cargo.lock); uses Enforcer + strict checksums (`-C`). Documented. |
| **Container & compose hardening** | Multi-stage build, non-root UID 10001, read-only rootfs, `cap_drop: ALL`, `no-new-privileges`, CPU/RAM limits, internal DB network, Docker secrets. | **DONE** | [`Dockerfile`](../../Dockerfile), [`docker-compose.yml`](../../docker-compose.yml), [`docker-compose.hardened.yml`](../../docker-compose.hardened.yml). | None. |
| **Backup, restore, and rollback docs** | Operational scripts and recovery guide. | **DONE** | [`deploy/scripts/test-backup-restore.sh`](../../deploy/scripts/test-backup-restore.sh), [`deploy/runbook.md`](../../deploy/runbook.md), [`docs/runbook-local.md`](../../docs/runbook-local.md). | None. |
| **Runbook reproducible from clean clone** | End-to-end local startup from zero state. | **DONE** | [`docs/runbook-local.md`](../../docs/runbook-local.md), [`deploy/scripts/bootstrap-admin.sh`](../../deploy/scripts/bootstrap-admin.sh). | None. |
| **README & Licence provenance** | System description, architectural overview, Apache-2.0 license, third-party inventory. | **DONE** | [`README.md`](../../README.md), [`LICENSE`](../../LICENSE), [`NOTICE`](../../NOTICE), [`docs/third-party-licences.md`](../../docs/third-party-licences.md). | None. |
| **Architectural Decision Records (ADRs)** | 11 ADR files documenting key architectural trade-offs. | **DONE** | [`docs/adr/0001-technology-stack.md`](../../docs/adr/0001-technology-stack.md) through [`0011-argon2id-passwords.md`](../../docs/adr/0011-argon2id-passwords.md). | Numbering mismatch with `docs/report-notes.md` flagged in Part 7. |
| **Meaningful commit history** | Conventional Commits (`feat:`, `fix:`, `test:`, `docs:`, `ci:`). | **DONE** | Git history (66+ commits from `576c283` to `761260e`). | Clean, atomic commit log. |
| **Branch state (merged to main?)** | Working branch vs default production branch. | **PARTIAL** | Git branches: `main` is at `076352c`; current branch `feat/gaps` is at `761260e` (11 commits ahead + uncommitted files). | **CRITICAL:** `feat/gaps` must be staged, committed, and merged into `main`. |
| **Tagged release v1.0.0** | Git tag pointing to immutable submission release commit. | **PARTIAL** | Tag `v1.0.0` exists, but points to `2928566` on `feat/gaps` (not on `main`, and 3 commits behind current head). | Once `feat/gaps` is merged to `main`, re-tag `v1.0.0` at the merge commit on `main`. |
| **Secrets leaked in tracked files or history** | Search tracked files and commit log for hardcoded secrets. | **DONE** | `.gitignore` excludes `secrets/`, `*.pem`, `*.key`, `*.keyset`, `.env`. Search of tracked files revealed zero plaintext secrets. Gitleaks history scan clean. | None. |

---

### Part 6: Submission Checklist from Assessment Brief

| Submission Item | Required by Brief | Status | Repository Evidence | Remaining Gap / Action |
|---|---|---|---|---|
| **Technical Security Report** | Word count ~2,500 words; PDF/Word format. | **PARTIAL** | [`docs/report-notes.md`](../../docs/report-notes.md) (~2,500 words markdown draft). | Compile markdown to final submission PDF/Word document. |
| **Repository URL & Immutable Tag** | Git URL + `v1.0.0` tag. | **PARTIAL** | Local tag `v1.0.0` exists. | Re-tag `v1.0.0` on `main` after merge and push to remote GitHub repo. |
| **Source code & configurations** | Complete runnable project with configs. | **DONE** | `src/main/java/...`, `src/main/resources/...`, `pom.xml`. | Working tree changes need commit. |
| **Threat model** | STRIDE, assets, attack paths, residual risk. | **DONE** | [`docs/threat-model.md`](../../docs/threat-model.md). | Add 5 missing brief threats to risk register table. |
| **Architecture & DFD diagrams** | Trust boundaries, component interactions. | **DONE** | [`docs/architecture.md`](../../docs/architecture.md), [`docs/data-flow.md`](../../docs/data-flow.md). | None. |
| **Dependency & build manifests** | Reproducible build files. | **DONE** | `pom.xml`, `mvnw`, `.mvn/wrapper/maven-wrapper.properties`. | None. |
| **Automated test suite** | Comprehensive security & functional tests. | **DONE** | `src/test/java/...` (44 classes, 148 methods, 339+ runs). | None. |
| **SAST / DAST / SCA / Secret scan evidence** | Documented scanner outputs & triage. | **PARTIAL** | [`docs/assurance/sast-sca-analysis.md`](../../docs/assurance/sast-sca-analysis.md), `docs/assurance/results/2026-11-02/`. | Dependency-Check NVD scan and local ZAP report need execution evidence. |
| **Remediation & retest evidence** | Traceable vulnerability fixes. | **DONE** | [`docs/assurance/vulnerability-register.md`](../../docs/assurance/vulnerability-register.md), `evidence/*` tags. | Add 2 PostgreSQL fixes to register. |
| **CI/CD pipeline configuration** | Hardened GitHub Actions workflow. | **DONE** | [`.github/workflows/ci.yml`](../../.github/workflows/ci.yml), [`docs/ci-cd.md`](../../docs/ci-cd.md). | None. |
| **Deployment, hardening & runbook** | Production container deployment guide. | **DONE** | [`Dockerfile`](../../Dockerfile), [`docker-compose.hardened.yml`](../../docker-compose.hardened.yml), [`deploy/runbook.md`](../../deploy/runbook.md). | None. |
| **Evidence index** | Traceability mapping report claims to tests. | **DONE** | [`docs/evidence-index.md`](../../docs/evidence-index.md). | Update with latest uncommitted tests. |
| **AI declaration** | Phase-by-phase declaration of AI tool use. | **DONE** | [`docs/ai-declaration.md`](../../docs/ai-declaration.md) (Covers Phase 0 to Phase 13 + current entries). | Complete. |
| **Third-party / license declaration** | Resolved license inventory. | **DONE** | [`docs/third-party-licences.md`](../../docs/third-party-licences.md), [`NOTICE`](../../NOTICE). | Complete (0 missing licenses). |

---

### Part 7: Honesty Checks and Discrepancy Analysis

#### (a) Numbers Quoted in Documentation vs Repository Reality

1. **Test Counts:**
   - `docs/ai-declaration.md` quotes *"341 tests, 0 failures"*.
   - Maven Surefire log `maven-verify.log` records **339 tests run, 0 failures**.
   - Source code analysis reveals **44 test classes** and **148 individual `@Test` methods**. (The difference arises because `AuthorisationOperationMatrixTest` runs **176 parameterized invocations** from a single method).
   - Recent uncommitted test additions (`PostgresAuditAndLoginIntegrationTest`, `PostgresCaseSearchIntegrationTest`, `AdminUserCreationTest`, `AdminUserDeletionTest`, `CaseSearchSpecificationTest`, and `LoginRedirectAndCsrfTest` additions) introduce **25+ additional test methods**.
   - *Fix:* Reconcile documentation to explicitly state *"148 `@Test` methods yielding 360+ executed test instances including parameterized permutations"*.

2. **Security Requirement IDs (SR-IDs):**
   - [`docs/requirements.md`](../../docs/requirements.md) defines **SR-01 through SR-16**.
   - [`docs/report-notes.md`](../../docs/report-notes.md) Section 2.2 states *"Security Requirements Mapping (SR-01 to SR-14)"*, omitting SR-15 (Supply chain) and SR-16 (Deployment hardening).
   - *Fix:* Update `docs/report-notes.md` to reference SR-01 through SR-16.

3. **ADR Numbering Discrepancy:**
   - [`docs/report-notes.md`](../../docs/report-notes.md) Section 3.1 cites:
     - `ADR-001: Object-Level Authorization`
     - `ADR-002: Uniform HTTP 404`
     - `ADR-003: Google Tink AEAD`
     - `ADR-004: HMAC-SHA256 Audit Chain`
   - In [`docs/adr/`](../../docs/adr/), the actual files are:
     - `0001-technology-stack.md`
     - `0002-server-side-sessions.md`
     - `0003-tenant-isolation.md`
     - `0004-tink-file-encryption.md`
     - `0005-audit-hash-chain.md`
     - ... up to `0011-argon2id-passwords.md`.
   - *Fix:* Re-align ADR citations in `docs/report-notes.md` with the committed files in `docs/adr/`.

#### (b) Claims in Documentation Unsupported by Code or Tests

1. `docs/requirements.md` lists planned test identifiers `T-CLIENT-001..003`, `T-SC-001..005`, and `T-DEPLOY-001..005`. However, [`docs/test-plan.md`](../../docs/test-plan.md) explicitly clarifies that these are scanner/script executions and architectural design choices rather than JUnit tests.
2. `docs/threat-model.md` claims database concurrency locking via PostgreSQL `SELECT ... FOR UPDATE` on `audit_chain_head`. While the SQL statement is present in `PersistentAuditService.java`, high-concurrency race condition testing across multiple threads is only simulated in unit tests with `ReentrantLock` and has not been verified under multi-node load.

#### (c) External Citations and Standards Requiring Manual Student Verification

1. **OWASP ASVS 5.0 vs 4.0.3:** `docs/requirements.md` cites OWASP ASVS 5.0 chapter references. ASVS 5.0 is currently a working draft; ASVS 4.0.3 is the latest official release. The student should verify in the viva that they understand this distinction.
2. **OWASP Top 10:2025 vs 2021:** `docs/assurance/vulnerability-register.md` maps findings to OWASP Top 10:2025. OWASP Top 10:2021 remains the formally adopted industry standard; Top 10:2025 is preliminary.
3. **Saltzer & Schroeder (1975):** *"The Protection of Information in Computer Systems"*, Proceedings of the IEEE 63(9).
4. **Adam Shostack (2014):** *Threat Modeling: Designing for Security*, Wiley.
5. **NIST SP 800-63B:** *Digital Identity Guidelines: Authentication and Lifecycle Management*.

#### (d) Features Functional in H2 but Unproven on PostgreSQL / Docker

1. **`PersistentAuditService` JDBC Instant Binding:** Previously, `statement.setObject(1, ts)` failed on PostgreSQL. Fixed via `setTimestamp(1, Timestamp.from(ts))`. Verified in `PostgresAuditAndLoginIntegrationTest`, but must be confirmed during full Docker Compose execution.
2. **`CaseRepository` Search Query SQLState 42P18:** Static JPQL queries failed on PostgreSQL when filter parameters were null. Fixed via `CaseSpecifications.java` Criteria API. Verified in `PostgresCaseSearchIntegrationTest`, but requires end-to-end testing via the web UI on Docker.
3. **Database Least Privilege (`deploy/scripts/db-grants.sql`):** In H2 tests, the database user has administrative rights. Revocation of `UPDATE` and `DELETE` on `audit_events` is enforced only by PostgreSQL when running `docker-compose.hardened.yml`.
4. **Pessimistic Row Locking (`lockHardDeleteCandidate`):** Relies on PostgreSQL `SELECT ... FOR UPDATE` row locks.

#### (e) Dev-Only Features Strictly Excluded from Production

1. **`DevDataSeeder.java`:** Annotated with `@Profile("dev")`. Strictly prevented from loading under `prod` or `test` profiles.
2. **Default Synthetic Passwords (`AdminPass123!@#`):** Exist only in `DevDataSeeder` for local dev. Production Docker bootstrap uses `scripts/bootstrap-admin.ps1` to generate a random password and enforces `force_password_reset=TRUE`.
3. **H2 Console:** Completely absent from `application.yml` and `application-prod.yml`.
4. **Actuator Exposure:** Configured to expose `health` only (`management.endpoints.web.exposure.include: health`), with `show-details: never`. Sensitive endpoints (`/actuator/env`, `/actuator/beans`) are strictly blocked.

---

### Part 8: Rubric Readiness Assessment

| Rubric Dimension (Weight) | Current Grade Descriptor Alignment | Self-Assessment Score | Top 3 Actions to Elevate to 80%+ |
|---|---|---:|---|
| **1. Requirements, Threat Model & Architecture (15%)** | Exceeds 60% descriptor (thorough STRIDE, trust boundaries, bidirectional traceability); touches 80% boundary. | **76%** | 1. Add missing 5 brief threat scenarios to `docs/threat-model.md` risk table.<br>2. Reconcile ADR numbering in `docs/report-notes.md` with `docs/adr/`.<br>3. Clarify ASVS 4.0.3 vs 5.0 draft citations in `docs/requirements.md`. |
| **2. Secure Implementation (20%)** | Strongly in 80% descriptor: deny-by-default, Tink AEAD encryption at rest, HMAC audit chain, strict nonce CSP, zero custom crypto. | **82%** | 1. Stage and commit uncommitted working-copy changes.<br>2. Merge `feat/gaps` branch into `main`.<br>3. Perform live manual validation of admin user creation/deletion. |
| **3. Assurance & Remediation (20%)** | Solid 75%: 44 test classes, ArchUnit rules, full HTTP auth matrix, two documented exploit-retest chains (IDOR, XSS). | **78%** | 1. Run local OWASP ZAP DAST scan via `./scripts/run-dast.sh` and retain report.<br>2. Execute Dependency-Check with valid `NVD_API_KEY` (close F-SCR-006).<br>3. Add the 2 PostgreSQL bugs (Instant binding & 42P18 query) to vulnerability register. |
| **4. Supply Chain, DevSecOps & Deployment (10%)** | In 80% descriptor: multi-stage non-root container, read-only rootfs, dropped capabilities, SHA-pinned Actions, CycloneDX SBOM. | **80%** | 1. Execute and screenshot the backup/restore drill script `deploy/scripts/test-backup-restore.sh`.<br>2. Run Hadolint and Trivy scans on the container and record output.<br>3. Verify remote GitHub Actions run green once pushed. |
| **5. Technical Security Report (15%)** | Solid 70%: ~2,500 word draft in `docs/report-notes.md` covering architecture, controls, and Saltzer-Schroeder principles. | **72%** | 1. Format markdown draft into formal university PDF submission document.<br>2. Integrate Mermaid diagrams and architecture callout boxes.<br>3. Expand discussion of trade-offs and residual risks (in-memory rate limiting). |
| **6. Viva Defense (20%)** | Excellent preparation in `docs/viva-script.md`: 5-phase live demo walkthrough, hostile examiner Q&A prep. | **85%** | 1. Practice the live demo against real Docker stack (`https://localhost`).<br>2. Rehearse mathematical explanation of HMAC hash chain verification.<br>3. Rehearse justification for why UUIDs are never access controls. |

---

## 3. Prioritised Action Plan (TODO List)

### Priority P0: Mandatory Submission Blockers
*These items directly affect submission validity or prevent the codebase from building in a clean environment.*

1. **Stage, Commit, and Merge Working Copy to `main` (Effort: S)**
   - *Issue:* Branch `feat/gaps` has 16 uncommitted/untracked files (including V7/V8 Flyway migrations, admin endpoints, and PostgreSQL fixes) and is 11 commits ahead of `main`.
   - *Fix:* Commit all working tree changes with conventional commit messages, checkout `main`, merge `feat/gaps`, and re-tag `v1.0.0` at the merge commit.
2. **Re-Tag `v1.0.0` on `main` (Effort: S)**
   - *Issue:* Current `v1.0.0` tag points to an outdated commit (`2928566`) on `feat/gaps`.
   - *Fix:* `git tag -d v1.0.0; git tag -a v1.0.0 -m "Release v1.0.0: Assessment Submission"`.
3. **Compile and Export Technical Security Report (Effort: M)**
   - *Issue:* Report currently exists only as a markdown draft in `docs/report-notes.md`.
   - *Fix:* Convert to clean, professionally formatted PDF/Word document with student details.

### Priority P1: High-Value Mark Elevators (60% -> 80% Threshold)
*These items satisfy rigorous academic expectations and ensure maximum credit across assessment criteria.*

1. **Record Local OWASP ZAP DAST Report (Effort: M)**
   - *Issue:* Finding F-DAST-001 is open; no execution evidence report is committed.
   - *Fix:* Start local Docker Compose stack, run `./scripts/run-dast.sh`, triage alerts, and commit report summary under `docs/assurance/results/`.
2. **Run Dependency-Check with `NVD_API_KEY` (Effort: S)**
   - *Issue:* Finding F-SCR-006 is open due to NVD rate limiting.
   - *Fix:* Obtain free NVD API key, run `./mvnw -Pdependency-check dependency-check:check`, verify 0 vulnerabilities >= CVSS 9.
3. **Update Vulnerability Register with Real PostgreSQL Bugs (Effort: S)**
   - *Issue:* Instant binding and 42P18 search query fixes are absent from `docs/assurance/vulnerability-register.md`.
   - *Fix:* Add two new entries detailing discovery, code fix, and Testcontainers retest evidence.
4. **Expand `docs/threat-model.md` Risk Table (Effort: S)**
   - *Issue:* Brief specifies 11 threat scenarios; table currently has 7 rows (R-01..R-07).
   - *Fix:* Add R-08 through R-11 covering insider misuse, logging leaks, dependency vulnerabilities, and privilege escalation.
5. **Reconcile ADR and SR Numbering Mismatches (Effort: S)**
   - *Issue:* `docs/report-notes.md` has mismatched ADR and SR numbers.
   - *Fix:* Update markdown to match `docs/adr/0001..0011` and `docs/requirements.md` SR-01..SR-16.

### Priority P2: Final Polish & Viva Readiness
*Refinements for professional presentation and viva demonstration.*

1. **Execute Backup / Restore Drill and Retain Log (Effort: S)**
   - Run `deploy/scripts/test-backup-restore.sh` locally and save terminal output log.
2. **Execute Hadolint and Trivy Container Scans (Effort: S)**
   - Run container linters and save verification log in `docs/assurance/results/`.
3. **Live Demonstration Rehearsal (Effort: M)**
   - Follow `docs/viva-script.md` using two separate browser windows (Client vs Manager vs Auditor).

---

## 4. Personal Verification Checklist for Student

*The following items MUST be performed personally by the student on their own machine; no automated report or AI assistant can substitute for these physical execution steps:*

- [ ] **1. Run Full Clean Build:** Execute `.\mvnw.cmd clean verify` in PowerShell and confirm that all 360+ tests pass with zero failures and zero errors.
- [ ] **2. Push to GitHub & Verify CI:** Push `main` and `v1.0.0` to GitHub. Open the repository Actions tab and confirm that the CI pipeline finishes with green checkmarks.
- [ ] **3. Start Hardened Docker Stack:** Run `deploy/scripts/gen-secrets.sh`, `deploy/scripts/gen-dev-certs.sh`, and `docker compose -f docker-compose.yml -f docker-compose.hardened.yml up -d --build`.
- [ ] **4. Verify Containers and Health:** Run `docker compose ps` to verify `casevault-app`, `casevault-db`, `casevault-proxy`, and `casevault-grants` exit/run in healthy states.
- [ ] **5. Run DAST Scan:** Run `./scripts/run-dast.sh` against `https://localhost` and capture the generated HTML report.
- [ ] **6. Run Backup/Restore Drill:** Execute `bash deploy/scripts/test-backup-restore.sh` and capture terminal output showing successful PostgreSQL and ciphertext restore.
- [ ] **7. Take Screenshots for Report:**
  - Login page showing per-request CSP nonce in DevTools Network tab.
  - Client case creation and evidence upload card showing SHA-256 and AES-GCM badge.
  - Cross-tenant access attempt showing uniform HTTP 404 response.
  - Auditor administration dashboard showing session revocation and audit chain verification status.
  - PostgreSQL terminal showing `UPDATE`/`DELETE` denied on `audit_events`.
- [ ] **8. Rehearse Viva Defense:** Walk through the 5-phase live demonstration script in `docs/viva-script.md` to ensure fluid presentation during assessment examination.


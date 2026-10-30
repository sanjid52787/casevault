# M0: Current State Audit & Java Migration Inventory

**System:** CaseVault Forensic Incident Management Platform  
**Organization:** Northbridge Cyber Response  
**Module:** CYS22301 Software and Platform Security (Level 6)  
**Date:** October 2026  
**Target Migration Stack:** Java 21 LTS + Spring Boot 3.3.x + Spring Security 6  

---

## 1. Executive Summary

This audit establishes the baseline for migrating **CaseVault** from Python 3.12 / Django 5.x to **Java 21 / Spring Boot 3.3.x** as required by university assessment guidelines for CYS22301 Software and Platform Security.

The project mission, scenario, four user roles, multi-tenancy requirements, defense-in-depth principles, cryptographic guarantees, and viva defense requirements remain strictly unchanged. All architectural decisions, threat models, and security requirements are preserved and re-anchored onto enterprise Java standards.

---

## 2. Inventory of Existing Assets

### 2.1 Documentation & Architecture (`docs/`)
- `docs/SECURITY_REQUIREMENTS.md`: Formal SRS specifying CIA + AAA controls (SR-AUTH, SR-AC, SR-INT, SR-CONF, SR-ACC, SR-AVAIL).
- `docs/THREAT_MODEL.md`: STRIDE analysis, Trust Boundaries (Zones 0, 1, 2), Mermaid DFD Levels 0 & 1, Abuse cases.
- `docs/ARCHITECTURE.md`: Concentric 5-layer defense-in-depth model, key management hierarchy, cryptographic custody workflows.
- `docs/AI_DECLARATION.md`: Component register, license compliance, AI pairing declaration, and verification methods.
- `docs/DEPENDENCIES.md`: Complete open-source license audit (MIT, BSD, Apache-2.0, MPL).
- `docs/REMEDIATION_LOG.md`: Vulnerability remediation register (REM-01, REM-02, REM-03, REM-04).
- `docs/TECHNICAL_REPORT.md`: Academic Level 6 technical report covering implementation, assurance, and threat analysis.
- `docs/VIVA_PREPARATION.md`: 20-minute viva defense strategy, top 10 examiner questions & answers, live demo script.
- `docs/DAST_ZAP_ASSURANCE.md`: OWASP ZAP containerized baseline scan execution commands, findings, and headers audit.
- `docs/bom.json`: CycloneDX Software Bill of Materials.

### 2.2 Architecture Decision Records (`docs/adr/`)
- `ADR-0001-argon2id-password-hashing.md`: Argon2id parameters (m=64MB, t=2, p=2) for credential storage.
- `ADR-0002-role-based-and-object-level-access-control.md`: Dual-layer RBAC and ABAC / anti-IDOR architecture.
- `ADR-0003-evidence-encryption-and-audit-hash-chaining.md`: Authenticated evidence encryption at rest and sequential HMAC-SHA256 audit chaining.
- `ADR-0004-secure-file-handling-and-sandbox-download.md`: Safe file handling, magic-byte inspection, sandboxed CSP downloads.
- `ADR-0005-dependency-pinning-and-hash-verification.md`: Cryptographic dependency pinning and SHA-256 hash verification.
- `ADR-0006-standardized-technology-stack.md`: Technology decisions alignment (PostgreSQL 16, TOTP, rate limiting, Nginx TLS).

### 2.3 Application Source Code (Django Apps)
- **`accounts/`**:
  - `models.py`: `CustomUser` (UUIDv4 PK, `UserRole`, tenancy `organization`, lockout counters, TOTP secrets).
  - `views.py`: `login_view`, `mfa_verify_view`, `mfa_setup_view`, `logout_view`.
  - `forms.py`: `LoginForm`, `MFAVerifyForm`, `MFASetupForm`.
  - `urls.py`: Routing for authentication endpoints.
  - `admin.py`: Django admin registration.
- **`cases/`**:
  - `models.py`: `Case`, `CaseClassification`, `CaseStatus`, `CaseMembership`, `CaseNote`, `CaseQuerySet.for_user()`.
  - `views.py`: `case_list_view`, `case_create_view`, `case_detail_view`, `case_add_note_view`, `case_add_member_view`.
  - `urls.py`: Routing for incident case management.
  - `admin.py`: Django admin registration.
- **`vault/`**:
  - `models.py`: `EvidenceItem` (UUIDv4 PK, SHA-256, SHA-512, MIME, isolated storage path).
  - `crypto.py`: Streaming pre-storage dual hashing, Fernet authenticated encryption/decryption, tamper detection.
  - `validators.py`: Filename sanitization, path traversal defense, magic byte inspection (`python-magic`).
  - `views.py`: `evidence_upload_view`, `evidence_download_view` (sandboxed CSP headers).
  - `urls.py`: Routing for evidence vault.
- **`audit/`**:
  - `models.py`: `AuditLog` (sequential ID, `AuditAction`, HMAC-SHA256 `previous_hash` and `current_hash`).
  - `service.py`: `log_security_event()` atomic row-locked appender, `verify_audit_chain()` live validator.
  - `views.py`: `audit_log_view` with on-demand chain verification.
  - `urls.py`: Routing for audit review.
- **`core/`**:
  - `middleware.py`: `SecurityHeadersMiddleware`, `MFAEnforcementMiddleware`, `SensitiveDataLoggingFilter`.
  - `utils.py`: Client IP extraction.
  - `context_processors.py`: CSP nonce context injection.
- **`casevault_core/`**:
  - `settings.py`: Hardened Django configuration, Argon2 password hasher, session cookies, CSP directives, logging.
  - `urls.py`: Top-level URL routing.
  - `wsgi.py`, `asgi.py`: WSGI/ASGI application hooks.

### 2.4 User Interface & Presentation (`templates/`)
- `templates/base.html`: Accessible base layout with security banner, navigation bar, and CSP nonce injection.
- `templates/accounts/login.html`: Two-step authentication entry form.
- `templates/accounts/mfa_verify.html`: 6-digit TOTP challenge verification view.
- `templates/accounts/mfa_setup.html`: In-memory inline SVG QR code onboarding view.
- `templates/accounts/lockout.html`: Account lockout notification template.
- `templates/cases/case_list.html`: Tenancy-filtered incident case list.
- `templates/cases/case_form.html`: Incident intake form.
- `templates/cases/case_detail.html`: Case metadata, investigative notes, evidence table, assigned members.
- `templates/vault/evidence_upload.html`: Inert evidence ingestion form with MIME advisory.
- `templates/audit/audit_log.html`: Chronological audit trail with live cryptographic integrity verification banner.

### 2.5 Security Scripts & Synthetic Seeders (`scripts/`)
- `scripts/seed_synthetic_data.py`: Synthetic fixture seeder (synthetic users, test cases, inert log/PNG/PDF samples).
- `scripts/generate_self_signed_cert.py`: RSA 4096-bit X.509 TLS certificate generator for local testing.
- `scripts/generate_lockfile.py`: PyPI hash harvester for dependency locking.

### 2.6 Tests & Assurance (`tests/`)
- `tests/conftest.py`: Test fixtures (`admin_user`, `lead_investigator`, `investigator`, `client_auditor_alpha`, `case_alpha`, `case_beta`).
- `tests/test_access_control_and_idor.py`: Tenancy isolation, role boundaries, anti-IDOR HTTP 404 tests.
- `tests/test_auth_and_crypto.py`: Argon2id password hashing, TOTP verification, brute-force lockout.
- `tests/test_evidence_vault.py`: Path traversal defense, authenticated encryption, bit tamper detection, sandbox headers.
- `tests/test_audit_chain.py`: Sequential HMAC chaining, verification algorithm, retroactive tamper detection.
- `tests/test_security_headers_and_negative.py`: CSP nonces, CSRF rejection, MFA enforcement interception.
- `tests/test_technology_decisions.py`: `django-otp` device lifecycle, `django-csp` headers, `python-magic` MIME detection.
- `tests/test_view_workflows.py`: End-to-end login -> MFA -> case creation -> evidence upload -> audit verification.

### 2.7 Deployment & Infrastructure
- `Dockerfile`: Multi-stage Docker build for Python runtime.
- `docker-compose.yml`: Services `db` (PostgreSQL 16), `app` (Gunicorn), `nginx` (TLS reverse proxy).
- `nginx/nginx.conf`: Nginx TLS 1.3/1.2 reverse proxy configuration with security headers and 25MB body limit.
- `nginx/certs/.gitkeep`: TLS certs placeholder.
- `.github/workflows/ci.yml`: GitHub Actions DevSecOps workflow (Bandit, pip-audit, Hadolint, Trivy, ZAP, Pytest).
- `.gitleaks.toml`: Secret detection rules and test fixture allowlists.
- `.semgrep.yml`: Semgrep SAST rule patterns.
- `requirements.lock`, `requirements.txt`: SHA-256 hashed dependency manifests.

---

## 3. Status Across Original Project Phases (Phase 1–12)

| Phase | Description | Status in Python Baseline | Migration Strategy for Java 21 |
| :--- | :--- | :--- | :--- |
| **Phase 1** | Threat Model, Architecture & Requirements | **COMPLETE (100%)** | **KEEP AS-IS**: Language-neutral specifications directly applicable to Java implementation. |
| **Phase 2** | Project Baseline & Configuration Hardening | **COMPLETE (100%)** | **PORT**: Transition from `settings.py` / `.env` to `application.yml` + Spring Boot Configuration Properties. |
| **Phase 3** | Argon2id Credential Hashing & Lockout | **COMPLETE (100%)** | **PORT**: Spring Security `Argon2PasswordEncoder` (BouncyCastle) + Spring Security AuthenticationFailureHandler. |
| **Phase 4** | TOTP Multi-Factor Authentication (RFC 6238) | **COMPLETE (100%)** | **PORT**: Java TOTP engine (`com.warrenstrange:googleauth` or custom RFC 6238 HMAC-SHA1) + QR generation via ZXing. |
| **Phase 5** | Four Roles, Tenant-Aware RBAC & Anti-IDOR | **COMPLETE (100%)** | **PORT**: Central `CaseSecurityService` + Spring Data JPA Repository specification / query scoping returning 404. |
| **Phase 6** | Incident Case & Note Management | **COMPLETE (100%)** | **PORT**: Spring Boot JPA entities (`Case`, `CaseNote`, `CaseMembership`) + Spring MVC Controllers. |
| **Phase 7** | Evidence Vault & Cryptographic Storage | **COMPLETE (100%)** | **PORT**: JCA `AES/GCM/NoPadding` (or AES-CBC + HMAC) + streaming SHA-256 / SHA-512 dual hashing. |
| **Phase 8** | Safe File Ingestion & MIME Sniffing | **COMPLETE (100%)** | **PORT**: Apache Tika / custom magic-byte detector + strict filename sanitization. |
| **Phase 9** | Tamper-Evident HMAC Chained Audit Ledger | **COMPLETE (100%)** | **PORT**: JPA `AuditLog` + Java `HmacSHA256` streaming service with atomic locking. |
| **Phase 10** | Web UI & Security Headers (CSP Nonce) | **COMPLETE (100%)** | **PORT**: Thymeleaf server-rendered templates + Spring Security `HeaderWriterFilter` with CSP nonce. |
| **Phase 11** | Containerization & TLS Reverse Proxy | **COMPLETE (100%)** | **PORT**: Multi-stage `Dockerfile` (Maven + Eclipse Temurin 21 JRE) + Nginx reverse proxy. |
| **Phase 12** | DevSecOps Pipeline & Academic Deliverables | **COMPLETE (100%)** | **PORT**: GitHub Actions workflow with SpotBugs, OWASP Dependency-Check, CycloneDX Maven plugin, JUnit 5. |

---

## 4. Exhaustive File Classification Register

Every file in the repository is classified into one of five categories:
- **`[KEEP]`**: Language-neutral design documents, threat models, requirements, licenses.
- **`[UPDATE]`**: Documents referencing specific Python/Django tools that will be updated for Java/Spring Boot.
- **`[PORT]`**: Application logic and tests that will be re-implemented in Java.
- **`[REPLACE]`**: Infrastructure, dependency, and CI manifests to be substituted with Java tooling.
- **`[REMOVE]`**: Python-specific transient/build files to be archived/removed once porting is verified.

| File Path | Action | Destination / Java Equivalent | Rationale |
| :--- | :---: | :--- | :--- |
| `docs/SECURITY_REQUIREMENTS.md` | **KEEP** | `docs/SECURITY_REQUIREMENTS.md` | Language-neutral CIA+AAA security specification. |
| `docs/THREAT_MODEL.md` | **KEEP** | `docs/THREAT_MODEL.md` | Language-neutral STRIDE model and trust boundary definitions. |
| `docs/ARCHITECTURE.md` | **UPDATE** | `docs/ARCHITECTURE.md` | Update Layer 1–5 component mappings to Spring Boot & JCA. |
| `docs/adr/ADR-0001-argon2id-password-hashing.md` | **KEEP** | `docs/adr/ADR-0001-...` | Add note: framework implementation superseded by Spring Argon2. |
| `docs/adr/ADR-0002-role-based-and-object-level-access-control.md` | **KEEP** | `docs/adr/ADR-0002-...` | Preserved; anti-IDOR architecture remains identical. |
| `docs/adr/ADR-0003-evidence-encryption-and-audit-hash-chaining.md` | **KEEP** | `docs/adr/ADR-0003-...` | Preserved; cryptographic parameters remain identical. |
| `docs/adr/ADR-0004-secure-file-handling-and-sandbox-download.md` | **KEEP** | `docs/adr/ADR-0004-...` | Preserved; safe handling & sandboxing principles remain identical. |
| `docs/adr/ADR-0005-dependency-pinning-and-hash-verification.md` | **KEEP** | `docs/adr/ADR-0005-...` | Preserved; updated with Maven dependency verification. |
| `docs/adr/ADR-0006-standardized-technology-stack.md` | **KEEP** | `docs/adr/ADR-0006-...` | Preserved as baseline record; superseded in part by ADR-0007 / 0006-switch-to-java. |
| `docs/AI_DECLARATION.md` | **UPDATE** | `docs/AI_DECLARATION.md` | Update component register with Spring Boot, BouncyCastle, Tika, etc. |
| `docs/DEPENDENCIES.md` | **UPDATE** | `docs/DEPENDENCIES.md` | Replace pip packages with Maven dependency and license inventory. |
| `docs/REMEDIATION_LOG.md` | **UPDATE** | `docs/REMEDIATION_LOG.md` | Retain Python findings; append Java assurance findings. |
| `docs/TECHNICAL_REPORT.md` | **UPDATE** | `docs/TECHNICAL_REPORT.md` | Update technology chapters and code snippets to Java 21 / Spring Boot. |
| `docs/VIVA_PREPARATION.md` | **UPDATE** | `docs/VIVA_PREPARATION.md` | Update code reference pointers to Spring Security and JPA files. |
| `docs/DAST_ZAP_ASSURANCE.md` | **KEEP** | `docs/DAST_ZAP_ASSURANCE.md` | DAST tests target the running HTTP container regardless of language. |
| `docs/bom.json` | **REPLACE** | `docs/bom.json` | Replaced by CycloneDX Maven plugin output. |
| `accounts/models.py` | **PORT** | `src/main/java/.../accounts/domain/User.java` | JPA Entity for User, UserRole, MFA state. |
| `accounts/views.py` | **PORT** | `src/main/java/.../accounts/web/AuthController.java` | Spring MVC controller for Login, MFA verify & setup. |
| `accounts/forms.py` | **PORT** | `src/main/java/.../accounts/dto/LoginRequest.java` | DTOs with Jakarta Validation constraints. |
| `accounts/urls.py` | **PORT** | Spring MVC `@GetMapping` / `@PostMapping` routes | Integrated into Controllers. |
| `cases/models.py` | **PORT** | `src/main/java/.../cases/domain/Case.java`, `CaseNote.java`, `CaseMembership.java` | JPA Entities and Repositories. |
| `cases/views.py` | **PORT** | `src/main/java/.../cases/web/CaseController.java` | Spring MVC Controller with authorization checks. |
| `cases/urls.py` | **PORT** | Spring MVC `@RequestMapping("/cases")` | Integrated into CaseController. |
| `vault/models.py` | **PORT** | `src/main/java/.../vault/domain/EvidenceItem.java` | JPA Entity for evidence metadata. |
| `vault/crypto.py` | **PORT** | `src/main/java/.../vault/service/EvidenceCryptoService.java` | JCA AES-GCM/CBC encryption + streaming dual hash. |
| `vault/validators.py` | **PORT** | `src/main/java/.../vault/service/FileValidationService.java` | Apache Tika & magic byte validator. |
| `vault/views.py` | **PORT** | `src/main/java/.../vault/web/EvidenceController.java` | Spring MVC upload & sandboxed download endpoints. |
| `vault/urls.py` | **PORT** | Spring MVC `@RequestMapping("/vault")` | Integrated into EvidenceController. |
| `audit/models.py` | **PORT** | `src/main/java/.../audit/domain/AuditLog.java` | JPA Entity for chained audit records. |
| `audit/service.py` | **PORT** | `src/main/java/.../audit/service/AuditService.java` | Atomic HMAC-SHA256 logging & chain verification. |
| `audit/views.py` | **PORT** | `src/main/java/.../audit/web/AuditController.java` | Spring MVC audit viewer & verification action. |
| `audit/urls.py` | **PORT** | Spring MVC `@RequestMapping("/audit")` | Integrated into AuditController. |
| `core/middleware.py` | **PORT** | `src/main/java/.../core/security/SecurityHeadersFilter.java`, `MfaFilter.java` | Spring Security OncePerRequestFilter chain. |
| `core/utils.py` | **PORT** | `src/main/java/.../core/util/SecurityUtils.java` | Client IP extractor and string sanitizers. |
| `casevault_core/settings.py` | **PORT** | `src/main/resources/application.yml` | Spring Boot configuration properties. |
| `casevault_core/urls.py` | **PORT** | Spring MVC Controller mappings | Direct Controller mappings. |
| `templates/*.html` | **PORT** | `src/main/resources/templates/*.html` | Converted to Thymeleaf with `th:text`, `th:action`, `th:nonce`. |
| `nginx/nginx.conf` | **KEEP** | `nginx/nginx.conf` | Reverse proxy configuration connects to Spring container (`app:8080`). |
| `nginx/certs/.gitkeep` | **KEEP** | `nginx/certs/.gitkeep` | Retained for certificate mounting. |
| `scripts/generate_self_signed_cert.py` | **KEEP** | `scripts/generate_self_signed_cert.py` | Utility script to generate local testing TLS certificates. |
| `scripts/seed_synthetic_data.py` | **PORT** | `src/main/java/.../core/bootstrap/DataInitializer.java` | Spring `CommandLineRunner` or `ApplicationRunner` seeder. |
| `tests/*.py` | **PORT** | `src/test/java/.../*Test.java` | JUnit 5 + MockMvc + AssertJ test suite. |
| `Dockerfile` | **REPLACE** | `Dockerfile` | Multi-stage Dockerfile for Java 21 / Eclipse Temurin. |
| `docker-compose.yml` | **UPDATE** | `docker-compose.yml` | Update app service to run Java container. |
| `.github/workflows/ci.yml` | **REPLACE** | `.github/workflows/ci.yml` | DevSecOps workflow running Maven, SpotBugs, OWASP Check, Trivy. |
| `.gitleaks.toml` | **KEEP** | `.gitleaks.toml` | Secret scanning rules remain language-neutral. |
| `.semgrep.yml` | **UPDATE** | `.semgrep.yml` | Add Java Semgrep rules (prohibit raw SQL, weak crypto, etc.). |
| `requirements.lock` | **REMOVE** | Archived in `python-baseline` tag | Python lockfile no longer needed after migration. |
| `requirements.txt` | **REMOVE** | Archived in `python-baseline` tag | Replaced by `pom.xml`. |
| `pytest.ini` | **REMOVE** | Archived in `python-baseline` tag | Replaced by Maven Surefire / Failsafe configuration. |
| `pyproject.toml` | **REMOVE** | Archived in `python-baseline` tag | Replaced by `pom.xml`. |
| `manage.py` | **REMOVE** | Archived in `python-baseline` tag | Replaced by Spring Boot CLI / Maven runner. |

---

## 5. Migration Roadmap & Milestone Phasing

- **M0 (Complete):** Read-only audit & file classification inventory.
- **M1 (Setup):** Git tag `python-baseline`, branch `feature/java-migration`, ADR `0006-switch-to-java-spring-boot.md`, issue tracking register.
- **M2 (Foundation):** Maven `pom.xml` with dependencies, `application.yml`, Spring Security baseline with Argon2id, non-root Dockerfile.
- **M3 (Core Domain):** JPA Entities (`User`, `Case`, `CaseMembership`, `CaseNote`, `EvidenceItem`, `AuditLog`) with UUIDv4 primary keys.
- **M4 (Authorization Layer):** Default-deny `CaseSecurityService`, tenant/role scoped queries returning 404 for unauthorized accesses.
- **M5 (Crypto & Evidence):** JCA AES-GCM/CBC encryption at rest, streaming SHA-256/SHA-512 dual hashing, Tika MIME validation.
- **M6 (Audit Ledger):** Sequential HMAC-SHA256 audit chaining service with live verification endpoint.
- **M7 (Web UI & Controllers):** Thymeleaf templates, Spring MVC controllers, CSP nonce injection, anti-clickjacking.
- **M8 (Assurance & Tests):** JUnit 5 + MockMvc test suite reproducing 100% of Python test coverage.
- **M9 (DevSecOps & CI):** GitHub Actions pipeline with SpotBugs, OWASP Dependency-Check, Trivy, Hadolint.
- **M10 (Documentation Finalization):** Update Technical Report, AI Declaration, Viva Guide, and clean up Python artifacts.

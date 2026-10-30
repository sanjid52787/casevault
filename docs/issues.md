# CaseVault Java Migration: Issue & Milestone Tracking Register

**System:** CaseVault Forensic Incident Management Platform  
**Organization:** Northbridge Cyber Response  
**Module:** CYS22301 Software and Platform Security (Level 6)  
**Standard:** ADR-0006 (`docs/adr/0006-switch-to-java-spring-boot.md`)  
**Target Stack:** Java 21 LTS + Spring Boot 3.3.x + Spring Security 6  

---

## Migration Issue Register (MIG-01 through MIG-12)

| Issue ID | Milestone / Component | Priority | Status | Description & Security Acceptance Criteria |
| :--- | :--- | :---: | :---: | :--- |
| **MIG-01** | Safe Migration Setup | Critical | **IN PROGRESS** | Preserve Python baseline under git tag `python-baseline`; create branch `feature/java-migration`; author ADR-0006; initialize tracking ledger. |
| **MIG-02** | Maven Build & Supply Chain | High | **OPEN** | Create `pom.xml` with exact pinned dependencies, Spring Boot starter parent 3.3.x, compiler target Java 21, and reproducible build configuration. |
| **MIG-03** | Core Security Filter Chain | Critical | **OPEN** | Configure Spring Security 6 `SecurityFilterChain` with default-deny rules, CSRF tokens, session fixation defense, and custom `SecurityHeadersFilter` with dynamic CSP nonces. |
| **MIG-04** | Identity & Argon2id Hashing | High | **OPEN** | Implement `CustomUserDetails`, `Argon2PasswordEncoder` (m=64MB, t=2, p=2), and brute-force lockout after 5 consecutive failures via `AuthenticationFailureHandler`. |
| **MIG-05** | TOTP Two-Factor Authentication | High | **OPEN** | Implement RFC 6238 TOTP verification, session elevation filter, Base32 secret generation, and inline SVG QR code rendering via ZXing (zero CDN leakage). |
| **MIG-06** | Domain Entities & JPA Layer | High | **OPEN** | Define JPA Entities (`User`, `Case`, `CaseMembership`, `CaseNote`, `EvidenceItem`, `AuditLog`) with UUIDv4 primary keys, PostgreSQL 16 schema, and H2 test configuration. |
| **MIG-07** | Central Authorization & Anti-IDOR | Critical | **OPEN** | Implement central `CaseSecurityService` with default-deny semantics, scoped repository lookups (`visibleTo(user)`), and return HTTP 404 for unauthorized objects. |
| **MIG-08** | Cryptographic Evidence Vault | Critical | **OPEN** | Implement streaming SHA-256 and SHA-512 dual pre-hashing, JCA AES-256-GCM encryption at rest, Apache Tika MIME detection, and sandboxed attachment downloads. |
| **MIG-09** | Chained HMAC Audit Ledger | Critical | **OPEN** | Implement sequential tamper-evident audit logger with row locking, JCA `HmacSHA256` chaining to `previous_hash`, and a live chain verification algorithm. |
| **MIG-10** | Thymeleaf UI & Controller Layer | Medium | **OPEN** | Convert server-rendered templates to Thymeleaf with HTML auto-escaping, anti-clickjacking, CSP nonce binding, and four-role role-aware navigation. |
| **MIG-11** | Automated Test Suite | High | **OPEN** | Implement comprehensive JUnit 5, MockMvc, and AssertJ test suite covering anti-IDOR, tamper detection, auth lockout, MFA, and achieving >80% code coverage. |
| **MIG-12** | DevSecOps Pipeline & Docs | High | **OPEN** | Multi-stage rootless Dockerfile (`eclipse-temurin:21-jre-alpine`), GitHub Actions CI with SpotBugs/Trivy/OWASP Check, updated Technical Report and Viva Guide. |

---

## Detailed Task Specifications

### MIG-01: Safe Migration Setup
- [x] Produce read-only audit `docs/migration/00-current-state-audit.md`.
- [x] Tag pure Python baseline as `python-baseline`.
- [x] Create branch `feature/java-migration`.
- [x] Author `docs/adr/0006-switch-to-java-spring-boot.md`.
- [x] Update previous ADRs with supersede references.
- [x] Create `docs/issues.md` issue ledger.

### MIG-02: Maven Build & Dependency Management
- [ ] Create `pom.xml` with dependencies:
  - `spring-boot-starter-web`
  - `spring-boot-starter-security`
  - `spring-boot-starter-data-jpa`
  - `spring-boot-starter-thymeleaf`
  - `spring-boot-starter-validation`
  - `org.postgresql:postgresql`
  - `com.h2database:h2` (test scope)
  - `org.bouncycastle:bcprov-jdk18on` (Argon2 provider)
  - `com.warrenstrange:googleauth` (RFC 6238 TOTP)
  - `com.google.zxing:core` & `javase` (inline QR generation)
  - `org.apache.tika:tika-core` (MIME sniffing)
  - `com.bucket4j:bucket4j-core` (rate limiting)
  - `org.cyclonedx:cyclonedx-maven-plugin`
  - `com.github.spotbugs:spotbugs-maven-plugin`

### MIG-03: Core Security Filter Chain & Configuration
- [ ] Configure `SecurityConfig` with `SecurityFilterChain`.
- [ ] Enforce session management: `SessionCreationPolicy.IF_REQUIRED`, session fixation protection.
- [ ] Enforce CSRF protection with `CookieCsrfTokenRepository.withHttpOnlyFalse()`.
- [ ] Enforce `SecurityHeadersFilter` with per-request dynamic CSP nonce (`nonce-...`), HSTS, `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`.

### MIG-04: Identity & Argon2id Password Hashing
- [ ] Implement `Argon2PasswordEncoder` with memory=65536 (64MB), iterations=2, parallelism=2, saltLength=16, hashLength=32.
- [ ] Minimum password length validation: 12 characters.
- [ ] Implement `LoginAttemptService` tracking consecutive failures per username/IP.
- [ ] Enforce 5-attempt limit and 15-minute lockout period.

### MIG-05: Multi-Factor Authentication (TOTP RFC 6238)
- [ ] Implement `MfaService` using `GoogleAuthenticator` / RFC 6238 TOTP.
- [ ] Enforce second-factor verification step before full session authentication.
- [ ] Inline SVG QR code generation without external network requests.
- [ ] `MfaAuthenticationFilter` intercepting unverified sessions.

### MIG-06: Domain Entities & Persistence
- [ ] Define `User` entity with `UserRole` enum (`ADMIN`, `LEAD_INVESTIGATOR`, `INVESTIGATOR`, `CLIENT_AUDITOR`).
- [ ] Define `Case` entity with UUIDv4 PK, `caseNumber`, `clientOrganization`, `CaseClassification`, `CaseStatus`.
- [ ] Define `CaseMembership` mapping investigators to cases.
- [ ] Define `CaseNote` with `isClientVisible` flag.
- [ ] Define `EvidenceItem` with SHA-256 and SHA-512 digests and UUID disk storage mapping.
- [ ] Define `AuditLog` with `previousHash` and `currentHash`.

### MIG-07: Central Authorization Layer & Anti-IDOR
- [ ] Create `CaseSecurityService`:
  - `canUserViewCase(User, Case)`
  - `canUserEditCase(User, Case)`
  - `canUserUploadEvidence(User, Case)`
  - `canUserViewNote(User, CaseNote)`
- [ ] Implement custom repository methods: `CaseRepository.findVisibleToUser(User)`.
- [ ] Throw custom `ResourceNotFoundException` (yielding HTTP 404, never 403) when looking up unauthorized case or evidence UUIDs.

### MIG-08: Cryptographic Evidence Vault
- [ ] Implement `EvidenceCryptoService`:
  - Streaming SHA-256 and SHA-512 calculation.
  - AES-256-GCM authenticated encryption at rest with 128-bit authentication tag.
  - Verification of decrypted plaintext hash against database record.
- [ ] Implement `FileValidationService`:
  - Path traversal neutralization.
  - Extension allowlist (`.txt`, `.log`, `.pdf`, `.png`, `.jpg`, `.pcap`, `.json`).
  - Apache Tika magic-byte content sniffing.
- [ ] Implement sandboxed download controller with `Content-Disposition: attachment` and `Content-Security-Policy: sandbox; default-src 'none';`.

### MIG-09: Tamper-Evident HMAC Chained Audit Subsystem
- [ ] Implement `AuditService`:
  - Atomic log appending with row locking on latest record.
  - Calculate `HmacSHA256` binding to previous entry's `currentHash`.
  - Live traversal verification algorithm (`verifyAuditChain()`).

### MIG-10: Web UI & Controller Layer
- [ ] Thymeleaf templates under `src/main/resources/templates/`.
- [ ] Contextual role-based rendering.
- [ ] CSP nonce binding on all styles and scripts.

### MIG-11: Automated Test Suite
- [ ] Unit & Integration tests in `src/test/java/`:
  - `AccessControlAndIdorTest`
  - `AuthAndCryptoTest`
  - `EvidenceVaultTest`
  - `AuditChainTest`
  - `SecurityHeadersTest`
  - `ViewWorkflowsTest`

### MIG-12: DevSecOps CI/CD & Deployment
- [ ] Rootless `Dockerfile` using `eclipse-temurin:21-jre-alpine` and unprivileged `casevault:10001` user.
- [ ] `.github/workflows/ci.yml` pipeline with Maven, SpotBugs, OWASP Dependency-Check, Trivy, Hadolint.
- [ ] Updated Technical Report & Viva Guide.

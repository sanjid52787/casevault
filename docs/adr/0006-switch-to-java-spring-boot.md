# ADR-0006: Migration from Python/Django to Java 21 and Spring Boot

## Status
Accepted (Migrating runtime and framework; supersedes framework-specific sections of ADR-0001 through ADR-0006).

---

## Context
CaseVault was initially prototyped and verified using Python 3.12 and Django 5.x. Following formal academic guidance from the module tutor for CYS22301 (Software and Platform Security, Level 6), the implementation language must be Java 21. Java is an explicitly approved language within the module specification, and implementing the platform in enterprise Java provides a rigorous foundation for evaluating type safety, memory safety, architectural patterns, and viva defense.

The core security mission, scenario (Northbridge Cyber Response), the four user roles (`client_user`, `security_analyst`, `case_manager`, `auditor_admin`), tenant-aware RBAC/ABAC, cryptographic guarantees (Argon2id, authenticated encryption at rest, HMAC audit hash chaining), and DevSecOps assurance objectives remain strictly unchanged.

---

## Decision
We will migrate CaseVault to **Java 21 (LTS)** using **Spring Boot 3.3.x** and **Spring Security 6**.

Key architectural pillars of the Java implementation:
1. **Runtime & Language:** Java 21 (LTS) utilizing records, sealed interfaces, pattern matching, and strong static typing.
2. **Framework:** Spring Boot 3.3.x with Spring Security 6 providing the centralized default-deny authorization filter chain.
3. **Data Access & Persistence:** Spring Data JPA with Hibernate, running against PostgreSQL 16 (production) and H2 in PostgreSQL compatibility mode (unit/integration tests).
4. **Presentation:** Server-rendered HTML using Thymeleaf with automatic context-aware escaping and dynamic CSP nonce injection.
5. **Cryptography:** Java Cryptography Architecture (JCA) using standard providers (`SunJCE`, BouncyCastle) for Argon2id (`Argon2PasswordEncoder`), AES-256-GCM authenticated encryption at rest, and HmacSHA256 audit chaining.
6. **MIME Inspection:** Apache Tika (`tika-core`) for robust magic byte inspection and content sniffing.
7. **Containerization & Deployment:** Multi-stage rootless Docker container (`eclipse-temurin:21-jre-alpine`) running unprivileged behind an Nginx TLS reverse proxy.

---

## Alternatives Considered

| Alternative | Evaluation | Outcome |
| :--- | :--- | :--- |
| **Stay on Python / Django** | Fully implemented and passing 24/24 tests, but conflicts with tutor requirement for Java evaluation in the assessment viva. | **Rejected** (Academic requirement) |
| **Quarkus (Java 21)** | Highly optimized for GraalVM native images and container density, but introduces specialized CDI/reactive paradigms that increase code complexity and diverge from standard enterprise reference patterns. | **Rejected** (Unnecessary complexity) |
| **Jakarta EE 10 / WildFly** | Enterprise standard, but requires heavyweight application server management, complex deployment descriptors, and provides less streamlined DevSecOps/test harness integration than Spring Boot. | **Rejected** (Operational overhead) |
| **Spring Boot 3.3.x (Java 21)** | Industry standard for secure enterprise applications; Spring Security 6 offers mature default-deny authorization, robust CSRF protection, comprehensive header writers, and seamless integration with testing (MockMvc, Testcontainers) and assurance tooling. | **Accepted** |

---

## Django → Spring Boot Technology Mapping

| Security / Architectural Component | Python / Django Baseline | Java 21 / Spring Boot Implementation | Security Control Preserved |
| :--- | :--- | :--- | :--- |
| **Language & Runtime** | Python 3.12 | Java 21 LTS (Eclipse Temurin) | Strong static typing, memory safety |
| **Web MVC Framework** | Django 5.2.18 | Spring Boot 3.3.x (Spring Web MVC) | Centralized request dispatching |
| **Security & Auth Engine** | Django Auth + Middleware | Spring Security 6 (`SecurityFilterChain`) | Default-deny filter chain |
| **Credential Hashing** | `argon2-cffi` (Argon2id) | Spring Security `Argon2PasswordEncoder` | NIST SP 800-63B, memory-hard hashing |
| **Multi-Factor Auth (MFA)** | `django-otp` + `pyotp` (RFC 6238) | `com.warrenstrange:googleauth` (RFC 6238) | NIST AAL2 TOTP second factor |
| **Brute-Force & Lockout** | `django-axes` + `django-ratelimit` | Spring Security failure handler + Bucket4j | Account lockout after 5 failed attempts |
| **Relational Database** | PostgreSQL 16 / SQLite fallback | PostgreSQL 16 / H2 PostgreSQL mode | Parameterized queries via JPA / ORM |
| **Object-Level Access (Anti-IDOR)**| `CaseQuerySet.for_user(user)` | `CaseSecurityService` + Scoped JPA Queries | Complete mediation; HTTP 404 for unauthorized |
| **Content Security Policy** | `django-csp` (per-request nonces) | Spring Security `HeaderWriter` + CSP Nonce | XSS mitigation, zero unsafe-inline |
| **Evidence Encryption at Rest** | `cryptography` (Fernet AES-CBC+HMAC) | JCA `AES/GCM/NoPadding` (256-bit) | Authenticated ciphertext, tamper detection |
| **Audit Ledger Chaining** | Python `hmac` + `hashlib.sha256` | Java JCA `Mac.getInstance("HmacSHA256")` | Cryptographic tamper-evident hash chaining |
| **MIME / File Sniffing** | `python-magic` (libmagic) | Apache Tika (`org.apache.tika:tika-core`) | Magic-byte signature content validation |
| **Template Engine** | Django Server-Rendered Templates | Thymeleaf Server-Rendered Templates | Context-aware HTML auto-escaping |
| **Application Server** | Gunicorn (WSGI) | Embedded Apache Tomcat | Hardened embedded servlet container |
| **Reverse Proxy & TLS** | Nginx (TLS 1.3/1.2 reverse proxy) | Nginx (TLS 1.3/1.2 reverse proxy) | Edge TLS termination & HSTS |
| **Dependency Management** | `pip` + `requirements.lock` (hashes) | Maven (`pom.xml`) + Dependency Verification | Reproducible, supply-chain verified builds |
| **Automated Testing** | Pytest, pytest-django, pytest-cov | JUnit 5, MockMvc, AssertJ, JaCoCo | Reproducible regression testing |
| **SAST (Static Analysis)** | Bandit + Semgrep | SpotBugs + FindSecBugs + Semgrep | Automated detection of CWE flaws |
| **SCA (Supply Chain)** | `pip-audit` | OWASP Dependency-Check Maven Plugin | Automated vulnerability detection in libs |
| **SBOM Generation** | CycloneDX Python CLI | CycloneDX Maven Plugin | Standard CycloneDX v1.6 SBOM |
| **Container Scanning** | Trivy + Hadolint | Trivy + Hadolint | Container vulnerability & lint audit |

---

## Consequences

### Positive
- Strict compile-time type verification eliminates entire classes of dynamic typing bugs.
- Idiomatic enterprise architecture is readily recognizable and defensible in a Level 6 academic viva.
- Standard Spring Security architecture centralizes authentication, authorization, CSRF, and security headers into a unified filter pipeline.
- High performance, low-latency execution with Java 21 LTS virtual threads.

### Negative / Trade-offs
- Increased verbosity relative to Python dynamic scripts.
- Slightly higher initial memory footprint (JVM heap vs Python interpreter process).
- Rebuilding test fixtures in Java requires establishing Spring test contexts (`@SpringBootTest`, `@WebMvcTest`).

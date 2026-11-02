# Future Work & Deferred Security Enhancements

**Project:** CaseVault  
**Context:** Level 6 Software & Platform Security Assessment  
**Document Purpose:** Architectural record of deliberately deferred enterprise security controls, operational enhancements, and post-MVP roadmap.

---

## 1. Multi-Factor Authentication (MFA / TOTP)
* **Threat Addressed:** Credential stuffing, password reuse across breaches, compromised endpoints (CWE-287, OWASP A07:2021).
* **Deferred Rationale:** In scope for Phase 1 MVP, the priority was establishing NIST SP 800-63B compliant Argon2id password hashing, dictionary blacklisting, constant-time verification, and session revocation. TOTP MFA was deferred to keep the assessment scope focused and manageable.
* **Proposed Implementation:**
  - Standard time-based one-time password algorithm (**RFC 6238**) with 30-second windows and SHA-1/SHA-256 HMAC.
  - Integration with authenticator apps (Google Authenticator, Microsoft Authenticator) via QR code generation (using a memory-safe Java QR library).
  - Storage of TOTP secret keys encrypted at rest via Google Tink AEAD.
  - Issuance of one-time backup recovery codes, hashed with Argon2id prior to database persistence.

---

## 2. Antivirus & Malware Scanning Integration (ICAP / ClamAV)
* **Threat Addressed:** Malicious payload execution, weaponized PDF/image exploits, malware staging in incident evidence storage (CWE-434, OWASP A04:2021).
* **Current Baseline:** CaseVault currently implements an offline stub `ScanService` alongside strict extension allow-lists, Apache Tika magic-byte MIME detection, off-root storage under random UUIDs, and Google Tink AES-GCM encryption at rest. In compliance with the university assessment rules, no live malware or EICAR strings are processed.
* **Proposed Implementation:**
  - Concrete implementation of `ScanService` connecting via Unix domain socket or TCP to a local **ClamAV daemon (`clamd`)**.
  - Alternative enterprise integration using **ICAP (Internet Content Adaptation Protocol)** to stream file buffers to commercial appliances (e.g. Trend Micro, Symantec) before persistence.
  - Quarantining of flagged files with immediate administrative audit alerts.

---

## 3. Distributed Session & Rate-Limiting Architecture
* **Threat Addressed:** Distributed denial of service (DDoS), credential brute-force attacks from rotating botnets, multi-node scaling inconsistencies (CWE-770, CWE-307).
* **Current Baseline:** Sessions are backed by PostgreSQL via Spring Session JDBC; rate limiting uses in-memory token buckets (`Bucket4j` / atomic tokens) per application instance.
* **Proposed Implementation:**
  - Deployment of a clustered **Redis / Dragonfly** instance with TLS transport encryption and password authentication.
  - Migration of `Bucket4j` rate-limiting state to Redis using the Redis proxy backend. This ensures uniform rate enforcement across horizontal application replicas behind the Nginx reverse proxy.
  - Integration of an IP reputation blocklist or Cloudflare Turnstile CAPTCHA upon progressive rate-limit breaches.

---

## 4. Hardware Security Module (HSM) & Cloud KMS Key Management
* **Threat Addressed:** Key theft via memory dump, local file system read access, compromised host machine (CWE-320, OWASP A02:2021).
* **Current Baseline:** Google Tink keysets are stored in a dedicated file outside the web root (`target/dev-tink-keyset.json`), referenced via the `TINK_KEYSET_PATH` environment variable.
* **Proposed Implementation:**
  - Adoption of **Envelope Encryption** using Google Cloud KMS, AWS KMS, or HashiCorp Vault.
  - Tink's KMS integration (`KmsClients`) allows the Key Encryption Key (KEK) to reside within an HSM, while Data Encryption Keys (DEKs) are dynamically decrypted in memory.
  - Automated cryptographic key rotation policies every 90 days with backward-compatible key versioning.

---

## 5. Enterprise Single Sign-On (OIDC / SAML 2.0)
* **Threat Addressed:** Password lifecycle overhead, decentralized account termination delays (CWE-287).
* **Proposed Implementation:**
  - Spring Security OAuth 2.0 / OIDC Client integration supporting Microsoft Entra ID (Azure AD), Okta, and Keycloak.
  - Automatic organization and role mapping based on signed JWT claims and OIDC ID tokens.
  - Just-in-Time (JIT) user account provisioning with mandatory central deactivation sync.

---

## 6. Immutable WORM Storage & Automated Backup Verification
* **Threat Addressed:** Ransomware destruction of database backups, audit log eradication by rogue sysadmins (CWE-311, CWE-778).
* **Proposed Implementation:**
  - Automated nightly PostgreSQL database dumps encrypted with Tink or GPG.
  - Streaming backups to an **AWS S3 Object Lock** or Azure Immutable Blob Storage bucket configured in Compliance WORM mode (Write Once, Read Many).
  - Nightly automated sandbox restore drill validating the HMAC-SHA256 audit chain from database restoration in an ephemeral container.

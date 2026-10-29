# Formal Security Requirements Specification (SRS)

**System:** CaseVault Incident Response Case Management & Evidence Platform  
**Organization:** Northbridge Cyber Response  
**Module:** CYS22301 Software and Platform Security (Level 6)  

---

## 1. Introduction and Objectives

Northbridge Cyber Response conducts digital forensics and incident response (DFIR) investigations for enterprise clients. The CaseVault platform provides secure intake, analysis, evidence storage, collaboration, and client reporting during active security incidents.

Given the extreme confidentiality and evidential integrity required in judicial and regulatory incident responses, CaseVault is engineered to satisfy rigorous security requirements categorized under the **CIA + AAA** model (Confidentiality, Integrity, Availability, Authentication, Authorization, and Accountability).

---

## 2. Security Requirements Matrix

### 2.1 Authentication (SR-AUTH)
- **SR-AUTH-01 (Memory-Hard Password Hashing):** All user credentials must be hashed using Argon2id with at least 64 MiB memory cost, 2 iterations, and 2 lanes. Legacy or single-pass hashing algorithms (MD5, SHA1, unsalted SHA256) are prohibited.
- **SR-AUTH-02 (Multi-Factor Authentication):** Time-Based One-Time Passwords (TOTP, RFC 6238) must be enforced for all users prior to granting session authorization.
- **SR-AUTH-03 (Brute-Force Protection):** Failed authentication attempts must be tracked; after 5 consecutive failed attempts on an account or from an IP address within 15 minutes, access must be throttled with progressive delays and locked out.
- **SR-AUTH-04 (Secure Session Management):** Session cookies must enforce `HttpOnly`, `Secure` (in production), and `SameSite=Strict`. Sessions must expire after 15 minutes of inactivity (`SESSION_COOKIE_AGE = 900`) and invalidate upon browser closure.
- **SR-AUTH-05 (Credential Confidentiality):** Passwords and TOTP secrets must never appear in application logs, URLs, error traces, or source code.

### 2.2 Authorization & Access Control (SR-AC)
- **SR-AC-01 (Role-Based Access Control):** Four discrete roles must be enforced: `ADMIN`, `LEAD_INVESTIGATOR`, `INVESTIGATOR`, and `CLIENT_AUDITOR`.
- **SR-AC-02 (Object-Level Authorization / Anti-IDOR):** Access to cases, notes, and evidence must be validated against user membership and organization tenancy at the query level (`Case.objects.for_user(request.user)`). Direct URL tampering (IDOR) must return HTTP 404 or 403.
- **SR-AC-03 (Tenant Isolation):** External `CLIENT_AUDITOR` accounts must never view case names, metadata, or evidence belonging to any organization other than their own.
- **SR-AC-04 (Least Privilege):** Database accounts, container runtime users, and file system processes must execute with the lowest viable privileges (non-root `casevault` user).

### 2.3 Data Integrity & Forensic Evidence (SR-INT)
- **SR-INT-01 (Pre-Ingestion Cryptographic Hashing):** All uploaded evidence must have SHA-256 and SHA-512 hashes calculated streaming in memory before disk storage or encryption.
- **SR-INT-02 (Encryption at Rest):** Evidence payloads stored on disk must be encrypted using authenticated symmetric encryption (Fernet / AES-128-CBC with HMAC-SHA256 authenticated envelope). Plaintext evidence must never reside in storage.
- **SR-INT-03 (Tamper Detection on Download):** Upon evidence retrieval, the ciphertext must be authenticated and decrypted; its plaintext hash must be re-evaluated against the stored record to guarantee bit-level integrity before streaming to the client.
- **SR-INT-04 (Inert File Storage):** Evidence files must be stored with randomized UUID filenames outside the web server root. Directory browsing and direct URL retrieval must be physically impossible.
- **SR-INT-05 (File Type Validation & Whitelist):** Uploaded files must match an explicit extension whitelist (`.txt`, `.pdf`, `.png`, `.jpg`, `.log`, `.pcap`, `.json`) and undergo magic-byte signature inspection. Executable scripts (`.php`, `.py`, `.sh`, `.exe`, `.svg`, `.html`) must be rejected.

### 2.4 Confidentiality & Output Security (SR-CONF)
- **SR-CONF-01 (Download Sandboxing):** Downloaded evidence files must be delivered with `Content-Disposition: attachment`, explicit MIME types, `X-Content-Type-Options: nosniff`, and a sandboxed Content Security Policy (`Content-Security-Policy: sandbox; default-src 'none';`) to prevent inline browser execution of malicious payloads.
- **SR-CONF-02 (Cross-Site Scripting Defense):** All web responses must enforce auto-escaped HTML templates, CSRF tokens on all state-altering requests (`POST`, `PUT`, `DELETE`), and strict CSP headers (`script-src 'self' 'nonce-...'`).
- **SR-CONF-03 (Secret Protection):** Cryptographic keys and database credentials must be loaded solely from environment variables. No secrets shall exist in git history or repo artifacts.

### 2.5 Accountability & Auditability (SR-ACC)
- **SR-ACC-01 (Comprehensive Audit Trail):** Every security-relevant event (authentication, MFA challenge, case creation, membership change, evidence upload, evidence download, permission failure) must be recorded in an immutable audit ledger.
- **SR-ACC-02 (Cryptographic Hash-Chaining):** Each audit record must include an HMAC-SHA256 cryptographic digest binding its contents to the previous log record, creating a tamper-evident hash chain.
- **SR-ACC-03 (Tamper Verification):** An administrative verification routine must exist to traverse the audit ledger and cryptographically verify the integrity of every entry. Any insertion, modification, or deletion must be mathematically pinpointed.

### 2.6 Availability & Platform Resilience (SR-AVAIL)
- **SR-AVAIL-01 (Denial-of-Service Defense):** File upload size limits (e.g. 25 MB max per artifact) and request payload limits must be enforced server-side.
- **SR-AVAIL-02 (Resource Isolation):** Heavy operations (hash computation, encryption) must be bounded in memory using streaming buffers (chunk size: 64 KiB) to prevent memory exhaustion attacks.
- **SR-AVAIL-03 (Graceful Error Handling):** All exceptions must produce sanitized, non-revealing error pages. Raw stack traces, SQL queries, or internal file paths must never be exposed to users.

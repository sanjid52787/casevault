# CaseVault Viva Defense Script & Assessment Demonstration Guide

**Project:** CaseVault — Secure Incident & Evidence Management Platform  
**Target Organization:** Northbridge Cyber Response (Fictional Incident Response Consultancy)  
**Academic Level:** Level 6 — Software and Platform Security  
**Repository Branch:** `feat/gaps` (Targeting `v1.0.0` Release)  

---

## 1. Executive Presentation Script (Opening 3-Minute Elevator Pitch)

> "Good morning/afternoon. CaseVault is a multi-tenant incident response and evidence management platform designed specifically for Northbridge Cyber Response. Our primary objective is to maintain strict cryptographic confidentiality, tenant isolation, and non-repudiation across sensitive security engagements.
> 
> Rather than treating security as an afterthought or an outer perimeter, CaseVault enforces **security by design** at every layer:
> 1. **Authentication:** NIST-compliant Argon2id password hashing with constant-time verification, bundled dictionary rejection, and IP/account-level progressive rate limiting.
> 2. **Tenant Isolation & Authorization:** Deny-by-default architecture where object-level authorization is calculated in the core domain service layer. Cross-tenant references return HTTP 404 (Not Found) rather than 403 (Forbidden) to prevent resource existence enumeration.
> 3. **Cryptographic Storage:** Files uploaded as evidence are validated via Apache Tika magic-byte inspection, quarantined outside the web root under synthetic UUID filenames, and encrypted at rest using **Google Tink AES-GCM-256 (AEAD)** with authenticated case metadata.
> 4. **Tamper-Evident Audit Logging:** An append-only audit trail in PostgreSQL where each record is cryptographically bound to its predecessor via an **HMAC-SHA256 hash chain**, verifiable mathematically on demand.
> 5. **Separation of Duties:** Analyst investigation, manager classification/approval, client access, and auditor administration are compartmentalized. An auditor can inspect security events and health probes, but can never inspect client case details or decrypted evidence."

---

## 2. Interactive Role Demonstration Walkthrough

When delivering the live demonstration to examiners, follow this sequential 5-phase workflow:

### Step 1: Pre-Authentication & Security Headers
* **URL:** `http://localhost:8080/login`
* **Examiner Demo Points:**
  - Open Browser DevTools Network tab.
  - Show the response headers:
    - `Content-Security-Policy: default-src 'self'; script-src 'self' 'nonce-...'` (Per-request cryptographic nonces; zero `unsafe-inline`).
    - `X-Content-Type-Options: nosniff` (Prevents MIME sniffing attacks).
    - `X-Frame-Options: DENY` (Mitigates clickjacking).
    - `Referrer-Policy: no-referrer` (Prevents credential and UUID leakage in Referer headers).
  - Attempt login with invalid credentials: show generic `"Invalid credentials"` message (zero account enumeration).
  - Inspect Actuator surface: `http://localhost:8080/actuator/health` returns status `UP`; `http://localhost:8080/actuator/env` is blocked/redirected (no secret disclosure).

### Step 2: Client User Workflow (Tenant A)
* **Login:** `CLIENT_USER` (`client_user-...@example.test`)
* **Actions:**
  - Create synthetic case: Title: *"Suspicious email reported by staff"*, Severity: `MEDIUM`, Category: `PHISHING`.
  - Notice status defaults to `NEW`. Notice Client has **no** controls to assign analysts or alter triage status.
  - Test Input Validation: Attempt to submit a 2-character title `ab`. Show clean Bean Validation error message without stack trace.
  - Test Stored XSS Mitigation: Enter `<script>alert(1)</script>` in description. Show that Thymeleaf `th:text` automatically HTML-escapes output to `&lt;script&gt;alert(1)&lt;/script&gt;`.
  - Upload Synthetic Evidence: Attach a `.txt` file containing synthetic logs.
  - Show Evidence Card: Displays file size (`70 bytes`), calculated SHA-256 digest, and green badge `AES-GCM Encrypted`.
  - Download Evidence: Click Download; observe HTTP 200, `Content-Disposition: attachment; filename*=UTF-8''...`, and successfully decrypted plaintext in browser.

### Step 3: Case Manager Workflow (Internal Operations)
* **Login:** `CASE_MANAGER`
* **Actions:**
  - Navigate to Cases list. Locate the client incident.
  - Open Case Details: Manager classification panel is visible.
  - Change Severity to `HIGH`, Category to `PHISHING`, Status to `TRIAGED`.
  - Assign `SECURITY_ANALYST` to owner role.
  - Attempt to view `/admin/audit`: Denied (HTTP 403 Forbidden). Manager has operational rights, not compliance audit authority.

### Step 4: Security Analyst Workflow (Investigation & Reporting)
* **Login:** `SECURITY_ANALYST`
* **Actions:**
  - Verify that only assigned cases appear in the analyst's workspace (strict tenant/assignment filter).
  - Add an Investigation Note: Mark `"Client visible"` checked.
  - Add a Remediation Action: *"Deploy anti-phishing mail filter rules"*, Status: `OPEN` $\to$ `IN_PROGRESS`.
  - Generate Draft Report: Click *"Generate Draft Report"*.
  - Show Report Card: Version 1 created in `DRAFT` status.
  - Show Separation of Duties: Analyst has a *"Submit for Approval"* button, but **no** *"Approve Report"* button.
  - Click *"Submit for Approval"*: Status transitions to `SUBMITTED`.

### Step 5: Report Approval & Client Retrieval
* **Login:** `CASE_MANAGER`
  - Case Manager sees the `SUBMITTED` report and the *"Approve Report"* button.
  - Click *"Approve Report"*: Status transitions to `APPROVED`.
  - *Enforcement Note:* If the manager had authored the report themselves, the backend service (`ReportApprovalService`) prohibits self-approval.
* **Login:** `CLIENT_USER`
  - Client navigates to the incident.
  - Reports Card displays `Version 1 [APPROVED]`.
  - Click Download Report: Client receives sanitised, structured investigation report containing remediation actions and client-visible notes. Redaction filters have removed any sensitive internal IP addresses or API keys.

### Step 6: Auditor / Administrator Workflow (Compliance & Hash Chain)
* **Login:** `AUDITOR_ADMIN`
* **Actions:**
  - Notice the dashboard: No access to case content or evidence files.
  - Attempt Forced Browsing to Case Details (`/cases/{uuid}`): Returns **HTTP 404 Not Found**. The auditor cannot read notes, client names, or decrypted evidence.
  - Open `/admin/health`: Shows application, database, and Tink storage health status without leaking file paths or database passwords.
  - Open `/admin/accounts`: Shows user statuses with ability to disable accounts or force password resets.
  - Open `/admin/audit`:
    - Show Structured Audit Table: Every event shows Actor Role, Action, Target Type, Outcome, and Correlation ID.
    - Test Filter Form: Filter by Action `AUTH_LOGIN`, Actor Role `CLIENT_USER`, Outcome `SUCCESS`. Show filtered results.
    - Verify Hash Chain: Click *"Verify Audit Hash Chain"*. Show green verification badge: *"INTACT & VERIFIED"*, confirming that sequential HMAC-SHA256 calculations match throughout history.

---

## 3. Defense against Examination Probes (Model Q&A)

### Q1: Why did you return HTTP 404 rather than HTTP 403 when an unauthorised user accesses a case?
> **Answer:** "Returning HTTP 403 (Forbidden) confirms to an attacker that the targeted resource UUID exists on the server, which facilitates resource enumeration, horizontal privilege reconnaissance, and existence oracle attacks. By returning HTTP 404 (Not Found) uniformly for missing resources, cross-tenant objects, and unauthorised auditor access, we eliminate information leakage and treat UUIDs as private identifiers rather than access tokens."

### Q2: How does CaseVault prevent Server-Side Request Forgery (SSRF) and Malicious File Execution during evidence upload?
> **Answer:** "We implement defense-in-depth across 5 layers:
> 1. **Allow-list Validation:** Files must match strict extensions (`.txt`, `.pdf`, `.png`, `.jpg`).
> 2. **Magic-Byte Inspection:** We use Apache Tika to inspect the initial byte signatures of the payload. A disguised executable named `malware.pdf` is rejected because its binary MIME type mismatches the declared header.
> 3. **Server-Generated Filename:** Uploads are stored under a cryptographically random UUID name; the user-supplied filename is never used as a filesystem path, preventing path traversal (`../`).
> 4. **Off-Root Storage:** The evidence directory is located outside the servlet container web root, preventing direct URI execution.
> 5. **Encryption at Rest:** All bytes are immediately encrypted with Google Tink AES-GCM-256 before disk persistence, rendering the file inert even if an attacker achieved local read access to the host storage."

### Q3: How is the Audit Log protected against insider modification or database administrator tampering?
> **Answer:** "Every audit event contains an HMAC-SHA256 hash computed over the event timestamp, actor ID, action, target, outcome, correlation ID, and the cryptographic hash of the preceding record (`prev_hash`). This forms a blockchain-like immutable hash chain. If a rogue database administrator updates or deletes a historical record, recalculating the chain breaks at that exact event ID (`firstBrokenEventId`). Furthermore, the PostgreSQL application user possesses only `INSERT` and `SELECT` grants on the audit table—no `UPDATE` or `DELETE` privileges exist."

### Q4: What are the primary residual risks and limitations of this build?
> **Answer:** "We document our residual risks transparently:
> 1. Rate limiting is currently managed in-memory using token buckets. In a multi-node horizontal deployment, this must be migrated to a distributed cache like Redis to prevent quota bypass across instances.
> 2. While we implemented a comprehensive `ScanService` interface with full unit tests, live enterprise antivirus (e.g. ClamAV daemon) is stubbed to ensure the test suite runs offline without synthetic malware false positives.
> 3. Two-factor authentication (TOTP RFC 6238) is designed in our threat model and recorded in `future-work.md`, but deferred to post-MVP to prioritize core cryptographic isolation."

---

## 4. Viva Technical Summary Sheet

| Security Control | Implementation Mechanism | Automated Evidence ID | Verification Tool / Command |
|---|---|---|---|
| **Password Storage** | Argon2id (19MB RAM, 2 iterations, 1 parallelism) | `T-AUTH-001` | `AuthenticationSessionSecurityTest` |
| **Session Security** | Spring Session JDBC, `SameSite=Strict`, `HttpOnly`, `Secure` | `T-SESS-003` | `AuthenticationSessionSecurityTest` |
| **Object Authorisation** | Service-layer `AccessPolicy` + `@PreAuthorize` | `T-AUTHZ-MATRIX-001` | `AuthorisationOperationMatrixTest` (177 tests) |
| **Evidence Encryption** | Google Tink AEAD AES-256-GCM at rest | `T-FILE-001..012` | `EvidenceSecurityTest`, `EvidenceHttpTest` |
| **File Verification** | Apache Tika Magic Byte MIME Detection + SHA-256 digest | `T-FILE-003` | `EvidenceSecurityTest` |
| **Audit Non-Repudiation** | HMAC-SHA256 sequential hash chain in PostgreSQL | `T-AUDIT-001..004` | `PersistentAuditServiceTest` |
| **Audit Multi-Filter** | Bound JDBC criteria query + Admin UI controls | `T-ADMIN-006` | `AdminSecurityTest`, `test_admin_audit_ui.py` |
| **XSS Prevention** | Thymeleaf strict `th:text` + CSP per-request nonces | `T-XSS-001`, `T-HDR-001` | `SecurityHeadersTest`, `CaseSecurityHardeningTest` |
| **Separation of Duties** | `ReportApprovalService` generator $\neq$ approver | `T-REPORT-004` | `ReportSecurityTest`, `ReportEndpointSecurityTest` |
| **Rate Limiting** | Token Bucket (Bucket4j/Atomic) with HTTP 429 & Retry-After | `T-RATE-001..005` | `RateLimitSecurityTest`, `IpRateLimitSecurityTest` |

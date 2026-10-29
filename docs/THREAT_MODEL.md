# Threat Model & Risk Assessment: CaseVault

**Organization:** Northbridge Cyber Response  
**System:** CaseVault Forensic Incident Management Platform  
**Methodology:** Microsoft STRIDE Threat Modeling + DFD Analysis  
**Module:** CYS22301 Software and Platform Security (Level 6)  

---

## 1. System Overview & Scope

CaseVault is a multi-tenant web application used by Northbridge Cyber Response incident responders, forensic specialists, engagement managers, and client auditors. The platform processes high-value digital forensic artifacts, investigative notes, indicators of compromise (IOCs), and formal incident reports.

### 1.1 Assets Under Protection
1. **Forensic Evidence Payloads (A1):** Disk images, memory dumps, PCAP network captures, server log extracts. (High Confidentiality, High Integrity).
2. **Case Strategy & Investigative Notes (A2):** Real-time hypothesis, active threat actor attribution, client vulnerability status. (High Confidentiality, High Integrity).
3. **User Credentials & MFA Secrets (A3):** Passwords, TOTP seeds, session tokens. (High Confidentiality, High Integrity).
4. **Audit Trail & Chain of Custody (A4):** Immutable logs documenting who viewed, uploaded, or retrieved evidence for judicial admissibility. (High Integrity, High Non-Repudiation).
5. **System Cryptographic Keys (A5):** Evidence encryption master key (`CASEVAULT_EVIDENCE_KEY`) and HMAC chaining key (`CASEVAULT_AUDIT_HMAC_KEY`). (Critical Confidentiality & Integrity).

---

## 2. Trust Boundaries & Security Zones

The system is partitioned into three distinct Trust Zones:
- **Zone 0 (Untrusted Public / Client Perimeter):** Web browser clients (investigators, external client auditors, network attackers). Communicates exclusively via HTTPS (TLS 1.3).
- **Zone 1 (DMZ / Application Processing Boundary):** Django application server running within a rootless container. Terminates TLS, validates inputs, enforces RBAC/ABAC, manages sessions, and computes cryptographic hashes.
- **Zone 2 (Internal Secure Storage Boundary):** Relational database (PostgreSQL/SQLite metadata store) and encrypted filesystem evidence vault (`vault_storage/`). Inaccessible from the public network.

```mermaid
flowchart TD
    subgraph Zone0 ["Trust Zone 0: Untrusted / Public Perimeter"]
        Attacker["Potential Threat Actor / Malicious Insider"]
        Investigator["Northbridge DFIR Investigator"]
        ClientAuditor["Client Auditor (External Tenancy)"]
    end

    subgraph Boundary1 ["Trust Boundary 1: Network / Transport (TLS + WAF/CSP)"]
    end

    subgraph Zone1 ["Trust Zone 1: Application Layer (Rootless Container)"]
        WAF["Security Middleware (CSP, CSRF, Rate Limiting)"]
        AuthModule["Auth & TOTP Engine (Argon2id)"]
        CaseEngine["Case & Note Engine (RBAC + ABAC)"]
        VaultEngine["Evidence Vault Stream (Validation + Fernet Crypto)"]
        AuditEngine["Audit Logger (HMAC Hash Chainer)"]
    end

    subgraph Boundary2 ["Trust Boundary 2: Storage & Cryptographic Isolation"]
    end

    subgraph Zone2 ["Trust Zone 2: Secure Data Layer"]
        DB[(Relational DB: User, Cases, Notes, Hashes)]
        Storage[(Encrypted Evidence Vault: AES-128-CBC + HMAC)]
        AuditLedger[(Audit Chain Store)]
    end

    Investigator -->|HTTPS + Session Cookie| WAF
    ClientAuditor -->|HTTPS + Session Cookie| WAF
    Attacker -.->|Adversarial Injections / IDOR attempts| WAF

    WAF --> AuthModule
    WAF --> CaseEngine
    WAF --> VaultEngine

    AuthModule --> DB
    CaseEngine --> DB
    VaultEngine -->|Stream Ciphertext| Storage
    VaultEngine -->|Store SHA-256/512| DB
    CaseEngine --> AuditEngine
    VaultEngine --> AuditEngine
    AuthModule --> AuditEngine
    AuditEngine --> AuditLedger
```

---

## 3. Data Flow Diagrams (DFD)

### 3.1 DFD Level 0: Context Diagram

```mermaid
flowchart LR
    User([User: Investigator / Client / Admin])
    System[[CaseVault Platform Boundary]]
    ExtStore[(Isolated Vault Storage & DB)]

    User -->|1. Credentials & TOTP Code| System
    User -->|2. Forensic Evidence Upload| System
    User -->|3. Query Case & Download Request| System

    System -->|4. Authenticated Session & Rendered HTML| User
    System -->|5. Sandboxed Evidence Stream| User

    System <-->|6. Encrypted Read/Write & HMAC Hash Audit| ExtStore
```

### 3.2 DFD Level 1: Decomposed Process Architecture

```mermaid
flowchart TD
    Actor([Investigator / Client Actor])
    
    P1[Process 1.0: Security Middleware & Ingress Validation]
    P2[Process 2.0: Authentication & MFA Validation]
    P3[Process 3.0: Authorization & Tenancy Scoping]
    P4[Process 4.0: Evidence Ingestion & Streaming Crypto]
    P5[Process 5.0: Evidence Retrieval & Integrity Check]
    P6[Process 6.0: HMAC Audit Trail Chaining]

    D1[(Store: Users & Sessions)]
    D2[(Store: Cases, Notes & Metadata)]
    D3[(Store: Encrypted Evidence Files)]
    D4[(Store: Tamper-Evident Audit Ledger)]

    Actor -->|HTTPS Request with CSRF & Headers| P1
    P1 -->|Pass Cleaned Request| P2
    P2 <-->|Verify Argon2id & TOTP| D1
    P2 -->|Authenticated Context| P3
    P3 <-->|Evaluate RBAC & Object Tenancy| D2
    
    P3 -->|Upload Request| P4
    P4 -->|1. Validate Magic Bytes & Whitelist| P4
    P4 -->|2. Compute SHA-256 / SHA-512| P4
    P4 -->|3. Encrypt via Fernet Stream| D3
    P4 -->|4. Store Metadata & Hashes| D2
    P4 -->|5. Trigger Log| P6

    P3 -->|Download Request| P5
    P5 <-->|Read Encrypted File| D3
    P5 -->|Authenticate & Decrypt| P5
    P5 -->|Verify Hash against DB Record| D2
    P5 -->|Stream with Sandbox CSP & Content-Disposition| Actor
    P5 -->|Trigger Log| P6

    P6 -->|Compute HMAC with Previous Hash| D4
```

---

## 4. STRIDE Threat Analysis

| Threat ID | STRIDE Category | Threat Description | Attack Vector / Scenario | Impact | Mitigation in CaseVault | Residual Risk |
|---|---|---|---|---|---|---|
| **T-S01** | **Spoofing** | Adversary attempts to guess or brute-force user credentials to impersonate an investigator. | Automated credential stuffing or online dictionary attack against `/auth/login/`. | High: Unauthorized access to all cases assigned to the victim. | • Argon2id hashing with high memory cost.<br>• Consecutive failure lockout (5 attempts in 15 mins).<br>• Mandatory RFC 6238 TOTP MFA. | Low (dependent on user keeping TOTP device secure). |
| **T-S02** | **Spoofing** | Session hijacking via stolen cookie. | Network eavesdropping or Cross-Site Scripting (XSS) exfiltrating session cookie. | Critical: Attacker assumes active session without credentials. | • `SESSION_COOKIE_HTTPONLY = True` (inaccessible to JS).<br>• `SESSION_COOKIE_SECURE = True` (TLS only).<br>• `SESSION_COOKIE_SAMESITE = 'Strict'`.<br>• Inactivity timeout (15 mins) and regeneration on privilege changes. | Very Low. |
| **T-T01** | **Tampering** | Uploading weaponized files disguised as inert evidence (e.g. polyglot `.php` or SVG with embedded JS). | Malicious actor uploads `exploit.svg` or `shell.php.png` to compromise server or client browser. | Critical: Remote Code Execution (RCE) on server or Stored XSS on investigator browser. | • Strict file extension whitelist (`.txt`, `.pdf`, `.png`, `.jpg`, `.log`, `.pcap`, `.json`).<br>• Magic byte header inspection.<br>• Random UUID storage filename outside web root.<br>• Download served with `Content-Disposition: attachment` and `CSP: sandbox`. | Negligible. |
| **T-T02** | **Tampering** | Malicious insider alters forensic evidence in storage to falsify legal chain of custody. | Direct filesystem manipulation or DB update of evidence files. | Critical: Compromised judicial evidence and legal liability. | • Pre-encryption SHA-256 and SHA-512 calculated in memory.<br>• Stored with authenticated encryption (HMAC in Fernet).<br>• Re-hashed upon download; mismatch immediately halts streaming. | Negligible (requires root key compromise). |
| **T-T03** | **Tampering** | Rogue user deletes or modifies historical audit log entries to conceal unauthorized access. | Direct SQL manipulation or unauthorized API call deleting audit log rows. | High: Undetectable insider abuse. | • HMAC-SHA256 cryptographic hash chaining linking each entry to previous.<br>• Verification routine flags broken chain immediately.<br>• Append-only model enforced by view logic. | Low (tampering is mathematically detected). |
| **T-R01** | **Repudiation** | Investigator denies having viewed, downloaded, or shared sensitive client evidence. | User claims evidence was leaked by another party or accessed without their knowledge. | Medium: Inability to enforce accountability during an internal leak investigation. | • Cryptographically chained audit trail logging every view and download event with actor ID, timestamp, and client IP hash. | Negligible. |
| **T-I01** | **Information Disclosure** | Insecure Direct Object Reference (IDOR / BOLA) allows Client A to view Client B's cases or evidence. | User edits case ID in URL (e.g. `/cases/case-uuid-1/` to `/cases/case-uuid-2/`). | Critical: Breach of client confidentiality and non-disclosure agreements. | • Object-level permission checks in all views.<br>• Querysets strictly scoped to `Case.objects.for_user(request.user)`.<br>• Unauthorized requests return HTTP 404 to avoid enumeration. | Negligible. |
| **T-I02** | **Information Disclosure** | Leakage of stack traces or sensitive credentials via debug logs or error pages. | Exception triggered intentionally by malformed input when `DEBUG=True`. | High: Exposure of database schema, environment variables, or file paths. | • `DEBUG = False` enforced in production.<br>• Custom 400/403/404/500 handlers returning sanitized user messages.<br>• Logging filter strips credentials and tokens. | Negligible. |
| **T-D01** | **Denial of Service** | Resource exhaustion via massive file uploads or algorithmic complexity attacks. | Threat actor uploads gigabytes of data or sends concurrent Argon2 verification requests. | High: Platform crashes or becomes unresponsive to legitimate responders. | • Strict file upload limit (25 MB max).<br>• Stream chunking (64 KiB buffer) preventing memory exhaustion.<br>• Rate limiting on authentication endpoints. | Low. |
| **T-E01** | **Elevation of Privilege** | Standard investigator attempts to execute administrative actions (e.g. creating users, modifying firm policies). | Manipulation of form fields (`role=ADMIN`) or direct navigation to `/admin/` endpoints. | Critical: Full takeover of system governance. | • Server-side role validation on all administrative endpoints.<br>• Role assignments restricted strictly to `ADMIN` role.<br>• Form binding protects role fields from mass-assignment. | Negligible. |

---

## 5. Abuse Cases & Verification Matrix

| Abuse Case ID | Adversary Objective | Adversary Action | Expected System Defense | Verification Test |
|---|---|---|---|---|
| **AC-01** | Bypass MFA | Enters username and password, then directly accesses protected `/cases/` URL without completing TOTP step. | Session marked `mfa_verified = False`; middleware immediately intercepts and redirects to `/auth/mfa-verify/`. | `test_unverified_mfa_cannot_access_cases()` |
| **AC-02** | IDOR Case Tampering | Investigator assigned to Case X attempts to post a note or view evidence in Case Y. | `Case.objects.for_user()` filters out Case Y; request terminates in HTTP 404. | `test_investigator_cannot_access_unassigned_case()` |
| **AC-03** | Stored XSS via File Upload | Attacker uploads `payload.html` containing `<script>alert(document.cookie)</script>` named as `report.pdf`. | Magic byte validator inspects header; identifies HTML content instead of PDF `%PDF`; rejects upload with error. | `test_reject_disguised_html_in_pdf()` |
| **AC-04** | Evidence Tampering Detection | Adversary modifies one byte of encrypted file on disk. | Fernet authenticated decryption detects HMAC signature failure (`InvalidToken`); download view logs tampering event and halts. | `test_tampered_evidence_file_raises_integrity_error()` |
| **AC-05** | Audit Log Deletion Tampering | Adversary deletes an intermediate row in the audit database. | System audit integrity check runs: `verify_audit_chain()` computes chain mismatch at deleted index; returns `is_valid = False` with exact corrupted index. | `test_audit_chain_detects_deleted_record()` |
| **AC-06** | Mass Assignment Escalation | Investigator submits `POST /profile/update/` with form body containing `role=ADMIN`. | Django form whitelist ignores unexpected `role` attribute; user role remains unchanged. | `test_role_mass_assignment_prevented()` |


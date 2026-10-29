# 20-Minute Viva Defense Preparation Guide: CaseVault

**Module:** CYS22301 Software and Platform Security (Level 6)  
**Weighting:** 20% of Final Assessment Grade  
**Candidate Preparation Reference:** Northbridge Cyber Response CaseVault Platform  

---

## 1. Opening Statement (First 2 Minutes)

> *"Examiners, CaseVault is a secure incident-response case-management and forensic evidence-sharing platform built for Northbridge Cyber Response. The platform is designed around the core principle of **provable forensic defensibility**.*  
> *Rather than relying on clever, custom code that introduces subtle vulnerabilities, CaseVault leverages well-vetted, established framework primitives and cryptographic standards: Argon2id for memory-hard credential hashing, RFC 6238 TOTP for MFA, dual-layer RBAC and ABAC to mathematically eliminate IDOR, Fernet authenticated symmetric encryption with pre-storage dual-hashing for evidence custody, and an HMAC-SHA256 hash-chained tamper-evident audit ledger.*  
> *Every security control is enforced server-side. Our test suite achieves an 87% domain coverage, Bandit SAST reports zero issues, and all dependencies are cryptographically pinned with SHA-256 hashes."*

---

## 2. Top 10 Viva Questions & Model Defense Answers

### Question 1: "Why did you choose Argon2id over PBKDF2 or Bcrypt for credential hashing?"
**Defensive Reasoning:**
- Standard Django defaults to PBKDF2 with SHA-256. While NIST compliant, PBKDF2 is computationally sequential but **not memory-hard**. An adversary using modern GPU clusters or ASICs can evaluate billions of PBKDF2 hashes in parallel at negligible cost.
- Bcrypt is memory-limited to a fixed 4 KiB state, allowing GPU parallelization.
- **Argon2id** (RFC 9106) won the Password Hashing Competition. It is a hybrid algorithm that combines Argon2d (resisting GPU time-memory trade-offs) and Argon2i (resisting side-channel cache timing attacks).
- In CaseVault, we configured Argon2id with 64 MiB of memory, 2 time iterations, and 2 lanes. This forces an attacker cracking offline hashes to allocate 64 MiB of physical RAM per attempt, rendering large-scale GPU dictionary attacks economically and computationally infeasible.
- **Code to show:** [settings.py](file:///c:/Users/emond/Downloads/case-management/casevault_core/settings.py#L90-L105) (`PASSWORD_HASHERS`) and [ADR-0001](file:///c:/Users/emond/Downloads/case-management/docs/adr/ADR-0001-argon2id-password-hashing.md).

---

### Question 2: "How does CaseVault prevent Insecure Direct Object References (IDOR / BOLA)?"
**Defensive Reasoning:**
- In an incident response consultancy, multi-tenancy isolation between competing clients is paramount. If Client A could modify a URL to `GET /cases/{case_uuid}/` and see Client B's breach details, this would constitute a catastrophic data breach.
- We defend against IDOR using a **dual-layer defense-in-depth model**:
  1. **Primary Keys are UUIDv4:** Case and Evidence IDs are 128-bit random UUIDs, preventing automated sequential enumeration (`1`, `2`, `3`).
  2. **Queryset-Level Complete Mediation (ABAC):** In [cases/models.py](file:///c:/Users/emond/Downloads/case-management/cases/models.py#L29-L50), we defined `CaseQuerySet.for_user(request.user)`. Every single view queries solely through this manager (`Case.objects.for_user(request.user)`).
  3. **Tenancy Scoping:** If a Client Auditor requests a case, the ORM filters by `client_organization=user.organization`. If an investigator requests a case, it filters by assigned membership.
  4. **404 Instead of 403 on Unauthorized Lookups:** If a user attempts to access an unassigned case UUID, Django's `get_object_or_404()` raises HTTP 404. This prevents attackers from discovering whether a case identifier even exists on the platform.
- **Code to show:** [cases/models.py](file:///c:/Users/emond/Downloads/case-management/cases/models.py#L29-L50) (`CaseQuerySet.for_user()`) and [tests/test_access_control_and_idor.py](file:///c:/Users/emond/Downloads/case-management/tests/test_access_control_and_idor.py#L14-L65).

---

### Question 3: "Walk me through how an evidence file is securely processed from upload to storage and download."
**Defensive Reasoning:**
1. **Validation & Sanitization:** When an investigator uploads a file, [vault/validators.py](file:///c:/Users/emond/Downloads/case-management/vault/validators.py#L65-L130) normalizes cross-platform path separators, strips path traversal prefixes (`../../`), and matches the extension against a strict whitelist (`.txt`, `.log`, `.pdf`, `.png`, `.jpg`, `.json`, `.csv`, `.pcap`).
2. **Magic-Byte Inspection:** The validator inspects the first 512 bytes for known binary magic bytes (`%PDF-`, PNG, JPEG, PCAP) and rejects script tags (`<script>`, `<?php`, `<svg`) or binary executables (`MZ`, `\x7fELF`).
3. **Pre-Storage Forensic Hashing:** In [vault/crypto.py](file:///c:/Users/emond/Downloads/case-management/vault/crypto.py#L35-L65), the plaintext stream computes both SHA-256 and SHA-512 cryptographic digests in memory *before* encryption. These hashes are stored in the database as the immutable chain of custody baseline.
4. **Authenticated Symmetric Encryption:** The payload is encrypted with Fernet (AES-128-CBC + HMAC-SHA256 authenticated envelope) and written to disk as `{random_uuid}.enc` in `vault_storage/`, completely outside the web server's document root.
5. **Sandboxed Download:** Upon download, the ciphertext is decrypted with HMAC signature verification (raising `InvalidToken` on bit-level tampering). The decrypted plaintext SHA-256 is verified against the database. It is served with `Content-Disposition: attachment`, `Content-Security-Policy: sandbox; default-src 'none';`, and `X-Content-Type-Options: nosniff` to guarantee the browser cannot execute the file as a script.
- **Code to show:** [vault/crypto.py](file:///c:/Users/emond/Downloads/case-management/vault/crypto.py#L35-L105) and [vault/views.py](file:///c:/Users/emond/Downloads/case-management/vault/views.py#L30-L150).

---

### Question 4: "Why did you use Fernet rather than writing custom AES-256-GCM code?"
**Defensive Reasoning:**
- Hard Rule #1 forbids writing custom cryptographic implementations. Bespoke implementations of AES-GCM are notorious for subtle implementation flaws, such as nonce reuse: if an IV/nonce is reused with the same key in AES-GCM, the authentication key can be recovered, destroying both integrity and confidentiality.
- Fernet is an established, audited specification built into Python's reference `cryptography` library. It uses AES-128-CBC with PKCS7 padding, HMAC-SHA256 authentication, 128-bit cryptographically secure random IVs generated per encryption, and a 64-bit timestamp.
- It provides **Authenticated Encryption with Associated Data (AEAD)** semantics: any attempt to flip a single bit in the ciphertext or header causes `InvalidToken` during decryption, immediately alerting the system to disk-level tampering.
- **Code to show:** [vault/crypto.py](file:///c:/Users/emond/Downloads/case-management/vault/crypto.py#L20-L40) and [ADR-0003](file:///c:/Users/emond/Downloads/case-management/docs/adr/ADR-0003-evidence-encryption-and-audit-hash-chaining.md).

---

### Question 5: "How does your audit log guarantee tamper-evidence and non-repudiation?"
**Defensive Reasoning:**
- In judicial forensics, an internal rogue administrator or compromised account might attempt to delete an audit log row or alter timestamps to conceal evidence theft.
- We implement **HMAC-SHA256 hash chaining** in [audit/models.py](file:///c:/Users/emond/Downloads/case-management/audit/models.py#L70-L95).
- Every record stores `previous_hash` and `current_hash`. The `current_hash` is computed as:
  $$\text{HMAC-SHA256}_{K}\left(H_{i-1} \parallel \text{timestamp} \parallel \text{actor\_id} \parallel \text{action} \parallel \text{model} \parallel \text{target\_id} \parallel \text{details}\right)$$
- If an adversary deletes row $k$, row $k+1$'s `previous_hash` will fail to match row $k-1$'s `current_hash`.
- If an adversary alters any field in row $k$, recomputing row $k$'s HMAC will produce a mismatch with `current_hash`.
- CaseVault includes a verification routine ([audit/service.py: verify_audit_chain()](file:///c:/Users/emond/Downloads/case-management/audit/service.py#L85-L135)) that walks the chain from genesis ($0^{64}$) to the latest entry, mathematically flagging the exact corrupted record.
- **Code to show:** [audit/service.py](file:///c:/Users/emond/Downloads/case-management/audit/service.py#L85-L135) and [tests/test_audit_chain.py](file:///c:/Users/emond/Downloads/case-management/tests/test_audit_chain.py#L14-L70).

---

### Question 6: "How do you enforce Multi-Factor Authentication and prevent MFA bypass?"
**Defensive Reasoning:**
- Authentication is split into two discrete steps:
  1. Primary credential validation: username and Argon2id password hash.
  2. RFC 6238 TOTP verification code.
- If a user has MFA enabled, primary login leaves `request.session['mfa_verified'] = False` and sets `request.session['mfa_user_id']`.
- An adversary might attempt to bypass the second step by directly requesting protected URLs (e.g., `GET /cases/`).
- To prevent this, we built [core/middleware.py: MFAEnforcementMiddleware](file:///c:/Users/emond/Downloads/case-management/core/middleware.py#L80-L115). On every single incoming HTTP request, the middleware intercepts the session. If `user.is_mfa_enabled` is true and `request.session['mfa_verified']` is false, it unconditionally halts execution and redirects to `/auth/mfa/verify/`.
- Only when `user.verify_totp(token)` succeeds is `mfa_verified` set to `True`.
- **Code to show:** [core/middleware.py](file:///c:/Users/emond/Downloads/case-management/core/middleware.py#L80-L115) and [tests/test_security_headers_and_negative.py](file:///c:/Users/emond/Downloads/case-management/tests/test_security_headers_and_negative.py#L40-L65).

---

### Question 7: "Explain your Content Security Policy (CSP) and why you chose dynamic nonces."
**Defensive Reasoning:**
- Modern defense against Cross-Site Scripting (XSS) requires strict Content Security Policy.
- In [core/middleware.py: SecurityHeadersMiddleware](file:///c:/Users/emond/Downloads/case-management/core/middleware.py#L22-L75), we generate a per-request cryptographically secure random nonce (`secrets.token_urlsafe(16)`).
- We set:
  `Content-Security-Policy: default-src 'self'; script-src 'self' 'nonce-{nonce}'; object-src 'none'; base-uri 'self'; form-action 'self'; frame-ancestors 'none';`
- Any `<script>` tag injected by an attacker will lack the server-generated per-request nonce and will be blocked by the browser.
- Furthermore, for evidence downloads, we override CSP with an isolated sandbox directive: `Content-Security-Policy: sandbox; default-src 'none';`. Even if an investigator downloads an inert file containing HTML, the browser executes it in an isolated, origin-less sandbox with JavaScript execution disabled.
- **Code to show:** [core/middleware.py](file:///c:/Users/emond/Downloads/case-management/core/middleware.py#L35-L65) and [vault/views.py](file:///c:/Users/emond/Downloads/case-management/vault/views.py#L140-L150).

---

### Question 8: "How does CaseVault protect against supply chain attacks?"
**Defensive Reasoning:**
- Per ADR-0005, we do not rely on loose version ranges (e.g. `django>=5.0`).
- We maintain [requirements.lock](file:///c:/Users/emond/Downloads/case-management/requirements.lock) containing exact version pins and cryptographic SHA-256 distribution hashes for every wheel and source distribution.
- In Docker and CI builds, pip enforces `--require-hashes`. If an attacker compromises PyPI and swaps a legitimate package with a tampered backdoor, pip detects the hash mismatch and aborts the build.
- All dependencies were audited for licence compliance ([docs/DEPENDENCIES.md](file:///c:/Users/emond/Downloads/case-management/docs/DEPENDENCIES.md)), verifying 100% permissive open-source licences (MIT, BSD, Apache-2.0).
- Our CI pipeline executes `pip-audit` on every push to detect known CVEs in the dependency graph.
- **Code to show:** [requirements.lock](file:///c:/Users/emond/Downloads/case-management/requirements.lock#L1-L25) and [ADR-0005](file:///c:/Users/emond/Downloads/case-management/docs/adr/ADR-0005-dependency-pinning-and-hash-verification.md).

---

### Question 9: "How is your deployment hardened against container breakout and privilege escalation?"
**Defensive Reasoning:**
- In [Dockerfile](file:///c:/Users/emond/Downloads/case-management/Dockerfile#L30-L55):
  1. **Multi-stage build:** Separates build tooling (compilers, headers) from the final minimal runtime image.
  2. **Non-root user execution:** Creates a dedicated service user and group `casevault` with fixed UID `10001` and GID `10001`. The container permanently drops root privileges via `USER casevault:casevault`.
  3. **Capability Dropping:** In `docker-compose.yml`, we specify `cap_drop: ALL` and `security_opt: [no-new-privileges:true]`. Even if an attacker exploited a remote code execution vulnerability inside Python, they cannot escalate privileges or manipulate host resources.
  4. **Filesystem Isolation:** Storage for evidence and database files reside in dedicated volume mounts with strict permissions.
- **Code to show:** [Dockerfile](file:///c:/Users/emond/Downloads/case-management/Dockerfile#L30-L55) and [docker-compose.yml](file:///c:/Users/emond/Downloads/case-management/docker-compose.yml#L25-L35).

---

### Question 10: "What vulnerabilities did your software assurance testing discover and how did you fix them?"
**Defensive Reasoning:**
- During assurance testing, our tooling identified and remediated several key issues documented in [docs/REMEDIATION_LOG.md](file:///c:/Users/emond/Downloads/case-management/docs/REMEDIATION_LOG.md):
  1. **Bandit B105 (Hardcoded secret in settings):** Found a static fallback string for `SECRET_KEY` in development mode. Fixed by generating an ephemeral random 64-character token in memory via `secrets.token_urlsafe(64)`.
  2. **Path Separator Normalization:** Discovered that Windows backslashes (`..\..\`) in uploaded filenames were not cleanly stripped on POSIX runtimes. Remediated by normalizing all `\` to `/` before basename extraction.
  3. **Transitive Dependency Vulnerability:** `pip-audit` detected an advisory in baseline `pip 26.1.2`. Upgraded to `pip 26.2.2`, resulting in 0 vulnerabilities.
  4. **Adversarial Negative Testing:** Built tests proving that disguised HTML payloads in `.pdf` files are caught by magic-byte inspection and that modified ciphertext bytes trigger Fernet `InvalidToken` errors.
- **Code to show:** [docs/REMEDIATION_LOG.md](file:///c:/Users/emond/Downloads/case-management/docs/REMEDIATION_LOG.md#L15-L80).

---

## 3. Live Viva Demonstration Script (3-5 Minutes)

1. **Demonstrate Role Separation & Tenancy:**
   - Log in as `alice_lead` (Password: `SecurePassw0rd!`). Show Case `NCR-2026-001` and Case `NCR-2026-002`.
   - Log in as `carol_auditor` (Apex Financial). Show that Carol **only** sees Case `NCR-2026-001`. Show that navigating directly to `/cases/{case_2_id}/` returns **HTTP 404 Not Found** (proving anti-IDOR).
2. **Demonstrate Evidence Ingestion & Cryptography:**
   - Upload an inert sample text file. Show that the pre-encryption SHA-256 and SHA-512 hashes are displayed in the UI.
   - Show that the file stored on disk in `vault_storage/` is encrypted with random UUID filename and cannot be read in plaintext.
   - Download the file. Show `Content-Disposition: attachment` and `sandbox` CSP header.
3. **Demonstrate Tamper-Evident Audit Ledger:**
   - Navigate to `/audit/`. Click **"Verify Cryptographic Hash Chain"**.
   - Show the green **"Audit Chain Integrity Verified"** alert.
   - Explain the `previous_hash` $\to$ `current_hash` HMAC link in the table.

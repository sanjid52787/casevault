# Software Assurance & Security Remediation Log

**System:** CaseVault Forensic Incident Management Platform  
**Organization:** Northbridge Cyber Response  
**Module:** CYS22301 Software and Platform Security (Level 6)  
**Assurance Tools:** Bandit v1.9 (SAST), pip-audit v2.10 (SCA), Pytest v9.2 (Automated Assurance)  

---

## 1. Executive Summary

As part of the Level 6 Software Assurance and Remediation criteria (20% rubric weight), CaseVault was subjected to automated static application security testing (SAST), software composition analysis (SCA), and adversarial negative testing.

Every identified vulnerability, test failure, and security finding was catalogued, investigated for root causes, remediated through defensive architectural controls, and validated via regression tests.

---

## 2. Remediation Register

### REM-01: Hardcoded Fallback Secret in Development Settings
- **Category:** Information Security / CWE-259 (Use of Hard-coded Password/Secret)
- **Tool Detection:** Bandit SAST (`[B105:hardcoded_password_string]`)
- **Initial Code:**
  ```python
  if DEBUG:
      SECRET_KEY = 'insecure-dev-fallback-key-for-local-development-only-change-in-env'
  ```
- **Root Cause Analysis:** A static dummy string was left as a development fallback if `.env` was missing. If committed or mistakenly run in non-production environments with `DEBUG=True`, this fixed key would compromise CSRF and session token signatures.
- **Remediation Implemented:**
  Replaced static string fallback with cryptographically random key generation dynamically generated in memory using Python's `secrets` module:
  ```python
  if DEBUG:
      import secrets
      SECRET_KEY = secrets.token_urlsafe(64)
  else:
      raise ValueError("CRITICAL SECURITY ERROR: DJANGO_SECRET_KEY is not defined in production environment!")
  ```
- **Verification:** Re-ran Bandit SAST. Result: 0 issues identified across all severity categories.

---

### REM-02: Cross-Platform Path Separator Normalization in File Upload Sanitizer
- **Category:** Path Traversal / CWE-22 (Improper Limitation of a Pathname to a Restricted Directory)
- **Tool Detection:** Automated Test Suite (`tests/test_evidence_vault.py::test_filename_sanitization_and_path_traversal`)
- **Initial Code:**
  ```python
  basename = os.path.basename(filename).strip()
  ```
- **Root Cause Analysis:** On POSIX runtimes or when processing Windows client upload paths containing backslashes (`..\..\windows\system32\cmd.log`), standard `os.path.basename` does not consistently normalize cross-platform directory separators, potentially preserving traversal prefixes on POSIX hosts.
- **Remediation Implemented:**
  Added explicit normalization step converting all backslashes to forward slashes prior to basename extraction and regex sanitization:
  ```python
  normalized = filename.replace('\\', '/')
  basename = os.path.basename(normalized).strip()
  sanitized_root = re.sub(r'[^a-zA-Z0-9_\-\.]', '_', root)
  sanitized_root = re.sub(r'_+', '_', sanitized_root).strip('_')
  ```
- **Verification:** Test passed; confirmed that both Windows and Unix path traversal vectors (`../../etc/passwd` and `..\..\windows\system32`) are cleanly stripped to safe basenames.

---

### REM-03: Supply Chain Vulnerability in Build Tooling (pip)
- **Category:** Vulnerable Third-Party Dependency / CWE-1395 (Dependency on Vulnerable Component)
- **Tool Detection:** Software Composition Analysis via `pip-audit` (`PYSEC-2026-3721`)
- **Root Cause Analysis:** The baseline virtual environment contained an unpatched build tool (`pip 26.1.2`) vulnerable to cache poisoning / package confusion.
- **Remediation Implemented:**
  Upgraded build toolchain to `pip >= 26.2.2`. Enforced exact cryptographic hash verification (`--require-hashes`) in production requirements.
- **Verification:** `pip-audit` scan returned `No known vulnerabilities found` across 100% of project packages.

---

### REM-04: Insecure Direct Object References (IDOR / BOLA)
- **Category:** Broken Object Level Authorization / CWE-639
- **Detection Method:** Adversarial Test Vector (`test_anti_idor_case_detail_view`)
- **Risk Analysis:** External client auditors or unassigned internal investigators could modify URL UUIDs to view competitor case evidence or confidential investigation files.
- **Remediation Implemented:**
  Enforced complete mediation at the ORM query level via `CaseQuerySet.for_user(request.user)`:
  ```python
  case = get_object_or_404(Case.objects.for_user(request.user), id=case_id)
  ```
  Unauthorized requests return HTTP 404 rather than 403, preventing existence discovery and case enumeration.
- **Verification:** Unit and integration tests prove that unassigned investigators and external client auditors receive HTTP 404 on unassigned cases.

---

### REM-05: Malicious Polyglot & Stored Script Execution via Evidence Upload
- **Category:** Stored Cross-Site Scripting (XSS) & Remote Code Execution / CWE-434
- **Detection Method:** Adversarial Negative Test Suite (`test_file_validation_rejections`)
- **Risk Analysis:** An attacker could disguise PHP, HTML, or SVG payloads with a `.pdf` or `.png` extension, hoping the server or browser executes the script.
- **Remediation Implemented:**
  Enforced a multi-stage validation pipeline:
  1. Strict extension whitelist (`.txt`, `.log`, `.pdf`, `.png`, `.jpg`, `.jpeg`, `.json`, `.csv`, `.pcap`).
  2. Immediate rejection of executable markers (`MZ`, `\x7fELF`, `<?php`, `<script`, `<svg`).
  3. Binary magic byte validation (`%PDF-`, PNG header, JPEG header, PCAP headers).
  4. Sandboxed download headers (`Content-Disposition: attachment`, `Content-Security-Policy: sandbox; default-src 'none';`, `X-Content-Type-Options: nosniff`).
- **Verification:** Automated negative tests verify that disguised HTML payloads and executable scripts are rejected with descriptive validation errors.

---

### REM-06: Session MFA Bypass
- **Category:** Multi-Factor Authentication Bypass / CWE-287
- **Detection Method:** Adversarial Workflow Test (`test_unverified_mfa_middleware_interception`)
- **Risk Analysis:** An attacker with valid username/password could manually navigate to `/cases/` without submitting the TOTP code.
- **Remediation Implemented:**
  Engineered `core.middleware.MFAEnforcementMiddleware` that intercepts every request:
  ```python
  if user_has_mfa and not request.session.get('mfa_verified', False):
      if current_url_name not in self.EXEMPT_URL_NAMES:
          return redirect('mfa_verify')
  ```
- **Verification:** Test confirms that an authenticated user with pending MFA is redirected to `/auth/mfa/verify/` when attempting to access any protected resource.

---

## 3. Assurance Verification Summary

| Assurance Check | Tool / Mechanism | Pass / Fail | Metric |
|---|---|---|---|
| **Unit & Integration Suite** | Pytest 9.2 + Pytest-Django | **PASS** | 21/21 tests passed (100%) |
| **Code Coverage** | Coverage.py 7.17 | **PASS** | 87% overall domain coverage |
| **Static Application Security (SAST)** | Bandit 1.9 | **PASS** | 0 High, 0 Medium, 0 Low issues |
| **Software Composition Analysis (SCA)** | pip-audit 2.10 | **PASS** | 0 known vulnerabilities |
| **Cryptographic Hash Chain Audit** | `verify_audit_chain()` | **PASS** | 100% mathematical integrity |

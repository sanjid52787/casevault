# Dependency & Licence Compliance Audit Register

**System:** CaseVault Forensic Incident Management Platform  
**Organization:** Northbridge Cyber Response  
**Module:** CYS22301 Software and Platform Security (Level 6)  
**Standard:** ADR-0005 Cryptographic Dependency Pinning & Open-Source Licence Compliance  

---

## 1. Compliance Statement

All external software components and libraries utilized by CaseVault have been vetted for legal licence compliance. Every package operates under a recognized, permissive open-source licence (MIT, BSD-2/3-Clause, Apache-2.0, MPL-2.0, PSF). No viral copyleft (GPL / AGPL) libraries are linked, ensuring zero intellectual property conflicts for enterprise deployment.

---

## 2. Dependency & Licence Register

| Package Name | Pinned Version | Approved Licence | Upstream Project Repository | Security Role |
|---|---|---|---|---|
| **Django** | 6.1.2 | BSD-3-Clause | https://www.djangoproject.com/ | Core MVC Web Framework & ORM |
| **argon2-cffi** | 25.1.0 | MIT | https://github.com/hynek/argon2-cffi | Memory-Hard Argon2id Credential Hasher |
| **argon2-cffi-bindings** | 26.1.0 | MIT | https://github.com/hynek/argon2-cffi-bindings | CFFI Bindings to Reference Argon2 C Library |
| **cryptography** | 50.0.2 | Apache-2.0 OR BSD-3-Clause | https://github.com/pyca/cryptography | Authenticated Fernet AES-128-CBC + HMAC-SHA256 |
| **pyotp** | 2.10.0 | MIT | https://github.com/pyauth/pyotp | RFC 6238 TOTP Multi-Factor Authentication |
| **python-dotenv** | 1.2.4 | BSD-3-Clause | https://github.com/theskumar/python-dotenv | Twelve-Factor Secret Configuration |
| **qrcode** | 8.2 | BSD-3-Clause | https://github.com/lincolnloop/python-qrcode | Inline SVG QR Code Generator for TOTP |
| **asgiref** | 3.13.0 | BSD-3-Clause | https://github.com/django/asgiref/ | Async Server Gateway Interface |
| **sqlparse** | 0.6.0 | BSD-3-Clause | https://github.com/andialbrecht/sqlparse | Non-validating SQL Parser for Django ORM |
| **cffi** | 2.1.1 | MIT-0 | https://cffi.readthedocs.io/ | Foreign Function Interface for Python |
| **pycparser** | 3.12 | BSD-3-Clause | https://github.com/eliben/pycparser | C Parser in Python |
| **tzdata** | 2026.6 | Apache-2.0 | https://github.com/python/tzdata | IANA Time Zone Database |

---

## 3. Software Assurance & Testing Tooling Register (Dev/CI Only)

| Package Name | Pinned Version | Licence | Purpose |
|---|---|---|---|
| **bandit** | 1.9.4 | Apache-2.0 | Static Application Security Testing (AST analysis) |
| **pip-audit** | 2.10.1 | Apache-2.0 | Software Composition Analysis & Vulnerability Scanner |
| **pytest** | 9.2.0 | MIT | Automated Testing Harness |
| **pytest-django** | 4.14.0 | BSD-3-Clause | Django Integration Test Fixtures |
| **pytest-cov** | 7.1.0 | MIT | Line and Branch Coverage Measurement |
| **coverage** | 7.17.0 | Apache-2.0 | Code Coverage Engine |
| **pip-licenses** | 5.5.5 | MIT | Automated Licence Audit Extraction |

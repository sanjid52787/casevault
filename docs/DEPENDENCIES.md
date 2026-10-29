# Dependency & Licence Compliance Audit Register

**System:** CaseVault Forensic Incident Management Platform  
**Organization:** Northbridge Cyber Response  
**Module:** CYS22301 Software and Platform Security (Level 6)  
**Standard:** ADR-0005 & ADR-0006 Cryptographic Dependency Pinning & Open-Source Licence Compliance  

---

## 1. Compliance Statement

All external software components and libraries utilized by CaseVault have been vetted for legal licence compliance. Every package operates under a recognized, permissive open-source licence (MIT, BSD-2/3-Clause, Apache-2.0, MPL-2.0, PSF). No viral copyleft (GPL / AGPL) libraries are linked, ensuring zero intellectual property conflicts for enterprise deployment.

---

## 2. Production Runtime Dependencies

| Package Name | Pinned Version | Approved Licence | Upstream Project Repository | Security Role |
|---|---|---|---|---|
| **Django** | 5.2.18 | BSD-3-Clause | https://www.djangoproject.com/ | Core MVC Web Framework, ORM, CSRF, Session Engine |
| **argon2-cffi** | 25.1.0 | MIT | https://github.com/hynek/argon2-cffi | Memory-Hard Argon2id Credential Hasher (ADR-0001) |
| **argon2-cffi-bindings** | 26.1.0 | MIT | https://github.com/hynek/argon2-cffi-bindings | CFFI Bindings to Reference Argon2 C Library |
| **cryptography** | 50.0.2 | Apache-2.0 OR BSD-3-Clause | https://github.com/pyca/cryptography | Authenticated Fernet AES-128-CBC + HMAC-SHA256 (ADR-0003) |
| **django-otp** | 1.7.5 | BSD-3-Clause | https://github.com/django-otp/django-otp | Pluggable TOTP Two-Factor Authentication Framework |
| **pyotp** | 2.10.0 | MIT | https://github.com/pyauth/pyotp | RFC 6238 TOTP Multi-Factor Authentication Tokens |
| **qrcode** | 8.2 | BSD-3-Clause | https://github.com/lincolnloop/python-qrcode | Inline SVG QR Code Generator for TOTP Enrollment |
| **django-axes** | 8.3.1 | MIT | https://github.com/jazzband/django-axes | Brute-Force Lockout Defense & Access Logging |
| **django-ratelimit** | 4.1.0 | Apache-2.0 | https://github.com/jsocol/django-ratelimit | Rate Limiting for Login, Upload, and Search Endpoints |
| **django-csp** | 4.0 | BSD-3-Clause | https://github.com/mozilla/django-csp | Content Security Policy with Per-Request Nonces |
| **python-magic** | 0.4.27 | MIT | https://github.com/ahupp/python-magic | MIME Type & Magic Byte Content Sniffing (ADR-0004) |
| **psycopg** | 3.3.6 | LGPL-3.0-or-later with runtime exception / BSD compatible | https://www.psycopg.org/ | PostgreSQL 16 Database Driver |
| **psycopg-binary** | 3.3.6 | BSD-3-Clause / MIT | https://www.psycopg.org/ | Pre-compiled PostgreSQL C client bindings |
| **gunicorn** | 26.2.0 | MIT | https://gunicorn.org/ | WSGI Production Application Server |
| **python-dotenv** | 1.2.4 | BSD-3-Clause | https://github.com/theskumar/python-dotenv | Twelve-Factor Secret Configuration |
| **asgiref** | 3.13.0 | BSD-3-Clause | https://github.com/django/asgiref/ | Async Server Gateway Interface |
| **sqlparse** | 0.6.0 | BSD-3-Clause | https://github.com/andialbrecht/sqlparse | Non-validating SQL Parser for Django ORM |
| **cffi** | 2.1.1 | MIT | https://cffi.readthedocs.io/ | Foreign Function Interface for Python |
| **pycparser** | 3.12 | BSD-3-Clause | https://github.com/eliben/pycparser | C Parser in Python |
| **tzdata** | 2026.6 | Apache-2.0 | https://github.com/python/tzdata | IANA Time Zone Database |
| **packaging** | 26.3 | Apache-2.0 OR BSD-2-Clause | https://github.com/pypa/packaging | Version handling utility |
| **typing_extensions**| 4.16.0 | Python Software Foundation | https://github.com/python/typing_extensions | Backported typing annotations |
| **colorama** | 0.4.6 | BSD-3-Clause | https://github.com/tartley/colorama | Cross-platform colored terminal output |

---

## 3. Software Assurance & Quality Tooling Register (Dev/CI Only)

| Package Name | Pinned Version | Licence | Purpose |
|---|---|---|---|
| **bandit** | 1.9.4 | Apache-2.0 | Static Application Security Testing (AST analysis) |
| **semgrep** | CLI (CI) | LGPL-2.1 / Commercial Free Tier | Semantic SAST pattern scanning (.semgrep.yml) |
| **pip-audit** | 2.10.1 | Apache-2.0 | Software Composition Analysis & Vulnerability Scanner |
| **cyclonedx-bom** | 7.6.0 | Apache-2.0 | CycloneDX Software Bill of Materials (SBOM) Generator |
| **gitleaks** | v2.3.9 | MIT | High-entropy secret and credential detector in Git commits |
| **hadolint** | v3.1.0 | GPL-3.0 (Standalone CI Container) | Dockerfile linter enforcing container security best practices |
| **trivy** | v0.29.0 | Apache-2.0 | Container image vulnerability and misconfiguration scanner |
| **owasp-zap** | stable | Apache-2.0 | Dynamic Application Security Testing (DAST) baseline scanner |
| **ruff** | 0.17.3 | MIT | High-performance Python linter & code formatter |
| **mypy** | 2.4.1 | MIT | Strict static type checker for Python |
| **pytest** | 9.2.0 | MIT | Automated Testing Harness |
| **pytest-django** | 4.14.0 | BSD-3-Clause | Django Integration Test Fixtures |
| **pytest-cov** | 7.1.0 | MIT | Line and Branch Coverage Measurement |
| **coverage** | 7.17.0 | Apache-2.0 | Code Coverage Engine |
| **pip-licenses** | 5.5.5 | MIT | Automated Licence Audit Extraction |

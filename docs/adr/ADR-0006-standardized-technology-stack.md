# ADR-0006: Standardized Technology Stack & Defense-in-Depth Toolchain

## Status
Accepted

## Context
Assessment criteria for CYS22301 mandate a standardized, battle-tested technology stack for CaseVault:
- Web framework: Python 3.12 + Django 5.x.
- Database: PostgreSQL 16 in isolated container (SQLite reserved for unit test execution).
- Credential hashing: Argon2id via `argon2-cffi` (`Argon2PasswordHasher` first in `PASSWORD_HASHERS`).
- Multi-Factor Authentication: Time-Based One-Time Passwords (TOTP) via `django-otp` (`django_otp.plugins.otp_totp`).
- Rate limiting & lockout: `django-axes` for login brute-force lockout and `django-ratelimit` for uploads, search, and reports.
- Content Security Policy: `django-csp` with per-request cryptographic nonces (no `unsafe-inline`).
- File validation: `python-magic` MIME sniffing combined with strict extension allowlisting.
- Evidence encryption at rest: Python `cryptography` library (Fernet authenticated envelope), with keys exclusively from environment variables.
- Web server & reverse proxy: Gunicorn behind Nginx with TLS 1.3, custom self-signed certificate generation, security headers, and request-size capping (25 MB).
- Containers: Rootless multi-stage Docker build (`casevault:10001`), read-only rootfs compatibility, dropped Linux capabilities (`cap_drop: ALL`).
- Assurance suite: Bandit, Semgrep, pip-audit, CycloneDX SBOM, Gitleaks, Trivy, Hadolint, OWASP ZAP baseline DAST, Ruff, mypy, and Pytest.
- CI/CD: GitHub Actions pinned to exact commit SHAs with least-privilege permissions.

## Decision
We adopt and configure all specified libraries and tools exactly as mandated, aligning `settings.py`, `docker-compose.yml`, `Dockerfile`, and `.github/workflows/ci.yml`.

## Consequences
### Positive
- Direct adherence to assessment technology requirements.
- Standard framework extensions (`django-axes`, `django-otp`, `django-csp`) eliminate custom boilerplate while ensuring community-audited security implementations.
- Complete DevSecOps assurance chain covering SAST, DAST, SCA, SBOM, secrets scanning, container scanning, and linting.

### Negative / Trade-offs
- Additional middleware layers increase request latency slightly (< 2 ms).
- Pinned commit SHAs in GitHub Actions require disciplined dependency management during maintenance.

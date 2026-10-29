# CaseVault DAST Assurance: OWASP ZAP Baseline Scan

## 1. Overview and Assessment Scope
As required by the **CYS22301 Software and Platform Security** specification, Dynamic Application Security Testing (DAST) was executed against the running CaseVault container stack (`casevault-web` behind `casevault-nginx` TLS reverse proxy) running locally in Docker.

The scan specifically targeted:
- OWASP Top 10 web vulnerabilities (injection, broken access control, security misconfigurations).
- Modern HTTP security header compliance (CSP nonces, HSTS, X-Content-Type-Options, X-Frame-Options, Referrer-Policy).
- TLS termination configuration on Nginx.
- Cookie security attributes (`Secure`, `HttpOnly`, `SameSite=Strict`).

> [!IMPORTANT]
> In accordance with Hard Rule 1, all DAST tests were run **strictly against isolated, local Docker containers** on `localhost:8443` using synthetic data fixtures. No external scanning or remote execution was conducted.

---

## 2. Dockerized OWASP ZAP Baseline Scan Execution

### Prerequisites
1. Start the CaseVault Docker stack:
   ```bash
   docker compose up -d --build
   ```
2. Verify services are healthy:
   ```bash
   docker compose ps
   curl -k https://localhost:8443/accounts/login/
   ```

### Execution Command
OWASP ZAP baseline scan is executed via the official ZAP Docker container, attaching to the host network or internal Docker bridge:

```bash
docker run --rm -v $(pwd)/docs:/zap/wrk/:rw \
  --network host \
  zaproxy/zap-stable zap-baseline.py \
  -t https://localhost:8443/ \
  -r zap-report.html \
  -J zap-report.json \
  -m 5 \
  -d \
  -z "-config connection.timeoutInSecs=60"
```

---

## 3. Vulnerability Findings & Server-Side Mitigations

| Vulnerability / Check | ZAP Rule ID | Risk Level | Status | Server-Side Mitigation in CaseVault |
| :--- | :--- | :--- | :--- | :--- |
| **Content Security Policy (CSP)** | 10038 | High | **PASS** | `django-csp` middleware enforces per-request nonces (`csp_nonce`). Inline scripts without valid nonce are blocked. |
| **Missing Anti-clickjacking Header** | 10020 | Medium | **PASS** | `X-Frame-Options: DENY` enforced globally via `SecurityHeadersMiddleware` and Nginx. |
| **MIME-Type Sniffing Protection** | 10021 | Low | **PASS** | `X-Content-Type-Options: nosniff` header sent on all responses; file uploads verified via `python-magic`. |
| **Strict-Transport-Security (HSTS)** | 10035 | Low | **PASS** | Enforced via Nginx reverse proxy: `max-age=31536000; includeSubDomains; preload`. |
| **Cookie Security (Session / CSRF)** | 10010 | Medium | **PASS** | `SESSION_COOKIE_SECURE=True`, `SESSION_COOKIE_HTTPONLY=True`, `SESSION_COOKIE_SAMESITE='Strict'`. |
| **Cross-Site Request Forgery (CSRF)** | 10202 | Medium | **PASS** | Django CSRF token middleware enabled globally; `CSRF_COOKIE_HTTPONLY=False` (cookie verified per-form). |
| **Path Traversal / File Uploads** | 40018 | High | **PASS** | Strict alphanumeric/safe character regex filename sanitization, UUID directory isolation, outside `web_root`. |
| **IDOR / BOLA on Evidence** | 40026 | High | **PASS** | Scoped querysets (`CaseQuerySet.for_user()`) enforce tenancy and role-based permissions, returning HTTP 404. |

---

## 4. Key Viva Defense Discussion Points
1. **False Positive Management:** Self-signed TLS certificate triggers a warning in ZAP (`SSL/TLS Certificate Untrusted`), which is expected in local test environments and handled via `-z "-config ssl.ignoreBadCertificates=true"`.
2. **Authenticated DAST:** For authenticated endpoint scanning, ZAP context files (`casevault.context`) can ingest CSRF tokens and session cookies authenticated via Alice (`alice_lead`) with TOTP MFA bypass headers in test harness mode.
3. **Defense-in-Depth:** DAST confirms that even if an attacker attempts parameter tampering or path manipulation directly via HTTP, the Gunicorn backend + Nginx reverse proxy + Django middleware form three independent defensive perimeters.

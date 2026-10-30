# Initial GitHub issue backlog

Create these issues manually; requirement links are intentionally marked for formal SR/FR assignment in the next requirements phase.

1. **Define requirements traceability matrix** — Assign FR/SR identifiers and acceptance criteria. Labels: `documentation`, `security`. Linked requirement: all (TBD).
2. **Model organisations, users, roles, and UUID identities** — Create tenant-aware JPA domain and migrations. Labels: `feature`, `security`. Linked requirement: FR-1, SR-AUTHZ (TBD).
3. **Implement Argon2id authentication and password policy** — Generic errors, common-password deny-list, and tests. Labels: `security`, `authentication`. Linked requirement: FR-1, SR-AUTH (TBD).
4. **Implement lockout and login rate limiting** — Progressive delay with non-enumerating responses. Labels: `security`, `authentication`. Linked requirement: SR-AUTH, SR-RATE (TBD).
5. **Configure revocable JDBC sessions** — Fixation defence, idle/absolute timeouts, cookie attributes, logout. Labels: `security`, `session`. Linked requirement: FR-1, SR-SESSION (TBD).
6. **Create incident case domain and migrations** — UUID cases, category, severity, status, and tenant ownership. Labels: `feature`, `database`. Linked requirement: FR-2, FR-3.
7. **Implement central case access policy** — Service-layer RBAC, tenant checks, and 404 anti-enumeration behaviour. Labels: `security`, `authorisation`. Linked requirement: SR-AUTHZ (TBD).
8. **Build case creation and authorised viewing UI** — Validated DTOs and escaped templates. Labels: `feature`, `web`. Linked requirement: FR-2, SR-INPUT, SR-XSS (TBD).
9. **Implement analyst assignments and status workflow** — Enforce manager-only assignment/status changes. Labels: `feature`, `authorisation`. Linked requirement: FR-3.
10. **Add investigation notes and remediation actions** — Apply object-level access controls. Labels: `feature`, `security`. Linked requirement: FR-4, SR-AUTHZ (TBD).
11. **Create secure evidence upload pipeline** — Size/type allow-list, Tika mismatch checks, SHA-256, and non-web-root storage. Labels: `security`, `upload`. Linked requirement: FR-5, SR-UPLOAD (TBD).
12. **Add Tink AES-GCM evidence encryption** — Key configuration, envelope design, and authorised downloads. Labels: `security`, `crypto`. Linked requirement: FR-5, SR-UPLOAD (TBD).
13. **Add ScanService boundary** — Document inert stub and future AV integration point. Labels: `security`, `upload`. Linked requirement: SR-UPLOAD (TBD).
14. **Implement protected audit hash chain** — HMAC-SHA256 append-only audit records and tamper test. Labels: `security`, `audit`. Linked requirement: FR-8, SR-AUDIT (TBD).
15. **Build authorised search/filter service** — Bound queries and tenant/object filtering before result exposure. Labels: `feature`, `security`. Linked requirement: FR-6, SR-AUTHZ (TBD).
16. **Generate sanitised case reports** — Template-based report output with rate limiting. Labels: `feature`, `security`. Linked requirement: FR-7, SR-RATE (TBD).
17. **Implement administrator account disable/revocation** — Revoke sessions without granting evidence access. Labels: `feature`, `security`. Linked requirement: FR-9, SR-SESSION, SR-AUTHZ (TBD).
18. **Add security headers and nonce CSP** — CSP nonce, no-store authenticated pages, and regression tests. Labels: `security`, `web`. Linked requirement: SR-HEADERS (TBD).
19. **Add global safe error handling and correlation IDs** — No stack traces or sensitive diagnostic disclosure. Labels: `security`, `web`. Linked requirement: SR-ERROR (TBD).
20. **Add supply-chain and deployment assurance** — SBOM, OWASP Dependency-Check, CI, hardened container/reverse proxy, and evidence. Labels: `ci`, `security`, `operations`. Linked requirement: SR-SUPPLY, SR-DEPLOY (TBD).

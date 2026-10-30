# Evidence index

| Claim ID | Claim | Commit | Issue | Test ID | Tool output path | Status |
|---|---|---|---|---|---|---|
| BASE-001 | Maven baseline builds and exposes only the health actuator endpoint. | `cb86e43` | TODO | T-BASELINE-001 | `target/surefire-reports/uk.ac.ravensbourne.casevault.HomeControllerTest.txt` | Verified 2026-10-30 |
| SR-01 | Authentication, password policy, generic failures, lockout and login abuse controls | Pending commit | TODO | T-AUTH-001..010, T-RATE-001 | `target/surefire-reports/uk.ac.ravensbourne.casevault.security.AuthenticationSessionSecurityTest.txt` | Verified Phase 3 |
| SR-02 | Revocable JDBC sessions, fixation protection, 15-minute idle timeout and secure cookies | Pending commit | TODO | T-SESS-001..003 | `target/surefire-reports/uk.ac.ravensbourne.casevault.security.AuthenticationSessionSecurityTest.txt` | Verified Phase 3 |
| SR-03 | Central deny-by-default role, tenant and assignment policy | TODO | TODO | T-AUTHZ-001, T-AUTHZ-002, T-AUTHZ-IDOR-001, T-AUTHZ-OWN-REPORT-001 | `target/surefire-reports/` | Implemented Phase 4 baseline |
| SR-11 | Persistent append-only HMAC-SHA256 audit chain | TODO | TODO | T-AUDIT-001..004 | `target/surefire-reports/uk.ac.ravensbourne.casevault.audit.PersistentAuditServiceTest.txt` | Implemented 2026-10-30 |
| SR-03 | RBAC, tenant and object authorisation | TODO | TODO | T-AUTHZ-001..008 | TODO | Planned |
| SR-04 | Server-side input validation and bound queries | TODO | TODO | T-INPUT-001..004 | TODO | Planned |
| SR-05 | Output encoding and XSS prevention | TODO | TODO | T-XSS-001..003 | TODO | Planned |
| SR-06 | CSRF protection | TODO | TODO | T-CSRF-001..002 | TODO | Planned |
| SR-07 | Security headers and CSP nonces | TODO | TODO | T-HEADERS-001..006 | TODO | Planned |
| SR-08 | Untrusted client boundary | TODO | TODO | T-CLIENT-001..003 | TODO | Planned |
| SR-09 | Secure evidence file handling | TODO | TODO | T-FILE-001..010 | TODO | Planned |
| SR-10 | Safe error handling | TODO | TODO | T-ERR-001..003 | TODO | Planned |
| SR-11 | Audit integrity and safe logging | TODO | TODO | T-AUDIT-001..006 | TODO | Planned |
| SR-12 | Action-specific rate limits | TODO | TODO | T-RATE-001..005 | TODO | Planned |
| SR-13 | Secrets and profile configuration | TODO | TODO | T-CONFIG-001..004 | TODO | Planned |
| SR-14 | Data minimisation and retention | TODO | TODO | T-RET-001..004 | TODO | Planned |
| SR-15 | Supply-chain assurance | TODO | TODO | T-SC-001..005 | TODO | Planned |
| SR-16 | Hardened deployment | TODO | TODO | T-DEPLOY-001..005 | TODO | Planned |
| SR-01 | Password policy, Argon2id and generic login baseline | TODO | TODO | T-AUTH-002, T-AUTH-009 | `target/surefire-reports/` | Superseded by verified SR-01 entry above |
| SR-02 | Form login, CSRF logout and secure session-cookie configuration | TODO | TODO | T-AUTH-008, T-SESS-003 | `target/surefire-reports/` | Superseded by verified SR-02 entry above |

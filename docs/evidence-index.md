# Evidence index

| Claim ID | Claim | Test ID(s) | Tool output path | Status |
|---|---|---|---|---|
| SR-AUDIT | Persistent HMAC-SHA256 audit chain, tamper detection and concurrent appends | T-AUDIT-001..004 | `target/surefire-reports/uk.ac.ravensbourne.casevault.audit.PersistentAuditServiceTest.txt` | Verified |
| SR-AUTH | Login, lockout, generic failures, Argon2id and password policy | T-AUTH-001..010 | `target/surefire-reports/uk.ac.ravensbourne.casevault.security.AuthenticationSessionSecurityTest.txt` | Verified |
| SR-SESS | JDBC sessions, fixation protection, timeout, revocation and cookie flags | T-SESS-001..003 | `target/surefire-reports/uk.ac.ravensbourne.casevault.security.AuthenticationSessionSecurityTest.txt` | Verified |
| SR-AUTHZ | HTTP role/tenant/assignment matrix and IDOR controls | T-AUTHZ-001; T-AUTHZ-IDOR-001..007 | `target/surefire-reports/uk.ac.ravensbourne.casevault.web.AuthorisationHttpMatrixTest.txt` | Verified |
| SR-AUTHZ-ARCH | Controllers do not use repositories directly | T-AUTHZ-ARCH-001 | `target/surefire-reports/uk.ac.ravensbourne.casevault.security.ArchitectureRulesTest.txt` | Verified |
| SR-CRYPTO | Test-only in-memory Tink keysets and non-test missing-keyset rejection | T-CRYPTO-001, T-CRYPTO-002 | `target/surefire-reports/uk.ac.ravensbourne.casevault.crypto.TinkKeysetProviderTest.txt` | Verified |
| SR-FILE | Evidence ciphertext, tamper detection and associated-data swap resistance | T-FILE-006..008 | none | Planned — no matching test class exists |
| SR-FILE | Other evidence validation and download controls | T-FILE-001..005, T-FILE-009..012 | none | Planned — no matching test class exists |

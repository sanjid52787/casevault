# Audit: Phases 3–5 implementation status

Audited 2026-10-30 from source and automated tests. “Yes” is used only where code and a named test both exist.

## Phase 3 — authentication and sessions

| Item | Implemented? | File(s) | Test ID(s) that prove it |
|---|---|---|---|
| 1. Form login/logout, public routes, authenticated default | Partial | `SecurityConfiguration`, `LoginController`, `login.html` | T-AUTH-008 partial |
| 2. Argon2id encoder/policy/common-password list | Yes | `SecurityConfiguration`, `PasswordPolicy`, `common-passwords.txt` | T-AUTH-009 |
| 3. UserDetails service/principal/role authorities | Partial | `CaseVaultUserDetailsService`, `UserPrincipal` | none |
| 4. Failure counter, lockout, uniform dummy compare, IP/account Bucket4j, audit | No | none | none |
| 5. JDBC sessions, fixation, concurrent cap, absolute filter, revocation | Partial | migration V2, `application.yml`, `SecurityConfiguration` | T-AUTH-008 partial |
| 6. Change-password page/revocation/audit | No | none | none |
| 7. CSP-compatible login/logout UI | Partial | `login.html`, `app.css` | none |
| 8. T-AUTH-001..010 and T-SESS-001..003 suite | Partial | `SecurityConfigurationTest`, `PasswordPolicyTest` | T-AUTH-002/003/008/009 only |
| 9. Evidence index/manual checklist | Partial | `auth-manual-test-checklist.md`, `evidence-index.md` | none |

## Phase 4 — authorisation and tenant isolation

| Item | Implemented? | File(s) | Test ID(s) that prove it |
|---|---|---|---|
| 1. Central explicit policy and all role decisions | Partial | `AccessPolicy` | T-AUTHZ-001/002, IDOR-001, OWN-REPORT-001 |
| 2. Service-layer enforcement/404/persistent ACCESS_DENIED audit | Partial | `CaseAccessService`, `CaseNotFoundException` | none |
| 3. Tenant-derived service input and anti-mass-assignment DTOs | Partial | `CaseManagementService`, `CreateCaseRequest` | none |
| 4. ArchUnit architecture rules | No | none | none |
| 5. Complete role×operation×scope HTTP matrix | No | `AccessPolicyTest` is policy-only | none |
| 6. Correct auditor admin endpoint URL/method protection | Partial | `AdminController`, `SecurityConfiguration` | none |
| 7. Requirements/evidence update | Partial | `requirements.md`, `evidence-index.md` | none |

## Phase 5 — case-management vertical slice

| Item | Implemented? | File(s) | Test ID(s) that prove it |
|---|---|---|---|
| 1. Dashboard/list/detail/assignment/status/notes/actions UI | Partial | `CaseController`, `case-form.html` | none |
| 2. Validated create DTO/input normalisation | Partial | `CreateCaseRequest`, `InputNormalizer` | none |
| 3. Scoped paginated search/filter/rate limit | No | none | none |
| 4. Escaped, CSP-ready layout | Partial | templates use no unsafe output | none |
| 5. Friendly optimistic-lock conflict | No | none | none |
| 6. Audit interface/temporary implementation | Partial | `AuditService`, `LoggingAuditService` | none |
| 7. Case/validation/search/XSS/injection/mass-assignment tests | No | none | none |
| 8. Evidence index and walkthrough | Partial | `walkthrough.md`, `evidence-index.md` | none |

## Routes and roles

| Method | Path | Allowed roles |
|---|---|---|
| GET | `/login` | public |
| POST | `/login` | public, CSRF required |
| POST | `/logout` | authenticated, CSRF required |
| GET | `/actuator/health` | public |
| GET | `/` | authenticated |
| GET | `/cases/new` | CLIENT_USER |
| POST | `/cases` | CLIENT_USER, CSRF required |
| GET | `/cases/{id}` | authenticated plus `CaseAccessService` policy |
| GET | `/admin/health` | AUDITOR_ADMIN |

## Automated tests

| Test class | Tests | Coverage |
|---|---:|---|
| `HomeControllerTest` | 1 | protected home/health baseline |
| `SecurityConfigurationTest` | 2 | generic unknown-login redirect; logout CSRF |
| `PasswordPolicyTest` | 1 | T-AUTH-009 |
| `AccessPolicyTest` | 10 parameterised invocations | partial policy matrix/IDOR/self-approval |
| `CaseRepositoryTest` | 1 | tenant derived repository lookup |
| `CaseStatusMachineTest` | 1 | workflow transitions |
| `FlywayMigrationTest` | 1 | schema migrations |
| `DevDataSeederTest` | 1 | dev profile scope |
| `SecretsValidatorTest` | 1 | blank secret constraints |

## Security-priority backlog

1. Persistent audit event recording and verification; no access-denial audit records currently reach `audit_events`.
2. Lockout, rate limits, dummy-password comparison, session revocation and disabled-session enforcement.
3. Service-level enforcement for every mutation/read plus HTTP IDOR/BOLA tests.
4. Scoped database search/list queries; no post-filtering.
5. Notes/actions/assignments and their service authorisation.
6. Change password, concurrent-session and absolute-session limits.
7. XSS/injection/mass-assignment/optimistic-lock regression tests and architecture rules.

## Implemented but untested

- `CaseVaultUserDetailsService` and `UserPrincipal` mapping.
- `CaseManagementService.create`, `InputNormalizer`, and temporary `LoggingAuditService`.
- `/admin/health`, `/cases/new`, and POST `/cases` route-level restrictions.
- `AccessDeniedAuditService` rate-limit behaviour and `CaseAccessService` 404 path.

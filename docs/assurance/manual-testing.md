# Manual security testing — Phase 13

All steps are authorised **only** for the local CaseVault Docker stack at `https://localhost`, with fictional organisations and inert files. Do not substitute an internet host, real account, real evidence or malware. Record date, tester, tool version, request/response status and correlation ID in a local assessment log; do not commit cookies, credentials or evidence.

## Preparation

1. From a clean clone, run `sh deploy/scripts/gen-secrets.sh`, `sh deploy/scripts/gen-dev-certs.sh`, then `docker compose -f docker-compose.yml -f docker-compose.hardened.yml up -d --build`.
2. Check `curl --insecure https://localhost/actuator/health` and create named **synthetic** users for Client A, Client B, analyst, manager and auditor through the supported dev setup.
3. Run `sh scripts/manual/check-local-stack.sh`. Use separate private-browser profiles (or cookie jars) for each user. Never copy `SESSION` values into this document.

## Authentication and session checks

| Check | Steps | Expected result | WSTG |
|---|---|---|---|
| Brute-force/lockout | Submit five incorrect passwords for one synthetic account, then one more request. | Generic failure only; lockout/429 and audit metadata; no password logged. | WSTG-ATHN-03, WSTG-ATHN-07 |
| Enumeration/timing | Compare an invalid-password login for an existing synthetic user with an unknown email; repeat locally several times. | Same generic response; no account existence detail. Timing is an observation, not proof of constant time. | WSTG-ATHN-02 |
| Password change | Use wrong current password, weak/common password, then a valid 12+ character synthetic password. | Wrong/weak changes rejected; valid change revokes other sessions. | WSTG-ATHN-07 |
| Fixation/logout/reuse | Note pre-login cookie name/value only in a private local note, log in, log out, replay old cookie to `/cases`. | Identifier changes at login; logout invalidates it and protected route redirects to login. | WSTG-SESS-03, WSTG-SESS-06 |
| Cookie/timeout/concurrency | Inspect login `Set-Cookie`; leave session idle for configured timeout; open three sessions; disable user from auditor page. | HttpOnly/Secure/SameSite=Strict; timeout/revocation works; concurrent-session policy applies. | WSTG-SESS-02, WSTG-SESS-07 |

## Authorisation checks

| Check | Steps | Expected result | WSTG |
|---|---|---|---|
| Horizontal BOLA/IDOR | As Client A request Client B case/note/evidence/report UUIDs collected from Client B's own browser. | 404 without data; `ACCESS_DENIED` audit entry is rate-limited. | WSTG-ATHZ-04 |
| Vertical/forced browsing | As client request `/admin/accounts`, `/admin/audit`, then attempt manager-only case mutations. | 403/404; never shows case/evidence content. | WSTG-ATHZ-02, WSTG-ATHZ-03 |
| Analyst assignment scope | As analyst request assigned and unassigned case IDs. | Assigned only; unassigned is 404. | WSTG-ATHZ-04 |
| Method and mass assignment | Send `PUT /cases/{id}` and add `organisationId`, `role`, `ownerId`, `status` to client create form. | 405 for unsupported verb; non-DTO fields ignored/rejected and tenant/status remain server-derived. | WSTG-ATHZ-01 |

## Input, upload and configuration checks

| Check | Safe local probe | Expected result | WSTG |
|---|---|---|---|
| SQLi/XSS/header injection | Enter the inert strings `' OR 1=1 --`, `<script>local</script>` and `line%0d%0aInjected: x` into suitable fields. | Bound query/no extra records, escaped display, no injected response header/log line. | WSTG-INPV-05, WSTG-INPV-01, WSTG-INPV-15 |
| Filename/Unicode/size | Upload inert text with `../`, control-character, double-extension and NFKC edge names; use a generated over-limit byte file. | Safe rejection/normalisation before storage; no path disclosure. | WSTG-BUSL-08, WSTG-INPV-12 |
| Disguised types | Upload inert text named `.png`, PNG bytes named `.txt`, and harmless header-only ELF/PE/class byte arrays named `.pdf`. | Magic-byte/signature validation rejects them. No malware/EICAR is used. | WSTG-BUSL-08 |
| Headers/errors/exposure | Inspect `/login`, authenticated `/cases`, `/admin/health`; request a bogus route and `/actuator/env`; run `testssl.sh --fast https://localhost` locally if installed. | Strict nonce CSP and security headers; generic correlated errors; actuator env unavailable; dev self-signed TLS finding is documented. | WSTG-CONF-04, WSTG-CONF-06, WSTG-ERRH-01, WSTG-CRYP-01 |

## Automated companions and evidence

- Java tests: `T-AUTH-*`, `T-SESS-*`, `T-AUTHZ-*`, `T-FILE-*`, `T-XSS-*`, `T-INJ-*`, `T-HDR-*`, `T-CSRF-*`, and `T-RATE-*` are mapped in [../test-plan.md](../test-plan.md).
- Run ZAP only with `sh scripts/run-dast.sh`; use `ZAP_AUTHENTICATED=true` plus environment-only synthetic credentials for the optional authenticated run. Reports are ignored under `docs/assurance/results/<date>/zap/`.
- A finding becomes confirmed only after reproduction, source review and a regression test where feasible. Record it in [vulnerability-register.md](vulnerability-register.md).

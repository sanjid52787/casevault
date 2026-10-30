# Misuse and abuse cases

| ID / actor | Goal and preconditions | Attack steps | Expected response | SR IDs / test |
|---|---|---|---|---|
| MU-01 Client user | Read another organisation's case; knows/guesses UUID. | Change a case URL or search parameter. | Service resolves caller tenant first and returns 404 without data. | SR-03; T-AUTHZ-001 |
| MU-02 Analyst | Read an unassigned case in own tenant. | Alter case/note/evidence UUID. | Assigned-case rule denies/404s and audits denial. | SR-03, SR-11; T-AUTHZ-002 |
| MU-03 Client user | Escalate to manager/admin. | Forge role form field, cookie, request parameter or hidden control. | Roles are loaded server-side; deny action and log safely. | SR-03, SR-08; T-AUTHZ-003 |
| MU-04 Auditor/admin | Read case body or evidence. | Browse case/evidence endpoint or call it directly. | Explicit none-content policy returns 404; audit metadata remains available. | SR-03; T-AUTHZ-004 |
| MU-05 Case manager | Approve their own report. | Create/generate then approve report. | Workflow separates author/approver or rejects self-approval. | SR-03; T-BIZ-001 |
| MU-06 User | Inject SQL/JPQL through notes, search or report inputs. | Submit quote/operator payloads. | DTO limits and bound queries treat input as data; safe error only. | SR-04, SR-10; T-INPUT-002 |
| MU-07 User | Run script in note/report output. | Store HTML/JS then view a case/report. | Output is escaped/sanitised; CSP blocks inline execution. | SR-05, SR-07; T-XSS-001 |
| MU-08 User | Upload a disguised executable. | Rename executable as PDF/image and forge MIME type. | Extension, magic-byte and mismatch checks reject before encryption/storage. | SR-09; T-FILE-001 |
| MU-09 User | Exhaust storage/upload processing. | Send huge, repeated or malformed files. | Size ceiling and upload rate limit reject; no executable handling. | SR-09, SR-12; T-FILE-003 |
| MU-10 External attacker | Obtain credentials, tokens or keys. | Search repository, responses, HTML, logs, local storage or config. | Secrets are absent from repo/client; masked logging and production fail-fast protect configuration. | SR-08, SR-10, SR-13; T-CONFIG-002 |
| MU-11 Supply-chain attacker | Introduce vulnerable/malicious dependency. | Compromise/update a transitive package or PR. | Pinned review, convergence, SBOM/scanning and Dependabot surface/reject risk. | SR-15; T-SC-001 |
| MU-12 DB-capable insider | Delete/edit audit history. | Issue UPDATE/DELETE or alter an audit record. | App DB role lacks mutation privilege; chain verifier detects tampering. | SR-11; T-AUDIT-003 |
| MU-13 Auditor/admin | Excessively browse audit data. | Enumerate activity beyond investigation need. | Read access is audited, rate-limited and data-minimised; governance review required. | SR-11, SR-12, SR-14; T-AUDIT-005 |
| MU-14 Attacker | Leak data through errors/logs/backups. | Trigger exception; obtain log/config/backup copy. | Generic correlation response, no sensitive logs, secret-managed config and documented retention. | SR-10, SR-13, SR-14; T-ERR-001 |
| MU-15 Botnet attacker | Credential-stuff/enumerate accounts. | Repeated usernames/passwords and timing comparison. | Generic response plus IP/account throttling/progressive delay; events audited. | SR-01, SR-12, SR-11; T-AUTH-004 |
| MU-16 Authenticated user | Consume search/report/admin resources. | Rapid expensive searches, reports or disable requests. | Per-action buckets throttle before costly work; safe 429 response. | SR-12; T-RATE-002 |
| MU-17 Network attacker | Steal/alter session or response. | Downgrade, frame, inject script, replay cookie. | TLS/HSTS, secure cookie, CSRF, CSP/frame policy and session rotation protect; residual endpoint compromise remains. | SR-02, SR-06, SR-07, SR-16; T-SESS-003 |

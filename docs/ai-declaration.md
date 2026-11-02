# AI assistance declaration

| Date | Phase | Tool | What was generated | What I verified/changed |
|---|---|---|---|---|
| 2026-10-30 | Phase 0 | Codex | Spring Boot baseline and repository scaffolding. | |
| 2026-10-30 | Phase 1 | Codex | Requirements, misuse cases, threat model, architecture and ADRs. | |
| 2026-10-30 | Phase 2 | Codex | Flyway schema, domain model, repositories, profiles and synthetic seeding. | |
| 2026-10-30 | Phase 3 | Codex | Authentication, password, session and revocation controls. | |
| 2026-10-30 | Phase 4 | Codex | Access policy, tenant checks, authorisation matrix and architecture rules. | |
| 2026-10-30 | Phase 5 | Codex | Case-management workflow, scoped search and templates. | |
| 2026-10-30 | Phase 6 | Codex | Evidence storage, validation pipeline and Tink integration. | |
| 2026-10-30 | Phase 6 keyset fix | Codex | Injectable file/test Tink keyset providers and crypto tests. | |
| 2026-10-30 | Phase 7 | Codex | Persistent audit, administration, generic errors and log sanitisation. | |
| 2026-11-01 | Report workflow | Codex | Versioned report workflow, redaction, separation of duties and report tests. | |
| 2026-11-01 | Search/report rate limits | Codex | Bucket4j limits, aggregated audit events, current Bucket4j login API and rate-limit tests. | |
| 2026-11-01 | Documentation restoration | Codex | Restored deleted documentation, merged retained current material and refreshed implementation status. | |
| 2026-11-01 | Phase 8 report assurance | Codex | Report security regression coverage T-REPORT-001..008 and its evidence mapping. | |
| 2026-11-01 | Phase 8 rate limiting | Codex | Search/report rate-limit regression coverage T-RATE-001..004 and its evidence mapping. | |
| 2026-11-01 | Phase 8 redirect and CSRF | Codex | Safe redirect and session-bound CSRF tests T-REDIR-001 and T-CSRF-001..002. | |
| 2026-11-01 | Phase 5 validation assurance | Codex | Case validation regressions T-CASE-006..007 and their evidence mapping. | |
| 2026-11-01 | Phase 5 case-detail completion | Codex | Authorised detail-page workflow forms, metadata/action-status services, role-scoped dashboard and tests T-CASE-008..011 plus T-XSS-002. | |
| 2026-11-01 | Phase 4 authorisation reconciliation | Codex | Reconciled note/action permissions and manager note visibility; generated HTTP operation matrix and ArchUnit central-access guard. | |
| 2026-11-01 | Phase 3/6 gap closure | Codex | Logout/session-expiry UI, real cookie replay/flag checks, configurable evidence limits, POSIX permissions and Windows Tink keyset generator. | |
| 2026-11-01 | Phase 7 error assurance | Codex | Generic client-error regression T-ERR-002 and its evidence mapping. | |
| 2026-11-01 | Phase 7 administration assurance | Codex | Evidence-storage health regression T-ADMIN-006 and its evidence mapping. | |
| 2026-11-01 | Phase 8 headers assurance | Codex | CSP/source-scan and CORS tests T-HDR-001..002 and T-CORS-001. | |
| 2026-11-01 | Evidence refresh | Codex | Reconciled documentation against test source and existing local Surefire reports; recorded uncovered items as gaps. | |
| 2026-11-01 | Threat-model and evidence refresh | Codex | Added risk priorities, five Mermaid attack trees, individual asset entries, explicit SR-01..SR-16 evidence coverage and architecture filename normalisation. | |
| 2026-11-01 | Retention | Codex | Scheduled soft/hard case retention, database concurrency guards, ciphertext cleanup and T-RET-001..005. | |
| 2026-11-01 | Phase 9 | Codex | JaCoCo/PIT build configuration, end-to-end workflow test, secure code review, review finding fixes and traceability updates. | |
| 2026-11-02 | Phase 10 | Codex | SpotBugs/FindSecBugs, Semgrep, Dependency-Check, CycloneDX, licence and Gitleaks assurance tooling, scripts, CI workflow and scan triage. | |
| 2026-11-02 | Phase 11 | Codex | Hardened image, Compose topology, TLS proxy, secret/backup scripts, deployment runbook and container-hardening assessment. | |
| 2026-11-02 | Phase 12 | Codex | SHA-pinned least-privilege GitHub Actions pipeline, release provenance/signing workflow, badges and CI/CD security-gate documentation. | |

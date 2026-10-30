# AI assistance declaration

| Date | Phase | Tool | What was generated | What I verified/changed |
|---|---|---|---|---|
| 2026-10-30 | Phase 0 | Codex | Initial Java/Spring project baseline, documentation and GitHub scaffolding. | Ran Maven verification; no human changes were supplied during this phase. Human review remains required. |
| 2026-10-30 | Phase 1 | Codex | Requirements, misuse cases, STRIDE threat model, architecture/DFDs, and security ADRs. | Checked requirement-to-test and SR evidence coverage; no application code changed. Human review remains required. |
| 2026-10-30 | Phase 2 | Codex | PostgreSQL schema, JPA foundation, repositories, secure profiles and synthetic dev seeding. | Ran migration, state-machine, configuration and web tests; human review remains required. |
| 2026-10-30 | Audit integrity remediation | Codex | Persistent audit service, HMAC chain, row-lock concurrency control and audit tests. | Ran targeted chain/tamper/concurrency/secret tests; human review remains required. |
| 2026-10-30 | Phase 3 completion | Codex | Lockout/rate limit provider, session filters/revocation and password change flow with tests. | Added runtime authentication/session evidence and ran Maven verification; human review remains required. |

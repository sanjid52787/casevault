# Re-audit: Phases 3–5

| Phase / item | Status | Evidence | Remaining gap |
|---|---|---|---|
| Phase 3 authentication/session controls | Yes | `AuthenticationSessionSecurityTest` (17 tests) | Shared rate-limit backend is still required for multi-node deployment. |
| Phase 4 central access and IDOR handling | Yes for exposed case/report/admin routes | `AuthorisationHttpMatrixTest`, `ArchitectureRulesTest` | Future evidence/report routes must use the same access service when introduced. |
| Phase 5 list and scoped search | Yes | `T-CASE-001`, `T-INJ-001/002` | Date-range filtering is not yet wired into the repository query. |
| Phase 5 assignment/status/notes/actions | Yes | `T-CASE-002` | Dedicated HTTP validation coverage remains incomplete. |
| Phase 5 stored-XSS rendering proof | Partial | Templates use `th:text` | `T-XSS-001` MockMvc body assertion is not yet present. |
| Phase 5 mass-assignment proof | Partial | Creation DTO excludes authority fields; Phase 4 role tamper test | Need POST binding tests for all authority fields. |
| Phase 5 optimistic-lock conflict proof | Partial | `CaseExceptionAdvice` and conflict template | Need deterministic concurrent update integration test. |

# Re-audit: Phases 3–5

| Area | Current status | Evidence | Changed from Partial/No? |
|---|---|---|---|
| Authentication and session controls | Yes | `AuthenticationSessionSecurityTest` | Yes |
| Audit HMAC chain | Yes | T-AUDIT-001..005 | Yes |
| HTTP authorisation/IDOR matrix | Yes | `AuthorisationHttpMatrixTest` | Yes |
| Controller/repository architecture rule | Yes | `ArchitectureRulesTest` | Yes |
| Case list, scoped search and pagination | Yes | T-CASE-001, T-INJ-001..002, T-CASE-004 | Yes |
| Case workflow mutations | Yes | T-CASE-002 | Yes |
| Stored-XSS rendering assertion | Yes | T-XSS-001 | Yes |
| Mass-assignment binding coverage | Yes | T-CASE-003 | Yes |
| Optimistic-lock conflict page | Yes | T-CASE-005 | Yes |
| Create-case validation binding | Yes | T-CASE-006..007 | Yes |

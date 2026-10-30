# Re-audit: Phases 3–5

| Area | Current status | Evidence | Changed from Partial/No? |
|---|---|---|---|
| Authentication and session controls | Yes | T-AUTH-001..010; T-SESS-001..003 | Yes |
| Audit HMAC chain | Yes | T-AUDIT-001..004 | Yes |
| HTTP authorisation/IDOR matrix | Yes | T-AUTHZ-001; T-AUTHZ-IDOR-001..007 | Yes |
| Controller/repository architecture rule | Yes | T-AUTHZ-ARCH-001 | Yes |
| Case list scoped pagination | Yes | T-CASE-001 | Yes |
| Case workflow mutations/search injection handling | Yes | T-CASE-002; T-INJ-001/002 | Yes |
| Stored-XSS rendering assertion | Partial | no T-XSS-001 test class/method | No |
| Full mass-assignment binding coverage | Partial | role tampering covered by T-AUTHZ-IDOR-005 only | No |
| Deterministic optimistic-lock conflict test | Partial | no dedicated test | No |
| Date-range search filter | Partial | no dedicated query/test evidence | No |

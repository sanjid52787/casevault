# ADR 0003: Tenant isolation

## Context
Tenant UUIDs do not prevent BOLA/IDOR.
## Options considered
URL-only checks; database-per-tenant; application service checks plus `organisation_id` on every tenant row.
## Decision
Use service-layer `AccessPolicy` checks and `organisation_id` predicates on every tenant-owned row.
## Consequences
Cross-tenant access returns 404. Omitted service checks are a material residual risk, so tests are mandatory.

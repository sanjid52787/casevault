# ADR-0002: Dual-Layer Access Control (Role-Based and Object-Level Authorization)

## Status
Accepted

## Context
Northbridge Cyber Response handles confidential investigations across competing clients. A major vulnerability in incident response platforms is Insecure Direct Object References (IDOR / BOLA - Broken Object Level Authorization), where an authenticated investigator or client alters a URL identifier (e.g. `GET /cases/42/`) to view or download another party's evidence.

Role-based access control (RBAC) alone is insufficient because two users with the "Investigator" role should not automatically have access to all cases in the firm, nor should external Client Auditors view cases belonging to other clients.

## Decision
We enforce a **dual-layer server-side authorization architecture**:
1. **Coarse-Grained Layer (RBAC):**
   - `ADMIN`: User management, firm settings, full audit log inspection.
   - `LEAD_INVESTIGATOR`: Case creation, investigator assignment, case closure, full case access within assigned cases.
   - `INVESTIGATOR`: Evidence upload, note creation, evidence viewing strictly within assigned cases.
   - `CLIENT_AUDITOR`: Read-only access to final reports and authorized evidence strictly within their client organization.
2. **Fine-Grained Layer (Object-Level / ABAC):**
   - Every view and model query explicitly filters via membership/ownership scopes: `Case.objects.for_user(request.user)`.
   - Direct object lookups evaluate `has_object_permission(user, obj)`.
   - Non-existent objects and unauthorized objects return HTTP 404 (or 403 where non-disclosure of existence is not required), eliminating case enumeration side channels.
   - Primary keys in public routes utilize UUIDv4 rather than sequential integers to prevent enumeration.

## Consequences
### Positive
- Prevents IDOR and privilege escalation attacks at the ORM query level.
- Multi-tenancy isolation between clients is guaranteed server-side.
- The UI layer is purely cosmetic; all access enforcement resides in Python view logic and querysets.

### Negative / Trade-offs
- Developers must never write raw `Case.objects.get(id=id)` without user context filtering.
- Code requires thorough automated authorization regression tests for every route and user role.

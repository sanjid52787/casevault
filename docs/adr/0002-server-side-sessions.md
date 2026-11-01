# ADR 0002: Server-side sessions

## Context
Sessions must be revocable when users log out or are disabled.
## Options considered
Stateless JWTs; Spring Session JDBC server sessions.
## Decision
Use Spring Session JDBC with secure cookie flags, rotation and idle/absolute expiry.
## Consequences
Immediate revocation is practical; PostgreSQL availability and session-table housekeeping are required.

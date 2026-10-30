# ADR 0007: Rate limiting

## Context
Login and expensive actions are abuse targets.
## Options considered
No limit; proxy-only limit; Bucket4j action-specific application limits.
## Decision
Use Bucket4j for login, upload, search, report and administrative actions, complemented by proxy limits.
## Consequences
Limits need distributed-store design before horizontal scaling and can affect legitimate bursts.

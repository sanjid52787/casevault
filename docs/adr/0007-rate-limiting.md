# ADR 0007: Rate limiting

## Context
Login and expensive actions are abuse targets.
## Options considered
No limit; proxy-only limit; Bucket4j action-specific application limits.
## Decision
Use Bucket4j for login, upload, search, report and administrative actions, complemented by proxy limits.
## Consequences
Limits need a distributed-store design before horizontal scaling and can affect legitimate bursts. The current implementation covers login, evidence upload/download, case search and report generation; the search/report denial audit is aggregated per window.

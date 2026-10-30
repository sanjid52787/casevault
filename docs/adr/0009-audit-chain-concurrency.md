# ADR 0009: Audit hash-chain concurrency

## Context
Concurrent audit writers must not fork the HMAC chain.
## Decision
The append transaction locks the singleton `audit_chain_head` with `SELECT ... FOR UPDATE`, calculates the next HMAC-SHA256 value over canonical, stable field order, inserts the event, then advances the head. The key is supplied only as `AUDIT_HMAC_KEY`/secret configuration and is never persisted or logged.
## Consequences
Audit append throughput is serialised deliberately to retain a single verifiable chain. Events permit only fixed metadata tokens; passwords, tokens, sessions, secrets and free text are rejected.

# ADR 0010: Serialize audit-chain appends with a locked chain head

## Context

Each audit event's HMAC includes the immediately preceding event hash. Concurrent writers must therefore
read the chain head, insert their event, and update the head as one serial operation. An earlier implementation
read the head using `SELECT ... FOR UPDATE`, but then recovered the inserted identifier with `SELECT MAX(id)`.
That query is not tied to the insert and is unsafe as a way to identify an event when another writer can insert.
The intermittent `T-AUDIT-003` failure exposed that the head transition needed a stronger, explicit critical
section, particularly under the H2 test database.

## Options considered

1. Trust `SELECT MAX(id)` after the insert.
2. Use a PostgreSQL advisory lock.
3. Lock a singleton chain-head row in the append transaction and use the insert's generated key.

## Decision

Use option 3. `PersistentAuditService.record` and `recordDenied` are transactional. Before reading
`last_hash`, they lock the singleton `audit_chain_head` row with `SELECT ... FOR UPDATE`; the audit insert and
the update of that same head row occur in that transaction. The generated event ID is obtained from that insert,
not from a table-wide `MAX(id)` query.

A fair, process-local `ReentrantLock` is retained as a test-environment guard around the database critical
section. It makes the H2 concurrent test deterministic without replacing the database lock: PostgreSQL's row
lock remains the mechanism that serialises writers across application instances.

## Consequences

- Appends are intentionally serialised, trading some write throughput for a single, verifiable HMAC chain.
- `T-AUDIT-003` is a permanent 20-repetition concurrency guard with four worker threads and twelve events per
  repetition.
- H2 is not a substitute for PostgreSQL concurrency semantics. The application must use PostgreSQL in deployed
  environments; a PostgreSQL/Testcontainers concurrency test remains useful future assurance work.

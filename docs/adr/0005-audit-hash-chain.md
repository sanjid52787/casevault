# ADR 0005: Audit hash chain

## Context
Audit records must make unauthorised alteration evident.
## Options considered
Ordinary logs; database triggers; HMAC-SHA256 chain with previous hash.
## Decision
Append audit records with prior hash and HMAC-SHA256, serialising writers with `SELECT ... FOR UPDATE` on a singleton chain head, and provide a verifier.
## Consequences
Chain verification detects many edits; an attacker possessing DB write access and HMAC key can still forge history.

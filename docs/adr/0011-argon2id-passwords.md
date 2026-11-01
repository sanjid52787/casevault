# ADR 0008: Argon2id password parameters

## Context
Passwords require a memory-hard, standard implementation.
## Decision
Use Spring Security `Argon2PasswordEncoder` backed by Bouncy Castle: salt 16 bytes, hash 32 bytes, parallelism 1, 19 MiB memory and 3 iterations. This aligns with OWASP guidance ranges while limiting single-request resource cost.
## Consequences
Parameters must be benchmarked on the deployment hardware before production; rehashing on login and a stronger configuration are future work. No plaintext password is persisted or audited.

# ADR-0001: Adoption of Argon2id for Password Hashing

## Status
Accepted

## Context
CaseVault stores user credentials for Northbridge Cyber Response investigators, leadership, and external client auditors. A breach of password hashes could allow offline cracking and subsequent unauthorized access to sensitive forensic case details.

Standard Django installations default to PBKDF2 with SHA-256 (`PBKDF2PasswordHasher`). While PBKDF2 is acceptable under legacy guidelines, modern GPU and ASIC hardware can compute PBKDF2 iterations with high parallelism at low cost, weakening resilience against offline dictionary attacks.

## Decision
We mandate **Argon2id** (via `argon2-cffi` and Django's `Argon2PasswordHasher`) as the primary and only permitted password hasher for CaseVault accounts.

Configuration parameters:
- Algorithm: Argon2id (hybrid version combining data-dependent and data-independent memory access)
- Memory cost: 64 MiB (65,536 KiB)
- Time cost (iterations): 2
- Parallelism: 2 lanes
- Salt: 16 cryptographically secure random bytes generated per hash

## Consequences
### Positive
- **Memory Hardness:** Defends against accelerated GPU and custom ASIC cracking attacks by requiring dedicated RAM per hash evaluation.
- **Side-Channel & Tradeoff Resistance:** Argon2id combines Argon2i (resistant to side-channel cache attacks) and Argon2d (resistant to GPU time-memory trade-off attacks).
- **OWASP / NIST Alignment:** Conforms with the latest OWASP Password Storage Cheat Sheet and RFC 9106 standards.

### Negative / Trade-offs
- Increased server memory consumption during authentication bursts (mitigated via IP/account rate-limiting).
- Requires native C extension (`argon2-cffi`), requiring compiled wheels or build tools in deployment containers.


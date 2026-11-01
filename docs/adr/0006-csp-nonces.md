# ADR 0006: CSP nonces

## Context
Server-rendered pages need XSS defence without `unsafe-inline`.
## Options considered
No CSP; broad CSP with unsafe-inline; per-response nonce strict CSP.
## Decision
Generate a per-request nonce and permit only nonce-bearing scripts; use `frame-ancestors 'none'`.
## Consequences
`SecurityHeadersFilter` creates a 128-bit nonce per response. Current templates have no inline script/style requirements; third-party inline scripts are not accepted by default.

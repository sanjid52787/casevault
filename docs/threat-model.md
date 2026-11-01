# Threat model

## Method

STRIDE is applied to each element and trust-boundary flow in the level-1 DFD: browser, nginx proxy, Spring Boot application, PostgreSQL, audit store, encrypted file store and CI/CD. This follows Adam Shostack, *Threat Modeling: Designing for Security* (2014). Risk scores prioritise work; they do not claim that risk is eliminated.

## Assets

| Asset | Value | Why |
|---|---:|---|
| Evidence plaintext/ciphertext | Critical | Client incident material and integrity evidence. |
| Cases, notes, actions and reports | High | Sensitive investigation and remediation records. |
| Credentials and server-side session tokens | Critical | Permit impersonation. |
| Tink keyset and audit HMAC key | Critical | Decrypt evidence or forge a chain if compromised. |
| Audit log | Critical | Accountability and incident evidence. |

## Top attack paths

1. **BOLA/tenant disclosure:** alter a UUID or filter to obtain another organisation's content. Mitigation: service-layer `CaseAccessService`, tenant-scoped queries and 404 responses.
2. **Credential takeover:** enumerate identities or stuff passwords. Mitigation: Argon2id, generic failures, dummy comparison, lockout and per-IP/per-account rate limits.
3. **Disguised evidence upload:** rename executable bytes as a safe extension. Mitigation: size, safe filename, allow-list, Tika detection, signature check, scan seam, AEAD and authorised download.
4. **Audit repudiation:** edit rows or cause concurrent writers to fork the chain. Mitigation: canonical HMAC-SHA256 links and transactional `SELECT ... FOR UPDATE` chain-head locking.
5. **Report disclosure:** obtain a draft, another tenant's report or internal notes. Mitigation: versioned workflow, generator/approver separation, report service access checks and redaction.

## Risk register

| ID | Threat | STRIDE | Asset | L | I | Score | Mitigation | Residual risk | Owner |
|---|---|---|---|---:|---:|---:|---|---|---|
| R-01 | Cross-tenant/BOLA access | E, I | Cases/evidence/reports | 4 | 5 | 20 | SR-AUTHZ, SR-FILE, SR-REPORT | New service paths can omit a check. | Security lead |
| R-02 | Credential stuffing | S, D | Credentials/sessions | 4 | 4 | 16 | SR-AUTH, SR-SESS, SR-RATE | Distributed attacks and weak user choices remain. | Security lead |
| R-03 | Malicious/disguised upload | T, I, D | Evidence/store | 3 | 5 | 15 | SR-FILE, SR-CRYPTO | No live anti-malware scanner. | Storage lead |
| R-04 | Audit tampering/fork | T, R | Audit/HMAC key | 3 | 5 | 15 | SR-AUDIT | DB superuser with HMAC key can forge history; external anchoring is future work. | Audit owner |
| R-05 | XSS/injection | T, I | Browser/session | 3 | 4 | 12 | SR-VAL, SR-XSS, SR-HDR | Future rich text needs dedicated policy. | Web lead |
| R-06 | Resource exhaustion | D | Application/storage | 4 | 3 | 12 | SR-FILE, SR-RATE | Volumetric DDoS exceeds application controls. | Operations |

## Evidence upload residual risk

Evidence upload currently reads a file into memory after the multipart size check and before Tika inspection, scanning, hashing and AEAD encryption. This creates bounded memory pressure under concurrent requests. Mitigations are the 10 MiB application/multipart limits, per-user and per-source-IP Bucket4j quotas, and an aggregated rate-limit audit event. A future streaming pipeline must preserve fail-closed validation ordering and AEAD associated-data binding.

`NoOpScanService` accepts synthetic academic evidence only; it is an integration seam, not anti-malware protection. Archives are blocked by the extension allow-list, so archive/zip bombs are outside current scope.

## Rate-limiting residual risk

Per-IP rate limits reduce automated abuse but can penalise legitimate users behind a shared NAT, VPN gateway or institutional proxy because they consume one shared bucket. In a reverse-proxy deployment, the application must derive a client IP only from a trusted proxy configuration; accepting an arbitrary client-supplied `X-Forwarded-For` header would allow an attacker to spoof the bucket key and bypass the quota. Proxy trust boundaries and forwarding configuration therefore remain an operational responsibility.

## Assumptions and out of scope

Production uses PostgreSQL. H2 is test-only and has different locking semantics; the audit service has an extra in-process guard for H2, while PostgreSQL `SELECT ... FOR UPDATE` remains the cross-instance lock. Host OS/hypervisor compromise, physical theft, nation-state attackers, volumetric DDoS, backup governance and external AV operation are not eliminated by this application.

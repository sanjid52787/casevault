# ADR-0003: Authenticated Evidence Encryption at Rest and Hash-Chained Audit Trail

## Status
Accepted (Cryptographic requirements preserved in full; framework binding superseded in part by ADR-0006 for Java JCA AES-GCM and HmacSHA256).

## Context
Forensic evidence collected during cyber incident investigations (memory dumps, network logs, configuration files) is legally sensitive. If the host filesystem, backup storage, or database volume is compromised, raw evidence must not be readable in plaintext.

Furthermore, audit logs are prime targets for malicious insiders or compromised accounts seeking to cover tracks. Modifying or deleting audit rows must be mathematically detectable to ensure forensic non-repudiation.

## Decision
1. **Evidence Encryption at Rest:**
   - Evidence files are encrypted during the ingestion stream using authenticated symmetric encryption (Fernet: AES-128-CBC with PKCS7 padding and HMAC-SHA256 authenticated envelope, compliant with standard NIST/FIPS requirements via Python's audited `cryptography` library).
   - Filenames on disk are randomized UUIDv4 identifiers stored in an isolated filesystem location outside the web root (`vault_storage/`).
   - The original inert file's SHA-256 and SHA-512 cryptographic hashes are calculated on the plaintext stream *prior* to encryption and stored as verifiable immutable metadata.
2. **Tamper-Evident Audit Hash Chaining:**
   - Each audit entry contains: `timestamp`, `actor_id`, `action`, `target_model`, `target_id`, `details`, `previous_hash`, and `current_hash`.
   - `current_hash` is computed as:
     `HMAC-SHA256(key=CASEVAULT_AUDIT_HMAC_KEY, data=f"{previous_hash}|{timestamp}|{actor_id}|{action}|{target_model}|{target_id}|{details}")`
   - The first entry uses a known genesis sentinel hash (`0000000000000000000000000000000000000000000000000000000000000000`).
   - An integrity verification function audits the entire chain from genesis to head, raising an alert if any row was modified, inserted, or deleted.

## Consequences
### Positive
- Guarantees confidentiality of forensic artifacts even if storage volumes are leaked or mounted out of band.
- Proves forensic chain of custody through pre-encryption cryptographic hashes (SHA-256 / SHA-512).
- Non-repudiation of audit events is cryptographically enforced without relying on third-party cloud blockchain services.

### Negative / Trade-offs
- Key management is critical: losing `CASEVAULT_EVIDENCE_KEY` renders stored evidence unrecoverable.
- Audit verification requires sequential row evaluation across the ledger.


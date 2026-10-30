# Threat model

## Method

STRIDE is applied per element and trust-boundary flow in the level-1 DFD: browser, nginx, controllers/services, PostgreSQL, audit store, encrypted file store, and CI/CD. This follows Adam Shostack, *Threat Modeling: Designing for Security* (2014). STRIDE identifies candidate threats; risk scoring prioritises engineering work rather than claiming every risk is removed.

## Assets

| Asset | Value | Why |
|---|---:|---|
| Evidence files and plaintext | Critical | Confidential client incident material and potential integrity evidence. |
| Case/notes/actions/reports | High | Sensitive investigation and operational records. |
| Credentials and session tokens | Critical | Permit account impersonation. |
| Tink keyset / encryption keys | Critical | Decrypt all stored evidence in scope. |
| Audit log and HMAC key | Critical | Accountability and integrity evidence. |

## STRIDE coverage

Browser: spoofed credentials/session, tampered requests, information disclosure. nginx: TLS spoofing/downgrade and availability. App services: all STRIDE classes, especially access-control elevation. PostgreSQL/audit/file store: tampering, disclosure and repudiation. CI/CD: malicious dependency/artifact tampering and privilege elevation.

## Top attack paths

1. **Cross-tenant evidence disclosure:** obtain UUID -> call direct download -> exploit missing service tenant check. Counter: SR-03/SR-09, T-AUTHZ-001/T-FILE-008.
2. **Account takeover:** enumerate username -> credential stuffing -> retain session. Counter: SR-01/SR-02/SR-12.
3. **Malicious upload:** disguise executable -> bypass MIME-only validation -> store/serve as active content. Counter: SR-09/SR-07.
4. **Audit repudiation:** obtain DB mutation route -> edit/delete event -> conceal action. Counter: SR-11 and independent chain verification.
5. **Supply-chain compromise:** dependency update/CI compromise -> malicious build artifact. Counter: SR-15/SR-16; residual risk remains in trusted suppliers.

## Risk register

| ID | Threat | STRIDE | Asset | L | I | Score / priority | Mitigation | Residual risk | Owner |
|---|---|---|---|---:|---:|---|---|---|---|
| R-01 | BOLA/cross-tenant access | E, I | Evidence/cases | 4 | 5 | 20 Critical | SR-03, SR-09 | Authorisation defects remain possible; regression tests required. | Security lead |
| R-02 | Credential stuffing | S, D | Credentials/sessions | 4 | 4 | 16 High | SR-01, SR-02, SR-12 | Distributed attacks and weak user passwords remain. | Security lead |
| R-03 | Upload bypass | T, I, D | App/evidence | 3 | 5 | 15 High | SR-09, SR-07 | Type detection/AV are not perfect; ScanService is a stub. | Storage lead |
| R-04 | Audit tampering | T, R | Audit/HMAC key | 3 | 5 | 15 High | SR-11, SR-13 | DB/secret administrator compromise can still harm assurance. | Audit owner |
| R-05 | Dependency/CI compromise | T, E | Build/image | 3 | 5 | 15 High | SR-15, SR-16 | Upstream compromise remains; review and monitoring needed. | DevOps |
| R-06 | XSS/content injection | T, I | Sessions/cases | 3 | 4 | 12 High | SR-05, SR-07 | Browser vulnerabilities and future rich text add risk. | Web lead |
| R-07 | Error/log/config leakage | I | Keys/data | 3 | 4 | 12 High | SR-10, SR-13, SR-14 | Operational copies/backups require separate governance. | Operations |
| R-08 | Resource exhaustion | D | Availability | 4 | 3 | 12 High | SR-09, SR-12, SR-16 | Volumetric network DoS exceeds app controls. | Operations |

## Assumptions and out of scope

Trusted administrators protect the production host, database platform and secret provider; full host OS compromise, hypervisor compromise, physical theft, nation-state capability, and volumetric DDoS are not eliminated by this application. External AV is intentionally not implemented; only inert local files are permitted. Backups, key rotation, legal retention obligations, and production incident response require an operational runbook in later phases.

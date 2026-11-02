# Assurance summary — Phase 13

## Coverage achieved

CaseVault combines unit, repository, Spring integration, MockMvc security regression, end-to-end workflow and manual local-stack checks. Existing named regressions cover authentication, sessions, tenant/object authorisation, validation, XSS, evidence encryption/validation, audit integrity, reporting, headers, CSRF, rate limits, retention and the synthetic end-to-end workflow. The detailed test mapping is in [../test-plan.md](../test-plan.md); claim status is in [../evidence-index.md](../evidence-index.md).

Phase 13 adds a local-only OWASP ZAP harness, a WSTG-mapped manual procedure, a vulnerability register and controlled remediation demonstrations. ZAP baseline scans public surface/configuration; an optional authenticated scan first logs in with environment-supplied synthetic credentials and injects the resulting transient session only into the ZAP process. Results are intentionally ignored because they can contain URLs, headers and local machine information.

## Tool limits and observed false positives/negatives

| Technique | Strength | Cannot reliably establish |
|---|---|---|
| ZAP baseline/active scan | Common server/header/configuration and reflected-input probes | Tenant BOLA, separation of duties, assignment business rules or all authenticated paths. |
| Semgrep/SpotBugs/CodeQL | Syntax/dataflow patterns and known dangerous APIs | Whether a repository query has the correct tenant predicate in every business context. |
| Dependency/SBOM tooling | Known component inventory/CVEs | Exploitability, configuration defects, unknown/malicious dependencies or local code logic. |
| Manual testing | Workflow and role checks with explicit intent | Exhaustive state/input coverage and race conditions. |
| Automated regression | Repeatable known-control evidence | New design defects not represented by a test. |

The historical Gitleaks generic-key alerts were validated as legacy test fixtures, not deployed secrets. The phase-10 Dependency-Check run remains incomplete without an NVD API key. No local ZAP/testssl result is claimed until Docker is available and the scripted scan is executed.

## Residual-risk acceptance

| Risk | Owner | Decision | Preconditions / review date |
|---|---|---|---|
| Single-node in-memory rate limits are not distributed and can affect users sharing NAT IPs. | Technical owner | Accepted for local assessment deployment | Replace with shared limit store before multi-node deployment. |
| Dev TLS certificate is self-signed. | Deployment owner | Accepted for localhost only | Use CA-issued certificate outside local demo. |
| No real malware/AV integration; no archive uploads allowed. | Security owner | Accepted for synthetic assessment scope | Integrate AV service before handling untrusted production files. |
| DAST, Trivy/Hadolint and restore drill lack local execution evidence if Docker is unavailable. | Release owner | Not accepted for release | Run/retain reports before deployment decision. |
| Audit filtering is incomplete. | Admin owner | Accepted temporarily | Resolve F-SCR-005 before operational handover. |

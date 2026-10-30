# ADR-0005: Cryptographic Dependency Pinning and Hash Verification

## Status
Accepted (Supply chain integrity principle preserved in full; packaging implementation superseded in part by ADR-0006 for Maven dependency management and OWASP Dependency-Check).

## Context
Modern software supply chain attacks compromise package registries (PyPI), insert malicious updates, or conduct typosquatting attacks. If dependencies are specified loosely (e.g. `django>=5.0`), automated builds can fetch compromised or tampered packages.

## Decision
We enforce strict cryptographic dependency pinning:
1. Every runtime and assurance dependency is pinned to an exact version with its SHA-256 hash recorded in `requirements.lock` using pip's `--require-hashes` standard format.
2. In production builds and CI pipelines, `pip install --no-deps --require-hashes -r requirements.lock` is enforced.
3. Licences of all dependencies are audited using `pip-licenses` and recorded in `docs/DEPENDENCIES.md` and `docs/AI_DECLARATION.md`.
4. Automated vulnerability scanning is executed via `pip-audit` against the PyPA advisory database before merging or releasing.

## Consequences
### Positive
- Defends against PyPI compromise, MITM package alteration, and unexpected breaking dependency changes.
- Ensures identical, verifiable, deterministic builds across development, CI/CD, and production containers.

### Negative / Trade-offs
- Updating dependencies requires regenerating and verifying cryptographic hashes across all wheel architectures.


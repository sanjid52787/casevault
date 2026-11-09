# CI/CD security gate

## Pipeline assurance gate

The GitHub Actions workflow in `.github/workflows/ci.yml` is deliberately limited to `push`, `pull_request`,
scheduled and manual events. It does not use `pull_request_target`, so code from an untrusted pull request is
not checked out with repository write credentials. The default token has `contents: read`; only CodeQL and the
tag-only release job receive elevated permissions.

| Gate | Evidence | Required for `main` | Required for release tag |
|---|---|---:|---:|
| Build/test | Java 21, Maven Wrapper, Enforcer, unit/integration/security tests and JaCoCo | Yes | Yes |
| SAST | SpotBugs/FindSecBugs, Semgrep and CodeQL | Yes | Yes |
| SCA | CycloneDX SBOM and Dependency-Check CVSS >= 9 gate | Yes when NVD access is available | Yes; NVD API key required |
| Secrets | Full-history Gitleaks scan | Yes | Yes |
| Container | Hadolint, image Trivy and Compose config Trivy | Yes | Yes |
| DAST | Authorised local DAST harness | Phase 13 only | Phase 13 only |
| Release integrity | SHA-256 checksums, Sigstore keyless signature/bundles, GitHub provenance attestation | N/A | Yes |

Maven has no native universal lockfile equivalent. CaseVault instead pins direct dependencies/plugins in
`pom.xml`, uses Maven Enforcer dependency convergence and duplicate-version rules, runs Maven with
`--strict-checksums` (`-C`), produces a CycloneDX SBOM and uses Dependabot. This reduces—but does not eliminate—
repository compromise and dependency-confusion risk.

## Branch protection guidance

Protect `main` in GitHub repository settings:

1. Require pull requests and at least one approving review; dismiss stale approvals after new commits.
2. Require `Build, test and coverage`, `SAST and CodeQL`, `Dependency and SBOM assurance`, `Full-history secret scan` and `Container build and scan` to pass before merge.
3. Require branches to be up to date before merge; block force-pushes and direct pushes to `main`.
4. Restrict who can dismiss reviews or alter protection rules; enable signed commits as a recommended policy.
5. Restrict release tags and protect the release environment; store `NVD_API_KEY` only as an environment/repository secret.

## Release provenance and SLSA target

The release job aims at SLSA Build Level 2 characteristics: version-controlled workflow, hosted build service,
isolated ephemeral runner, provenance attestation and keyless Sigstore signing. It is not a claim of a SLSA
level certification. Missing work includes protected/reviewed workflow changes, an explicit trusted builder
configuration, source/repository provenance policy, verified reusable workflows, hermetic dependency retrieval
and independent provenance verification by deployers.

## Local validation

`act` was not available in the repository environment. Validate syntax and the project gates locally with
`./mvnw -B -C verify`; run Hadolint/Trivy on a Docker-enabled machine as documented in
`docs/assurance/container-hardening.md`. `act` does not faithfully reproduce GitHub OIDC, CodeQL uploads,
attestations, GHCR publishing or protected-environment secrets, so a successful `act` run is not release proof.

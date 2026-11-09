# Container hardening assessment

## Implemented controls

| Area | Implemented control | Rationale / residual risk |
|---|---|---|
| Image build | Multi-stage Maven build; Java 21 JRE runtime contains no Maven/compiler; Spring Boot layers copied separately. | Base image tags are specific but not digest-pinned; pin digests in release CI after tested image selection. |
| Runtime identity | App runs as UID/GID 10001 with a no-login shell. | nginx needs a privileged bind capability for port 443; it drops all other capabilities. |
| Filesystem | Hardened overlay uses read-only root filesystems, bounded `tmpfs`, and a separate writable evidence volume. | PostgreSQL/evidence named volumes are necessarily writable and require host-volume protection. |
| Process limits | `pids_limit`, memory and CPU limits; JVM MaxRAMPercentage and exit-on-OOM. | Limits require operational sizing/load testing. |
| Network | Only proxy publishes 443; application/database are on an internal Docker network. | Docker daemon/host administrators bypass container network isolation. |
| Secrets | Docker secrets read at start-up; entrypoint does not print them; local generator writes only Git-ignored files. | Local Compose secrets are files on the host, not a substitute for a managed production secret manager. |
| Database roles | Migration role owns DDL; runtime role gets no DDL and audit table is INSERT/SELECT only after the grant job. | Verify grants against actual PostgreSQL in CI/operations before release. |
| TLS/proxy | TLS 1.2/1.3, HSTS, request size/rate limits, forwarded headers, dotfile/actuator restrictions. | Development certificate is self-signed and must be replaced in production. |

## Scanner results

| Tool | Command | Result | Interpretation / next action |
|---|---|---|---|
| Hadolint | `hadolint Dockerfile` | Not executed | Hadolint is not installed in this repository environment. Run in CI or a Docker-enabled workstation; remediate rather than suppress warnings. |
| Trivy config | `trivy config --severity HIGH,CRITICAL .` | Not executed | Trivy is not installed locally. It should scan the Dockerfile/Compose configuration in CI. |
| Trivy image | `trivy image --severity HIGH,CRITICAL casevault:<tag>` | Not executed | Docker is unavailable, so no image could be built/scanned here. This is a release gate, not a clean result. |
| Restore drill | `sh deploy/scripts/test-backup-restore.sh casevault` | Not executed | Docker is unavailable. The script restores to a new database and invokes the profile-limited audit/evidence verifier; retain an executed run before deployment. |

## Before/after evidence

Before Phase 11 the repository had no Dockerfile, Compose topology, TLS proxy configuration or container scanner instructions. The deployment files now encode the controls above. No scanner result is represented as passing until Docker, Hadolint and Trivy are installed and the exact commands are run. This avoids a false hardening claim.

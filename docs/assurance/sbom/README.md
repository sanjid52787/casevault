# CycloneDX SBOM reference

`bom.json` is the generated CycloneDX 1.6 aggregate SBOM reference from the 2026-11-02 Maven verification
run. It contained 101 resolved components. Regenerate it with `./mvnw -B verify` after any dependency change;
the Maven configuration writes the fresh artifact to `target/bom.json`.

The SBOM is an inventory, not a vulnerability assessment. Pair it with the Dependency-Check profile and the
human licence review recorded in `../sast-sca-analysis.md`.

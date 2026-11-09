# Assurance evidence

Automated test identifiers and expected Surefire report paths are indexed in `../evidence-index.md`. The reports
are generated locally under `target/surefire-reports/` and are intentionally not committed. Manual checks are
kept beside this file; only synthetic data may be used.

## Automated assurance

Run all local assurance stages from a clean working directory:

```powershell
.\scripts\run-assurance.ps1
```

The script writes machine-local reports under `docs/assurance/results/YYYY-MM-DD/`; that directory is ignored
because reports contain machine paths and can be regenerated. Set `NVD_API_KEY` in the process environment before
the Dependency-Check stage to avoid NVD throttling. The committed CycloneDX reference is under `sbom/`.

Install local command-line scanners, for example, with `python -m pip install --user semgrep` and
`winget install Gitleaks.Gitleaks`, then reopen the shell so their command directories are on `PATH`. Do not
place an NVD key in `.env`, source code or Git configuration: use a short-lived process/CI secret only.

Install the pre-commit secret scan once per clone with `Copy-Item scripts/pre-commit .git/hooks/pre-commit` on
Unix-like systems (ensure it is executable). On Windows, run `scripts/verify-gitleaks.ps1` after installing
Gitleaks and adding it to `PATH`. Both self-test scripts create a clearly fake marker only in a temporary
directory and verify that Gitleaks rejects it; no marker is committed.

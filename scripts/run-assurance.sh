#!/usr/bin/env sh
set -eu
stamp="$(date +%Y-%m-%d)"
results="docs/assurance/results/$stamp"
mkdir -p "$results"
run() {
  name="$1"
  shift
  "$@" >"$results/$name.log" 2>&1 || { cat "$results/$name.log"; return 1; }
  cat "$results/$name.log"
}
run maven-verify ./mvnw -B verify
run spotbugs ./mvnw -B spotbugs:check
if command -v semgrep >/dev/null 2>&1; then run semgrep semgrep scan --config .semgrep --error;
else echo "SKIPPED: semgrep not installed" >"$results/semgrep.log"; fi
run dependency-check ./mvnw -B -Pdependency-check dependency-check:check
run sbom ./mvnw -B cyclonedx:makeAggregateBom
if command -v gitleaks >/dev/null 2>&1; then run gitleaks gitleaks detect --source . --config .gitleaks.toml --redact; run gitleaks-self-test ./scripts/verify-gitleaks.sh; else echo "SKIPPED: gitleaks not installed" >"$results/gitleaks.log"; fi
cp target/bom.json "$results/bom.json"

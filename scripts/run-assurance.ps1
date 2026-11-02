param([switch]$SkipDependencyCheck)
$ErrorActionPreference = 'Stop'
$stamp = Get-Date -Format 'yyyy-MM-dd'
$results = Join-Path $PSScriptRoot "..\docs\assurance\results\$stamp"
New-Item -ItemType Directory -Force -Path $results | Out-Null
function Invoke-Assurance([string]$Name, [scriptblock]$Command) { & $Command *>&1 | Tee-Object -FilePath (Join-Path $results "$Name.log"); if ($LASTEXITCODE -ne 0) { throw "$Name failed" } }
Invoke-Assurance 'maven-verify' { .\mvnw.cmd -B verify }
Invoke-Assurance 'spotbugs' { .\mvnw.cmd -B spotbugs:check }
$semgrep = Get-Command semgrep -ErrorAction SilentlyContinue
if (-not $semgrep) {
    $semgrep = Get-ChildItem (Join-Path $env:APPDATA 'Python') -Filter semgrep.exe -Recurse -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($semgrep) { $env:Path = "$(Split-Path $semgrep.FullName);$env:Path" }
}
if ($semgrep) { Invoke-Assurance 'semgrep' { semgrep scan --config .semgrep --error } }
else { 'SKIPPED: semgrep not installed' | Set-Content (Join-Path $results 'semgrep.log') }
if (-not $SkipDependencyCheck) { Invoke-Assurance 'dependency-check' { .\mvnw.cmd -B -Pdependency-check dependency-check:check } }
Invoke-Assurance 'sbom' { .\mvnw.cmd -B cyclonedx:makeAggregateBom }
if (Get-Command gitleaks -ErrorAction SilentlyContinue) { Invoke-Assurance 'gitleaks' { gitleaks detect --source . --config .gitleaks.toml --redact }; Invoke-Assurance 'gitleaks-self-test' { .\scripts\verify-gitleaks.ps1 } } else { 'SKIPPED: gitleaks not installed' | Set-Content (Join-Path $results 'gitleaks.log') }
Copy-Item target\bom.json (Join-Path $results 'bom.json') -Force

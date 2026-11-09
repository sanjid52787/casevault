param(
    [string]$Target = "https://localhost",
    [string]$OutputDirectory = ""
)
$ErrorActionPreference = 'Stop'
if ($Target -notmatch '^https://(localhost|127\.0\.0\.1)(:|/|$)') { throw "DAST target must be local HTTPS: $Target" }
if (-not $OutputDirectory) { $OutputDirectory = "docs/assurance/results/$((Get-Date).ToString('yyyy-MM-dd'))/zap" }
$env:ZAP_TARGET = $Target
$env:ZAP_OUTPUT_DIR = $OutputDirectory
& bash ./scripts/run-dast.sh
exit $LASTEXITCODE

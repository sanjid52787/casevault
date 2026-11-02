$ErrorActionPreference = 'Stop'
if (-not (Get-Command gitleaks -ErrorAction SilentlyContinue)) { throw 'gitleaks is not installed' }
$temporaryDirectory = Join-Path ([System.IO.Path]::GetTempPath()) ([guid]::NewGuid().ToString())
New-Item -ItemType Directory -Path $temporaryDirectory | Out-Null
try {
    # Split the marker so no matching string is committed in this script.
    Set-Content -NoNewline -Path (Join-Path $temporaryDirectory 'fake-secret.txt') -Value ('CASEVAULT_TEST_FAKE_SECRET_' + '0123456789ABCDEF')
    & gitleaks detect --no-git --source $temporaryDirectory --config .gitleaks.toml --redact *> $null
    if ($LASTEXITCODE -eq 0) { throw 'gitleaks did not flag the deliberately fake temporary marker' }
    Write-Output 'gitleaks temporary-marker self-test passed'
} finally {
    Remove-Item -LiteralPath $temporaryDirectory -Recurse -Force -ErrorAction SilentlyContinue
}
